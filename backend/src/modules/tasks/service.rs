//! Task business rules.
//!
//! Two properties are specific to this module and are the reason it is as careful
//! as it is:
//!
//! * **A task is not shared when its project is.** Visibility needs
//!   `tasks.client_visible = true` *and* a live project link. Both are in the SQL
//!   predicate, and changing the flag is audited under its own action code so that
//!   "when did this become visible to the client, and who decided that" always has
//!   an answer.
//! * **`completed_at` is derived, never supplied.** The database enforces
//!   `(status = 'DONE') = (completed_at IS NOT NULL)`; `TaskStatus::completed_at_for`
//!   is the single place that computes it, so the constraint never fires.
//!
//! The authorisation shape is the same as `projects::service`: re-read the row
//! `FOR UPDATE`, build the target from the row and from a real assignee lookup,
//! authorise, check the version, mutate, audit, commit.

use time::OffsetDateTime;
use uuid::Uuid;

use super::dto::{
    AssignTaskRequest, CancelTaskQuery, ClientTaskListQuery, ClientTaskResponse, CreateTaskRequest,
    TaskAssigneeResponse, TaskListQuery, TaskPriority, TaskResponse, TaskStatus, UpdateTaskRequest,
};
use super::repo::{self, ClientTaskRow, NewTask, TaskRow, TaskUpdate};
use crate::app::AppState;
use crate::modules::audit::{action, AuditEvent, AuditMetadata, Outcome};
use crate::modules::authentication::principal::Principal;
use crate::modules::authorization::domain::{ResourceType, Target, TargetContext};
use crate::modules::projects::dto::ProjectStatus;
use crate::modules::projects::service as projects;
use crate::modules::projects::visibility::ScopeFilter;
use crate::platform::errors::{AppError, AppResult};
use crate::shared::pagination::{Cursor, Page, PageRequest};
use crate::shared::validation as v;

pub const PERM_READ: &str = "tasks.read";
pub const PERM_CREATE: &str = "tasks.create";
pub const PERM_UPDATE: &str = "tasks.update";
pub const PERM_ASSIGN: &str = "tasks.assign";
pub const PERM_DELETE: &str = "tasks.delete";
pub const PERM_PORTAL_READ: &str = "client.portal.tasks.read";

const TARGET_TASK: &str = "TASK";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn event(action_code: &'static str, principal: &Principal, ip: &Option<String>) -> AuditEvent {
    AuditEvent::new(action_code, Outcome::Success)
        .actor(
            principal.user_id(),
            principal.session.principal_type,
            Some(principal.session.session_id),
        )
        .source_ip(ip.clone())
}

fn status_of(row: &TaskRow) -> AppResult<TaskStatus> {
    TaskStatus::parse(&row.status).ok_or_else(|| {
        AppError::Internal("tasks.status holds a value outside the catalogue".into())
    })
}

fn priority_of(row: &TaskRow) -> AppResult<TaskPriority> {
    TaskPriority::parse(&row.priority).ok_or_else(|| {
        AppError::Internal("tasks.priority holds a value outside the catalogue".into())
    })
}

fn to_response(row: TaskRow) -> AppResult<TaskResponse> {
    let status = status_of(&row)?;
    let priority = priority_of(&row)?;
    Ok(TaskResponse {
        id: row.id,
        project_id: row.project_id,
        title: row.title,
        description: row.description,
        status,
        priority,
        due_date: row.due_date,
        client_visible: row.client_visible,
        internal_note: row.internal_note,
        version: row.version,
        created_by: row.created_by,
        created_at: row.created_at,
        updated_at: row.updated_at,
        completed_at: row.completed_at,
    })
}

fn to_client_response(row: ClientTaskRow) -> AppResult<ClientTaskResponse> {
    let status = TaskStatus::parse(&row.status)
        .ok_or_else(|| AppError::Internal("tasks.status holds an unrecognised value".into()))?;
    let priority = TaskPriority::parse(&row.priority)
        .ok_or_else(|| AppError::Internal("tasks.priority holds an unrecognised value".into()))?;
    Ok(ClientTaskResponse {
        id: row.id,
        project_id: row.project_id,
        title: row.title,
        description: row.description,
        status,
        priority,
        due_date: row.due_date,
        completed_at: row.completed_at,
        updated_at: row.updated_at,
    })
}

fn cursor_for(row: &TaskRow, sort_column: &str) -> Cursor {
    let at = if sort_column == "t.updated_at" {
        row.updated_at
    } else {
        row.created_at
    };
    repo::to_cursor(at, row.id)
}

/// Build the object-level target for a task.
///
/// The department comes from the task's **project**, because a task has none of its
/// own; the membership fact is a real `task_assignees` lookup. Neither is taken
/// from the request.
fn task_target(
    task_id: Uuid,
    project_department_id: Option<Uuid>,
    actor_is_assignee: bool,
) -> Target {
    Target::Resource(
        TargetContext::new(ResourceType::Task, task_id)
            .with_department(project_department_id)
            .with_membership(actor_is_assignee),
    )
}

async fn require_internal_user(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
) -> AppResult<()> {
    match repo::user_principal_type(tx, user_id).await?.as_deref() {
        Some("INTERNAL") => Ok(()),
        Some(_) => Err(AppError::conflict(
            "EXTERNAL_PRINCIPAL",
            "Task assignment is limited to internal principals.",
        )),
        None => Err(AppError::field(
            "user_id",
            "NOT_FOUND",
            "No active user with that identifier exists.",
        )),
    }
}

// ---------------------------------------------------------------------------
// Internal endpoints
// ---------------------------------------------------------------------------

/// `GET /api/v1/tasks` and `GET /api/v1/projects/{id}/tasks`.
///
/// `project_id` is a *filter*, not an authorisation: narrowing to one project does
/// not widen what the actor may see, because the scope predicate is applied
/// regardless.
pub async fn list(
    state: &AppState,
    principal: &Principal,
    query: &TaskListQuery,
    project_id_from_path: Option<Uuid>,
) -> AppResult<Page<TaskResponse>> {
    let status = query.parsed_status()?;
    let page = PageRequest::resolve(
        &query.page(),
        repo::SORTS,
        repo::DEFAULT_SORT,
        state.config.limits.max_page_size,
    )?;

    // A path-supplied project wins over a query-supplied one; the nested route is
    // the more specific statement of intent.
    let project_id = project_id_from_path.or(query.project_id);

    let Some(filter) = ScopeFilter::build(&principal.actor, PERM_READ, ResourceType::Task) else {
        return Err(AppError::AuthorizationDenied.hide_from_external(principal.is_external()));
    };
    if filter.matches_nothing() {
        return Ok(Page::empty());
    }

    let rows = repo::list(
        &state.db,
        principal.user_id(),
        &filter,
        project_id,
        status.map(TaskStatus::as_str),
        &page,
    )
    .await?;

    let sort_column = page.sort_column;
    let raw = Page::build(rows, &page, |row| cursor_for(row, sort_column));
    let items = raw
        .items
        .into_iter()
        .map(to_response)
        .collect::<AppResult<Vec<_>>>()?;
    Ok(Page {
        items,
        next_cursor: raw.next_cursor,
        has_more: raw.has_more,
    })
}

pub async fn get(state: &AppState, principal: &Principal, id: Uuid) -> AppResult<TaskResponse> {
    let row = repo::find(&state.db, id).await?.ok_or(AppError::NotFound)?;
    let project = projects::load_context(state, row.project_id, principal.user_id())
        .await?
        .ok_or(AppError::NotFound)?;
    let is_assignee = repo::is_active_assignee_pool(&state.db, id, principal.user_id()).await?;
    state.require(
        principal,
        PERM_READ,
        &task_target(row.id, project.department_id, is_assignee),
    )?;
    to_response(row)
}

/// `POST /api/v1/tasks`.
///
/// The task does not exist yet, so `ASSIGNED` cannot be satisfied by an assignee
/// lookup. Active membership of the **project** stands in for it here and only
/// here: somebody working on a project may add work to it. Every later decision
/// about the task uses the task's own assignees.
pub async fn create(
    state: &AppState,
    principal: &Principal,
    ip: &Option<String>,
    request: CreateTaskRequest,
) -> AppResult<TaskResponse> {
    let title = v::required_text("title", &request.title, v::MAX_TITLE_LEN)?;
    let description = v::optional_text(
        "description",
        request.description.as_deref(),
        v::MAX_TASK_DESCRIPTION_LEN,
    )?;
    let internal_note = v::optional_text(
        "internal_note",
        request.internal_note.as_deref(),
        v::MAX_LONG_TEXT_LEN,
    )?;
    let priority = match request.priority.as_deref() {
        None => TaskPriority::Normal,
        Some(raw) => v::parse_enum("priority", raw, TaskPriority::parse, TaskPriority::ALLOWED)?,
    };

    let mut tx = state.begin().await?;
    // A missing project is `404`, deliberately not a field-level `400`. This runs
    // before the permission check (the department the decision needs comes from the
    // project), so a distinguishable "no such project" answer here would let an
    // external principal enumerate project identifiers through the create endpoint
    // — the one place where the usual order of load-then-authorise leaks. Both
    // branches now render as `404` for such a principal (TH-10).
    let project =
        projects::load_context_for_update(&mut tx, request.project_id, principal.user_id())
            .await?
            .ok_or(AppError::NotFound)?;

    let id = Uuid::now_v7();
    state.require(
        principal,
        PERM_CREATE,
        &task_target(id, project.department_id, project.actor_is_member),
    )?;

    if project.status == ProjectStatus::Archived {
        return Err(AppError::conflict(
            "PROJECT_ARCHIVED",
            "An archived project cannot gain tasks.",
        ));
    }

    let row = repo::insert(
        &mut tx,
        &NewTask {
            id,
            project_id: request.project_id,
            title,
            description,
            // Always TODO, and `client_visible` is not written at all — the column
            // default of `false` is what a new task gets.
            status: TaskStatus::Todo.as_str(),
            priority: priority.as_str(),
            due_date: request.due_date,
            internal_note,
            created_by: principal.user_id(),
        },
    )
    .await?;

    state
        .audit(
            &mut tx,
            event(action::TASK_CREATED, principal, ip)
                .target(TARGET_TASK, row.id)
                .meta(
                    AuditMetadata::new()
                        .id("project_id", row.project_id)
                        .str("priority", priority.as_str())
                        .bool("client_visible", false),
                ),
        )
        .await?;
    tx.commit().await?;

    to_response(row)
}

/// `PATCH /api/v1/tasks/{id}`.
pub async fn update(
    state: &AppState,
    principal: &Principal,
    ip: &Option<String>,
    id: Uuid,
    request: UpdateTaskRequest,
) -> AppResult<TaskResponse> {
    let mut tx = state.begin().await?;
    let row = repo::find_for_update(&mut tx, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let project = projects::load_context_for_update(&mut tx, row.project_id, principal.user_id())
        .await?
        .ok_or(AppError::NotFound)?;
    let is_assignee = repo::is_active_assignee(&mut tx, id, principal.user_id()).await?;

    state.require(
        principal,
        PERM_UPDATE,
        &task_target(row.id, project.department_id, is_assignee),
    )?;

    if row.version != request.version {
        return Err(AppError::VersionConflict {
            expected: request.version,
            actual: row.version,
        });
    }

    let current_status = status_of(&row)?;
    let mut meta = AuditMetadata::new();

    let title = match &request.title {
        Some(raw) => {
            meta = meta.changed("title");
            v::required_text("title", raw, v::MAX_TITLE_LEN)?
        }
        None => row.title.clone(),
    };
    let description = match &request.description {
        Some(raw) => {
            meta = meta.changed("description");
            v::optional_text("description", Some(raw), v::MAX_TASK_DESCRIPTION_LEN)?
        }
        None => row.description.clone(),
    };
    let internal_note = match &request.internal_note {
        Some(raw) => {
            meta = meta.changed("internal_note");
            v::optional_text("internal_note", Some(raw), v::MAX_LONG_TEXT_LEN)?
        }
        None => row.internal_note.clone(),
    };
    let priority = match &request.priority {
        Some(raw) => {
            meta = meta.changed("priority");
            v::parse_enum("priority", raw, TaskPriority::parse, TaskPriority::ALLOWED)?
        }
        None => priority_of(&row)?,
    };

    let next_status = match &request.status {
        None => current_status,
        Some(raw) => {
            let requested = v::parse_enum("status", raw, TaskStatus::parse, TaskStatus::ALLOWED)?;
            if !current_status.can_transition_to(requested) {
                return Err(AppError::conflict(
                    "INVALID_STATE_TRANSITION",
                    "This status change is not permitted from the task's current status.",
                ));
            }
            if requested != current_status {
                meta = meta.changed("status");
            }
            requested
        }
    };

    let due_date = request.due_date.unwrap_or(row.due_date);
    if request.due_date.is_some() {
        meta = meta.changed("due_date");
    }

    let visibility_changed =
        matches!(request.client_visible, Some(requested) if requested != row.client_visible);
    let client_visible = request.client_visible.unwrap_or(row.client_visible);
    if visibility_changed {
        meta = meta.changed("client_visible");
    }

    let now = OffsetDateTime::now_utc();
    let patch = TaskUpdate {
        title,
        description,
        status: next_status.as_str(),
        priority: priority.as_str(),
        due_date,
        client_visible,
        internal_note,
        completed_at: next_status.completed_at_for(row.completed_at, now),
    };

    let Some(updated) = repo::update(&mut tx, id, request.version, &patch).await? else {
        return Err(AppError::VersionConflict {
            expected: request.version,
            actual: row.version,
        });
    };

    state
        .audit(
            &mut tx,
            event(action::TASK_UPDATED, principal, ip)
                .target(TARGET_TASK, updated.id)
                .meta(meta),
        )
        .await?;

    // A distinct record, because "who decided this could leave the company, and
    // when" is a different question from "who edited this task" and must be
    // answerable without reading every TASK.UPDATED event's changed-field list.
    if visibility_changed {
        state
            .audit(
                &mut tx,
                event(action::TASK_CLIENT_VISIBILITY_CHANGED, principal, ip)
                    .target(TARGET_TASK, updated.id)
                    .meta(
                        AuditMetadata::new()
                            .id("project_id", updated.project_id)
                            .bool("client_visible", updated.client_visible)
                            .bool("previous_client_visible", row.client_visible),
                    ),
            )
            .await?;
    }

    tx.commit().await?;
    to_response(updated)
}

/// `DELETE /api/v1/tasks/{id}` — cancellation.
///
/// The row is never deleted. `tasks` is referenced by `task_assignees` with `ON
/// DELETE RESTRICT`, and more importantly a deleted task is a piece of history that
/// no longer exists: cancellation records that the work was dropped, and by whom.
pub async fn cancel(
    state: &AppState,
    principal: &Principal,
    ip: &Option<String>,
    id: Uuid,
    query: &CancelTaskQuery,
) -> AppResult<()> {
    let mut tx = state.begin().await?;
    let row = repo::find_for_update(&mut tx, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let project = projects::load_context_for_update(&mut tx, row.project_id, principal.user_id())
        .await?
        .ok_or(AppError::NotFound)?;
    let is_assignee = repo::is_active_assignee(&mut tx, id, principal.user_id()).await?;

    state.require(
        principal,
        PERM_DELETE,
        &task_target(row.id, project.department_id, is_assignee),
    )?;

    // A `DELETE` has no body, so the concurrency token arrives as a query
    // parameter. It is optional, but honoured when supplied: cancelling a task
    // somebody else has since finished is exactly the lost update `version` exists
    // to catch.
    if let Some(expected) = query.version {
        if expected != row.version {
            return Err(AppError::VersionConflict {
                expected,
                actual: row.version,
            });
        }
    }

    let current = status_of(&row)?;
    if current == TaskStatus::Cancelled {
        return Err(AppError::conflict(
            "ALREADY_CANCELLED",
            "This task is already cancelled.",
        ));
    }
    if !current.can_transition_to(TaskStatus::Cancelled) {
        return Err(AppError::conflict(
            "INVALID_STATE_TRANSITION",
            "A completed task cannot be cancelled.",
        ));
    }

    let patch = TaskUpdate {
        title: row.title.clone(),
        description: row.description.clone(),
        status: TaskStatus::Cancelled.as_str(),
        priority: priority_of(&row)?.as_str(),
        due_date: row.due_date,
        client_visible: row.client_visible,
        internal_note: row.internal_note.clone(),
        // Cancelling clears the completion timestamp, satisfying
        // `tasks_completion_consistent` in the one direction it is easy to forget.
        completed_at: TaskStatus::Cancelled
            .completed_at_for(row.completed_at, OffsetDateTime::now_utc()),
    };

    if repo::update(&mut tx, id, row.version, &patch)
        .await?
        .is_none()
    {
        return Err(AppError::VersionConflict {
            expected: row.version,
            actual: row.version,
        });
    }

    // There is no dedicated `TASK.CANCELLED` action code in the audit catalogue,
    // and `modules::audit` is not this module's to extend. The event is recorded as
    // an update whose metadata names the terminal status, which keeps the action
    // code set stable and still answers "who cancelled this, and when".
    state
        .audit(
            &mut tx,
            event(action::TASK_UPDATED, principal, ip)
                .target(TARGET_TASK, row.id)
                .meta(
                    AuditMetadata::new()
                        .changed("status")
                        .str("status", TaskStatus::Cancelled.as_str())
                        .str("previous_status", current.as_str()),
                ),
        )
        .await?;
    tx.commit().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Assignees
// ---------------------------------------------------------------------------

pub async fn assign(
    state: &AppState,
    principal: &Principal,
    ip: &Option<String>,
    id: Uuid,
    request: AssignTaskRequest,
) -> AppResult<()> {
    let mut tx = state.begin().await?;
    let row = repo::find_for_update(&mut tx, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let project = projects::load_context_for_update(&mut tx, row.project_id, principal.user_id())
        .await?
        .ok_or(AppError::NotFound)?;
    let is_assignee = repo::is_active_assignee(&mut tx, id, principal.user_id()).await?;

    state.require(
        principal,
        PERM_ASSIGN,
        &task_target(row.id, project.department_id, is_assignee),
    )?;

    if matches!(status_of(&row)?, TaskStatus::Cancelled) {
        return Err(AppError::conflict(
            "TASK_CANCELLED",
            "A cancelled task cannot be assigned.",
        ));
    }

    // The database refuses an external principal here with a trigger; this turns
    // that into a legible error rather than an opaque invariant violation.
    require_internal_user(&mut tx, request.user_id).await?;

    if repo::is_active_assignee(&mut tx, id, request.user_id).await? {
        return Err(AppError::conflict(
            "ALREADY_ASSIGNED",
            "That user is already assigned to this task.",
        ));
    }

    repo::add_assignee(&mut tx, id, request.user_id, principal.user_id()).await?;
    // Assignment resolves `ASSIGNED` scope, so it is a privilege change.
    state
        .bump_security_version(&mut tx, request.user_id)
        .await?;

    state
        .audit(
            &mut tx,
            event(action::TASK_ASSIGNED, principal, ip)
                .target(TARGET_TASK, row.id)
                .meta(
                    AuditMetadata::new()
                        .id("assignee_user_id", request.user_id)
                        .id("project_id", row.project_id),
                ),
        )
        .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn unassign(
    state: &AppState,
    principal: &Principal,
    ip: &Option<String>,
    id: Uuid,
    user_id: Uuid,
) -> AppResult<()> {
    let mut tx = state.begin().await?;
    let row = repo::find_for_update(&mut tx, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let project = projects::load_context_for_update(&mut tx, row.project_id, principal.user_id())
        .await?
        .ok_or(AppError::NotFound)?;
    let is_assignee = repo::is_active_assignee(&mut tx, id, principal.user_id()).await?;

    state.require(
        principal,
        PERM_ASSIGN,
        &task_target(row.id, project.department_id, is_assignee),
    )?;

    if !repo::remove_assignee(&mut tx, id, user_id).await? {
        return Err(AppError::NotFound);
    }
    state.bump_security_version(&mut tx, user_id).await?;

    state
        .audit(
            &mut tx,
            event(action::TASK_UNASSIGNED, principal, ip)
                .target(TARGET_TASK, row.id)
                .meta(AuditMetadata::new().id("assignee_user_id", user_id)),
        )
        .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn list_assignees(
    state: &AppState,
    principal: &Principal,
    id: Uuid,
) -> AppResult<Vec<TaskAssigneeResponse>> {
    let row = repo::find(&state.db, id).await?.ok_or(AppError::NotFound)?;
    let project = projects::load_context(state, row.project_id, principal.user_id())
        .await?
        .ok_or(AppError::NotFound)?;
    let is_assignee = repo::is_active_assignee_pool(&state.db, id, principal.user_id()).await?;
    state.require(
        principal,
        PERM_READ,
        &task_target(row.id, project.department_id, is_assignee),
    )?;

    Ok(repo::list_assignees(&state.db, id)
        .await?
        .into_iter()
        .map(|a| TaskAssigneeResponse {
            user_id: a.user_id,
            display_name: a.display_name,
            email: a.email,
            assigned_by: a.assigned_by,
            assigned_at: a.assigned_at,
        })
        .collect())
}

// ---------------------------------------------------------------------------
// Client portal
// ---------------------------------------------------------------------------

/// `GET /api/v1/client-portal/projects/{id}/tasks`.
///
/// Two conditions, both in SQL: the task is individually flagged `client_visible`,
/// **and** its project is linked to a client account this principal is an ACTIVE
/// member of. A shared project with no visible tasks returns an empty page, which
/// is the correct answer and not an error — the client is not told that hidden
/// tasks exist.
pub async fn client_list_for_project(
    state: &AppState,
    principal: &Principal,
    project_id: Uuid,
    query: &ClientTaskListQuery,
) -> AppResult<Page<ClientTaskResponse>> {
    let page = PageRequest::resolve(
        &query.page(),
        &[("created_at", "t.created_at")],
        "t.created_at",
        state.config.limits.max_page_size,
    )?;

    if ScopeFilter::build(&principal.actor, PERM_PORTAL_READ, ResourceType::Task).is_none() {
        return Err(AppError::AuthorizationDenied.hide_from_external(principal.is_external()));
    }

    // The project itself must be visible before its task list is even considered,
    // so that an unshared project id is a `404` rather than an empty page — an
    // empty page and a missing project would otherwise be distinguishable only by
    // timing, and the difference is enumerable.
    crate::modules::projects::service::client_get(state, principal, project_id).await?;

    let rows = repo::list_for_client(&state.db, principal.user_id(), project_id, &page).await?;
    let raw = Page::build(rows, &page, |row| repo::to_cursor(row.created_at, row.id));
    let items = raw
        .items
        .into_iter()
        .map(to_client_response)
        .collect::<AppResult<Vec<_>>>()?;
    Ok(Page {
        items,
        next_cursor: raw.next_cursor,
        has_more: raw.has_more,
    })
}

/// `GET /api/v1/client-portal/tasks/{id}`.
pub async fn client_get(
    state: &AppState,
    principal: &Principal,
    id: Uuid,
) -> AppResult<ClientTaskResponse> {
    let row = repo::find_for_client(&state.db, principal.user_id(), id)
        .await?
        .ok_or(AppError::NotFound)?;

    // The row was selected only because the database established both conditions,
    // so `ASSIGNED` is satisfied as a matter of record.
    let target = Target::Resource(
        TargetContext::new(ResourceType::Task, row.id)
            .with_department(None)
            .with_membership(true),
    );
    state.require(principal, PERM_PORTAL_READ, &target)?;

    to_client_response(row)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::authorization::catalog;
    use crate::modules::authorization::domain::PrincipalType;

    #[test]
    fn the_permissions_this_module_uses_are_all_in_the_catalogue() {
        for code in [
            PERM_READ,
            PERM_CREATE,
            PERM_UPDATE,
            PERM_ASSIGN,
            PERM_DELETE,
            PERM_PORTAL_READ,
        ] {
            assert!(
                catalog::exists(code),
                "`{code}` is not a catalogue permission"
            );
        }
    }

    /// The internal task routes need no ad-hoc "is this a client?" check because
    /// the envelope already denies, and `hide_from_external` turns that denial into
    /// a `404`. That only holds while every `tasks.*` code stays INTERNAL-only.
    #[test]
    fn no_internal_task_permission_is_reachable_by_a_client() {
        for code in [
            PERM_READ,
            PERM_CREATE,
            PERM_UPDATE,
            PERM_ASSIGN,
            PERM_DELETE,
        ] {
            assert!(
                !catalog::envelope_permits(code, PrincipalType::Client),
                "`{code}` is reachable by an external principal"
            );
        }
        assert!(catalog::envelope_permits(
            PERM_PORTAL_READ,
            PrincipalType::Client
        ));
    }

    /// An external principal's denial must be indistinguishable from absence.
    #[test]
    fn a_denial_becomes_a_not_found_for_an_external_principal() {
        assert!(matches!(
            AppError::AuthorizationDenied.hide_from_external(true),
            AppError::NotFound
        ));
        assert_eq!(AppError::NotFound.code(), "RESOURCE_NOT_FOUND");
        // ...and stays a 403 inside the company, where existence disclosure is fine.
        assert!(matches!(
            AppError::AuthorizationDenied.hide_from_external(false),
            AppError::AuthorizationDenied
        ));
    }

    #[test]
    fn the_cursor_follows_the_column_being_sorted_on() {
        let row = TaskRow {
            id: Uuid::now_v7(),
            project_id: Uuid::now_v7(),
            title: "t".into(),
            description: String::new(),
            status: "TODO".into(),
            priority: "NORMAL".into(),
            due_date: None,
            client_visible: false,
            internal_note: String::new(),
            version: 1,
            created_by: None,
            created_at: OffsetDateTime::from_unix_timestamp(1_000).expect("instant"),
            updated_at: OffsetDateTime::from_unix_timestamp(2_000).expect("instant"),
            completed_at: None,
        };
        assert_eq!(
            cursor_for(&row, "t.created_at").timestamp_micros,
            1_000_000_000
        );
        assert_eq!(
            cursor_for(&row, "t.updated_at").timestamp_micros,
            2_000_000_000
        );
    }

    #[test]
    fn an_unrecognised_stored_status_or_priority_fails_closed() {
        let mut row = TaskRow {
            id: Uuid::now_v7(),
            project_id: Uuid::now_v7(),
            title: "t".into(),
            description: String::new(),
            status: "ABANDONED".into(),
            priority: "NORMAL".into(),
            due_date: None,
            client_visible: false,
            internal_note: String::new(),
            version: 1,
            created_by: None,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
            completed_at: None,
        };
        assert!(matches!(status_of(&row), Err(AppError::Internal(_))));
        row.status = "TODO".into();
        row.priority = "CRITICAL".into();
        assert!(matches!(priority_of(&row), Err(AppError::Internal(_))));
    }

    /// The target a task is authorised against must carry the *project's*
    /// department, never `None`, or every `DEPARTMENT`-scoped grant would silently
    /// stop covering tasks.
    #[test]
    fn the_task_target_carries_the_projects_department_and_the_real_assignment() {
        let dept = Uuid::now_v7();
        let task = Uuid::now_v7();
        let Target::Resource(ctx) = task_target(task, Some(dept), true) else {
            panic!("a task target is always a resource target");
        };
        assert_eq!(ctx.resource_type, ResourceType::Task);
        assert_eq!(ctx.resource_id, task);
        assert_eq!(ctx.department_id, Some(dept));
        assert!(ctx.actor_is_member);
        assert!(!ctx.is_actor_self, "a task is never a user record");

        let Target::Resource(ctx) = task_target(task, None, false) else {
            panic!()
        };
        assert_eq!(ctx.department_id, None);
        assert!(!ctx.actor_is_member);
    }

    /// The cancellation path must clear `completed_at`, or
    /// `tasks_completion_consistent` turns a business action into a 500.
    #[test]
    fn cancelling_a_finished_task_would_clear_its_completion_timestamp() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let was_done = Some(now - time::Duration::days(2));
        assert_eq!(TaskStatus::Cancelled.completed_at_for(was_done, now), None);
        // (The transition itself is refused — this asserts the timestamp rule
        // independently, so it still holds if the transition table is relaxed.)
        assert!(!TaskStatus::Done.can_transition_to(TaskStatus::Cancelled));
    }
}
