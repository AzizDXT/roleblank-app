//! Project business rules: the transaction boundary, the authorisation decision,
//! the audit record, and the invariants.
//!
//! The shape every mutation here follows, without exception:
//!
//! ```text
//! begin -> re-read the row FOR UPDATE -> build the target from the ROW
//!       -> require -> check the version -> mutate -> audit -> commit
//! ```
//!
//! The target is built from the loaded row's real `department_id` and a real
//! membership lookup, never from the path parameter. Authorising against an
//! identifier the caller supplied is route-level authorisation wearing an
//! object-level costume, and it is precisely how BOLA is reintroduced (TH-11).

use time::{Date, OffsetDateTime};
use uuid::Uuid;

use super::dto::{
    AddProjectMemberRequest, ArchiveProjectRequest, ClientProjectListQuery, ClientProjectResponse,
    CreateProjectRequest, ProjectClientLinkResponse, ProjectListQuery, ProjectMemberResponse,
    ProjectResponse, ProjectRole, ProjectStatus, ShareProjectRequest, UpdateProjectRequest,
};
use super::repo::{self, ClientProjectRow, NewProject, ProjectRow, ProjectUpdate};
use super::visibility::ScopeFilter;
use crate::app::AppState;
use crate::modules::audit::{action, AuditEvent, AuditMetadata, Outcome};
use crate::modules::authentication::principal::Principal;
use crate::modules::authorization::domain::{ResourceType, Target, TargetContext};
use crate::platform::errors::{AppError, AppResult};
use crate::shared::pagination::{Cursor, Page, PageRequest};
use crate::shared::validation as v;

pub const PERM_READ: &str = "projects.read";
pub const PERM_CREATE: &str = "projects.create";
pub const PERM_UPDATE: &str = "projects.update";
pub const PERM_ARCHIVE: &str = "projects.archive";
pub const PERM_MEMBERS: &str = "projects.members.manage";
pub const PERM_SHARE: &str = "projects.clients.share";
pub const PERM_PORTAL_READ: &str = "client.portal.projects.read";

const TARGET_PROJECT: &str = "PROJECT";

// ---------------------------------------------------------------------------
// Shared helpers
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

/// Record a refused attempt at a sensitive operation.
///
/// A denial that leaves no trace is an intrusion-detection blind spot: the whole
/// value of recording "who tried what and was refused" is that a probe looks
/// different from ordinary use.
fn denial_event(principal: &Principal, ip: &Option<String>, project_id: Uuid) -> AuditEvent {
    AuditEvent::new(action::AUTHORIZATION_DENIED, Outcome::Denied)
        .actor(
            principal.user_id(),
            principal.session.principal_type,
            Some(principal.session.session_id),
        )
        .target(TARGET_PROJECT, project_id)
        .source_ip(ip.clone())
}

fn status_of(row: &ProjectRow) -> AppResult<ProjectStatus> {
    ProjectStatus::parse(&row.status).ok_or_else(|| {
        // Unparseable state must fail closed and loudly rather than be coerced into
        // the nearest plausible value.
        AppError::Internal("projects.status holds a value outside the catalogue".into())
    })
}

fn to_response(row: ProjectRow) -> AppResult<ProjectResponse> {
    let status = status_of(&row)?;
    Ok(ProjectResponse {
        id: row.id,
        code: row.code,
        name: row.name,
        description: row.description,
        status,
        manager_user_id: row.manager_user_id,
        department_id: row.department_id,
        start_date: row.start_date,
        target_date: row.target_date,
        internal_note: row.internal_note,
        version: row.version,
        created_by: row.created_by,
        created_at: row.created_at,
        updated_at: row.updated_at,
        archived_at: row.archived_at,
        completed_at: row.completed_at,
    })
}

fn to_client_response(row: ClientProjectRow) -> AppResult<ClientProjectResponse> {
    let status = ProjectStatus::parse(&row.status).ok_or_else(|| {
        AppError::Internal("projects.status holds a value outside the catalogue".into())
    })?;
    Ok(ClientProjectResponse {
        id: row.id,
        code: row.code,
        name: row.name,
        description: row.description,
        status,
        start_date: row.start_date,
        target_date: row.target_date,
        completed_at: row.completed_at,
        updated_at: row.updated_at,
    })
}

/// `target_date >= start_date`, mirroring `projects_dates_ordered`.
///
/// Checked here so the caller gets a field-level validation error rather than an
/// opaque `INVARIANT_VIOLATION` from a CHECK constraint.
fn validate_date_order(start: Option<Date>, target: Option<Date>) -> AppResult<()> {
    if let (Some(s), Some(t)) = (start, target) {
        if t < s {
            return Err(AppError::field(
                "target_date",
                "OUT_OF_RANGE",
                "The target date cannot be earlier than the start date.",
            ));
        }
    }
    Ok(())
}

/// Refuse an operation whose subject is not company staff.
///
/// The database enforces the same rule with a trigger, which would surface as an
/// opaque `INVARIANT_VIOLATION`. Checking here turns it into a legible refusal
/// without making the trigger redundant — the trigger is what holds if this code
/// is ever bypassed.
async fn require_internal_user(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
) -> AppResult<()> {
    match repo::user_principal_type(tx, user_id).await?.as_deref() {
        Some("INTERNAL") => Ok(()),
        Some(_) => Err(AppError::conflict(
            "EXTERNAL_PRINCIPAL",
            "Project membership is limited to internal principals.",
        )),
        None => Err(AppError::field(
            "user_id",
            "NOT_FOUND",
            "No active user with that identifier exists.",
        )),
    }
}

/// The facts about a project that an authorisation decision depends on.
///
/// Exposed to the tasks module so it can authorise a task against its project's
/// department without reaching into this module's repository — a module calls
/// another module's service, never its repo.
#[derive(Debug, Clone)]
pub struct ProjectContext {
    pub department_id: Option<Uuid>,
    pub status: ProjectStatus,
    /// Whether the *actor* holds a live membership of this project.
    pub actor_is_member: bool,
}

/// Load a project's authorisation context inside an open transaction, with the row
/// locked, so the department cannot move between the decision and the write.
pub async fn load_context_for_update(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    project_id: Uuid,
    actor_user_id: Uuid,
) -> AppResult<Option<ProjectContext>> {
    let Some(row) = repo::find_for_update(tx, project_id).await? else {
        return Ok(None);
    };
    let actor_is_member = repo::is_active_member(tx, project_id, actor_user_id).await?;
    let status = status_of(&row)?;
    Ok(Some(ProjectContext {
        department_id: row.department_id,
        status,
        actor_is_member,
    }))
}

/// The read-path equivalent of `load_context_for_update`, for endpoints that do
/// not mutate and therefore do not need a row lock.
pub async fn load_context(
    state: &AppState,
    project_id: Uuid,
    actor_user_id: Uuid,
) -> AppResult<Option<ProjectContext>> {
    let Some(row) = repo::find(&state.db, project_id).await? else {
        return Ok(None);
    };
    let actor_is_member = repo::is_active_member_pool(&state.db, project_id, actor_user_id).await?;
    let status = status_of(&row)?;
    Ok(Some(ProjectContext {
        department_id: row.department_id,
        status,
        actor_is_member,
    }))
}

fn cursor_for(row: &ProjectRow, sort_column: &str) -> Cursor {
    // The cursor must carry the value of the column actually being sorted on, or a
    // page boundary compares two different clocks.
    let at = if sort_column == "p.updated_at" {
        row.updated_at
    } else {
        row.created_at
    };
    repo::to_cursor(at, row.id)
}

// ---------------------------------------------------------------------------
// Internal endpoints
// ---------------------------------------------------------------------------

/// `GET /api/v1/projects`.
///
/// The permission gate for a collection is the actor's *scopes*, translated into a
/// `WHERE` clause. `Target::Collection` is covered only by `GLOBAL`, so a narrower
/// grant cannot authorise an unfiltered listing — it produces a filtered query
/// instead. Nothing is fetched and then discarded.
pub async fn list(
    state: &AppState,
    principal: &Principal,
    query: &ProjectListQuery,
) -> AppResult<Page<ProjectResponse>> {
    let status = query.parsed_status()?;
    let page = PageRequest::resolve(
        &query.page(),
        repo::SORTS,
        repo::DEFAULT_SORT,
        state.config.limits.max_page_size,
    )?;

    let Some(filter) = ScopeFilter::build(&principal.actor, PERM_READ, ResourceType::Project)
    else {
        // No grant at all. `hide_from_external` turns this into a 404 for an
        // external principal, which is also what stops an internal-only route from
        // confirming its own existence to the client portal.
        return Err(AppError::AuthorizationDenied.hide_from_external(principal.is_external()));
    };
    if filter.matches_nothing() {
        return Ok(Page::empty());
    }

    let rows = repo::list(
        &state.db,
        principal.user_id(),
        &filter,
        status.map(ProjectStatus::as_str),
        query.department_id,
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

/// `GET /api/v1/projects/{id}`.
pub async fn get(state: &AppState, principal: &Principal, id: Uuid) -> AppResult<ProjectResponse> {
    let row = repo::find(&state.db, id).await?.ok_or(AppError::NotFound)?;
    let is_member = repo::is_active_member_pool(&state.db, id, principal.user_id()).await?;
    let target = Target::Resource(
        TargetContext::new(ResourceType::Project, row.id)
            .with_department(row.department_id)
            .with_membership(is_member),
    );
    state.require(principal, PERM_READ, &target)?;
    to_response(row)
}

/// `POST /api/v1/projects`.
///
/// Authorised against the *requested* department rather than against
/// `Target::Collection`, so a `DEPARTMENT`-scoped creator can create inside their
/// own department and nowhere else. `ASSIGNED` cannot cover a creation, which is
/// correct: nobody is a member of a project that does not exist yet.
pub async fn create(
    state: &AppState,
    principal: &Principal,
    ip: &Option<String>,
    request: CreateProjectRequest,
) -> AppResult<ProjectResponse> {
    let code = v::validate_code("code", &request.code)?;
    let name = v::required_text("name", &request.name, v::MAX_NAME_LEN)?;
    let description = v::optional_text(
        "description",
        request.description.as_deref(),
        v::MAX_LONG_TEXT_LEN,
    )?;
    let internal_note = v::optional_text(
        "internal_note",
        request.internal_note.as_deref(),
        v::MAX_LONG_TEXT_LEN,
    )?;
    validate_date_order(request.start_date, request.target_date)?;

    let id = Uuid::now_v7();
    let target = Target::Resource(
        TargetContext::new(ResourceType::Project, id)
            .with_department(request.department_id)
            .with_membership(false),
    );
    state.require(principal, PERM_CREATE, &target)?;

    let mut tx = state.begin().await?;
    require_internal_user(&mut tx, request.manager_user_id).await?;

    let row = repo::insert(
        &mut tx,
        &NewProject {
            id,
            code,
            name,
            description,
            // Never taken from the request: a project always starts ACTIVE, so a
            // caller cannot create one that is already archived (and therefore
            // invisible to the people who would have reviewed it).
            status: ProjectStatus::Active.as_str(),
            manager_user_id: request.manager_user_id,
            department_id: request.department_id,
            start_date: request.start_date,
            target_date: request.target_date,
            internal_note,
            created_by: principal.user_id(),
        },
    )
    .await?;

    state
        .audit(
            &mut tx,
            event(action::PROJECT_CREATED, principal, ip)
                .target(TARGET_PROJECT, row.id)
                .meta(
                    AuditMetadata::new()
                        .str("code", &row.code)
                        .opt_id("department_id", row.department_id)
                        .id("manager_user_id", row.manager_user_id),
                ),
        )
        .await?;
    tx.commit().await?;

    to_response(row)
}

/// `PATCH /api/v1/projects/{id}`.
pub async fn update(
    state: &AppState,
    principal: &Principal,
    ip: &Option<String>,
    id: Uuid,
    request: UpdateProjectRequest,
) -> AppResult<ProjectResponse> {
    let mut tx = state.begin().await?;
    let row = repo::find_for_update(&mut tx, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let is_member = repo::is_active_member(&mut tx, id, principal.user_id()).await?;

    let target = Target::Resource(
        TargetContext::new(ResourceType::Project, row.id)
            .with_department(row.department_id)
            .with_membership(is_member),
    );
    state.require(principal, PERM_UPDATE, &target)?;

    // The concurrency check comes after authorisation so that a stale version is
    // never used to probe whether a project exists.
    if row.version != request.version {
        return Err(AppError::VersionConflict {
            expected: request.version,
            actual: row.version,
        });
    }

    let current_status = status_of(&row)?;
    let mut meta = AuditMetadata::new();

    let name = match &request.name {
        Some(raw) => {
            meta = meta.changed("name");
            v::required_text("name", raw, v::MAX_NAME_LEN)?
        }
        None => row.name.clone(),
    };
    let description = match &request.description {
        Some(raw) => {
            meta = meta.changed("description");
            v::optional_text("description", Some(raw), v::MAX_LONG_TEXT_LEN)?
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

    let next_status = match &request.status {
        None => current_status,
        Some(raw) => {
            let requested =
                v::parse_enum("status", raw, ProjectStatus::parse, ProjectStatus::ALLOWED)?;
            if requested == ProjectStatus::Archived {
                // Archiving carries its own permission (`projects.archive`).
                // Allowing it through the update path would let `projects.update`
                // alone remove a project from everyone's view.
                return Err(AppError::field(
                    "status",
                    "NOT_ALLOWED",
                    "Use POST /projects/{id}/archive to archive a project.",
                ));
            }
            if !current_status.can_transition_to(requested) {
                return Err(AppError::conflict(
                    "INVALID_STATE_TRANSITION",
                    "This status change is not permitted from the project's current status.",
                ));
            }
            if requested != current_status {
                meta = meta.changed("status");
            }
            requested
        }
    };

    let manager_user_id = match request.manager_user_id {
        Some(new_manager) if new_manager != row.manager_user_id => {
            require_internal_user(&mut tx, new_manager).await?;
            meta = meta.changed("manager_user_id");
            new_manager
        }
        _ => row.manager_user_id,
    };

    let department_id = match request.department_id {
        None => row.department_id,
        Some(requested) if requested == row.department_id => row.department_id,
        Some(requested) => {
            // Moving a project between departments changes who can reach it. The
            // actor must be authorised for the destination as well as for the
            // origin, or a DEPARTMENT-scoped editor could push a project into a
            // department they have no authority over — or pull one out of theirs.
            let destination = Target::Resource(
                TargetContext::new(ResourceType::Project, row.id)
                    .with_department(requested)
                    .with_membership(is_member),
            );
            state.require(principal, PERM_UPDATE, &destination)?;
            meta = meta.changed("department_id");
            requested
        }
    };

    let start_date = request.start_date.unwrap_or(row.start_date);
    let target_date = request.target_date.unwrap_or(row.target_date);
    if request.start_date.is_some() {
        meta = meta.changed("start_date");
    }
    if request.target_date.is_some() {
        meta = meta.changed("target_date");
    }
    validate_date_order(start_date, target_date)?;

    let now = OffsetDateTime::now_utc();
    let patch = ProjectUpdate {
        name,
        description,
        status: next_status.as_str(),
        manager_user_id,
        department_id,
        start_date,
        target_date,
        internal_note,
        // Derived from the status by the one function that knows the rule, so the
        // `projects_archive_consistent` CHECK can never be the thing that discovers
        // an inconsistency.
        archived_at: next_status.archived_at_for(row.archived_at, now),
        completed_at: next_status.completed_at_for(row.completed_at, now),
    };

    let Some(updated) = repo::update(&mut tx, id, request.version, &patch).await? else {
        // The row was locked, so this is unreachable in practice; treating it as a
        // conflict rather than an unwrap keeps a surprising future schema change
        // from becoming a panic.
        return Err(AppError::VersionConflict {
            expected: request.version,
            actual: row.version,
        });
    };

    state
        .audit(
            &mut tx,
            event(action::PROJECT_UPDATED, principal, ip)
                .target(TARGET_PROJECT, updated.id)
                .meta(meta),
        )
        .await?;
    tx.commit().await?;

    to_response(updated)
}

/// `POST /api/v1/projects/{id}/archive`.
pub async fn archive(
    state: &AppState,
    principal: &Principal,
    ip: &Option<String>,
    id: Uuid,
    request: ArchiveProjectRequest,
) -> AppResult<ProjectResponse> {
    let reason = v::optional_text("reason", request.reason.as_deref(), v::MAX_REASON_LEN)?;

    let mut tx = state.begin().await?;
    let row = repo::find_for_update(&mut tx, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let is_member = repo::is_active_member(&mut tx, id, principal.user_id()).await?;
    let target = Target::Resource(
        TargetContext::new(ResourceType::Project, row.id)
            .with_department(row.department_id)
            .with_membership(is_member),
    );
    state.require(principal, PERM_ARCHIVE, &target)?;

    if row.version != request.version {
        return Err(AppError::VersionConflict {
            expected: request.version,
            actual: row.version,
        });
    }

    let current = status_of(&row)?;
    if current == ProjectStatus::Archived {
        return Err(AppError::conflict(
            "ALREADY_ARCHIVED",
            "This project is already archived.",
        ));
    }

    let now = OffsetDateTime::now_utc();
    let patch = ProjectUpdate {
        name: row.name.clone(),
        description: row.description.clone(),
        status: ProjectStatus::Archived.as_str(),
        manager_user_id: row.manager_user_id,
        department_id: row.department_id,
        start_date: row.start_date,
        target_date: row.target_date,
        internal_note: row.internal_note.clone(),
        archived_at: ProjectStatus::Archived.archived_at_for(row.archived_at, now),
        completed_at: ProjectStatus::Archived.completed_at_for(row.completed_at, now),
    };

    let Some(updated) = repo::update(&mut tx, id, request.version, &patch).await? else {
        return Err(AppError::VersionConflict {
            expected: request.version,
            actual: row.version,
        });
    };

    let mut meta = AuditMetadata::new().str("previous_status", current.as_str());
    if !reason.is_empty() {
        meta = meta.str("reason", &reason);
    }
    state
        .audit(
            &mut tx,
            event(action::PROJECT_ARCHIVED, principal, ip)
                .target(TARGET_PROJECT, updated.id)
                .meta(meta),
        )
        .await?;
    tx.commit().await?;

    to_response(updated)
}

// ---------------------------------------------------------------------------
// Members
// ---------------------------------------------------------------------------

pub async fn list_members(
    state: &AppState,
    principal: &Principal,
    id: Uuid,
) -> AppResult<Vec<ProjectMemberResponse>> {
    let row = repo::find(&state.db, id).await?.ok_or(AppError::NotFound)?;
    let is_member = repo::is_active_member_pool(&state.db, id, principal.user_id()).await?;
    let target = Target::Resource(
        TargetContext::new(ResourceType::Project, row.id)
            .with_department(row.department_id)
            .with_membership(is_member),
    );
    state.require(principal, PERM_READ, &target)?;

    repo::list_members(&state.db, id)
        .await?
        .into_iter()
        .map(|m| {
            let role = ProjectRole::parse(&m.role_in_project).ok_or_else(|| {
                AppError::Internal("project_memberships.role_in_project is out of range".into())
            })?;
            Ok(ProjectMemberResponse {
                user_id: m.user_id,
                display_name: m.display_name,
                email: m.email,
                role_in_project: role,
                added_by: m.added_by,
                added_at: m.added_at,
            })
        })
        .collect()
}

pub async fn add_member(
    state: &AppState,
    principal: &Principal,
    ip: &Option<String>,
    id: Uuid,
    request: AddProjectMemberRequest,
) -> AppResult<()> {
    let role = match request.role_in_project.as_deref() {
        None => ProjectRole::Member,
        Some(raw) => v::parse_enum(
            "role_in_project",
            raw,
            ProjectRole::parse,
            ProjectRole::ALLOWED,
        )?,
    };

    let mut tx = state.begin().await?;
    let row = repo::find_for_update(&mut tx, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let is_member = repo::is_active_member(&mut tx, id, principal.user_id()).await?;
    let target = Target::Resource(
        TargetContext::new(ResourceType::Project, row.id)
            .with_department(row.department_id)
            .with_membership(is_member),
    );
    state.require(principal, PERM_MEMBERS, &target)?;

    if status_of(&row)? == ProjectStatus::Archived {
        return Err(AppError::conflict(
            "PROJECT_ARCHIVED",
            "An archived project cannot gain members.",
        ));
    }

    // A trigger refuses an external principal here as well. This check exists so
    // the caller gets a field error rather than an opaque invariant violation.
    require_internal_user(&mut tx, request.user_id).await?;

    if repo::is_active_member(&mut tx, id, request.user_id).await? {
        return Err(AppError::conflict(
            "ALREADY_A_MEMBER",
            "That user is already a member of this project.",
        ));
    }

    repo::add_member(
        &mut tx,
        id,
        request.user_id,
        role.as_str(),
        principal.user_id(),
    )
    .await?;

    // Membership resolves `ASSIGNED` scope, so adding one is a privilege change.
    state
        .bump_security_version(&mut tx, request.user_id)
        .await?;

    state
        .audit(
            &mut tx,
            event(action::PROJECT_MEMBER_ADDED, principal, ip)
                .target(TARGET_PROJECT, row.id)
                .meta(
                    AuditMetadata::new()
                        .id("member_user_id", request.user_id)
                        .str("role_in_project", role.as_str()),
                ),
        )
        .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn remove_member(
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
    let is_member = repo::is_active_member(&mut tx, id, principal.user_id()).await?;
    let target = Target::Resource(
        TargetContext::new(ResourceType::Project, row.id)
            .with_department(row.department_id)
            .with_membership(is_member),
    );
    state.require(principal, PERM_MEMBERS, &target)?;

    if !repo::remove_member(&mut tx, id, user_id).await? {
        return Err(AppError::NotFound);
    }
    state.bump_security_version(&mut tx, user_id).await?;

    state
        .audit(
            &mut tx,
            event(action::PROJECT_MEMBER_REMOVED, principal, ip)
                .target(TARGET_PROJECT, row.id)
                .meta(AuditMetadata::new().id("member_user_id", user_id)),
        )
        .await?;
    tx.commit().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Client sharing — the external trust boundary
// ---------------------------------------------------------------------------

pub async fn list_client_links(
    state: &AppState,
    principal: &Principal,
    id: Uuid,
) -> AppResult<Vec<ProjectClientLinkResponse>> {
    let row = repo::find(&state.db, id).await?.ok_or(AppError::NotFound)?;
    let is_member = repo::is_active_member_pool(&state.db, id, principal.user_id()).await?;
    let target = Target::Resource(
        TargetContext::new(ResourceType::Project, row.id)
            .with_department(row.department_id)
            .with_membership(is_member),
    );
    state.require(principal, PERM_READ, &target)?;

    Ok(repo::list_client_links(&state.db, id)
        .await?
        .into_iter()
        .map(|l| ProjectClientLinkResponse {
            client_account_id: l.client_account_id,
            client_code: l.client_code,
            client_name: l.client_name,
            client_status: l.client_status,
            note: l.note,
            shared_by: l.shared_by,
            shared_at: l.shared_at,
        })
        .collect())
}

/// `POST /api/v1/projects/{id}/clients` — moving company data across the external
/// trust boundary.
///
/// `projects.clients.share` is flagged dangerous in the catalogue, so it demands a
/// recent second factor. That is not a UX nicety: a stolen session with broad
/// project permissions would otherwise be enough to publish a project to an
/// attacker-controlled client account.
pub async fn share_with_client(
    state: &AppState,
    principal: &Principal,
    ip: &Option<String>,
    id: Uuid,
    request: ShareProjectRequest,
) -> AppResult<()> {
    state.require_step_up_for(principal, PERM_SHARE)?;
    let note = v::optional_text("note", request.note.as_deref(), v::MAX_REASON_LEN)?;

    let mut tx = state.begin().await?;
    let row = repo::find_for_update(&mut tx, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let is_member = repo::is_active_member(&mut tx, id, principal.user_id()).await?;
    let target = Target::Resource(
        TargetContext::new(ResourceType::Project, row.id)
            .with_department(row.department_id)
            .with_membership(is_member),
    );

    if let Err(denied) = state.require(principal, PERM_SHARE, &target) {
        let reason = state.decide(principal, PERM_SHARE, &target).reason();
        state
            .audit(
                &mut tx,
                denial_event(principal, ip, row.id).meta(
                    AuditMetadata::new()
                        .str("permission", PERM_SHARE)
                        .str("reason", reason)
                        .id("client_account_id", request.client_account_id),
                ),
            )
            .await?;
        // The denial record must survive the refusal, so the transaction commits.
        tx.commit().await?;
        return Err(denied);
    }

    if status_of(&row)? == ProjectStatus::Archived {
        return Err(AppError::conflict(
            "PROJECT_ARCHIVED",
            "An archived project cannot be shared with a client.",
        ));
    }

    match repo::client_account_status(&mut tx, request.client_account_id)
        .await?
        .as_deref()
    {
        Some("ACTIVE") => {}
        Some(_) => {
            return Err(AppError::conflict(
                "CLIENT_ACCOUNT_NOT_ACTIVE",
                "That client account is not active and cannot receive a share.",
            ))
        }
        None => {
            return Err(AppError::field(
                "client_account_id",
                "NOT_FOUND",
                "No client account with that identifier exists.",
            ))
        }
    }

    repo::share_with_client(
        &mut tx,
        id,
        request.client_account_id,
        &note,
        principal.user_id(),
    )
    .await?;

    state
        .audit(
            &mut tx,
            event(action::PROJECT_SHARED_WITH_CLIENT, principal, ip)
                .target(TARGET_PROJECT, row.id)
                .meta(
                    AuditMetadata::new()
                        .id("client_account_id", request.client_account_id)
                        .str("project_code", &row.code)
                        // Stated explicitly in the record because it is the single
                        // most misunderstood property of sharing.
                        .bool("tasks_included", false),
                ),
        )
        .await?;
    tx.commit().await?;
    Ok(())
}

/// `DELETE /api/v1/projects/{id}/clients/{client_account_id}`.
///
/// Revocation takes effect on the next query the client makes: visibility is
/// derived from the link every time, and there is no cache to invalidate.
pub async fn unshare_from_client(
    state: &AppState,
    principal: &Principal,
    ip: &Option<String>,
    id: Uuid,
    client_account_id: Uuid,
) -> AppResult<()> {
    state.require_step_up_for(principal, PERM_SHARE)?;

    let mut tx = state.begin().await?;
    let row = repo::find_for_update(&mut tx, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let is_member = repo::is_active_member(&mut tx, id, principal.user_id()).await?;
    let target = Target::Resource(
        TargetContext::new(ResourceType::Project, row.id)
            .with_department(row.department_id)
            .with_membership(is_member),
    );

    if let Err(denied) = state.require(principal, PERM_SHARE, &target) {
        let reason = state.decide(principal, PERM_SHARE, &target).reason();
        state
            .audit(
                &mut tx,
                denial_event(principal, ip, row.id).meta(
                    AuditMetadata::new()
                        .str("permission", PERM_SHARE)
                        .str("reason", reason)
                        .id("client_account_id", client_account_id),
                ),
            )
            .await?;
        tx.commit().await?;
        return Err(denied);
    }

    if !repo::unshare_from_client(&mut tx, id, client_account_id, principal.user_id()).await? {
        return Err(AppError::NotFound);
    }

    state
        .audit(
            &mut tx,
            event(action::PROJECT_UNSHARED_FROM_CLIENT, principal, ip)
                .target(TARGET_PROJECT, row.id)
                .meta(AuditMetadata::new().id("client_account_id", client_account_id)),
        )
        .await?;
    tx.commit().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Client portal
// ---------------------------------------------------------------------------

/// `GET /api/v1/client-portal/projects`.
///
/// The visibility predicate is inside the query (layer 4). The permission check
/// that follows is layer 2/3, and it is deliberately not the only thing standing
/// between one client and another's data.
pub async fn client_list(
    state: &AppState,
    principal: &Principal,
    query: &ClientProjectListQuery,
) -> AppResult<Page<ClientProjectResponse>> {
    let page = PageRequest::resolve(
        &query.page(),
        &[("created_at", "p.created_at")],
        "p.created_at",
        state.config.limits.max_page_size,
    )?;

    // Layer 2/3: does this principal hold the portal permission at all? A
    // collection is covered by GLOBAL, and by ASSIGNED once the query itself has
    // established that the rows are ones the actor is linked to — which is what the
    // predicate below does, row by row.
    if ScopeFilter::build(&principal.actor, PERM_PORTAL_READ, ResourceType::Project).is_none() {
        return Err(AppError::AuthorizationDenied.hide_from_external(principal.is_external()));
    }

    let rows = repo::list_for_client(&state.db, principal.user_id(), &page).await?;
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

/// `GET /api/v1/client-portal/projects/{id}`.
///
/// The row is fetched *with* the visibility predicate. A project that exists but is
/// not shared with this principal produces no row and therefore a `404` — never a
/// `403`, which would confirm that the identifier names something real (TH-10).
pub async fn client_get(
    state: &AppState,
    principal: &Principal,
    id: Uuid,
) -> AppResult<ClientProjectResponse> {
    let row = repo::find_for_client(&state.db, principal.user_id(), id)
        .await?
        .ok_or(AppError::NotFound)?;

    // Reaching this point means the database has already established an ACTIVE
    // membership in an ACTIVE client account holding a live link to this project,
    // so `ASSIGNED` is satisfied as a matter of record rather than of assertion.
    let target = Target::Resource(
        TargetContext::new(ResourceType::Project, row.id)
            .with_department(None)
            .with_membership(true),
    );
    state.require(principal, PERM_PORTAL_READ, &target)?;

    to_client_response(row)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn date(y: i32, m: time::Month, d: u8) -> Option<Date> {
        Date::from_calendar_date(y, m, d).ok()
    }

    #[test]
    fn a_target_date_before_the_start_date_is_refused() {
        let start = date(2024, time::Month::June, 1);
        let target = date(2024, time::Month::January, 1);
        let err = validate_date_order(start, target).expect_err("should be refused");
        assert!(matches!(err, AppError::Validation { .. }));

        assert!(
            validate_date_order(start, start).is_ok(),
            "equal dates are fine"
        );
        assert!(validate_date_order(start, date(2024, time::Month::July, 1)).is_ok());
        assert!(
            validate_date_order(None, target).is_ok(),
            "an open start bounds nothing"
        );
        assert!(validate_date_order(start, None).is_ok());
    }

    /// The version-conflict contract: the error reports what the caller sent and
    /// what the row actually holds, so a client can re-read and retry rather than
    /// guess.
    #[test]
    fn a_stale_version_is_reported_with_both_numbers() {
        let err = AppError::VersionConflict {
            expected: 3,
            actual: 7,
        };
        assert_eq!(err.code(), "VERSION_CONFLICT");
        match err {
            AppError::VersionConflict { expected, actual } => {
                assert_eq!(expected, 3);
                assert_eq!(actual, 7);
                assert_ne!(expected, actual);
            }
            other => panic!("expected a version conflict, got {other}"),
        }
    }

    #[test]
    fn the_permissions_this_module_uses_are_all_in_the_catalogue() {
        use crate::modules::authorization::catalog;
        for code in [
            PERM_READ,
            PERM_CREATE,
            PERM_UPDATE,
            PERM_ARCHIVE,
            PERM_MEMBERS,
            PERM_SHARE,
            PERM_PORTAL_READ,
        ] {
            assert!(
                catalog::exists(code),
                "`{code}` is not a catalogue permission"
            );
        }
    }

    /// If sharing ever stopped being dangerous, `require_step_up_for` would become
    /// a no-op and the strongest control on the external boundary would vanish
    /// silently.
    #[test]
    fn sharing_is_and_must_remain_a_dangerous_permission() {
        use crate::modules::authorization::catalog;
        assert!(catalog::is_dangerous(PERM_SHARE));
    }

    /// Every internal permission this module gates on must be out of reach for an
    /// external principal by the envelope alone, so the internal routes need no
    /// second, ad-hoc check.
    #[test]
    fn no_internal_project_permission_is_reachable_by_a_client() {
        use crate::modules::authorization::catalog;
        use crate::modules::authorization::domain::PrincipalType;
        for code in [
            PERM_READ,
            PERM_CREATE,
            PERM_UPDATE,
            PERM_ARCHIVE,
            PERM_MEMBERS,
            PERM_SHARE,
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

    #[test]
    fn the_cursor_follows_the_column_being_sorted_on() {
        let created = OffsetDateTime::from_unix_timestamp(1_000).expect("instant");
        let updated = OffsetDateTime::from_unix_timestamp(2_000).expect("instant");
        let row = ProjectRow {
            id: Uuid::now_v7(),
            code: "c".into(),
            name: "n".into(),
            description: String::new(),
            status: "ACTIVE".into(),
            manager_user_id: Uuid::now_v7(),
            department_id: None,
            start_date: None,
            target_date: None,
            internal_note: String::new(),
            version: 1,
            created_by: None,
            created_at: created,
            updated_at: updated,
            archived_at: None,
            completed_at: None,
        };
        assert_eq!(
            cursor_for(&row, "p.created_at").timestamp_micros,
            1_000_000_000
        );
        assert_eq!(
            cursor_for(&row, "p.updated_at").timestamp_micros,
            2_000_000_000
        );
    }

    #[test]
    fn an_unrecognised_stored_status_fails_closed() {
        let row = ProjectRow {
            id: Uuid::now_v7(),
            code: "c".into(),
            name: "n".into(),
            description: String::new(),
            status: "DELETED".into(),
            manager_user_id: Uuid::now_v7(),
            department_id: None,
            start_date: None,
            target_date: None,
            internal_note: String::new(),
            version: 1,
            created_by: None,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
            archived_at: None,
            completed_at: None,
        };
        assert!(matches!(status_of(&row), Err(AppError::Internal(_))));
    }
}
