//! Departments: transaction boundary, authorisation, audit, invariants.
//!
//! Every mutation in this file follows the same five steps, in this order:
//! open the transaction, load the row `FOR UPDATE`, authorise against the *loaded*
//! row, mutate, audit inside the same transaction. Checking before the transaction
//! opens leaves a window in which the row changes between the decision and the
//! write (TH-43); auditing outside it leaves a state change with no record.

use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::app::AppState;
use crate::modules::audit::{action, AuditEvent, AuditMetadata, Outcome};
use crate::modules::authentication::principal::Principal;
use crate::modules::authorization::domain::{PrincipalType, ResourceType, Target, TargetContext};
use crate::modules::authorization::evaluator;
use crate::platform::errors::{AppError, AppResult};
use crate::shared::pagination::{Cursor, Page, PageQuery, PageRequest};
use crate::shared::validation as v;

use super::dto::{
    AddDepartmentMemberRequest, ArchiveDepartmentRequest, CreateDepartmentRequest,
    DepartmentMemberResponse, DepartmentResponse, DepartmentRole, DepartmentStatus,
    UpdateDepartmentRequest,
};
use super::repo::{self, DepartmentRow, Visibility};

const READ: &str = "departments.read";
const CREATE: &str = "departments.create";
const UPDATE: &str = "departments.update";
const ARCHIVE: &str = "departments.archive";
const MEMBERS_MANAGE: &str = "departments.members.manage";

// ---------------------------------------------------------------------------
// Pure rules — testable without a database, which is why they live here and not
// inline in the flows below.
// ---------------------------------------------------------------------------

/// A department's own id *is* its department for scope purposes: a
/// `departments.read@DEPARTMENT` grant means "the departments I am a member of".
fn target_for(row: &DepartmentRow, actor_is_member: bool) -> Target {
    Target::Resource(
        TargetContext::new(ResourceType::Department, row.id)
            .with_department(Some(row.id))
            .with_membership(actor_is_member),
    )
}

/// Authorise placing *some* user into this department, for callers outside this
/// module.
///
/// Invitations name a `department_id` in the request body, and on acceptance that
/// becomes a real membership — which resolves DEPARTMENT scope and is therefore an
/// authorisation operation no less than `add_member` is. Without this, a principal
/// holding only `iam.users.invite` could mint an account inside a department they
/// cannot manage and read, through an address they control, data their own account
/// is refused (the "escalation by proxy" case in
/// `scripts/exploit_department_placement.sh`).
///
/// The demand is deliberately identical to `add_member`'s — same permission, same
/// target construction, same step-up — because the outcome is identical. It is
/// exposed as a function rather than as public constants so that the scope
/// semantics of a department stay owned by this module.
pub(crate) async fn authorize_placement(
    state: &AppState,
    principal: &Principal,
    tx: &mut Transaction<'_, Postgres>,
    department_id: Uuid,
) -> AppResult<()> {
    let row = repo::find_for_update(tx, department_id)
        .await?
        .ok_or_else(|| {
            AppError::field(
                "department_id",
                "UNKNOWN",
                "That department does not exist.",
            )
        })?;
    let actor_is_member = repo::is_active_member(&mut **tx, row.id, principal.user_id()).await?;
    state.require(
        principal,
        MEMBERS_MANAGE,
        &target_for(&row, actor_is_member),
    )?;
    state.require_step_up_for(principal, MEMBERS_MANAGE)?;
    check_mutable(status_of(&row)?)?;
    Ok(())
}

fn status_of(row: &DepartmentRow) -> AppResult<DepartmentStatus> {
    DepartmentStatus::parse(&row.status)
        .ok_or_else(|| AppError::internal("department row has an unrecognised status"))
}

/// Optimistic concurrency. Returning the actual version lets the client re-read
/// and retry deliberately instead of guessing.
pub fn check_version(expected: i32, actual: i32) -> AppResult<()> {
    if expected == actual {
        Ok(())
    } else {
        Err(AppError::VersionConflict { expected, actual })
    }
}

/// An archived department is read-only. Allowing edits would let membership and
/// leadership drift on a row that no longer resolves any scope.
pub fn check_mutable(status: DepartmentStatus) -> AppResult<()> {
    match status {
        DepartmentStatus::Active => Ok(()),
        DepartmentStatus::Archived => Err(AppError::conflict(
            "DEPARTMENT_ARCHIVED",
            "This department is archived and can no longer be modified.",
        )),
    }
}

/// Archiving is not idempotent on purpose: a second archive of an already
/// archived department would rewrite `archived_at`, destroying the record of when
/// it actually happened.
pub fn check_archivable(status: DepartmentStatus) -> AppResult<()> {
    match status {
        DepartmentStatus::Active => Ok(()),
        DepartmentStatus::Archived => Err(AppError::conflict(
            "DEPARTMENT_ALREADY_ARCHIVED",
            "This department is already archived.",
        )),
    }
}

/// Membership is INTERNAL-only. A database trigger enforces the same rule, but a
/// trigger produces `INVARIANT_VIOLATION` with no field attribution; checking here
/// first turns it into an error the caller can act on. The trigger remains the
/// authority — this is the legible message, not the only barrier.
pub fn check_internal_principal(principal_type: &str) -> AppResult<()> {
    match PrincipalType::parse(principal_type) {
        Some(PrincipalType::Internal) => Ok(()),
        _ => Err(AppError::conflict(
            "PRINCIPAL_TYPE_MISMATCH",
            "Department membership is limited to internal users.",
        )),
    }
}

/// An archived account is gone; adding it to a department would resurrect an
/// organisational fact about someone who has left. `SUSPENDED` is deliberately
/// allowed: suspension is temporary and is enforced at authentication, so keeping
/// the membership is what makes reinstatement a single action rather than an
/// archaeology exercise.
pub fn check_user_joinable(user_status: &str) -> AppResult<()> {
    match user_status {
        "ARCHIVED" => Err(AppError::conflict(
            "USER_ARCHIVED",
            "That user is archived and cannot be added to a department.",
        )),
        _ => Ok(()),
    }
}

/// Archiving must not orphan work. Refusing is the deliberate choice: silently
/// detaching projects would leave rows whose `department_id` still points at an
/// archived unit, and nulling them would destroy the record of which unit owned
/// the work. The operator moves or archives the projects first.
pub fn check_no_live_projects(live: i64) -> AppResult<()> {
    if live == 0 {
        Ok(())
    } else {
        Err(AppError::conflict(
            "DEPARTMENT_HAS_LIVE_PROJECTS",
            "This department still has projects that are not archived. \
             Move or archive them before archiving the department.",
        ))
    }
}

// ---------------------------------------------------------------------------
// Flows
// ---------------------------------------------------------------------------

pub async fn list(
    state: &AppState,
    principal: &Principal,
    query: &PageQuery,
) -> AppResult<Page<DepartmentResponse>> {
    let request = PageRequest::resolve(
        query,
        repo::SORTS,
        repo::DEFAULT_SORT,
        state.config.limits.max_page_size,
    )?;

    // `Target::Collection` is covered only by GLOBAL. Anything narrower does not
    // authorise "list everything" — it authorises a *filtered* listing, and the
    // filter is a SQL predicate rather than a post-fetch loop in Rust.
    let visibility = if state
        .decide(principal, READ, &Target::Collection)
        .is_allowed()
    {
        // Holding the permission at `Collection` is not the end of the decision: a
        // narrow DENY does not appear in a `Collection` evaluation, but it still has
        // to be subtracted, or this listing returns rows that `GET /departments/{id}`
        // refuses (TH-49).
        repo::everything_minus_denials(&principal.actor)
    } else {
        let scopes = evaluator::effective_scopes(&principal.actor, READ);
        repo::visibility_for(&scopes, &principal.actor)
    };

    if matches!(visibility, Visibility::Nothing) {
        // Route the refusal through the standard gate so the denial metric, the log
        // line and the 404-instead-of-403 shaping for external principals all happen
        // in exactly one place.
        state.require(principal, READ, &Target::Collection)?;
        return Ok(Page::empty());
    }

    let rows = repo::list(&state.db, &visibility, &request).await?;
    let page = Page::build(rows, &request, |row| Cursor {
        timestamp_micros: repo::cursor_micros(row.created_at),
        id: row.id,
    });

    let items = page
        .items
        .into_iter()
        .map(to_response)
        .collect::<AppResult<Vec<_>>>()?;
    Ok(Page {
        items,
        next_cursor: page.next_cursor,
        has_more: page.has_more,
    })
}

pub async fn get(
    state: &AppState,
    principal: &Principal,
    id: Uuid,
) -> AppResult<DepartmentResponse> {
    let row = repo::find(&state.db, id).await?.ok_or(AppError::NotFound)?;
    let is_member = repo::is_active_member(&state.db, row.id, principal.user_id()).await?;
    state.require(principal, READ, &target_for(&row, is_member))?;
    to_response(row)
}

pub async fn create(
    state: &AppState,
    principal: &Principal,
    source_ip: Option<String>,
    request: CreateDepartmentRequest,
) -> AppResult<DepartmentResponse> {
    // Validation lives in the service, not the handler, so a direct service call is
    // protected identically to an HTTP one.
    let code = v::validate_code("code", &request.code)?;
    let name = v::required_text("name", &request.name, 150)?;
    let description = v::optional_text(
        "description",
        request.description.as_deref(),
        v::MAX_DESCRIPTION_LEN,
    )?;

    // Creating a department is a collection-level act: there is no row yet to make
    // an object-level decision about, so only a GLOBAL grant reaches it.
    state.require(principal, CREATE, &Target::Collection)?;
    state.require_step_up_for(principal, CREATE)?;

    let mut tx = state.begin().await?;

    if let Some(lead) = request.lead_user_id {
        let user = repo::find_user(&mut *tx, lead).await?.ok_or_else(|| {
            AppError::conflict("UNKNOWN_USER", "The nominated lead does not exist.")
        })?;
        check_internal_principal(&user.principal_type)?;
    }

    let row = repo::insert(
        &mut tx,
        Uuid::now_v7(),
        &code,
        &name,
        &description,
        request.lead_user_id,
        principal.user_id(),
    )
    .await?;

    state
        .audit(
            &mut tx,
            AuditEvent::new(action::DEPARTMENT_CREATED, Outcome::Success)
                .actor(
                    principal.user_id(),
                    principal.session.principal_type,
                    Some(principal.session.session_id),
                )
                .target(ResourceType::Department.as_str(), row.id)
                .source_ip(source_ip)
                .meta(
                    AuditMetadata::new()
                        .str("code", &row.code)
                        .opt_id("lead_user_id", row.lead_user_id),
                ),
        )
        .await?;

    tx.commit().await.map_err(AppError::from)?;
    to_response(row)
}

pub async fn update(
    state: &AppState,
    principal: &Principal,
    source_ip: Option<String>,
    id: Uuid,
    request: UpdateDepartmentRequest,
) -> AppResult<DepartmentResponse> {
    let name = match &request.name {
        None => None,
        Some(raw) => Some(v::required_text("name", raw, 150)?),
    };
    let description = match &request.description {
        None => None,
        Some(raw) => Some(v::optional_text(
            "description",
            Some(raw),
            v::MAX_DESCRIPTION_LEN,
        )?),
    };

    let mut tx = state.begin().await?;
    let row = repo::find_for_update(&mut tx, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let is_member = repo::is_active_member(&mut *tx, row.id, principal.user_id()).await?;
    state.require(principal, UPDATE, &target_for(&row, is_member))?;
    state.require_step_up_for(principal, UPDATE)?;

    check_mutable(status_of(&row)?)?;
    check_version(request.version, row.version)?;

    let set_lead = request.lead_user_id.is_some();
    let lead_user_id = request.lead_user_id.flatten();
    if let Some(lead) = lead_user_id {
        let user = repo::find_user(&mut *tx, lead).await?.ok_or_else(|| {
            AppError::conflict("UNKNOWN_USER", "The nominated lead does not exist.")
        })?;
        check_internal_principal(&user.principal_type)?;
    }

    // The version predicate is repeated in the statement even though the row is
    // locked: defence in depth costs nothing here, and it means the write can never
    // succeed against a version the caller did not see.
    let updated = repo::update(
        &mut tx,
        row.id,
        request.version,
        name.as_deref(),
        description.as_deref(),
        set_lead,
        lead_user_id,
    )
    .await?
    .ok_or(AppError::VersionConflict {
        expected: request.version,
        actual: row.version,
    })?;

    let mut meta = AuditMetadata::new();
    if name.is_some() {
        meta = meta.changed("name");
    }
    if description.is_some() {
        meta = meta.changed("description");
    }
    if set_lead {
        meta = meta
            .changed("lead_user_id")
            .opt_id("lead_user_id", lead_user_id);
    }

    state
        .audit(
            &mut tx,
            AuditEvent::new(action::DEPARTMENT_UPDATED, Outcome::Success)
                .actor(
                    principal.user_id(),
                    principal.session.principal_type,
                    Some(principal.session.session_id),
                )
                .target(ResourceType::Department.as_str(), updated.id)
                .source_ip(source_ip)
                .meta(meta),
        )
        .await?;

    tx.commit().await.map_err(AppError::from)?;
    to_response(updated)
}

pub async fn archive(
    state: &AppState,
    principal: &Principal,
    source_ip: Option<String>,
    id: Uuid,
    request: ArchiveDepartmentRequest,
) -> AppResult<DepartmentResponse> {
    let mut tx = state.begin().await?;
    let row = repo::find_for_update(&mut tx, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let is_member = repo::is_active_member(&mut *tx, row.id, principal.user_id()).await?;
    state.require(principal, ARCHIVE, &target_for(&row, is_member))?;
    state.require_step_up_for(principal, ARCHIVE)?;

    check_archivable(status_of(&row)?)?;
    check_version(request.version, row.version)?;
    check_no_live_projects(repo::count_live_projects(&mut tx, row.id).await?)?;

    let archived = repo::archive(&mut tx, row.id, request.version)
        .await?
        .ok_or(AppError::VersionConflict {
            expected: request.version,
            actual: row.version,
        })?;

    state
        .audit(
            &mut tx,
            AuditEvent::new(action::DEPARTMENT_ARCHIVED, Outcome::Success)
                .actor(
                    principal.user_id(),
                    principal.session.principal_type,
                    Some(principal.session.session_id),
                )
                .target(ResourceType::Department.as_str(), archived.id)
                .source_ip(source_ip)
                .meta(AuditMetadata::new().str("code", &archived.code)),
        )
        .await?;

    tx.commit().await.map_err(AppError::from)?;
    to_response(archived)
}

pub async fn list_members(
    state: &AppState,
    principal: &Principal,
    id: Uuid,
    query: &PageQuery,
) -> AppResult<Page<DepartmentMemberResponse>> {
    let request = PageRequest::resolve(
        query,
        repo::MEMBER_SORTS,
        repo::MEMBER_DEFAULT_SORT,
        state.config.limits.max_page_size,
    )?;

    // Authorised against the loaded department, not the path parameter.
    let row = repo::find(&state.db, id).await?.ok_or(AppError::NotFound)?;
    let is_member = repo::is_active_member(&state.db, row.id, principal.user_id()).await?;
    state.require(principal, READ, &target_for(&row, is_member))?;

    let rows = repo::list_members(&state.db, row.id, &request).await?;
    let page = Page::build(rows, &request, |member| Cursor {
        timestamp_micros: repo::cursor_micros(member.joined_at),
        id: member.id,
    });

    let items = page
        .items
        .into_iter()
        .map(|member| {
            Ok(DepartmentMemberResponse {
                user_id: member.user_id,
                display_name: member.display_name,
                email: member.email,
                role_in_department: DepartmentRole::parse(&member.role_in_department).ok_or_else(
                    || AppError::internal("department membership has an unrecognised role"),
                )?,
                joined_at: member.joined_at,
            })
        })
        .collect::<AppResult<Vec<_>>>()?;
    Ok(Page {
        items,
        next_cursor: page.next_cursor,
        has_more: page.has_more,
    })
}

pub async fn add_member(
    state: &AppState,
    principal: &Principal,
    source_ip: Option<String>,
    id: Uuid,
    request: AddDepartmentMemberRequest,
) -> AppResult<DepartmentMemberResponse> {
    let role = match request.role_in_department.as_deref() {
        None => DepartmentRole::Member,
        Some(raw) => v::parse_enum(
            "role_in_department",
            raw,
            DepartmentRole::parse,
            DepartmentRole::ALLOWED,
        )?,
    };

    let mut tx = state.begin().await?;
    let row = repo::find_for_update(&mut tx, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let actor_is_member = repo::is_active_member(&mut *tx, row.id, principal.user_id()).await?;
    state.require(
        principal,
        MEMBERS_MANAGE,
        &target_for(&row, actor_is_member),
    )?;
    state.require_step_up_for(principal, MEMBERS_MANAGE)?;

    // Department membership resolves DEPARTMENT scope, so it is an authorisation
    // operation — and the delegation guard already refuses one actor to grant
    // *themselves* a role for exactly that reason ("You cannot assign roles to
    // yourself", `delegation.rs`). The same rule has to hold here, or a holder of
    // `departments.members.manage` can walk into any department and self-grant
    // whatever DEPARTMENT-scoped visibility their other permissions imply —
    // `projects.read@DEPARTMENT` over a department they were never placed in.
    //
    // The membership takes effect immediately: `principal` reloads `department_ids`
    // from live rows on every request, so there is no window in which this is
    // pending review.
    if request.user_id == principal.user_id() {
        return Err(AppError::delegation(
            "You cannot add yourself to a department. Ask another administrator.",
        ));
    }

    // ...and no authorisation operation may target the system owner
    // (`docs/backend/04-authorization.md` §6).
    //
    // Checked *after* authorisation, not before. `guard_root` answers
    // `403 ROOT_PROTECTED` while every other subject id on this route answers `404`
    // to an external principal — so running it first turned the endpoint into an
    // oracle that confirmed the owner's user id, and the existence of internal
    // users at all, to a CLIENT that may not know either (threat model boundary 2).
    // Order does not weaken the protection: `require` judges the *actor*, this
    // judges the *subject*, and the subject is still refused. It only stops the
    // system answering a question the caller was never allowed to ask.
    state.guard_root(state.is_root_user(request.user_id).await?)?;

    check_mutable(status_of(&row)?)?;

    let user = repo::find_user(&mut *tx, request.user_id)
        .await?
        .ok_or_else(|| AppError::conflict("UNKNOWN_USER", "That user does not exist."))?;
    check_internal_principal(&user.principal_type)?;
    check_user_joinable(&user.status)?;

    // The department row is held `FOR UPDATE`, so this read and the insert below
    // cannot race another membership change on the same department.
    if repo::is_active_member(&mut *tx, row.id, user.id).await? {
        return Err(AppError::conflict(
            "ALREADY_A_MEMBER",
            "That user is already an active member of this department.",
        ));
    }

    // A fresh row rather than resurrecting the old one: the partial unique index is
    // on `removed_at IS NULL`, so re-adding someone who was removed works and both
    // periods of membership remain in the history.
    let joined_at = repo::insert_membership(
        &mut tx,
        Uuid::now_v7(),
        row.id,
        user.id,
        role.as_str(),
        principal.user_id(),
    )
    .await?;

    // Effective authority just changed for the subject.
    state.bump_security_version(&mut tx, user.id).await?;

    state
        .audit(
            &mut tx,
            AuditEvent::new(action::DEPARTMENT_MEMBER_ADDED, Outcome::Success)
                .actor(
                    principal.user_id(),
                    principal.session.principal_type,
                    Some(principal.session.session_id),
                )
                .target(ResourceType::Department.as_str(), row.id)
                .source_ip(source_ip)
                .meta(
                    AuditMetadata::new()
                        .id("subject_user_id", user.id)
                        .str("role_in_department", role.as_str()),
                ),
        )
        .await?;

    tx.commit().await.map_err(AppError::from)?;

    Ok(DepartmentMemberResponse {
        user_id: user.id,
        display_name: user.display_name,
        email: user.email,
        role_in_department: role,
        joined_at,
    })
}

pub async fn remove_member(
    state: &AppState,
    principal: &Principal,
    source_ip: Option<String>,
    id: Uuid,
    user_id: Uuid,
) -> AppResult<()> {
    let mut tx = state.begin().await?;
    let row = repo::find_for_update(&mut tx, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let actor_is_member = repo::is_active_member(&mut *tx, row.id, principal.user_id()).await?;
    state.require(
        principal,
        MEMBERS_MANAGE,
        &target_for(&row, actor_is_member),
    )?;
    state.require_step_up_for(principal, MEMBERS_MANAGE)?;

    // After authorisation, for the reason spelled out in `add_member`: run first, it
    // identifies the system owner to a caller who may not enumerate users at all.
    state.guard_root(state.is_root_user(user_id).await?)?;

    // Removal stays available on an archived department: taking someone out of a
    // department is only ever a reduction of authority, and blocking it would strand
    // access on a unit nobody can edit.
    if !repo::remove_membership(&mut tx, row.id, user_id).await? {
        return Err(AppError::NotFound);
    }

    state.bump_security_version(&mut tx, user_id).await?;

    state
        .audit(
            &mut tx,
            AuditEvent::new(action::DEPARTMENT_MEMBER_REMOVED, Outcome::Success)
                .actor(
                    principal.user_id(),
                    principal.session.principal_type,
                    Some(principal.session.session_id),
                )
                .target(ResourceType::Department.as_str(), row.id)
                .source_ip(source_ip)
                .meta(AuditMetadata::new().id("subject_user_id", user_id)),
        )
        .await?;

    tx.commit().await.map_err(AppError::from)?;
    Ok(())
}

fn to_response(row: DepartmentRow) -> AppResult<DepartmentResponse> {
    let status = status_of(&row)?;
    Ok(DepartmentResponse {
        id: row.id,
        code: row.code,
        name: row.name,
        description: row.description,
        status,
        lead_user_id: row.lead_user_id,
        version: row.version,
        created_by: row.created_by,
        created_at: row.created_at,
        updated_at: row.updated_at,
        archived_at: row.archived_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stale_version_is_a_conflict_carrying_both_numbers() {
        assert!(check_version(4, 4).is_ok());
        match check_version(3, 7) {
            Err(AppError::VersionConflict { expected, actual }) => {
                assert_eq!((expected, actual), (3, 7));
            }
            other => panic!("expected a version conflict, got {other:?}"),
        }
        // A version from the future is just as stale a belief as one from the past.
        assert!(matches!(
            check_version(9, 7),
            Err(AppError::VersionConflict { .. })
        ));
        assert!(matches!(
            check_version(0, 1),
            Err(AppError::VersionConflict { .. })
        ));
    }

    /// The full transition matrix, valid and invalid.
    #[test]
    fn the_status_transition_matrix_holds() {
        // ACTIVE -> ARCHIVED is the only archive transition there is.
        assert!(check_archivable(DepartmentStatus::Active).is_ok());
        assert!(matches!(
            check_archivable(DepartmentStatus::Archived),
            Err(AppError::Conflict {
                code: "DEPARTMENT_ALREADY_ARCHIVED",
                ..
            })
        ));

        // Edits are permitted only while ACTIVE.
        assert!(check_mutable(DepartmentStatus::Active).is_ok());
        assert!(matches!(
            check_mutable(DepartmentStatus::Archived),
            Err(AppError::Conflict {
                code: "DEPARTMENT_ARCHIVED",
                ..
            })
        ));
    }

    #[test]
    fn membership_is_internal_only() {
        assert!(check_internal_principal("INTERNAL").is_ok());
        for refused in ["CLIENT", "internal", "", "ADMIN", "INTERNAL "] {
            assert!(
                matches!(
                    check_internal_principal(refused),
                    Err(AppError::Conflict {
                        code: "PRINCIPAL_TYPE_MISMATCH",
                        ..
                    })
                ),
                "accepted principal type {refused:?}"
            );
        }
    }

    /// Archiving refuses rather than orphaning. The alternative — detaching the
    /// projects — destroys the record of which unit owned the work.
    #[test]
    fn archiving_refuses_while_live_projects_reference_the_department() {
        assert!(check_no_live_projects(0).is_ok());
        for live in [1, 2, 5_000] {
            assert!(
                matches!(
                    check_no_live_projects(live),
                    Err(AppError::Conflict {
                        code: "DEPARTMENT_HAS_LIVE_PROJECTS",
                        ..
                    })
                ),
                "allowed archiving with {live} live projects"
            );
        }
    }

    #[test]
    fn an_archived_user_cannot_be_added_but_a_suspended_one_can() {
        assert!(matches!(
            check_user_joinable("ARCHIVED"),
            Err(AppError::Conflict {
                code: "USER_ARCHIVED",
                ..
            })
        ));
        for allowed in ["ACTIVE", "SUSPENDED", "PENDING"] {
            assert!(check_user_joinable(allowed).is_ok(), "refused {allowed}");
        }
    }

    #[test]
    fn every_conflict_renders_as_409_and_never_leaks_internals() {
        for err in [
            check_archivable(DepartmentStatus::Archived).unwrap_err(),
            check_mutable(DepartmentStatus::Archived).unwrap_err(),
            check_internal_principal("CLIENT").unwrap_err(),
            check_no_live_projects(1).unwrap_err(),
            check_version(1, 2).unwrap_err(),
        ] {
            assert_eq!(err.status(), axum::http::StatusCode::CONFLICT);
            let rendered = format!("{err}");
            assert!(!rendered.contains("SELECT"), "leaked SQL: {rendered}");
            assert!(
                !rendered.contains("departments "),
                "leaked a table name: {rendered}"
            );
        }
    }
}
