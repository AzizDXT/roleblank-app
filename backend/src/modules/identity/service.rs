//! User lifecycle: read, update, suspend, reactivate, archive.
//!
//! Every mutation in this file follows the same five steps, in this order:
//!
//! ```text
//!   1. open the transaction
//!   2. re-read the subject FOR UPDATE                (closes the TOCTOU window)
//!   3. guard_root                                    (ADR-004 layer 4, before anything else)
//!   4. authorise against the loaded row, then act
//!   5. audit inside the same transaction, then commit
//! ```
//!
//! There is no `delete_user`, no `set_principal_type`, no `grant_role` and no
//! ownership transfer. Their absence is the design (ADR-004): a code path that
//! could legitimately move ownership is a code path that could be abused to steal
//! it.

use uuid::Uuid;

use crate::app::AppState;
use crate::modules::audit::{action, AuditEvent, AuditMetadata, Outcome};
use crate::modules::authorization::domain::{ScopeType, Target, TargetContext};
use crate::modules::authorization::evaluator;
use crate::platform::errors::{AppError, AppResult};
use crate::platform::http::extract::Authenticated;
use crate::shared::pagination::{Page, PageRequest};
use crate::shared::validation as v;

use super::dto::{
    opt_rfc3339, rfc3339, ArchiveUserRequest, ListUsersQuery, ReactivateUserRequest,
    SuspendUserRequest, UpdateUserRequest, UserResponse, UserStatus,
};
use super::repo::{self, UserListFilters, UserRow};

pub const PERM_USERS_READ: &str = "iam.users.read";
pub const PERM_USERS_UPDATE: &str = "iam.users.update";
pub const PERM_USERS_SUSPEND: &str = "iam.users.suspend";
pub const PERM_USERS_ARCHIVE: &str = "iam.users.archive";
pub const PERM_USERS_INVITE: &str = "iam.users.invite";

/// Session revocation reasons, matching the `sessions.revocation_reason` CHECK.
const REASON_SUSPENDED: &str = "USER_SUSPENDED";
const REASON_ARCHIVED: &str = "USER_ARCHIVED";

// =============================================================================
// Lifecycle rules
// =============================================================================

/// The complete set of legal status transitions.
///
/// Written as an explicit matrix rather than as scattered `if` statements, so that
/// the whole policy is visible in one place and testable without a database. Two
/// properties this encodes:
///
/// * **`ARCHIVED` is terminal.** Un-archiving would resurrect an account whose
///   sessions, memberships and access were deliberately ended; if a person returns
///   they get a new account and a new audit trail.
/// * **Nothing returns to `PENDING`.** `PENDING` means "has never been reviewed",
///   and that is not a state an account can re-enter once it has been.
pub fn transition_allowed(from: UserStatus, to: UserStatus) -> bool {
    use UserStatus::*;
    matches!(
        (from, to),
        (Pending, Active)
            | (Pending, Suspended)
            | (Pending, Archived)
            | (Active, Suspended)
            | (Active, Archived)
            | (Suspended, Active)
            | (Suspended, Archived)
    )
}

fn require_transition(from: UserStatus, to: UserStatus) -> AppResult<()> {
    if transition_allowed(from, to) {
        return Ok(());
    }
    Err(AppError::conflict(
        "INVALID_STATUS_TRANSITION",
        format!("An account that is {from} cannot become {to}."),
    ))
}

// =============================================================================
// Projection
// =============================================================================

/// Build the API view of a user.
///
/// Field by field, deliberately. A `From<UserRow>` derive would mean that adding a
/// column to `users` silently adds it to every response.
pub(super) fn user_response(row: &UserRow) -> UserResponse {
    UserResponse {
        id: row.id,
        email: row.email.clone(),
        display_name: row.display_name.clone(),
        principal_type: row.principal_type.clone(),
        status: row.status.clone(),
        mfa_required: row.mfa_required,
        mfa_enrolled: row.mfa_enrolled,
        security_version: row.security_version,
        version: row.version,
        created_at: rfc3339(row.created_at),
        updated_at: rfc3339(row.updated_at),
        activated_at: opt_rfc3339(row.activated_at),
        suspended_at: opt_rfc3339(row.suspended_at),
        archived_at: opt_rfc3339(row.archived_at),
    }
}

fn user_target(actor_id: Uuid, row: &UserRow) -> Target {
    Target::Resource(TargetContext::other_user(actor_id, row.id))
}

// =============================================================================
// Reads
// =============================================================================

/// `GET /api/v1/users`.
///
/// A narrower-than-GLOBAL grant does not authorise "list everything" — it turns
/// the listing into a *filtered query*. The scope is translated into a `WHERE`
/// clause here and the predicate is applied by PostgreSQL; nothing is fetched and
/// then discarded in Rust, which is what makes this endpoint incapable of leaking
/// a row through a filtering bug.
pub async fn list_users(
    state: &AppState,
    principal: &Authenticated,
    query: &ListUsersQuery,
) -> AppResult<Page<UserResponse>> {
    let page_query = query.page();
    let request = PageRequest::resolve(
        &page_query,
        repo::USER_SORTS,
        repo::USER_DEFAULT_SORT,
        state.config.limits.max_page_size,
    )?;

    let mut filters = UserListFilters::default();

    if let Some(raw) = &query.principal_type {
        // Parsed against a closed set; the string never reaches SQL unvalidated.
        let parsed = v::parse_enum(
            "principal_type",
            raw,
            crate::modules::authorization::domain::PrincipalType::parse,
            &["INTERNAL", "CLIENT"],
        )?;
        filters.principal_type = Some(parsed.as_str().to_string());
    }
    if let Some(raw) = &query.status {
        let parsed = v::parse_enum(
            "status",
            raw,
            UserStatus::parse,
            &["PENDING", "ACTIVE", "SUSPENDED", "ARCHIVED"],
        )?;
        filters.status = Some(parsed.as_str().to_string());
    }
    if let Some(raw) = &query.search {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            let bounded = v::required_text("search", trimmed, v::MAX_NAME_LEN)?;
            filters.search = Some(bounded.to_lowercase());
        }
    }

    // Explicit denials narrow the listing whatever the caller's breadth. They are
    // invisible to a `Collection` evaluation — `effective_scopes` strips only GLOBAL
    // denials — so without this a holder of `iam.users.read@GLOBAL` sees users that
    // `GET /users/{id}` refuses them (TH-49). Applied before the branch below so it
    // covers both the broad and the scope-derived path.
    {
        let mut denied_ids: Vec<Uuid> = Vec::new();
        let mut denied_departments: Vec<Uuid> = Vec::new();
        for denial in principal
            .actor
            .denies
            .iter()
            .filter(|d| d.permission_code == PERM_USERS_READ && d.scope.is_coherent())
        {
            match denial.scope.scope_type {
                ScopeType::Own => denied_ids.push(principal.user_id()),
                ScopeType::Resource => {
                    if let (
                        Some(crate::modules::authorization::domain::ResourceType::User),
                        Some(id),
                    ) = (denial.scope.resource_type, denial.scope.resource_id)
                    {
                        denied_ids.push(id);
                    }
                }
                ScopeType::Department => {
                    denied_departments.extend(principal.actor.department_ids.iter().copied());
                }
                // GLOBAL is already total; ASSIGNED names no user record.
                ScopeType::Global | ScopeType::Assigned => {}
            }
        }
        denied_ids.sort_unstable();
        denied_ids.dedup();
        denied_departments.sort_unstable();
        denied_departments.dedup();
        if !denied_ids.is_empty() {
            filters.excluded_ids = Some(denied_ids);
        }
        if !denied_departments.is_empty() {
            filters.excluded_department_ids = Some(denied_departments);
        }
    }

    // `Target::Collection` is covered only by GLOBAL. Anything narrower falls
    // through to the scope-derived predicate below.
    if !state
        .decide(principal, PERM_USERS_READ, &Target::Collection)
        .is_allowed()
    {
        let scopes = evaluator::effective_scopes(&principal.actor, PERM_USERS_READ);

        let has_department = scopes.iter().any(|s| s.scope_type == ScopeType::Department);
        let mut visible_ids: Vec<Uuid> = Vec::new();
        for scope in &scopes {
            match scope.scope_type {
                ScopeType::Own => visible_ids.push(principal.user_id()),
                ScopeType::Resource => {
                    if let (
                        Some(crate::modules::authorization::domain::ResourceType::User),
                        Some(id),
                    ) = (scope.resource_type, scope.resource_id)
                    {
                        visible_ids.push(id);
                    }
                }
                _ => {}
            }
        }

        if has_department {
            // DEPARTMENT and SELF are combined by *choosing the department filter
            // alone* rather than by OR-ing the two predicates. The result can only
            // ever be narrower than the actor's authority, and a filter that is too
            // narrow is a usability complaint whereas one that is too wide is a
            // data leak.
            filters.department_ids = Some(principal.actor.department_ids.clone());
        } else if !visible_ids.is_empty() {
            visible_ids.sort_unstable();
            visible_ids.dedup();
            filters.only_ids = Some(visible_ids);
        } else {
            // No usable scope at all. `require` produces the correctly shaped
            // refusal for this principal type (404 for external, 403 for internal).
            state.require(principal, PERM_USERS_READ, &Target::Collection)?;
        }
    }

    let rows = repo::list_users(&state.db, &request, &filters).await?;
    let sort_column = request.sort_column;
    let page = Page::build(rows, &request, |row| {
        repo::to_cursor(repo::user_sort_value(row, sort_column), row.id)
    });

    Ok(Page {
        items: page.items.iter().map(user_response).collect(),
        next_cursor: page.next_cursor,
        has_more: page.has_more,
    })
}

/// `GET /api/v1/users/{id}`.
pub async fn get_user(
    state: &AppState,
    principal: &Authenticated,
    id: Uuid,
) -> AppResult<UserResponse> {
    // Load first, then authorise against the row. Authorising against the path
    // parameter would be route-level authorisation wearing an object-level costume.
    let row = repo::find_user(&state.db, id)
        .await?
        .ok_or(AppError::NotFound)?;
    state.require(
        principal,
        PERM_USERS_READ,
        &user_target(principal.user_id(), &row),
    )?;
    Ok(user_response(&row))
}

// =============================================================================
// Mutations
// =============================================================================

/// `PATCH /api/v1/users/{id}` — profile fields only.
pub async fn update_user(
    state: &AppState,
    principal: &Authenticated,
    id: Uuid,
    request: UpdateUserRequest,
) -> AppResult<UserResponse> {
    let mut tx = state.begin().await?;
    let row = repo::find_user_for_update(&mut tx, id)
        .await?
        .ok_or(AppError::NotFound)?;

    if repo::is_root(&mut tx, row.id).await? {
        return Err(deny_root(state, tx, principal, row.id, "USER_UPDATE").await);
    }
    state.guard_root(false)?;

    state.require(
        principal,
        PERM_USERS_UPDATE,
        &user_target(principal.user_id(), &row),
    )?;
    state.require_step_up_for(principal, PERM_USERS_UPDATE)?;

    let mut metadata = AuditMetadata::new();

    let display_name = match &request.display_name {
        None => row.display_name.clone(),
        Some(value) => {
            let cleaned = v::required_text("display_name", value, v::MAX_DISPLAY_NAME_LEN)?;
            if cleaned != row.display_name {
                metadata = metadata.changed("display_name");
            }
            cleaned
        }
    };

    let (email, email_normalized) = match &request.email {
        None => (row.email.clone(), row.email_normalized.clone()),
        Some(value) => {
            let normalized = v::validate_email("email", value)?;
            let raw = value.trim().to_string();
            if normalized != row.email_normalized {
                // Duplicate detection is on the normalised form, which is also what
                // the unique index enforces. Comparing raw addresses would let
                // `Alice@x.com` and `alice@x.com` both be created and then collide
                // at the database with an opaque constraint error.
                if let Some(existing) = repo::find_user_by_email(&mut tx, &normalized).await? {
                    if existing.id != row.id {
                        return Err(AppError::conflict(
                            "EMAIL_IN_USE",
                            "Another account already uses this email address.",
                        ));
                    }
                }
                metadata = metadata.changed("email");
            }
            (raw, normalized)
        }
    };

    let affected = repo::update_profile(
        &mut tx,
        row.id,
        &display_name,
        &email,
        &email_normalized,
        request.version,
    )
    .await?;
    if affected == 0 {
        let actual = repo::current_version(&mut tx, row.id)
            .await?
            .unwrap_or(row.version);
        return Err(AppError::VersionConflict {
            expected: request.version,
            actual,
        });
    }

    state
        .audit(
            &mut tx,
            AuditEvent::new(action::USER_UPDATED, Outcome::Success)
                .actor(
                    principal.user_id(),
                    principal.session.principal_type,
                    Some(principal.session.session_id),
                )
                .target("USER", row.id)
                .meta(metadata),
        )
        .await?;

    let updated = repo::find_user_for_update(&mut tx, row.id)
        .await?
        .ok_or_else(|| AppError::internal("user disappeared inside its own transaction"))?;

    tx.commit().await.map_err(AppError::from)?;
    Ok(user_response(&updated))
}

/// `POST /api/v1/users/{id}/suspend`.
///
/// Suspension that leaves existing sessions alive is not suspension, so the
/// revocation happens in the same transaction as the status change. There is no
/// window, and no background job that could fail on its own.
pub async fn suspend_user(
    state: &AppState,
    principal: &Authenticated,
    id: Uuid,
    request: SuspendUserRequest,
) -> AppResult<UserResponse> {
    let reason = v::optional_text("reason", request.reason.as_deref(), v::MAX_REASON_LEN)?;
    change_status(
        state,
        principal,
        id,
        request.version,
        UserStatus::Suspended,
        PERM_USERS_SUSPEND,
        action::USER_SUSPENDED,
        Some(REASON_SUSPENDED),
        &reason,
        "USER_SUSPEND",
    )
    .await
}

/// `POST /api/v1/users/{id}/reactivate`.
pub async fn reactivate_user(
    state: &AppState,
    principal: &Authenticated,
    id: Uuid,
    request: ReactivateUserRequest,
) -> AppResult<UserResponse> {
    change_status(
        state,
        principal,
        id,
        request.version,
        UserStatus::Active,
        PERM_USERS_SUSPEND,
        action::USER_REACTIVATED,
        None,
        "",
        "USER_REACTIVATE",
    )
    .await
}

/// `POST /api/v1/users/{id}/archive`.
///
/// The end of an account's life, and the **only** removal this API offers. There
/// is no `DELETE /users/{id}`: historical references and audit meaning must
/// survive, and the runtime database role holds no `DELETE` grant on `users`
/// regardless of what this code asks for.
pub async fn archive_user(
    state: &AppState,
    principal: &Authenticated,
    id: Uuid,
    request: ArchiveUserRequest,
) -> AppResult<UserResponse> {
    let reason = v::optional_text("reason", request.reason.as_deref(), v::MAX_REASON_LEN)?;
    change_status(
        state,
        principal,
        id,
        request.version,
        UserStatus::Archived,
        PERM_USERS_ARCHIVE,
        action::USER_ARCHIVED,
        Some(REASON_ARCHIVED),
        &reason,
        "USER_ARCHIVE",
    )
    .await
}

/// The shared body of every lifecycle transition.
///
/// One function rather than three near-copies: the ROOT guard, the self-target
/// refusal, the transition matrix, the session revocation and the audit write must
/// be identical for suspend, reactivate and archive, and three copies is three
/// chances for one of them to drift.
#[allow(clippy::too_many_arguments)]
async fn change_status(
    state: &AppState,
    principal: &Authenticated,
    id: Uuid,
    expected_version: i32,
    to: UserStatus,
    permission: &'static str,
    audit_action: &'static str,
    revoke_reason: Option<&str>,
    reason: &str,
    root_context: &'static str,
) -> AppResult<UserResponse> {
    let mut tx = state.begin().await?;
    let row = repo::find_user_for_update(&mut tx, id)
        .await?
        .ok_or(AppError::NotFound)?;

    // ROOT first, before authorisation and before validation. The owner must be
    // refused identically whether the caller is an unprivileged employee, an
    // administrator, or the owner themselves.
    if repo::is_root(&mut tx, row.id).await? {
        return Err(deny_root(state, tx, principal, row.id, root_context).await);
    }
    state.guard_root(false)?;

    // Refused rather than analysed. An actor removing their own access is at best a
    // support ticket and at worst an attacker covering their tracks by suspending
    // the account whose sessions are being investigated.
    if row.id == principal.user_id() {
        return Err(AppError::conflict(
            "SELF_TARGET_REFUSED",
            "You cannot change your own account status.",
        ));
    }

    state.require(
        principal,
        permission,
        &user_target(principal.user_id(), &row),
    )?;
    state.require_step_up_for(principal, permission)?;

    let from = UserStatus::from_row(&row.status)?;
    require_transition(from, to)?;

    let affected = repo::set_status(&mut tx, row.id, to.as_str(), expected_version).await?;
    if affected == 0 {
        let actual = repo::current_version(&mut tx, row.id)
            .await?
            .unwrap_or(row.version);
        return Err(AppError::VersionConflict {
            expected: expected_version,
            actual,
        });
    }

    let mut metadata = AuditMetadata::new()
        .str("from_status", from.as_str())
        .str("to_status", to.as_str());
    if !reason.is_empty() {
        metadata = metadata.str("reason", reason);
    }

    if let Some(revocation_reason) = revoke_reason {
        let revoked = repo::revoke_all_sessions(&mut tx, row.id, revocation_reason).await?;
        metadata = metadata.int("sessions_revoked", revoked as i64);

        if revoked > 0 {
            state
                .audit(
                    &mut tx,
                    AuditEvent::new(action::SESSION_REVOKED_ALL, Outcome::Success)
                        .actor(
                            principal.user_id(),
                            principal.session.principal_type,
                            Some(principal.session.session_id),
                        )
                        .target("USER", row.id)
                        .meta(
                            AuditMetadata::new()
                                .str("reason", revocation_reason)
                                .int("count", revoked as i64),
                        ),
                )
                .await?;
        }
    }

    // A status change alters what this principal may do, so the security version
    // moves with it — that is the signal a client uses to notice its capability set
    // changed, and the invalidation key any future cache must use.
    state.bump_security_version(&mut tx, row.id).await?;

    state
        .audit(
            &mut tx,
            AuditEvent::new(audit_action, Outcome::Success)
                .actor(
                    principal.user_id(),
                    principal.session.principal_type,
                    Some(principal.session.session_id),
                )
                .target("USER", row.id)
                .meta(metadata),
        )
        .await?;

    let updated = repo::find_user_for_update(&mut tx, row.id)
        .await?
        .ok_or_else(|| AppError::internal("user disappeared inside its own transaction"))?;

    tx.commit().await.map_err(AppError::from)?;
    Ok(user_response(&updated))
}

// =============================================================================
// ROOT protection
// =============================================================================

/// Record and return the refusal of an operation that targeted the system owner.
///
/// The audit event is committed even though the operation failed: an attempt on
/// the owner is exactly the signal an intrusion-detection pipeline wants, and
/// rolling it back with the failed transaction would discard it. The transaction
/// is consumed here so no caller can accidentally continue with it.
async fn deny_root(
    state: &AppState,
    mut tx: sqlx::Transaction<'_, sqlx::Postgres>,
    principal: &Authenticated,
    subject_id: Uuid,
    operation: &str,
) -> AppError {
    let event = AuditEvent::new(action::ROOT_PROTECTION_TRIGGERED, Outcome::Denied)
        .actor(
            principal.user_id(),
            principal.session.principal_type,
            Some(principal.session.session_id),
        )
        .target("USER", subject_id)
        .meta(AuditMetadata::new().str("operation", operation));

    let recorded = async {
        state.audit(&mut tx, event).await?;
        tx.commit().await.map_err(AppError::from)
    }
    .await;

    if let Err(e) = recorded {
        tracing::error!(error = %e, "failed to record a ROOT protection event");
    }

    // Inside the company the refusal is deliberately unmistakable: a `403
    // ROOT_PROTECTED` cannot be misdiagnosed as a transient failure, and existence
    // disclosure to an employee is acceptable (docs/backend/04 §10).
    //
    // Across the external trust boundary it is not. `is_root` is checked *before*
    // authorisation, so an external CLIENT that supplies the owner's identifier
    // receives `403` where every other identifier — real or invented — receives
    // `404`. That difference identifies the system owner's user id to a principal
    // that is not permitted to know any internal user exists at all, which is the
    // client envelope (boundary 2 of the threat model) losing to a diagnostic
    // nicety. The envelope wins; the refusal is masked for external principals only.
    //
    // `hide_from_external` is deliberately not used: it maps only
    // `AuthorizationDenied`, and widening it would also mask the refusal on the
    // authorisation routes, where the unmistakable error is the documented and
    // correct answer for the internal principals that can reach them.
    if principal.is_external() {
        AppError::NotFound
    } else {
        AppError::RootProtected
    }
}

/// Remove the system owner from a set of target ids **before** a bulk operation
/// acts on any of them.
///
/// Exposed for every future bulk endpoint. Discovering the owner midway through a
/// batch means part of the batch has already been applied, which is the failure
/// mode ADR-004 layer 4 names explicitly: "select all" must not be able to sweep
/// the owner up.
pub async fn without_root(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ids: &[Uuid],
) -> AppResult<Vec<Uuid>> {
    repo::exclude_root_ids(tx, ids).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The full transition matrix, asserted cell by cell. A change to
    /// `transition_allowed` that widens it fails here rather than in production.
    #[test]
    fn the_status_transition_matrix_is_exactly_as_documented() {
        use UserStatus::*;

        let allowed = [
            (Pending, Active),
            (Pending, Suspended),
            (Pending, Archived),
            (Active, Suspended),
            (Active, Archived),
            (Suspended, Active),
            (Suspended, Archived),
        ];

        for from in UserStatus::ALL {
            for to in UserStatus::ALL {
                let expected = allowed.contains(&(from, to));
                assert_eq!(
                    transition_allowed(from, to),
                    expected,
                    "{from} -> {to} should be {}",
                    if expected { "allowed" } else { "forbidden" }
                );
            }
        }
    }

    /// Archiving is the end. Anything else would resurrect an account whose
    /// sessions, memberships and access were deliberately ended.
    #[test]
    fn archived_is_terminal() {
        for to in UserStatus::ALL {
            assert!(
                !transition_allowed(UserStatus::Archived, to),
                "ARCHIVED -> {to} must be refused"
            );
        }
    }

    #[test]
    fn nothing_ever_returns_to_pending() {
        for from in UserStatus::ALL {
            assert!(
                !transition_allowed(from, UserStatus::Pending),
                "{from} -> PENDING must be refused"
            );
        }
    }

    #[test]
    fn a_status_never_transitions_to_itself() {
        for status in UserStatus::ALL {
            assert!(
                !transition_allowed(status, status),
                "{status} -> {status} must be refused"
            );
        }
    }

    #[test]
    fn a_refused_transition_is_a_conflict_naming_both_states() {
        let err = require_transition(UserStatus::Archived, UserStatus::Active).unwrap_err();
        assert_eq!(err.code(), "INVALID_STATUS_TRANSITION");
        let rendered = format!("{err}");
        assert!(rendered.contains("ARCHIVED"), "{rendered}");
        assert!(rendered.contains("ACTIVE"), "{rendered}");
    }

    #[test]
    fn a_legal_transition_produces_no_error() {
        assert!(require_transition(UserStatus::Active, UserStatus::Suspended).is_ok());
        assert!(require_transition(UserStatus::Suspended, UserStatus::Active).is_ok());
    }

    /// Every permission this module names must exist in the catalogue. A typo would
    /// otherwise become a permanent `DenyUnknownPermission` that reads like a
    /// misconfiguration rather than a bug.
    #[test]
    fn every_permission_used_here_is_in_the_catalogue() {
        use crate::modules::authorization::catalog;
        for code in [
            PERM_USERS_READ,
            PERM_USERS_UPDATE,
            PERM_USERS_SUSPEND,
            PERM_USERS_ARCHIVE,
            PERM_USERS_INVITE,
        ] {
            assert!(
                catalog::exists(code),
                "`{code}` is not a catalogued permission"
            );
        }
        // The permission that must NOT exist: users are archived, never deleted.
        assert!(!catalog::exists("iam.users.delete"));
    }

    #[test]
    fn session_revocation_reasons_match_the_database_check() {
        for reason in [REASON_SUSPENDED, REASON_ARCHIVED] {
            assert!([
                "LOGOUT",
                "LOGOUT_ALL",
                "PASSWORD_CHANGED",
                "PASSWORD_RESET",
                "USER_SUSPENDED",
                "USER_ARCHIVED",
                "ADMIN_REVOKED",
                "REFRESH_REUSE_DETECTED",
                "MFA_RESET",
                "SECURITY_POLICY",
            ]
            .contains(&reason));
        }
    }
}
