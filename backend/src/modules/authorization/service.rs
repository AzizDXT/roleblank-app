//! Authorization services: the transaction boundary, the authorisation gate, the
//! delegation guard and the audit record for every operation that moves authority.
//!
//! The shape of every authority-changing operation in this file is the same, and
//! it is the shape the whole module exists to make uniform:
//!
//! ```text
//! 1. validate the request body                    (no database, cheap, closed DTO)
//! 2. BEGIN
//! 3. load the SUBJECT row FOR UPDATE              (TH-43: no interleaving)
//! 4. state.require(..)  on a target built from the loaded row
//! 5. state.require_step_up_for(..) when the permission is dangerous
//! 6. delegation::check_*  with subject facts read from the database
//! 7. mutate
//! 8. bump_security_version for every user whose authority moved
//! 9. audit inside the same transaction
//! 10. COMMIT
//! ```
//!
//! A refusal at 4, 5 or 6 is *also* written to the audit log with
//! `Outcome::Denied` and then committed, because a probe against the delegation
//! guard is exactly the event an intrusion-detection feed needs and it must not be
//! rolled back with the failed transaction.
//!
//! ## Why roles are authorised against `Target::Collection`
//!
//! `ResourceType` has no `ROLE` variant, so a role cannot be named by a
//! `RESOURCE`-scoped grant and has no department or membership to resolve
//! `DEPARTMENT`/`ASSIGNED` against. Every role-level decision therefore uses
//! `Target::Collection`, which `evaluator::scope_covers` admits **only** for
//! `GLOBAL`. That is the fail-closed reading: a department-bounded administrator
//! cannot read, author or delete roles, rather than being silently upgraded to
//! global authority over the role catalogue.

use std::collections::HashSet;
use std::time::Duration;

use sqlx::{Postgres, Transaction};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::app::AppState;
use crate::modules::audit::{action, AuditEvent, AuditMetadata, Outcome};
use crate::modules::authentication::principal::{load_actor, Principal};
use crate::modules::authorization::delegation::{self, DelegationRequest, RoleSummary};
use crate::modules::authorization::domain::{
    ActorContext, PrincipalType, ResourceType, Scope, ScopeType, Target, TargetContext,
};
use crate::modules::authorization::{catalog, evaluator, repo};
use crate::platform::errors::{AppError, AppResult};
use crate::shared::pagination::{Cursor, Page, PageQuery, PageRequest};
use crate::shared::validation as v;

use super::dto::*;

// ---------------------------------------------------------------------------
// The permission codes this module enforces
// ---------------------------------------------------------------------------

const PERMISSIONS_READ: &str = "iam.permissions.read";
const PERMISSIONS_DELEGATE: &str = "iam.permissions.delegate";
const ROLES_READ: &str = "iam.roles.read";
const ROLES_CREATE: &str = "iam.roles.create";
const ROLES_UPDATE: &str = "iam.roles.update";
const ROLES_DELETE: &str = "iam.roles.delete";
const ROLES_ASSIGN: &str = "iam.roles.assign";

/// Matches `roles.name`'s `CHECK (length(name) BETWEEN 1 AND 100)`.
const MAX_ROLE_NAME_LEN: usize = 100;
/// Matches `roles.description`'s `CHECK (length(description) <= 500)`.
const MAX_ROLE_DESCRIPTION_LEN: usize = 500;

const TARGET_ROLE: &str = "ROLE";
const TARGET_USER: &str = "USER";

// ---------------------------------------------------------------------------
// Subject facts — always from the database, never from request input
// ---------------------------------------------------------------------------

/// What the delegation guard needs to know about the person being changed.
///
/// Constructed only by `load_subject`, which reads the user row and asks
/// `state.is_root_user`. There is deliberately no constructor taking a
/// `principal_type` or an `is_root` from the caller: a request body that could set
/// either would defeat the client envelope and the ROOT invariant at once (TH-13).
#[derive(Debug, Clone, Copy)]
pub struct SubjectFacts {
    pub id: Uuid,
    pub principal_type: PrincipalType,
    pub is_root: bool,
    /// An archived account may still have authority *removed* — that is cleanup —
    /// but must never have any added.
    pub is_archived: bool,
}

// ---------------------------------------------------------------------------
// Pure helpers — each one is unit-tested below without a database
// ---------------------------------------------------------------------------

fn delegation_request<'a>(
    actor: &'a ActorContext,
    subject: &SubjectFacts,
    has_recent_step_up: bool,
) -> DelegationRequest<'a> {
    DelegationRequest {
        actor,
        subject_id: subject.id,
        subject_principal_type: subject.principal_type,
        subject_is_root: subject.is_root,
        has_recent_step_up,
    }
}

/// `delegation` raises `StepUpRequired { window_seconds: 0 }` because it is a pure
/// module and does not know the deployment's configured window. The HTTP layer
/// does, and a client that is told "verify within 0 seconds" cannot act on it.
fn with_step_up_window(window: Duration, err: AppError) -> AppError {
    match err {
        AppError::StepUpRequired { .. } => AppError::StepUpRequired {
            window_seconds: window.as_secs(),
        },
        other => other,
    }
}

/// The single funnel through which every per-permission delegation decision in
/// this module passes. It adds no logic of its own beyond translating the window.
pub(crate) fn authorise_grant(
    actor: &ActorContext,
    subject: &SubjectFacts,
    has_recent_step_up: bool,
    permission_code: &str,
    requested_scope: Scope,
    step_up_window: Duration,
) -> AppResult<()> {
    let req = delegation_request(actor, subject, has_recent_step_up);
    delegation::check_permission_grant(&req, permission_code, requested_scope)
        .map_err(|e| with_step_up_window(step_up_window, e))
}

pub(crate) fn authorise_role_assignment(
    actor: &ActorContext,
    subject: &SubjectFacts,
    has_recent_step_up: bool,
    role: &RoleSummary,
    step_up_window: Duration,
) -> AppResult<()> {
    let req = delegation_request(actor, subject, has_recent_step_up);
    delegation::check_role_assignment(&req, role)
        .map_err(|e| with_step_up_window(step_up_window, e))
}

pub(crate) fn authorise_role_authoring(
    actor: &ActorContext,
    has_recent_step_up: bool,
    is_system_role: bool,
    allowed_principal_type: PrincipalType,
    permissions: &[(String, Scope)],
    step_up_window: Duration,
) -> AppResult<()> {
    delegation::check_role_authoring(
        actor,
        has_recent_step_up,
        is_system_role,
        allowed_principal_type,
        permissions,
    )
    .map_err(|e| with_step_up_window(step_up_window, e))
}

/// A permission code arriving from a request is checked against the compiled
/// catalogue, never against the database table and never ignored: an unknown code
/// means the caller is probing the authorisation surface
/// (`docs/backend/04-authorization.md` §3).
pub(crate) fn validate_permission_code(field: &'static str, raw: &str) -> AppResult<String> {
    let code = raw.trim();
    if code.is_empty() {
        return Err(AppError::field(
            field,
            "REQUIRED",
            "A permission code is required.",
        ));
    }
    // Bound before the lookup so a megabyte of "code" is not scanned 40 times.
    if code.len() > 100 || !catalog::exists(code) {
        return Err(AppError::UnknownPermission);
    }
    Ok(code.to_string())
}

const ROLE_SCOPES: &[&str] = &["GLOBAL", "DEPARTMENT", "ASSIGNED", "SELF"];
const OVERRIDE_SCOPES: &[&str] = &["GLOBAL", "DEPARTMENT", "ASSIGNED", "SELF", "RESOURCE"];
const RESOURCE_TYPES: &[&str] = &["PROJECT", "TASK", "DEPARTMENT", "CLIENT_ACCOUNT", "USER"];

pub(crate) fn parse_role_scope(raw: &str) -> AppResult<Scope> {
    let scope_type = v::parse_enum("scope", raw, ScopeType::parse, ROLE_SCOPES)?;
    if !scope_type.valid_on_role() {
        return Err(AppError::field(
            "permissions",
            "INVALID_SCOPE",
            "RESOURCE scope can only be used on a per-user override, not on a role.",
        ));
    }
    Ok(Scope::simple(scope_type))
}

pub(crate) fn parse_override_scope(
    raw: &str,
    resource_type: Option<&str>,
    resource_id: Option<Uuid>,
) -> AppResult<Scope> {
    let resource_type = resource_type.map(str::trim).filter(|s| !s.is_empty());
    let scope_type = v::parse_enum("scope", raw, ScopeType::parse, OVERRIDE_SCOPES)?;
    match scope_type {
        ScopeType::Resource => {
            let raw_type = resource_type.ok_or_else(|| {
                AppError::field(
                    "resource_type",
                    "REQUIRED",
                    "RESOURCE scope requires both `resource_type` and `resource_id`.",
                )
            })?;
            let parsed_type = v::parse_enum(
                "resource_type",
                raw_type,
                ResourceType::parse,
                RESOURCE_TYPES,
            )?;
            let id = resource_id.ok_or_else(|| {
                AppError::field(
                    "resource_id",
                    "REQUIRED",
                    "RESOURCE scope requires both `resource_type` and `resource_id`.",
                )
            })?;
            Ok(Scope::resource(parsed_type, id))
        }
        other => {
            // A non-RESOURCE scope carrying an object is incoherent. Rejecting it
            // rather than dropping the extra fields means a caller who believed
            // they were narrowing a grant is told they were not.
            if resource_type.is_some() || resource_id.is_some() {
                return Err(AppError::field(
                    "resource_id",
                    "NOT_ALLOWED",
                    "`resource_type` and `resource_id` are only valid with RESOURCE scope.",
                ));
            }
            Ok(Scope::simple(other))
        }
    }
}

/// Rebuild a stored scope. Corrupt authorisation data fails the operation rather
/// than being interpreted — a grant whose scope cannot be read must never be
/// treated as absent, because "absent" would let it bypass the delegation check.
fn scope_from_row(
    scope_type: &str,
    resource_type: Option<&str>,
    resource_id: Option<Uuid>,
) -> AppResult<Scope> {
    let Some(parsed) = ScopeType::parse(scope_type) else {
        return Err(AppError::internal(
            "stored grant has an unrecognised scope_type",
        ));
    };
    let scope = match parsed {
        ScopeType::Resource => {
            let (Some(rt), Some(rid)) = (resource_type.and_then(ResourceType::parse), resource_id)
            else {
                return Err(AppError::internal(
                    "RESOURCE-scoped grant is missing its object",
                ));
            };
            Scope::resource(rt, rid)
        }
        other => {
            // A non-RESOURCE scope carrying an object contradicts itself. The
            // database `CHECK` forbids it, so reaching this means the row was
            // written around the schema; interpreting it as a plain GLOBAL grant
            // would silently widen it.
            if resource_type.is_some() || resource_id.is_some() {
                return Err(AppError::internal(
                    "stored grant carries an object on a non-RESOURCE scope",
                ));
            }
            Scope::simple(other)
        }
    };
    if !scope.is_coherent() {
        return Err(AppError::internal("stored grant has an incoherent scope"));
    }
    Ok(scope)
}

pub(crate) fn guard_role_deletion(live_assignments: i64) -> AppResult<()> {
    if live_assignments > 0 {
        return Err(AppError::conflict(
            "ROLE_IN_USE",
            "This role is still assigned to at least one user. \
             Remove the assignments before deleting it.",
        ));
    }
    Ok(())
}

pub(crate) fn check_version(expected: i32, actual: i32) -> AppResult<()> {
    if expected != actual {
        return Err(AppError::VersionConflict { expected, actual });
    }
    Ok(())
}

pub(crate) fn validate_role_permissions(
    items: &[RolePermissionInput],
) -> AppResult<Vec<(String, Scope)>> {
    v::validate_array_len("permissions", items, v::MAX_ARRAY_LEN)?;
    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let code = validate_permission_code("permissions", &item.permission_code)?;
        let scope = parse_role_scope(&item.scope)?;
        // `role_permissions` is keyed on (role_id, permission_code), so a duplicate
        // would either be a primary-key violation rendered as an opaque 409 or, if
        // the key ever changed, a role holding one permission at two scopes.
        if !seen.insert(code.clone()) {
            return Err(AppError::field(
                "permissions",
                "DUPLICATE",
                "Each permission may appear at most once in a role.",
            ));
        }
        out.push((code, scope));
    }
    Ok(out)
}

fn parse_expiry(raw: Option<&str>) -> AppResult<Option<OffsetDateTime>> {
    let Some(raw) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let at = OffsetDateTime::parse(raw, &Rfc3339).map_err(|_| {
        AppError::field(
            "expires_at",
            "INVALID_FORMAT",
            "Must be an RFC 3339 timestamp.",
        )
    })?;
    // An override that is already expired is not a grant, it is a misunderstanding.
    if at <= OffsetDateTime::now_utc() {
        return Err(AppError::field(
            "expires_at",
            "OUT_OF_RANGE",
            "Must be in the future.",
        ));
    }
    Ok(Some(at))
}

/// RFC 3339 for the wire. Formatting can only fail for years outside the format's
/// range, which no column here can hold; an empty string is still preferable to a
/// panic in a response path.
fn rfc3339(at: OffsetDateTime) -> String {
    at.format(&Rfc3339).unwrap_or_default()
}

fn cursor_of(id: Uuid, at: OffsetDateTime) -> Cursor {
    Cursor {
        timestamp_micros: (at.unix_timestamp_nanos() / 1_000) as i64,
        id,
    }
}

fn principal_type_of(raw: &str) -> AppResult<PrincipalType> {
    PrincipalType::parse(raw)
        .ok_or_else(|| AppError::internal("user row has an unrecognised principal_type"))
}

// ---------------------------------------------------------------------------
// Audit helpers
// ---------------------------------------------------------------------------

fn event(
    principal: &Principal,
    ip: Option<String>,
    action_code: &'static str,
    outcome: Outcome,
) -> AuditEvent {
    AuditEvent::new(action_code, outcome)
        .actor(
            principal.user_id(),
            principal.session.principal_type,
            Some(principal.session.session_id),
        )
        .source_ip(ip)
}

/// A refusal targeting ROOT is recorded under its own action so it is trivially
/// alertable; everything else is an ordinary authorisation denial.
fn denial_action(err: &AppError) -> &'static str {
    match err {
        AppError::RootProtected => action::ROOT_PROTECTION_TRIGGERED,
        _ => action::AUTHORIZATION_DENIED,
    }
}

/// Record a refused sensitive operation, **commit the record**, and hand the
/// original error back unchanged.
///
/// The commit is the point. Returning the error without committing would roll the
/// audit row back together with the transaction it was written in, and the system
/// would forget every probe it refused.
async fn refuse(
    state: &AppState,
    mut tx: Transaction<'_, Postgres>,
    principal: &Principal,
    ip: Option<String>,
    operation: &'static str,
    target: Option<(&'static str, Uuid)>,
    err: AppError,
) -> AppError {
    let mut denial = event(principal, ip, denial_action(&err), Outcome::Denied).meta(
        AuditMetadata::new()
            // `err.code()` is the stable machine identifier, never user-supplied
            // text — an audit record must not be a log-injection surface.
            .str("operation", operation)
            .str("reason", err.code()),
    );
    if let Some((target_type, target_id)) = target {
        denial = denial.target(target_type, target_id);
    }

    if let Err(audit_err) = state.audit(&mut tx, denial).await {
        tracing::error!(error = %audit_err, operation, "failed to record an authorisation denial");
        return err;
    }
    if let Err(commit_err) = tx.commit().await {
        tracing::error!(error = %commit_err, operation, "failed to commit an authorisation denial");
    }
    err
}

// ---------------------------------------------------------------------------
// GET /api/v1/permissions
// ---------------------------------------------------------------------------

/// The catalogue, served from `catalog::PERMISSIONS` rather than from the
/// `permissions` table.
///
/// The two are verified identical at startup, but if they ever diverge the code
/// table is the one that is actually enforced, and an administrator reading this
/// endpoint must see what the evaluator will do — not what a row says it should do.
pub fn permission_catalogue(
    state: &AppState,
    principal: &Principal,
) -> AppResult<PermissionCatalogueResponse> {
    state.require(principal, PERMISSIONS_READ, &Target::Collection)?;
    Ok(PermissionCatalogueResponse {
        items: catalog::PERMISSIONS
            .iter()
            .map(|def| PermissionResponse {
                code: def.code,
                module: def.module,
                max_principal_type: def.max_principal_type.as_str(),
                is_dangerous: def.is_dangerous,
            })
            .collect(),
    })
}

// ---------------------------------------------------------------------------
// Roles — reads
// ---------------------------------------------------------------------------

fn role_summary_response(row: repo::RoleRow) -> RoleSummaryResponse {
    RoleSummaryResponse {
        id: row.id,
        code: row.code,
        name: row.name,
        description: row.description,
        is_system: row.is_system,
        allowed_principal_type: row.allowed_principal_type,
        version: row.version,
        created_at: rfc3339(row.created_at),
        updated_at: rfc3339(row.updated_at),
    }
}

pub async fn list_roles(
    state: &AppState,
    principal: &Principal,
    query: &PageQuery,
) -> AppResult<Page<RoleSummaryResponse>> {
    state.require(principal, ROLES_READ, &Target::Collection)?;
    let page = PageRequest::resolve(
        query,
        repo::ROLE_SORTS,
        repo::ROLE_DEFAULT_SORT,
        state.config.limits.max_page_size,
    )?;
    let rows = repo::list_roles(&state.db, &page).await?;
    let built = Page::build(rows, &page, |r| cursor_of(r.id, r.created_at));
    Ok(Page {
        items: built.items.into_iter().map(role_summary_response).collect(),
        next_cursor: built.next_cursor,
        has_more: built.has_more,
    })
}

pub async fn get_role(
    state: &AppState,
    principal: &Principal,
    role_id: Uuid,
) -> AppResult<RoleDetailResponse> {
    // Load first, decide second (MODULE_GUIDE §3.1). For an external principal
    // `require` renders as 404, so authorising after the read discloses nothing.
    let role = repo::find_role(&state.db, role_id)
        .await?
        .ok_or(AppError::NotFound)?;
    state.require(principal, ROLES_READ, &Target::Collection)?;
    let permissions = repo::role_permissions(&state.db, role.id).await?;
    Ok(detail_response(role, permissions))
}

fn detail_response(
    role: repo::RoleRow,
    permissions: Vec<repo::RolePermissionRow>,
) -> RoleDetailResponse {
    RoleDetailResponse {
        role: role_summary_response(role),
        permissions: permissions
            .into_iter()
            .map(|p| RoleGrantResponse {
                permission_code: p.permission_code,
                scope: p.scope_type,
            })
            .collect(),
    }
}

/// Assemble the delegation guard's view of a role from its stored rows.
async fn role_summary_for_delegation(
    tx: &mut Transaction<'_, Postgres>,
    role: &repo::RoleRow,
) -> AppResult<(RoleSummary, Vec<repo::RolePermissionRow>)> {
    let rows = repo::role_permissions(&mut **tx, role.id).await?;
    let mut permissions = Vec::with_capacity(rows.len());
    for row in &rows {
        // No `resource_type`/`resource_id` columns exist on `role_permissions`, so a
        // stored RESOURCE scope would be incoherent and `scope_from_row` refuses it.
        let scope = scope_from_row(&row.scope_type, None, None)?;
        permissions.push((row.permission_code.clone(), scope));
    }
    Ok((
        RoleSummary {
            id: role.id,
            code: role.code.clone(),
            is_system: role.is_system,
            allowed_principal_type: principal_type_of(&role.allowed_principal_type)?,
            permissions,
        },
        rows,
    ))
}

// ---------------------------------------------------------------------------
// POST /api/v1/roles
// ---------------------------------------------------------------------------

pub async fn create_role(
    state: &AppState,
    principal: &Principal,
    ip: Option<String>,
    request: CreateRoleRequest,
) -> AppResult<RoleDetailResponse> {
    let code = v::validate_role_code("code", &request.code)?;
    let name = v::required_text("name", &request.name, MAX_ROLE_NAME_LEN)?;
    let description = v::optional_text(
        "description",
        request.description.as_deref(),
        MAX_ROLE_DESCRIPTION_LEN,
    )?;
    let allowed_principal_type = v::parse_enum(
        "allowed_principal_type",
        &request.allowed_principal_type,
        PrincipalType::parse,
        &["INTERNAL", "CLIENT"],
    )?;
    let permissions = validate_role_permissions(&request.permissions)?;

    let step_up = principal.has_recent_step_up(state.config.sessions.step_up_window);
    let window = state.config.sessions.step_up_window;

    let mut tx = state.begin().await?;

    if let Err(e) = state.require(principal, ROLES_CREATE, &Target::Collection) {
        return Err(refuse(state, tx, principal, ip, "role.create", None, e).await);
    }
    // `is_system` is hard-coded false: the API has no path to authoring a built-in
    // role, and `check_role_authoring` would refuse one anyway.
    if let Err(e) = authorise_role_authoring(
        &principal.actor,
        step_up,
        false,
        allowed_principal_type,
        &permissions,
        window,
    ) {
        return Err(refuse(state, tx, principal, ip, "role.create", None, e).await);
    }

    let role_id = Uuid::now_v7();
    let role = repo::insert_role(
        &mut tx,
        role_id,
        &code,
        &name,
        &description,
        allowed_principal_type.as_str(),
        principal.user_id(),
    )
    .await?;

    for (permission_code, scope) in &permissions {
        repo::insert_role_permission(
            &mut tx,
            role.id,
            permission_code,
            scope.scope_type.as_str(),
            principal.user_id(),
        )
        .await?;
    }

    state
        .audit(
            &mut tx,
            event(principal, ip, action::ROLE_CREATED, Outcome::Success)
                .target(TARGET_ROLE, role.id)
                .meta(
                    AuditMetadata::new()
                        .str("role_code", &role.code)
                        .str("allowed_principal_type", allowed_principal_type.as_str())
                        .list(
                            "permissions",
                            permissions
                                .iter()
                                .map(|(c, s)| format!("{c}@{}", s.scope_type.as_str())),
                        ),
                ),
        )
        .await?;

    let rows = repo::role_permissions(&mut *tx, role.id).await?;
    tx.commit().await?;
    Ok(detail_response(role, rows))
}

// ---------------------------------------------------------------------------
// PATCH /api/v1/roles/{id}
// ---------------------------------------------------------------------------

pub async fn update_role(
    state: &AppState,
    principal: &Principal,
    ip: Option<String>,
    role_id: Uuid,
    request: UpdateRoleRequest,
) -> AppResult<RoleDetailResponse> {
    let requested_permissions = match &request.permissions {
        Some(items) => Some(validate_role_permissions(items)?),
        None => None,
    };

    let step_up = principal.has_recent_step_up(state.config.sessions.step_up_window);
    let window = state.config.sessions.step_up_window;

    let mut tx = state.begin().await?;
    let Some(role) = repo::find_role_for_update(&mut tx, role_id).await? else {
        return Err(AppError::NotFound);
    };

    if let Err(e) = state.require(principal, ROLES_UPDATE, &Target::Collection) {
        return Err(refuse(
            state,
            tx,
            principal,
            ip,
            "role.update",
            Some((TARGET_ROLE, role.id)),
            e,
        )
        .await);
    }

    let (summary, existing_rows) = role_summary_for_delegation(&mut tx, &role).await?;
    // When the permission set is not being replaced, the authoring check still runs
    // against the *existing* contents: renaming a role you could not have authored
    // is still an act of authority over it, and this is what refuses `is_system`
    // roles for everyone including ROOT.
    let effective_permissions = requested_permissions
        .clone()
        .unwrap_or_else(|| summary.permissions.clone());
    if let Err(e) = authorise_role_authoring(
        &principal.actor,
        step_up,
        role.is_system,
        summary.allowed_principal_type,
        &effective_permissions,
        window,
    ) {
        return Err(refuse(
            state,
            tx,
            principal,
            ip,
            "role.update",
            Some((TARGET_ROLE, role.id)),
            e,
        )
        .await);
    }

    check_version(request.version, role.version)?;

    let name = match &request.name {
        Some(n) => v::required_text("name", n, MAX_ROLE_NAME_LEN)?,
        None => role.name.clone(),
    };
    let description = match &request.description {
        Some(d) => v::optional_text("description", Some(d), MAX_ROLE_DESCRIPTION_LEN)?,
        None => role.description.clone(),
    };

    // The guarded UPDATE is the real concurrency control; the check above only
    // produces the better error message. Zero rows here means someone committed
    // between the lock and now, which cannot happen while we hold it — so a `None`
    // is a genuine conflict and never an overwrite.
    let Some(updated) =
        repo::update_role(&mut tx, role.id, request.version, &name, &description).await?
    else {
        return Err(AppError::VersionConflict {
            expected: request.version,
            actual: role.version,
        });
    };

    let mut metadata = AuditMetadata::new().str("role_code", &updated.code);
    if request.name.is_some() {
        metadata = metadata.changed("name");
    }
    if request.description.is_some() {
        metadata = metadata.changed("description");
    }

    let final_rows = match &requested_permissions {
        None => existing_rows,
        Some(permissions) => {
            repo::delete_role_permissions(&mut tx, updated.id).await?;
            for (permission_code, scope) in permissions {
                repo::insert_role_permission(
                    &mut tx,
                    updated.id,
                    permission_code,
                    scope.scope_type.as_str(),
                    principal.user_id(),
                )
                .await?;
            }
            metadata = metadata.changed("permissions").list(
                "permissions",
                permissions
                    .iter()
                    .map(|(c, s)| format!("{c}@{}", s.scope_type.as_str())),
            );

            // Changing a role's contents changes the effective authority of every
            // holder, so each of them gets a security-version bump.
            let holders = repo::role_holder_ids(&mut tx, updated.id).await?;
            metadata = metadata.int("holders_affected", holders.len() as i64);
            for holder in holders {
                state.bump_security_version(&mut tx, holder).await?;
            }

            repo::role_permissions(&mut *tx, updated.id).await?
        }
    };

    state
        .audit(
            &mut tx,
            event(principal, ip, action::ROLE_UPDATED, Outcome::Success)
                .target(TARGET_ROLE, updated.id)
                .meta(metadata),
        )
        .await?;
    tx.commit().await?;
    Ok(detail_response(updated, final_rows))
}

// ---------------------------------------------------------------------------
// DELETE /api/v1/roles/{id}
// ---------------------------------------------------------------------------

pub async fn delete_role(
    state: &AppState,
    principal: &Principal,
    ip: Option<String>,
    role_id: Uuid,
) -> AppResult<()> {
    let step_up = principal.has_recent_step_up(state.config.sessions.step_up_window);
    let window = state.config.sessions.step_up_window;

    let mut tx = state.begin().await?;
    let Some(role) = repo::find_role_for_update(&mut tx, role_id).await? else {
        return Err(AppError::NotFound);
    };

    if let Err(e) = state.require(principal, ROLES_DELETE, &Target::Collection) {
        return Err(refuse(
            state,
            tx,
            principal,
            ip,
            "role.delete",
            Some((TARGET_ROLE, role.id)),
            e,
        )
        .await);
    }

    let (summary, _) = role_summary_for_delegation(&mut tx, &role).await?;
    // Refuses `is_system` for everyone including ROOT, and refuses deleting a role
    // whose contents the actor could not have authored — you may not dispose of
    // authority you were never able to grant.
    if let Err(e) = authorise_role_authoring(
        &principal.actor,
        step_up,
        role.is_system,
        summary.allowed_principal_type,
        &summary.permissions,
        window,
    ) {
        return Err(refuse(
            state,
            tx,
            principal,
            ip,
            "role.delete",
            Some((TARGET_ROLE, role.id)),
            e,
        )
        .await);
    }

    // The assignment count is read inside the transaction with the role row locked,
    // so "zero holders" cannot become "one holder" between the check and the delete.
    let assignments = repo::count_role_assignments(&mut tx, role.id).await?;
    guard_role_deletion(assignments)?;

    repo::delete_role_permissions(&mut tx, role.id).await?;
    if repo::delete_role(&mut tx, role.id).await? == 0 {
        // Only reachable if the row is `is_system`, which the guard above already
        // refused. Fail closed rather than report a deletion that did not happen.
        return Err(AppError::delegation(
            "Built-in system roles cannot be modified or deleted.",
        ));
    }

    state
        .audit(
            &mut tx,
            event(principal, ip, action::ROLE_DELETED, Outcome::Success)
                .target(TARGET_ROLE, role.id)
                .meta(AuditMetadata::new().str("role_code", &role.code)),
        )
        .await?;
    tx.commit().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Subject loading
// ---------------------------------------------------------------------------

/// Load and lock the subject, and establish whether they are the system owner.
///
/// `is_root` comes from `system_ownership` via `state.is_root_user`, which is the
/// only authority on the question. Ownership is immutable, so reading it outside
/// the transaction cannot go stale.
async fn load_locked_subject(
    state: &AppState,
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
) -> AppResult<SubjectFacts> {
    let Some(row) = repo::lock_user(tx, user_id).await? else {
        return Err(AppError::NotFound);
    };
    Ok(SubjectFacts {
        id: row.id,
        principal_type: principal_type_of(&row.principal_type)?,
        is_root: state.is_root_user(row.id).await?,
        is_archived: row.status == "ARCHIVED",
    })
}

/// Adding authority to a closed account is never a legitimate operation, and an
/// archived account that quietly accumulates grants is exactly what a dormant
/// backdoor looks like.
fn guard_grant_to_archived(subject: &SubjectFacts) -> AppResult<()> {
    if subject.is_archived {
        return Err(AppError::conflict(
            "SUBJECT_ARCHIVED",
            "Authority cannot be granted to an archived account.",
        ));
    }
    Ok(())
}

/// The object-level target for an operation on a person.
fn user_target(actor_id: Uuid, subject_id: Uuid) -> Target {
    Target::Resource(TargetContext::other_user(actor_id, subject_id))
}

// ---------------------------------------------------------------------------
// GET /api/v1/users/{id}/roles
// ---------------------------------------------------------------------------

pub async fn list_user_roles(
    state: &AppState,
    principal: &Principal,
    user_id: Uuid,
) -> AppResult<UserRolesResponse> {
    let subject = repo::find_user(&state.db, user_id)
        .await?
        .ok_or(AppError::NotFound)?;
    state.require(
        principal,
        ROLES_READ,
        &user_target(principal.user_id(), subject.id),
    )?;
    let rows = repo::list_user_roles(&state.db, subject.id).await?;
    Ok(UserRolesResponse {
        user_id: subject.id,
        items: rows
            .into_iter()
            .map(|r| UserRoleResponse {
                role_id: r.role_id,
                code: r.code,
                name: r.name,
                is_system: r.is_system,
                allowed_principal_type: r.allowed_principal_type,
                granted_by: r.granted_by,
                granted_at: rfc3339(r.granted_at),
            })
            .collect(),
    })
}

// ---------------------------------------------------------------------------
// POST /api/v1/users/{id}/roles
// ---------------------------------------------------------------------------

pub async fn assign_role(
    state: &AppState,
    principal: &Principal,
    ip: Option<String>,
    user_id: Uuid,
    request: AssignRoleRequest,
) -> AppResult<UserRolesResponse> {
    let step_up = principal.has_recent_step_up(state.config.sessions.step_up_window);
    let window = state.config.sessions.step_up_window;

    let mut tx = state.begin().await?;
    let subject = load_locked_subject(state, &mut tx, user_id).await?;
    let target = user_target(principal.user_id(), subject.id);

    if let Err(e) = state.require(principal, ROLES_ASSIGN, &target) {
        return Err(refuse(
            state,
            tx,
            principal,
            ip,
            "role.assign",
            Some((TARGET_USER, subject.id)),
            e,
        )
        .await);
    }
    // `iam.roles.assign` is dangerous, so the endpoint itself needs a recent
    // second factor even before any single permission inside the role is examined.
    if let Err(e) = state.require_step_up_for(principal, ROLES_ASSIGN) {
        return Err(refuse(
            state,
            tx,
            principal,
            ip,
            "role.assign",
            Some((TARGET_USER, subject.id)),
            e,
        )
        .await);
    }

    let Some(role) = repo::find_role(&mut *tx, request.role_id).await? else {
        return Err(AppError::NotFound);
    };
    let (summary, _) = role_summary_for_delegation(&mut tx, &role).await?;

    if let Err(e) = authorise_role_assignment(&principal.actor, &subject, step_up, &summary, window)
    {
        return Err(refuse(
            state,
            tx,
            principal,
            ip,
            "role.assign",
            Some((TARGET_USER, subject.id)),
            e,
        )
        .await);
    }

    guard_grant_to_archived(&subject)?;

    if repo::assignment_exists(&mut tx, subject.id, role.id).await? {
        return Err(AppError::conflict(
            "ROLE_ALREADY_ASSIGNED",
            "This user already holds that role.",
        ));
    }

    repo::insert_role_assignment(
        &mut tx,
        Uuid::now_v7(),
        subject.id,
        role.id,
        principal.user_id(),
    )
    .await?;
    state.bump_security_version(&mut tx, subject.id).await?;

    state
        .audit(
            &mut tx,
            event(principal, ip, action::ROLE_ASSIGNED, Outcome::Success)
                .target(TARGET_USER, subject.id)
                .meta(
                    AuditMetadata::new()
                        .id("role_id", role.id)
                        .str("role_code", &role.code)
                        .str("subject_principal_type", subject.principal_type.as_str()),
                ),
        )
        .await?;

    let rows = repo::list_user_roles(&mut *tx, subject.id).await?;
    tx.commit().await?;
    Ok(UserRolesResponse {
        user_id: subject.id,
        items: rows
            .into_iter()
            .map(|r| UserRoleResponse {
                role_id: r.role_id,
                code: r.code,
                name: r.name,
                is_system: r.is_system,
                allowed_principal_type: r.allowed_principal_type,
                granted_by: r.granted_by,
                granted_at: rfc3339(r.granted_at),
            })
            .collect(),
    })
}

// ---------------------------------------------------------------------------
// DELETE /api/v1/users/{id}/roles/{role_id}
// ---------------------------------------------------------------------------

pub async fn unassign_role(
    state: &AppState,
    principal: &Principal,
    ip: Option<String>,
    user_id: Uuid,
    role_id: Uuid,
) -> AppResult<()> {
    let step_up = principal.has_recent_step_up(state.config.sessions.step_up_window);
    let window = state.config.sessions.step_up_window;

    let mut tx = state.begin().await?;
    let subject = load_locked_subject(state, &mut tx, user_id).await?;
    let target = user_target(principal.user_id(), subject.id);

    if let Err(e) = state.require(principal, ROLES_ASSIGN, &target) {
        return Err(refuse(
            state,
            tx,
            principal,
            ip,
            "role.unassign",
            Some((TARGET_USER, subject.id)),
            e,
        )
        .await);
    }
    if let Err(e) = state.require_step_up_for(principal, ROLES_ASSIGN) {
        return Err(refuse(
            state,
            tx,
            principal,
            ip,
            "role.unassign",
            Some((TARGET_USER, subject.id)),
            e,
        )
        .await);
    }

    let Some(role) = repo::find_role(&mut *tx, role_id).await? else {
        return Err(AppError::NotFound);
    };
    let (summary, _) = role_summary_for_delegation(&mut tx, &role).await?;

    // Removal runs the same guard as addition. It is a reduction of authority, but
    // it is still authority over *this* person's privileges: rules 3 (no
    // self-modification) and 4 (ROOT is never a target) must hold in both
    // directions, and an actor who cannot grant a role has no business deciding who
    // keeps it.
    if let Err(e) = authorise_role_assignment(&principal.actor, &subject, step_up, &summary, window)
    {
        return Err(refuse(
            state,
            tx,
            principal,
            ip,
            "role.unassign",
            Some((TARGET_USER, subject.id)),
            e,
        )
        .await);
    }

    // Zero rows means the user never held this role. Reporting success would tell
    // an operator an authority was removed when nothing changed.
    if repo::delete_role_assignment(&mut tx, subject.id, role.id).await? == 0 {
        return Err(AppError::NotFound);
    }
    state.bump_security_version(&mut tx, subject.id).await?;

    state
        .audit(
            &mut tx,
            event(principal, ip, action::ROLE_UNASSIGNED, Outcome::Success)
                .target(TARGET_USER, subject.id)
                .meta(
                    AuditMetadata::new()
                        .id("role_id", role.id)
                        .str("role_code", &role.code),
                ),
        )
        .await?;
    tx.commit().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// GET /api/v1/users/{id}/permissions
// ---------------------------------------------------------------------------

pub async fn effective_permissions(
    state: &AppState,
    principal: &Principal,
    user_id: Uuid,
) -> AppResult<EffectivePermissionsResponse> {
    let subject = repo::find_user(&state.db, user_id)
        .await?
        .ok_or(AppError::NotFound)?;
    state.require(
        principal,
        PERMISSIONS_READ,
        &user_target(principal.user_id(), subject.id),
    )?;

    let principal_type = principal_type_of(&subject.principal_type)?;
    let is_root = state.is_root_user(subject.id).await?;
    // The same loader the authentication path uses, so what this endpoint reports
    // is what the evaluator will actually see on the subject's next request.
    let actor = load_actor(&state.db, subject.id, principal_type, is_root).await?;

    Ok(EffectivePermissionsResponse {
        user_id: subject.id,
        principal_type: principal_type.as_str().to_string(),
        is_root,
        items: evaluator::capability_list(&actor)
            .into_iter()
            .map(|(permission_code, scopes)| CapabilityResponse {
                permission_code,
                scopes: scopes.into_iter().map(|s| s.as_str()).collect(),
            })
            .collect(),
    })
}

// ---------------------------------------------------------------------------
// Overrides
// ---------------------------------------------------------------------------

fn override_response(row: repo::OverrideRow) -> OverrideResponse {
    OverrideResponse {
        id: row.id,
        user_id: row.user_id,
        permission_code: row.permission_code,
        effect: row.effect,
        scope: row.scope_type,
        resource_type: row.resource_type,
        resource_id: row.resource_id,
        expires_at: row.expires_at.map(rfc3339),
        reason: row.reason,
        granted_by: row.granted_by,
        granted_at: rfc3339(row.granted_at),
    }
}

pub async fn list_overrides(
    state: &AppState,
    principal: &Principal,
    user_id: Uuid,
) -> AppResult<OverrideListResponse> {
    let subject = repo::find_user(&state.db, user_id)
        .await?
        .ok_or(AppError::NotFound)?;
    state.require(
        principal,
        PERMISSIONS_READ,
        &user_target(principal.user_id(), subject.id),
    )?;
    let rows = repo::list_overrides(&state.db, subject.id).await?;
    Ok(OverrideListResponse {
        user_id: subject.id,
        items: rows.into_iter().map(override_response).collect(),
    })
}

pub async fn create_override(
    state: &AppState,
    principal: &Principal,
    ip: Option<String>,
    user_id: Uuid,
    request: CreateOverrideRequest,
) -> AppResult<OverrideResponse> {
    let permission_code = validate_permission_code("permission_code", &request.permission_code)?;
    let effect = v::parse_enum(
        "effect",
        &request.effect,
        crate::modules::authorization::domain::Effect::parse,
        &["ALLOW", "DENY"],
    )?;
    let scope = parse_override_scope(
        &request.scope,
        request.resource_type.as_deref(),
        request.resource_id,
    )?;
    let expires_at = parse_expiry(request.expires_at.as_deref())?;
    let reason = v::optional_text("reason", request.reason.as_deref(), v::MAX_REASON_LEN)?;

    let step_up = principal.has_recent_step_up(state.config.sessions.step_up_window);
    let window = state.config.sessions.step_up_window;

    let mut tx = state.begin().await?;
    let subject = load_locked_subject(state, &mut tx, user_id).await?;
    let target = user_target(principal.user_id(), subject.id);

    if let Err(e) = state.require(principal, PERMISSIONS_DELEGATE, &target) {
        return Err(refuse(
            state,
            tx,
            principal,
            ip,
            "override.create",
            Some((TARGET_USER, subject.id)),
            e,
        )
        .await);
    }
    if let Err(e) = state.require_step_up_for(principal, PERMISSIONS_DELEGATE) {
        return Err(refuse(
            state,
            tx,
            principal,
            ip,
            "override.create",
            Some((TARGET_USER, subject.id)),
            e,
        )
        .await);
    }

    // §6 rule 6: a DENY may be created by anyone who could grant the corresponding
    // ALLOW, so the same check runs for both effects.
    if let Err(e) = authorise_grant(
        &principal.actor,
        &subject,
        step_up,
        &permission_code,
        scope,
        window,
    ) {
        return Err(refuse(
            state,
            tx,
            principal,
            ip,
            "override.create",
            Some((TARGET_USER, subject.id)),
            e,
        )
        .await);
    }

    guard_grant_to_archived(&subject)?;

    let row = repo::insert_override(
        &mut tx,
        Uuid::now_v7(),
        subject.id,
        &permission_code,
        effect.as_str(),
        scope.scope_type.as_str(),
        scope.resource_type.map(|r| r.as_str()),
        scope.resource_id,
        expires_at,
        &reason,
        principal.user_id(),
    )
    .await?;

    state.bump_security_version(&mut tx, subject.id).await?;
    state
        .audit(
            &mut tx,
            event(
                principal,
                ip,
                action::PERMISSION_OVERRIDE_CREATED,
                Outcome::Success,
            )
            .target(TARGET_USER, subject.id)
            .meta(
                AuditMetadata::new()
                    .id("override_id", row.id)
                    .str("permission", &permission_code)
                    .str("effect", effect.as_str())
                    .str("scope", scope.scope_type.as_str())
                    .opt_id("resource", scope.resource_id)
                    .bool("expires", expires_at.is_some()),
            ),
        )
        .await?;
    tx.commit().await?;
    Ok(override_response(row))
}

pub async fn delete_override(
    state: &AppState,
    principal: &Principal,
    ip: Option<String>,
    user_id: Uuid,
    override_id: Uuid,
) -> AppResult<()> {
    let step_up = principal.has_recent_step_up(state.config.sessions.step_up_window);
    let window = state.config.sessions.step_up_window;

    let mut tx = state.begin().await?;
    let subject = load_locked_subject(state, &mut tx, user_id).await?;
    let target = user_target(principal.user_id(), subject.id);

    if let Err(e) = state.require(principal, PERMISSIONS_DELEGATE, &target) {
        return Err(refuse(
            state,
            tx,
            principal,
            ip,
            "override.delete",
            Some((TARGET_USER, subject.id)),
            e,
        )
        .await);
    }
    if let Err(e) = state.require_step_up_for(principal, PERMISSIONS_DELEGATE) {
        return Err(refuse(
            state,
            tx,
            principal,
            ip,
            "override.delete",
            Some((TARGET_USER, subject.id)),
            e,
        )
        .await);
    }

    // An override that does not exist — or belongs to someone else — is a 404, not
    // a silent success.
    let Some(existing) = repo::find_override_for_update(&mut tx, override_id, subject.id).await?
    else {
        return Err(AppError::NotFound);
    };

    let scope = scope_from_row(
        &existing.scope_type,
        existing.resource_type.as_deref(),
        existing.resource_id,
    )?;
    // Removing a DENY is an escalation and removing an ALLOW is a restriction;
    // §6 rule 6 requires the same authority for both, so the guard runs regardless
    // of the effect being removed.
    if let Err(e) = authorise_grant(
        &principal.actor,
        &subject,
        step_up,
        &existing.permission_code,
        scope,
        window,
    ) {
        return Err(refuse(
            state,
            tx,
            principal,
            ip,
            "override.delete",
            Some((TARGET_USER, subject.id)),
            e,
        )
        .await);
    }

    if repo::delete_override(&mut tx, existing.id, subject.id).await? == 0 {
        return Err(AppError::NotFound);
    }
    state.bump_security_version(&mut tx, subject.id).await?;

    state
        .audit(
            &mut tx,
            event(
                principal,
                ip,
                action::PERMISSION_OVERRIDE_REMOVED,
                Outcome::Success,
            )
            .target(TARGET_USER, subject.id)
            .meta(
                AuditMetadata::new()
                    .id("override_id", existing.id)
                    .str("permission", &existing.permission_code)
                    .str("effect", &existing.effect)
                    .str("scope", &existing.scope_type),
            ),
        )
        .await?;
    tx.commit().await?;
    Ok(())
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::authorization::domain::Grant;

    const READ: &str = "projects.read";
    const WINDOW: Duration = Duration::from_secs(600);

    fn actor_with(grants: &[(&str, Scope)]) -> ActorContext {
        let mut a = ActorContext::empty(Uuid::now_v7(), PrincipalType::Internal);
        for (code, scope) in grants {
            a.allows.push(Grant {
                permission_code: (*code).into(),
                scope: *scope,
            });
        }
        a
    }

    fn subject() -> SubjectFacts {
        SubjectFacts {
            id: Uuid::now_v7(),
            principal_type: PrincipalType::Internal,
            is_root: false,
            is_archived: false,
        }
    }

    fn field_code(err: &AppError) -> String {
        match err {
            AppError::Validation { errors } => errors[0].code.to_string(),
            other => panic!("expected a validation error, got {other}"),
        }
    }

    // ---- the matrix ------------------------------------------------------

    /// **The load-bearing test of this whole file.**
    ///
    /// For every combination of a scope the actor holds and a scope it requests,
    /// the service's delegation funnel must return exactly what
    /// `delegation::derivable` says. If the HTTP layer ever adds a shortcut — a
    /// "harmless" widening, a special case for GLOBAL, a scope that is silently
    /// normalised — this diverges and fails.
    #[test]
    fn the_service_matches_the_derivation_lattice_exactly() {
        let object_a = Uuid::from_u128(0xA);
        let object_b = Uuid::from_u128(0xB);
        let scopes = [
            Scope::global(),
            Scope::simple(ScopeType::Department),
            Scope::simple(ScopeType::Assigned),
            Scope::simple(ScopeType::Own),
            Scope::resource(ResourceType::Project, object_a),
            Scope::resource(ResourceType::Project, object_b),
            Scope::resource(ResourceType::Task, object_a),
        ];

        for held in scopes {
            let actor = actor_with(&[(READ, held)]);
            let subject = subject();
            for requested in scopes {
                let allowed =
                    authorise_grant(&actor, &subject, true, READ, requested, WINDOW).is_ok();
                assert_eq!(
                    allowed,
                    delegation::derivable(held, requested),
                    "holding {:?} and requesting {:?}: the service disagreed with the lattice",
                    held,
                    requested
                );
            }
        }
    }

    /// The same matrix through role authoring, which is the other way a scope can
    /// be handed out.
    #[test]
    fn role_authoring_matches_the_derivation_lattice_for_role_scopes() {
        let scopes = [
            Scope::global(),
            Scope::simple(ScopeType::Department),
            Scope::simple(ScopeType::Assigned),
            Scope::simple(ScopeType::Own),
        ];
        for held in scopes {
            let actor = actor_with(&[(READ, held)]);
            for requested in scopes {
                let allowed = authorise_role_authoring(
                    &actor,
                    true,
                    false,
                    PrincipalType::Internal,
                    &[(READ.to_string(), requested)],
                    WINDOW,
                )
                .is_ok();
                assert_eq!(
                    allowed,
                    delegation::derivable(held, requested),
                    "role authoring diverged for {:?} -> {:?}",
                    held.scope_type,
                    requested.scope_type
                );
            }
        }
    }

    #[test]
    fn an_actor_holding_nothing_can_delegate_nothing() {
        let actor = actor_with(&[]);
        let subject = subject();
        for def in catalog::PERMISSIONS {
            assert!(
                authorise_grant(&actor, &subject, true, def.code, Scope::global(), WINDOW).is_err(),
                "an ungranted actor delegated `{}`",
                def.code
            );
        }
    }

    /// The delegation module cannot know the configured window and reports zero.
    /// A client told "verify within 0 seconds" cannot act on it, so the service
    /// substitutes the real value.
    #[test]
    fn the_step_up_window_is_translated_for_the_client() {
        // `iam.roles.assign` is dangerous, and the actor holds it without step-up.
        let actor = actor_with(&[("iam.roles.assign", Scope::global())]);
        let err = authorise_grant(
            &actor,
            &subject(),
            false,
            "iam.roles.assign",
            Scope::global(),
            WINDOW,
        )
        .unwrap_err();
        match err {
            AppError::StepUpRequired { window_seconds } => assert_eq!(window_seconds, 600),
            other => panic!("expected StepUpRequired, got {other}"),
        }
    }

    #[test]
    fn root_as_a_subject_is_refused_whatever_the_actor_holds() {
        let mut actor = actor_with(&[(READ, Scope::global())]);
        actor.is_root = true;
        let root_subject = SubjectFacts {
            id: Uuid::now_v7(),
            principal_type: PrincipalType::Internal,
            is_root: true,
            is_archived: false,
        };
        assert!(matches!(
            authorise_grant(&actor, &root_subject, true, READ, Scope::global(), WINDOW),
            Err(AppError::RootProtected)
        ));
    }

    // ---- permission codes -------------------------------------------------

    #[test]
    fn an_unknown_permission_code_is_a_probe_not_a_validation_nicety() {
        for bogus in [
            "iam.users.delete",
            "projects.*",
            "*",
            "PROJECTS.READ",
            "not.a.permission",
        ] {
            assert!(
                matches!(
                    validate_permission_code("permission_code", bogus),
                    Err(AppError::UnknownPermission)
                ),
                "accepted `{bogus}`"
            );
        }
        // An enormous "code" is refused without scanning the catalogue for it.
        assert!(validate_permission_code("permission_code", &"a".repeat(100_000)).is_err());
        // Empty is a plain validation error — nothing was probed.
        assert_eq!(
            field_code(&validate_permission_code("permission_code", "  ").unwrap_err()),
            "REQUIRED"
        );

        assert_eq!(
            validate_permission_code("permission_code", " projects.read ").unwrap(),
            "projects.read"
        );
    }

    // ---- scope parsing ----------------------------------------------------

    #[test]
    fn role_scopes_parse_and_refuse_resource() {
        assert_eq!(parse_role_scope("GLOBAL").unwrap(), Scope::global());
        assert_eq!(
            parse_role_scope("DEPARTMENT").unwrap(),
            Scope::simple(ScopeType::Department)
        );
        assert_eq!(
            parse_role_scope(" SELF ").unwrap(),
            Scope::simple(ScopeType::Own)
        );

        let err = parse_role_scope("RESOURCE").unwrap_err();
        assert_eq!(field_code(&err), "INVALID_SCOPE");

        for bad in ["global", "EVERYTHING", "", "GLOBAL; DROP TABLE roles"] {
            assert!(parse_role_scope(bad).is_err(), "accepted `{bad}`");
        }
    }

    #[test]
    fn override_scopes_require_a_coherent_object() {
        let id = Uuid::now_v7();
        let ok = parse_override_scope("RESOURCE", Some("PROJECT"), Some(id)).unwrap();
        assert_eq!(ok, Scope::resource(ResourceType::Project, id));
        assert!(ok.is_coherent());

        // RESOURCE missing its object.
        assert_eq!(
            field_code(&parse_override_scope("RESOURCE", None, Some(id)).unwrap_err()),
            "REQUIRED"
        );
        assert_eq!(
            field_code(&parse_override_scope("RESOURCE", Some("PROJECT"), None).unwrap_err()),
            "REQUIRED"
        );
        // An unknown resource type is not silently dropped.
        assert!(parse_override_scope("RESOURCE", Some("ROLE"), Some(id)).is_err());

        // A non-RESOURCE scope carrying an object.
        assert_eq!(
            field_code(&parse_override_scope("GLOBAL", Some("PROJECT"), Some(id)).unwrap_err()),
            "NOT_ALLOWED"
        );
        assert_eq!(
            field_code(&parse_override_scope("ASSIGNED", None, Some(id)).unwrap_err()),
            "NOT_ALLOWED"
        );

        assert_eq!(
            parse_override_scope("GLOBAL", None, None).unwrap(),
            Scope::global()
        );
        // A blank string is treated as absent rather than as an unknown type.
        assert_eq!(
            parse_override_scope("SELF", Some("  "), None).unwrap(),
            Scope::simple(ScopeType::Own)
        );
    }

    /// A stored scope that cannot be reconstructed must fail the operation, never
    /// be treated as absent — "absent" would skip the delegation check entirely.
    #[test]
    fn a_corrupt_stored_scope_fails_closed() {
        assert!(scope_from_row("EVERYTHING", None, None).is_err());
        assert!(scope_from_row("RESOURCE", None, None).is_err());
        assert!(scope_from_row("RESOURCE", Some("PROJECT"), None).is_err());
        assert!(scope_from_row("GLOBAL", Some("PROJECT"), Some(Uuid::now_v7())).is_err());
        assert!(scope_from_row("GLOBAL", None, None).is_ok());
    }

    // ---- role permission lists --------------------------------------------

    #[test]
    fn a_role_permission_list_is_bounded_deduplicated_and_catalogued() {
        let input = |code: &str, scope: &str| RolePermissionInput {
            permission_code: code.into(),
            scope: scope.into(),
        };

        let ok = validate_role_permissions(&[
            input("projects.read", "DEPARTMENT"),
            input("tasks.read", "ASSIGNED"),
        ])
        .unwrap();
        assert_eq!(ok.len(), 2);
        assert_eq!(ok[0].1, Scope::simple(ScopeType::Department));

        assert_eq!(
            field_code(
                &validate_role_permissions(&[
                    input("projects.read", "GLOBAL"),
                    input("projects.read", "DEPARTMENT"),
                ])
                .unwrap_err()
            ),
            "DUPLICATE"
        );

        assert!(matches!(
            validate_role_permissions(&[input("projects.destroy", "GLOBAL")]),
            Err(AppError::UnknownPermission)
        ));

        let too_many: Vec<RolePermissionInput> = (0..v::MAX_ARRAY_LEN + 1)
            .map(|_| input("projects.read", "GLOBAL"))
            .collect();
        assert_eq!(
            field_code(&validate_role_permissions(&too_many).unwrap_err()),
            "TOO_MANY"
        );
    }

    // ---- deletion and concurrency -----------------------------------------

    #[test]
    fn a_role_with_live_assignments_cannot_be_deleted() {
        assert!(guard_role_deletion(0).is_ok());
        for count in [1i64, 2, 10_000] {
            let err = guard_role_deletion(count).unwrap_err();
            assert_eq!(err.code(), "ROLE_IN_USE");
            assert_eq!(err.status(), axum::http::StatusCode::CONFLICT);
        }
    }

    #[test]
    fn a_stale_version_is_a_conflict_and_never_an_overwrite() {
        assert!(check_version(3, 3).is_ok());
        match check_version(3, 5).unwrap_err() {
            AppError::VersionConflict { expected, actual } => {
                assert_eq!((expected, actual), (3, 5));
            }
            other => panic!("expected VersionConflict, got {other}"),
        }
        // A version from the future is equally a conflict: it means the client is
        // guessing rather than re-reading.
        assert!(check_version(9, 5).is_err());
        assert_eq!(
            check_version(1, 2).unwrap_err().status(),
            axum::http::StatusCode::CONFLICT
        );
    }

    // ---- expiry -----------------------------------------------------------

    #[test]
    fn override_expiry_must_be_rfc3339_and_in_the_future() {
        assert!(parse_expiry(None).unwrap().is_none());
        assert!(parse_expiry(Some("   ")).unwrap().is_none());

        let future = OffsetDateTime::now_utc() + time::Duration::hours(1);
        let parsed = parse_expiry(Some(&rfc3339(future))).unwrap().expect("some");
        assert!(parsed > OffsetDateTime::now_utc());

        assert_eq!(
            field_code(&parse_expiry(Some("2000-01-01T00:00:00Z")).unwrap_err()),
            "OUT_OF_RANGE"
        );
        for bad in ["tomorrow", "2026-13-01T00:00:00Z", "1700000000", ""] {
            if bad.is_empty() {
                continue; // empty is "absent", asserted above
            }
            assert!(parse_expiry(Some(bad)).is_err(), "accepted `{bad}`");
        }
    }

    // ---- denial classification --------------------------------------------

    #[test]
    fn a_refusal_targeting_root_is_recorded_under_its_own_action() {
        assert_eq!(
            denial_action(&AppError::RootProtected),
            action::ROOT_PROTECTION_TRIGGERED
        );
        assert_eq!(
            denial_action(&AppError::AuthorizationDenied),
            action::AUTHORIZATION_DENIED
        );
        assert_eq!(
            denial_action(&AppError::delegation("x")),
            action::AUTHORIZATION_DENIED
        );
    }

    /// The audit metadata for a denial must carry the stable error code and never
    /// caller-supplied prose, which would make the audit log a log-injection sink.
    #[test]
    fn denial_metadata_uses_the_stable_error_code() {
        let err = AppError::delegation("You hold `x` at DEPARTMENT and cannot grant it at GLOBAL.");
        assert_eq!(err.code(), "DELEGATION_DENIED");
        let meta = AuditMetadata::new()
            .str("operation", "role.assign")
            .str("reason", err.code());
        let value = meta.into_value();
        assert_eq!(value["reason"], serde_json::json!("DELEGATION_DENIED"));
        assert_eq!(value["operation"], serde_json::json!("role.assign"));
    }
}
