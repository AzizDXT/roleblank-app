//! Client accounts: transaction boundary, authorisation, audit, invariants.
//!
//! Two properties this file exists to keep true:
//!
//! 1. **No external principal reaches any of it.** `clients.*` is
//!    `max_principal_type = INTERNAL`, so the evaluator refuses a `CLIENT` at step
//!    3, before any grant is looked at, and `state.require` converts that refusal
//!    into `404` rather than `403`. Nothing here re-implements that rule; it just
//!    propagates what `require` returns.
//! 2. **A membership becomes visible only by an explicit, authorised, audited
//!    act.** `PENDING` grants nothing at all — that is the whole point of the
//!    self-registration flow — and `activate` is the one operation that changes it.

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
    AddClientMemberRequest, ArchiveClientRequest, ClientAccountResponse, ClientAccountStatus,
    ClientMemberResponse, ClientMembershipStatus, CreateClientRequest, UpdateClientRequest,
};
use super::repo::{self, ClientAccountRow, MembershipRow, Visibility};

const READ: &str = "clients.read";
const CREATE: &str = "clients.create";
const UPDATE: &str = "clients.update";
const ARCHIVE: &str = "clients.archive";
const MEMBERS_MANAGE: &str = "clients.members.manage";

// ---------------------------------------------------------------------------
// Pure rules
// ---------------------------------------------------------------------------

/// **The rule the entire external trust boundary rests on.**
///
/// A membership confers visibility only when it is `ACTIVE` *and* its account is
/// `ACTIVE`. Both halves are also compiled into the client-visibility SQL
/// predicate (`docs/backend/04-authorization.md` §9), so this function and that
/// predicate must always agree — which is why the transitions below can never set
/// `ACTIVE` implicitly.
pub fn grants_visibility(membership: ClientMembershipStatus, account: ClientAccountStatus) -> bool {
    matches!(membership, ClientMembershipStatus::Active)
        && matches!(account, ClientAccountStatus::Active)
}

/// A client account is "assigned" to the internal actor who manages it. Client
/// memberships hold external users only, so there is no other relationship an
/// internal principal can have with the row.
fn target_for(row: &ClientAccountRow, actor_id: Uuid) -> Target {
    Target::Resource(
        TargetContext::new(ResourceType::ClientAccount, row.id)
            // A client account belongs to no department; saying so explicitly stops
            // a DEPARTMENT-scoped grant from reaching it.
            .with_department(None)
            .with_membership(row.account_manager_user_id == Some(actor_id)),
    )
}

fn account_status_of(row: &ClientAccountRow) -> AppResult<ClientAccountStatus> {
    ClientAccountStatus::parse(&row.status)
        .ok_or_else(|| AppError::internal("client account row has an unrecognised status"))
}

fn membership_status_of(row: &MembershipRow) -> AppResult<ClientMembershipStatus> {
    ClientMembershipStatus::parse(&row.status)
        .ok_or_else(|| AppError::internal("client membership row has an unrecognised status"))
}

pub fn check_version(expected: i32, actual: i32) -> AppResult<()> {
    if expected == actual {
        Ok(())
    } else {
        Err(AppError::VersionConflict { expected, actual })
    }
}

/// An archived account is read-only. A `SUSPENDED` one is not: suspension is a
/// live commercial state, and changing the account manager of a suspended customer
/// is exactly the sort of thing that needs doing.
pub fn check_account_mutable(status: ClientAccountStatus) -> AppResult<()> {
    match status {
        ClientAccountStatus::Active | ClientAccountStatus::Suspended => Ok(()),
        ClientAccountStatus::Archived => Err(AppError::conflict(
            "CLIENT_ARCHIVED",
            "This client account is archived and can no longer be modified.",
        )),
    }
}

/// `ACTIVE | SUSPENDED -> ARCHIVED`. Re-archiving is refused rather than treated
/// as idempotent, so a double submit cannot rewrite `archived_at` and destroy the
/// record of when the relationship actually ended.
pub fn check_account_archivable(status: ClientAccountStatus) -> AppResult<()> {
    match status {
        ClientAccountStatus::Active | ClientAccountStatus::Suspended => Ok(()),
        ClientAccountStatus::Archived => Err(AppError::conflict(
            "CLIENT_ALREADY_ARCHIVED",
            "This client account is already archived.",
        )),
    }
}

/// Client-account membership is `CLIENT`-only. A database trigger enforces the
/// same rule; checking here first turns `INVARIANT_VIOLATION` into something the
/// caller can act on, without the trigger ceasing to be the real barrier.
pub fn check_client_principal(principal_type: &str) -> AppResult<()> {
    match PrincipalType::parse(principal_type) {
        Some(PrincipalType::Client) => Ok(()),
        _ => Err(AppError::conflict(
            "PRINCIPAL_TYPE_MISMATCH",
            "Client-account membership is limited to external client users.",
        )),
    }
}

/// The account manager is company staff.
pub fn check_internal_principal(principal_type: &str) -> AppResult<()> {
    match PrincipalType::parse(principal_type) {
        Some(PrincipalType::Internal) => Ok(()),
        _ => Err(AppError::conflict(
            "PRINCIPAL_TYPE_MISMATCH",
            "The account manager must be an internal user.",
        )),
    }
}

/// An archived user account is gone. Re-attaching it to a customer would create a
/// membership nobody intends to activate and that a later reviewer has to explain.
/// `SUSPENDED` is allowed: suspension is enforced at authentication, so the
/// membership record staying put is what makes reinstatement one action.
pub fn check_user_addable(user_status: &str) -> AppResult<()> {
    match user_status {
        "ARCHIVED" => Err(AppError::conflict(
            "USER_ARCHIVED",
            "That user is archived and cannot be added to a client account.",
        )),
        _ => Ok(()),
    }
}

/// `None` — no row at all — and `REMOVED` are the two states from which someone
/// may be (re-)added. Anything else is already a member.
pub fn check_addable(existing: Option<ClientMembershipStatus>) -> AppResult<()> {
    match existing {
        None | Some(ClientMembershipStatus::Removed) => Ok(()),
        Some(_) => Err(AppError::conflict(
            "ALREADY_A_MEMBER",
            "That user is already a member of this client account.",
        )),
    }
}

/// `PENDING -> ACTIVE` and `SUSPENDED -> ACTIVE` only.
///
/// `REMOVED -> ACTIVE` is refused deliberately: reinstating someone must go back
/// through `PENDING`, so that restoring external access is never a single
/// keystroke on a membership that was explicitly ended.
pub fn check_activatable(current: ClientMembershipStatus) -> AppResult<()> {
    match current {
        ClientMembershipStatus::Pending | ClientMembershipStatus::Suspended => Ok(()),
        ClientMembershipStatus::Active => Err(AppError::conflict(
            "MEMBERSHIP_ALREADY_ACTIVE",
            "That membership is already active.",
        )),
        ClientMembershipStatus::Removed => Err(AppError::conflict(
            "MEMBERSHIP_REMOVED",
            "That membership was removed. Add the user again to start a new one.",
        )),
    }
}

/// Every state except `REMOVED` can be removed. Removing an already removed
/// membership is a conflict rather than a silent success, so a client cannot use
/// the endpoint to discover whether a membership ever existed.
pub fn check_removable(current: ClientMembershipStatus) -> AppResult<()> {
    match current {
        ClientMembershipStatus::Removed => Err(AppError::conflict(
            "MEMBERSHIP_ALREADY_REMOVED",
            "That membership has already been removed.",
        )),
        _ => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// Flows
// ---------------------------------------------------------------------------

pub async fn list(
    state: &AppState,
    principal: &Principal,
    query: &PageQuery,
) -> AppResult<Page<ClientAccountResponse>> {
    let request = PageRequest::resolve(
        query,
        repo::SORTS,
        repo::DEFAULT_SORT,
        state.config.limits.max_page_size,
    )?;

    let visibility = if state
        .decide(principal, READ, &Target::Collection)
        .is_allowed()
    {
        Visibility::Everything
    } else {
        let scopes = evaluator::effective_scopes(&principal.actor, READ);
        repo::visibility_for(&scopes, &principal.actor)
    };

    if matches!(visibility, Visibility::Nothing) {
        // One place decides how a refusal is shaped. A CLIENT principal has no
        // scopes here at all (the envelope removes them), lands in this branch, and
        // receives `404` — the customer-management surface does not acknowledge
        // itself to an external user.
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
) -> AppResult<ClientAccountResponse> {
    let row = repo::find(&state.db, id).await?.ok_or(AppError::NotFound)?;
    state.require(principal, READ, &target_for(&row, principal.user_id()))?;
    to_response(row)
}

pub async fn create(
    state: &AppState,
    principal: &Principal,
    source_ip: Option<String>,
    request: CreateClientRequest,
) -> AppResult<ClientAccountResponse> {
    let code = v::validate_code("code", &request.code)?;
    let name = v::required_text("name", &request.name, v::MAX_NAME_LEN)?;
    let description = v::optional_text(
        "description",
        request.description.as_deref(),
        v::MAX_DESCRIPTION_LEN,
    )?;

    // There is no row yet, so the decision is collection-level and only a GLOBAL
    // grant reaches it.
    state.require(principal, CREATE, &Target::Collection)?;
    state.require_step_up_for(principal, CREATE)?;

    let mut tx = state.begin().await?;

    if let Some(manager) = request.account_manager_user_id {
        let user = repo::find_user(&mut *tx, manager).await?.ok_or_else(|| {
            AppError::conflict(
                "UNKNOWN_USER",
                "The nominated account manager does not exist.",
            )
        })?;
        check_internal_principal(&user.principal_type)?;
    }

    let row = repo::insert(
        &mut tx,
        Uuid::now_v7(),
        &code,
        &name,
        &description,
        request.account_manager_user_id,
        principal.user_id(),
    )
    .await?;

    state
        .audit(
            &mut tx,
            AuditEvent::new(action::CLIENT_CREATED, Outcome::Success)
                .actor(
                    principal.user_id(),
                    principal.session.principal_type,
                    Some(principal.session.session_id),
                )
                .target(ResourceType::ClientAccount.as_str(), row.id)
                .source_ip(source_ip)
                .meta(
                    AuditMetadata::new()
                        .str("code", &row.code)
                        .opt_id("account_manager_user_id", row.account_manager_user_id),
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
    request: UpdateClientRequest,
) -> AppResult<ClientAccountResponse> {
    let name = match &request.name {
        None => None,
        Some(raw) => Some(v::required_text("name", raw, v::MAX_NAME_LEN)?),
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
    state.require(principal, UPDATE, &target_for(&row, principal.user_id()))?;
    state.require_step_up_for(principal, UPDATE)?;

    check_account_mutable(account_status_of(&row)?)?;
    check_version(request.version, row.version)?;

    let set_manager = request.account_manager_user_id.is_some();
    let manager = request.account_manager_user_id.flatten();
    if let Some(manager_id) = manager {
        let user = repo::find_user(&mut *tx, manager_id)
            .await?
            .ok_or_else(|| {
                AppError::conflict(
                    "UNKNOWN_USER",
                    "The nominated account manager does not exist.",
                )
            })?;
        check_internal_principal(&user.principal_type)?;
    }

    let updated = repo::update(
        &mut tx,
        row.id,
        request.version,
        name.as_deref(),
        description.as_deref(),
        set_manager,
        manager,
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
    if set_manager {
        meta = meta
            .changed("account_manager_user_id")
            .opt_id("account_manager_user_id", manager);
    }

    state
        .audit(
            &mut tx,
            AuditEvent::new(action::CLIENT_UPDATED, Outcome::Success)
                .actor(
                    principal.user_id(),
                    principal.session.principal_type,
                    Some(principal.session.session_id),
                )
                .target(ResourceType::ClientAccount.as_str(), updated.id)
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
    request: ArchiveClientRequest,
) -> AppResult<ClientAccountResponse> {
    let mut tx = state.begin().await?;
    let row = repo::find_for_update(&mut tx, id)
        .await?
        .ok_or(AppError::NotFound)?;
    state.require(principal, ARCHIVE, &target_for(&row, principal.user_id()))?;
    state.require_step_up_for(principal, ARCHIVE)?;

    check_account_archivable(account_status_of(&row)?)?;
    check_version(request.version, row.version)?;

    // Archiving revokes nothing explicitly: no membership row is touched and no
    // project link is cut. It does not need to. The client-visibility predicate
    // joins `client_accounts` and requires `ca.status = 'ACTIVE'`
    // (`docs/backend/04-authorization.md` §9), so every membership of this account
    // stops granting visibility on the very next query — with no cache to
    // invalidate and no fan-out UPDATE that could half-fail and leave some external
    // users still able to see the work. Un-archiving (were it ever added) would
    // therefore restore exactly what was there, which is also why the memberships
    // are deliberately left alone.
    let archived = repo::archive(&mut tx, row.id, request.version)
        .await?
        .ok_or(AppError::VersionConflict {
            expected: request.version,
            actual: row.version,
        })?;

    state
        .audit(
            &mut tx,
            AuditEvent::new(action::CLIENT_ARCHIVED, Outcome::Success)
                .actor(
                    principal.user_id(),
                    principal.session.principal_type,
                    Some(principal.session.session_id),
                )
                .target(ResourceType::ClientAccount.as_str(), archived.id)
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
) -> AppResult<Page<ClientMemberResponse>> {
    let request = PageRequest::resolve(
        query,
        repo::MEMBER_SORTS,
        repo::MEMBER_DEFAULT_SORT,
        state.config.limits.max_page_size,
    )?;

    let row = repo::find(&state.db, id).await?.ok_or(AppError::NotFound)?;
    state.require(principal, READ, &target_for(&row, principal.user_id()))?;
    let account_status = account_status_of(&row)?;

    let rows = repo::list_members(&state.db, row.id, &request).await?;
    let page = Page::build(rows, &request, |member| Cursor {
        timestamp_micros: repo::cursor_micros(member.created_at),
        id: member.id,
    });

    let items = page
        .items
        .into_iter()
        .map(|member| {
            let status = ClientMembershipStatus::parse(&member.status).ok_or_else(|| {
                AppError::internal("client membership row has an unrecognised status")
            })?;
            Ok(ClientMemberResponse {
                user_id: member.user_id,
                display_name: member.display_name,
                email: member.email,
                status,
                invited_by: member.invited_by,
                grants_visibility: grants_visibility(status, account_status),
                created_at: member.created_at,
                activated_at: member.activated_at,
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
    request: AddClientMemberRequest,
) -> AppResult<ClientMemberResponse> {
    let mut tx = state.begin().await?;
    let row = repo::find_for_update(&mut tx, id)
        .await?
        .ok_or(AppError::NotFound)?;
    state.require(
        principal,
        MEMBERS_MANAGE,
        &target_for(&row, principal.user_id()),
    )?;
    state.require_step_up_for(principal, MEMBERS_MANAGE)?;

    let account_status = account_status_of(&row)?;
    check_account_mutable(account_status)?;

    let user = repo::find_user(&mut *tx, request.user_id)
        .await?
        .ok_or_else(|| AppError::conflict("UNKNOWN_USER", "That user does not exist."))?;
    // The subject is by construction a CLIENT principal, so it can never be the
    // system owner — `system_ownership` refuses a non-INTERNAL user — and no
    // separate root guard is needed here.
    check_client_principal(&user.principal_type)?;
    check_user_addable(&user.status)?;

    let existing = repo::find_membership_for_update(&mut tx, row.id, user.id).await?;
    let existing_status = existing.as_ref().map(membership_status_of).transpose()?;
    check_addable(existing_status)?;

    // Whether this is a first invitation or the revival of a removed one, the
    // result is PENDING. Nothing on this path can produce a visible membership.
    let membership = match existing {
        Some(previous) => {
            repo::revive_membership_as_pending(&mut tx, previous.id, principal.user_id())
                .await?
                .ok_or_else(|| {
                    AppError::conflict("ALREADY_A_MEMBER", "That membership changed concurrently.")
                })?
        }
        None => {
            repo::insert_pending_membership(
                &mut tx,
                Uuid::now_v7(),
                row.id,
                user.id,
                principal.user_id(),
            )
            .await?
        }
    };

    let status = membership_status_of(&membership)?;

    state
        .audit(
            &mut tx,
            AuditEvent::new(action::CLIENT_MEMBER_ADDED, Outcome::Success)
                .actor(
                    principal.user_id(),
                    principal.session.principal_type,
                    Some(principal.session.session_id),
                )
                .target(ResourceType::ClientAccount.as_str(), row.id)
                .source_ip(source_ip)
                .meta(
                    AuditMetadata::new()
                        .id("subject_user_id", user.id)
                        .str("status", status.as_str())
                        .bool(
                            "grants_visibility",
                            grants_visibility(status, account_status),
                        ),
                ),
        )
        .await?;

    tx.commit().await.map_err(AppError::from)?;

    Ok(ClientMemberResponse {
        user_id: user.id,
        display_name: user.display_name,
        email: user.email,
        status,
        invited_by: membership.invited_by,
        grants_visibility: grants_visibility(status, account_status),
        created_at: membership.created_at,
        activated_at: membership.activated_at,
    })
}

/// The moment company data becomes visible to someone outside the company.
///
/// It is a separate endpoint, a separate authorisation decision and a separate
/// audit event precisely because it is the only step in the whole flow that is
/// irreversible in effect: once an external user has seen a project, unsharing it
/// does not unsee it.
pub async fn activate_member(
    state: &AppState,
    principal: &Principal,
    source_ip: Option<String>,
    id: Uuid,
    user_id: Uuid,
) -> AppResult<ClientMemberResponse> {
    let mut tx = state.begin().await?;
    let row = repo::find_for_update(&mut tx, id)
        .await?
        .ok_or(AppError::NotFound)?;
    state.require(
        principal,
        MEMBERS_MANAGE,
        &target_for(&row, principal.user_id()),
    )?;
    state.require_step_up_for(principal, MEMBERS_MANAGE)?;

    let account_status = account_status_of(&row)?;
    // Activating a membership on an archived account would produce a member whose
    // `grants_visibility` is false anyway — an activation that does not activate.
    // Refusing says so instead of pretending.
    check_account_mutable(account_status)?;

    let membership = repo::find_membership_for_update(&mut tx, row.id, user_id)
        .await?
        .ok_or(AppError::NotFound)?;
    check_activatable(membership_status_of(&membership)?)?;

    let activated = repo::activate_membership(&mut tx, membership.id)
        .await?
        .ok_or_else(|| {
            AppError::conflict(
                "MEMBERSHIP_CHANGED",
                "That membership changed concurrently.",
            )
        })?;
    let status = membership_status_of(&activated)?;

    // Effective authority changed for the subject.
    state.bump_security_version(&mut tx, user_id).await?;

    state
        .audit(
            &mut tx,
            AuditEvent::new(action::CLIENT_MEMBER_ACTIVATED, Outcome::Success)
                .actor(
                    principal.user_id(),
                    principal.session.principal_type,
                    Some(principal.session.session_id),
                )
                .target(ResourceType::ClientAccount.as_str(), row.id)
                .source_ip(source_ip)
                .meta(
                    AuditMetadata::new()
                        .id("subject_user_id", user_id)
                        .str("status", status.as_str())
                        .bool(
                            "grants_visibility",
                            grants_visibility(status, account_status),
                        ),
                ),
        )
        .await?;

    tx.commit().await.map_err(AppError::from)?;

    let user = repo::find_user(&state.db, user_id)
        .await?
        .ok_or_else(|| AppError::internal("membership references a user that vanished"))?;

    Ok(ClientMemberResponse {
        user_id,
        display_name: user.display_name,
        email: user.email,
        status,
        invited_by: activated.invited_by,
        grants_visibility: grants_visibility(status, account_status),
        created_at: activated.created_at,
        activated_at: activated.activated_at,
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
    state.require(
        principal,
        MEMBERS_MANAGE,
        &target_for(&row, principal.user_id()),
    )?;
    state.require_step_up_for(principal, MEMBERS_MANAGE)?;

    // Removal stays available on an archived account: it only ever reduces access,
    // and blocking it would strand an external membership on a row nobody can edit.
    let membership = repo::find_membership_for_update(&mut tx, row.id, user_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let previous = membership_status_of(&membership)?;
    check_removable(previous)?;

    if !repo::remove_membership(&mut tx, membership.id).await? {
        return Err(AppError::conflict(
            "MEMBERSHIP_CHANGED",
            "That membership changed concurrently.",
        ));
    }

    state.bump_security_version(&mut tx, user_id).await?;

    state
        .audit(
            &mut tx,
            AuditEvent::new(action::CLIENT_MEMBER_REMOVED, Outcome::Success)
                .actor(
                    principal.user_id(),
                    principal.session.principal_type,
                    Some(principal.session.session_id),
                )
                .target(ResourceType::ClientAccount.as_str(), row.id)
                .source_ip(source_ip)
                .meta(
                    AuditMetadata::new()
                        .id("subject_user_id", user_id)
                        .str("previous_status", previous.as_str()),
                ),
        )
        .await?;

    tx.commit().await.map_err(AppError::from)?;
    Ok(())
}

fn to_response(row: ClientAccountRow) -> AppResult<ClientAccountResponse> {
    let status = account_status_of(&row)?;
    Ok(ClientAccountResponse {
        id: row.id,
        code: row.code,
        name: row.name,
        description: row.description,
        status,
        account_manager_user_id: row.account_manager_user_id,
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
    use crate::modules::authorization::domain::{ActorContext, Decision, Grant, Scope};

    // ---- visibility --------------------------------------------------------

    /// **The test this module exists for.** A `PENDING` membership grants nothing,
    /// under every account status, without exception.
    #[test]
    fn a_pending_membership_yields_no_visibility() {
        for account in ClientAccountStatus::ALL {
            assert!(
                !grants_visibility(ClientMembershipStatus::Pending, *account),
                "a PENDING membership became visible against an {account:?} account"
            );
        }
    }

    #[test]
    fn only_an_active_membership_of_an_active_account_grants_visibility() {
        for membership in ClientMembershipStatus::ALL {
            for account in ClientAccountStatus::ALL {
                let expected = *membership == ClientMembershipStatus::Active
                    && *account == ClientAccountStatus::Active;
                assert_eq!(
                    grants_visibility(*membership, *account),
                    expected,
                    "membership {membership:?} on account {account:?}"
                );
            }
        }
    }

    /// The other half of the same property, at the layer the request actually goes
    /// through: `principal::load_actor` only loads `client_account_ids` for
    /// memberships whose status is `ACTIVE`, so a self-registered external user
    /// whose membership is still `PENDING` arrives with an empty set and is denied
    /// even the portal permission they legitimately hold.
    #[test]
    fn a_pending_client_principal_is_denied_everything() {
        let mut actor = ActorContext::empty(Uuid::now_v7(), PrincipalType::Client);
        // A PENDING membership contributes no client account id at all.
        assert!(actor.client_account_ids.is_empty());
        actor.allows.push(Grant {
            permission_code: "client.portal.projects.read".into(),
            scope: Scope::simple(crate::modules::authorization::domain::ScopeType::Assigned),
        });

        let project = Target::Resource(
            TargetContext::new(ResourceType::Project, Uuid::now_v7()).with_membership(false),
        );
        assert_eq!(
            evaluator::evaluate(&actor, "client.portal.projects.read", &project),
            Decision::DenyOutOfScope
        );

        // And the internal customer-management surface is refused at the envelope,
        // before any grant is consulted — which is what makes the `404` correct.
        for permission in [READ, CREATE, UPDATE, ARCHIVE, MEMBERS_MANAGE] {
            assert_eq!(
                evaluator::evaluate(&actor, permission, &Target::Collection),
                Decision::DenyPrincipalEnvelope,
                "{permission} was not refused by the principal envelope"
            );
            assert!(
                evaluator::effective_scopes(&actor, permission).is_empty(),
                "{permission} produced scopes for an external principal"
            );
        }
    }

    /// A client principal therefore always lands in the "nothing visible" branch of
    /// `list`, which routes through `state.require` and becomes a `404`.
    #[test]
    fn a_client_principal_derives_no_listing_filter() {
        let actor = ActorContext::empty(Uuid::now_v7(), PrincipalType::Client);
        let scopes = evaluator::effective_scopes(&actor, READ);
        assert_eq!(repo::visibility_for(&scopes, &actor), Visibility::Nothing);
    }

    // ---- concurrency -------------------------------------------------------

    #[test]
    fn a_stale_version_is_a_conflict_carrying_both_numbers() {
        assert!(check_version(2, 2).is_ok());
        match check_version(2, 9) {
            Err(AppError::VersionConflict { expected, actual }) => {
                assert_eq!((expected, actual), (2, 9));
            }
            other => panic!("expected a version conflict, got {other:?}"),
        }
        assert!(matches!(
            check_version(9, 2),
            Err(AppError::VersionConflict { .. })
        ));
    }

    // ---- transition matrices ----------------------------------------------

    #[test]
    fn the_account_status_transition_matrix_holds() {
        // -> ARCHIVED
        assert!(check_account_archivable(ClientAccountStatus::Active).is_ok());
        assert!(check_account_archivable(ClientAccountStatus::Suspended).is_ok());
        assert!(matches!(
            check_account_archivable(ClientAccountStatus::Archived),
            Err(AppError::Conflict {
                code: "CLIENT_ALREADY_ARCHIVED",
                ..
            })
        ));

        // editable?
        assert!(check_account_mutable(ClientAccountStatus::Active).is_ok());
        assert!(check_account_mutable(ClientAccountStatus::Suspended).is_ok());
        assert!(matches!(
            check_account_mutable(ClientAccountStatus::Archived),
            Err(AppError::Conflict {
                code: "CLIENT_ARCHIVED",
                ..
            })
        ));
    }

    #[test]
    fn the_membership_status_transition_matrix_holds() {
        use ClientMembershipStatus::*;

        // -> ACTIVE
        assert!(check_activatable(Pending).is_ok());
        assert!(check_activatable(Suspended).is_ok());
        assert!(matches!(
            check_activatable(Active),
            Err(AppError::Conflict {
                code: "MEMBERSHIP_ALREADY_ACTIVE",
                ..
            })
        ));
        assert!(
            matches!(
                check_activatable(Removed),
                Err(AppError::Conflict {
                    code: "MEMBERSHIP_REMOVED",
                    ..
                })
            ),
            "a removed membership must not be re-activated in one step"
        );

        // -> REMOVED
        for removable in [Pending, Active, Suspended] {
            assert!(
                check_removable(removable).is_ok(),
                "{removable:?} should be removable"
            );
        }
        assert!(matches!(
            check_removable(Removed),
            Err(AppError::Conflict {
                code: "MEMBERSHIP_ALREADY_REMOVED",
                ..
            })
        ));

        // -> PENDING (adding, or re-adding)
        assert!(check_addable(None).is_ok());
        assert!(check_addable(Some(Removed)).is_ok());
        for occupied in [Pending, Active, Suspended] {
            assert!(
                matches!(
                    check_addable(Some(occupied)),
                    Err(AppError::Conflict {
                        code: "ALREADY_A_MEMBER",
                        ..
                    })
                ),
                "{occupied:?} should not be addable again"
            );
        }
    }

    // ---- principal envelopes ----------------------------------------------

    #[test]
    fn client_membership_is_external_only_and_the_manager_is_internal_only() {
        assert!(check_client_principal("CLIENT").is_ok());
        assert!(check_internal_principal("INTERNAL").is_ok());
        for refused in ["INTERNAL", "internal", "", "ADMIN"] {
            assert!(
                matches!(
                    check_client_principal(refused),
                    Err(AppError::Conflict {
                        code: "PRINCIPAL_TYPE_MISMATCH",
                        ..
                    })
                ),
                "client membership accepted {refused:?}"
            );
        }
        for refused in ["CLIENT", "client", "", "ADMIN"] {
            assert!(
                matches!(
                    check_internal_principal(refused),
                    Err(AppError::Conflict {
                        code: "PRINCIPAL_TYPE_MISMATCH",
                        ..
                    })
                ),
                "account manager accepted {refused:?}"
            );
        }
    }

    #[test]
    fn an_archived_user_cannot_be_added_but_a_suspended_one_can() {
        assert!(matches!(
            check_user_addable("ARCHIVED"),
            Err(AppError::Conflict {
                code: "USER_ARCHIVED",
                ..
            })
        ));
        for allowed in ["ACTIVE", "SUSPENDED", "PENDING"] {
            assert!(check_user_addable(allowed).is_ok(), "refused {allowed}");
        }
    }

    #[test]
    fn every_conflict_renders_as_409_and_never_leaks_internals() {
        for err in [
            check_account_archivable(ClientAccountStatus::Archived).unwrap_err(),
            check_account_mutable(ClientAccountStatus::Archived).unwrap_err(),
            check_activatable(ClientMembershipStatus::Removed).unwrap_err(),
            check_removable(ClientMembershipStatus::Removed).unwrap_err(),
            check_addable(Some(ClientMembershipStatus::Active)).unwrap_err(),
            check_client_principal("INTERNAL").unwrap_err(),
            check_version(1, 2).unwrap_err(),
        ] {
            assert_eq!(err.status(), axum::http::StatusCode::CONFLICT);
            let rendered = format!("{err}");
            assert!(!rendered.contains("SELECT"), "leaked SQL: {rendered}");
            assert!(
                !rendered.contains("client_memberships"),
                "leaked a table name: {rendered}"
            );
        }
    }
}
