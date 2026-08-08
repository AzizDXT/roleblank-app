//! Invitations — the only path to an INTERNAL account.
//!
//! An invitation is a *deferred grant of authority*, and that is what makes it
//! dangerous. Between creation and acceptance the inviter may lose the very
//! permissions the invitation hands out, be suspended, or leave the company. So
//! the role set is validated **twice**:
//!
//! * at creation, against the inviter's authority and with a step-up when any role
//!   carries a dangerous permission;
//! * at acceptance, against the inviter's authority *as it stands then*, so a
//!   stale invitation cannot outlive the authority that created it.
//!
//! An invitation can never produce the system owner. Ownership is the singleton
//! `system_ownership` row, established once by `modules::bootstrap` and immutable
//! afterwards; nothing in this file writes to that table, and no role, permission
//! or flag confers ownership (ADR-004).

use std::time::Duration as StdDuration;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::app::AppState;
use crate::modules::audit::{action, AuditEvent, AuditMetadata, Outcome};
use crate::modules::authentication::principal;
use crate::modules::authorization::catalog;
use crate::modules::authorization::delegation::{self, DelegationRequest, RoleSummary};
use crate::modules::authorization::domain::{PrincipalType, Scope, ScopeType, Target};
use crate::modules::outbox;
use crate::platform::crypto::{password, tokens};
use crate::platform::errors::{AppError, AppResult};
use crate::platform::http::extract::{Authenticated, ClientIp};
use crate::platform::http::rate_limit::{keys, RateLimitDecision};
use crate::shared::pagination::{Page, PageRequest};
use crate::shared::secret::Secret;
use crate::shared::validation as v;

use super::dto::{
    opt_rfc3339, rfc3339, AcceptInvitationRequest, AcceptInvitationResponse,
    CreateInvitationRequest, InvitationResponse, ListInvitationsQuery,
};
use super::repo::{self, InvitationRow, NewInvitation, NewUser};
use super::service::PERM_USERS_INVITE;

/// Default invitation lifetime when the `invitations.ttl_hours` setting is absent
/// or unusable. Matches the seeded value in migration 0008.
const DEFAULT_TTL_HOURS: i64 = 72;
/// Bounds on the configured lifetime. A zero-hour TTL would make every invitation
/// dead on arrival; a multi-year one turns a leaked mailbox into a permanent way in.
const MIN_TTL_HOURS: i64 = 1;
const MAX_TTL_HOURS: i64 = 720; // 30 days

const ACCEPT_RATE_WINDOW: StdDuration = StdDuration::from_secs(3600);

/// The public route the invitation link points at, per
/// `docs/product/01-application-structure.md` §`public.invitation.accept`. A
/// front-end path: the recipient opens a page which then calls
/// `POST /api/v1/invitations/accept` with the token in the body, never in a URL
/// this API sees (TH-36).
const INVITATION_ACCEPT_PATH: &str = "/invitations/accept";

// =============================================================================
// Creation
// =============================================================================

/// `POST /api/v1/invitations`.
pub async fn create_invitation(
    state: &AppState,
    principal: &Authenticated,
    request: CreateInvitationRequest,
) -> AppResult<InvitationResponse> {
    state.require(principal, PERM_USERS_INVITE, &Target::Collection)?;

    let email_normalized = v::validate_email("email", &request.email)?;
    let email = request.email.trim().to_string();
    let display_name = v::required_text(
        "display_name",
        &request.display_name,
        v::MAX_DISPLAY_NAME_LEN,
    )?;
    let subject_type = v::parse_enum(
        "principal_type",
        &request.principal_type,
        PrincipalType::parse,
        &["INTERNAL", "CLIENT"],
    )?;
    v::validate_array_len("role_ids", &request.role_ids, v::MAX_ARRAY_LEN)?;

    // The two envelope constraints the database also enforces, checked here so the
    // caller gets a field error rather than an opaque constraint violation.
    if subject_type == PrincipalType::Internal && request.client_account_id.is_some() {
        return Err(AppError::field(
            "client_account_id",
            "NOT_APPLICABLE",
            "An INTERNAL invitation cannot be attached to a client account.",
        ));
    }
    if subject_type == PrincipalType::Client && request.department_id.is_some() {
        return Err(AppError::field(
            "department_id",
            "NOT_APPLICABLE",
            "A CLIENT invitation cannot be attached to a department.",
        ));
    }

    let mut role_ids = request.role_ids.clone();
    role_ids.sort_unstable();
    role_ids.dedup();

    let mut tx = state.begin().await?;

    if repo::find_user_by_email(&mut tx, &email_normalized)
        .await?
        .is_some()
    {
        // An authenticated internal caller with `iam.users.invite` may already list
        // users, so this is not an enumeration oracle — unlike the anonymous
        // registration endpoint, which deliberately answers identically either way.
        return Err(AppError::conflict(
            "EMAIL_IN_USE",
            "An account already exists for this email address.",
        ));
    }

    // Placement is an authorisation decision, not a data field.
    //
    // `department_id` and `client_account_id` arrive in the request body and become
    // real memberships on acceptance — a department membership resolves DEPARTMENT
    // scope, and a client membership becomes ACTIVE, the state that makes company
    // data visible outside the company. Authorising only `iam.users.invite` here
    // would let a principal reach through an invitation what they are refused
    // directly, using an address they control as a proxy. Each module authorises
    // its own placement, inside this transaction and against the locked row, so the
    // demand cannot go stale between the decision and the write.
    if let Some(department_id) = request.department_id {
        crate::modules::departments::service::authorize_placement(
            state,
            &principal.0,
            &mut tx,
            department_id,
        )
        .await?;
    }
    if let Some(client_account_id) = request.client_account_id {
        crate::modules::clients::service::authorize_placement(
            state,
            &principal.0,
            &mut tx,
            client_account_id,
        )
        .await?;
    }

    // Load every role and its permissions, then decide. Nothing is written until
    // all of them pass.
    let mut summaries = Vec::with_capacity(role_ids.len());
    for role_id in &role_ids {
        summaries.push(load_role_summary(&mut tx, *role_id).await?);
    }

    // Step-up is demanded for the *whole* request if any single role carries a
    // dangerous permission. Checked before the delegation guard so the caller gets
    // the real configured window rather than the guard's placeholder zero.
    if summaries.iter().any(role_is_dangerous) {
        state.require_step_up(principal)?;
    }

    let has_recent_step_up = principal.has_recent_step_up(state.config.sessions.step_up_window);
    for summary in &summaries {
        // `subject_id` is nil because the invitee does not exist yet. That is safe
        // and deliberate: the only thing the guard uses it for is the
        // "no self-modification of privilege" rule, and a nil id can never equal a
        // UUIDv7 actor id, so the rule can neither fire spuriously nor be dodged.
        let delegation_request = DelegationRequest {
            actor: &principal.actor,
            subject_id: Uuid::nil(),
            subject_principal_type: subject_type,
            subject_is_root: false,
            has_recent_step_up,
        };
        delegation::check_role_assignment(&delegation_request, summary)?;
    }

    // 32 bytes from the OS CSPRNG, handed out exactly once, stored only as a
    // SHA-256 digest. The prefix makes a leaked token identifiable to
    // secret-scanning tooling and makes presenting it to the wrong endpoint fail
    // loudly instead of ambiguously.
    let token = tokens::generate(tokens::INVITE_TOKEN_PREFIX)?;
    let ttl = ttl_hours(state).await;
    let expires_at = OffsetDateTime::now_utc() + Duration::hours(ttl);

    let invitation = NewInvitation {
        id: Uuid::now_v7(),
        email: email.clone(),
        email_normalized: email_normalized.clone(),
        display_name: display_name.clone(),
        principal_type: subject_type.as_str().to_string(),
        client_account_id: request.client_account_id,
        department_id: request.department_id,
        token_hash: token.hash.clone(),
        invited_by: principal.user_id(),
        expires_at,
    };

    repo::insert_invitation(&mut tx, &invitation).await?;
    for summary in &summaries {
        // Roles are stored at GLOBAL, which is the scope `invitation_roles`
        // defaults to and the only one a role assignment expresses; the role's own
        // permissions carry their scopes.
        repo::insert_invitation_role(&mut tx, invitation.id, summary.id, "GLOBAL").await?;
    }

    state
        .audit(
            &mut tx,
            AuditEvent::new(action::INVITATION_CREATED, Outcome::Success)
                .actor(
                    principal.user_id(),
                    principal.session.principal_type,
                    Some(principal.session.session_id),
                )
                .target("INVITATION", invitation.id)
                .meta(
                    AuditMetadata::new()
                        .str("email_normalized", &email_normalized)
                        .str("principal_type", subject_type.as_str())
                        .list("roles", summaries.iter().map(|s| s.code.clone()))
                        .opt_id("department_id", request.department_id)
                        .opt_id("client_account_id", request.client_account_id),
                ),
        )
        .await?;

    // The plaintext token leaves this process exactly once, in this payload, bound
    // for the mail provider. It commits in the same transaction as the invitation
    // row: a `tokio::spawn` after commit could lose the mail on a crash, and a send
    // before commit could deliver a token for an invitation that rolled back.
    //
    // The payload is built from `outbox::InvitationPayload`, the type the worker
    // deserialises, rather than from a free `json!`. A hand-shaped payload is not
    // rejected here — it is rejected at delivery, as a *permanent* failure, so the
    // invitation would dead-letter and the invitee would simply never hear from us
    // while the invitation row sat happily PENDING. The type makes that a compile
    // error rather than a silent operational hole.
    let payload = serde_json::to_value(outbox::InvitationPayload {
        to: email.clone(),
        invite_url: outbox::action_link(
            &state.config.public_base_url,
            INVITATION_ACCEPT_PATH,
            token.plaintext.expose(),
        ),
        // The inviter's own name, so the recipient can tell a legitimate invitation
        // from a phishing attempt. It is user-controlled text and is sanitised and
        // bounded by the mail builder before it reaches a message body.
        inviter_display_name: principal.session.display_name.clone(),
        expires_in_hours: u32::try_from(ttl).unwrap_or(u32::MAX),
    })
    .map_err(|_| AppError::internal("could not serialise the invitation mail payload"))?;
    outbox::enqueue(&mut tx, outbox::event_type::MAIL_INVITATION, payload).await?;

    let row = repo::find_invitation_for_update(&mut tx, invitation.id)
        .await?
        .ok_or_else(|| AppError::internal("invitation disappeared inside its own transaction"))?;

    tx.commit().await.map_err(AppError::from)?;

    Ok(invitation_response(&row, role_ids))
}

/// `GET /api/v1/invitations`.
pub async fn list_invitations(
    state: &AppState,
    principal: &Authenticated,
    query: &ListInvitationsQuery,
) -> AppResult<Page<InvitationResponse>> {
    // Listing invitations is GLOBAL-only: there is no narrower scope that makes
    // sense for "every pending grant of authority in the company".
    state.require(principal, PERM_USERS_INVITE, &Target::Collection)?;

    let page_query = query.page();
    let request = PageRequest::resolve(
        &page_query,
        repo::INVITATION_SORTS,
        repo::INVITATION_DEFAULT_SORT,
        state.config.limits.max_page_size,
    )?;

    let status = match &query.status {
        None => None,
        Some(raw) => Some(v::parse_enum(
            "status",
            raw,
            |s| matches!(s, "PENDING" | "ACCEPTED" | "REVOKED" | "EXPIRED").then(|| s.to_string()),
            &["PENDING", "ACCEPTED", "REVOKED", "EXPIRED"],
        )?),
    };

    let rows = repo::list_invitations(&state.db, &request, status.as_deref()).await?;
    let sort_column = request.sort_column;
    let page = Page::build(rows, &request, |row| {
        repo::to_cursor(repo::invitation_sort_value(row, sort_column), row.id)
    });

    // One extra query for the whole page rather than one per row.
    let ids: Vec<Uuid> = page.items.iter().map(|row| row.id).collect();
    let pairs = repo::invitation_roles_for(&state.db, &ids).await?;

    let items = page
        .items
        .iter()
        .map(|row| {
            let roles = pairs
                .iter()
                .filter(|(invitation_id, _)| *invitation_id == row.id)
                .map(|(_, role_id)| *role_id)
                .collect();
            invitation_response(row, roles)
        })
        .collect();

    Ok(Page {
        items,
        next_cursor: page.next_cursor,
        has_more: page.has_more,
    })
}

/// `DELETE /api/v1/invitations/{id}` — revoke, not erase.
///
/// The row survives with `status = 'REVOKED'`, so "who invited whom, and who
/// changed their mind" remains answerable.
pub async fn revoke_invitation(
    state: &AppState,
    principal: &Authenticated,
    id: Uuid,
) -> AppResult<InvitationResponse> {
    let mut tx = state.begin().await?;

    // Authorise before the row is loaded. The decision is `Target::Collection` —
    // it needs nothing from the invitation — so loading first bought no accuracy
    // and cost an existence oracle: an unauthorised internal principal received
    // `403` for a real invitation id and `404` for an invented one, and could
    // enumerate outstanding invitations without ever being allowed to read one.
    state.require(principal, PERM_USERS_INVITE, &Target::Collection)?;

    let row = repo::find_invitation_for_update(&mut tx, id)
        .await?
        .ok_or(AppError::NotFound)?;

    let affected = repo::mark_invitation_revoked(&mut tx, row.id).await?;
    if affected == 0 {
        return Err(AppError::conflict(
            "INVITATION_NOT_PENDING",
            "Only a pending invitation can be revoked.",
        ));
    }

    state
        .audit(
            &mut tx,
            AuditEvent::new(action::INVITATION_REVOKED, Outcome::Success)
                .actor(
                    principal.user_id(),
                    principal.session.principal_type,
                    Some(principal.session.session_id),
                )
                .target("INVITATION", row.id)
                .meta(AuditMetadata::new().str("email_normalized", &row.email_normalized)),
        )
        .await?;

    let roles = repo::invitation_role_ids(&mut tx, row.id).await?;
    let updated = repo::find_invitation_for_update(&mut tx, row.id)
        .await?
        .ok_or_else(|| AppError::internal("invitation disappeared inside its own transaction"))?;

    tx.commit().await.map_err(AppError::from)?;
    Ok(invitation_response(&updated, roles))
}

// =============================================================================
// Acceptance
// =============================================================================

/// `POST /api/v1/invitations/accept` — anonymous, token in the body.
///
/// Every rejection reason returns the same `AUTHENTICATION_FAILED`: unknown token,
/// already accepted, revoked, expired, and inviter-no-longer-authorised are
/// indistinguishable to the caller. Distinguishing them would tell somebody
/// holding a stolen token exactly what happened to it.
pub async fn accept_invitation(
    state: &AppState,
    client_ip: ClientIp,
    mut request: AcceptInvitationRequest,
) -> AppResult<AcceptInvitationResponse> {
    // Accepting an invitation creates an account, but it draws on its **own**
    // per-IP budget rather than self-registration's.
    //
    // Sharing the registration budget coupled two flows with different risk: an
    // attacker hammering `/api/v1/registration` from an address could exhaust it
    // and block invitation acceptance for every legitimate user behind that same
    // address — a corporate NAT, which is the normal case. It also capped
    // onboarding at three people per hour per office. Acceptance still needs a
    // limit (the token is guessable in principle), just not a shared one.
    let decision = state
        .limiter
        .check(
            &keys::invitation_accept_ip(client_ip.0),
            state.config.rate_limits.invitation_accept_per_ip_per_hour,
            ACCEPT_RATE_WINDOW,
        )
        .await;
    if let RateLimitDecision::Limited {
        retry_after_seconds,
    } = decision
    {
        return Err(AppError::TooManyRequests {
            retry_after_seconds,
        });
    }

    // Shape check before touching the database: a flood of 100 KB garbage tokens
    // would otherwise each cost an indexed lookup.
    if !tokens::is_well_formed(&request.token, tokens::INVITE_TOKEN_PREFIX) {
        return Err(AppError::AuthenticationFailed);
    }
    let token_hash = tokens::hash_token(&request.token);

    // A non-locking preview, purely so that Argon2id runs *before* a transaction is
    // opened. Hashing costs tens of milliseconds; doing it inside the transaction
    // would hold a pooled connection — and the invitation row lock — for that long.
    // Nothing is decided on this read: every check is repeated authoritatively
    // under `FOR UPDATE` below.
    //
    // No dummy-hash timing equalisation here, unlike login: the token is 256 bits
    // of uniform randomness, so "does this token exist" is not a question an
    // attacker can usefully ask.
    let preview = repo::find_invitation_by_token(&state.db, &token_hash)
        .await?
        .ok_or(AppError::AuthenticationFailed)?;

    let display_name = match &request.display_name {
        None => preview.display_name.clone(),
        Some(value) => v::required_text("display_name", value, v::MAX_DISPLAY_NAME_LEN)?,
    };
    password::validate_password(&request.password, &preview.email_normalized, &display_name)?;

    let supplied = Secret::new(std::mem::take(&mut request.password));
    let password_hash = state.hasher.hash(&supplied).await?;
    drop(supplied);

    // ---- the inviter's delegation context, built BEFORE the transaction opens ---
    //
    // **Why this must not happen inside the transaction.** `load_actor` issues three
    // queries and `actor_basics` a fourth. Run from inside an open transaction they
    // ask the pool for a *second* connection while this task already holds one. Once
    // the number of simultaneous acceptances reaches the pool size, every task holds
    // a connection and every task waits for one that only a peer could release: the
    // pool deadlocks until `acquire_timeout`, and the attempts queued behind the
    // invitation's row lock are killed by `statement_timeout` first. Measured at
    // fifty concurrent acceptances of a single valid token, that yielded 17×503,
    // 3×500 and — the part that actually matters — *zero* successful acceptances.
    // The invitee simply could not create their account, and the exhausted pool is
    // shared with every other endpoint, so the blast radius was the whole service.
    //
    // Hoisting these reads costs nothing in correctness. They were already issued on
    // a *different* connection with its own snapshot, so sitting inside the
    // transaction never made them consistent with the invitation row. The freshness
    // that genuinely matters — "is the inviter still active *now*" — is re-checked
    // below on the transaction's own connection, which needs no second pool slot.
    let inviter_preview = repo::actor_basics(&state.db, preview.invited_by)
        .await?
        .ok_or(AppError::AuthenticationFailed)?;
    let inviter_type = PrincipalType::parse(&inviter_preview.principal_type)
        .ok_or_else(|| AppError::internal("inviter has an unrecognised principal_type"))?;
    let inviter_actor = principal::load_actor(
        &state.db,
        preview.invited_by,
        inviter_type,
        inviter_preview.is_root,
    )
    .await?;

    let mut tx = state.begin().await?;

    // The authoritative read. `FOR UPDATE` is what makes two simultaneous
    // acceptances deterministic: the second blocks here and observes
    // `status = 'ACCEPTED'` once the first commits.
    let invitation = repo::find_invitation_by_token_for_update(&mut tx, &token_hash)
        .await?
        .ok_or(AppError::AuthenticationFailed)?;

    if invitation.status != "PENDING" {
        return Err(AppError::AuthenticationFailed);
    }
    if invitation.expires_at <= OffsetDateTime::now_utc() {
        // Retire the row so it stops occupying the "one PENDING per email" partial
        // unique index, then fail exactly like every other rejection.
        repo::mark_invitation_expired(&mut tx, invitation.id).await?;
        tx.commit().await.map_err(AppError::from)?;
        return Err(AppError::AuthenticationFailed);
    }

    let subject_type = PrincipalType::parse(&invitation.principal_type)
        .ok_or_else(|| AppError::internal("invitation has an unrecognised principal_type"))?;

    // The delegation context above was computed from the non-locking preview. If the
    // locked row names a different author, that context belongs to the wrong
    // principal and every authority check below would be validating the wrong
    // person. `invited_by` is immutable so this cannot happen — it is asserted
    // rather than assumed, because the cost of being wrong is an unauthorised grant.
    if invitation.invited_by != preview.invited_by {
        return Err(AppError::AuthenticationFailed);
    }

    // ---- re-validate against the inviter's authority as it stands NOW ----------
    //
    // On the transaction's own connection, so it costs no second pool slot. This is
    // the authoritative freshness check: a suspension that landed while this request
    // was queued behind the row lock is observed here, not by the hoisted read.
    let inviter = repo::actor_basics(&mut *tx, invitation.invited_by)
        .await?
        .ok_or(AppError::AuthenticationFailed)?;
    if inviter.status != "ACTIVE" {
        // The authority behind this invitation no longer exists. Honouring it would
        // let a suspended or departed administrator keep placing people in the
        // company after their own access ended.
        tracing::warn!(
            invitation.id = %invitation.id,
            "refused an invitation whose inviter is no longer active"
        );
        return Err(AppError::AuthenticationFailed);
    }

    let new_user_id = Uuid::now_v7();
    let role_ids = repo::invitation_role_ids(&mut tx, invitation.id).await?;

    let mut summaries = Vec::with_capacity(role_ids.len());
    for role_id in &role_ids {
        summaries.push(load_role_summary(&mut tx, *role_id).await?);
    }

    for summary in &summaries {
        let delegation_request = DelegationRequest {
            actor: &inviter_actor,
            subject_id: new_user_id,
            subject_principal_type: subject_type,
            // Structurally impossible: `new_user_id` was minted a few lines above
            // and cannot be the owner, and nothing here writes `system_ownership`.
            // Stated explicitly so the guard is applied uniformly rather than
            // skipped on a "can't happen" argument.
            subject_is_root: false,
            // Step-up recency was proved by the inviter at creation time and cannot
            // be re-proved by a principal who is not present. What is re-checked
            // here is *authority* — rules 1, 2, 5, 6 and 7 of the delegation guard,
            // including any DENY override added since.
            has_recent_step_up: true,
        };
        delegation::check_role_assignment(&delegation_request, summary).map_err(|e| {
            tracing::warn!(
                invitation.id = %invitation.id,
                role = %summary.code,
                "invitation refused: the inviter can no longer delegate one of its roles"
            );
            match e {
                // Never leak which role, or why, to an anonymous caller.
                AppError::DelegationDenied { .. } | AppError::RootProtected => {
                    AppError::AuthenticationFailed
                }
                other => other,
            }
        })?;
    }

    // MFA is mandatory for anyone holding a dangerous permission, so the account is
    // created already in the MFA_ENROLMENT_REQUIRED state rather than relying on a
    // later prompt the user could ignore.
    let mfa_required = summaries.iter().any(role_is_dangerous);

    repo::insert_user(
        &mut tx,
        &NewUser {
            id: new_user_id,
            email: invitation.email.clone(),
            email_normalized: invitation.email_normalized.clone(),
            display_name: display_name.clone(),
            // Taken from the invitation, which only an authorised internal
            // principal could author — never from the acceptance request, which has
            // no field for it.
            principal_type: subject_type.as_str().to_string(),
            status: "ACTIVE".to_string(),
            mfa_required,
            activated: true,
        },
    )
    .await?;
    repo::insert_credentials(&mut tx, new_user_id, &password_hash).await?;

    for summary in &summaries {
        repo::assign_role(&mut tx, new_user_id, summary.id, invitation.invited_by).await?;
    }

    if let Some(client_account_id) = invitation.client_account_id {
        // ACTIVE, unlike self-registration: an internal principal named this
        // account deliberately when they issued the invitation.
        repo::insert_client_membership(
            &mut tx,
            client_account_id,
            new_user_id,
            "ACTIVE",
            invitation.invited_by,
        )
        .await?;
    }
    if let Some(department_id) = invitation.department_id {
        repo::insert_department_membership(
            &mut tx,
            department_id,
            new_user_id,
            invitation.invited_by,
        )
        .await?;
    }

    // Single use, gated on rows affected. If a concurrent acceptance won, this
    // returns zero and the whole transaction — including the user row inserted
    // above — rolls back. Exactly one of two racing acceptances succeeds.
    let consumed = repo::mark_invitation_accepted(&mut tx, invitation.id, new_user_id).await?;
    if consumed != 1 {
        return Err(AppError::AuthenticationFailed);
    }

    state
        .audit(
            &mut tx,
            AuditEvent::new(action::USER_CREATED, Outcome::Success)
                .actor(new_user_id, subject_type, None)
                .target("USER", new_user_id)
                .source_ip(client_ip.hint())
                .meta(
                    AuditMetadata::new()
                        .str("source", "INVITATION")
                        .str("principal_type", subject_type.as_str())
                        .id("invitation_id", invitation.id)
                        .bool("mfa_required", mfa_required)
                        .list("roles", summaries.iter().map(|s| s.code.clone())),
                ),
        )
        .await?;

    state
        .audit(
            &mut tx,
            AuditEvent::new(action::INVITATION_ACCEPTED, Outcome::Success)
                .actor(new_user_id, subject_type, None)
                .target("INVITATION", invitation.id)
                .source_ip(client_ip.hint())
                .meta(AuditMetadata::new().id("user_id", new_user_id)),
        )
        .await?;

    tx.commit().await.map_err(AppError::from)?;

    // No session and no token: the invitee authenticates through the ordinary login
    // path, which is also where MFA enrolment is enforced.
    Ok(AcceptInvitationResponse {
        user_id: new_user_id,
        email: invitation.email,
        display_name,
        principal_type: subject_type.as_str().to_string(),
        status: "ACTIVE".to_string(),
        mfa_enrolment_required: mfa_required,
    })
}

// =============================================================================
// Helpers
// =============================================================================

/// Load a role together with every permission it carries.
///
/// The permissions are what the delegation guard actually checks. Validating a
/// role as an opaque unit — "may I assign roles?" — is the classic escalation hole:
/// an administrator with `iam.roles.assign` but without `settings.security.write`
/// could otherwise assign a role that contains it.
async fn load_role_summary(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    role_id: Uuid,
) -> AppResult<RoleSummary> {
    let role = repo::find_role(tx, role_id).await?.ok_or_else(|| {
        AppError::field("role_ids", "NOT_FOUND", "One of the roles does not exist.")
    })?;

    let allowed_principal_type = PrincipalType::parse(&role.allowed_principal_type)
        .ok_or_else(|| AppError::internal("role has an unrecognised allowed_principal_type"))?;

    let mut permissions = Vec::new();
    for (code, scope_type) in repo::role_permissions(tx, role_id).await? {
        let Some(parsed) = ScopeType::parse(&scope_type) else {
            // Unparseable authorisation data must never be treated as a wider
            // grant, and must never be silently dropped from a delegation check —
            // dropping it would let an un-delegatable permission slip through.
            return Err(AppError::internal(
                "role permission has an unrecognised scope_type",
            ));
        };
        if !parsed.valid_on_role() {
            return Err(AppError::internal(
                "role permission carries a RESOURCE scope",
            ));
        }
        permissions.push((code, Scope::simple(parsed)));
    }

    Ok(RoleSummary {
        id: role.id,
        code: role.code,
        is_system: role.is_system,
        allowed_principal_type,
        permissions,
    })
}

/// Does this role carry anything flagged dangerous?
fn role_is_dangerous(role: &RoleSummary) -> bool {
    role.permissions
        .iter()
        .any(|(code, _)| catalog::is_dangerous(code))
}

/// The configured invitation lifetime, clamped.
///
/// A malformed or out-of-range setting falls back to the documented default rather
/// than failing the request: a bad setting must not make invitations impossible,
/// and it must not make them eternal either.
async fn ttl_hours(state: &AppState) -> i64 {
    let configured = match repo::read_setting(&state.db, "invitations.ttl_hours").await {
        Ok(Some(value)) => value.as_i64(),
        Ok(None) => None,
        Err(e) => {
            tracing::warn!(error = %e, "could not read invitations.ttl_hours; using the default");
            None
        }
    };
    configured
        .unwrap_or(DEFAULT_TTL_HOURS)
        .clamp(MIN_TTL_HOURS, MAX_TTL_HOURS)
}

fn invitation_response(row: &InvitationRow, role_ids: Vec<Uuid>) -> InvitationResponse {
    InvitationResponse {
        id: row.id,
        email: row.email.clone(),
        display_name: row.display_name.clone(),
        principal_type: row.principal_type.clone(),
        status: row.status.clone(),
        invited_by: row.invited_by,
        department_id: row.department_id,
        client_account_id: row.client_account_id,
        role_ids,
        expires_at: rfc3339(row.expires_at),
        created_at: rfc3339(row.created_at),
        accepted_at: opt_rfc3339(row.accepted_at),
        accepted_user_id: row.accepted_user_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn role(code: &str, permissions: &[&str]) -> RoleSummary {
        RoleSummary {
            id: Uuid::now_v7(),
            code: code.into(),
            is_system: false,
            allowed_principal_type: PrincipalType::Internal,
            permissions: permissions
                .iter()
                .map(|c| ((*c).to_string(), Scope::global()))
                .collect(),
        }
    }

    #[test]
    fn a_role_is_dangerous_when_any_one_of_its_permissions_is() {
        assert!(!role_is_dangerous(&role(
            "reader",
            &["projects.read", "tasks.read"]
        )));
        assert!(role_is_dangerous(&role(
            "sharer",
            &["projects.read", "projects.clients.share"]
        )));
        assert!(role_is_dangerous(&role(
            "granter",
            &["iam.permissions.delegate"]
        )));
        assert!(!role_is_dangerous(&role("empty", &[])));
    }

    /// An unknown permission code must not be treated as harmless. It cannot be
    /// assigned at all — the delegation guard rejects it — but the step-up decision
    /// must not be the thing that lets it through quietly.
    #[test]
    fn an_unknown_permission_is_not_reported_as_safe_by_accident() {
        let r = role("mystery", &["not.a.real.permission"]);
        // `is_dangerous` answers false for unknown codes, so the guard — not this
        // helper — is what refuses the role. Assert the guard actually does.
        assert!(!role_is_dangerous(&r));
        let actor = crate::modules::authorization::domain::ActorContext::empty(
            Uuid::now_v7(),
            PrincipalType::Internal,
        );
        let request = DelegationRequest {
            actor: &actor,
            subject_id: Uuid::nil(),
            subject_principal_type: PrincipalType::Internal,
            subject_is_root: false,
            has_recent_step_up: true,
        };
        assert!(matches!(
            delegation::check_role_assignment(&request, &r),
            Err(AppError::UnknownPermission)
        ));
    }

    /// The nil subject id used at creation time can never collide with a real actor,
    /// so the "no self-modification" rule can neither misfire nor be dodged.
    #[test]
    fn the_placeholder_subject_id_can_never_be_a_real_actor() {
        for _ in 0..100 {
            assert_ne!(Uuid::now_v7(), Uuid::nil());
        }
    }

    #[test]
    fn the_invitation_lifetime_is_clamped_at_both_ends() {
        assert_eq!(
            DEFAULT_TTL_HOURS.clamp(MIN_TTL_HOURS, MAX_TTL_HOURS),
            DEFAULT_TTL_HOURS
        );
        assert_eq!(0i64.clamp(MIN_TTL_HOURS, MAX_TTL_HOURS), MIN_TTL_HOURS);
        assert_eq!((-5i64).clamp(MIN_TTL_HOURS, MAX_TTL_HOURS), MIN_TTL_HOURS);
        assert_eq!(i64::MAX.clamp(MIN_TTL_HOURS, MAX_TTL_HOURS), MAX_TTL_HOURS);
        assert_eq!(
            100_000i64.clamp(MIN_TTL_HOURS, MAX_TTL_HOURS),
            MAX_TTL_HOURS
        );
    }

    #[test]
    fn invitation_tokens_carry_their_own_prefix_and_are_recognisable() {
        let t = tokens::generate(tokens::INVITE_TOKEN_PREFIX).expect("csprng");
        assert!(t.plaintext.expose().starts_with("rb_iv_"));
        assert!(tokens::is_well_formed(
            t.plaintext.expose(),
            tokens::INVITE_TOKEN_PREFIX
        ));
        // An access token presented here fails the shape check before any lookup.
        let access = tokens::generate(tokens::ACCESS_TOKEN_PREFIX).expect("csprng");
        assert!(!tokens::is_well_formed(
            access.plaintext.expose(),
            tokens::INVITE_TOKEN_PREFIX
        ));
        assert_eq!(
            t.hash.len(),
            32,
            "the stored digest is what the column CHECK requires"
        );
    }
}
