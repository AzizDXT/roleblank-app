//! The authentication service: transaction boundary, audit, and invariants.
//!
//! The invariant that governs every function here: **a client can never tell one
//! authentication failure from another.** Unknown account, wrong password,
//! suspended user, expired token, revoked session, consumed reset link — all of
//! them return `AppError::AuthenticationFailed`, which renders one fixed body
//! (TH-23). The *reason* is recorded in the audit log, where it belongs.
//!
//! The second invariant is timing: the unknown-account path performs the same
//! Argon2id work as the known-account path, because a response that returns in
//! microseconds instead of tens of milliseconds is an account-existence oracle
//! that no amount of identical JSON can hide.

use std::net::IpAddr;
use std::time::Duration as StdDuration;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::app::AppState;
use crate::modules::audit::{action, AuditEvent, AuditMetadata, Outcome};
use crate::modules::authentication::principal::Principal;
use crate::modules::authentication::{dto, repo, sessions};
use crate::modules::authorization::domain::PrincipalType;
use crate::modules::authorization::evaluator;
use crate::platform::crypto::{password, tokens};
use crate::platform::errors::{AppError, AppResult};
use crate::platform::http::rate_limit::{keys, RateLimitDecision};
use crate::shared::secret::Secret;
use crate::shared::validation as v;

const MINUTE: StdDuration = StdDuration::from_secs(60);
const HOUR: StdDuration = StdDuration::from_secs(3600);

/// Reset links are short-lived on purpose: the window in which a link sitting in a
/// mailbox is useful to an attacker is the window this constant sets.
const RESET_TOKEN_TTL: Duration = Duration::minutes(30);

const STATUS_ACTIVE: &str = "ACTIVE";

/// Request-derived context that is recorded but never trusted.
///
/// `ip` keys the rate limiter; the two hints are stored so a user can recognise
/// their own sessions. Neither ever participates in an authorisation decision —
/// IP binding breaks mobile clients on every network change and hands an attacker
/// a spoofable input (ADR-005).
#[derive(Debug, Clone)]
pub struct ClientHints {
    pub ip: IpAddr,
    pub ip_hint: Option<String>,
    pub user_agent_hint: Option<String>,
}

/// Consume one unit of a rate-limit bucket, or fail the request.
pub(super) async fn enforce_limit(
    state: &AppState,
    key: &str,
    quota: u32,
    window: StdDuration,
) -> AppResult<()> {
    match state.limiter.check(key, quota, window).await {
        RateLimitDecision::Allowed { .. } => Ok(()),
        RateLimitDecision::Limited {
            retry_after_seconds,
        } => Err(AppError::TooManyRequests {
            retry_after_seconds,
        }),
    }
}

pub(super) fn parse_principal_type(raw: &str) -> AppResult<PrincipalType> {
    PrincipalType::parse(raw)
        .ok_or_else(|| AppError::Internal("user has an unrecognised principal_type".into()))
}

// =============================================================================
// Login
// =============================================================================

/// `POST /auth/login`.
///
/// The step numbering follows `docs/backend/03-authentication.md` §4 exactly. The
/// two steps that are easy to "simplify" and must not be are 3 (the dummy hash)
/// and 4 (the inactive-account path also spending the hash), because both exist
/// solely to keep the response time independent of the account's existence and
/// state.
pub async fn login(
    state: &AppState,
    hints: &ClientHints,
    request: dto::LoginRequest,
) -> AppResult<dto::TokenResponse> {
    // 1 — per-IP first, before any parsing or database work.
    enforce_limit(
        state,
        &keys::login_ip(hints.ip),
        state.config.rate_limits.login_per_ip_per_minute,
        MINUTE,
    )
    .await?;

    let email_normalized = v::normalize_email(&request.email);
    let password = Secret::new(request.password);

    // Shape bounds, not validation: an address longer than the column or a
    // password longer than the policy permits can never match a stored account, so
    // rejecting them costs nothing and reveals nothing. Doing it here keeps a 200 KB
    // "password" out of Argon2's input hashing.
    if email_normalized.is_empty()
        || email_normalized.len() > v::MAX_EMAIL_LEN
        || password.expose().chars().count() > password::MAX_PASSWORD_CHARS
    {
        return Err(AppError::AuthenticationFailed);
    }

    // 1 (continued) — per normalised account, so case variation cannot multiply
    // the quota and one host cannot grind every account at once.
    let account_key = keys::login_account(&email_normalized);
    enforce_limit(
        state,
        &account_key,
        state.config.rate_limits.login_per_account_per_minute,
        MINUTE,
    )
    .await?;

    // 2 — look the account up.
    let Some(candidate) = repo::find_login_candidate(&state.db, &email_normalized).await? else {
        // 3 — the account does not exist. Spend the same Argon2id time anyway.
        state.hasher.verify_dummy(&password).await;
        audit_login_failure(state, hints, &email_normalized, None, "unknown_account").await?;
        return Err(AppError::AuthenticationFailed);
    };

    let principal_type = parse_principal_type(&candidate.principal_type)?;
    let subject = Some((candidate.user_id, principal_type));

    // 4 — PENDING, SUSPENDED and ARCHIVED are all indistinguishable from a wrong
    // password. `verify_dummy` rather than an early return, so the timing is too.
    if candidate.status != STATUS_ACTIVE {
        state.hasher.verify_dummy(&password).await;
        audit_login_failure(state, hints, &email_normalized, subject, "inactive_account").await?;
        return Err(AppError::AuthenticationFailed);
    }

    // 5 — the real verification, under the hashing semaphore.
    if !state
        .hasher
        .verify(&password, &candidate.password_hash)
        .await?
    {
        audit_login_failure(state, hints, &email_normalized, subject, "bad_password").await?;
        return Err(AppError::AuthenticationFailed);
    }

    // 6 — a user who must use MFA, or who chose to enrol, gets a session that can
    // reach nothing but the MFA endpoints until they prove the second factor.
    let pending_mfa =
        sessions::requires_mfa_completion(candidate.mfa_required, candidate.mfa_enrolled);

    let issued =
        issue_session(state, hints, candidate.user_id, principal_type, pending_mfa).await?;

    // A user who mistyped their password four times must not still be penalised
    // after they get it right.
    state.limiter.reset(&account_key).await;

    Ok(issued)
}

/// Create a session, enforce the per-user cap, and mint the first token pair.
async fn issue_session(
    state: &AppState,
    hints: &ClientHints,
    user_id: Uuid,
    principal_type: PrincipalType,
    pending_mfa: bool,
) -> AppResult<dto::TokenResponse> {
    let now = OffsetDateTime::now_utc();
    let lifetimes = sessions::new_lifetimes(&state.config.sessions, now)?;
    let refresh_expires_at =
        sessions::refresh_expiry(&state.config.sessions, now, lifetimes.absolute_expires_at)?;

    let access = tokens::generate(tokens::ACCESS_TOKEN_PREFIX)?;
    let refresh = tokens::generate(tokens::REFRESH_TOKEN_PREFIX)?;
    let session_id = Uuid::now_v7();

    let mut tx = state.begin().await?;

    // The cap is counted and applied inside the transaction. Counting outside it
    // and inserting inside leaves a window in which N concurrent logins each see
    // room for one more (TH-43).
    let live = repo::count_live_sessions(&mut tx, user_id).await?;
    let surplus = sessions::surplus_sessions(live, state.config.sessions.max_per_user);
    if surplus > 0 {
        for evicted in repo::oldest_live_session_ids(&mut tx, user_id, surplus).await? {
            repo::revoke_session(&mut tx, evicted, sessions::reason::SECURITY_POLICY).await?;
            state
                .audit(
                    &mut tx,
                    AuditEvent::new(action::SESSION_REVOKED, Outcome::Success)
                        .actor(user_id, principal_type, Some(evicted))
                        .target("SESSION", evicted)
                        .source_ip(hints.ip_hint.clone())
                        .meta(AuditMetadata::new().str("reason", "session_limit_exceeded")),
                )
                .await?;
        }
    }

    repo::insert_session(
        &mut tx,
        repo::NewSession {
            id: session_id,
            user_id,
            access_token_hash: access.hash.clone(),
            access_expires_at: lifetimes.access_expires_at,
            idle_expires_at: lifetimes.idle_expires_at,
            absolute_expires_at: lifetimes.absolute_expires_at,
            // Always PASSWORD at login. `MFA` is reached only by verifying a second
            // factor, and the `sessions_mfa_consistent` CHECK refuses the
            // combination `pending_mfa AND auth_level = 'MFA'` independently.
            auth_level: sessions::AUTH_LEVEL_PASSWORD,
            pending_mfa,
            client_ip_hint: hints.ip_hint.clone(),
            user_agent_hint: hints.user_agent_hint.clone(),
        },
    )
    .await?;

    repo::insert_refresh_token(
        &mut tx,
        repo::NewRefreshToken {
            id: Uuid::now_v7(),
            session_id,
            token_hash: refresh.hash.clone(),
            generation: 0,
            expires_at: refresh_expires_at,
        },
    )
    .await?;

    state
        .audit(
            &mut tx,
            AuditEvent::new(action::AUTH_LOGIN_SUCCEEDED, Outcome::Success)
                .actor(user_id, principal_type, Some(session_id))
                .target("SESSION", session_id)
                .source_ip(hints.ip_hint.clone())
                .meta(
                    AuditMetadata::new()
                        .bool("mfa_pending", pending_mfa)
                        .str("assurance", sessions::AUTH_LEVEL_PASSWORD),
                ),
        )
        .await?;

    tx.commit().await?;

    Ok(dto::TokenResponse {
        // The single moment plaintext token material exists outside the CSPRNG.
        // Only the digests reached the database.
        access_token: access.plaintext.expose().clone(),
        refresh_token: refresh.plaintext.expose().clone(),
        expires_in: (lifetimes.access_expires_at - now).whole_seconds(),
        mfa_required: pending_mfa,
        token_type: dto::TOKEN_TYPE,
    })
}

/// Record a failed login.
///
/// The attempted **normalised** email is recorded because an operator
/// investigating a spray needs to know which accounts were targeted. The password
/// is never recorded, in any form, not even a length — the metadata builder would
/// refuse a key containing `password` anyway.
async fn audit_login_failure(
    state: &AppState,
    hints: &ClientHints,
    email_normalized: &str,
    subject: Option<(Uuid, PrincipalType)>,
    reason: &'static str,
) -> AppResult<()> {
    let mut event = AuditEvent::new(action::AUTH_LOGIN_FAILED, Outcome::Failure)
        .source_ip(hints.ip_hint.clone())
        .meta(
            AuditMetadata::new()
                .str("attempted_email", email_normalized)
                .str("reason", reason),
        );
    if let Some((user_id, principal_type)) = subject {
        event = event
            .actor(user_id, principal_type, None)
            .target("USER", user_id);
    }

    let mut tx = state.begin().await?;
    state.audit(&mut tx, event).await?;
    tx.commit().await?;
    Ok(())
}

// =============================================================================
// Refresh
// =============================================================================

/// `POST /auth/refresh` — unconditional rotation with reuse detection (§5).
pub async fn refresh(
    state: &AppState,
    hints: &ClientHints,
    request: dto::RefreshRequest,
) -> AppResult<dto::TokenResponse> {
    enforce_limit(
        state,
        &keys::refresh_ip(hints.ip),
        state.config.rate_limits.refresh_per_ip_per_minute,
        MINUTE,
    )
    .await?;

    // A refresh token presented to the access path, or garbage, fails here without
    // costing an indexed lookup.
    if !tokens::is_well_formed(&request.refresh_token, tokens::REFRESH_TOKEN_PREFIX) {
        return Err(AppError::AuthenticationFailed);
    }
    let presented = tokens::hash_token(&request.refresh_token);
    let now = OffsetDateTime::now_utc();

    let mut tx = state.begin().await?;

    // `FOR UPDATE` on the token row. Two concurrent refreshes now have a
    // deterministic outcome: one rotates, the other reads a consumed row.
    let Some(row) = repo::lock_refresh_token(&mut tx, &presented).await? else {
        // Unknown token. Not audited: an attacker with a token generator would
        // otherwise be able to write unbounded rows into an append-only table.
        return Err(AppError::AuthenticationFailed);
    };

    let principal_type = parse_principal_type(&row.principal_type)?;
    let verdict = sessions::classify_refresh(
        sessions::RefreshFacts {
            consumed: row.consumed_at.is_some(),
            token_expires_at: row.token_expires_at,
            session_revoked: row.session_revoked_at.is_some(),
            absolute_expires_at: row.absolute_expires_at,
            idle_expires_at: row.idle_expires_at,
            user_is_active: row.user_status == STATUS_ACTIVE,
        },
        now,
    );

    match verdict {
        sessions::RefreshVerdict::ReuseDetected => {
            // Two parties hold the same refresh token. The only safe reading is
            // compromise, so the entire family dies — including the legitimate
            // holder's. A spurious re-login is a smaller harm than an undetected
            // persistent session (ADR-005).
            repo::revoke_session(
                &mut tx,
                row.session_id,
                sessions::reason::REFRESH_REUSE_DETECTED,
            )
            .await?;
            let killed = repo::consume_family(&mut tx, row.session_id).await?;
            state
                .audit(
                    &mut tx,
                    AuditEvent::new(action::AUTH_REFRESH_REUSE_DETECTED, Outcome::Failure)
                        .actor(row.user_id, principal_type, Some(row.session_id))
                        .target("SESSION", row.session_id)
                        .source_ip(hints.ip_hint.clone())
                        .meta(
                            AuditMetadata::new()
                                .int("presented_generation", i64::from(row.generation))
                                .int(
                                    "tokens_invalidated",
                                    i64::try_from(killed).unwrap_or(i64::MAX),
                                )
                                .str("action_taken", "session_family_revoked"),
                        ),
                )
                .await?;
            // The revocation must survive; the response is still the generic failure.
            tx.commit().await?;
            return Err(AppError::AuthenticationFailed);
        }
        // Dropping the transaction rolls it back; nothing was written.
        sessions::RefreshVerdict::Rejected => return Err(AppError::AuthenticationFailed),
        sessions::RefreshVerdict::Rotate => {}
    }

    // Gated on rows affected even though the row is locked: if the lock were ever
    // removed by a refactor, single use would still hold here.
    if repo::consume_refresh_token(&mut tx, row.token_id).await? != 1 {
        return Err(AppError::AuthenticationFailed);
    }

    let lifetimes =
        sessions::refreshed_lifetimes(&state.config.sessions, now, row.absolute_expires_at)?;
    let refresh_expires_at =
        sessions::refresh_expiry(&state.config.sessions, now, row.absolute_expires_at)?;
    let access = tokens::generate(tokens::ACCESS_TOKEN_PREFIX)?;
    let next_refresh = tokens::generate(tokens::REFRESH_TOKEN_PREFIX)?;
    let next_id = Uuid::now_v7();

    repo::insert_refresh_token(
        &mut tx,
        repo::NewRefreshToken {
            id: next_id,
            session_id: row.session_id,
            token_hash: next_refresh.hash.clone(),
            generation: sessions::next_generation(row.generation)?,
            expires_at: refresh_expires_at,
        },
    )
    .await?;
    repo::link_replacement(&mut tx, row.token_id, next_id).await?;

    // Rotation is unconditional: the previous access token dies here too, so a
    // stolen access token has at most one access lifetime of value even if the
    // thief also holds the refresh token.
    if repo::rotate_access_token(
        &mut tx,
        row.session_id,
        &access.hash,
        lifetimes.access_expires_at,
        lifetimes.idle_expires_at,
    )
    .await?
        != 1
    {
        return Err(AppError::AuthenticationFailed);
    }

    state
        .audit(
            &mut tx,
            AuditEvent::new(action::AUTH_REFRESHED, Outcome::Success)
                .actor(row.user_id, principal_type, Some(row.session_id))
                .target("SESSION", row.session_id)
                .source_ip(hints.ip_hint.clone())
                .meta(AuditMetadata::new().int("generation", i64::from(row.generation) + 1)),
        )
        .await?;

    tx.commit().await?;

    Ok(dto::TokenResponse {
        access_token: access.plaintext.expose().clone(),
        refresh_token: next_refresh.plaintext.expose().clone(),
        expires_in: (lifetimes.access_expires_at - now).whole_seconds(),
        // Refreshing does not complete MFA. A pending session stays pending.
        mfa_required: row.pending_mfa,
        token_type: dto::TOKEN_TYPE,
    })
}

// =============================================================================
// Logout
// =============================================================================

/// `POST /auth/logout` — revoke the calling session only.
///
/// The session's unconsumed refresh tokens are deliberately left alone. Revoking
/// the session already makes every future refresh fail, and marking them consumed
/// would turn an ordinary client retry after logout into a spurious
/// `AUTH_REFRESH_REUSE_DETECTED` alarm.
pub async fn logout(
    state: &AppState,
    principal: &Principal,
    hints: &ClientHints,
) -> AppResult<dto::RevocationResponse> {
    let mut tx = state.begin().await?;
    let revoked = repo::revoke_session(
        &mut tx,
        principal.session.session_id,
        sessions::reason::LOGOUT,
    )
    .await?;
    state
        .audit(
            &mut tx,
            AuditEvent::new(action::AUTH_LOGOUT, Outcome::Success)
                .actor(
                    principal.user_id(),
                    principal.session.principal_type,
                    Some(principal.session.session_id),
                )
                .target("SESSION", principal.session.session_id)
                .source_ip(hints.ip_hint.clone())
                .meta(AuditMetadata::new().str("scope", "current_session")),
        )
        .await?;
    tx.commit().await?;

    Ok(dto::RevocationResponse {
        revoked_sessions: i64::try_from(revoked).unwrap_or(0),
    })
}

/// `POST /auth/logout-all` — revoke every session of the calling user, including
/// the one making the request.
pub async fn logout_all(
    state: &AppState,
    principal: &Principal,
    hints: &ClientHints,
) -> AppResult<dto::RevocationResponse> {
    let mut tx = state.begin().await?;
    let revoked = repo::revoke_user_sessions(
        &mut tx,
        principal.user_id(),
        sessions::reason::LOGOUT_ALL,
        None,
    )
    .await?;
    state
        .audit(
            &mut tx,
            AuditEvent::new(action::SESSION_REVOKED_ALL, Outcome::Success)
                .actor(
                    principal.user_id(),
                    principal.session.principal_type,
                    Some(principal.session.session_id),
                )
                .target("USER", principal.user_id())
                .source_ip(hints.ip_hint.clone())
                .meta(
                    AuditMetadata::new()
                        .int(
                            "revoked_sessions",
                            i64::try_from(revoked).unwrap_or(i64::MAX),
                        )
                        .str("scope", "all_sessions"),
                ),
        )
        .await?;
    tx.commit().await?;

    Ok(dto::RevocationResponse {
        revoked_sessions: i64::try_from(revoked).unwrap_or(0),
    })
}

// =============================================================================
// Identity
// =============================================================================

/// `GET /auth/me`.
///
/// Pure: everything it returns was already loaded when the bearer token was
/// resolved, so this endpoint costs no additional query. A session that has not
/// completed MFA gets a **structurally smaller** type with no capability list —
/// a session that cannot call a business endpoint has no business learning which
/// business endpoints it would be allowed to call.
///
/// Takes the step-up window rather than the whole `AppState` so that the
/// projection — including the reduced one — is exercisable in a unit test with no
/// database, no pool and no key ring.
pub fn me(principal: &Principal, step_up_window: StdDuration) -> dto::MeProjection {
    let session = &principal.session;

    if session.pending_mfa {
        return dto::MeProjection::PendingMfa(Box::new(dto::PendingMfaMeResponse {
            user_id: session.user_id,
            email: session.email.clone(),
            display_name: session.display_name.clone(),
            principal_type: session.principal_type,
            security_version: session.security_version,
            session_id: session.session_id,
            mfa_enrolled: session.mfa_enrolled,
            mfa_required: session.mfa_required,
            mfa_pending: true,
            // A pending session has, by construction, never verified a factor.
            step_up_active: false,
            next_action: if session.mfa_enrolled {
                dto::NEXT_ACTION_VERIFY
            } else {
                dto::NEXT_ACTION_ENROL
            },
        }));
    }

    let capabilities = evaluator::capability_list(&principal.actor)
        .into_iter()
        .map(|(permission, scopes)| dto::CapabilityResponse { permission, scopes })
        .collect();

    dto::MeProjection::Full(Box::new(dto::MeResponse {
        user_id: session.user_id,
        email: session.email.clone(),
        display_name: session.display_name.clone(),
        principal_type: session.principal_type,
        is_root: session.is_root,
        security_version: session.security_version,
        session_id: session.session_id,
        auth_level: session.auth_level.clone(),
        mfa_enrolled: session.mfa_enrolled,
        mfa_required: session.mfa_required,
        mfa_pending: false,
        // Recomputed from `mfa_verified_at` on every call, never a stored flag.
        step_up_active: principal.has_recent_step_up(step_up_window),
        capabilities,
    }))
}

// =============================================================================
// Session management (the caller's own sessions only)
// =============================================================================

/// `GET /auth/sessions`.
///
/// Scoped to `principal.user_id()` in the SQL itself. There is no path parameter
/// and therefore no object to confuse: a caller cannot ask for someone else's list.
/// Revoking *another* user's session is a separate, step-up-gated operation that
/// lives in the users module, not here.
pub async fn list_sessions(
    state: &AppState,
    principal: &Principal,
) -> AppResult<dto::SessionListResponse> {
    let limit = i64::from(state.config.limits.max_page_size);
    let rows = repo::list_live_sessions(&state.db, principal.user_id(), limit).await?;

    let sessions = rows
        .into_iter()
        .map(|r| dto::SessionSummary {
            current: r.id == principal.session.session_id,
            id: r.id,
            auth_level: r.auth_level,
            created_at: dto::rfc3339(r.created_at),
            last_activity_at: dto::rfc3339(r.last_activity_at),
            access_expires_at: dto::rfc3339(r.access_expires_at),
            idle_expires_at: dto::rfc3339(r.idle_expires_at),
            absolute_expires_at: dto::rfc3339(r.absolute_expires_at),
            client_ip_hint: r.client_ip_hint,
            user_agent_hint: r.user_agent_hint,
        })
        .collect();

    Ok(dto::SessionListResponse { sessions })
}

/// `DELETE /auth/sessions/{id}`.
///
/// Ownership is a predicate in the `UPDATE`, not a check in Rust: the statement
/// cannot touch a row belonging to another user even if this function were called
/// with an id the caller guessed. Zero rows affected is reported as `NotFound`,
/// which is also the right answer for "someone else's session" — a caller learns
/// nothing about sessions that are not theirs.
pub async fn revoke_own_session(
    state: &AppState,
    principal: &Principal,
    session_id: Uuid,
    hints: &ClientHints,
) -> AppResult<dto::RevocationResponse> {
    let mut tx = state.begin().await?;
    let revoked = repo::revoke_own_session(
        &mut tx,
        session_id,
        principal.user_id(),
        sessions::reason::LOGOUT,
    )
    .await?;

    if revoked == 0 {
        return Err(AppError::NotFound);
    }

    state
        .audit(
            &mut tx,
            AuditEvent::new(action::SESSION_REVOKED, Outcome::Success)
                .actor(
                    principal.user_id(),
                    principal.session.principal_type,
                    Some(principal.session.session_id),
                )
                .target("SESSION", session_id)
                .source_ip(hints.ip_hint.clone())
                .meta(AuditMetadata::new().str("reason", "self_revoked").bool(
                    "was_current_session",
                    session_id == principal.session.session_id,
                )),
        )
        .await?;
    tx.commit().await?;

    Ok(dto::RevocationResponse {
        revoked_sessions: i64::try_from(revoked).unwrap_or(0),
    })
}

// =============================================================================
// Password change
// =============================================================================

/// `POST /auth/password/change`.
///
/// Requires the current password even though the caller already holds a valid
/// session: that is what stops a stolen access token from becoming permanent
/// account takeover. Rate limited on the *account* key, because the current
/// password is the same secret the login endpoint protects and an attacker with a
/// stolen token would otherwise have an unmetered oracle for it.
pub async fn change_password(
    state: &AppState,
    principal: &Principal,
    hints: &ClientHints,
    request: dto::PasswordChangeRequest,
) -> AppResult<dto::RevocationResponse> {
    let account_key = keys::login_account(&v::normalize_email(&principal.session.email));
    enforce_limit(
        state,
        &account_key,
        state.config.rate_limits.login_per_account_per_minute,
        MINUTE,
    )
    .await?;

    let Some(credential) = repo::load_credential(&state.db, principal.user_id()).await? else {
        // A session for a user with no credentials row should be impossible; it is
        // still an authentication failure rather than a 500, so a corrupted record
        // is not an oracle for "this account is broken".
        return Err(AppError::AuthenticationFailed);
    };

    let current = Secret::new(request.current_password);
    if !state
        .hasher
        .verify(&current, &credential.password_hash)
        .await?
    {
        return Err(AppError::AuthenticationFailed);
    }

    // Policy is checked in the service, not the handler, so a direct service call
    // is equally protected.
    password::validate_password(
        &request.new_password,
        &credential.email,
        &credential.display_name,
    )?;

    // Hashed before the transaction opens: Argon2id holds a core for tens of
    // milliseconds and there is no reason to hold a database connection for it.
    let new_hash = state
        .hasher
        .hash(&Secret::new(request.new_password))
        .await?;

    let mut tx = state.begin().await?;
    if repo::update_password(&mut tx, principal.user_id(), &new_hash).await? != 1 {
        return Err(AppError::Internal(
            "password update affected no rows".into(),
        ));
    }
    // All *other* sessions: the caller keeps the one they are using, everyone else
    // holding a token for this account is evicted.
    let revoked = repo::revoke_user_sessions(
        &mut tx,
        principal.user_id(),
        sessions::reason::PASSWORD_CHANGED,
        Some(principal.session.session_id),
    )
    .await?;

    state
        .audit(
            &mut tx,
            AuditEvent::new(action::PASSWORD_CHANGED, Outcome::Success)
                .actor(
                    principal.user_id(),
                    principal.session.principal_type,
                    Some(principal.session.session_id),
                )
                .target("USER", principal.user_id())
                .source_ip(hints.ip_hint.clone())
                .meta(
                    AuditMetadata::new()
                        .int(
                            "revoked_sessions",
                            i64::try_from(revoked).unwrap_or(i64::MAX),
                        )
                        .str("initiated_by", "self_service"),
                ),
        )
        .await?;
    tx.commit().await?;

    state.limiter.reset(&account_key).await;

    Ok(dto::RevocationResponse {
        revoked_sessions: i64::try_from(revoked).unwrap_or(0),
    })
}

// =============================================================================
// Password reset
// =============================================================================

/// `POST /auth/password-reset/request` — **always** 202 with the same body.
///
/// Every branch below returns `PasswordResetAcceptedResponse::fixed()`. The
/// response type has no variable field, so no future edit can make the body depend
/// on whether the account exists (TH-23).
pub async fn request_password_reset(
    state: &AppState,
    hints: &ClientHints,
    request: dto::PasswordResetRequestRequest,
) -> AppResult<dto::PasswordResetAcceptedResponse> {
    enforce_limit(
        state,
        &keys::password_reset_ip(hints.ip),
        state.config.rate_limits.password_reset_per_ip_per_hour,
        HOUR,
    )
    .await?;

    let email_normalized = v::normalize_email(&request.email);
    if email_normalized.is_empty() || email_normalized.len() > v::MAX_EMAIL_LEN {
        return Ok(dto::PasswordResetAcceptedResponse::fixed());
    }

    // Keyed on the submitted address whether or not it exists, so a 429 here says
    // nothing about the account.
    enforce_limit(
        state,
        &keys::password_reset_account(&email_normalized),
        state.config.rate_limits.password_reset_per_ip_per_hour,
        HOUR,
    )
    .await?;

    let subject = repo::find_reset_subject(&state.db, &email_normalized).await?;
    let Some(subject) = subject.filter(|s| s.status == STATUS_ACTIVE) else {
        return Ok(dto::PasswordResetAcceptedResponse::fixed());
    };
    let principal_type = parse_principal_type(&subject.principal_type)?;

    let token = tokens::generate(tokens::RESET_TOKEN_PREFIX)?;
    let expires_at = OffsetDateTime::now_utc() + RESET_TOKEN_TTL;

    let mut tx = state.begin().await?;
    // One live link at a time. Repeated requests must not accumulate a stack of
    // simultaneously valid tokens in a mailbox.
    repo::consume_live_reset_tokens(&mut tx, subject.user_id).await?;
    repo::insert_reset_token(
        &mut tx,
        Uuid::now_v7(),
        subject.user_id,
        &token.hash,
        expires_at,
        hints.ip_hint.as_deref(),
    )
    .await?;

    // The outbox event and the token row commit together: a send before commit
    // produces a link for a token that rolled back, and a spawn after commit loses
    // the mail on a crash. The plaintext token exists here and in the mail body,
    // nowhere else — the outbox worker logs the event id and type only.
    repo::enqueue_outbox_event(
        &mut tx,
        Uuid::now_v7(),
        "PASSWORD_RESET_REQUESTED",
        serde_json::json!({
            "user_id": subject.user_id,
            "email": subject.email,
            "display_name": subject.display_name,
            "reset_token": token.plaintext.expose(),
            "expires_at": dto::rfc3339(expires_at),
        }),
    )
    .await?;

    state
        .audit(
            &mut tx,
            AuditEvent::new(action::PASSWORD_RESET_REQUESTED, Outcome::Success)
                .actor(subject.user_id, principal_type, None)
                .target("USER", subject.user_id)
                .source_ip(hints.ip_hint.clone())
                .meta(
                    AuditMetadata::new().int("expires_in_seconds", RESET_TOKEN_TTL.whole_seconds()),
                ),
        )
        .await?;
    tx.commit().await?;

    Ok(dto::PasswordResetAcceptedResponse::fixed())
}

/// `POST /auth/password-reset/confirm`.
///
/// Single use is enforced by `FOR UPDATE` plus a rows-affected gate on
/// `consumed_at IS NULL`, so two concurrent confirmations cannot both succeed.
/// Completing a reset revokes **all** sessions, including any the attacker who
/// prompted the reset may already hold.
pub async fn confirm_password_reset(
    state: &AppState,
    hints: &ClientHints,
    request: dto::PasswordResetConfirmRequest,
) -> AppResult<dto::RevocationResponse> {
    enforce_limit(
        state,
        &keys::password_reset_ip(hints.ip),
        state.config.rate_limits.password_reset_per_ip_per_hour,
        HOUR,
    )
    .await?;

    if !tokens::is_well_formed(&request.token, tokens::RESET_TOKEN_PREFIX) {
        return Err(AppError::AuthenticationFailed);
    }
    let presented = tokens::hash_token(&request.token);
    let now = OffsetDateTime::now_utc();

    let mut tx = state.begin().await?;
    let Some(row) = repo::lock_reset_token(&mut tx, &presented).await? else {
        return Err(AppError::AuthenticationFailed);
    };

    // Unknown, consumed, expired and "user is no longer ACTIVE" are one failure.
    if row.consumed_at.is_some() || row.expires_at <= now || row.user_status != STATUS_ACTIVE {
        return Err(AppError::AuthenticationFailed);
    }

    let principal_type = parse_principal_type(&row.principal_type)?;
    password::validate_password(&request.new_password, &row.email, &row.display_name)?;

    // Hashed inside the transaction. The alternative — hashing first — would need
    // the account's email and display name before the token is validated, which
    // would turn this endpoint into an identity-disclosure oracle for anyone
    // holding a guessed token. Tens of milliseconds of held connection is the
    // cheaper trade.
    let new_hash = state
        .hasher
        .hash(&Secret::new(request.new_password))
        .await?;

    if repo::consume_reset_token(&mut tx, row.token_id).await? != 1 {
        return Err(AppError::AuthenticationFailed);
    }
    if repo::update_password(&mut tx, row.user_id, &new_hash).await? != 1 {
        return Err(AppError::Internal(
            "password update affected no rows".into(),
        ));
    }

    let revoked =
        repo::revoke_user_sessions(&mut tx, row.user_id, sessions::reason::PASSWORD_RESET, None)
            .await?;

    state
        .audit(
            &mut tx,
            AuditEvent::new(action::PASSWORD_RESET_COMPLETED, Outcome::Success)
                .actor(row.user_id, principal_type, None)
                .target("USER", row.user_id)
                .source_ip(hints.ip_hint.clone())
                .meta(
                    AuditMetadata::new()
                        .int(
                            "revoked_sessions",
                            i64::try_from(revoked).unwrap_or(i64::MAX),
                        )
                        .str("scope", "all_sessions"),
                ),
        )
        .await?;
    tx.commit().await?;

    Ok(dto::RevocationResponse {
        revoked_sessions: i64::try_from(revoked).unwrap_or(0),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::authentication::principal::SessionInfo;
    use crate::modules::authorization::domain::{ActorContext, Grant, Scope, ScopeType};

    /// The documented default step-up window.
    const WINDOW: StdDuration = StdDuration::from_secs(600);

    fn principal(
        pending_mfa: bool,
        mfa_enrolled: bool,
        verified_at: Option<OffsetDateTime>,
    ) -> Principal {
        let user_id = Uuid::now_v7();
        let mut actor = ActorContext::empty(user_id, PrincipalType::Internal);
        actor.allows.push(Grant {
            permission_code: "projects.read".into(),
            scope: Scope::simple(ScopeType::Global),
        });
        Principal {
            session: SessionInfo {
                session_id: Uuid::now_v7(),
                user_id,
                principal_type: PrincipalType::Internal,
                is_root: false,
                pending_mfa,
                mfa_verified_at: verified_at,
                auth_level: if pending_mfa {
                    "PASSWORD".into()
                } else {
                    "MFA".into()
                },
                security_version: 7,
                mfa_required: true,
                mfa_enrolled,
                display_name: "Alice".into(),
                email: "alice@example.com".into(),
            },
            actor,
        }
    }

    /// The reduced projection is the whole point of the pending-MFA state: the
    /// session can see who it is and what it must do next, and nothing else.
    #[test]
    fn a_pending_mfa_session_gets_the_reduced_projection() {
        let p = principal(true, false, None);
        let body = serde_json::to_value(me(&p, WINDOW)).expect("serialise");

        assert_eq!(body["mfa_pending"], serde_json::json!(true));
        assert_eq!(body["step_up_active"], serde_json::json!(false));
        assert_eq!(
            body["next_action"],
            serde_json::json!(dto::NEXT_ACTION_ENROL)
        );
        assert_eq!(body["security_version"], serde_json::json!(7));
        assert_eq!(body["principal_type"], serde_json::json!("INTERNAL"));

        // The capability list and the authority flags must be absent, not empty.
        assert!(
            body.get("capabilities").is_none(),
            "the capability list leaked to a pending session"
        );
        assert!(body.get("is_root").is_none());
        assert!(body.get("auth_level").is_none());
    }

    #[test]
    fn an_enrolled_pending_session_is_told_to_verify_not_to_enrol() {
        let body = serde_json::to_value(me(&principal(true, true, None), WINDOW)).unwrap();
        assert_eq!(
            body["next_action"],
            serde_json::json!(dto::NEXT_ACTION_VERIFY)
        );
    }

    #[test]
    fn a_completed_session_gets_the_full_projection_with_capabilities() {
        let p = principal(false, true, Some(OffsetDateTime::now_utc()));
        let body = serde_json::to_value(me(&p, WINDOW)).unwrap();

        assert_eq!(body["mfa_pending"], serde_json::json!(false));
        assert_eq!(body["step_up_active"], serde_json::json!(true));
        assert_eq!(body["is_root"], serde_json::json!(false));
        assert_eq!(body["auth_level"], serde_json::json!("MFA"));
        let caps = body["capabilities"].as_array().expect("capabilities");
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0]["permission"], serde_json::json!("projects.read"));
        assert_eq!(caps[0]["scopes"], serde_json::json!(["GLOBAL"]));
    }

    /// `step_up_active` is recomputed from `mfa_verified_at` on every call. A
    /// cached boolean would keep saying "recently verified" after the window shut.
    #[test]
    fn step_up_expires_with_the_window_rather_than_being_remembered() {
        let stale = OffsetDateTime::now_utc() - Duration::seconds(601);
        let body = serde_json::to_value(me(&principal(false, true, Some(stale)), WINDOW)).unwrap();
        assert_eq!(body["step_up_active"], serde_json::json!(false));

        let never = serde_json::to_value(me(&principal(false, true, None), WINDOW)).unwrap();
        assert_eq!(never["step_up_active"], serde_json::json!(false));
    }

    /// No projection of `/auth/me` may carry token material or a stored secret.
    #[test]
    fn no_me_projection_contains_credential_material() {
        for p in [
            principal(true, false, None),
            principal(false, true, Some(OffsetDateTime::now_utc())),
        ] {
            let body = serde_json::to_string(&me(&p, WINDOW)).unwrap();
            for needle in [
                "rb_at_",
                "rb_rt_",
                "$argon2",
                "password",
                "token_hash",
                "secret",
            ] {
                assert!(
                    !body.contains(needle),
                    "`/auth/me` leaked `{needle}`: {body}"
                );
            }
        }
    }

    #[test]
    fn an_unrecognised_principal_type_fails_closed() {
        assert!(parse_principal_type("INTERNAL").is_ok());
        assert!(parse_principal_type("CLIENT").is_ok());
        for bad in ["internal", "ADMIN", "", "SYSTEM"] {
            assert!(parse_principal_type(bad).is_err(), "accepted `{bad}`");
        }
    }
}
