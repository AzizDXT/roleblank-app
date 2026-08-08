//! Axum handlers for the authentication endpoints.
//!
//! Handlers parse, delegate and serialise. There is no business rule in this file
//! — validation, rate limiting, authorisation and audit all live in the service,
//! so a direct service call is exactly as protected as an HTTP call.
//!
//! **Extractor choice is the security decision made here**, and it is the only
//! one:
//!
//!   * `Authenticated` rejects an MFA-pending session automatically and is used
//!     for everything a password-only session must not reach.
//!   * `MfaPendingSession` accepts pending *and* completed sessions. It is used by
//!     the MFA *enrolment and verification* endpoints, and by `/me` and `/logout`,
//!     which `docs/backend/03-authentication.md` §4 explicitly lists as reachable
//!     from a pending session — `/me` must be, or a client stuck in
//!     `MFA_ENROLLMENT_REQUIRED` could never discover why.
//!
//! The two MFA endpoints that *weaken* the second factor — `/mfa/disable` and
//! `/mfa/recovery/regenerate` — take `Authenticated`, matching what `ROUTE_TABLE`
//! declares for them. Being an MFA route is not the criterion; whether a
//! password-only session may reach it is.
//!
//! The router is returned unmounted. It expects to be nested at `/api/v1/auth`.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{delete, get, post};
use axum::Router;

use crate::app::AppState;
use crate::modules::authentication::service::ClientHints;
use crate::modules::authentication::{dto, mfa, service};
use crate::platform::errors::{AppError, AppResult};
use crate::platform::http::extract::{
    Authenticated, ClientIp, Json, MfaPendingSession, PathId, UserAgentHint,
};

/// The authentication routes, relative to their mount point (`/api/v1/auth`).
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/login", post(login))
        .route("/refresh", post(refresh))
        .route("/logout", post(logout))
        .route("/logout-all", post(logout_all))
        .route("/me", get(me))
        .route("/sessions", get(list_sessions))
        .route("/sessions/{id}", delete(revoke_session))
        .route("/password/change", post(change_password))
        .route("/password-reset/request", post(request_password_reset))
        .route("/password-reset/confirm", post(confirm_password_reset))
        .route("/mfa/totp/setup", post(mfa_totp_setup))
        .route("/mfa/totp/activate", post(mfa_totp_activate))
        .route("/mfa/verify", post(mfa_verify))
        .route("/mfa/recovery/verify", post(mfa_recovery_verify))
        .route("/mfa/recovery/regenerate", post(mfa_recovery_regenerate))
        .route("/mfa/disable", post(mfa_disable))
}

fn hints(ip: ClientIp, agent: UserAgentHint) -> ClientHints {
    ClientHints {
        ip: ip.0,
        ip_hint: ip.hint(),
        user_agent_hint: agent.0,
    }
}

// =============================================================================
// Unauthenticated
// =============================================================================

async fn login(
    State(state): State<AppState>,
    ip: ClientIp,
    agent: UserAgentHint,
    Json(body): Json<dto::LoginRequest>,
) -> AppResult<impl IntoResponse> {
    // Counted at the boundary rather than at each of `login`'s six early returns,
    // so a future refusal path cannot be added without being counted. Only genuine
    // credential failures are recorded — a throttle or a malformed body is a
    // different operational signal and has its own series.
    let response = service::login(&state, &hints(ip, agent), body)
        .await
        .inspect_err(|e| {
            if matches!(e, AppError::AuthenticationFailed) {
                state.metrics.auth_failure();
            }
        })?;
    Ok((StatusCode::OK, axum::Json(response)))
}

async fn refresh(
    State(state): State<AppState>,
    ip: ClientIp,
    agent: UserAgentHint,
    Json(body): Json<dto::RefreshRequest>,
) -> AppResult<impl IntoResponse> {
    let response = service::refresh(&state, &hints(ip, agent), body).await?;
    Ok((StatusCode::OK, axum::Json(response)))
}

/// Always `202`, always the same body. See `service::request_password_reset`.
async fn request_password_reset(
    State(state): State<AppState>,
    ip: ClientIp,
    agent: UserAgentHint,
    Json(body): Json<dto::PasswordResetRequestRequest>,
) -> AppResult<impl IntoResponse> {
    let response = service::request_password_reset(&state, &hints(ip, agent), body).await?;
    Ok((StatusCode::ACCEPTED, axum::Json(response)))
}

async fn confirm_password_reset(
    State(state): State<AppState>,
    ip: ClientIp,
    agent: UserAgentHint,
    Json(body): Json<dto::PasswordResetConfirmRequest>,
) -> AppResult<impl IntoResponse> {
    let response = service::confirm_password_reset(&state, &hints(ip, agent), body).await?;
    Ok((StatusCode::OK, axum::Json(response)))
}

// =============================================================================
// Session-bearing
// =============================================================================

/// `MfaPendingSession`, not `Authenticated`: a session in the
/// `MFA_ENROLLMENT_REQUIRED` state must be able to log out rather than being stuck
/// holding a live token it cannot dispose of.
async fn logout(
    State(state): State<AppState>,
    MfaPendingSession(principal): MfaPendingSession,
    ip: ClientIp,
    agent: UserAgentHint,
) -> AppResult<impl IntoResponse> {
    let response = service::logout(&state, &principal, &hints(ip, agent)).await?;
    Ok((StatusCode::OK, axum::Json(response)))
}

async fn logout_all(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    ip: ClientIp,
    agent: UserAgentHint,
) -> AppResult<impl IntoResponse> {
    let response = service::logout_all(&state, &principal, &hints(ip, agent)).await?;
    Ok((StatusCode::OK, axum::Json(response)))
}

/// `MfaPendingSession` so that a pending session receives the **reduced**
/// projection rather than a `403` it cannot act on. The service decides which
/// projection to build; the handler never sees the difference.
async fn me(
    State(state): State<AppState>,
    MfaPendingSession(principal): MfaPendingSession,
) -> AppResult<impl IntoResponse> {
    let response = service::me(&principal, state.config.sessions.step_up_window);
    Ok((StatusCode::OK, axum::Json(response)))
}

async fn list_sessions(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
) -> AppResult<impl IntoResponse> {
    let response = service::list_sessions(&state, &principal).await?;
    Ok((StatusCode::OK, axum::Json(response)))
}

async fn revoke_session(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    ip: ClientIp,
    agent: UserAgentHint,
    PathId(session_id): PathId,
) -> AppResult<impl IntoResponse> {
    let response =
        service::revoke_own_session(&state, &principal, session_id, &hints(ip, agent)).await?;
    Ok((StatusCode::OK, axum::Json(response)))
}

async fn change_password(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    ip: ClientIp,
    agent: UserAgentHint,
    Json(body): Json<dto::PasswordChangeRequest>,
) -> AppResult<impl IntoResponse> {
    let response = service::change_password(&state, &principal, &hints(ip, agent), body).await?;
    Ok((StatusCode::OK, axum::Json(response)))
}

// =============================================================================
// MFA — all reachable from a pending session, which is the point
// =============================================================================

async fn mfa_totp_setup(
    State(state): State<AppState>,
    MfaPendingSession(principal): MfaPendingSession,
    ip: ClientIp,
    agent: UserAgentHint,
) -> AppResult<impl IntoResponse> {
    let response = mfa::totp_setup(&state, &principal, &hints(ip, agent)).await?;
    Ok((StatusCode::CREATED, axum::Json(response)))
}

async fn mfa_totp_activate(
    State(state): State<AppState>,
    MfaPendingSession(principal): MfaPendingSession,
    ip: ClientIp,
    agent: UserAgentHint,
    Json(body): Json<dto::CodeRequest>,
) -> AppResult<impl IntoResponse> {
    let response = mfa::totp_activate(&state, &principal, &hints(ip, agent), body).await?;
    Ok((StatusCode::OK, axum::Json(response)))
}

async fn mfa_verify(
    State(state): State<AppState>,
    MfaPendingSession(principal): MfaPendingSession,
    ip: ClientIp,
    agent: UserAgentHint,
    Json(body): Json<dto::CodeRequest>,
) -> AppResult<impl IntoResponse> {
    let response = mfa::verify(&state, &principal, &hints(ip, agent), body).await?;
    Ok((StatusCode::OK, axum::Json(response)))
}

async fn mfa_recovery_verify(
    State(state): State<AppState>,
    MfaPendingSession(principal): MfaPendingSession,
    ip: ClientIp,
    agent: UserAgentHint,
    Json(body): Json<dto::CodeRequest>,
) -> AppResult<impl IntoResponse> {
    let response = mfa::recovery_verify(&state, &principal, &hints(ip, agent), body).await?;
    Ok((StatusCode::OK, axum::Json(response)))
}

/// Step-up gated inside the service (§8): minting a fresh set of bypass
/// credentials from a merely-password-authenticated session would defeat MFA.
///
/// `Authenticated`, not `MfaPendingSession`, and this is the one place in this file
/// where the two differ from what the endpoint *does*. `ROUTE_TABLE` has always
/// declared both this route and `/mfa/disable` as `Authenticated` with
/// `step_up = true`, while the handlers took the pending-tolerant extractor and
/// relied on `state.require_step_up` inside the service to exclude a pending
/// session. That exclusion was correct — a pending session has by construction
/// never verified a factor, so the window can never be satisfied — but it was a
/// consequence of one line in a service rather than a property of the type, and
/// `Authenticated` exists precisely so that a handler which forgets to think about
/// MFA gets the safe behaviour. The service check stays: two independent barriers,
/// not one moved.
async fn mfa_recovery_regenerate(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    ip: ClientIp,
    agent: UserAgentHint,
) -> AppResult<impl IntoResponse> {
    let response = mfa::recovery_regenerate(&state, &principal, &hints(ip, agent)).await?;
    Ok((StatusCode::OK, axum::Json(response)))
}

/// Step-up gated, and refused outright for an account with `mfa_required`.
///
/// `Authenticated` for the same reason as `mfa_recovery_regenerate` above: turning
/// off the second factor is the last thing a half-authenticated session should be
/// able to attempt, and the extractor now says so.
async fn mfa_disable(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    ip: ClientIp,
    agent: UserAgentHint,
) -> AppResult<impl IntoResponse> {
    let response = mfa::disable(&state, &principal, &hints(ip, agent)).await?;
    Ok((StatusCode::OK, axum::Json(response)))
}

#[cfg(test)]
mod tests {
    /// The route table this module is expected to expose, as a documented list
    /// rather than as something a reader has to reconstruct from `router()`.
    const EXPECTED: &[(&str, &str)] = &[
        ("POST", "/login"),
        ("POST", "/refresh"),
        ("POST", "/logout"),
        ("POST", "/logout-all"),
        ("GET", "/me"),
        ("GET", "/sessions"),
        ("DELETE", "/sessions/{id}"),
        ("POST", "/password/change"),
        ("POST", "/password-reset/request"),
        ("POST", "/password-reset/confirm"),
        ("POST", "/mfa/totp/setup"),
        ("POST", "/mfa/totp/activate"),
        ("POST", "/mfa/verify"),
        ("POST", "/mfa/recovery/verify"),
        ("POST", "/mfa/recovery/regenerate"),
        ("POST", "/mfa/disable"),
    ];

    /// The router must build. `Router::new()` panics on a malformed path pattern,
    /// so constructing it is a real assertion about every route string above.
    #[test]
    fn the_router_builds_with_every_documented_route() {
        let _router = super::router();
        assert_eq!(
            EXPECTED.len(),
            16,
            "the documented route table changed size"
        );
    }

    /// Every path is mount-relative. A leading `/api/v1/auth` here would produce
    /// `/api/v1/auth/api/v1/auth/login` once nested.
    #[test]
    fn paths_are_relative_to_the_mount_point() {
        for (_, path) in EXPECTED {
            assert!(path.starts_with('/'), "`{path}` must start with a slash");
            assert!(
                !path.starts_with("/api/"),
                "`{path}` embeds the mount point; the parent router nests this one"
            );
        }
    }

    /// A token must never be accepted from a URL, so no route may take one as a
    /// path segment.
    #[test]
    fn no_route_carries_a_credential_in_its_path() {
        for (_, path) in EXPECTED {
            for forbidden in ["token", "password", "code", "secret"] {
                assert!(
                    !path.contains(&format!("{{{forbidden}}}")),
                    "`{path}` puts a credential in the URL"
                );
            }
        }
    }
}
