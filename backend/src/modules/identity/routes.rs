//! Identity HTTP surface. Parse, delegate, serialise — no business rules here.
//!
//! Note what is absent: there is **no** `DELETE /api/v1/users/{id}`. Accounts are
//! archived. The absence is the API contract, and it is backed by the runtime
//! database role holding no `DELETE` grant on `users` (ADR-004 layer 3).
//!
//! Every route except the three anonymous ones takes `Authenticated`, which
//! rejects an MFA-pending session automatically. A handler cannot forget to think
//! about MFA, because the safe extractor is the default one.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::{delete, get, post};
use axum::Router;
use uuid::Uuid;

use crate::app::AppState;
use crate::platform::errors::AppResult;
use crate::platform::http::extract::{Authenticated, ClientIp, Json};
use crate::platform::http::idempotency::{self, Idempotent};
use crate::shared::pagination::Page;

use super::dto::{
    AcceptInvitationRequest, AcceptInvitationResponse, ArchiveUserRequest, CreateInvitationRequest,
    InvitationResponse, ListInvitationsQuery, ListUsersQuery, ReactivateUserRequest,
    RegisterRequest, RegistrationAcceptedResponse, RegistrationConfigResponse, SuspendUserRequest,
    UpdateUserRequest, UserResponse,
};
use super::{invitations, registration, service};

pub fn router() -> Router<AppState> {
    Router::new()
        // ---- users ---------------------------------------------------------
        .route("/api/v1/users", get(list_users))
        .route("/api/v1/users/{id}", get(get_user).patch(update_user))
        .route("/api/v1/users/{id}/suspend", post(suspend_user))
        .route("/api/v1/users/{id}/reactivate", post(reactivate_user))
        .route("/api/v1/users/{id}/archive", post(archive_user))
        // ---- invitations ---------------------------------------------------
        // `/accept` is registered before the parameterised route reads it as an
        // id; a static segment takes priority over a parameter, so an anonymous
        // acceptance never lands in the authenticated revoke handler.
        .route("/api/v1/invitations/accept", post(accept_invitation))
        .route(
            "/api/v1/invitations",
            get(list_invitations).post(create_invitation),
        )
        .route("/api/v1/invitations/{id}", delete(revoke_invitation))
        // ---- registration (anonymous) --------------------------------------
        .route("/api/v1/registration/config", get(registration_config))
        .route("/api/v1/registration", post(register))
}

// =============================================================================
// Users
// =============================================================================

async fn list_users(
    State(state): State<AppState>,
    principal: Authenticated,
    Query(query): Query<ListUsersQuery>,
) -> AppResult<axum::Json<Page<UserResponse>>> {
    Ok(axum::Json(
        service::list_users(&state, &principal, &query).await?,
    ))
}

async fn get_user(
    State(state): State<AppState>,
    principal: Authenticated,
    Path(id): Path<Uuid>,
) -> AppResult<axum::Json<UserResponse>> {
    Ok(axum::Json(service::get_user(&state, &principal, id).await?))
}

async fn update_user(
    State(state): State<AppState>,
    principal: Authenticated,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateUserRequest>,
) -> AppResult<axum::Json<UserResponse>> {
    Ok(axum::Json(
        service::update_user(&state, &principal, id, request).await?,
    ))
}

async fn suspend_user(
    State(state): State<AppState>,
    principal: Authenticated,
    Path(id): Path<Uuid>,
    Json(request): Json<SuspendUserRequest>,
) -> AppResult<axum::Json<UserResponse>> {
    Ok(axum::Json(
        service::suspend_user(&state, &principal, id, request).await?,
    ))
}

async fn reactivate_user(
    State(state): State<AppState>,
    principal: Authenticated,
    Path(id): Path<Uuid>,
    Json(request): Json<ReactivateUserRequest>,
) -> AppResult<axum::Json<UserResponse>> {
    Ok(axum::Json(
        service::reactivate_user(&state, &principal, id, request).await?,
    ))
}

async fn archive_user(
    State(state): State<AppState>,
    principal: Authenticated,
    Path(id): Path<Uuid>,
    Json(request): Json<ArchiveUserRequest>,
) -> AppResult<axum::Json<UserResponse>> {
    Ok(axum::Json(
        service::archive_user(&state, &principal, id, request).await?,
    ))
}

// =============================================================================
// Invitations
// =============================================================================

/// Honours `Idempotency-Key` (`api/openapi.yaml`). An invitation is a deferred
/// grant of authority, so a duplicate produced by a retry is a second live way into
/// the company — and the one-pending-per-address index would turn the retry into an
/// opaque `409` rather than the original response.
async fn create_invitation(
    State(state): State<AppState>,
    principal: Authenticated,
    request: Idempotent<CreateInvitationRequest>,
) -> AppResult<Response> {
    let principal_id = principal.user_id();
    let inner = state.clone();
    idempotency::create(
        &state,
        principal_id,
        "invitations.create",
        request,
        move |body| async move { invitations::create_invitation(&inner, &principal, body).await },
    )
    .await
}

async fn list_invitations(
    State(state): State<AppState>,
    principal: Authenticated,
    Query(query): Query<ListInvitationsQuery>,
) -> AppResult<axum::Json<Page<InvitationResponse>>> {
    Ok(axum::Json(
        invitations::list_invitations(&state, &principal, &query).await?,
    ))
}

async fn revoke_invitation(
    State(state): State<AppState>,
    principal: Authenticated,
    Path(id): Path<Uuid>,
) -> AppResult<axum::Json<InvitationResponse>> {
    Ok(axum::Json(
        invitations::revoke_invitation(&state, &principal, id).await?,
    ))
}

/// Anonymous by necessity — the invitee has no account yet. The token travels in
/// the body, never in the path or the query string (TH-36).
async fn accept_invitation(
    State(state): State<AppState>,
    client_ip: ClientIp,
    Json(request): Json<AcceptInvitationRequest>,
) -> AppResult<(StatusCode, axum::Json<AcceptInvitationResponse>)> {
    let response = invitations::accept_invitation(&state, client_ip, request).await?;
    Ok((StatusCode::CREATED, axum::Json(response)))
}

// =============================================================================
// Registration (anonymous)
// =============================================================================

async fn registration_config(
    State(state): State<AppState>,
) -> AppResult<axum::Json<RegistrationConfigResponse>> {
    Ok(axum::Json(registration::registration_config(&state).await?))
}

/// Always `202 Accepted` with the same body, whether or not the address was free.
/// A `201` for a new account and a `409` for a duplicate would be an enumeration
/// oracle spelled in status codes.
async fn register(
    State(state): State<AppState>,
    client_ip: ClientIp,
    Json(request): Json<RegisterRequest>,
) -> AppResult<(StatusCode, axum::Json<RegistrationAcceptedResponse>)> {
    let response = registration::register(&state, client_ip, request).await?;
    Ok((StatusCode::ACCEPTED, axum::Json(response)))
}
