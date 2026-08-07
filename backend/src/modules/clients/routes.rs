//! Client-accounts HTTP surface: parse, delegate, serialise. No business rules.
//!
//! Note what is *not* here: no principal-type check. It would be redundant and,
//! worse, a second place for the rule to live. `clients.*` is INTERNAL-only in the
//! catalogue, so the evaluator refuses an external principal at the envelope and
//! `state.require` renders it as `404`. One rule, one implementation.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::{delete, get, post};
use axum::{Json as JsonResponse, Router};

use crate::app::AppState;
use crate::platform::errors::AppResult;
use crate::platform::http::extract::{Authenticated, ClientIp, Json, PathId, PathIds};
use crate::platform::http::idempotency::{self, Idempotent};
use crate::shared::pagination::{Page, PageQuery};

use super::dto::{
    AddClientMemberRequest, ArchiveClientRequest, ClientAccountResponse, ClientMemberResponse,
    CreateClientRequest, UpdateClientRequest,
};
use super::service;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/clients", get(list).post(create))
        .route("/api/v1/clients/{id}", get(detail).patch(update))
        .route("/api/v1/clients/{id}/archive", post(archive))
        .route(
            "/api/v1/clients/{id}/members",
            get(list_members).post(add_member),
        )
        .route(
            "/api/v1/clients/{id}/members/{user_id}/activate",
            post(activate_member),
        )
        .route(
            "/api/v1/clients/{id}/members/{user_id}",
            delete(remove_member),
        )
}

async fn list(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    Query(query): Query<PageQuery>,
) -> AppResult<JsonResponse<Page<ClientAccountResponse>>> {
    service::list(&state, &principal, &query)
        .await
        .map(JsonResponse)
}

/// Honours `Idempotency-Key` (`api/openapi.yaml`).
async fn create(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    ClientIp(ip): ClientIp,
    body: Idempotent<CreateClientRequest>,
) -> AppResult<Response> {
    let principal_id = principal.user_id();
    let inner = state.clone();
    idempotency::create(
        &state,
        principal_id,
        "clients.create",
        body,
        move |request| async move {
            service::create(&inner, &principal, Some(ip.to_string()), request).await
        },
    )
    .await
}

async fn detail(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    PathId(id): PathId,
) -> AppResult<JsonResponse<ClientAccountResponse>> {
    service::get(&state, &principal, id).await.map(JsonResponse)
}

async fn update(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    ClientIp(ip): ClientIp,
    PathId(id): PathId,
    Json(body): Json<UpdateClientRequest>,
) -> AppResult<JsonResponse<ClientAccountResponse>> {
    service::update(&state, &principal, Some(ip.to_string()), id, body)
        .await
        .map(JsonResponse)
}

async fn archive(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    ClientIp(ip): ClientIp,
    PathId(id): PathId,
    Json(body): Json<ArchiveClientRequest>,
) -> AppResult<JsonResponse<ClientAccountResponse>> {
    service::archive(&state, &principal, Some(ip.to_string()), id, body)
        .await
        .map(JsonResponse)
}

async fn list_members(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    PathId(id): PathId,
    Query(query): Query<PageQuery>,
) -> AppResult<JsonResponse<Page<ClientMemberResponse>>> {
    service::list_members(&state, &principal, id, &query)
        .await
        .map(JsonResponse)
}

async fn add_member(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    ClientIp(ip): ClientIp,
    PathId(id): PathId,
    Json(body): Json<AddClientMemberRequest>,
) -> AppResult<(StatusCode, JsonResponse<ClientMemberResponse>)> {
    let member = service::add_member(&state, &principal, Some(ip.to_string()), id, body).await?;
    Ok((StatusCode::CREATED, JsonResponse(member)))
}

/// A `POST` rather than a `PATCH` on the membership: activation is a named action
/// with its own permission decision and its own audit event, not a field edit.
async fn activate_member(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    ClientIp(ip): ClientIp,
    PathIds(id, user_id): PathIds,
) -> AppResult<JsonResponse<ClientMemberResponse>> {
    service::activate_member(&state, &principal, Some(ip.to_string()), id, user_id)
        .await
        .map(JsonResponse)
}

async fn remove_member(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    ClientIp(ip): ClientIp,
    PathIds(id, user_id): PathIds,
) -> AppResult<StatusCode> {
    service::remove_member(&state, &principal, Some(ip.to_string()), id, user_id).await?;
    Ok(StatusCode::NO_CONTENT)
}
