//! Client-accounts HTTP surface: parse, delegate, serialise. No business rules.
//!
//! Note what is *not* here: no principal-type check. It would be redundant and,
//! worse, a second place for the rule to live. `clients.*` is INTERNAL-only in the
//! catalogue, so the evaluator refuses an external principal at the envelope and
//! `state.require` renders it as `404`. One rule, one implementation.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post};
use axum::{Json as JsonResponse, Router};
use uuid::Uuid;

use crate::app::AppState;
use crate::platform::errors::AppResult;
use crate::platform::http::extract::{Authenticated, ClientIp, Json};
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

async fn create(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    ClientIp(ip): ClientIp,
    Json(body): Json<CreateClientRequest>,
) -> AppResult<(StatusCode, JsonResponse<ClientAccountResponse>)> {
    let created = service::create(&state, &principal, Some(ip.to_string()), body).await?;
    Ok((StatusCode::CREATED, JsonResponse(created)))
}

async fn detail(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    Path(id): Path<Uuid>,
) -> AppResult<JsonResponse<ClientAccountResponse>> {
    service::get(&state, &principal, id).await.map(JsonResponse)
}

async fn update(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    ClientIp(ip): ClientIp,
    Path(id): Path<Uuid>,
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
    Path(id): Path<Uuid>,
    Json(body): Json<ArchiveClientRequest>,
) -> AppResult<JsonResponse<ClientAccountResponse>> {
    service::archive(&state, &principal, Some(ip.to_string()), id, body)
        .await
        .map(JsonResponse)
}

async fn list_members(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    Path(id): Path<Uuid>,
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
    Path(id): Path<Uuid>,
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
    Path((id, user_id)): Path<(Uuid, Uuid)>,
) -> AppResult<JsonResponse<ClientMemberResponse>> {
    service::activate_member(&state, &principal, Some(ip.to_string()), id, user_id)
        .await
        .map(JsonResponse)
}

async fn remove_member(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    ClientIp(ip): ClientIp,
    Path((id, user_id)): Path<(Uuid, Uuid)>,
) -> AppResult<StatusCode> {
    service::remove_member(&state, &principal, Some(ip.to_string()), id, user_id).await?;
    Ok(StatusCode::NO_CONTENT)
}
