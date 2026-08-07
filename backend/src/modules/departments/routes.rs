//! Departments HTTP surface: parse, delegate, serialise. No business rules.
//!
//! Every handler is three lines of plumbing around one `service` call. There is no
//! authorisation, no validation and no invariant here on purpose: a rule that lives
//! in a handler is a rule that a second caller of the same service silently skips.

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
    AddDepartmentMemberRequest, ArchiveDepartmentRequest, CreateDepartmentRequest,
    DepartmentMemberResponse, DepartmentResponse, UpdateDepartmentRequest,
};
use super::service;

/// Absolute paths so the router can be merged into the application router without
/// the mount point becoming an implicit part of this module's contract.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/departments", get(list).post(create))
        .route("/api/v1/departments/{id}", get(detail).patch(update))
        .route("/api/v1/departments/{id}/archive", post(archive))
        .route(
            "/api/v1/departments/{id}/members",
            get(list_members).post(add_member),
        )
        .route(
            "/api/v1/departments/{id}/members/{user_id}",
            delete(remove_member),
        )
}

async fn list(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    Query(query): Query<PageQuery>,
) -> AppResult<JsonResponse<Page<DepartmentResponse>>> {
    service::list(&state, &principal, &query)
        .await
        .map(JsonResponse)
}

/// Honours `Idempotency-Key` (`api/openapi.yaml`).
async fn create(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    ClientIp(ip): ClientIp,
    body: Idempotent<CreateDepartmentRequest>,
) -> AppResult<Response> {
    let principal_id = principal.user_id();
    let inner = state.clone();
    idempotency::create(
        &state,
        principal_id,
        "departments.create",
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
) -> AppResult<JsonResponse<DepartmentResponse>> {
    service::get(&state, &principal, id).await.map(JsonResponse)
}

async fn update(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    ClientIp(ip): ClientIp,
    PathId(id): PathId,
    Json(body): Json<UpdateDepartmentRequest>,
) -> AppResult<JsonResponse<DepartmentResponse>> {
    service::update(&state, &principal, Some(ip.to_string()), id, body)
        .await
        .map(JsonResponse)
}

async fn archive(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    ClientIp(ip): ClientIp,
    PathId(id): PathId,
    Json(body): Json<ArchiveDepartmentRequest>,
) -> AppResult<JsonResponse<DepartmentResponse>> {
    service::archive(&state, &principal, Some(ip.to_string()), id, body)
        .await
        .map(JsonResponse)
}

async fn list_members(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    PathId(id): PathId,
    Query(query): Query<PageQuery>,
) -> AppResult<JsonResponse<Page<DepartmentMemberResponse>>> {
    service::list_members(&state, &principal, id, &query)
        .await
        .map(JsonResponse)
}

async fn add_member(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    ClientIp(ip): ClientIp,
    PathId(id): PathId,
    Json(body): Json<AddDepartmentMemberRequest>,
) -> AppResult<(StatusCode, JsonResponse<DepartmentMemberResponse>)> {
    let member = service::add_member(&state, &principal, Some(ip.to_string()), id, body).await?;
    Ok((StatusCode::CREATED, JsonResponse(member)))
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
