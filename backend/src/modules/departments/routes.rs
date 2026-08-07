//! Departments HTTP surface: parse, delegate, serialise. No business rules.
//!
//! Every handler is three lines of plumbing around one `service` call. There is no
//! authorisation, no validation and no invariant here on purpose: a rule that lives
//! in a handler is a rule that a second caller of the same service silently skips.

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

async fn create(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    ClientIp(ip): ClientIp,
    Json(body): Json<CreateDepartmentRequest>,
) -> AppResult<(StatusCode, JsonResponse<DepartmentResponse>)> {
    let created = service::create(&state, &principal, Some(ip.to_string()), body).await?;
    Ok((StatusCode::CREATED, JsonResponse(created)))
}

async fn detail(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    Path(id): Path<Uuid>,
) -> AppResult<JsonResponse<DepartmentResponse>> {
    service::get(&state, &principal, id).await.map(JsonResponse)
}

async fn update(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    ClientIp(ip): ClientIp,
    Path(id): Path<Uuid>,
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
    Path(id): Path<Uuid>,
    Json(body): Json<ArchiveDepartmentRequest>,
) -> AppResult<JsonResponse<DepartmentResponse>> {
    service::archive(&state, &principal, Some(ip.to_string()), id, body)
        .await
        .map(JsonResponse)
}

async fn list_members(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    Path(id): Path<Uuid>,
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
    Path(id): Path<Uuid>,
    Json(body): Json<AddDepartmentMemberRequest>,
) -> AppResult<(StatusCode, JsonResponse<DepartmentMemberResponse>)> {
    let member = service::add_member(&state, &principal, Some(ip.to_string()), id, body).await?;
    Ok((StatusCode::CREATED, JsonResponse(member)))
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
