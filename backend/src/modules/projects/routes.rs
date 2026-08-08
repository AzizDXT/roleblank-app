//! Axum handlers for projects. Parse, delegate, serialise — no business rules.
//!
//! Every handler uses `Authenticated`, which rejects an MFA-pending session by
//! construction, and every one delegates immediately: an authorisation decision,
//! a validation rule or a status transition living in a handler would be invisible
//! to a direct service call, and the services are what the tests exercise.

use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::{delete, get, post};
use axum::{Json as AxumJson, Router};

use super::dto::{
    AddProjectMemberRequest, ArchiveProjectRequest, ClientProjectListQuery, ClientProjectResponse,
    CreateProjectRequest, ProjectClientLinkResponse, ProjectListQuery, ProjectMemberResponse,
    ProjectResponse, ShareProjectRequest, UpdateProjectRequest,
};
use super::service;
use crate::app::AppState;
use crate::platform::errors::{AppError, AppResult};
use crate::platform::http::extract::{Authenticated, ClientIp, Json, PathId, PathIds};
use crate::platform::http::idempotency::{self, Idempotent};
use crate::shared::pagination::Page;

/// Axum's own `Query` rejection renders as `text/plain` and names Rust types.
/// Converting it here keeps the promise that every error on this API is
/// `application/problem+json` and carries a stable `code`.
fn query<T>(result: Result<Query<T>, QueryRejection>) -> AppResult<T> {
    match result {
        Ok(Query(value)) => Ok(value),
        Err(rejection) => {
            tracing::debug!(
                rejection = %crate::platform::observability::sanitize::log_value(rejection.body_text()),
                "rejected a query string"
            );
            Err(AppError::BadRequest(
                "The query string is not valid for this endpoint, or contains unrecognised parameters.",
            ))
        }
    }
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/projects", get(list).post(create))
        .route("/api/v1/projects/{id}", get(get_one).patch(patch))
        .route("/api/v1/projects/{id}/archive", post(archive))
        .route(
            "/api/v1/projects/{id}/members",
            get(list_members).post(add_member),
        )
        .route(
            "/api/v1/projects/{id}/members/{user_id}",
            delete(remove_member),
        )
        .route(
            "/api/v1/projects/{id}/clients",
            get(list_clients).post(share),
        )
        .route(
            "/api/v1/projects/{id}/clients/{client_account_id}",
            delete(unshare),
        )
        // The client portal. Separate paths rather than a flag on the internal
        // routes: a projection is chosen by the route, so there is no request in
        // which the internal serialiser could be reached by an external principal.
        .route("/api/v1/client-portal/projects", get(client_list))
        .route("/api/v1/client-portal/projects/{id}", get(client_get))
}

// ---- internal --------------------------------------------------------------

async fn list(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    params: Result<Query<ProjectListQuery>, QueryRejection>,
) -> AppResult<AxumJson<Page<ProjectResponse>>> {
    let params = query(params)?;
    Ok(AxumJson(service::list(&state, &principal, &params).await?))
}

/// Honours `Idempotency-Key` (`api/openapi.yaml`), so a client that retries after a
/// lost response gets the original project back rather than a second one.
async fn create(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    ClientIp(ip): ClientIp,
    body: Idempotent<CreateProjectRequest>,
) -> AppResult<Response> {
    let principal_id = principal.user_id();
    let inner = state.clone();
    idempotency::create(
        &state,
        principal_id,
        "projects.create",
        body,
        move |request| async move {
            service::create(&inner, &principal, &Some(ip.to_string()), request).await
        },
    )
    .await
}

async fn get_one(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    PathId(id): PathId,
) -> AppResult<AxumJson<ProjectResponse>> {
    Ok(AxumJson(service::get(&state, &principal, id).await?))
}

async fn patch(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    ClientIp(ip): ClientIp,
    PathId(id): PathId,
    Json(body): Json<UpdateProjectRequest>,
) -> AppResult<AxumJson<ProjectResponse>> {
    Ok(AxumJson(
        service::update(&state, &principal, &Some(ip.to_string()), id, body).await?,
    ))
}

async fn archive(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    ClientIp(ip): ClientIp,
    PathId(id): PathId,
    Json(body): Json<ArchiveProjectRequest>,
) -> AppResult<AxumJson<ProjectResponse>> {
    Ok(AxumJson(
        service::archive(&state, &principal, &Some(ip.to_string()), id, body).await?,
    ))
}

async fn list_members(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    PathId(id): PathId,
) -> AppResult<AxumJson<Vec<ProjectMemberResponse>>> {
    Ok(AxumJson(
        service::list_members(&state, &principal, id).await?,
    ))
}

async fn add_member(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    ClientIp(ip): ClientIp,
    PathId(id): PathId,
    Json(body): Json<AddProjectMemberRequest>,
) -> AppResult<StatusCode> {
    service::add_member(&state, &principal, &Some(ip.to_string()), id, body).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn remove_member(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    ClientIp(ip): ClientIp,
    PathIds(id, user_id): PathIds,
) -> AppResult<StatusCode> {
    service::remove_member(&state, &principal, &Some(ip.to_string()), id, user_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_clients(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    PathId(id): PathId,
) -> AppResult<AxumJson<Vec<ProjectClientLinkResponse>>> {
    Ok(AxumJson(
        service::list_client_links(&state, &principal, id).await?,
    ))
}

async fn share(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    ClientIp(ip): ClientIp,
    PathId(id): PathId,
    Json(body): Json<ShareProjectRequest>,
) -> AppResult<StatusCode> {
    service::share_with_client(&state, &principal, &Some(ip.to_string()), id, body).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn unshare(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    ClientIp(ip): ClientIp,
    PathIds(id, client_account_id): PathIds,
) -> AppResult<StatusCode> {
    service::unshare_from_client(
        &state,
        &principal,
        &Some(ip.to_string()),
        id,
        client_account_id,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---- client portal ---------------------------------------------------------

async fn client_list(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    params: Result<Query<ClientProjectListQuery>, QueryRejection>,
) -> AppResult<AxumJson<Page<ClientProjectResponse>>> {
    let params = query(params)?;
    Ok(AxumJson(
        service::client_list(&state, &principal, &params).await?,
    ))
}

async fn client_get(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    PathId(id): PathId,
) -> AppResult<AxumJson<ClientProjectResponse>> {
    Ok(AxumJson(service::client_get(&state, &principal, id).await?))
}
