//! Axum handlers for tasks. Parse, delegate, serialise — no business rules.

use axum::extract::rejection::QueryRejection;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::{delete, get};
use axum::{Json as AxumJson, Router};
use uuid::Uuid;

use super::dto::{
    AssignTaskRequest, CancelTaskQuery, ClientTaskListQuery, ClientTaskResponse, CreateTaskRequest,
    TaskAssigneeResponse, TaskListQuery, TaskResponse, UpdateTaskRequest,
};
use super::service;
use crate::app::AppState;
use crate::platform::errors::{AppError, AppResult};
use crate::platform::http::extract::{Authenticated, ClientIp, Json};
use crate::platform::http::idempotency::{self, Idempotent};
use crate::shared::pagination::Page;

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

/// The path parameter is named `{id}` in every route, including the nested project
/// routes, so that this router and `projects::router` can be merged: axum's matcher
/// refuses two routes that use different parameter names in the same position.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/tasks", get(list).post(create))
        .route(
            "/api/v1/tasks/{id}",
            get(get_one).patch(patch).delete(cancel),
        )
        .route(
            "/api/v1/tasks/{id}/assignees",
            get(list_assignees).post(assign),
        )
        .route("/api/v1/tasks/{id}/assignees/{user_id}", delete(unassign))
        // Read-only on purpose. A nested `POST` would take the project from the path
        // while the body also names one, and two sources of truth for "which project
        // is this task in" is a confused deputy waiting to happen. Creation is
        // `POST /api/v1/tasks` with `project_id` in the body, and only there.
        .route("/api/v1/projects/{id}/tasks", get(list_for_project))
        .route(
            "/api/v1/client-portal/projects/{id}/tasks",
            get(client_list_for_project),
        )
        .route("/api/v1/client-portal/tasks/{id}", get(client_get))
}

// ---- internal --------------------------------------------------------------

async fn list(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    params: Result<Query<TaskListQuery>, QueryRejection>,
) -> AppResult<AxumJson<Page<TaskResponse>>> {
    let params = query(params)?;
    Ok(AxumJson(
        service::list(&state, &principal, &params, None).await?,
    ))
}

async fn list_for_project(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    Path(project_id): Path<Uuid>,
    params: Result<Query<TaskListQuery>, QueryRejection>,
) -> AppResult<AxumJson<Page<TaskResponse>>> {
    let params = query(params)?;
    Ok(AxumJson(
        service::list(&state, &principal, &params, Some(project_id)).await?,
    ))
}

/// Honours `Idempotency-Key` (`api/openapi.yaml`), so a retried create replays the
/// original task rather than adding a duplicate to the project.
async fn create(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    ClientIp(ip): ClientIp,
    body: Idempotent<CreateTaskRequest>,
) -> AppResult<Response> {
    let principal_id = principal.user_id();
    let inner = state.clone();
    idempotency::create(
        &state,
        principal_id,
        "tasks.create",
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
    Path(id): Path<Uuid>,
) -> AppResult<AxumJson<TaskResponse>> {
    Ok(AxumJson(service::get(&state, &principal, id).await?))
}

async fn patch(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    ClientIp(ip): ClientIp,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateTaskRequest>,
) -> AppResult<AxumJson<TaskResponse>> {
    Ok(AxumJson(
        service::update(&state, &principal, &Some(ip.to_string()), id, body).await?,
    ))
}

/// `DELETE` cancels; it never removes a row.
async fn cancel(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    ClientIp(ip): ClientIp,
    Path(id): Path<Uuid>,
    params: Result<Query<CancelTaskQuery>, QueryRejection>,
) -> AppResult<StatusCode> {
    let params = query(params)?;
    service::cancel(&state, &principal, &Some(ip.to_string()), id, &params).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_assignees(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    Path(id): Path<Uuid>,
) -> AppResult<AxumJson<Vec<TaskAssigneeResponse>>> {
    Ok(AxumJson(
        service::list_assignees(&state, &principal, id).await?,
    ))
}

async fn assign(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    ClientIp(ip): ClientIp,
    Path(id): Path<Uuid>,
    Json(body): Json<AssignTaskRequest>,
) -> AppResult<StatusCode> {
    service::assign(&state, &principal, &Some(ip.to_string()), id, body).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn unassign(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    ClientIp(ip): ClientIp,
    Path((id, user_id)): Path<(Uuid, Uuid)>,
) -> AppResult<StatusCode> {
    service::unassign(&state, &principal, &Some(ip.to_string()), id, user_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---- client portal ---------------------------------------------------------

async fn client_list_for_project(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    Path(project_id): Path<Uuid>,
    params: Result<Query<ClientTaskListQuery>, QueryRejection>,
) -> AppResult<AxumJson<Page<ClientTaskResponse>>> {
    let params = query(params)?;
    Ok(AxumJson(
        service::client_list_for_project(&state, &principal, project_id, &params).await?,
    ))
}

async fn client_get(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    Path(id): Path<Uuid>,
) -> AppResult<AxumJson<ClientTaskResponse>> {
    Ok(AxumJson(service::client_get(&state, &principal, id).await?))
}
