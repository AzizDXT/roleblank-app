//! Bootstrap HTTP surface. Parse, delegate, serialise — no business rules here.

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::Router;

use crate::app::AppState;
use crate::platform::errors::AppResult;
use crate::platform::http::extract::{ClientIp, Json};

use super::dto::{BootstrapRootRequest, BootstrapRootResponse, BootstrapStatusResponse};
use super::service;

/// Both routes are anonymous by necessity: they exist to serve a system that has
/// no principals yet. Neither takes an `Authenticated` extractor, and that is the
/// reason `POST /root` carries an operator secret, an advisory lock and a
/// permanent 409 instead.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/bootstrap/status", get(status))
        .route("/api/v1/bootstrap/root", post(create_root))
}

async fn status(State(state): State<AppState>) -> AppResult<axum::Json<BootstrapStatusResponse>> {
    Ok(axum::Json(service::status(&state).await?))
}

async fn create_root(
    State(state): State<AppState>,
    client_ip: ClientIp,
    Json(request): Json<BootstrapRootRequest>,
) -> AppResult<(StatusCode, axum::Json<BootstrapRootResponse>)> {
    let response = service::create_root(&state, client_ip, request).await?;
    Ok((StatusCode::CREATED, axum::Json(response)))
}
