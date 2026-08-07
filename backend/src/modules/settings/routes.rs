//! Settings and feature-flag routes.
//!
//! Handlers parse, delegate and serialise. Validation and every authorisation
//! decision live in the service, so calling the service directly — from a test, a
//! CLI subcommand or another module — is equally protected.

use axum::extract::{Path, State};
use axum::routing::{get, put};
use axum::Router;

use crate::app::AppState;
use crate::platform::errors::AppResult;
use crate::platform::http::extract::{Authenticated, Json};

use super::dto::{
    FeatureFlagResponse, SettingResponse, UpdateFeatureFlagRequest, UpdateSettingRequest,
};
use super::service;

/// Mounted under `/api/v1`.
///
/// There is no `POST` and no `DELETE`. Settings and flags are created by
/// migrations, not by the API: a key that appears at runtime is a key nothing
/// reads, and a key that can be deleted is a security control that can be removed
/// rather than merely changed.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/settings", get(list_settings))
        .route("/settings/{key}", put(update_setting))
        .route("/feature-flags", get(list_feature_flags))
        .route("/feature-flags/{key}", put(update_feature_flag))
}

async fn list_settings(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
) -> AppResult<axum::Json<Vec<SettingResponse>>> {
    Ok(axum::Json(
        service::list_settings(&state, &principal).await?,
    ))
}

/// The path segment arrives as a `String` and is validated in the service. Taking
/// it as anything more structured would move a rejection into axum's extractor,
/// whose plain-text rejection body is not our error shape.
async fn update_setting(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    Path(key): Path<String>,
    Json(request): Json<UpdateSettingRequest>,
) -> AppResult<axum::Json<SettingResponse>> {
    Ok(axum::Json(
        service::update_setting(&state, &principal, &key, request).await?,
    ))
}

async fn list_feature_flags(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
) -> AppResult<axum::Json<Vec<FeatureFlagResponse>>> {
    Ok(axum::Json(
        service::list_feature_flags(&state, &principal).await?,
    ))
}

async fn update_feature_flag(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    Path(key): Path<String>,
    Json(request): Json<UpdateFeatureFlagRequest>,
) -> AppResult<axum::Json<FeatureFlagResponse>> {
    Ok(axum::Json(
        service::update_feature_flag(&state, &principal, &key, request).await?,
    ))
}
