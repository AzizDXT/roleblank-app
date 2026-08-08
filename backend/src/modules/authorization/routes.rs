//! Axum handlers for the authorization surface.
//!
//! Handlers parse, delegate and serialise. **There is no business rule in this
//! file** — no permission check, no scope arithmetic, no transaction. Every
//! decision lives in `service`, so calling the service directly (from a test, from
//! another module, from a future job) is exactly as protected as calling it over
//! HTTP.
//!
//! Two extraction choices are deliberate:
//!
//! * path identifiers use `PathId`/`PathIds` from `platform::http::extract`, not
//!   axum's `Path<Uuid>`, whose rejection renders `text/plain` and echoes the
//!   caller's input — see the essay at the top of that module. This file used to
//!   carry its own `parse_id`, written before the shared extractors existed, and
//!   the two had already diverged: the local one called `raw.trim()`, so
//!   `/roles/%20{uuid}%20` was accepted here while `/departments/%20{uuid}%20` was
//!   a `400`. Both sides pinned their own behaviour with a test, so neither would
//!   ever have noticed the other. Nothing was exploitable — a UUID is a UUID once
//!   parsed — but two implementations of one rule is the drift this codebase
//!   argues against everywhere else, and the stricter of the two is the one to
//!   keep.
//! * the page query is read with `Query::try_from_uri` rather than as an extractor
//!   argument, for the same reason.

use axum::extract::{Query, State};
use axum::http::{StatusCode, Uri};
use axum::response::Response;
use axum::routing::{delete, get};
use axum::Router;

use crate::app::AppState;
use crate::platform::errors::{AppError, AppResult};
use crate::platform::http::extract::{Authenticated, ClientIp, Json, PathId, PathIds};
use crate::platform::http::idempotency::{self, Idempotent};
use crate::shared::pagination::{Page, PageQuery};

use super::dto::*;
use super::service;

/// Mounted by the application router under `/api/v1`.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/permissions", get(list_permissions))
        .route("/roles", get(list_roles).post(create_role))
        .route(
            "/roles/{role_id}",
            get(get_role).patch(update_role).delete(delete_role),
        )
        .route(
            "/users/{user_id}/roles",
            get(list_user_roles).post(assign_role),
        )
        .route("/users/{user_id}/roles/{role_id}", delete(unassign_role))
        .route("/users/{user_id}/permissions", get(effective_permissions))
        .route(
            "/users/{user_id}/permission-overrides",
            get(list_overrides).post(create_override),
        )
        .route(
            "/users/{user_id}/permission-overrides/{override_id}",
            delete(delete_override),
        )
}

/// `PageQuery` is `deny_unknown_fields`, so an unexpected query parameter is a
/// refusal rather than a silently ignored filter someone believed was applied.
fn page_query(uri: &Uri) -> AppResult<PageQuery> {
    Query::<PageQuery>::try_from_uri(uri)
        .map(|q| q.0)
        .map_err(|_| {
            AppError::BadRequest(
                "The query string contains parameters this endpoint does not accept.",
            )
        })
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn list_permissions(
    State(state): State<AppState>,
    principal: Authenticated,
) -> AppResult<axum::Json<PermissionCatalogueResponse>> {
    Ok(axum::Json(service::permission_catalogue(
        &state,
        &principal.0,
    )?))
}

async fn list_roles(
    State(state): State<AppState>,
    principal: Authenticated,
    uri: Uri,
) -> AppResult<axum::Json<Page<RoleSummaryResponse>>> {
    let query = page_query(&uri)?;
    Ok(axum::Json(
        service::list_roles(&state, &principal.0, &query).await?,
    ))
}

/// Honours `Idempotency-Key` (`api/openapi.yaml`). Creating a role creates
/// authority, so a duplicate created by a retry is a duplicate grant of it.
async fn create_role(
    State(state): State<AppState>,
    principal: Authenticated,
    ip: ClientIp,
    body: Idempotent<CreateRoleRequest>,
) -> AppResult<Response> {
    let principal_id = principal.user_id();
    let inner = state.clone();
    idempotency::create(
        &state,
        principal_id,
        "roles.create",
        body,
        move |request| async move {
            service::create_role(&inner, &principal.0, ip.hint(), request).await
        },
    )
    .await
}

async fn get_role(
    State(state): State<AppState>,
    principal: Authenticated,
    PathId(role_id): PathId,
) -> AppResult<axum::Json<RoleDetailResponse>> {
    Ok(axum::Json(
        service::get_role(&state, &principal.0, role_id).await?,
    ))
}

async fn update_role(
    State(state): State<AppState>,
    principal: Authenticated,
    ip: ClientIp,
    PathId(role_id): PathId,
    Json(body): Json<UpdateRoleRequest>,
) -> AppResult<axum::Json<RoleDetailResponse>> {
    Ok(axum::Json(
        service::update_role(&state, &principal.0, ip.hint(), role_id, body).await?,
    ))
}

async fn delete_role(
    State(state): State<AppState>,
    principal: Authenticated,
    ip: ClientIp,
    PathId(role_id): PathId,
) -> AppResult<StatusCode> {
    service::delete_role(&state, &principal.0, ip.hint(), role_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_user_roles(
    State(state): State<AppState>,
    principal: Authenticated,
    PathId(user_id): PathId,
) -> AppResult<axum::Json<UserRolesResponse>> {
    Ok(axum::Json(
        service::list_user_roles(&state, &principal.0, user_id).await?,
    ))
}

async fn assign_role(
    State(state): State<AppState>,
    principal: Authenticated,
    ip: ClientIp,
    PathId(user_id): PathId,
    Json(body): Json<AssignRoleRequest>,
) -> AppResult<(StatusCode, axum::Json<UserRolesResponse>)> {
    let roles = service::assign_role(&state, &principal.0, ip.hint(), user_id, body).await?;
    Ok((StatusCode::CREATED, axum::Json(roles)))
}

async fn unassign_role(
    State(state): State<AppState>,
    principal: Authenticated,
    ip: ClientIp,
    PathIds(user_id, role_id): PathIds,
) -> AppResult<StatusCode> {
    service::unassign_role(&state, &principal.0, ip.hint(), user_id, role_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn effective_permissions(
    State(state): State<AppState>,
    principal: Authenticated,
    PathId(user_id): PathId,
) -> AppResult<axum::Json<EffectivePermissionsResponse>> {
    Ok(axum::Json(
        service::effective_permissions(&state, &principal.0, user_id).await?,
    ))
}

async fn list_overrides(
    State(state): State<AppState>,
    principal: Authenticated,
    PathId(user_id): PathId,
) -> AppResult<axum::Json<OverrideListResponse>> {
    Ok(axum::Json(
        service::list_overrides(&state, &principal.0, user_id).await?,
    ))
}

async fn create_override(
    State(state): State<AppState>,
    principal: Authenticated,
    ip: ClientIp,
    PathId(user_id): PathId,
    Json(body): Json<CreateOverrideRequest>,
) -> AppResult<(StatusCode, axum::Json<OverrideResponse>)> {
    let created = service::create_override(&state, &principal.0, ip.hint(), user_id, body).await?;
    Ok((StatusCode::CREATED, axum::Json(created)))
}

async fn delete_override(
    State(state): State<AppState>,
    principal: Authenticated,
    ip: ClientIp,
    PathIds(user_id, override_id): PathIds,
) -> AppResult<StatusCode> {
    service::delete_override(&state, &principal.0, ip.hint(), user_id, override_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_page_query_is_closed() {
        let ok: Uri = "/roles?limit=10&sort=code&direction=asc"
            .parse()
            .expect("uri");
        let parsed = page_query(&ok).expect("valid query");
        assert_eq!(parsed.limit.as_deref(), Some("10"));
        assert_eq!(parsed.sort.as_deref(), Some("code"));

        assert!(page_query(&"/roles".parse::<Uri>().expect("uri")).is_ok());

        // An unrecognised parameter is refused rather than ignored: a caller who
        // believes they filtered a listing must not receive an unfiltered one.
        let sneaky: Uri = "/roles?include_system=false".parse().expect("uri");
        let err = page_query(&sneaky).unwrap_err();
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    }
}
