//! System routes: two health probes, the metrics scrape, and one authenticated
//! information endpoint.
//!
//! Handlers parse, delegate and serialise. There is no business rule here.

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;

use crate::app::AppState;
use crate::platform::errors::{AppError, AppResult};
use crate::platform::http::extract::Authenticated;

use super::dto::{HealthResponse, SystemInfoResponse};
use super::service;

/// The system surface.
///
/// **Mounted at the root**, not under `/api/v1` — the health probes and the metrics
/// scrape are outside the versioned API because an orchestrator's probe URL must
/// not move when the API version does. The one authenticated route therefore
/// carries its full path.
///
/// The two halves are built separately so a reviewer can see, in one place, exactly
/// which paths bypass authentication.
pub fn router() -> Router<AppState> {
    anonymous_routes().merge(authenticated_routes())
}

/// Three routes, all anonymous by necessity: a probe cannot authenticate, and a
/// scrape target that required a session would need credentials distributed to the
/// monitoring system. Each is separately justified at its handler.
fn anonymous_routes() -> Router<AppState> {
    Router::new()
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .route("/metrics", get(metrics))
}

fn authenticated_routes() -> Router<AppState> {
    Router::new().route("/api/v1/system/info", get(system_info))
}

/// Probe responses must never be cached: a cached `ok` from an orchestrator's
/// proxy would keep routing traffic to a process that has since lost its database.
fn no_store<T: IntoResponse>(status: StatusCode, body: T) -> Response {
    (status, [(header::CACHE_CONTROL, "no-store")], body).into_response()
}

/// `GET /health/live` — process liveness only.
///
/// Deliberately performs **no** database call. Liveness answers "should the
/// supervisor restart this process?", and a database outage is not a reason to
/// restart every replica: doing so turns a recoverable dependency failure into a
/// crash loop that removes the capacity needed to recover. Dependency health is
/// `/health/ready`'s job, and its consequence is removal from the load balancer,
/// not termination.
async fn live() -> Response {
    no_store(StatusCode::OK, axum::Json(HealthResponse::ok()))
}

/// `GET /health/ready` — the database answers and the schema is current.
///
/// The response body is one of exactly two fixed documents. **It must not leak the
/// database hostname, the driver's error message, the schema version, the
/// migration name, or any other topology detail**: this endpoint is reachable by
/// anyone who can reach the service, and a readiness body that names its
/// dependencies is free reconnaissance (TH-35). The service layer collapses every
/// failure to a `bool` precisely so that no such value is in scope here.
async fn ready(State(state): State<AppState>) -> Response {
    if service::is_ready(&state).await {
        no_store(StatusCode::OK, axum::Json(HealthResponse::ok()))
    } else {
        no_store(
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(HealthResponse::not_ready()),
        )
    }
}

/// `GET /metrics` — Prometheus text exposition.
///
/// Two operational rules that are not enforceable from inside this process:
///
/// * **In production this endpoint must be restricted by the operator's network
///   policy** — a scrape target reachable from the internet publishes request
///   volumes, error rates and authorisation-denial counts, which is a live feed of
///   how an attack is progressing. `RB_METRICS_ENABLED=false` turns it off
///   entirely; the network policy is what protects it when it is on.
/// * The series carry **no principal-identifying labels** by construction — no user
///   id, no email, no session id, no path segment containing an identifier.
///   Metric labels are unbounded cardinality *and* they end up in a monitoring
///   system with a different, usually weaker, access-control model than this one.
///
/// Disabled means `404`, not `403`: an operator who turned it off should not have
/// the endpoint's existence confirmed to a prober.
async fn metrics(State(state): State<AppState>) -> AppResult<Response> {
    if !state.config.metrics_enabled {
        return Err(AppError::NotFound);
    }

    // Sampled at scrape time rather than tracked continuously: the pool already
    // knows its own size and idle count, so mirroring them on every checkout would
    // be bookkeeping for a number nobody reads between scrapes. Without this the
    // two gauges were published and never written — the same "documented but
    // absent" shape the rest of this closure has been removing.
    state.metrics.db_pool(state.db.size(), state.db.num_idle());

    let body = state.metrics.render();
    Ok((
        StatusCode::OK,
        [
            // The exposition format version Prometheus expects for text scrapes.
            (
                header::CONTENT_TYPE,
                "text/plain; version=0.0.4; charset=utf-8",
            ),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body,
    )
        .into_response())
}

/// `GET /api/v1/system/info` — authenticated.
async fn system_info(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
) -> AppResult<axum::Json<SystemInfoResponse>> {
    Ok(axum::Json(service::info(&state, &principal).await?))
}

#[cfg(test)]
mod tests {
    use super::super::dto::{HealthResponse, SystemInfoResponse};

    /// A regression guard on the readiness contract that does not need a database.
    ///
    /// The handler can only ever hand `axum::Json` one of these two values, so
    /// asserting on them asserts on the wire body.
    #[test]
    fn the_readiness_body_is_a_closed_document() {
        let body = serde_json::to_string(&HealthResponse::not_ready()).expect("serialise");
        assert_eq!(body, r#"{"status":"not_ready"}"#);
        assert!(!body.contains("migration"));
        assert!(!body.contains("db"));
    }

    /// `enabled_features` is a list of keys, never of objects: an object would
    /// eventually grow a `description` or an `is_security_sensitive` member.
    #[test]
    fn enabled_features_is_a_flat_list_of_keys() {
        let value = serde_json::to_value(SystemInfoResponse {
            environment: "development".into(),
            initialized: false,
            enabled_features: vec!["client_portal".into(), "chat".into()],
        })
        .expect("serialise");
        let features = value["enabled_features"].as_array().expect("array");
        assert!(features.iter().all(|f| f.is_string()));
    }
}
