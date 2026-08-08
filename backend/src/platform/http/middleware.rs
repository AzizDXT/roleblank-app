//! HTTP middleware: security headers, CORS, body limits, timeouts, panic capture.
//!
//! The ordering in `apply` is load-bearing and is commented there.

use axum::body::Body;
use axum::extract::Request;
use axum::http::{header, HeaderName, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Router;
use std::time::Duration;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;

use crate::app::AppState;
use crate::platform::config::{Config, Environment};
use crate::platform::errors::AppError;

/// Headers applied to every response.
///
/// This API returns only JSON and is consumed by non-browser clients, so the set
/// is small and deliberate. Headers that only matter for HTML documents (CSP,
/// X-Frame-Options, Referrer-Policy) are the future web layer's responsibility and
/// are not added here as security theatre.
pub async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    // The one browser-relevant header that genuinely applies: without it a
    // response can be sniffed into a different type than we declared.
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );

    // Every response from this API is either a security decision or
    // principal-specific data. None of it may be stored by an intermediary.
    if !headers.contains_key(header::CACHE_CONTROL) {
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store, no-cache, must-revalidate, private"),
        );
    }
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));

    // Do not advertise the implementation. Not a control on its own, but there is
    // no reason to hand an attacker the version-to-CVE mapping for free.
    headers.remove(header::SERVER);

    response
}

/// Reject request bodies and methods this API does not serve.
///
/// State-changing `GET` is impossible by construction here: no `GET` handler
/// mutates. This middleware additionally refuses `TRACE` and `CONNECT`, which have
/// no meaning for this API and have historically been reflection gadgets.
pub async fn method_guard(request: Request, next: Next) -> Response {
    if matches!(request.method(), &Method::TRACE | &Method::CONNECT) {
        return (
            StatusCode::METHOD_NOT_ALLOWED,
            [(header::CONTENT_TYPE, "application/problem+json")],
            r#"{"type":"https://roleblank.internal/problems/method_not_allowed","title":"Method not allowed","status":405,"code":"METHOD_NOT_ALLOWED","detail":"This method is not supported."}"#,
        )
            .into_response();
    }
    next.run(request).await
}

/// Build the CORS layer.
///
/// **Default deny.** With no configured origins the layer allows none, which is
/// the correct posture for an API with no frontend yet. A wildcard origin is
/// refused at configuration validation in production (TH-37), so it cannot reach
/// here; in development it is still never emitted alongside credentials.
pub fn cors_layer(config: &Config) -> CorsLayer {
    let origins: Vec<HeaderValue> = config
        .cors_allowed_origins
        .iter()
        .filter_map(|o| HeaderValue::from_str(o).ok())
        .collect();

    if origins.is_empty() {
        tracing::info!(
            "CORS: no origins configured; cross-origin browser requests will be refused"
        );
    }

    CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PATCH,
            Method::PUT,
            Method::DELETE,
        ])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            HeaderName::from_static("x-request-id"),
            HeaderName::from_static("idempotency-key"),
        ])
        .expose_headers([HeaderName::from_static("x-request-id"), header::RETRY_AFTER])
        // Credentials are NOT allowed: this API authenticates with a bearer header,
        // never a cookie. Allowing credentials would only matter for a
        // cookie-bearing client, and enabling it without needing it widens the
        // blast radius of any future origin misconfiguration.
        .allow_credentials(false)
        .max_age(Duration::from_secs(600))
}

/// Turn a panic into a `500` instead of a dropped connection.
///
/// A panic in a handler is a bug, but a *dropped connection* is a worse symptom:
/// it looks like a network fault and hides the defect. This converts it into a
/// logged, correlated `500` — while `#![forbid(unsafe_code)]` and the no-`unwrap`
/// rule are what stop panics happening in the first place.
fn panic_response(_err: Box<dyn std::any::Any + Send + 'static>) -> Response<Body> {
    tracing::error!(
        request_id = crate::platform::http::request_id::RequestId::current().unwrap_or_default(),
        "a handler panicked; returning 500"
    );
    AppError::Internal("handler panicked".into()).into_response()
}

/// Compose every layer onto the router.
///
/// **Order matters.** tower applies layers bottom-up on the request path, so the
/// listing below is outermost-last. Reading it as "what happens to a request in
/// order":
///
///   1. panic capture      — outermost, so it catches panics from everything inside
///   2. request id         — established before anything can log
///   3. timeout            — bounds total handling time
///   4. body limit         — rejects an oversized body before a handler buffers it
///   5. method guard
///   6. CORS
///   7. security headers   — innermost, applied to whatever response emerged
pub fn apply(router: Router<AppState>, state: &AppState) -> Router<AppState> {
    let config = &state.config;
    router
        // Innermost, so it runs immediately before the handler's extractors — which
        // is where the expensive work starts. Resolving a bearer token is a database
        // query whether or not the token is real, so without this an attacker with
        // a bag of invented tokens can force one query per request while never
        // authenticating. Innermost also means its `429` still travels back out
        // through the header and CORS layers, so a throttled response is shaped like
        // every other response.
        //
        // This is the *coarse* ceiling. The budget that actually governs normal
        // authenticated traffic is per-principal and lives in the extractors
        // (`http::extract`), because only there is the principal known.
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            general_ip_limit,
        ))
        .layer(axum::middleware::from_fn(security_headers))
        .layer(cors_layer(config))
        .layer(axum::middleware::from_fn(method_guard))
        // 256 KiB by default. Every endpoint here takes a small JSON document; the
        // limit exists so a 200 MB body is refused at the transport rather than
        // buffered into memory (TH-33).
        .layer(RequestBodyLimitLayer::new(config.limits.max_body_bytes))
        // Bounds slow-client and slow-query handling. Paired with the database
        // `statement_timeout`, so neither layer can hang waiting on the other.
        //
        // `with_status_code` rather than the deprecated `new`: the default would be
        // a bare 408 with no body, which breaks the promise that every error is
        // `application/problem+json`. 503 is the honest code — the request was not
        // malformed, we simply could not finish it in time.
        .layer(TimeoutLayer::with_status_code(
            StatusCode::SERVICE_UNAVAILABLE,
            config.limits.request_timeout,
        ))
        .layer(axum::middleware::from_fn(
            crate::platform::http::request_id::layer,
        ))
        .layer(CatchPanicLayer::custom(panic_response))
        // Outermost of all, so it observes the status every other layer produces —
        // including a panic that `CatchPanicLayer` has just turned into a `500`.
        .layer(axum::middleware::from_fn_with_state(state.clone(), observe))
}

/// Record one HTTP request and its latency.
///
/// **The matched route pattern, never the URI.** `/api/v1/projects/{id}` is one
/// series; the raw path would mint one per identifier, which is an
/// attacker-controlled cardinality explosion in a process-resident map. The metrics
/// module bounds its own series count, but the bound must not be the only defence —
/// filling it with junk would evict the series an operator actually needs.
///
/// **Outermost on purpose.** A request refused by an inner layer — rate limit, body
/// limit, authentication — is still a request, and an error rate that counts only
/// the requests that got through is worse than no error rate, because it looks
/// healthy exactly when the system is refusing everything.
///
/// This closes a gap of the same shape as the rate limiter: `/metrics` and the
/// comment above it promised request-volume and error-rate telemetry that nothing
/// recorded. Two series were being written in the entire process.
async fn observe(
    axum::extract::State(state): axum::extract::State<AppState>,
    matched: Option<axum::extract::MatchedPath>,
    request: Request,
    next: Next,
) -> Response {
    // Read before `next.run` consumes the request.
    let method = request.method().clone();
    let route = matched
        .map(|m| m.as_str().to_string())
        // No matched path means no route matched: a `404` on an unknown URI. One
        // series, deliberately, or scanning the address space would be a way to
        // fill this map.
        .unwrap_or_else(|| "<unmatched>".to_string());

    let started = std::time::Instant::now();
    let response = next.run(request).await;
    state.metrics.latency(started.elapsed());
    state
        .metrics
        .http_request(method.as_str(), &route, response.status().as_u16());
    response
}

/// The coarse per-address ceiling, applied before authentication.
///
/// Deliberately generous. It is not the control that governs normal traffic — that
/// is the per-principal budget in `http::extract`, which can tell one user from
/// another. This layer exists for the population that has no principal yet:
/// anonymous callers, and callers presenting tokens that will turn out to be
/// invalid. Both cost a database round trip to find out.
///
/// Because it cannot distinguish a busy office from an attacker sharing its
/// address, its quota is set high enough that ordinary shared-NAT use never reaches
/// it, and low enough that a single host cannot saturate the pool.
async fn general_ip_limit(
    axum::extract::State(state): axum::extract::State<AppState>,
    crate::platform::http::extract::ClientIp(ip): crate::platform::http::extract::ClientIp,
    request: Request,
    next: Next,
) -> Result<Response, AppError> {
    crate::platform::http::rate_limit::enforce(
        state.limiter.as_ref(),
        &crate::platform::http::rate_limit::keys::general_ip(ip),
        state.config.rate_limits.general_per_ip_per_minute,
        crate::platform::http::rate_limit::MINUTE,
    )
    .await?;
    Ok(next.run(request).await)
}

/// Warn loudly about a development-only posture, once, at startup.
pub fn log_posture(config: &Config) {
    if config.environment != Environment::Production {
        tracing::warn!(
            environment = config.environment.as_str(),
            cors_origins = config.cors_allowed_origins.len(),
            openapi_exposed = config.expose_openapi,
            "running with development configuration; this posture must never reach production"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::routing::get;
    use tower::ServiceExt;

    fn test_router() -> Router {
        Router::new()
            .route("/ok", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(security_headers))
            .layer(axum::middleware::from_fn(method_guard))
    }

    #[tokio::test]
    async fn security_headers_are_applied_to_every_response() {
        let response = test_router()
            .oneshot(Request::builder().uri("/ok").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let headers = response.headers();
        assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
        let cache = headers
            .get(header::CACHE_CONTROL)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            cache.contains("no-store"),
            "responses must not be cacheable: {cache}"
        );
        assert!(cache.contains("private"));
        assert!(
            headers.get(header::SERVER).is_none(),
            "the server header must not be advertised"
        );
    }

    #[tokio::test]
    async fn trace_and_connect_are_refused() {
        for method in [Method::TRACE, Method::CONNECT] {
            let response = test_router()
                .oneshot(
                    Request::builder()
                        .method(method.clone())
                        .uri("/ok")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::METHOD_NOT_ALLOWED,
                "{method} should be refused"
            );
            let body = to_bytes(response.into_body(), 4096).await.unwrap();
            let text = String::from_utf8_lossy(&body);
            assert!(
                text.contains("METHOD_NOT_ALLOWED"),
                "should be a problem+json body: {text}"
            );
        }
    }

    #[tokio::test]
    async fn ordinary_methods_pass_the_guard() {
        let response = test_router()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/ok")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    // TH-37 — that an empty origin list allows nothing, and that a wildcard is
    // never synthesised, is asserted behaviourally in `tests/security/` against a
    // fully constructed application. tower-http does not expose the origin
    // predicate for inspection, so a unit test here could only re-state the
    // construction rather than verify the behaviour.
}
