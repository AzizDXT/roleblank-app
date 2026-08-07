//! Attack probes against the anonymous and authentication surface (brief §74).
//!
//! Each test is an attack, named for the attack. They exercise the paths an
//! unauthenticated attacker reaches first: malformed input, oversized input,
//! injection strings, token misuse, and enumeration.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use serde_json::json;

use crate::common::{TestApp, TEST_BOOTSTRAP_SECRET, TEST_PASSWORD};

/// Bootstrap an owner and return an authenticated-but-MFA-pending token, which is
/// the most privileged thing an attacker could plausibly obtain here.
async fn bootstrapped(app: &TestApp) -> String {
    app.post(
        "/api/v1/bootstrap/root",
        None,
        json!({
            "bootstrap_secret": TEST_BOOTSTRAP_SECRET,
            "email": "owner@probe.test",
            "display_name": "Owner",
            "password": TEST_PASSWORD,
        }),
    )
    .await
    .assert_status(StatusCode::CREATED);

    let login = app
        .post(
            "/api/v1/auth/login",
            None,
            json!({"email": "owner@probe.test", "password": TEST_PASSWORD}),
        )
        .await;
    login.assert_status(StatusCode::OK);
    login.str_at("/access_token").to_string()
}

// ===========================================================================
// Authentication surface
// ===========================================================================

#[tokio::test]
async fn missing_and_malformed_bearer_headers_are_refused() {
    let app = TestApp::spawn().await;

    // No header at all.
    app.get("/api/v1/auth/me", None)
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "AUTHENTICATION_FAILED");

    let malformed = [
        "",
        "Bearer",
        "Bearer ",
        "rb_at_abcdefghijklmnopqrstuvwxyz0123456789ABCDE",
        "Basic dXNlcjpwYXNzd29yZA==",
        "Token rb_at_abc",
        "Bearer  double  space",
        &format!("Bearer {}", "A".repeat(5000)),
    ];

    for value in malformed {
        let request = Request::builder()
            .method(Method::GET)
            .uri("/api/v1/auth/me")
            .header(header::AUTHORIZATION, value)
            .body(Body::empty())
            .expect("request");
        app.request(request)
            .await
            .assert_error(StatusCode::UNAUTHORIZED, "AUTHENTICATION_FAILED")
            .assert_no_secrets();
    }
}

/// TH-36. A distinct code, not a generic 401, so the caller learns they have a leak.
#[tokio::test]
async fn a_token_in_the_query_string_is_refused_distinctly() {
    let app = TestApp::spawn().await;
    let token = bootstrapped(&app).await;

    for path in [
        "/api/v1/auth/me?access_token=rb_at_x",
        "/api/v1/auth/me?token=rb_at_x",
        "/api/v1/auth/me?bearer=x",
        "/api/v1/auth/me?anything=rb_at_leaked_value",
    ] {
        let request = Request::builder()
            .method(Method::GET)
            .uri(path)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .expect("request");
        app.request(request)
            .await
            .assert_error(StatusCode::BAD_REQUEST, "BAD_REQUEST");
    }
}

#[tokio::test]
async fn a_forged_or_expired_token_never_authenticates() {
    let app = TestApp::spawn().await;
    bootstrapped(&app).await;

    let forged = [
        // Right shape, wrong value.
        format!("rb_at_{}", "A".repeat(43)),
        format!("rb_at_{}", "z".repeat(43)),
        // A refresh token presented where an access token is expected.
        format!("rb_rt_{}", "A".repeat(43)),
        // Right prefix, wrong length.
        format!("rb_at_{}", "A".repeat(42)),
        format!("rb_at_{}", "A".repeat(44)),
        // Illegal alphabet.
        format!("rb_at_{}", "!".repeat(43)),
    ];

    for token in forged {
        app.get("/api/v1/auth/me", Some(&token))
            .await
            .assert_error(StatusCode::UNAUTHORIZED, "AUTHENTICATION_FAILED");
    }
}

/// TH-23. Unknown account and wrong password must be indistinguishable in status,
/// code and body.
#[tokio::test]
async fn login_does_not_reveal_whether_an_account_exists() {
    let app = TestApp::spawn().await;
    bootstrapped(&app).await;

    let unknown = app
        .post(
            "/api/v1/auth/login",
            None,
            json!({"email": "nobody@probe.test", "password": TEST_PASSWORD}),
        )
        .await;
    let wrong_password = app
        .post(
            "/api/v1/auth/login",
            None,
            json!({"email": "owner@probe.test", "password": "definitely not the password"}),
        )
        .await;

    assert_eq!(unknown.status, wrong_password.status);
    assert_eq!(unknown.error_code(), wrong_password.error_code());
    assert_eq!(
        unknown.json().get("detail"),
        wrong_password.json().get("detail"),
        "the two failure modes are distinguishable by their body"
    );
    unknown.assert_error(StatusCode::UNAUTHORIZED, "AUTHENTICATION_FAILED");
}

/// Timing must not distinguish them either. This is a coarse check — a precise
/// timing analysis needs a dedicated harness — but it catches the gross case where
/// the unknown-account path returns without hashing at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn login_timing_does_not_reveal_whether_an_account_exists() {
    let app = TestApp::spawn().await;
    bootstrapped(&app).await;

    async fn median_micros(app: &TestApp, email: &str) -> u128 {
        use roleblank_backend::platform::http::rate_limit::keys;
        let peer = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

        let mut samples = Vec::new();
        for _ in 0..7 {
            // Clear the limiter before each sample. Fourteen logins from one address
            // exceed the ten-per-minute per-IP quota, and a `429` returns in
            // microseconds without hashing anything — so without this the second
            // batch measures the rate limiter rather than Argon2, and the test
            // reports a twelve-fold "timing leak" that does not exist. (Found when
            // this suite was wired into the test binary; it had never been run.)
            app.state.limiter.reset(&keys::login_ip(peer)).await;
            app.state.limiter.reset(&keys::login_account(email)).await;

            let start = std::time::Instant::now();
            let _ = app
                .post(
                    "/api/v1/auth/login",
                    None,
                    json!({"email": email, "password": "wrong password entirely"}),
                )
                .await;
            samples.push(start.elapsed().as_micros());
        }
        samples.sort_unstable();
        samples[samples.len() / 2]
    }

    let known = median_micros(&app, "owner@probe.test").await;
    let unknown = median_micros(&app, "nobody@probe.test").await;

    let ratio = known.max(unknown) as f64 / known.min(unknown).max(1) as f64;
    assert!(
        ratio < 3.0,
        "the unknown-account path is {ratio:.1}x different from the known-account path \
         (known={known}us unknown={unknown}us) — the dummy-hash equalisation is not working"
    );
}

// ===========================================================================
// Input handling
// ===========================================================================

#[tokio::test]
async fn an_oversized_body_is_refused_at_the_transport() {
    let app = TestApp::spawn().await;

    // Well beyond the 256 KiB limit.
    let huge = "x".repeat(2 * 1024 * 1024);
    let response = app
        .post(
            "/api/v1/auth/login",
            None,
            json!({"email": "a@b.test", "password": huge}),
        )
        .await;

    assert!(
        matches!(
            response.status,
            StatusCode::PAYLOAD_TOO_LARGE | StatusCode::BAD_REQUEST
        ),
        "an oversized body produced {} instead of being refused",
        response.status
    );
    response.assert_no_secrets();
}

#[tokio::test]
async fn malformed_json_is_refused_without_leaking_serde_detail() {
    let app = TestApp::spawn().await;

    for body in [
        "not json at all",
        "{",
        "{\"email\":}",
        "[]",
        "null",
        "{\"email\": \"a@b.test\", \"password\": }",
        // Deeply nested — a naive parser is a stack-overflow target.
        &format!("{}{}", "[".repeat(2000), "]".repeat(2000)),
    ] {
        let request = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/auth/login")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .expect("request");
        let response = app.request(request).await;
        assert!(
            response.status.is_client_error(),
            "malformed body {body:?} produced {}",
            response.status
        );
        response.assert_no_secrets();
        // serde's message names Rust types and field paths — it must not reach the client.
        let text = String::from_utf8_lossy(&response.raw);
        assert!(
            !text.contains("LoginRequest"),
            "a Rust type name leaked: {text}"
        );
        assert!(
            !text.contains("line 1 column"),
            "a serde position leaked: {text}"
        );
    }
}

#[tokio::test]
async fn an_unsupported_content_type_is_refused() {
    let app = TestApp::spawn().await;

    for content_type in [
        "application/x-www-form-urlencoded",
        "multipart/form-data; boundary=x",
        "text/plain",
        "application/xml",
        "",
    ] {
        let request = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/auth/login")
            .header(header::CONTENT_TYPE, content_type)
            .body(Body::from(r#"{"email":"a@b.test","password":"x"}"#))
            .expect("request");
        let response = app.request(request).await;
        assert_eq!(
            response.status,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "content type {content_type:?} was accepted"
        );
    }

    // The charset parameter is legitimate and must still be accepted.
    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/login")
        .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
        .body(Body::from(
            r#"{"email":"a@b.test","password":"wrong password here"}"#,
        ))
        .expect("request");
    let response = app.request(request).await;
    assert_ne!(response.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

/// TH-12. The mass-assignment defence: an unknown field is a rejection, not an
/// ignored extra.
#[tokio::test]
async fn unknown_and_privileged_json_fields_are_rejected() {
    let app = TestApp::spawn().await;

    let payloads = [
        json!({"email":"a@b.test","password":"x","is_root":true}),
        json!({"email":"a@b.test","password":"x","principal_type":"INTERNAL"}),
        json!({"email":"a@b.test","password":"x","role_ids":["00000000-0000-7000-8000-000000000001"]}),
        json!({"email":"a@b.test","password":"x","permissions":["audit.read"]}),
        json!({"email":"a@b.test","password":"x","status":"ACTIVE"}),
        json!({"email":"a@b.test","password":"x","mfa_verified":true}),
        json!({"email":"a@b.test","password":"x","security_version":999}),
        json!({"email":"a@b.test","password":"x","__proto__":{"is_root":true}}),
    ];

    for payload in payloads {
        let response = app.post("/api/v1/auth/login", None, payload.clone()).await;
        assert_eq!(
            response.status,
            StatusCode::BAD_REQUEST,
            "payload {payload} was not rejected"
        );
    }
}

/// SQL injection strings must be treated as ordinary data everywhere they can
/// reach — and the sort parameter, which cannot be parameterised, must reject them
/// by allowlist rather than by escaping.
#[tokio::test]
async fn sql_injection_strings_are_inert() {
    let app = TestApp::spawn().await;
    let token = bootstrapped(&app).await;

    let injections = [
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "1; DELETE FROM audit_events",
        "\" UNION SELECT password_hash FROM credentials --",
        "admin'--",
        "%27%20OR%201=1",
    ];

    for injection in injections {
        // As a login identifier.
        app.post(
            "/api/v1/auth/login",
            None,
            json!({"email": injection, "password": injection}),
        )
        .await
        .assert_no_secrets();

        // As a sort parameter — refused by allowlist, and the value is not echoed.
        let encoded = injection
            .replace(' ', "%20")
            .replace('\'', "%27")
            .replace('"', "%22");
        let response = app
            .get(&format!("/api/v1/users?sort={encoded}"), Some(&token))
            .await;
        assert!(
            response.status.is_client_error(),
            "sort={injection:?} produced {}",
            response.status
        );
        let text = String::from_utf8_lossy(&response.raw);
        assert!(
            !text.contains("DROP"),
            "the rejected sort value was echoed back: {text}"
        );
    }

    // The database is intact.
    let users: (i64,) = sqlx::query_as("SELECT count(*) FROM users")
        .fetch_one(&app.db)
        .await
        .expect("count");
    assert_eq!(users.0, 1);
    let tables: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public'",
    )
    .fetch_one(&app.db)
    .await
    .expect("count tables");
    assert!(tables.0 > 20, "tables disappeared");
}

#[tokio::test]
async fn pagination_parameters_are_bounded() {
    let app = TestApp::spawn().await;
    let token = bootstrapped(&app).await;

    for query in [
        "limit=101",
        "limit=999999999",
        "limit=0",
        "limit=-1",
        "limit=abc",
        "limit=1e10",
        "direction=sideways",
        "cursor=notavalidcursor",
        &format!("cursor={}", "A".repeat(10_000)),
    ] {
        let response = app
            .get(&format!("/api/v1/users?{query}"), Some(&token))
            .await;
        assert!(
            response.status.is_client_error(),
            "{query} was accepted with status {}",
            response.status
        );
    }
}

/// TH-32. A CRLF payload in a stored, loggable field must not survive into a log
/// or into audit metadata as a line break.
#[tokio::test]
async fn crlf_payloads_cannot_forge_a_log_line() {
    let app = TestApp::spawn().await;

    let attack = "Attacker\r\n{\"level\":\"INFO\",\"message\":\"admin approved payment\"}";
    app.post(
        "/api/v1/bootstrap/root",
        None,
        json!({
            "bootstrap_secret": TEST_BOOTSTRAP_SECRET,
            "email": "crlf@probe.test",
            "display_name": attack,
            "password": TEST_PASSWORD,
        }),
    )
    .await;

    // Whatever was stored, no audit metadata may contain a raw line break.
    let metadata: Vec<(serde_json::Value,)> = sqlx::query_as("SELECT metadata FROM audit_events")
        .fetch_all(&app.db)
        .await
        .expect("read");
    for (value,) in metadata {
        let text = serde_json::to_string(&value).expect("serialise");
        assert!(
            !text.contains("\\r\\n"),
            "a CRLF sequence survived into audit metadata: {text}"
        );
    }
}

// ===========================================================================
// Transport and headers
// ===========================================================================

#[tokio::test]
async fn security_headers_are_present_on_every_response() {
    let app = TestApp::spawn().await;

    for (path, expect_ok) in [("/health/live", true), ("/api/v1/auth/me", false)] {
        let response = app.get(path, None).await;
        assert_eq!(response.status.is_success(), expect_ok);
        assert_eq!(
            response
                .headers
                .get("x-content-type-options")
                .and_then(|v| v.to_str().ok()),
            Some("nosniff"),
            "missing nosniff on {path}"
        );
        let cache = response
            .headers
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert!(cache.contains("no-store"), "{path} is cacheable: {cache}");
        assert!(
            response.headers.get(header::SERVER).is_none(),
            "the server header is advertised on {path}"
        );
        assert!(
            response.headers.get("x-request-id").is_some(),
            "no correlation id returned for {path}"
        );
    }
}

#[tokio::test]
async fn trace_and_connect_are_refused() {
    let app = TestApp::spawn().await;

    for method in [Method::TRACE, Method::CONNECT] {
        let request = Request::builder()
            .method(method.clone())
            .uri("/health/live")
            .body(Body::empty())
            .expect("request");
        let response = app.request(request).await;
        assert_eq!(
            response.status,
            StatusCode::METHOD_NOT_ALLOWED,
            "{method} was accepted"
        );
    }
}

/// A caller-supplied correlation id is accepted only if it cannot poison a log.
#[tokio::test]
async fn a_hostile_request_id_header_is_replaced_not_echoed() {
    let app = TestApp::spawn().await;

    for hostile in [
        "abc\r\nINFO forged",
        "has spaces",
        "\"quoted\"",
        &"A".repeat(5000),
        "short",
    ] {
        let request = Request::builder()
            .method(Method::GET)
            .uri("/health/live")
            .header("x-request-id", hostile.replace(['\r', '\n'], ""))
            .body(Body::empty())
            .expect("request");
        let response = app.request(request).await;
        let echoed = response
            .headers
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert!(
            !echoed.contains(' '),
            "a hostile request id was echoed: {echoed:?}"
        );
        assert!(echoed.len() <= 64);
    }
}

/// The health endpoints are anonymous internet surface and must reveal nothing.
#[tokio::test]
async fn health_endpoints_leak_no_infrastructure_detail() {
    let app = TestApp::spawn().await;

    for path in ["/health/live", "/health/ready"] {
        let response = app.get(path, None).await;
        let text = String::from_utf8_lossy(&response.raw).to_lowercase();
        for forbidden in [
            "postgres",
            "roleblank-postgres",
            "5432",
            "password",
            "migrator",
            "sqlx",
            "/work",
            "version",
            "host",
        ] {
            assert!(
                !text.contains(forbidden),
                "{path} leaked `{forbidden}`: {text}"
            );
        }
    }
}
