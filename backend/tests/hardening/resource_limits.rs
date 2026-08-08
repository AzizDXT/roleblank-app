//! §12 — resource exhaustion.
//!
//! Every probe here has to satisfy three conditions, not one:
//!
//!   * the abusive request is **refused** with a stable `code`;
//!   * the process is **still serving** afterwards — asserted by a following
//!     ordinary request, because a refusal that costs the service its liveness is
//!     not a defence;
//!   * the refusal happened **without unbounded work**. That is asserted
//!     structurally rather than by measuring memory: a body forty times the limit
//!     must be refused with `PAYLOAD_TOO_LARGE` rather than with a parse error,
//!     because a parse error would mean the whole document was buffered and handed
//!     to serde before anybody objected.
//!
//! The observed limits are pinned as constants so that a configuration change that
//! loosens one is a test failure rather than a silent widening.

use axum::http::{header, Method, StatusCode};
use serde_json::json;

use crate::common::TestApp;
use crate::world::{self, World};

/// `LimitsConfig::max_body_bytes` in the test configuration.
const MAX_BODY_BYTES: usize = 262_144;
/// `shared::pagination::MAX_PAGE_SIZE`, and the ceiling the test config sets.
const MAX_PAGE_SIZE: u32 = 100;
/// `modules::outbox::idempotency::MAX_KEY_LEN`.
const MAX_IDEMPOTENCY_KEY_LEN: usize = 200;
/// The bound `extract::bearer_from` applies before it parses anything.
const MAX_AUTHORIZATION_HEADER_LEN: usize = 512;

/// The service is still healthy. Called after every abusive probe.
async fn assert_still_serving(app: &TestApp, context: &str) {
    let live = app.get("/health/live", None).await;
    assert_eq!(
        live.status,
        StatusCode::OK,
        "{context}: the service stopped serving after the probe"
    );
}

#[tokio::test]
async fn an_oversized_body_is_refused_at_the_transport() {
    let w = World::build().await;
    let before = world::snapshot(&w.app).await;

    // Just under the limit: accepted by the transport, so the refusal is about the
    // content. This is the control that fixes where the boundary actually is.
    let filler = "a".repeat(MAX_BODY_BYTES - 1024);
    let under = w
        .app
        .post(
            "/api/v1/auth/login",
            None,
            json!({"email": "a@b.test", "password": filler}),
        )
        .await;
    assert_ne!(
        under.status,
        StatusCode::PAYLOAD_TOO_LARGE,
        "a body under the limit was refused as too large"
    );

    // At and beyond the limit, in increasing multiples. The largest is forty times
    // the ceiling: if that produced a parse error rather than `413`, the document
    // would have been buffered first.
    for multiple in [1usize, 2, 10, 40] {
        let oversized = vec![b'a'; MAX_BODY_BYTES * multiple + 1];
        let mut body = Vec::with_capacity(oversized.len() + 64);
        body.extend_from_slice(br#"{"email":"a@b.test","password":""#);
        body.extend_from_slice(&oversized);
        body.extend_from_slice(br#""}"#);

        let response = w
            .app
            .request(world::raw_request(
                Method::POST,
                "/api/v1/auth/login",
                None,
                Some("application/json"),
                &[],
                body,
            ))
            .await;
        response.assert_error(StatusCode::PAYLOAD_TOO_LARGE, "PAYLOAD_TOO_LARGE");
        assert_still_serving(&w.app, &format!("{multiple}x the body limit")).await;
    }

    assert_eq!(
        before,
        world::snapshot(&w.app).await,
        "an oversized body changed state"
    );
}

/// Deeply nested and structurally malformed JSON must be refused by the parser
/// without exhausting the stack.
///
/// A recursive-descent parser with no depth bound turns a 50 KB document into a
/// stack overflow, and a stack overflow in Rust aborts the process — it is not a
/// catchable panic, so `CatchPanicLayer` would not save it.
#[tokio::test]
async fn deeply_nested_and_malformed_json_is_refused_without_exhausting_the_stack() {
    let w = World::build().await;

    let cases: Vec<(&str, Vec<u8>)> = vec![
        (
            "100k nested arrays",
            format!("{}{}", "[".repeat(100_000), "]".repeat(100_000)).into_bytes(),
        ),
        ("100k unclosed arrays", "[".repeat(100_000).into_bytes()),
        (
            "40k nested objects",
            format!("{}1{}", "{\"a\":".repeat(40_000), "}".repeat(40_000)).into_bytes(),
        ),
        (
            "nesting inside a legitimate field",
            format!(
                r#"{{"email":"a@b.test","password":{}"x"{}}}"#,
                "[".repeat(50_000),
                "]".repeat(50_000)
            )
            .into_bytes(),
        ),
        ("truncated document", br#"{"email":"a@b.test""#.to_vec()),
        ("bare scalar", b"1".to_vec()),
        ("empty body", Vec::new()),
        ("json null", b"null".to_vec()),
        ("array at the top level", b"[1,2,3]".to_vec()),
        ("nan", b"{\"email\":NaN}".to_vec()),
        (
            "trailing garbage",
            br#"{"email":"a@b.test"} DROP TABLE users"#.to_vec(),
        ),
        ("duplicated closing braces", b"{}}}}}}}}}}".to_vec()),
    ];

    for (name, body) in cases {
        assert!(
            body.len() <= MAX_BODY_BYTES,
            "{name} is larger than the body limit, so it would test the wrong control"
        );
        let response = w
            .app
            .request(world::raw_request(
                Method::POST,
                "/api/v1/auth/login",
                None,
                Some("application/json"),
                &[],
                body,
            ))
            .await;
        assert_eq!(
            response.status,
            StatusCode::BAD_REQUEST,
            "{name}: expected a 400, got {} with {}",
            response.status,
            String::from_utf8_lossy(&response.raw)
        );
        assert_eq!(
            response.error_code(),
            Some("BAD_REQUEST"),
            "{name}: wrong code"
        );
        assert_still_serving(&w.app, name).await;
    }
}

/// A huge array and a huge string inside an otherwise well-formed body.
///
/// These fit under the transport limit, so the transport cannot help. The bound has
/// to come from validation, and it has to arrive before the values are used.
#[tokio::test]
async fn oversized_collections_and_strings_are_refused_by_validation() {
    let w = World::build().await;
    let before = world::snapshot(&w.app).await;
    let root = w.root.bearer();

    // ~5 000 UUIDs, comfortably inside the 256 KiB body limit and fifty times the
    // 100-element array bound.
    let many_roles: Vec<String> = (0..5_000)
        .map(|_| uuid::Uuid::now_v7().to_string())
        .collect();
    w.app
        .post(
            "/api/v1/invitations",
            root,
            json!({
                "email": "bulk@hardening.test",
                "display_name": "Bulk",
                "principal_type": "INTERNAL",
                "role_ids": many_roles
            }),
        )
        .await
        .assert_error(StatusCode::BAD_REQUEST, "VALIDATION_FAILED");

    // A huge string in every text field that takes one.
    let huge = "a".repeat(200_000);
    let probes = vec![
        (
            "/api/v1/invitations".to_string(),
            json!({"email": huge, "display_name": "x", "principal_type": "INTERNAL"}),
        ),
        (
            "/api/v1/invitations".to_string(),
            json!({"email": "a@b.test", "display_name": huge, "principal_type": "INTERNAL"}),
        ),
        (
            "/api/v1/departments".to_string(),
            json!({"code": huge, "name": "x"}),
        ),
        (
            "/api/v1/departments".to_string(),
            json!({"code": "probe", "name": huge}),
        ),
        (
            "/api/v1/departments".to_string(),
            json!({"code": "probe", "name": "x", "description": huge}),
        ),
        (
            "/api/v1/roles".to_string(),
            json!({"code": huge, "name": "x", "allowed_principal_type": "INTERNAL"}),
        ),
        (
            "/api/v1/tasks".to_string(),
            json!({"project_id": w.project, "title": huge}),
        ),
        (
            "/api/v1/tasks".to_string(),
            json!({"project_id": w.project, "title": "x", "internal_note": huge}),
        ),
    ];
    for (path, body) in probes {
        let response = w.app.post(&path, root, body).await;
        response.assert_error(StatusCode::BAD_REQUEST, "VALIDATION_FAILED");
        let text = String::from_utf8_lossy(&response.raw);
        assert!(
            text.len() < 4_000,
            "{path}: the refusal echoed the oversized value back ({} bytes)",
            text.len()
        );
    }

    // A huge *key* rather than a huge value: `deny_unknown_fields` must reject it
    // without the key ever becoming a lookup.
    let body = format!(r#"{{"{}":"x","email":"a@b.test"}}"#, "k".repeat(100_000));
    w.app
        .request(world::raw_request(
            Method::POST,
            "/api/v1/auth/login",
            None,
            Some("application/json"),
            &[],
            body.into_bytes(),
        ))
        .await
        .assert_error(StatusCode::BAD_REQUEST, "BAD_REQUEST");

    assert_eq!(
        before,
        world::snapshot(&w.app).await,
        "an oversized-collection probe changed state"
    );
    assert_still_serving(&w.app, "oversized collections").await;
}

/// Pagination is the classic amplification surface: one integer decides how much
/// work the database does.
#[tokio::test]
async fn pagination_parameters_are_bounded_at_both_ends() {
    let w = World::build().await;
    let root = w.root.bearer();

    // Endpoints reached through each of the three query extractors in use, so the
    // bound is proven on all of them rather than on one.
    let listings = [
        "/api/v1/users",
        "/api/v1/projects",
        "/api/v1/tasks",
        "/api/v1/departments",
        "/api/v1/clients",
        "/api/v1/roles",
        "/api/v1/audit/events",
    ];

    let refused_limits = [
        "0",
        "-1",
        "101",
        "1000",
        "999999999",
        "9223372036854775807",
        "18446744073709551616",
        "1e9",
        "0x64",
        "abc",
        " ",
        "1.5",
        "١٠٠", // Arabic-Indic digits: `str::parse` must not accept them
    ];
    // `+1` is deliberately absent from that list. `str::parse::<u32>` accepts a
    // leading `+`, so `?limit=+1` resolves to 1 — lenient, but still a value inside
    // the bound, so it is an acceptance rather than a hole. Recorded in the report
    // as INFO rather than asserted as a refusal, because asserting the current
    // behaviour either way would pin an accident.
    for path in listings {
        for limit in refused_limits {
            let response = w
                .app
                .get(&format!("{path}?limit={}", urlencode(limit)), root)
                .await;
            response.assert_error(StatusCode::BAD_REQUEST, "VALIDATION_FAILED");
        }
        // The ceiling itself is accepted, which fixes where the boundary is.
        let ok = w
            .app
            .get(&format!("{path}?limit={MAX_PAGE_SIZE}"), root)
            .await;
        assert!(
            ok.status.is_success(),
            "{path}: the documented maximum page size was refused: {}",
            String::from_utf8_lossy(&ok.raw)
        );
        // And a page never returns more than it promised.
        let items = ok
            .json()
            .get("items")
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        assert!(
            items <= MAX_PAGE_SIZE as usize,
            "{path} returned {items} items for a limit of {MAX_PAGE_SIZE}"
        );
    }

    // Cursors are bounded before they are decoded, so an unbounded base64 blob is
    // never work the server does.
    // 60 000 characters rather than more: `http::Uri` refuses a URI at 64 KiB with
    // `InvalidUri(TooLong)`, so a larger probe would be rejected by the client-side
    // builder and would never reach the server. That transport ceiling is itself a
    // bound worth recording, and it sits *below* anything the application does.
    for cursor in [
        "!!!".to_string(),
        "A".repeat(65),
        "A".repeat(60_000),
        "../../etc/passwd".to_string(),
        data_encoding::BASE64URL_NOPAD.encode(&[0u8; 23]),
        data_encoding::BASE64URL_NOPAD.encode(&[0u8; 4096]),
    ] {
        w.app
            .get(
                &format!("/api/v1/users?cursor={}", urlencode(&cursor)),
                root,
            )
            .await
            .assert_error(StatusCode::BAD_REQUEST, "VALIDATION_FAILED");
    }

    // There is no offset pagination to abuse — `OFFSET 100000` makes PostgreSQL
    // walk and discard a hundred thousand rows, which is the amplification cursors
    // exist to remove. If an `offset` parameter ever appears, this fails.
    for path in ["/api/v1/users", "/api/v1/departments", "/api/v1/projects"] {
        w.app
            .get(&format!("{path}?offset=1000000"), root)
            .await
            .assert_error(StatusCode::BAD_REQUEST, "BAD_REQUEST");
    }

    assert_still_serving(&w.app, "pagination").await;
}

/// Headers a caller controls, at sizes a caller chooses.
#[tokio::test]
async fn oversized_headers_are_refused_or_ignored_without_work() {
    let w = World::build().await;

    // An `Idempotency-Key` past its bound is a field error, not a silent discard:
    // discarding it would hand the client a non-idempotent request it believes is
    // idempotent.
    for length in [MAX_IDEMPOTENCY_KEY_LEN + 1, 1_000, 100_000] {
        let response = w
            .app
            .request(world::raw_request(
                Method::POST,
                "/api/v1/departments",
                w.root.bearer(),
                Some("application/json"),
                &[("idempotency-key", &"k".repeat(length))],
                br#"{"code":"probe","name":"Probe"}"#.to_vec(),
            ))
            .await;
        response.assert_error(StatusCode::BAD_REQUEST, "VALIDATION_FAILED");
        assert_eq!(
            response
                .json()
                .pointer("/errors/0/code")
                .and_then(|v| v.as_str()),
            Some("TOO_LONG"),
            "a {length}-character idempotency key produced the wrong field code"
        );
    }
    // The bound itself is accepted, so the refusals above are about the excess.
    let at_bound = w
        .app
        .request(world::raw_request(
            Method::POST,
            "/api/v1/departments",
            w.root.bearer(),
            Some("application/json"),
            &[("idempotency-key", &"k".repeat(MAX_IDEMPOTENCY_KEY_LEN))],
            br#"{"code":"idem_probe","name":"Probe"}"#.to_vec(),
        ))
        .await;
    assert_ne!(
        at_bound.error_code(),
        Some("VALIDATION_FAILED"),
        "a key at exactly the maximum length was refused"
    );

    // An oversized bearer header is refused before it is parsed, and is
    // indistinguishable from any other authentication failure.
    for length in [MAX_AUTHORIZATION_HEADER_LEN, 10_000, 1_000_000] {
        let response = w
            .app
            .request(world::raw_request(
                Method::GET,
                "/api/v1/system/info",
                Some(&"a".repeat(length)),
                None,
                &[],
                Vec::new(),
            ))
            .await;
        response.assert_error(StatusCode::UNAUTHORIZED, "AUTHENTICATION_FAILED");
    }

    // A huge correlation id is ignored, not adopted, and not echoed.
    let mut request = world::raw_request(Method::GET, "/health/live", None, None, &[], Vec::new());
    request.headers_mut().insert(
        "x-request-id",
        header::HeaderValue::from_str(&"a".repeat(200_000)).expect("an ASCII header"),
    );
    let response = w.app.request(request).await;
    assert_eq!(response.status, StatusCode::OK);
    let echoed = response
        .headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        echoed.len() <= 64,
        "a {}-character correlation id was echoed",
        echoed.len()
    );

    assert_still_serving(&w.app, "oversized headers").await;
}

/// The content-type gate, and what happens to bytes that are not text at all.
#[tokio::test]
async fn unsupported_media_types_and_invalid_utf8_are_refused() {
    let w = World::build().await;

    for content_type in [
        "text/plain",
        "application/x-www-form-urlencoded",
        "multipart/form-data; boundary=x",
        "application/xml",
        "application/json-patch+json",
        "application/JSON5",
        "text/json",
        "",
        "application/json/../../x",
        "application/octet-stream",
    ] {
        let response = w
            .app
            .request(world::raw_request(
                Method::POST,
                "/api/v1/auth/login",
                None,
                Some(content_type),
                &[],
                br#"{"email":"a@b.test","password":"x"}"#.to_vec(),
            ))
            .await;
        response.assert_error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "UNSUPPORTED_MEDIA_TYPE");
    }

    // A missing content type is refused too — the gate is an allowlist, not a
    // denylist.
    w.app
        .request(world::raw_request(
            Method::POST,
            "/api/v1/auth/login",
            None,
            None,
            &[],
            br#"{"email":"a@b.test","password":"x"}"#.to_vec(),
        ))
        .await
        .assert_error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "UNSUPPORTED_MEDIA_TYPE");

    // A parameterised, correctly-cased content type is accepted, which is the
    // control for the refusals above.
    let ok = w
        .app
        .request(world::raw_request(
            Method::POST,
            "/api/v1/auth/login",
            None,
            Some("application/json; charset=utf-8"),
            &[],
            br#"{"email":"a@b.test","password":"x"}"#.to_vec(),
        ))
        .await;
    assert_ne!(ok.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);

    // Bytes that are not UTF-8 at all, inside an otherwise well-formed document.
    let mut body = br#"{"email":"a@b.test","password":""#.to_vec();
    body.extend_from_slice(&[0xff, 0xfe, 0x80, 0x81, 0xc0, 0xaf]);
    body.extend_from_slice(br#""}"#);
    w.app
        .request(world::raw_request(
            Method::POST,
            "/api/v1/auth/login",
            None,
            Some("application/json"),
            &[],
            body,
        ))
        .await
        .assert_error(StatusCode::BAD_REQUEST, "BAD_REQUEST");

    // A lone surrogate escape: valid JSON syntax, not a valid Rust `String`.
    w.app
        .request(world::raw_request(
            Method::POST,
            "/api/v1/auth/login",
            None,
            Some("application/json"),
            &[],
            br#"{"email":"\ud800","password":"x"}"#.to_vec(),
        ))
        .await
        .assert_error(StatusCode::BAD_REQUEST, "BAD_REQUEST");

    // Non-UTF-8 in the path, percent-encoded so it survives the URL.
    let response = w
        .app
        .get("/api/v1/departments/%FF%FE%80", w.root.bearer())
        .await;
    response.assert_error(StatusCode::BAD_REQUEST, "VALIDATION_FAILED");

    assert_still_serving(&w.app, "media types").await;
}

/// The refusals must not be a way to make the server do unbounded work *for* the
/// attacker: a rejected request must leave no trace it could accumulate.
#[tokio::test]
async fn refused_requests_accumulate_no_state() {
    let w = World::build().await;
    let before = world::snapshot(&w.app).await;

    for _ in 0..50 {
        let _ = w
            .app
            .request(world::raw_request(
                Method::POST,
                "/api/v1/departments",
                w.root.bearer(),
                Some("application/json"),
                &[("idempotency-key", &"k".repeat(400))],
                br#"{"code":"probe","name":"Probe","is_root":true}"#.to_vec(),
            ))
            .await;
        let _ = w
            .app
            .request(world::raw_request(
                Method::POST,
                "/api/v1/auth/login",
                None,
                Some("text/plain"),
                &[],
                vec![b'a'; 1024],
            ))
            .await;
    }

    assert_eq!(
        before,
        world::snapshot(&w.app).await,
        "refused requests left rows behind — in particular no idempotency record \
         may be reserved for a request that never parsed"
    );
    assert_still_serving(&w.app, "repeated refusals").await;
}

fn urlencode(value: &str) -> String {
    let mut out = String::with_capacity(value.len() * 3);
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}
