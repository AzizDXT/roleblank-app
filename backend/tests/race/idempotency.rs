//! Concurrency: `Idempotency-Key` on the creation endpoints.
//!
//! **Why this race is dangerous.** A client POSTs "create project", the response is
//! lost to a network blip, the client retries. Without a record of the first attempt
//! the retry either creates a second object or — when a unique index gets in the way,
//! as it does here — fails with a conflict the client cannot distinguish from "your
//! request was wrong". The mobile-network version of this is not a rare event: it is
//! what happens every time a train goes into a tunnel.
//!
//! The record is keyed on `(principal, operation, key)` and carries a fingerprint of
//! the request body. Three properties follow, and each has its own test below:
//! a repeat with the same body replays; a repeat with a *different* body is refused
//! rather than silently answered with the wrong stored response; and one principal's
//! key can never reach another's record, which would be a cross-tenant read.
//!
//! **This suite was written against an unimplemented feature.** `api/openapi.yaml`
//! documents the header on six creation endpoints and the record module existed in
//! full, but nothing read the header — so every one of those documented promises was
//! false. The wiring in `platform::http::idempotency` was added to make these pass.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use serde_json::json;
use uuid::Uuid;

use crate::common::{TestApp, TestResponse};
use crate::fixtures::{self, Actor};

const KEY: &str = "018f3a1e-6b7c-7f2a-9c31-2b4d5e6f7a8b";

async fn creator(app: &TestApp, email: &str) -> Actor {
    fixtures::actor(app, email, &["projects.create", "projects.read"]).await
}

/// A `POST` carrying an `Idempotency-Key`.
///
/// Built by hand rather than through the harness helper because the header is the
/// entire subject of this suite and the helper has no way to set one.
async fn post_with_key(
    app: &TestApp,
    path: &str,
    token: &str,
    key: Option<&str>,
    body: serde_json::Value,
) -> TestResponse {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(key) = key {
        builder = builder.header("Idempotency-Key", key);
    }
    let request = builder
        .body(Body::from(
            serde_json::to_vec(&body).expect("serialise the body"),
        ))
        .expect("build the request");
    app.request(request).await
}

fn project_body(code: &str) -> impl Fn(Uuid) -> serde_json::Value + '_ {
    move |manager| {
        json!({
            "code": code,
            "name": format!("Project {code}"),
            "manager_user_id": manager,
        })
    }
}

async fn project_count(app: &TestApp) -> i64 {
    fixtures::count(app, "SELECT count(*) FROM projects").await
}

// ===========================================================================
// The race
// ===========================================================================

/// Two simultaneous identical creates with one key: one project, two identical
/// responses.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_simultaneous_identical_posts_create_one_resource() {
    let app = Arc::new(TestApp::spawn().await);
    let actor = creator(&app, "idem@race.test").await;
    let body = project_body("idem-race")(actor.id);

    // A barrier, so both requests are inside `begin` before either has finished its
    // work. That is the case the record's `INSERT ... ON CONFLICT DO NOTHING` exists
    // for: a `SELECT`-then-`INSERT` would let both find nothing and both proceed.
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let mut handles = Vec::with_capacity(2);
    for _ in 0..2 {
        let app = app.clone();
        let barrier = barrier.clone();
        let token = actor.access_token.clone();
        let body = body.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let response = post_with_key(&app, "/api/v1/projects", &token, Some(KEY), body).await;
            (response.status, response.body.clone())
        }));
    }

    let mut responses = Vec::with_capacity(2);
    for handle in handles {
        responses.push(handle.await.expect("task must not panic"));
    }

    for (status, body) in &responses {
        assert_eq!(
            *status,
            StatusCode::CREATED,
            "both requests must be answered as creations, got {status} with {body:?}"
        );
    }
    assert_eq!(
        responses[0].1, responses[1].1,
        "the two responses differ; a client cannot tell which one is authoritative"
    );

    // The database is the arbiter.
    assert_eq!(
        project_count(&app).await,
        1,
        "the retry created a second project"
    );
    assert_eq!(
        fixtures::audit_count(&app, "PROJECT.CREATED").await,
        1,
        "the replay was audited as a second creation"
    );

    // Exactly one record, completed, holding the response that was replayed.
    let records: Vec<(String, Option<i32>)> = sqlx::query_as(
        "SELECT status, response_status FROM idempotency_records
          WHERE principal_id = $1 AND idempotency_key = $2",
    )
    .bind(actor.id)
    .bind(KEY)
    .fetch_all(&app.db)
    .await
    .expect("read the idempotency records");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].0, "COMPLETED");
    assert_eq!(records[0].1, Some(201));
}

/// Ten at once. Still one project.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn ten_simultaneous_identical_posts_create_one_resource() {
    const ATTEMPTS: usize = 10;

    let app = Arc::new(TestApp::spawn().await);
    let actor = creator(&app, "idem10@race.test").await;
    let body = project_body("idem-race-10")(actor.id);

    let barrier = Arc::new(tokio::sync::Barrier::new(ATTEMPTS));
    let mut handles = Vec::with_capacity(ATTEMPTS);
    for _ in 0..ATTEMPTS {
        let app = app.clone();
        let barrier = barrier.clone();
        let token = actor.access_token.clone();
        let body = body.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let response = post_with_key(&app, "/api/v1/projects", &token, Some(KEY), body).await;
            (response.status, response.error_code().map(str::to_string))
        }));
    }

    let mut created = 0usize;
    for handle in handles {
        let (status, code) = handle.await.expect("task must not panic");
        match status {
            StatusCode::CREATED => created += 1,
            // A duplicate that is still waiting when the window closes is a
            // conflict the client may simply retry. It must never be a
            // `UNIQUE_VIOLATION` from the project code index, which is what an
            // unguarded duplicate would produce.
            StatusCode::CONFLICT => assert_eq!(code.as_deref(), Some("IDEMPOTENCY_RACE")),
            other => panic!("a duplicate create returned {other} with code {code:?}"),
        }
    }

    assert!(created >= 1, "no request was answered");
    assert_eq!(
        project_count(&app).await,
        1,
        "{ATTEMPTS} identical creates produced more than one project"
    );
    assert_eq!(fixtures::audit_count(&app, "PROJECT.CREATED").await, 1);
}

// ===========================================================================
// Sequential replay
// ===========================================================================

#[tokio::test]
async fn a_retry_with_the_same_key_and_body_replays_the_stored_response() {
    let app = TestApp::spawn().await;
    let actor = creator(&app, "idem-seq@race.test").await;
    let body = project_body("idem-seq")(actor.id);

    let first = post_with_key(
        &app,
        "/api/v1/projects",
        &actor.access_token,
        Some(KEY),
        body.clone(),
    )
    .await;
    first.assert_status(StatusCode::CREATED).assert_no_secrets();

    for _ in 0..3 {
        let replay = post_with_key(
            &app,
            "/api/v1/projects",
            &actor.access_token,
            Some(KEY),
            body.clone(),
        )
        .await;
        replay.assert_status(StatusCode::CREATED);
        assert_eq!(
            replay.body, first.body,
            "the replay is not byte-for-byte the original response"
        );
    }

    assert_eq!(project_count(&app).await, 1);
    assert_eq!(fixtures::audit_count(&app, "PROJECT.CREATED").await, 1);
}

/// Without a key the endpoint behaves exactly as it always did: no record is
/// written, and a genuine duplicate is refused by the unique index.
#[tokio::test]
async fn a_request_without_a_key_writes_no_record() {
    let app = TestApp::spawn().await;
    let actor = creator(&app, "idem-none@race.test").await;
    let body = project_body("idem-none")(actor.id);

    post_with_key(
        &app,
        "/api/v1/projects",
        &actor.access_token,
        None,
        body.clone(),
    )
    .await
    .assert_status(StatusCode::CREATED);

    post_with_key(&app, "/api/v1/projects", &actor.access_token, None, body)
        .await
        .assert_error(StatusCode::CONFLICT, "UNIQUE_VIOLATION");

    assert_eq!(project_count(&app).await, 1);
    assert_eq!(
        fixtures::count(&app, "SELECT count(*) FROM idempotency_records").await,
        0,
        "a request with no Idempotency-Key reserved one anyway"
    );
}

// ===========================================================================
// Same key, different body
// ===========================================================================

/// A silently wrong replay is far worse than an error, so this is a hard refusal.
#[tokio::test]
async fn the_same_key_with_a_different_body_is_refused() {
    let app = TestApp::spawn().await;
    let actor = creator(&app, "idem-diff@race.test").await;

    post_with_key(
        &app,
        "/api/v1/projects",
        &actor.access_token,
        Some(KEY),
        project_body("idem-diff-a")(actor.id),
    )
    .await
    .assert_status(StatusCode::CREATED);

    let reused = post_with_key(
        &app,
        "/api/v1/projects",
        &actor.access_token,
        Some(KEY),
        project_body("idem-diff-b")(actor.id),
    )
    .await;
    reused
        .assert_error(StatusCode::CONFLICT, "IDEMPOTENCY_KEY_REUSED")
        .assert_no_secrets();

    assert_eq!(
        project_count(&app).await,
        1,
        "the second body was created despite the key being reused"
    );
    assert!(
        fixtures::count(
            &app,
            "SELECT count(*) FROM projects WHERE code = 'idem-diff-b'",
        )
        .await
            == 0
    );

    // Even a single changed character counts: the fingerprint is over the raw bytes.
    let nearly = post_with_key(
        &app,
        "/api/v1/projects",
        &actor.access_token,
        Some(KEY),
        json!({
            "code": "idem-diff-a",
            "name": "Project idem-diff-a ",
            "manager_user_id": actor.id,
        }),
    )
    .await;
    nearly.assert_error(StatusCode::CONFLICT, "IDEMPOTENCY_KEY_REUSED");
}

// ===========================================================================
// Scoping
// ===========================================================================

/// The key namespace is per principal. An unscoped one would let anybody replay
/// somebody else's response by guessing a key — a cross-tenant read dressed up as a
/// retry.
#[tokio::test]
async fn one_principals_key_does_not_touch_anothers() {
    let app = TestApp::spawn().await;
    let alice = creator(&app, "alice@idem.test").await;
    let bob = creator(&app, "bob@idem.test").await;

    let alices = post_with_key(
        &app,
        "/api/v1/projects",
        &alice.access_token,
        Some(KEY),
        project_body("idem-alice")(alice.id),
    )
    .await;
    alices.assert_status(StatusCode::CREATED);

    // The same key string, a different principal, a different body. If the namespace
    // were shared this would be `IDEMPOTENCY_KEY_REUSED`; if it were shared *and*
    // the fingerprint check were absent, Bob would receive Alice's project.
    let bobs = post_with_key(
        &app,
        "/api/v1/projects",
        &bob.access_token,
        Some(KEY),
        project_body("idem-bob")(bob.id),
    )
    .await;
    bobs.assert_status(StatusCode::CREATED);

    assert_ne!(
        bobs.id_at("/id"),
        alices.id_at("/id"),
        "Bob was handed Alice's project"
    );
    assert_eq!(bobs.str_at("/code"), "idem-bob");
    assert_eq!(project_count(&app).await, 2);

    let records: i64 = fixtures::count(
        &app,
        "SELECT count(*) FROM idempotency_records WHERE idempotency_key IS NOT NULL",
    )
    .await;
    assert_eq!(records, 2, "the two principals shared one record");

    // And Alice's own retry still replays her own response, unaffected by Bob.
    let alice_again = post_with_key(
        &app,
        "/api/v1/projects",
        &alice.access_token,
        Some(KEY),
        project_body("idem-alice")(alice.id),
    )
    .await;
    assert_eq!(alice_again.body, alices.body);
}

// ===========================================================================
// The key is released when the work does not happen
// ===========================================================================

/// A create that *fails* must not consume the key for the next 24 hours: the
/// client's corrected retry is the thing we want it to send.
#[tokio::test]
async fn a_failed_create_releases_the_key_for_a_corrected_retry() {
    let app = TestApp::spawn().await;
    let actor = creator(&app, "idem-fail@race.test").await;

    // Rejected by validation: the code does not match the column's pattern.
    let rejected = post_with_key(
        &app,
        "/api/v1/projects",
        &actor.access_token,
        Some(KEY),
        json!({
            "code": "NOT A VALID CODE",
            "name": "Doomed",
            "manager_user_id": actor.id,
        }),
    )
    .await;
    rejected.assert_error(StatusCode::BAD_REQUEST, "VALIDATION_FAILED");

    assert_eq!(project_count(&app).await, 0);
    assert_eq!(
        fixtures::count(&app, "SELECT count(*) FROM idempotency_records").await,
        0,
        "a failed create left its key reserved; the corrected retry would be refused \
         for the next 24 hours"
    );

    // The corrected retry, same key, is served normally.
    post_with_key(
        &app,
        "/api/v1/projects",
        &actor.access_token,
        Some(KEY),
        project_body("idem-fixed")(actor.id),
    )
    .await
    .assert_status(StatusCode::CREATED);
    assert_eq!(project_count(&app).await, 1);
}

// ===========================================================================
// The key itself
// ===========================================================================

/// A malformed key is rejected rather than ignored. Ignoring it would hand the
/// client a non-idempotent request it believes is idempotent.
#[tokio::test]
async fn a_malformed_key_is_rejected_rather_than_discarded() {
    let app = TestApp::spawn().await;
    let actor = creator(&app, "idem-bad@race.test").await;

    // Every value here is one the HTTP layer will happily carry, so the refusal
    // comes from the key's own validation rather than from the header parser. A
    // control character such as `\u{7f}` is rejected by `http` itself and so cannot
    // reach the endpoint at all; the tab below is the case that can.
    for bad in [
        "short",             // below the 8-character floor
        "has a space in it", // a leading or trailing one is invisible in a log
        "abcd1234\tmore",    // a control character `http` does allow through
        &"k".repeat(201),    // past the column's bound
    ] {
        let response = post_with_key(
            &app,
            "/api/v1/projects",
            &actor.access_token,
            Some(bad),
            project_body("idem-bad")(actor.id),
        )
        .await;
        assert_eq!(
            response.status,
            StatusCode::BAD_REQUEST,
            "key {bad:?} was accepted"
        );
        assert_eq!(response.error_code(), Some("VALIDATION_FAILED"));
        // A validation message that quoted the key back would make the endpoint a
        // reflection gadget.
        assert!(
            !String::from_utf8_lossy(&response.raw).contains(bad),
            "the rejected key was echoed back"
        );
    }

    // A header that is not valid UTF-8 at all. `http` carries arbitrary bytes in a
    // header value, so this reaches the extractor and has to be refused there rather
    // than being silently dropped — a discarded key would leave the client believing
    // its retry was deduplicated when it was not.
    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/projects")
        .header(
            header::AUTHORIZATION,
            format!("Bearer {}", actor.access_token),
        )
        .header(header::CONTENT_TYPE, "application/json")
        .header(
            "Idempotency-Key",
            axum::http::HeaderValue::from_bytes(b"abcd1234\xff\xfe").expect("a byte header"),
        )
        .body(Body::from(
            serde_json::to_vec(&project_body("idem-bad")(actor.id)).expect("serialise"),
        ))
        .expect("build the request");
    app.request(request)
        .await
        .assert_error(StatusCode::BAD_REQUEST, "VALIDATION_FAILED");

    assert_eq!(project_count(&app).await, 0);
}

/// The header is honoured on more than one endpoint, and the operations are scoped
/// separately — the same key on two different endpoints is two records, not a
/// collision.
#[tokio::test]
async fn the_key_is_scoped_by_operation_as_well_as_by_principal() {
    let app = TestApp::spawn().await;
    let actor = fixtures::actor(
        &app,
        "idem-ops@race.test",
        &[
            "projects.create",
            "projects.read",
            "tasks.create",
            "tasks.read",
        ],
    )
    .await;

    let project = post_with_key(
        &app,
        "/api/v1/projects",
        &actor.access_token,
        Some(KEY),
        project_body("idem-ops")(actor.id),
    )
    .await;
    project.assert_status(StatusCode::CREATED);
    let project_id = project.id_at("/id");

    // The same key, a different operation, a different body. Scoped by operation, so
    // this is a fresh reservation rather than a reuse.
    let task = post_with_key(
        &app,
        "/api/v1/tasks",
        &actor.access_token,
        Some(KEY),
        json!({ "project_id": project_id, "title": "First task" }),
    )
    .await;
    task.assert_status(StatusCode::CREATED);

    // And the task create is itself idempotent.
    let replay = post_with_key(
        &app,
        "/api/v1/tasks",
        &actor.access_token,
        Some(KEY),
        json!({ "project_id": project_id, "title": "First task" }),
    )
    .await;
    assert_eq!(replay.body, task.body);
    assert_eq!(
        fixtures::count(&app, "SELECT count(*) FROM tasks").await,
        1,
        "the retried task create produced a duplicate"
    );

    let operations: Vec<(String,)> =
        sqlx::query_as("SELECT operation FROM idempotency_records ORDER BY operation")
            .fetch_all(&app.db)
            .await
            .expect("read the records");
    assert_eq!(
        operations
            .iter()
            .map(|o| o.0.as_str())
            .collect::<Vec<&str>>(),
        vec!["projects.create", "tasks.create"]
    );
}
