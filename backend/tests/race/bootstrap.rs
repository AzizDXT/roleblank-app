//! Concurrency: the first-run bootstrap race.
//!
//! Brief §72 requires this to be *executed*, not reasoned about. If two requests
//! can both observe an uninitialised system and both create an owner, the system
//! has two owners and the invariant that everything else rests on is gone.
//!
//! The defence is layered: a transaction-scoped advisory lock serialises the
//! attempts, a re-check inside the transaction closes the check-then-act window,
//! and the singleton primary key on `system_ownership` makes a second row
//! impossible even if both of those failed.

use std::sync::Arc;

use axum::http::StatusCode;
use serde_json::json;

use crate::common::{TestApp, TEST_BOOTSTRAP_SECRET, TEST_PASSWORD};

fn body(n: usize) -> serde_json::Value {
    json!({
        "bootstrap_secret": TEST_BOOTSTRAP_SECRET,
        "email": format!("owner{n}@race.test"),
        "display_name": format!("Owner {n}"),
        "password": TEST_PASSWORD,
    })
}

/// 100 concurrent attempts. Exactly one may succeed.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn one_hundred_concurrent_bootstraps_produce_exactly_one_owner() {
    const ATTEMPTS: usize = 100;

    let app = Arc::new(TestApp::spawn().await);

    // A barrier so the requests are genuinely simultaneous rather than merely
    // spawned in a loop — without it the first would usually finish before the
    // last starts, and the test would pass without ever exercising the race.
    let tally = {
        let app = app.clone();
        crate::fixtures::race(ATTEMPTS, move |n| {
            let app = app.clone();
            async move { app.post("/api/v1/bootstrap/root", None, body(n)).await }
        })
        .await
    };
    tally.report("bootstrap_root x100");

    // A hundred simultaneous bootstrap attempts must never produce a server error:
    // the endpoint is anonymous internet-facing surface, and a 5xx here is the
    // system telling an attacker it reached a state it did not anticipate.
    assert_eq!(
        tally.server_errors(),
        0,
        "concurrent bootstrap produced server errors: {:?}",
        tally.by_status
    );

    let created = tally.status(StatusCode::CREATED) + tally.status(StatusCode::OK);
    // Two legitimate ways to lose, and both are correct behaviour:
    //   409 — another attempt got there first
    //   429 — the per-IP bootstrap limit (5/hour) refused it before it even
    //         reached the transaction. A hundred simultaneous bootstrap attempts
    //         from one address *is* an attack, and the limiter treating it as one
    //         is the point.
    let refused = tally.status(StatusCode::CONFLICT) + tally.status(StatusCode::TOO_MANY_REQUESTS);

    assert_eq!(
        created, 1,
        "exactly one bootstrap must succeed (got {created}) — {:?}",
        tally.by_status
    );
    assert!(
        tally
            .unexpected(&[
                StatusCode::CREATED,
                StatusCode::OK,
                StatusCode::CONFLICT,
                StatusCode::TOO_MANY_REQUESTS,
            ])
            .is_empty(),
        "every losing attempt must be a clean 409 or 429, got: {:?}",
        tally.by_status
    );
    assert_eq!(refused, ATTEMPTS - 1);

    // The database is the real arbiter.
    let owners: (i64,) = sqlx::query_as("SELECT count(*) FROM system_ownership")
        .fetch_one(&app.db)
        .await
        .expect("count owners");
    assert_eq!(
        owners.0, 1,
        "the database holds {} ownership rows",
        owners.0
    );

    let users: (i64,) = sqlx::query_as("SELECT count(*) FROM users")
        .fetch_one(&app.db)
        .await
        .expect("count users");
    assert_eq!(
        users.0, 1,
        "a losing attempt left a user behind — its transaction did not roll back cleanly"
    );

    let initialised: (bool,) =
        sqlx::query_as("SELECT initialized_at IS NOT NULL FROM system_state WHERE id")
            .fetch_one(&app.db)
            .await
            .expect("read system state");
    assert!(initialised.0);
}

/// After initialisation the endpoint is permanently closed, and says so with a
/// stable code rather than a generic failure.
#[tokio::test]
async fn bootstrap_is_permanently_closed_after_the_first_success() {
    let app = TestApp::spawn().await;

    app.post("/api/v1/bootstrap/root", None, body(1))
        .await
        .assert_status(StatusCode::CREATED);

    for attempt in 2..=5 {
        app.post("/api/v1/bootstrap/root", None, body(attempt))
            .await
            .assert_error(StatusCode::CONFLICT, "SYSTEM_ALREADY_INITIALIZED");
    }

    let owners: (i64,) = sqlx::query_as("SELECT count(*) FROM system_ownership")
        .fetch_one(&app.db)
        .await
        .expect("count");
    assert_eq!(owners.0, 1);
}

/// A wrong secret must not initialise anything, and must not reveal whether the
/// system is initialisable — the status endpoint is the only thing that says that,
/// and it says only a boolean.
#[tokio::test]
async fn a_wrong_bootstrap_secret_creates_nothing() {
    let app = TestApp::spawn().await;

    // Deliberately fewer attempts than the per-IP bootstrap quota (5/hour), so the
    // test measures the secret check rather than the rate limiter. That the quota
    // then refuses further attempts is asserted separately below.
    for wrong in [
        "",
        TEST_BOOTSTRAP_SECRET.to_uppercase().as_str(),
        &TEST_BOOTSTRAP_SECRET[..TEST_BOOTSTRAP_SECRET.len() - 1],
    ] {
        let response = app
            .post(
                "/api/v1/bootstrap/root",
                None,
                json!({
                    "bootstrap_secret": wrong,
                    "email": "attacker@race.test",
                    "display_name": "Attacker",
                    "password": TEST_PASSWORD,
                }),
            )
            .await;
        assert!(
            response.status.is_client_error(),
            "a wrong secret was accepted: {}",
            String::from_utf8_lossy(&response.raw)
        );
        response.assert_no_secrets();
    }

    let users: (i64,) = sqlx::query_as("SELECT count(*) FROM users")
        .fetch_one(&app.db)
        .await
        .expect("count");
    assert_eq!(users.0, 0, "a rejected bootstrap left a user behind");

    // Still initialisable with the correct secret afterwards — a wrong guess must
    // not brick the installation.
    app.post("/api/v1/bootstrap/root", None, body(1))
        .await
        .assert_status(StatusCode::CREATED);
}

/// Guessing the bootstrap secret must be rate limited, not merely rejected.
///
/// Without this the secret's entropy is the only defence against an offline-speed
/// online guessing attack against the most consequential endpoint in the system.
#[tokio::test]
async fn repeated_bootstrap_guesses_are_rate_limited() {
    let app = TestApp::spawn().await;

    let mut limited = false;
    for attempt in 0..12 {
        let response = app
            .post(
                "/api/v1/bootstrap/root",
                None,
                json!({
                    "bootstrap_secret": format!("guess-number-{attempt}-padded-to-length-0123456789"),
                    "email": "attacker@race.test",
                    "display_name": "Attacker",
                    "password": TEST_PASSWORD,
                }),
            )
            .await;
        if response.status == StatusCode::TOO_MANY_REQUESTS {
            limited = true;
            assert!(
                response
                    .headers
                    .contains_key(axum::http::header::RETRY_AFTER),
                "a 429 must tell the caller when to retry"
            );
            break;
        }
    }
    assert!(
        limited,
        "twelve bootstrap guesses were accepted without any rate limiting"
    );

    let users: (i64,) = sqlx::query_as("SELECT count(*) FROM users")
        .fetch_one(&app.db)
        .await
        .expect("count");
    assert_eq!(users.0, 0);
}

/// The status endpoint is reachable by anonymous internet, so it must reveal
/// nothing beyond a single boolean.
#[tokio::test]
async fn the_status_endpoint_reveals_only_a_boolean() {
    let app = TestApp::spawn().await;

    let before = app.get("/api/v1/bootstrap/status", None).await;
    before.assert_status(StatusCode::OK);
    assert_eq!(before.json(), &json!({"initialized": false}));

    app.post("/api/v1/bootstrap/root", None, body(1))
        .await
        .assert_status(StatusCode::CREATED);

    let after = app.get("/api/v1/bootstrap/status", None).await;
    after.assert_status(StatusCode::OK);
    assert_eq!(
        after.json(),
        &json!({"initialized": true}),
        "the status endpoint must not grow additional fields — it is anonymous surface"
    );
}

/// The owner is created into the MFA-enrolment-required state, and is protected
/// from the moment it exists.
#[tokio::test]
async fn the_owner_is_created_in_the_correct_initial_state() {
    let app = TestApp::spawn().await;

    let created = app.post("/api/v1/bootstrap/root", None, body(1)).await;
    created
        .assert_status(StatusCode::CREATED)
        .assert_no_secrets();

    let row: (String, String, bool, bool) = sqlx::query_as(
        "SELECT u.status, u.principal_type, u.mfa_required, u.mfa_enrolled
           FROM users u JOIN system_ownership o ON o.root_user_id = u.id",
    )
    .fetch_one(&app.db)
    .await
    .expect("owner row");

    assert_eq!(row.0, "ACTIVE");
    assert_eq!(row.1, "INTERNAL");
    assert!(row.2, "the owner must have mfa_required set");
    assert!(
        !row.3,
        "the owner must start un-enrolled — the MFA_ENROLMENT_REQUIRED state"
    );

    // The password must have been stored as an Argon2id PHC string, never plainly.
    let hash: (String,) = sqlx::query_as(
        "SELECT c.password_hash FROM credentials c
           JOIN system_ownership o ON o.root_user_id = c.user_id",
    )
    .fetch_one(&app.db)
    .await
    .expect("credential row");
    assert!(
        hash.0.starts_with("$argon2id$"),
        "password was not hashed with Argon2id"
    );
    assert!(!hash.0.contains(TEST_PASSWORD));
}

/// The bootstrap is audited, and the secret never reaches the audit log.
#[tokio::test]
async fn bootstrap_is_audited_without_leaking_the_secret() {
    let app = TestApp::spawn().await;
    app.post("/api/v1/bootstrap/root", None, body(1))
        .await
        .assert_status(StatusCode::CREATED);

    let events: Vec<(String, String, serde_json::Value)> =
        sqlx::query_as("SELECT action_code, outcome, metadata FROM audit_events ORDER BY seq")
            .fetch_all(&app.db)
            .await
            .expect("read audit");

    assert!(
        events
            .iter()
            .any(|(action, outcome, _)| action == "SYSTEM.BOOTSTRAPPED" && outcome == "SUCCESS"),
        "bootstrap was not audited: {events:?}"
    );

    let serialised = serde_json::to_string(&events).expect("serialise");
    assert!(
        !serialised.contains(TEST_BOOTSTRAP_SECRET),
        "the bootstrap secret reached the audit log"
    );
    assert!(
        !serialised.contains(TEST_PASSWORD),
        "the password reached the audit log"
    );
    assert!(
        !serialised.contains("$argon2"),
        "a password hash reached the audit log"
    );
}
