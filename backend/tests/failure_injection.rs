//! What happens when things break.
//!
//! Every other suite asks whether the system does the right thing when the world
//! behaves. This one asks what it does when the world does not: the database goes
//! away mid-flight, a transaction fails after it has already written, two writers
//! collide on a unique index, and the process is handed a key it cannot use.
//!
//! The property under test is the same in every case and it is a *security*
//! property, not a robustness one. A failure must produce an honest, bounded,
//! non-leaking answer. The three ways that goes wrong are: a panic (which drops the
//! connection and hides the defect), a `500` carrying driver text (which hands an
//! attacker the connection string, the failing SQL and the column names), and a
//! partial commit (which leaves the database in a state no code path believes is
//! possible).
//!
//! Real failures are used wherever the harness allows one: the pool is genuinely
//! closed, the unique index genuinely fires, the key ring is genuinely handed a
//! short key. Nothing here is a mock.

mod common;

#[path = "race/fixtures.rs"]
mod fixtures;

use std::sync::Arc;

use axum::http::StatusCode;
use serde_json::json;
use uuid::Uuid;

use roleblank_backend::platform::crypto::aead::KeyRing;
use roleblank_backend::platform::crypto::password::{Argon2Params, Hasher};
use roleblank_backend::shared::secret::Secret;

use common::{TestApp, TEST_PASSWORD};

// ===========================================================================
// The database goes away mid-flight
// ===========================================================================

/// Closing the pool is the closest a test can get to a database that has genuinely
/// gone: every subsequent acquisition fails with `PoolClosed`, which is what a
/// connection to a failed-over primary looks like from inside the driver.
///
/// The required answer is `503 SERVICE_UNAVAILABLE` — "retry shortly" — not `500`,
/// which tells a client its request was wrong, and certainly not a panic, which
/// drops the connection and makes the outage look like a network fault.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unreachable_database_answers_503_rather_than_panicking() {
    let app = TestApp::spawn().await;
    let actor = fixtures::actor(&app, "outage@failure.test", &["projects.read"]).await;

    // Healthy first, so the failure below is attributable to the closure.
    app.get("/api/v1/projects", Some(&actor.access_token))
        .await
        .assert_status(StatusCode::OK);
    app.get("/health/ready", None)
        .await
        .assert_status(StatusCode::OK);

    app.db.close().await;

    // An authenticated read: the failure happens in the extractor, before any
    // handler runs.
    let read = app.get("/api/v1/projects", Some(&actor.access_token)).await;
    read.assert_error(StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE")
        .assert_no_secrets();

    // An anonymous write: the failure happens inside a service, in `begin`.
    let write = app
        .post(
            "/api/v1/auth/login",
            None,
            json!({"email": actor.email, "password": TEST_PASSWORD}),
        )
        .await;
    assert!(
        write.status.is_server_error(),
        "a login against a dead database returned {}",
        write.status
    );
    write.assert_no_secrets();

    // Readiness must report the outage rather than claiming health.
    let ready = app.get("/health/ready", None).await;
    assert!(
        ready.status.is_server_error(),
        "readiness reported healthy against a closed pool: {}",
        ready.status
    );

    // Liveness is deliberately independent of the database: a dependency outage must
    // not get the process killed and restarted into the same outage.
    app.get("/health/live", None)
        .await
        .assert_status(StatusCode::OK);
}

/// The outage must not leak, and must not accumulate. Fifty requests against a dead
/// pool return fifty bounded errors, not a hang, a panic, or a growing queue.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dead_pool_produces_bounded_errors_rather_than_a_leak() {
    let app = Arc::new(TestApp::spawn().await);
    let actor = fixtures::actor(&app, "flood@failure.test", &["projects.read"]).await;
    app.db.close().await;

    let barrier = Arc::new(tokio::sync::Barrier::new(50));
    let mut handles = Vec::with_capacity(50);
    for _ in 0..50 {
        let app = app.clone();
        let barrier = barrier.clone();
        let token = actor.access_token.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let response = app.get("/api/v1/projects", Some(&token)).await;
            (
                response.status,
                response.error_code().map(str::to_string),
                response.raw,
            )
        }));
    }

    for handle in handles {
        let (status, code, raw) = tokio::time::timeout(std::time::Duration::from_secs(20), handle)
            .await
            .expect("a request against a dead pool hung rather than failing")
            .expect("no request may panic — a panic drops the connection and hides the fault");

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(code.as_deref(), Some("SERVICE_UNAVAILABLE"));

        // The driver's own message carries the connection string, the failing SQL
        // and the column names. None of it may reach the client.
        let text = String::from_utf8_lossy(&raw).to_lowercase();
        for forbidden in ["postgres://", "dev_app_pw", "sqlx", "select ", "panicked"] {
            assert!(
                !text.contains(forbidden),
                "the outage response leaked `{forbidden}`: {text}"
            );
        }
    }
}

// ===========================================================================
// A transaction that fails part-way
// ===========================================================================

/// A password reset writes three things in one transaction: it consumes the token,
/// it replaces the hash, and it revokes every session. If a later step fails, the
/// earlier ones must vanish — and the one that matters most is the *token*. A token
/// left consumed by a reset that did not happen locks the user out of their own
/// recovery: their link is spent, their password is unchanged, and the only way back
/// is another request they may not be able to make.
///
/// The failure is injected by removing the credentials row, so `update_password`
/// affects no rows and the service refuses. That is a real, reachable inconsistency
/// — an account whose credentials were deleted out from under it — rather than a
/// stubbed error.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_transaction_that_fails_part_way_leaves_no_partial_state() {
    let app = TestApp::spawn().await;
    let actor = fixtures::actor(&app, "partial@failure.test", &[]).await;

    app.post(
        "/api/v1/auth/password-reset/request",
        None,
        json!({ "email": actor.email }),
    )
    .await
    .assert_status(StatusCode::ACCEPTED);
    let token = fixtures::queued_reset_token(&app).await;

    sqlx::query("DELETE FROM credentials WHERE user_id = $1")
        .bind(actor.id)
        .execute(&app.db)
        .await
        .expect("remove the credentials row");

    let confirmed = app
        .post(
            "/api/v1/auth/password-reset/confirm",
            None,
            json!({"token": &token, "new_password": "a replacement passphrase 5512"}),
        )
        .await;
    assert!(
        confirmed.status.is_server_error(),
        "the broken account produced {} rather than an internal error",
        confirmed.status
    );
    confirmed.assert_no_secrets();

    // The consuming UPDATE ran *before* the failure. It must have rolled back.
    let consumed: i64 = fixtures::count(
        &app,
        "SELECT count(*) FROM password_reset_tokens WHERE consumed_at IS NOT NULL",
    )
    .await;
    assert_eq!(
        consumed, 0,
        "the reset token was left consumed by a reset that did not happen"
    );

    // Nor may the session revocation or the audit record have committed.
    let revoked: i64 = fixtures::count(
        &app,
        "SELECT count(*) FROM sessions WHERE revoked_at IS NOT NULL",
    )
    .await;
    assert_eq!(revoked, 0, "sessions were revoked by a reset that failed");
    assert_eq!(
        fixtures::audit_count(&app, "PASSWORD.RESET_COMPLETED").await,
        0,
        "the audit log records a password reset that never happened"
    );

    // And once the account is repaired, the same link still works — which is only
    // true because the token was not consumed.
    let hash = app
        .state
        .hasher
        .hash(&Secret::new(TEST_PASSWORD.to_string()))
        .await
        .expect("hash");
    sqlx::query("INSERT INTO credentials (user_id, password_hash) VALUES ($1, $2)")
        .bind(actor.id)
        .bind(&hash)
        .execute(&app.db)
        .await
        .expect("restore the credentials row");

    fixtures::reset_password_reset_limits(&app, &actor.email).await;
    app.post(
        "/api/v1/auth/password-reset/confirm",
        None,
        json!({"token": token, "new_password": "a replacement passphrase 5512"}),
    )
    .await
    .assert_status(StatusCode::OK);
}

/// A rolled-back creation must leave nothing at all, including in the tables that
/// are written *before* the failing statement.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rejected_bootstrap_leaves_neither_a_user_nor_an_owner() {
    let app = TestApp::spawn().await;

    // A pre-existing account with the address the bootstrap will try to claim, so
    // `users_email_normalized_key` fires part-way through the bootstrap transaction.
    fixtures::create_user(&app, "owner@failure.test").await;

    let response = app
        .post(
            "/api/v1/bootstrap/root",
            None,
            json!({
                "bootstrap_secret": common::TEST_BOOTSTRAP_SECRET,
                "email": "owner@failure.test",
                "display_name": "Owner",
                "password": TEST_PASSWORD,
            }),
        )
        .await;
    assert!(
        response.status.is_client_error(),
        "a colliding bootstrap returned {}",
        response.status
    );
    response.assert_no_secrets();

    assert_eq!(
        fixtures::count(&app, "SELECT count(*) FROM system_ownership").await,
        0,
        "a failed bootstrap established an owner"
    );
    assert_eq!(
        fixtures::count(
            &app,
            "SELECT count(*) FROM system_state WHERE initialized_at IS NOT NULL",
        )
        .await,
        0,
        "a failed bootstrap marked the system initialised, permanently closing the \
         only endpoint that could have fixed it"
    );
    assert_eq!(
        fixtures::count(&app, "SELECT count(*) FROM users").await,
        1,
        "the failed bootstrap left a user behind"
    );
}

// ===========================================================================
// Unique-index collisions
// ===========================================================================

/// A duplicate key is a client-side conflict, not a server fault. Rendering it as
/// `500` would tell a client to retry something that can never succeed, and would
/// put a driver message in a log line under an error level nobody can triage.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_duplicate_key_is_a_clean_409_not_a_500() {
    let app = TestApp::spawn().await;
    let actor = fixtures::actor(
        &app,
        "dupes@failure.test",
        &["projects.create", "projects.read", "departments.create"],
    )
    .await;

    let body = json!({
        "code": "collide",
        "name": "Collide",
        "manager_user_id": actor.id,
    });
    app.post("/api/v1/projects", Some(&actor.access_token), body.clone())
        .await
        .assert_status(StatusCode::CREATED);

    let duplicate = app
        .post("/api/v1/projects", Some(&actor.access_token), body)
        .await;
    duplicate
        .assert_error(StatusCode::CONFLICT, "UNIQUE_VIOLATION")
        .assert_no_secrets();

    // The constraint name, the table name and the SQL must not travel with it.
    let text = String::from_utf8_lossy(&duplicate.raw).to_lowercase();
    for forbidden in ["projects_code_key", "duplicate key", "pg_", "insert into"] {
        assert!(
            !text.contains(forbidden),
            "the conflict leaked `{forbidden}`: {text}"
        );
    }

    // The same on another table, so this is the central mapping and not one
    // handler's care.
    let department = json!({ "code": "dup-dept", "name": "Duplicated" });
    app.post(
        "/api/v1/departments",
        Some(&actor.access_token),
        department.clone(),
    )
    .await
    .assert_status(StatusCode::CREATED);
    app.post("/api/v1/departments", Some(&actor.access_token), department)
        .await
        .assert_error(StatusCode::CONFLICT, "UNIQUE_VIOLATION");

    assert_eq!(
        fixtures::count(&app, "SELECT count(*) FROM projects").await,
        1
    );
    assert_eq!(
        fixtures::count(&app, "SELECT count(*) FROM departments").await,
        1
    );
}

/// The same collision under contention. Two simultaneous creates of one code: one
/// wins, one gets a clean conflict, and neither gets a `500` — which is what an
/// unhandled `23505` racing through two transactions would produce.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn simultaneous_duplicate_creates_conflict_without_a_500() {
    let app = Arc::new(TestApp::spawn().await);
    let actor = fixtures::actor(
        &app,
        "race-dupes@failure.test",
        &["projects.create", "projects.read"],
    )
    .await;

    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let mut handles = Vec::with_capacity(2);
    for n in 0..2 {
        let app = app.clone();
        let barrier = barrier.clone();
        let token = actor.access_token.clone();
        let manager = actor.id;
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let response = app
                .post(
                    "/api/v1/projects",
                    Some(&token),
                    json!({
                        "code": "simultaneous",
                        "name": format!("Attempt {n}"),
                        "manager_user_id": manager,
                    }),
                )
                .await;
            (response.status, response.error_code().map(str::to_string))
        }));
    }

    let mut created = 0usize;
    for handle in handles {
        let (status, code) = handle.await.expect("task must not panic");
        match status {
            StatusCode::CREATED => created += 1,
            StatusCode::CONFLICT => assert_eq!(code.as_deref(), Some("UNIQUE_VIOLATION")),
            other => panic!("a colliding create returned {other} with code {code:?}"),
        }
    }

    assert_eq!(created, 1);
    assert_eq!(
        fixtures::count(
            &app,
            "SELECT count(*) FROM projects WHERE code = 'simultaneous'",
        )
        .await,
        1
    );
    // The loser's audit row must have rolled back with its insert.
    assert_eq!(fixtures::audit_count(&app, "PROJECT.CREATED").await, 1);
}

/// A foreign-key violation is likewise a conflict, not a fault.
#[tokio::test]
async fn a_reference_to_a_missing_row_is_refused_without_a_500() {
    let app = TestApp::spawn().await;
    let actor = fixtures::actor(
        &app,
        "fk@failure.test",
        &["projects.create", "projects.read", "tasks.create"],
    )
    .await;

    let orphan = app
        .post(
            "/api/v1/tasks",
            Some(&actor.access_token),
            json!({ "project_id": Uuid::now_v7(), "title": "Orphan" }),
        )
        .await;
    assert!(
        orphan.status.is_client_error(),
        "a task in a non-existent project returned {}",
        orphan.status
    );
    orphan.assert_no_secrets();
    assert_eq!(fixtures::count(&app, "SELECT count(*) FROM tasks").await, 0);
}

// ===========================================================================
// A configuration that cannot work
// ===========================================================================

/// A key ring must refuse a key it cannot use, at construction, rather than at the
/// first row it is asked to encrypt.
///
/// The failure mode this prevents is specific and irreversible: a process that
/// starts with a wrong-length or zero-versioned key accepts MFA enrolments and
/// writes ciphertext rows whose `key_version` names a key nobody has. Those rows are
/// not recoverable. Refusing at construction turns a permanent data-loss event into
/// a process that does not start.
#[tokio::test]
async fn a_malformed_encryption_key_is_refused_at_construction() {
    let mut config = common::test_config("unused_no_connection_is_opened");

    // The working configuration, so the failures below are attributable.
    config
        .keyring()
        .expect("a 32-byte key at version 1 must work");

    for wrong_length in [0usize, 1, 16, 31, 33, 64] {
        config.security.encryption_key = Secret::new(vec![0x11; wrong_length]);
        let error = config
            .keyring()
            .err()
            .unwrap_or_else(|| panic!("a {wrong_length}-byte encryption key was accepted"));
        // The refusal must not quote the key, in any form.
        let rendered = format!("{error}");
        assert!(
            !rendered.contains("\u{11}"),
            "the refusal echoed key material: {rendered}"
        );
    }

    // Version 0 is refused too: it is the value an unset environment variable parses
    // to, and a row written at version 0 can never be matched to a key.
    config.security.encryption_key = Secret::new(vec![0x11; 32]);
    config.security.encryption_key_version = 0;
    assert!(
        config.keyring().is_err(),
        "encryption key version 0 was accepted"
    );

    // A retired key of the wrong length is refused as well, so a rotation cannot be
    // half-applied.
    config.security.encryption_key_version = 2;
    config.security.previous_encryption_key = Some((1, Secret::new(vec![0x22; 16])));
    assert!(
        config.keyring().is_err(),
        "a malformed previous key was accepted, which would silently make every row \
         written under it unreadable"
    );

    // Directly, so the guarantee does not depend on the config wrapper.
    assert!(KeyRing::new(1, Secret::new(vec![0u8; 16])).is_err());
    assert!(KeyRing::new(0, Secret::new(vec![0u8; 32])).is_err());
    assert!(KeyRing::new(1, Secret::new(vec![0u8; 32])).is_ok());
}

/// The password hasher refuses a work factor weaker than current guidance, for the
/// same reason: a misconfigured cost is a silent, permanent downgrade of every
/// password written while it is in force.
#[tokio::test]
async fn a_weak_password_hashing_configuration_is_refused_at_construction() {
    assert!(
        Hasher::new(Argon2Params::default(), 4).is_ok(),
        "the shipped parameters must be accepted"
    );

    let weak = [
        Argon2Params {
            memory_kib: 1024,
            iterations: 2,
            parallelism: 1,
        },
        Argon2Params {
            memory_kib: 19_456,
            iterations: 0,
            parallelism: 1,
        },
        Argon2Params {
            memory_kib: 0,
            iterations: 0,
            parallelism: 0,
        },
    ];
    for params in weak {
        assert!(
            Hasher::new(params, 4).is_err(),
            "a weak Argon2 configuration was accepted: {params:?}"
        );
    }
}

/// A configuration that cannot work must be refused *before* the state that depends
/// on it is built, so a process never reaches the point of serving traffic with it.
#[tokio::test]
async fn an_unusable_configuration_never_produces_application_state() {
    let mut config = common::test_config("unused_no_connection_is_opened");
    config.security.encryption_key = Secret::new(vec![0x11; 16]);

    // This is the exact call `cli.rs` makes on the way to building `AppState`. It has
    // to be the thing that fails, not a later request.
    assert!(config.keyring().is_err());
    assert!(
        config.security.audit_chain_key.expose().len() == 32,
        "the audit chain key is held separately from the encryption key on purpose \
         (ADR-006); a test that shared them would not notice if the code did"
    );
}
