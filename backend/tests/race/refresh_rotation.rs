//! Concurrency and lifecycle: refresh-token rotation and reuse detection.
//!
//! **Why this race is the most dangerous one in the system.** Rotation is what
//! bounds the value of a stolen refresh token: each token is single-use, so a thief
//! and the legitimate client cannot both keep refreshing — one of them presents an
//! already-consumed token, and that presentation is the *only* signal the system
//! ever gets that a token was copied. Two failure modes follow directly:
//!
//! * If two concurrent refreshes of the same token can both rotate, the token is no
//!   longer single-use and the detector never fires. A thief refreshes forever
//!   alongside the owner, invisibly, until the absolute ceiling.
//! * If the *loser* of a legitimate race is merely rejected rather than treated as
//!   reuse, the same hole exists with an extra step: an attacker deliberately races
//!   the client, loses, and learns that losing is free.
//!
//! So the required behaviour is uncomfortable on purpose: the loser of an honest
//! double-submit kills the whole family, and the user has to log in again. A
//! spurious re-login is a far smaller harm than an undetected persistent session
//! (ADR-005), and the system cannot tell the two cases apart — by construction,
//! because if it could, so could an attacker.

use std::sync::Arc;

use axum::http::StatusCode;
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::common::TestApp;
use crate::fixtures;

const SUBJECT: &str = "rotator@race.test";

fn refresh_body(token: &str) -> serde_json::Value {
    json!({ "refresh_token": token })
}

/// How many of a session's refresh tokens are still unconsumed.
async fn live_refresh_tokens(app: &TestApp, session_id: Uuid) -> i64 {
    let row: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM session_refresh_tokens
          WHERE session_id = $1 AND consumed_at IS NULL",
    )
    .bind(session_id)
    .fetch_one(&app.db)
    .await
    .expect("count live refresh tokens");
    row.0
}

async fn session_is_revoked(app: &TestApp, session_id: Uuid) -> Option<String> {
    let row: (Option<String>,) =
        sqlx::query_as("SELECT revocation_reason FROM sessions WHERE id = $1")
            .bind(session_id)
            .fetch_one(&app.db)
            .await
            .expect("read the session");
    row.0
}

// ===========================================================================
// The race
// ===========================================================================

/// Two concurrent refreshes of one token: one rotates, the other is read as reuse
/// and takes the entire family down with it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_concurrent_refreshes_rotate_once_and_revoke_the_family() {
    let app = Arc::new(TestApp::spawn().await);
    let actor = fixtures::actor(&app, SUBJECT, &[]).await;
    let session_id = actor.session_id;

    assert_eq!(
        live_refresh_tokens(&app, session_id).await,
        1,
        "a fresh session must start with exactly one live refresh token"
    );

    // Genuinely simultaneous. Spawned in a loop the first would finish before the
    // second started, the `FOR UPDATE` would never contend, and the loser would
    // simply be reading a consumed row in sequence — which is a different test.
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let mut handles = Vec::with_capacity(2);
    for _ in 0..2 {
        let app = app.clone();
        let barrier = barrier.clone();
        let token = actor.refresh_token.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let response = app
                .post("/api/v1/auth/refresh", None, refresh_body(&token))
                .await;
            (
                response.status,
                response.error_code().map(str::to_string),
                response
                    .body
                    .as_ref()
                    .and_then(|b| b.get("refresh_token"))
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
            )
        }));
    }

    let mut rotated: Vec<String> = Vec::new();
    let mut refused = 0usize;
    for handle in handles {
        let (status, code, next_refresh) = handle.await.expect("task must not panic");
        match status {
            StatusCode::OK => {
                rotated.push(next_refresh.expect("a successful refresh must mint a new token"));
            }
            StatusCode::UNAUTHORIZED => {
                assert_eq!(code.as_deref(), Some("AUTHENTICATION_FAILED"));
                refused += 1;
            }
            other => panic!("a refresh returned {other} with code {code:?}"),
        }
    }

    assert_eq!(
        rotated.len(),
        1,
        "both refreshes rotated; the token was not single-use"
    );
    assert_eq!(refused, 1);
    let winners_token = rotated.remove(0);

    // ---- the family is dead -------------------------------------------------

    assert_eq!(
        session_is_revoked(&app, session_id).await.as_deref(),
        Some("REFRESH_REUSE_DETECTED"),
        "the loser did not revoke the session; a thief racing a client would go \
         undetected"
    );
    assert_eq!(
        live_refresh_tokens(&app, session_id).await,
        0,
        "a refresh token survived the family revocation"
    );

    // ---- and the detection is recorded -------------------------------------

    // Asserted before any further probing, because every subsequent presentation of
    // a consumed token is itself a reuse event — see below.
    assert_eq!(
        fixtures::audit_count(&app, "AUTH.REFRESH_REUSE_DETECTED").await,
        1,
        "reuse detection must leave an audit event — it is the only record that a \
         token was ever held by two parties"
    );

    let meta: (serde_json::Value,) = sqlx::query_as(
        "SELECT metadata FROM audit_events WHERE action_code = 'AUTH.REFRESH_REUSE_DETECTED'",
    )
    .fetch_one(&app.db)
    .await
    .expect("read the reuse event");
    assert_eq!(
        meta.0["action_taken"],
        json!("session_family_revoked"),
        "the audit event must say what was done about it: {}",
        meta.0
    );
    assert!(
        meta.0["invalidated_count"].as_i64().unwrap_or(0) >= 1,
        "the event must record how many tokens died: {}",
        meta.0
    );
    // Nothing in the event may have been silently swallowed by the metadata
    // builder's secret-key net. A `__redacted` marker here means the event is
    // recording less than its author intended, and that the incident also produced a
    // spurious "refused to write a secret" ERROR in the operational log.
    assert!(
        !meta.0.to_string().contains("__redacted"),
        "a field of the reuse event was redacted: {}",
        meta.0
    );

    let outcome: (String,) = sqlx::query_as(
        "SELECT outcome FROM audit_events WHERE action_code = 'AUTH.REFRESH_REUSE_DETECTED'",
    )
    .fetch_one(&app.db)
    .await
    .expect("read the reuse outcome");
    assert_eq!(outcome.0, "FAILURE");

    // ---- nothing survives ---------------------------------------------------

    // The original token is dead — and, critically, so is the token the *winner*
    // was just handed. The winner is the party most likely to be legitimate, and it
    // is still evicted, because the system cannot tell which of the two racers was
    // the thief.
    for dead in [&actor.refresh_token, &winners_token] {
        app.post("/api/v1/auth/refresh", None, refresh_body(dead))
            .await
            .assert_error(StatusCode::UNAUTHORIZED, "AUTHENTICATION_FAILED");
    }

    // The access token dies with the session, on the very next request.
    app.get("/api/v1/auth/me", Some(&actor.access_token))
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "AUTHENTICATION_FAILED");

    // Each of those two probes presented a *consumed* token, and reuse is classified
    // first and unconditionally — before the revoked session is even looked at — so
    // each raised its own alarm. That is deliberate and is worth pinning: an
    // attacker must not be able to quieten the detector by first getting the session
    // revoked.
    assert_eq!(
        fixtures::audit_count(&app, "AUTH.REFRESH_REUSE_DETECTED").await,
        3,
        "presenting a consumed token against an already-revoked session must still \
         be recorded as reuse"
    );
}

/// Eight at once, in case two is not enough contention to expose a lost lock.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn eight_concurrent_refreshes_still_rotate_at_most_once() {
    const ATTEMPTS: usize = 8;

    let app = Arc::new(TestApp::spawn().await);
    let actor = fixtures::actor(&app, SUBJECT, &[]).await;

    let barrier = Arc::new(tokio::sync::Barrier::new(ATTEMPTS));
    let mut handles = Vec::with_capacity(ATTEMPTS);
    for _ in 0..ATTEMPTS {
        let app = app.clone();
        let barrier = barrier.clone();
        let token = actor.refresh_token.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            app.post("/api/v1/auth/refresh", None, refresh_body(&token))
                .await
                .status
        }));
    }

    let mut rotated = 0usize;
    let mut other: Vec<StatusCode> = Vec::new();
    for handle in handles {
        match handle.await.expect("task must not panic") {
            StatusCode::OK => rotated += 1,
            // 401 is a loser; 429 is the per-IP refresh quota, which is a legitimate
            // outcome for eight simultaneous refreshes from one address.
            StatusCode::UNAUTHORIZED | StatusCode::TOO_MANY_REQUESTS => {}
            s => other.push(s),
        }
    }

    assert!(
        other.is_empty(),
        "every losing refresh must be a clean 401 or 429, got: {other:?}"
    );
    assert!(rotated <= 1, "{rotated} refreshes rotated; at most one may");

    // However many lost, the family is gone and no token remains usable.
    assert_eq!(live_refresh_tokens(&app, actor.session_id).await, 0);
    assert_eq!(
        session_is_revoked(&app, actor.session_id).await.as_deref(),
        Some("REFRESH_REUSE_DETECTED")
    );
}

// ===========================================================================
// Lifecycle
// ===========================================================================

/// Sequential reuse — the ordinary shape of a stolen token — is detected, and the
/// legitimate holder's freshly issued token dies with it.
#[tokio::test]
async fn reusing_a_consumed_refresh_token_revokes_the_whole_family() {
    let app = TestApp::spawn().await;
    let actor = fixtures::actor(&app, SUBJECT, &[]).await;

    // One honest rotation first, so there is a live successor to lose.
    let rotated = app
        .post(
            "/api/v1/auth/refresh",
            None,
            refresh_body(&actor.refresh_token),
        )
        .await;
    rotated.assert_status(StatusCode::OK).assert_no_secrets();
    let second_refresh = rotated.str_at("/refresh_token").to_string();
    let second_access = rotated.str_at("/access_token").to_string();

    assert_ne!(second_refresh, actor.refresh_token, "rotation must rotate");
    assert_ne!(
        second_access, actor.access_token,
        "rotation is unconditional: the old access token must die too, or a stolen \
         access token keeps its value for the whole session"
    );
    app.get("/api/v1/auth/me", Some(&second_access))
        .await
        .assert_status(StatusCode::OK);
    app.get("/api/v1/auth/me", Some(&actor.access_token))
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "AUTHENTICATION_FAILED");

    // Now the thief presents the copy they took before the rotation.
    app.post(
        "/api/v1/auth/refresh",
        None,
        refresh_body(&actor.refresh_token),
    )
    .await
    .assert_error(StatusCode::UNAUTHORIZED, "AUTHENTICATION_FAILED");

    assert_eq!(
        session_is_revoked(&app, actor.session_id).await.as_deref(),
        Some("REFRESH_REUSE_DETECTED")
    );
    assert_eq!(live_refresh_tokens(&app, actor.session_id).await, 0);
    assert_eq!(
        fixtures::audit_count(&app, "AUTH.REFRESH_REUSE_DETECTED").await,
        1
    );

    // The legitimate holder is evicted as well. That is the intended cost.
    app.post("/api/v1/auth/refresh", None, refresh_body(&second_refresh))
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "AUTHENTICATION_FAILED");
    app.get("/api/v1/auth/me", Some(&second_access))
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "AUTHENTICATION_FAILED");
}

/// An attacker who waits out the refresh TTL before probing must not be able to
/// convert a compromise signal into a silent expiry. Reuse is classified first and
/// unconditionally, so an expired *and* consumed token is still reuse.
#[tokio::test]
async fn reuse_is_detected_even_after_the_token_has_expired() {
    let app = TestApp::spawn().await;
    let actor = fixtures::actor(&app, SUBJECT, &[]).await;

    app.post(
        "/api/v1/auth/refresh",
        None,
        refresh_body(&actor.refresh_token),
    )
    .await
    .assert_status(StatusCode::OK);

    sqlx::query(
        "UPDATE session_refresh_tokens SET expires_at = now() - interval '1 day'
          WHERE session_id = $1",
    )
    .bind(actor.session_id)
    .execute(&app.db)
    .await
    .expect("age every token in the family");

    app.post(
        "/api/v1/auth/refresh",
        None,
        refresh_body(&actor.refresh_token),
    )
    .await
    .assert_error(StatusCode::UNAUTHORIZED, "AUTHENTICATION_FAILED");

    assert_eq!(
        fixtures::audit_count(&app, "AUTH.REFRESH_REUSE_DETECTED").await,
        1,
        "an expired consumed token was treated as a mere expiry, so waiting out the \
         TTL is a way to probe a family silently"
    );
}

/// A refresh token is useless once its session has been revoked — and the refusal
/// is a plain rejection, not a reuse alarm, because logging out and then retrying
/// is an ordinary client mistake rather than evidence of theft.
#[tokio::test]
async fn a_refresh_token_is_dead_once_its_session_is_revoked() {
    let app = TestApp::spawn().await;
    let actor = fixtures::actor(&app, SUBJECT, &[]).await;

    app.post("/api/v1/auth/logout", Some(&actor.access_token), json!({}))
        .await
        .assert_status(StatusCode::OK);

    app.post(
        "/api/v1/auth/refresh",
        None,
        refresh_body(&actor.refresh_token),
    )
    .await
    .assert_error(StatusCode::UNAUTHORIZED, "AUTHENTICATION_FAILED");

    assert_eq!(
        session_is_revoked(&app, actor.session_id).await.as_deref(),
        Some("LOGOUT")
    );
    assert_eq!(
        fixtures::audit_count(&app, "AUTH.REFRESH_REUSE_DETECTED").await,
        0,
        "refreshing after a logout raised a false theft alarm; logout deliberately \
         leaves the token unconsumed so that an ordinary retry is not an incident"
    );
}

/// Suspension must take effect on the very next refresh, with no wait for the
/// access token to expire.
#[tokio::test]
async fn a_refresh_token_is_dead_once_the_user_is_suspended() {
    let app = TestApp::spawn().await;
    let actor = fixtures::actor(&app, SUBJECT, &[]).await;

    sqlx::query("UPDATE users SET status = 'SUSPENDED', suspended_at = now() WHERE id = $1")
        .bind(actor.id)
        .execute(&app.db)
        .await
        .expect("suspend the account");

    app.post(
        "/api/v1/auth/refresh",
        None,
        refresh_body(&actor.refresh_token),
    )
    .await
    .assert_error(StatusCode::UNAUTHORIZED, "AUTHENTICATION_FAILED");

    // The token was *not* consumed, so reactivating the account does not leave the
    // user with a family that has been silently spent.
    assert_eq!(live_refresh_tokens(&app, actor.session_id).await, 1);
    assert_eq!(
        fixtures::audit_count(&app, "AUTH.REFRESH_REUSE_DETECTED").await,
        0,
        "a suspended user's refresh was misreported as token theft"
    );
}

/// Rotation extends access and idle, and nothing extends the absolute ceiling.
/// Without this, a thief who keeps refreshing has a session that never ends.
#[tokio::test]
async fn rotation_never_extends_the_absolute_ceiling() {
    let app = TestApp::spawn().await;
    let actor = fixtures::actor(&app, SUBJECT, &[]).await;

    let before: (OffsetDateTime, i32) = sqlx::query_as(
        "SELECT s.absolute_expires_at, max(rt.generation)::int
           FROM sessions s JOIN session_refresh_tokens rt ON rt.session_id = s.id
          WHERE s.id = $1 GROUP BY s.absolute_expires_at",
    )
    .bind(actor.session_id)
    .fetch_one(&app.db)
    .await
    .expect("read the ceiling");
    assert_eq!(before.1, 0, "the first refresh token is generation 0");

    let mut token = actor.refresh_token.clone();
    for expected_generation in 1..=3 {
        let rotated = app
            .post("/api/v1/auth/refresh", None, refresh_body(&token))
            .await;
        rotated.assert_status(StatusCode::OK);
        token = rotated.str_at("/refresh_token").to_string();

        let after: (OffsetDateTime, i32) = sqlx::query_as(
            "SELECT s.absolute_expires_at, max(rt.generation)::int
               FROM sessions s JOIN session_refresh_tokens rt ON rt.session_id = s.id
              WHERE s.id = $1 GROUP BY s.absolute_expires_at",
        )
        .bind(actor.session_id)
        .fetch_one(&app.db)
        .await
        .expect("read the ceiling");

        assert_eq!(
            after.0, before.0,
            "the absolute ceiling moved on refresh {expected_generation}; every \
             compromise must have an end"
        );
        assert_eq!(
            after.1, expected_generation,
            "the generation must be a monotonic record of the family's history"
        );
    }

    // Exactly one token is live at any point in the chain.
    assert_eq!(live_refresh_tokens(&app, actor.session_id).await, 1);
    assert_eq!(fixtures::audit_count(&app, "AUTH.REFRESHED").await, 3);
}
