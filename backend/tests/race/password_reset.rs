//! Concurrency and lifecycle: consuming a password-reset token.
//!
//! **Why this race is dangerous.** A reset link is a bearer credential that
//! rewrites the account's only knowledge factor. If two confirmations of the same
//! token can both succeed, the password ends up as whichever transaction committed
//! last — and the *other* party believes they set it. That is not a lost update in
//! the ordinary sense: it is an attacker who intercepted the link racing the
//! legitimate owner and, half the time, owning the account afterwards while the
//! owner sees a success page. Single use is the whole security property of the
//! flow, and it has to hold under contention, not merely in sequence.
//!
//! The defence is `SELECT ... FOR UPDATE` on the token row plus a rows-affected
//! gate on `consumed_at IS NULL`, so the second transaction either blocks and then
//! sees a consumed row, or its consuming UPDATE affects zero rows and it rolls
//! back everything it had done — including the password write.

use std::sync::Arc;

use axum::http::StatusCode;
use serde_json::json;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::common::{TestApp, TEST_PASSWORD};
use crate::fixtures;

const SUBJECT: &str = "resetter@race.test";
const NEW_PASSWORD_A: &str = "first winner passphrase 8391";
const NEW_PASSWORD_B: &str = "second winner passphrase 4417";

/// Seed an account with a live session, then request a reset and read the token.
async fn subject_with_live_reset(app: &TestApp) -> (Uuid, String, String) {
    let actor = fixtures::actor(app, SUBJECT, &[]).await;

    app.post(
        "/api/v1/auth/password-reset/request",
        None,
        json!({ "email": SUBJECT }),
    )
    .await
    // Always 202, whether or not the account exists. Asserted here so a change that
    // made the response depend on existence would fail in the flow that uses it.
    .assert_status(StatusCode::ACCEPTED);

    let token = fixtures::queued_reset_token(app).await;
    (actor.id, actor.access_token, token)
}

/// Whether a password is the account's current one, asked the way login asks.
async fn password_is(app: &TestApp, user_id: Uuid, candidate: &str) -> bool {
    let hash: (String,) =
        sqlx::query_as("SELECT password_hash FROM credentials WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&app.db)
            .await
            .expect("read the stored hash");
    app.state
        .hasher
        .verify(
            &roleblank_backend::shared::secret::Secret::new(candidate.to_string()),
            &hash.0,
        )
        .await
        .expect("verify")
}

// ===========================================================================
// The race
// ===========================================================================

/// Two simultaneous confirmations of one token. Exactly one may take effect, and
/// the password must end up in one of two well-defined states, never a third.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_simultaneous_confirmations_consume_the_token_once() {
    let app = Arc::new(TestApp::spawn().await);
    let (user_id, _session_token, token) = subject_with_live_reset(&app).await;

    // Both confirmations set a *different* password, so "which one won" is
    // observable. Two identical passwords would make a double-apply invisible.
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let mut handles = Vec::with_capacity(2);
    for candidate in [NEW_PASSWORD_A, NEW_PASSWORD_B] {
        let app = app.clone();
        let barrier = barrier.clone();
        let token = token.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let response = app
                .post(
                    "/api/v1/auth/password-reset/confirm",
                    None,
                    json!({"token": token, "new_password": candidate}),
                )
                .await;
            (
                candidate,
                response.status,
                response.error_code().map(str::to_string),
            )
        }));
    }

    let mut winner: Option<&str> = None;
    let mut refused = 0usize;
    for handle in handles {
        let (candidate, status, code) = handle.await.expect("task must not panic");
        match status {
            StatusCode::OK => {
                assert!(
                    winner.is_none(),
                    "both confirmations succeeded; the token was consumed twice"
                );
                winner = Some(candidate);
            }
            StatusCode::UNAUTHORIZED => {
                // The loser sees the same undifferentiated failure as an unknown or
                // expired token. Anything more specific would confirm to whoever
                // holds a stolen link that it was genuine and has just been spent.
                assert_eq!(code.as_deref(), Some("AUTHENTICATION_FAILED"));
                refused += 1;
            }
            other => panic!("a confirmation returned {other} with code {code:?}"),
        }
    }

    let winner = winner.expect("exactly one confirmation must succeed");
    assert_eq!(refused, 1);

    // A single well-defined end state: the winner's password, and nothing else.
    assert!(
        password_is(&app, user_id, winner).await,
        "the account does not hold the winning password"
    );
    let loser = if winner == NEW_PASSWORD_A {
        NEW_PASSWORD_B
    } else {
        NEW_PASSWORD_A
    };
    assert!(
        !password_is(&app, user_id, loser).await,
        "the losing confirmation's password was applied as well — the write was not \
         rolled back with its transaction"
    );
    assert!(
        !password_is(&app, user_id, TEST_PASSWORD).await,
        "the original password still works after a successful reset"
    );

    // The token table is the arbiter: one row, consumed exactly once.
    let tokens: (i64, i64) = sqlx::query_as(
        "SELECT count(*), count(*) FILTER (WHERE consumed_at IS NOT NULL)
           FROM password_reset_tokens WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_one(&app.db)
    .await
    .expect("count reset tokens");
    assert_eq!(tokens.0, 1, "more than one reset token exists");
    assert_eq!(tokens.1, 1, "the token was not consumed");

    // Exactly one completion was audited. Two would mean the loser committed an
    // audit row for a password change that rolled back.
    assert_eq!(
        fixtures::audit_count(&app, "PASSWORD.RESET_COMPLETED").await,
        1
    );
}

/// A distinct passphrase per racer, so that a double-apply is *observable*.
///
/// Fifty identical passwords would make two successful writes indistinguishable
/// from one — the account would hold the right password either way and the bug
/// would pass.
fn racer_password(n: usize) -> String {
    format!("racing passphrase number {n} zulu")
}

/// Fifty simultaneous confirmations of one token (§7).
///
/// **What the extra scale buys over the two-way test above.** Two confirmations
/// contend for the token row and nothing else. Fifty also contend for the
/// connection pool and the per-IP quota, so this is where a lock held across a
/// second pool acquisition, or a rows-affected gate that was quietly dropped,
/// stops being theoretical. The end state must still be a *single* well-defined
/// password — not "one of the fifty, probably".
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn fifty_simultaneous_confirmations_consume_the_token_once() {
    const ATTEMPTS: usize = 50;

    let app = Arc::new(TestApp::spawn().await);
    let (user_id, session_token, token) = subject_with_live_reset(&app).await;

    // Hand the confirm path its full per-IP budget back: the reset *request* above
    // already spent one, and this test is about the token, not the quota. The quota
    // still binds during the race — it is 5/hour and shared between request and
    // confirm — so most racers are refused by the limiter before they ever reach
    // the token. That is a correct outer defence, and the counts are reported.
    fixtures::reset_password_reset_limits(&app, SUBJECT).await;

    // Which racer won, recorded as it happens. Reading it back afterwards by trying
    // all fifty candidates would cost fifty Argon2id verifications at production
    // parameters for no extra assurance.
    let winners: Arc<std::sync::Mutex<Vec<usize>>> = Arc::new(std::sync::Mutex::new(Vec::new()));

    let tally = {
        let app = app.clone();
        let winners = winners.clone();
        fixtures::race(ATTEMPTS, move |n| {
            let app = app.clone();
            let token = token.clone();
            let winners = winners.clone();
            async move {
                let response = app
                    .post(
                        "/api/v1/auth/password-reset/confirm",
                        None,
                        json!({"token": token, "new_password": racer_password(n)}),
                    )
                    .await;
                if response.status == StatusCode::OK {
                    winners.lock().expect("winner list").push(n);
                }
                response
            }
        })
        .await
    };
    tally.report("password_reset_confirm x50");

    assert_eq!(
        tally.server_errors(),
        0,
        "concurrent confirmation produced server errors: {:?}",
        tally.by_status
    );
    assert!(
        tally
            .unexpected(&[
                StatusCode::OK,
                StatusCode::UNAUTHORIZED,
                StatusCode::TOO_MANY_REQUESTS,
            ])
            .is_empty(),
        "every losing confirmation must be a clean 401 or 429, got: {:?}",
        tally.by_status
    );
    assert_eq!(
        tally.status(StatusCode::OK),
        1,
        "exactly one confirmation may succeed, got {:?}",
        tally.by_status
    );

    // A loser must not be able to tell a spent link from a forged one: anything more
    // specific confirms to whoever holds a stolen link that it was genuine.
    assert_eq!(
        tally.code("AUTHENTICATION_FAILED"),
        tally.status(StatusCode::UNAUTHORIZED),
        "a losing confirmation returned a code other than AUTHENTICATION_FAILED"
    );

    // ---- one well-defined final password ----------------------------------
    let winners = winners.lock().expect("winner list").clone();
    assert_eq!(
        winners.len(),
        1,
        "expected exactly one winner, got {winners:?}"
    );
    let winner = winners[0];
    assert!(
        password_is(&app, user_id, &racer_password(winner)).await,
        "the account does not hold the winning racer's password"
    );
    assert!(
        !password_is(&app, user_id, TEST_PASSWORD).await,
        "the original password still works after a successful reset"
    );
    // A neighbour's password must not have been applied on top of the winner's.
    let neighbour = (winner + 1) % ATTEMPTS;
    assert!(
        !password_is(&app, user_id, &racer_password(neighbour)).await,
        "a losing confirmation's password was applied as well — its write was not \
         rolled back with its transaction"
    );

    // ---- the token was consumed exactly once ------------------------------
    let tokens: (i64, i64) = sqlx::query_as(
        "SELECT count(*), count(*) FILTER (WHERE consumed_at IS NOT NULL)
           FROM password_reset_tokens WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_one(&app.db)
    .await
    .expect("count reset tokens");
    assert_eq!(tokens.0, 1, "more than one reset token exists");
    assert_eq!(tokens.1, 1, "the token was not consumed exactly once");

    // ---- every session is gone --------------------------------------------
    // A recovery that leaves the attacker's session alive is not a recovery.
    let live_sessions = fixtures::count(
        &app,
        "SELECT count(*) FROM sessions WHERE revoked_at IS NULL",
    )
    .await;
    assert_eq!(
        live_sessions, 0,
        "{live_sessions} sessions survived the reset"
    );
    app.get("/api/v1/auth/me", Some(&session_token))
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "AUTHENTICATION_FAILED");

    // Exactly one completion audited: two would mean a loser committed an audit row
    // for a password change that rolled back.
    assert_eq!(
        fixtures::audit_count(&app, "PASSWORD.RESET_COMPLETED").await,
        1
    );
}

/// A successful reset kills every session, including any the attacker who prompted
/// the reset already holds. A reset that leaves a live session is not a recovery.
#[tokio::test]
async fn a_successful_reset_revokes_every_session() {
    let app = TestApp::spawn().await;
    let (user_id, session_token, token) = subject_with_live_reset(&app).await;

    // A second live session, as a second device would be.
    fixtures::reset_login_limits(&app, SUBJECT).await;
    let (second_token, _) = fixtures::login(&app, SUBJECT).await;

    // Both work before the reset.
    for live in [&session_token, &second_token] {
        app.get("/api/v1/auth/me", Some(live))
            .await
            .assert_status(StatusCode::OK);
    }

    let confirmed = app
        .post(
            "/api/v1/auth/password-reset/confirm",
            None,
            json!({"token": token, "new_password": NEW_PASSWORD_A}),
        )
        .await;
    confirmed.assert_status(StatusCode::OK).assert_no_secrets();
    assert_eq!(
        confirmed.json()["revoked_sessions"].as_i64(),
        Some(2),
        "both sessions should have been reported revoked"
    );

    // Neither token is usable on the very next request — no waiting for expiry.
    for dead in [&session_token, &second_token] {
        app.get("/api/v1/auth/me", Some(dead))
            .await
            .assert_error(StatusCode::UNAUTHORIZED, "AUTHENTICATION_FAILED");
    }

    let live: i64 = fixtures::count(
        &app,
        "SELECT count(*) FROM sessions WHERE revoked_at IS NULL",
    )
    .await;
    assert_eq!(live, 0, "a session survived a password reset");

    let reasons: Vec<(String,)> =
        sqlx::query_as("SELECT DISTINCT revocation_reason FROM sessions WHERE user_id = $1")
            .bind(user_id)
            .fetch_all(&app.db)
            .await
            .expect("read revocation reasons");
    assert_eq!(reasons.len(), 1);
    assert_eq!(reasons[0].0, "PASSWORD_RESET");
}

// ===========================================================================
// Lifecycle
// ===========================================================================

/// Replaying a consumed token is refused, and is indistinguishable from a token
/// that never existed.
#[tokio::test]
async fn a_consumed_reset_token_cannot_be_replayed() {
    let app = TestApp::spawn().await;
    let (user_id, _session, token) = subject_with_live_reset(&app).await;

    app.post(
        "/api/v1/auth/password-reset/confirm",
        None,
        json!({"token": &token, "new_password": NEW_PASSWORD_A}),
    )
    .await
    .assert_status(StatusCode::OK);

    let replay = app
        .post(
            "/api/v1/auth/password-reset/confirm",
            None,
            json!({"token": &token, "new_password": NEW_PASSWORD_B}),
        )
        .await;
    replay.assert_error(StatusCode::UNAUTHORIZED, "AUTHENTICATION_FAILED");

    let unknown = app
        .post(
            "/api/v1/auth/password-reset/confirm",
            None,
            json!({"token": format!("rb_pr_{}", "A".repeat(43)), "new_password": NEW_PASSWORD_B}),
        )
        .await;
    assert_eq!(unknown.status, replay.status);
    assert_eq!(unknown.error_code(), replay.error_code());

    assert!(
        password_is(&app, user_id, NEW_PASSWORD_A).await,
        "the replay changed the password"
    );
}

/// An expired token is dead even though it was never used.
#[tokio::test]
async fn an_expired_reset_token_is_refused() {
    let app = TestApp::spawn().await;
    let (user_id, _session, token) = subject_with_live_reset(&app).await;

    sqlx::query("UPDATE password_reset_tokens SET expires_at = $2 WHERE user_id = $1")
        .bind(user_id)
        .bind(OffsetDateTime::now_utc() - Duration::seconds(1))
        .execute(&app.db)
        .await
        .expect("expire the token");

    app.post(
        "/api/v1/auth/password-reset/confirm",
        None,
        json!({"token": token, "new_password": NEW_PASSWORD_A}),
    )
    .await
    .assert_error(StatusCode::UNAUTHORIZED, "AUTHENTICATION_FAILED");

    assert!(
        password_is(&app, user_id, TEST_PASSWORD).await,
        "an expired token changed the password"
    );
}

/// Requesting a second reset must invalidate the first, or a mailbox accumulates a
/// stack of simultaneously valid ways into the account.
#[tokio::test]
async fn requesting_a_second_reset_kills_the_first_link() {
    let app = TestApp::spawn().await;
    let (user_id, _session, first_token) = subject_with_live_reset(&app).await;

    fixtures::clear_outbox(&app).await;
    fixtures::reset_password_reset_limits(&app, SUBJECT).await;
    app.post(
        "/api/v1/auth/password-reset/request",
        None,
        json!({ "email": SUBJECT }),
    )
    .await
    .assert_status(StatusCode::ACCEPTED);
    let second_token = fixtures::queued_reset_token(&app).await;
    assert_ne!(first_token, second_token);

    app.post(
        "/api/v1/auth/password-reset/confirm",
        None,
        json!({"token": first_token, "new_password": NEW_PASSWORD_A}),
    )
    .await
    .assert_error(StatusCode::UNAUTHORIZED, "AUTHENTICATION_FAILED");

    app.post(
        "/api/v1/auth/password-reset/confirm",
        None,
        json!({"token": second_token, "new_password": NEW_PASSWORD_B}),
    )
    .await
    .assert_status(StatusCode::OK);

    assert!(password_is(&app, user_id, NEW_PASSWORD_B).await);

    let live: i64 = fixtures::count(
        &app,
        "SELECT count(*) FROM password_reset_tokens WHERE consumed_at IS NULL",
    )
    .await;
    assert_eq!(live, 0, "a live reset token survived");
}

/// A suspended account cannot be recovered through a link issued while it was
/// active — otherwise suspension would be undone by a message already in a mailbox.
#[tokio::test]
async fn a_reset_link_stops_working_when_the_account_is_suspended() {
    let app = TestApp::spawn().await;
    let (user_id, _session, token) = subject_with_live_reset(&app).await;

    sqlx::query("UPDATE users SET status = 'SUSPENDED', suspended_at = now() WHERE id = $1")
        .bind(user_id)
        .execute(&app.db)
        .await
        .expect("suspend the account");

    app.post(
        "/api/v1/auth/password-reset/confirm",
        None,
        json!({"token": token, "new_password": NEW_PASSWORD_A}),
    )
    .await
    .assert_error(StatusCode::UNAUTHORIZED, "AUTHENTICATION_FAILED");

    assert!(
        password_is(&app, user_id, TEST_PASSWORD).await,
        "a suspended account's password was reset"
    );
}
