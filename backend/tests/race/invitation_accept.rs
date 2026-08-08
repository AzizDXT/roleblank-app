//! Concurrency and lifecycle: accepting an invitation.
//!
//! **Why this race is dangerous.** An invitation is a deferred grant of authority.
//! Accepting it creates an account *and* assigns the roles the inviter chose, so a
//! double acceptance is not a cosmetic duplicate — it is a second account holding
//! the same authority, created from a single authorisation, under an email address
//! whose uniqueness index the second insert would have to violate to exist at all.
//! The most likely shape of the bug is not two accounts but one account plus a
//! `500`: two transactions both pass a check-then-act on `status = 'PENDING'`, the
//! loser's `INSERT INTO users` trips `users_email_normalized_key`, and an anonymous
//! caller learns from the error shape that the address is now taken.
//!
//! The defence is a `SELECT ... FOR UPDATE` on the invitation row taken *before*
//! anything is written, so the loser blocks and then re-reads `ACCEPTED`, plus a
//! rows-affected gate on the consuming UPDATE so single use still holds if the lock
//! were ever refactored away.

use std::sync::Arc;

use axum::http::StatusCode;
use serde_json::json;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::common::{TestApp, TEST_PASSWORD};
use crate::fixtures::{self, Actor};

const INVITEE: &str = "invitee@race.test";

/// An inviter who may invite, plus a pending invitation, plus its live token.
async fn pending_invitation(app: &TestApp) -> (Actor, Uuid, String) {
    let inviter = fixtures::actor(app, "inviter@race.test", &["iam.users.invite"]).await;

    let created = app
        .post(
            "/api/v1/invitations",
            Some(&inviter.access_token),
            json!({
                "email": INVITEE,
                "display_name": "Invitee",
                "principal_type": "INTERNAL",
                // No roles: the delegation guard then has nothing to re-check, so
                // this test measures the acceptance race and not the guard.
                "role_ids": [],
            }),
        )
        .await;
    created
        .assert_status(StatusCode::CREATED)
        .assert_no_secrets();
    let invitation_id = created.id_at("/id");

    // The token exists in plaintext in exactly one place after the response: the
    // outbox payload bound for the mail provider.
    let token = fixtures::queued_invitation_token(app).await;
    (inviter, invitation_id, token)
}

fn accept_body(token: &str, name: &str) -> serde_json::Value {
    json!({
        "token": token,
        "password": TEST_PASSWORD,
        "display_name": name,
    })
}

// ===========================================================================
// The race
// ===========================================================================

/// Two simultaneous acceptances of one token. Exactly one may create an account.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_simultaneous_acceptances_create_exactly_one_user() {
    let app = Arc::new(TestApp::spawn().await);
    let (_inviter, invitation_id, token) = pending_invitation(&app).await;

    // A barrier, not a loop: without it the first acceptance would commit before the
    // second opened its transaction, the `FOR UPDATE` would never contend, and the
    // test would pass whether or not the lock existed.
    let barrier = Arc::new(tokio::sync::Barrier::new(2));

    let mut handles = Vec::with_capacity(2);
    for n in 0..2 {
        let app = app.clone();
        let barrier = barrier.clone();
        let token = token.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let response = app
                .post(
                    "/api/v1/invitations/accept",
                    None,
                    accept_body(&token, &format!("Racer {n}")),
                )
                .await;
            (response.status, response.error_code().map(str::to_string))
        }));
    }

    let mut accepted = 0usize;
    let mut refused = 0usize;
    for handle in handles {
        let (status, code) = handle.await.expect("task must not panic");
        match status {
            StatusCode::CREATED => accepted += 1,
            StatusCode::UNAUTHORIZED => {
                // The loser must fail *cleanly*, with the same undifferentiated code
                // every other rejection uses. A 409 here would tell an anonymous
                // caller that the token was real and has just been used; a 500 would
                // mean the unique index, not the lock, was what stopped the second
                // insert.
                assert_eq!(code.as_deref(), Some("AUTHENTICATION_FAILED"));
                refused += 1;
            }
            other => panic!("an acceptance returned {other} with code {code:?}"),
        }
    }

    assert_eq!(accepted, 1, "exactly one acceptance must succeed");
    assert_eq!(refused, 1);

    // The database is the arbiter, not the two responses.
    assert_eq!(
        fixtures::count(
            &app,
            "SELECT count(*) FROM users WHERE email_normalized = 'invitee@race.test'",
        )
        .await,
        1,
        "the losing acceptance left a second account behind"
    );
    assert_eq!(
        fixtures::count(&app, "SELECT count(*) FROM credentials").await,
        // The inviter and the one invitee.
        2,
        "a rolled-back acceptance left a credentials row behind"
    );

    let (status, accepted_user): (String, Option<Uuid>) =
        sqlx::query_as("SELECT status, accepted_user_id FROM invitations WHERE id = $1")
            .bind(invitation_id)
            .fetch_one(&app.db)
            .await
            .expect("read the invitation");
    assert_eq!(status, "ACCEPTED");
    let accepted_user = accepted_user.expect("an accepted invitation must name its user");

    let invitee: (Uuid,) =
        sqlx::query_as("SELECT id FROM users WHERE email_normalized = 'invitee@race.test'")
            .fetch_one(&app.db)
            .await
            .expect("the invitee");
    assert_eq!(
        accepted_user, invitee.0,
        "the invitation points at an account that is not the one that exists"
    );

    // Exactly one acceptance was audited. Two would mean the losing transaction
    // committed its audit rows even though its user insert rolled back — the audit
    // log would then record an account creation that never happened.
    assert_eq!(fixtures::audit_count(&app, "INVITATION.ACCEPTED").await, 1);
}

/// Fifty at once on one token (§7). Exactly one account, and no server errors.
///
/// **Why fifty and not two.** Two acceptances contend for the invitation row and
/// nothing else. Fifty also contend for the *connection pool*, and that is a
/// second, independent way for this endpoint to fail: any request that holds an
/// open transaction while reaching back to the pool for another connection can
/// starve the pool it is itself waiting on. Raising the count is what turns that
/// latent deadlock into an observable one — it produced three `500`s at twenty.
///
/// The per-IP acceptance budget (20/hour) is deliberately *not* cleared: fifty
/// simultaneous account creations from one address is an attack, and the limiter
/// refusing most of them is correct. What is asserted is therefore the shape of the
/// distribution — at most one success, every loser a *clean* refusal — rather than
/// an exact split between the two defences.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn fifty_simultaneous_acceptances_still_create_exactly_one_user() {
    const ATTEMPTS: usize = 50;

    let app = Arc::new(TestApp::spawn().await);
    let (_inviter, _invitation_id, token) = pending_invitation(&app).await;

    let tally = {
        let app = app.clone();
        fixtures::race(ATTEMPTS, move |n| {
            let app = app.clone();
            let token = token.clone();
            async move {
                app.post(
                    "/api/v1/invitations/accept",
                    None,
                    accept_body(&token, &format!("Racer {n}")),
                )
                .await
            }
        })
        .await
    };
    tally.report("invitation_accept x50");

    // A race may produce refusals. It may never produce a server error: a 5xx here
    // means the application drove itself into a state it did not anticipate, and an
    // anonymous caller is the one who observed it.
    assert_eq!(
        tally.server_errors(),
        0,
        "concurrent acceptance produced server errors: {:?}",
        tally.by_status
    );

    // Two legitimate ways to lose, both refusals rather than failures:
    //   401 — the invitation was already consumed
    //   429 — the per-IP acceptance quota refused the attempt first
    assert!(
        tally
            .unexpected(&[
                StatusCode::CREATED,
                StatusCode::UNAUTHORIZED,
                StatusCode::TOO_MANY_REQUESTS,
            ])
            .is_empty(),
        "every losing acceptance must be a clean 401 or 429, got: {:?}",
        tally.by_status
    );

    let accepted = tally.status(StatusCode::CREATED);
    assert!(
        accepted <= 1,
        "{accepted} acceptances succeeded; at most one may"
    );

    // The database is the arbiter, not the response count.
    assert_eq!(
        fixtures::count(
            &app,
            "SELECT count(*) FROM users WHERE email_normalized = 'invitee@race.test'",
        )
        .await,
        accepted as i64,
        "the number of accounts does not match the number of successful acceptances"
    );
    assert_eq!(
        fixtures::count(
            &app,
            "SELECT count(*) FROM invitations WHERE status = 'ACCEPTED'",
        )
        .await,
        accepted as i64,
        "the invitation was consumed a different number of times than it succeeded"
    );
}

// ===========================================================================
// Lifecycle: every state that is not PENDING
// ===========================================================================

/// A revoked invitation is dead, and says nothing about why.
#[tokio::test]
async fn a_revoked_invitation_cannot_be_accepted() {
    let app = TestApp::spawn().await;
    let (inviter, invitation_id, token) = pending_invitation(&app).await;

    app.delete(
        &format!("/api/v1/invitations/{invitation_id}"),
        Some(&inviter.access_token),
    )
    .await
    .assert_status(StatusCode::OK);

    app.post(
        "/api/v1/invitations/accept",
        None,
        accept_body(&token, "Nope"),
    )
    .await
    .assert_error(StatusCode::UNAUTHORIZED, "AUTHENTICATION_FAILED")
    .assert_no_secrets();

    assert_eq!(
        fixtures::count(
            &app,
            "SELECT count(*) FROM users WHERE email_normalized = 'invitee@race.test'",
        )
        .await,
        0,
        "a revoked invitation created an account"
    );

    let status: (String,) = sqlx::query_as("SELECT status FROM invitations WHERE id = $1")
        .bind(invitation_id)
        .fetch_one(&app.db)
        .await
        .expect("read the invitation");
    assert_eq!(
        status.0, "REVOKED",
        "the row must survive revocation — who invited whom must stay answerable"
    );
}

/// An expired invitation is dead, and is retired so it stops occupying the
/// one-pending-per-address index.
#[tokio::test]
async fn an_expired_invitation_cannot_be_accepted_and_is_retired() {
    let app = TestApp::spawn().await;
    let (_inviter, invitation_id, token) = pending_invitation(&app).await;

    // Moved into the past rather than waited out: the configured lifetime is at
    // least an hour and a test may not sleep for it.
    sqlx::query("UPDATE invitations SET expires_at = $2 WHERE id = $1")
        .bind(invitation_id)
        .bind(OffsetDateTime::now_utc() - Duration::seconds(1))
        .execute(&app.db)
        .await
        .expect("expire the invitation");

    app.post(
        "/api/v1/invitations/accept",
        None,
        accept_body(&token, "Too Late"),
    )
    .await
    .assert_error(StatusCode::UNAUTHORIZED, "AUTHENTICATION_FAILED");

    assert_eq!(
        fixtures::count(
            &app,
            "SELECT count(*) FROM users WHERE email_normalized = 'invitee@race.test'",
        )
        .await,
        0
    );

    let status: (String,) = sqlx::query_as("SELECT status FROM invitations WHERE id = $1")
        .bind(invitation_id)
        .fetch_one(&app.db)
        .await
        .expect("read the invitation");
    assert_eq!(
        status.0, "EXPIRED",
        "an expired invitation must be retired, or it keeps the address blocked \
         against `invitations_one_pending_per_email` forever"
    );
}

/// Replaying a token that has already been accepted is refused, and — the part that
/// matters — refused identically to every other failure. A distinguishable answer
/// would tell whoever intercepted the link that it was real.
#[tokio::test]
async fn an_already_accepted_invitation_cannot_be_accepted_again() {
    let app = TestApp::spawn().await;
    let (_inviter, invitation_id, token) = pending_invitation(&app).await;

    app.post(
        "/api/v1/invitations/accept",
        None,
        accept_body(&token, "First"),
    )
    .await
    .assert_status(StatusCode::CREATED);

    let replay = app
        .post(
            "/api/v1/invitations/accept",
            None,
            accept_body(&token, "Second"),
        )
        .await;
    replay
        .assert_error(StatusCode::UNAUTHORIZED, "AUTHENTICATION_FAILED")
        .assert_no_secrets();

    // Indistinguishable from a token that never existed.
    let unknown_token = format!("rb_iv_{}", "A".repeat(43));
    let unknown = app
        .post(
            "/api/v1/invitations/accept",
            None,
            accept_body(&unknown_token, "Ghost"),
        )
        .await;
    assert_eq!(unknown.status, replay.status);
    assert_eq!(unknown.error_code(), replay.error_code());

    assert_eq!(
        fixtures::count(
            &app,
            "SELECT count(*) FROM users WHERE email_normalized = 'invitee@race.test'",
        )
        .await,
        1,
        "the replay created a second account"
    );
    assert_eq!(fixtures::audit_count(&app, "INVITATION.ACCEPTED").await, 1);

    let status: (String,) = sqlx::query_as("SELECT status FROM invitations WHERE id = $1")
        .bind(invitation_id)
        .fetch_one(&app.db)
        .await
        .expect("read the invitation");
    assert_eq!(status.0, "ACCEPTED");
}

/// An invitation cannot outlive the authority that created it: if the inviter is
/// suspended before the invitee gets round to accepting, the invitation is dead.
#[tokio::test]
async fn an_invitation_dies_with_its_inviters_access() {
    let app = TestApp::spawn().await;
    let (inviter, _invitation_id, token) = pending_invitation(&app).await;

    sqlx::query("UPDATE users SET status = 'SUSPENDED', suspended_at = now() WHERE id = $1")
        .bind(inviter.id)
        .execute(&app.db)
        .await
        .expect("suspend the inviter");

    app.post(
        "/api/v1/invitations/accept",
        None,
        accept_body(&token, "Orphan"),
    )
    .await
    .assert_error(StatusCode::UNAUTHORIZED, "AUTHENTICATION_FAILED");

    assert_eq!(
        fixtures::count(
            &app,
            "SELECT count(*) FROM users WHERE email_normalized = 'invitee@race.test'",
        )
        .await,
        0,
        "a departed administrator was still able to place someone in the company"
    );
}
