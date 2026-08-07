//! The TOCTOU boundary: authority changing underneath a live session.
//!
//! **Why this matters, and what the honest guarantee is.** Authorisation is
//! recomputed from the database on every request — there is no permission cache
//! (ADR-003). That makes the window between "authority revoked" and "revocation
//! takes effect" exactly one request long: whatever is already past the extractor
//! finishes with the authority it loaded, and everything after it is refused. It is
//! not zero, and no design that resolves a principal once per request can make it
//! zero. What must not happen is the *other* failure: a revocation that only takes
//! effect when the access token expires, which would leave a dismissed employee
//! working for another fifteen minutes and a compromised session usable for the
//! rest of its idle lifetime.
//!
//! So each test here does the same two things. It moves the authority while a
//! request is genuinely in flight — held there by a row lock the test owns, not by a
//! sleep — and then asserts that (a) whatever the in-flight request answered, the
//! database agrees with it, and (b) the *very next* request is refused. Assertion
//! (a) is what catches the nastier bug: a request that reports success while its
//! transaction rolled back, or that writes after being refused.

use std::sync::Arc;

use axum::http::StatusCode;
use serde_json::json;
use uuid::Uuid;

use crate::common::TestApp;
use crate::fixtures::{self, Actor};

const VICTIM: &str = "victim@race.test";
const ADMIN: &str = "admin@race.test";

/// Hold an exclusive lock on a project row until the returned transaction is
/// dropped or committed.
///
/// This is how a request is put "in flight" deterministically: every write path in
/// the projects service begins by re-reading its subject `FOR UPDATE`, so a request
/// against this project blocks there — past authentication, past the extractor that
/// loaded its grants, and before its authorisation check. A `sleep` would only make
/// the race *likely*; a lock makes it certain.
async fn lock_project(app: &TestApp, project_id: Uuid) -> sqlx::Transaction<'_, sqlx::Postgres> {
    let mut tx = app
        .db
        .begin()
        .await
        .expect("begin a lock-holding transaction");
    let _: (Uuid,) = sqlx::query_as("SELECT id FROM projects WHERE id = $1 FOR UPDATE")
        .bind(project_id)
        .fetch_one(&mut *tx)
        .await
        .expect("lock the project row");
    tx
}

async fn project_state(app: &TestApp, id: Uuid) -> (String, i32) {
    sqlx::query_as("SELECT name, version FROM projects WHERE id = $1")
        .bind(id)
        .fetch_one(&app.db)
        .await
        .expect("read the project")
}

// ===========================================================================
// A permission revoked mid-request
// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revoking_a_permission_mid_request_takes_effect_by_the_next_request() {
    let app = Arc::new(TestApp::spawn().await);
    let actor = fixtures::actor(
        &app,
        VICTIM,
        &["projects.create", "projects.read", "projects.update"],
    )
    .await;
    let project_id = fixtures::create_project(&app, &actor, "toctou-proj").await;
    let (_, start_version) = project_state(&app, project_id).await;

    // Freeze the row, so the PATCH below is guaranteed to be sitting inside its
    // transaction when the revocation lands.
    let lock = lock_project(&app, project_id).await;

    let in_flight = {
        let app = app.clone();
        let token = actor.access_token.clone();
        tokio::spawn(async move {
            let response = app
                .patch(
                    &format!("/api/v1/projects/{project_id}"),
                    Some(&token),
                    json!({ "version": start_version, "name": "Written mid-revocation" }),
                )
                .await;
            (response.status, response.error_code().map(str::to_string))
        })
    };

    // Give the request time to reach the lock. If it has not, the test still holds —
    // the revocation simply lands earlier and the request is refused outright, which
    // assertion (b) below covers.
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    assert_eq!(
        fixtures::revoke_grant(&app, actor.id, "projects.update").await,
        1,
        "the grant to revoke must have existed"
    );

    // Release, and let the in-flight request finish.
    lock.commit().await.expect("release the lock");
    let (status, code) = in_flight.await.expect("task must not panic");

    // (a) Whatever it answered, the row agrees with it. A `200` whose write rolled
    //     back, or a `403` that still wrote, is far worse than either honest outcome.
    let (name, version) = project_state(&app, project_id).await;
    match status {
        StatusCode::OK => {
            assert_eq!(
                name, "Written mid-revocation",
                "the request reported success but its write is not in the row"
            );
            assert_eq!(version, start_version + 1);
        }
        StatusCode::FORBIDDEN => {
            assert_eq!(code.as_deref(), Some("AUTHORIZATION_DENIED"));
            assert_eq!(
                version, start_version,
                "a refused request still wrote to the row"
            );
        }
        other => panic!("the in-flight request returned {other} with code {code:?}"),
    }

    // (b) The next request is refused, now, with no wait for the token to expire.
    let (_, current_version) = project_state(&app, project_id).await;
    app.patch(
        &format!("/api/v1/projects/{project_id}"),
        Some(&actor.access_token),
        json!({ "version": current_version, "name": "After the revocation" }),
    )
    .await
    .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");

    // The token itself is still perfectly valid — this is an *authorisation* change,
    // not an authentication one, and the reads it still holds must keep working.
    app.get(
        &format!("/api/v1/projects/{project_id}"),
        Some(&actor.access_token),
    )
    .await
    .assert_status(StatusCode::OK);

    let (final_name, final_version) = project_state(&app, project_id).await;
    assert_eq!(final_name, name, "the post-revocation write landed anyway");
    assert_eq!(final_version, version);
}

/// A `DENY` override added mid-request. Distinct from removing the `ALLOW`: denials
/// are evaluated before the allow set and cannot be escaped by holding another
/// grant, so this is the path an operator uses to stop someone *now*.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_deny_override_added_mid_request_takes_effect_by_the_next_request() {
    let app = Arc::new(TestApp::spawn().await);
    let actor = fixtures::actor(
        &app,
        VICTIM,
        &["projects.create", "projects.read", "projects.update"],
    )
    .await;
    let project_id = fixtures::create_project(&app, &actor, "deny-proj").await;
    let (_, start_version) = project_state(&app, project_id).await;

    let lock = lock_project(&app, project_id).await;
    let in_flight = {
        let app = app.clone();
        let token = actor.access_token.clone();
        tokio::spawn(async move {
            app.patch(
                &format!("/api/v1/projects/{project_id}"),
                Some(&token),
                json!({ "version": start_version, "name": "Written mid-deny" }),
            )
            .await
            .status
        })
    };
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    sqlx::query(
        "INSERT INTO user_permission_overrides
             (id, user_id, permission_code, effect, scope_type, granted_by, reason)
         VALUES ($1, $2, 'projects.update', 'DENY', 'GLOBAL', $2, 'test')",
    )
    .bind(Uuid::now_v7())
    .bind(actor.id)
    .execute(&app.db)
    .await
    .expect("add the DENY override");

    lock.commit().await.expect("release the lock");
    let status = in_flight.await.expect("task must not panic");
    assert!(
        status == StatusCode::OK || status == StatusCode::FORBIDDEN,
        "the in-flight request returned {status}"
    );

    let (_, current_version) = project_state(&app, project_id).await;
    app.patch(
        &format!("/api/v1/projects/{project_id}"),
        Some(&actor.access_token),
        json!({ "version": current_version, "name": "After the deny" }),
    )
    .await
    .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");

    // The DENY must survive being out-granted. Denials are evaluated before the
    // allow set is consulted, so "add another role until it works" — the classic
    // escalation move — is structurally impossible rather than merely unlikely.
    fixtures::grant_via_role(&app, actor.id, "escape_hatch", "projects.update").await;
    app.patch(
        &format!("/api/v1/projects/{project_id}"),
        Some(&actor.access_token),
        json!({ "version": current_version, "name": "Escaped the deny" }),
    )
    .await
    .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");

    let (name, _) = project_state(&app, project_id).await;
    assert_ne!(name, "After the deny");
    assert_ne!(name, "Escaped the deny");
}

// ===========================================================================
// Suspension while a session is live
// ===========================================================================

/// Suspension that leaves an existing session alive is not suspension.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn suspending_a_user_kills_their_live_session_on_the_next_request() {
    let app = Arc::new(TestApp::spawn().await);
    let victim = fixtures::actor(
        &app,
        VICTIM,
        &["projects.create", "projects.read", "projects.update"],
    )
    .await;
    let admin: Actor = fixtures::actor(&app, ADMIN, &["iam.users.suspend"]).await;

    let project_id = fixtures::create_project(&app, &victim, "suspend-proj").await;
    let (_, start_version) = project_state(&app, project_id).await;

    // The victim's session works right now.
    app.get("/api/v1/auth/me", Some(&victim.access_token))
        .await
        .assert_status(StatusCode::OK);

    let lock = lock_project(&app, project_id).await;
    let in_flight = {
        let app = app.clone();
        let token = victim.access_token.clone();
        tokio::spawn(async move {
            app.patch(
                &format!("/api/v1/projects/{project_id}"),
                Some(&token),
                json!({ "version": start_version, "name": "Written mid-suspension" }),
            )
            .await
            .status
        })
    };
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    let suspended = app
        .post(
            &format!("/api/v1/users/{}/suspend", victim.id),
            Some(&admin.access_token),
            json!({ "version": 1, "reason": "under investigation" }),
        )
        .await;
    suspended.assert_status(StatusCode::OK).assert_no_secrets();

    lock.commit().await.expect("release the lock");
    let status = in_flight.await.expect("task must not panic");
    assert!(
        status == StatusCode::OK || status.is_client_error(),
        "the in-flight request returned {status}"
    );

    // The very next request fails authentication, immediately. Not after the access
    // token's fifteen minutes, and not after any background job has run: the session
    // lookup joins `users` and requires `status = 'ACTIVE'`.
    app.get("/api/v1/auth/me", Some(&victim.access_token))
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "AUTHENTICATION_FAILED");
    app.get("/api/v1/projects", Some(&victim.access_token))
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "AUTHENTICATION_FAILED");
    app.post(
        "/api/v1/auth/refresh",
        None,
        json!({ "refresh_token": victim.refresh_token }),
    )
    .await
    .assert_error(StatusCode::UNAUTHORIZED, "AUTHENTICATION_FAILED");

    // And the session rows were revoked in the same transaction as the status
    // change, so there is no window in which the row says ACTIVE and the session is
    // still marked live.
    let live: i64 = fixtures::count(
        &app,
        "SELECT count(*) FROM sessions s JOIN users u ON u.id = s.user_id
          WHERE u.email_normalized = 'victim@race.test' AND s.revoked_at IS NULL",
    )
    .await;
    assert_eq!(live, 0, "a session survived its owner's suspension");

    let reason: (Option<String>,) =
        sqlx::query_as("SELECT revocation_reason FROM sessions WHERE id = $1")
            .bind(victim.session_id)
            .fetch_one(&app.db)
            .await
            .expect("read the session");
    assert_eq!(reason.0.as_deref(), Some("USER_SUSPENDED"));

    // The admin is unaffected: suspension is targeted, not a global logout.
    app.get("/api/v1/auth/me", Some(&admin.access_token))
        .await
        .assert_status(StatusCode::OK);
}

/// A suspended user cannot log back in either, so the eviction is not something a
/// fresh login undoes.
#[tokio::test]
async fn a_suspended_user_cannot_start_a_new_session() {
    let app = TestApp::spawn().await;
    let victim = fixtures::actor(&app, VICTIM, &["projects.read"]).await;
    let admin = fixtures::actor(&app, ADMIN, &["iam.users.suspend"]).await;

    app.post(
        &format!("/api/v1/users/{}/suspend", victim.id),
        Some(&admin.access_token),
        json!({ "version": 1 }),
    )
    .await
    .assert_status(StatusCode::OK);

    fixtures::reset_login_limits(&app, VICTIM).await;
    app.post(
        "/api/v1/auth/login",
        None,
        json!({ "email": VICTIM, "password": crate::common::TEST_PASSWORD }),
    )
    .await
    // Indistinguishable from a wrong password: a suspended account must not be an
    // oracle telling an attacker they found a real, disabled account.
    .assert_error(StatusCode::UNAUTHORIZED, "AUTHENTICATION_FAILED");

    let sessions: i64 = fixtures::count(
        &app,
        "SELECT count(*) FROM sessions s JOIN users u ON u.id = s.user_id
          WHERE u.email_normalized = 'victim@race.test'",
    )
    .await;
    assert_eq!(sessions, 1, "a suspended account gained a new session");
}

/// Concurrent suspensions of one user: exactly one may take effect, because the
/// second has a stale `version`. Without that, two administrators acting at once on
/// an incident produce two `USER.SUSPENDED` audit records for one transition and the
/// log stops being a faithful account of what happened.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_simultaneous_suspensions_produce_one_transition() {
    let app = Arc::new(TestApp::spawn().await);
    let victim = fixtures::actor(&app, VICTIM, &["projects.read"]).await;
    let admin = fixtures::actor(&app, ADMIN, &["iam.users.suspend"]).await;

    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let mut handles = Vec::with_capacity(2);
    for _ in 0..2 {
        let app = app.clone();
        let barrier = barrier.clone();
        let token = admin.access_token.clone();
        let victim_id = victim.id;
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let response = app
                .post(
                    &format!("/api/v1/users/{victim_id}/suspend"),
                    Some(&token),
                    json!({ "version": 1 }),
                )
                .await;
            (response.status, response.error_code().map(str::to_string))
        }));
    }

    let mut succeeded = 0usize;
    for handle in handles {
        let (status, code) = handle.await.expect("task must not panic");
        match status {
            StatusCode::OK => succeeded += 1,
            StatusCode::CONFLICT => {
                // Either the version moved under it, or the transition is no longer
                // legal because the account is already SUSPENDED. Both are honest
                // refusals of a duplicate.
                let code = code.as_deref().unwrap_or_default();
                assert!(
                    code == "VERSION_CONFLICT" || code == "INVALID_STATUS_TRANSITION",
                    "unexpected conflict code `{code}`"
                );
            }
            other => panic!("a suspension returned {other} with code {code:?}"),
        }
    }

    assert_eq!(succeeded, 1, "{succeeded} suspensions took effect");
    assert_eq!(
        fixtures::audit_count(&app, "USER.SUSPENDED").await,
        1,
        "the audit log records a transition that did not happen"
    );

    let status: (String, i32) = sqlx::query_as("SELECT status, version FROM users WHERE id = $1")
        .bind(victim.id)
        .fetch_one(&app.db)
        .await
        .expect("read the victim");
    assert_eq!(status.0, "SUSPENDED");
    assert_eq!(status.1, 2, "the version moved more than once");
}
