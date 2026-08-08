//! Adversary T4: a malicious administrator who wants ROOT.
//!
//! The administrator here is deliberately over-equipped. It holds the whole
//! built-in `system_administrator` role **plus** an explicit
//! `iam.permissions.delegate@GLOBAL` override, and it holds a recent second factor.
//! Nothing it is refused below is refused for want of a permission or a step-up —
//! every refusal is the ownership invariant itself (ADR-004, TH-04..TH-07).
//!
//! The final assertion of most tests is the database, not the status code: a `403`
//! that still wrote the row would be worse than no check at all.

use axum::http::StatusCode;
use serde_json::json;
use uuid::Uuid;

use crate::common::TestApp;
use crate::fixtures::{login, reset_login_limits, World, ROLE_EMPLOYEE, ROOT_EMAIL};
use roleblank_backend::platform::http::rate_limit::keys;

/// The owner's row and the ownership record, exactly as they must remain.
async fn assert_ownership_intact(app: &TestApp, root_id: uuid::Uuid) {
    let owners: (i64,) = sqlx::query_as("SELECT count(*) FROM system_ownership")
        .fetch_one(&app.db)
        .await
        .expect("count owners");
    assert_eq!(owners.0, 1, "the number of system owners changed");

    let owner: (uuid::Uuid,) = sqlx::query_as("SELECT root_user_id FROM system_ownership")
        .fetch_one(&app.db)
        .await
        .expect("read ownership");
    assert_eq!(owner.0, root_id, "ownership moved to another account");

    let row: (String, bool, String) =
        sqlx::query_as("SELECT status, mfa_required, principal_type FROM users WHERE id = $1")
            .bind(root_id)
            .fetch_one(&app.db)
            .await
            .expect("read the owner");
    assert_eq!(row.0, "ACTIVE", "the owner is no longer ACTIVE");
    assert!(row.1, "MFA was made optional for the owner");
    assert_eq!(row.2, "INTERNAL", "the owner was moved across the envelope");
}

// ===========================================================================
// Lifecycle
// ===========================================================================

/// TH-04. Every lifecycle operation an administrator has, aimed at the owner.
#[tokio::test]
async fn an_administrator_cannot_suspend_archive_or_edit_the_owner() {
    let w = World::build().await;

    let vectors: Vec<(&str, String, serde_json::Value)> = vec![
        (
            "PATCH",
            format!("/api/v1/users/{}", w.root.id),
            json!({"version": 1, "display_name": "Not the owner any more"}),
        ),
        (
            "PATCH",
            format!("/api/v1/users/{}", w.root.id),
            json!({"version": 1, "email": "attacker@evil.test"}),
        ),
        (
            "POST",
            format!("/api/v1/users/{}/suspend", w.root.id),
            json!({"version": 1, "reason": "housekeeping"}),
        ),
        (
            "POST",
            format!("/api/v1/users/{}/archive", w.root.id),
            json!({"version": 1, "reason": "left the company"}),
        ),
        (
            "POST",
            format!("/api/v1/users/{}/reactivate", w.root.id),
            json!({"version": 1}),
        ),
    ];

    for (method, path, body) in vectors {
        let response = match method {
            "PATCH" => w.app.patch(&path, w.admin.bearer(), body).await,
            _ => w.app.post(&path, w.admin.bearer(), body).await,
        };
        response
            .assert_error(StatusCode::FORBIDDEN, "ROOT_PROTECTED")
            .assert_no_secrets();
    }

    assert_ownership_intact(&w.app, w.root.id).await;
}

/// The refusal must not depend on who is asking: the owner is refused the same
/// operations on itself, so there is no "I was only tidying up my own account"
/// path to a suspended owner.
#[tokio::test]
async fn the_owner_cannot_disable_itself_either() {
    let w = World::build().await;

    for (path, body) in [
        (
            format!("/api/v1/users/{}/suspend", w.root.id),
            json!({"version": 1}),
        ),
        (
            format!("/api/v1/users/{}/archive", w.root.id),
            json!({"version": 1}),
        ),
    ] {
        w.app
            .post(&path, w.root.bearer(), body)
            .await
            .assert_error(StatusCode::FORBIDDEN, "ROOT_PROTECTED");
    }
    w.app
        .patch(
            &format!("/api/v1/users/{}", w.root.id),
            w.root.bearer(),
            json!({"version": 1, "display_name": "Renamed"}),
        )
        .await
        .assert_error(StatusCode::FORBIDDEN, "ROOT_PROTECTED");

    assert_ownership_intact(&w.app, w.root.id).await;
}

/// There is no `DELETE /users/{id}` at all — accounts are archived, never removed.
#[tokio::test]
async fn there_is_no_route_that_deletes_a_user() {
    let w = World::build().await;

    for target in [w.root.id, w.employee.id] {
        let response = w
            .app
            .delete(&format!("/api/v1/users/{target}"), w.admin.bearer())
            .await;
        assert_eq!(
            response.status,
            StatusCode::METHOD_NOT_ALLOWED,
            "DELETE /users/{{id}} exists"
        );
    }

    let users: (i64,) = sqlx::query_as("SELECT count(*) FROM users")
        .fetch_one(&w.app.db)
        .await
        .expect("count");
    assert_eq!(users.0, 7, "the user population changed");
}

// ===========================================================================
// Authority
// ===========================================================================

/// Rule 4 of the delegation guard: ROOT is never a valid target of an
/// authorisation operation, for any actor including ROOT itself.
#[tokio::test]
async fn no_authorisation_operation_may_target_the_owner() {
    let w = World::build().await;

    // Assigning a role to the owner.
    w.app
        .post(
            &format!("/api/v1/users/{}/roles", w.root.id),
            w.admin.bearer(),
            json!({"role_id": ROLE_EMPLOYEE}),
        )
        .await
        .assert_error(StatusCode::FORBIDDEN, "ROOT_PROTECTED");

    // Taking one away — a reduction of authority is still authority over the owner.
    w.app
        .delete(
            &format!("/api/v1/users/{}/roles/{}", w.root.id, ROLE_EMPLOYEE),
            w.admin.bearer(),
        )
        .await
        .assert_error(StatusCode::FORBIDDEN, "ROOT_PROTECTED");

    // A DENY override on the owner would be a lock-out with extra steps.
    for effect in ["ALLOW", "DENY"] {
        w.app
            .post(
                &format!("/api/v1/users/{}/permission-overrides", w.root.id),
                w.admin.bearer(),
                json!({"permission_code": "audit.read", "effect": effect, "scope": "GLOBAL"}),
            )
            .await
            .assert_error(StatusCode::FORBIDDEN, "ROOT_PROTECTED");
    }

    // ...and the owner may not do it to itself.
    w.app
        .post(
            &format!("/api/v1/users/{}/permission-overrides", w.root.id),
            w.root.bearer(),
            json!({"permission_code": "audit.read", "effect": "DENY", "scope": "GLOBAL"}),
        )
        .await
        .assert_error(StatusCode::FORBIDDEN, "ROOT_PROTECTED");

    let overrides: (i64,) =
        sqlx::query_as("SELECT count(*) FROM user_permission_overrides WHERE user_id = $1")
            .bind(w.root.id)
            .fetch_one(&w.app.db)
            .await
            .expect("count");
    assert_eq!(overrides.0, 0, "an override was created on the owner");

    let assignments: (i64,) =
        sqlx::query_as("SELECT count(*) FROM user_role_assignments WHERE user_id = $1")
            .bind(w.root.id)
            .fetch_one(&w.app.db)
            .await
            .expect("count");
    assert_eq!(assignments.0, 0, "a role was attached to the owner");

    assert_ownership_intact(&w.app, w.root.id).await;
}

/// TH-06. Session revocation is an availability weapon. `DELETE /auth/sessions/{id}`
/// is scoped to the caller in the `UPDATE` itself, so an administrator holding the
/// owner's session identifier gets a `404` and the owner keeps working.
#[tokio::test]
async fn an_administrator_cannot_revoke_the_owners_sessions() {
    let w = World::build().await;

    let me = w.app.get("/api/v1/auth/me", w.root.bearer()).await;
    me.assert_status(StatusCode::OK);
    let root_session = me.id_at("/session_id");

    w.app
        .delete(
            &format!("/api/v1/auth/sessions/{root_session}"),
            w.admin.bearer(),
        )
        .await
        .assert_error(StatusCode::NOT_FOUND, "RESOURCE_NOT_FOUND");

    // `logout-all` is self-scoped, so an administrator calling it evicts only itself.
    w.app
        .post("/api/v1/auth/logout-all", w.admin.bearer(), json!({}))
        .await
        .assert_status(StatusCode::OK);

    w.app
        .get("/api/v1/auth/me", w.root.bearer())
        .await
        .assert_status(StatusCode::OK);

    let live: (i64,) =
        sqlx::query_as("SELECT count(*) FROM sessions WHERE user_id = $1 AND revoked_at IS NULL")
            .bind(w.root.id)
            .fetch_one(&w.app.db)
            .await
            .expect("count");
    assert_eq!(live.0, 1, "the owner's session was revoked");
}

/// There is no route that writes `system_ownership`, so there is no request that
/// can mint a second owner however it is shaped.
#[tokio::test]
async fn ownership_cannot_be_established_through_any_route() {
    let w = World::build().await;

    // Bootstrap is permanently closed once initialised, whoever asks.
    for token in [None, w.admin.bearer(), w.root.bearer()] {
        w.app
            .post(
                "/api/v1/bootstrap/root",
                token,
                json!({
                    "bootstrap_secret": crate::common::TEST_BOOTSTRAP_SECRET,
                    "email": "second-owner@evil.test",
                    "display_name": "Second Owner",
                    "password": crate::common::TEST_PASSWORD,
                }),
            )
            .await
            .assert_error(StatusCode::CONFLICT, "SYSTEM_ALREADY_INITIALIZED");
    }

    // An invitation cannot confer ownership either: there is no field for it, and a
    // role cannot carry it because ownership is not a permission.
    let invited = w
        .app
        .post(
            "/api/v1/invitations",
            w.admin.bearer(),
            json!({
                "email": "heir@evil.test",
                "display_name": "Heir",
                "principal_type": "INTERNAL",
                "role_ids": [],
                "is_root": true,
            }),
        )
        .await;
    invited.assert_error(StatusCode::BAD_REQUEST, "BAD_REQUEST");

    assert_ownership_intact(&w.app, w.root.id).await;
}

// ===========================================================================
// Availability
// ===========================================================================

/// TH-07. Failed logins must throttle the owner, never lock the account.
///
/// A permanent lock would hand any anonymous attacker a denial of service against
/// the one account that cannot be restored by anybody else.
#[tokio::test]
async fn the_owner_cannot_be_locked_out_by_failed_logins() {
    let w = World::build().await;

    let mut throttled = 0;
    for _ in 0..25 {
        let response = w
            .app
            .post(
                "/api/v1/auth/login",
                None,
                json!({"email": ROOT_EMAIL, "password": "not the owner's password"}),
            )
            .await;
        match response.status {
            StatusCode::UNAUTHORIZED => {
                assert_eq!(response.error_code(), Some("AUTHENTICATION_FAILED"));
            }
            StatusCode::TOO_MANY_REQUESTS => {
                throttled += 1;
                assert_eq!(response.error_code(), Some("RATE_LIMITED"));
                assert!(
                    response.headers.contains_key("retry-after"),
                    "a throttled login must say when to retry"
                );
            }
            other => panic!("a failed login produced {other}"),
        }
        response.assert_no_secrets();
    }
    assert!(
        throttled > 0,
        "the attack was not throttled at all — the limiter is not engaged"
    );

    // The account itself is untouched: no lock column, no status change, no
    // revoked sessions. Throttling is the *only* effect.
    assert_ownership_intact(&w.app, w.root.id).await;
    let live: (i64,) =
        sqlx::query_as("SELECT count(*) FROM sessions WHERE user_id = $1 AND revoked_at IS NULL")
            .bind(w.root.id)
            .fetch_one(&w.app.db)
            .await
            .expect("count");
    assert_eq!(live.0, 1, "failed logins revoked the owner's live session");

    // Once the buckets refill, the owner logs in normally. Resetting them is the
    // test's stand-in for waiting a minute, and it proves the limiter is the whole
    // of the barrier — there is nothing else to unlock.
    reset_login_limits(&w.app).await;
    let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
    w.app.state.limiter.reset(&keys::login_ip(ip)).await;

    let token = login(&w.app, ROOT_EMAIL).await;
    assert!(token.starts_with("rb_at_"));
}

// ===========================================================================
// The record
// ===========================================================================

/// An attempt on the owner is exactly the event an intrusion-detection feed wants,
/// so the refusal is committed even though the transaction it lived in failed.
#[tokio::test]
async fn every_attempt_on_the_owner_is_recorded_and_the_record_cannot_be_erased() {
    let w = World::build().await;

    w.app
        .post(
            &format!("/api/v1/users/{}/suspend", w.root.id),
            w.admin.bearer(),
            json!({"version": 1}),
        )
        .await
        .assert_error(StatusCode::FORBIDDEN, "ROOT_PROTECTED");
    w.app
        .post(
            &format!("/api/v1/users/{}/roles", w.root.id),
            w.admin.bearer(),
            json!({"role_id": ROLE_EMPLOYEE}),
        )
        .await
        .assert_error(StatusCode::FORBIDDEN, "ROOT_PROTECTED");

    let recorded: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM audit_events
          WHERE action_code = 'ROOT.PROTECTION_TRIGGERED' AND actor_user_id = $1",
    )
    .bind(w.admin.id)
    .fetch_one(&w.app.db)
    .await
    .expect("count root protection events");
    assert!(
        recorded.0 >= 2,
        "attempts on the owner were not committed to the audit log (found {})",
        recorded.0
    );

    // TH-29: there is no route that can remove them.
    for path in ["/api/v1/audit/events", "/api/v1/audit/events/x"] {
        let response = w.app.delete(path, w.admin.bearer()).await;
        assert!(
            response.status == StatusCode::METHOD_NOT_ALLOWED
                || response.status == StatusCode::NOT_FOUND,
            "DELETE {path} produced {} — the audit log has a mutating route",
            response.status
        );
    }
    let attempted_write = w
        .app
        .post("/api/v1/audit/events", w.admin.bearer(), json!({}))
        .await;
    assert_eq!(
        attempted_write.status,
        StatusCode::METHOD_NOT_ALLOWED,
        "an audit event can be appended through the API"
    );

    // ...and the runtime database role could not do it either.
    let runtime = w.app.runtime_role_pool().await;
    let deleted = sqlx::query("DELETE FROM audit_events")
        .execute(&runtime)
        .await;
    assert!(
        deleted.is_err(),
        "the runtime database role deleted audit rows"
    );
    let updated = sqlx::query("UPDATE audit_events SET outcome = 'SUCCESS'")
        .execute(&runtime)
        .await;
    assert!(
        updated.is_err(),
        "the runtime database role rewrote audit rows"
    );
}

/// Regression: the department membership routes must not identify the owner to an
/// external principal.
///
/// `guard_root` answers `403 ROOT_PROTECTED`; every other subject id on this route
/// answers `404` to a CLIENT, because `departments.*` is INTERNAL-only and
/// `require` masks the refusal. While the guard ran *before* authorisation, the
/// difference between those two answers was a usable oracle: it confirmed the
/// system owner's user id — and that internal users exist at all — to a principal
/// outside the company, which is the client envelope (threat-model boundary 2)
/// losing to a diagnostic nicety.
///
/// Both answers must now be indistinguishable. The owner is of course still
/// refused; that is asserted from an internal principal below.
#[tokio::test]
async fn the_department_routes_do_not_identify_the_owner_to_a_client() {
    let w = World::build().await;
    let stranger = Uuid::now_v7();

    for (label, subject) in [("the owner", w.root.id), ("an unknown user", stranger)] {
        let response = w
            .app
            .post(
                &format!("/api/v1/departments/{}/members", w.department),
                w.client_a.bearer(),
                json!({"user_id": subject}),
            )
            .await;
        response.assert_error(StatusCode::NOT_FOUND, "RESOURCE_NOT_FOUND");
        let _ = label;

        let removed = w
            .app
            .delete(
                &format!("/api/v1/departments/{}/members/{subject}", w.department),
                w.client_a.bearer(),
            )
            .await;
        removed.assert_error(StatusCode::NOT_FOUND, "RESOURCE_NOT_FOUND");
    }

    // The protection itself is intact: an internal principal that *is* allowed to
    // manage members still cannot touch the owner, and still gets the unmistakable
    // refusal the documentation promises internal callers.
    w.app
        .post(
            &format!("/api/v1/departments/{}/members", w.department),
            w.admin.bearer(),
            json!({"user_id": w.root.id}),
        )
        .await
        .assert_error(StatusCode::FORBIDDEN, "ROOT_PROTECTED");
}
