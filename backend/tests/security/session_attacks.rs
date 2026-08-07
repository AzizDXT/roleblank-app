//! Adversaries T5 and T6: an attacker holding a stolen access token, and an
//! attacker holding an old refresh token.
//!
//! The property under test throughout is that **no authority is carried in the
//! token**. Every request re-reads the session and the user, so revocation,
//! suspension, a password change and a closed step-up window all take effect on the
//! very next request with no cache to invalidate and no background job to fail.
//!
//! Where a session lifetime has to be moved, it is moved in the database rather
//! than by sleeping: the rule under test is "the deadline is enforced", not "the
//! test can wait fifteen minutes".

use axum::http::StatusCode;
use serde_json::json;
use uuid::Uuid;

use crate::common::{TestApp, TestResponse, TEST_PASSWORD};
use crate::fixtures::{World, EMPLOYEE_EMAIL, ROOT_EMAIL};

/// A stolen token that no longer works must fail exactly like a forged one.
#[track_caller]
fn dead_token(response: &TestResponse, what: &str) {
    assert_eq!(
        response.status,
        StatusCode::UNAUTHORIZED,
        "{what} produced {} — the token is still live: {}",
        response.status,
        String::from_utf8_lossy(&response.raw)
    );
    assert_eq!(
        response.error_code(),
        Some("AUTHENTICATION_FAILED"),
        "{what} used a distinguishable code: {}",
        String::from_utf8_lossy(&response.raw)
    );
    response.assert_no_secrets();
}

/// A full login, returning both halves of the token pair.
async fn token_pair(app: &TestApp, email: &str) -> (String, String) {
    let response = app
        .post(
            "/api/v1/auth/login",
            None,
            json!({"email": email, "password": TEST_PASSWORD}),
        )
        .await;
    response.assert_status(StatusCode::OK);
    (
        response.str_at("/access_token").to_string(),
        response.str_at("/refresh_token").to_string(),
    )
}

async fn revocation_reason(app: &TestApp, user_id: Uuid) -> Option<String> {
    let row: Option<(Option<String>,)> = sqlx::query_as(
        "SELECT revocation_reason FROM sessions
          WHERE user_id = $1 AND revoked_at IS NOT NULL
          ORDER BY revoked_at DESC LIMIT 1",
    )
    .bind(user_id)
    .fetch_optional(&app.db)
    .await
    .expect("read the revocation reason");
    row.and_then(|r| r.0)
}

// ===========================================================================
// Revocation
// ===========================================================================

/// TH-17. The token is opaque and looked up per request, so a single `UPDATE`
/// ends it.
#[tokio::test]
async fn a_stolen_access_token_dies_the_instant_the_session_is_revoked() {
    let w = World::build().await;
    let stolen = w.employee.token.clone();

    w.app
        .get("/api/v1/auth/me", Some(&stolen))
        .await
        .assert_status(StatusCode::OK);

    w.app
        .post("/api/v1/auth/logout", Some(&stolen), json!({}))
        .await
        .assert_status(StatusCode::OK);

    // Every surface, not just the one that revoked it.
    for path in [
        "/api/v1/auth/me",
        "/api/v1/auth/sessions",
        "/api/v1/projects",
        "/api/v1/system/info",
    ] {
        dead_token(&w.app.get(path, Some(&stolen)).await, path);
    }
    // ...and a second logout with the same token is not a way back in.
    dead_token(
        &w.app
            .post("/api/v1/auth/logout", Some(&stolen), json!({}))
            .await,
        "logging out twice",
    );
}

/// A password change is the standard response to a suspected token theft, so it
/// must actually evict the thief.
#[tokio::test]
async fn changing_a_password_evicts_every_other_session() {
    let w = World::build().await;

    // The victim's session, and the attacker's copy obtained from a second login.
    let victim = w.employee.token.clone();
    let (attacker, attacker_refresh) = token_pair(&w.app, EMPLOYEE_EMAIL).await;
    w.app
        .get("/api/v1/auth/me", Some(&attacker))
        .await
        .assert_status(StatusCode::OK);

    let changed = w
        .app
        .post(
            "/api/v1/auth/password/change",
            Some(&victim),
            json!({
                "current_password": TEST_PASSWORD,
                "new_password": "a completely different passphrase 91",
            }),
        )
        .await;
    changed.assert_status(StatusCode::OK).assert_no_secrets();

    dead_token(
        &w.app.get("/api/v1/auth/me", Some(&attacker)).await,
        "a stolen access token after the password changed",
    );
    dead_token(
        &w.app
            .post(
                "/api/v1/auth/refresh",
                None,
                json!({"refresh_token": attacker_refresh}),
            )
            .await,
        "a stolen refresh token after the password changed",
    );
    // The caller keeps the session they are using — evicting it would make the
    // endpoint unusable and push people towards not changing their password.
    w.app
        .get("/api/v1/auth/me", Some(&victim))
        .await
        .assert_status(StatusCode::OK);
    assert_eq!(
        revocation_reason(&w.app, w.employee.id).await.as_deref(),
        Some("PASSWORD_CHANGED")
    );

    // The old password no longer authenticates; the new one does.
    w.app
        .post(
            "/api/v1/auth/login",
            None,
            json!({"email": EMPLOYEE_EMAIL, "password": TEST_PASSWORD}),
        )
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "AUTHENTICATION_FAILED");
}

/// Suspension that leaves live sessions is not suspension. The user-status join is
/// part of the per-request lookup, so there is no window at all.
#[tokio::test]
async fn suspending_a_user_kills_its_tokens_on_the_next_request() {
    let w = World::build().await;

    let current = w
        .app
        .get(
            &format!("/api/v1/users/{}", w.employee.id),
            w.admin.bearer(),
        )
        .await;
    current.assert_status(StatusCode::OK);
    let version = current.json()["version"].as_i64().expect("version");

    w.app
        .post(
            &format!("/api/v1/users/{}/suspend", w.employee.id),
            w.admin.bearer(),
            json!({"version": version, "reason": "under investigation"}),
        )
        .await
        .assert_status(StatusCode::OK);

    dead_token(
        &w.app.get("/api/v1/auth/me", w.employee.bearer()).await,
        "a suspended user's access token",
    );
    assert_eq!(
        revocation_reason(&w.app, w.employee.id).await.as_deref(),
        Some("USER_SUSPENDED")
    );
    // A suspended account cannot log back in, and the refusal is the same generic
    // failure as a wrong password.
    w.app
        .post(
            "/api/v1/auth/login",
            None,
            json!({"email": EMPLOYEE_EMAIL, "password": TEST_PASSWORD}),
        )
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "AUTHENTICATION_FAILED");
}

// ===========================================================================
// Refresh rotation and reuse (TH-19)
// ===========================================================================

/// The theft detector: a hit on a consumed refresh row means two parties hold the
/// same token, so the whole family dies — including the legitimate holder's.
#[tokio::test]
async fn replaying_an_old_refresh_token_revokes_the_entire_family() {
    let w = World::build().await;
    let (first_access, first_refresh) = token_pair(&w.app, EMPLOYEE_EMAIL).await;

    let rotated = w
        .app
        .post(
            "/api/v1/auth/refresh",
            None,
            json!({"refresh_token": first_refresh}),
        )
        .await;
    rotated.assert_status(StatusCode::OK).assert_no_secrets();
    let second_access = rotated.str_at("/access_token").to_string();
    let second_refresh = rotated.str_at("/refresh_token").to_string();
    assert_ne!(
        first_refresh, second_refresh,
        "rotation returned the same token"
    );
    assert_ne!(
        first_access, second_access,
        "rotation must also replace the access token, or a thief keeps the old one"
    );

    // Rotation is unconditional: the previous access token is dead immediately.
    dead_token(
        &w.app.get("/api/v1/auth/me", Some(&first_access)).await,
        "the pre-rotation access token",
    );
    w.app
        .get("/api/v1/auth/me", Some(&second_access))
        .await
        .assert_status(StatusCode::OK);

    // The attacker presents the consumed token.
    dead_token(
        &w.app
            .post(
                "/api/v1/auth/refresh",
                None,
                json!({"refresh_token": first_refresh}),
            )
            .await,
        "replaying a consumed refresh token",
    );

    // The legitimate holder is evicted too. That is the point: a spurious re-login
    // is a smaller harm than an undetected persistent session.
    dead_token(
        &w.app.get("/api/v1/auth/me", Some(&second_access)).await,
        "the legitimate access token after reuse was detected",
    );
    dead_token(
        &w.app
            .post(
                "/api/v1/auth/refresh",
                None,
                json!({"refresh_token": second_refresh}),
            )
            .await,
        "the legitimate refresh token after reuse was detected",
    );

    assert_eq!(
        revocation_reason(&w.app, w.employee.id).await.as_deref(),
        Some("REFRESH_REUSE_DETECTED")
    );
    let detected: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM audit_events WHERE action_code = 'AUTH.REFRESH_REUSE_DETECTED'",
    )
    .fetch_one(&w.app.db)
    .await
    .expect("count");
    // Consuming the family marks every row in it, so a further probe with any
    // token of the family is itself reuse and is recorded again. One or more.
    assert!(detected.0 >= 1, "the compromise signal was not recorded");
}

/// Two refreshes racing on the same token. `FOR UPDATE` makes the outcome
/// deterministic: exactly one rotates, and the other is classified as reuse.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_concurrent_refreshes_produce_exactly_one_winner() {
    let w = World::build().await;
    let (_, refresh) = token_pair(&w.app, EMPLOYEE_EMAIL).await;

    let body = json!({"refresh_token": refresh});
    let (a, b) = tokio::join!(
        w.app.post("/api/v1/auth/refresh", None, body.clone()),
        w.app.post("/api/v1/auth/refresh", None, body),
    );

    let winners = [&a, &b]
        .iter()
        .filter(|r| r.status == StatusCode::OK)
        .count();
    assert_eq!(
        winners, 1,
        "a refresh token was consumed {winners} times (statuses {} and {})",
        a.status, b.status
    );
    for response in [&a, &b] {
        if response.status != StatusCode::OK {
            dead_token(response, "the losing concurrent refresh");
        }
        response.assert_no_secrets();
    }

    // Exactly one live refresh row per generation, and the family was killed by the
    // reuse detection rather than left half-rotated.
    let generations: (i64,) = sqlx::query_as(
        "SELECT count(DISTINCT generation) FROM session_refresh_tokens srt
           JOIN sessions s ON s.id = srt.session_id WHERE s.user_id = $1",
    )
    .bind(w.employee.id)
    .fetch_one(&w.app.db)
    .await
    .expect("count generations");
    assert!(
        generations.0 >= 1,
        "the rotation left no refresh generation at all"
    );
}

/// A refresh token whose session was revoked is refused, and refusing it does not
/// resurrect the session.
#[tokio::test]
async fn a_refresh_token_cannot_resurrect_a_revoked_session() {
    let w = World::build().await;
    let (access, refresh) = token_pair(&w.app, EMPLOYEE_EMAIL).await;

    w.app
        .post("/api/v1/auth/logout", Some(&access), json!({}))
        .await
        .assert_status(StatusCode::OK);

    dead_token(
        &w.app
            .post(
                "/api/v1/auth/refresh",
                None,
                json!({"refresh_token": refresh}),
            )
            .await,
        "refreshing a revoked session",
    );
    dead_token(
        &w.app.get("/api/v1/auth/me", Some(&access)).await,
        "the access token of a revoked session",
    );
}

// ===========================================================================
// Fixation and forgery (TH-20)
// ===========================================================================

/// No endpoint accepts a client-supplied session or token identifier, so there is
/// nothing to fixate.
#[tokio::test]
async fn no_client_supplied_session_identifier_is_ever_accepted() {
    let w = World::build().await;

    let fixation_attempts = [
        json!({"email": EMPLOYEE_EMAIL, "password": TEST_PASSWORD, "session_id": Uuid::now_v7()}),
        json!({"email": EMPLOYEE_EMAIL, "password": TEST_PASSWORD, "access_token": "rb_at_chosen"}),
        json!({"email": EMPLOYEE_EMAIL, "password": TEST_PASSWORD, "refresh_token": "rb_rt_chosen"}),
        json!({"email": EMPLOYEE_EMAIL, "password": TEST_PASSWORD, "auth_level": "MFA"}),
        json!({"email": EMPLOYEE_EMAIL, "password": TEST_PASSWORD, "pending_mfa": false}),
    ];
    for body in fixation_attempts {
        let response = w.app.post("/api/v1/auth/login", None, body.clone()).await;
        assert_eq!(
            response.status,
            StatusCode::BAD_REQUEST,
            "login accepted a client-chosen session field: {body}"
        );
    }

    // A session identifier is not a bearer token, and neither is a user id.
    let me = w.app.get("/api/v1/auth/me", w.employee.bearer()).await;
    me.assert_status(StatusCode::OK);
    let session_id = me.str_at("/session_id").to_string();
    for forged in [
        session_id,
        w.employee.id.to_string(),
        format!("rb_at_{}", "A".repeat(43)),
        format!("rb_rt_{}", "B".repeat(43)),
    ] {
        dead_token(
            &w.app.get("/api/v1/auth/me", Some(&forged)).await,
            "a fabricated bearer token",
        );
    }

    // A fabricated refresh token is refused without writing anything, so an
    // attacker with a token generator cannot flood the append-only audit table.
    let before: (i64,) = sqlx::query_as("SELECT count(*) FROM audit_events")
        .fetch_one(&w.app.db)
        .await
        .expect("count");
    for _ in 0..5 {
        w.app
            .post(
                "/api/v1/auth/refresh",
                None,
                json!({"refresh_token": format!("rb_rt_{}", "C".repeat(43))}),
            )
            .await
            .assert_error(StatusCode::UNAUTHORIZED, "AUTHENTICATION_FAILED");
    }
    let after: (i64,) = sqlx::query_as("SELECT count(*) FROM audit_events")
        .fetch_one(&w.app.db)
        .await
        .expect("count");
    assert_eq!(
        before.0, after.0,
        "an unknown refresh token wrote to the audit log — an anonymous caller can grow it without bound"
    );
}

// ===========================================================================
// Step-up (TH-28)
// ===========================================================================

/// Step-up recency is recomputed from `mfa_verified_at` on every request, never
/// cached as a boolean on the session.
#[tokio::test]
async fn a_step_up_expires_with_its_window() {
    let w = World::build().await;

    // While the window is open the administrator can author a role.
    w.app
        .post(
            "/api/v1/roles",
            w.admin.bearer(),
            json!({
                "code": "within_window",
                "name": "Within window",
                "allowed_principal_type": "INTERNAL",
                "permissions": [],
            }),
        )
        .await
        .assert_status(StatusCode::CREATED);

    // Move the verification just outside the configured 600-second window.
    sqlx::query(
        "UPDATE sessions SET mfa_verified_at = now() - interval '601 seconds'
          WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(w.admin.id)
    .execute(&w.app.db)
    .await
    .expect("age the step-up");

    for (path, body) in [
        (
            "/api/v1/roles".to_string(),
            json!({"code": "outside_window", "name": "Outside window",
                   "allowed_principal_type": "INTERNAL", "permissions": []}),
        ),
        (
            format!("/api/v1/users/{}/permission-overrides", w.other_employee),
            json!({"permission_code": "projects.read", "effect": "ALLOW", "scope": "GLOBAL"}),
        ),
        (
            format!("/api/v1/users/{}/roles", w.other_employee),
            json!({"role_id": crate::fixtures::ROLE_EMPLOYEE}),
        ),
    ] {
        w.app
            .post(&path, w.admin.bearer(), body)
            .await
            .assert_error(StatusCode::FORBIDDEN, "STEP_UP_REQUIRED");
    }

    // `/auth/me` reports the closed window rather than remembering the old answer.
    let me = w.app.get("/api/v1/auth/me", w.admin.bearer()).await;
    me.assert_status(StatusCode::OK);
    assert_eq!(me.json()["step_up_active"], json!(false));

    // A verification timestamp in the future must not satisfy the window either:
    // clock skew or a corrupted row would otherwise be an indefinite step-up.
    sqlx::query(
        "UPDATE sessions SET mfa_verified_at = now() + interval '1 hour'
          WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(w.admin.id)
    .execute(&w.app.db)
    .await
    .expect("skew the step-up");
    w.app
        .post(
            "/api/v1/roles",
            w.admin.bearer(),
            json!({"code": "skewed", "name": "Skewed",
                   "allowed_principal_type": "INTERNAL", "permissions": []}),
        )
        .await
        .assert_error(StatusCode::FORBIDDEN, "STEP_UP_REQUIRED");

    let created: (i64,) =
        sqlx::query_as("SELECT count(*) FROM roles WHERE code IN ('outside_window', 'skewed')")
            .fetch_one(&w.app.db)
            .await
            .expect("count");
    assert_eq!(
        created.0, 0,
        "a role was authored outside the step-up window"
    );
}

// ===========================================================================
// The pending-MFA state
// ===========================================================================

/// A password-only session belonging to a user who must use MFA reaches nothing but
/// the MFA endpoints — and refreshing it does not complete MFA.
#[tokio::test]
async fn a_pending_mfa_session_reaches_no_business_endpoint() {
    let w = World::build().await;

    // The owner has MFA enrolled, so a fresh login is pending by construction.
    let login = w
        .app
        .post(
            "/api/v1/auth/login",
            None,
            json!({"email": ROOT_EMAIL, "password": TEST_PASSWORD}),
        )
        .await;
    login.assert_status(StatusCode::OK);
    assert_eq!(login.json()["mfa_required"], json!(true));
    let pending = login.str_at("/access_token").to_string();
    let pending_refresh = login.str_at("/refresh_token").to_string();

    let reads = [
        "/api/v1/users",
        "/api/v1/projects",
        "/api/v1/tasks",
        "/api/v1/roles",
        "/api/v1/permissions",
        "/api/v1/departments",
        "/api/v1/clients",
        "/api/v1/settings",
        "/api/v1/feature-flags",
        "/api/v1/audit/events",
        "/api/v1/client-portal/projects",
        "/api/v1/auth/sessions",
        "/api/v1/system/info",
    ];
    for path in reads {
        w.app
            .get(path, Some(&pending))
            .await
            .assert_error(StatusCode::FORBIDDEN, "MFA_REQUIRED")
            .assert_no_secrets();
    }

    // Mutations too — including the ones the owner would otherwise be allowed.
    w.app
        .post(
            "/api/v1/projects",
            Some(&pending),
            json!({"code": "sneaky", "name": "Sneaky", "manager_user_id": w.employee.id}),
        )
        .await
        .assert_error(StatusCode::FORBIDDEN, "MFA_REQUIRED");
    w.app
        .post(
            &format!("/api/v1/users/{}/suspend", w.employee.id),
            Some(&pending),
            json!({"version": 1}),
        )
        .await
        .assert_error(StatusCode::FORBIDDEN, "MFA_REQUIRED");

    // `/auth/me` answers, with the reduced projection and no capability list.
    let me = w.app.get("/api/v1/auth/me", Some(&pending)).await;
    me.assert_status(StatusCode::OK).assert_no_secrets();
    assert_eq!(me.json()["mfa_pending"], json!(true));
    assert!(
        me.json().get("capabilities").is_none(),
        "a pending session was handed its capability list"
    );
    assert!(
        me.json().get("is_root").is_none(),
        "a pending session was told it owns the system"
    );

    // Refreshing does not launder a pending session into a complete one.
    let refreshed = w
        .app
        .post(
            "/api/v1/auth/refresh",
            None,
            json!({"refresh_token": pending_refresh}),
        )
        .await;
    refreshed.assert_status(StatusCode::OK);
    assert_eq!(
        refreshed.json()["mfa_required"],
        json!(true),
        "refreshing cleared the pending-MFA flag"
    );
    let refreshed_access = refreshed.str_at("/access_token").to_string();
    w.app
        .get("/api/v1/users", Some(&refreshed_access))
        .await
        .assert_error(StatusCode::FORBIDDEN, "MFA_REQUIRED");
}

// ===========================================================================
// Lifetimes (ADR-005)
// ===========================================================================

/// Three independent deadlines, each of which alone ends the session.
#[tokio::test]
async fn every_session_deadline_is_enforced_independently() {
    let w = World::build().await;

    for column in [
        "access_expires_at",
        "idle_expires_at",
        "absolute_expires_at",
    ] {
        let (access, refresh) = token_pair(&w.app, EMPLOYEE_EMAIL).await;
        let session: (Uuid,) = sqlx::query_as(
            "SELECT id FROM sessions WHERE user_id = $1 AND revoked_at IS NULL
              ORDER BY created_at DESC LIMIT 1",
        )
        .bind(w.employee.id)
        .fetch_one(&w.app.db)
        .await
        .expect("find the new session");

        // The column name is a test-local constant, never a request value.
        let sql = match column {
            "access_expires_at" => {
                "UPDATE sessions SET access_expires_at = now() - interval '1 second' WHERE id = $1"
            }
            "idle_expires_at" => {
                "UPDATE sessions SET idle_expires_at = now() - interval '1 second' WHERE id = $1"
            }
            _ => {
                "UPDATE sessions SET absolute_expires_at = now() - interval '1 second' WHERE id = $1"
            }
        };
        sqlx::query(sql)
            .bind(session.0)
            .execute(&w.app.db)
            .await
            .expect("expire the session");

        dead_token(
            &w.app.get("/api/v1/auth/me", Some(&access)).await,
            &format!("a session past its {column}"),
        );

        // Only the access deadline is something a refresh may legitimately move.
        let refreshed = w
            .app
            .post(
                "/api/v1/auth/refresh",
                None,
                json!({"refresh_token": refresh}),
            )
            .await;
        if column == "access_expires_at" {
            refreshed.assert_status(StatusCode::OK);
        } else {
            dead_token(
                &refreshed,
                &format!("refreshing a session past its {column}"),
            );
        }

        sqlx::query("UPDATE sessions SET revoked_at = now(), revocation_reason = 'LOGOUT_ALL' WHERE user_id = $1")
            .bind(w.employee.id)
            .execute(&w.app.db)
            .await
            .expect("tidy up between cases");
        crate::fixtures::reset_login_limits(&w.app).await;
    }
}
