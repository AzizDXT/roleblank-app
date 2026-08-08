//! §6 — attacking authentication: passwords, second factors and sessions.
//!
//! `session_attacks.rs` covers the session lifecycle. This suite covers the three
//! things that file does not:
//!
//!   * the **password surface** as an enumeration oracle — every malformed,
//!     oversized, empty and Unicode variant must be indistinguishable from a plain
//!     wrong password, on status, on `code` and on the rendered body;
//!   * the **second factor** as a replayable credential — a TOTP code and a
//!     recovery code are each usable exactly once, and MFA cannot be taken off an
//!     account by a session that has not proved possession recently;
//!   * **privilege freshness** — the single most important property in this file,
//!     and the last test below: a change to a user's authority must take effect on
//!     the very next request that session makes, with no re-login and no waiting
//!     for a token to expire.
//!
//! Rate limiters are reset explicitly wherever a test needs to make more than a
//! handful of attempts, so that a refusal is the control under test rather than
//! the fixture's own budget running out.

use axum::http::StatusCode;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::common::{TestApp, TestResponse, TEST_PASSWORD};
use crate::fixtures::{
    grant_override, login, password_hash, seed_user, totp_code_at_offset, World, ROLE_EMPLOYEE,
};
use roleblank_backend::platform::http::rate_limit::keys;

// ===========================================================================
// Shared assertions
// ===========================================================================

/// The single, deliberately undifferentiated authentication failure.
#[track_caller]
fn auth_failed(response: &TestResponse, what: &str) {
    assert_eq!(
        response.status,
        StatusCode::UNAUTHORIZED,
        "{what} produced {} rather than the generic authentication failure: {}",
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

/// A problem body with the correlation id removed.
///
/// `request_id` is the one field that legitimately differs between two otherwise
/// identical responses, so it is stripped before comparison. Everything else —
/// `type`, `title`, `status`, `code`, `detail`, any `errors` array — must match
/// exactly, because any difference at all is a signal an attacker can read.
fn comparable(response: &TestResponse) -> Value {
    let mut body = response.json().clone();
    if let Some(object) = body.as_object_mut() {
        object.remove("request_id");
    }
    body
}

/// Reset every limiter that a login-shaped attack consumes.
async fn reset_login_budget(app: &TestApp, emails: &[&str]) {
    let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
    app.state.limiter.reset(&keys::login_ip(ip)).await;
    for email in emails {
        app.state
            .limiter
            .reset(&keys::login_account(&email.to_lowercase()))
            .await;
    }
}

async fn reset_mfa_budget(app: &TestApp, session_id: Uuid, user_id: Uuid) {
    app.state
        .limiter
        .reset(&keys::mfa_session(session_id))
        .await;
    app.state.limiter.reset(&keys::mfa_account(user_id)).await;
}

/// Enrol TOTP and **return the secret**, which the fixture helper discards.
///
/// Several tests below need to compute a code for a chosen step rather than for
/// "now", which is what makes the replay assertions deterministic.
async fn enrol_and_keep_secret(app: &TestApp, token: &str) -> String {
    let enrol = app
        .post("/api/v1/auth/mfa/totp/setup", Some(token), json!({}))
        .await;
    assert!(
        enrol.status.is_success(),
        "TOTP enrolment failed: {}",
        String::from_utf8_lossy(&enrol.raw)
    );
    let secret = enrol.str_at("/secret").to_string();

    // Activation consumes exactly the step it matched. Every later code in this
    // file is computed at offset +1, which is inside the ±1 skew window the server
    // accepts and is strictly greater than the consumed watermark — so it is
    // reliably valid and reliably unconsumed, whatever the clock is doing.
    let activated = app
        .post(
            "/api/v1/auth/mfa/totp/activate",
            Some(token),
            json!({"code": totp_code_at_offset(&secret, 0)}),
        )
        .await;
    assert!(
        activated.status.is_success(),
        "TOTP activation failed: {}",
        String::from_utf8_lossy(&activated.raw)
    );
    secret
}

/// The recovery codes minted by an activation.
async fn enrol_and_keep_recovery_codes(app: &TestApp, token: &str) -> (String, Vec<String>) {
    let enrol = app
        .post("/api/v1/auth/mfa/totp/setup", Some(token), json!({}))
        .await;
    enrol.assert_status(StatusCode::CREATED);
    let secret = enrol.str_at("/secret").to_string();

    let activated = app
        .post(
            "/api/v1/auth/mfa/totp/activate",
            Some(token),
            json!({"code": totp_code_at_offset(&secret, 0)}),
        )
        .await;
    assert!(activated.status.is_success(), "TOTP activation failed");
    let codes = activated
        .json()
        .pointer("/recovery_codes/codes")
        .and_then(Value::as_array)
        .expect("activation must return recovery codes")
        .iter()
        .filter_map(|c| c.as_str().map(str::to_string))
        .collect::<Vec<_>>();
    assert!(!codes.is_empty(), "no recovery codes were issued");
    (secret, codes)
}

// ===========================================================================
// Passwords
// ===========================================================================

/// TH-23. Nine ways of getting a password wrong, and one account that does not
/// exist. Every one of them must render **the same bytes**.
///
/// Comparing only the status code would miss the two ways this actually leaks in
/// practice: a `detail` that says "no such user", and a `VALIDATION_FAILED` on one
/// input shape but `AUTHENTICATION_FAILED` on another — which tells an attacker
/// which shapes reached the account lookup.
#[tokio::test]
async fn no_password_failure_mode_is_distinguishable_from_any_other() {
    let w = World::build().await;
    let real = w.employee.email.clone();

    let attempts: Vec<(&str, String, String)> = vec![
        ("wrong password", real.clone(), "not the password".into()),
        (
            "nonexistent account, wrong password",
            "ghost@fixture.test".into(),
            "not the password".into(),
        ),
        (
            "nonexistent account, the real password",
            "ghost@fixture.test".into(),
            TEST_PASSWORD.into(),
        ),
        ("empty password", real.clone(), String::new()),
        (
            "empty password, nonexistent account",
            "ghost@fixture.test".into(),
            String::new(),
        ),
        // Long enough to be past any sane policy ceiling but not past the body
        // limit, so it reaches the handler rather than the transport.
        ("very long password", real.clone(), "a".repeat(4096)),
        (
            "very long password, nonexistent account",
            "ghost@fixture.test".into(),
            "a".repeat(4096),
        ),
        // Multi-byte, combining marks, RTL override and an astral-plane emoji: a
        // password field that counts bytes rather than characters, or that
        // normalises Unicode, behaves differently here than on ASCII.
        (
            "Unicode password",
            real.clone(),
            "пароль-ではありません-\u{202E}-🔐\u{0301}".into(),
        ),
        (
            "Unicode password, nonexistent account",
            "ghost@fixture.test".into(),
            "пароль-ではありません-\u{202E}-🔐\u{0301}".into(),
        ),
        (
            "the right password with a NUL appended",
            real.clone(),
            format!("{TEST_PASSWORD}\u{0}"),
        ),
        (
            "the right password with trailing whitespace",
            real.clone(),
            format!("{TEST_PASSWORD} "),
        ),
    ];

    let mut baseline: Option<(StatusCode, Value)> = None;
    for (label, email, password) in attempts {
        reset_login_budget(&w.app, &[&real, "ghost@fixture.test"]).await;
        let response = w
            .app
            .post(
                "/api/v1/auth/login",
                None,
                json!({"email": email, "password": password}),
            )
            .await;
        auth_failed(&response, label);

        let observed = (response.status, comparable(&response));
        match &baseline {
            None => baseline = Some(observed),
            Some(expected) => assert_eq!(
                &observed, expected,
                "`{label}` is distinguishable from the other failures — \
                 this is an account-enumeration oracle"
            ),
        }
    }
}

/// The email side of the same oracle, plus the request shapes that never reach the
/// account lookup at all.
///
/// A malformed payload is allowed to be a `400` — it is a different *class* of
/// answer, and the attacker learns nothing about accounts from it. What must not
/// happen is a `400` for one address and a `401` for another, which would identify
/// the address rather than the payload.
///
/// Named rather than written inline so the intent — "build a login body from an
/// address" — survives, and so the list below stays readable as a table.
type LoginBodyShape = fn(&str) -> Value;

#[tokio::test]
async fn a_malformed_or_oversized_login_reveals_nothing_about_the_account() {
    let w = World::build().await;
    let real = w.employee.email.clone();

    // Shapes that never reach a lookup. Each is sent with a real and a fake
    // address, and the two answers must agree.
    let shapes: Vec<(&str, LoginBodyShape)> = vec![
        ("missing password field", |e| json!({"email": e})),
        ("null password", |e| json!({"email": e, "password": null})),
        (
            "numeric password",
            |e| json!({"email": e, "password": 12345}),
        ),
        ("array password", |e| json!({"email": e, "password": ["a"]})),
        (
            "object password",
            |e| json!({"email": e, "password": {"$ne": ""}}),
        ),
        (
            "extra privileged field",
            |e| json!({"email": e, "password": "x", "is_root": true}),
        ),
        (
            "extra role field",
            |e| json!({"email": e, "password": "x", "role_ids": ["00000000-0000-7000-8000-000000000001"]}),
        ),
    ];

    for (label, build) in shapes {
        reset_login_budget(&w.app, &[&real, "ghost@fixture.test"]).await;
        let against_real = w.app.post("/api/v1/auth/login", None, build(&real)).await;
        reset_login_budget(&w.app, &[&real, "ghost@fixture.test"]).await;
        let against_ghost = w
            .app
            .post("/api/v1/auth/login", None, build("ghost@fixture.test"))
            .await;

        assert_eq!(
            against_real.status, against_ghost.status,
            "`{label}` answered differently for a real and a fake address"
        );
        assert_eq!(
            comparable(&against_real),
            comparable(&against_ghost),
            "`{label}` produced a distinguishable body for a real address"
        );
        against_real.assert_no_secrets();
    }

    // An oversized body is refused at the transport, before the handler and before
    // any account lookup — so it cannot be an oracle by construction.
    let huge = json!({"email": real, "password": "z".repeat(400_000)});
    let oversized = w.app.post("/api/v1/auth/login", None, huge).await;
    oversized.assert_error(StatusCode::PAYLOAD_TOO_LARGE, "PAYLOAD_TOO_LARGE");
    oversized.assert_no_secrets();
}

/// The reset request is the other place an address can be confirmed.
#[tokio::test]
async fn requesting_a_password_reset_never_confirms_an_address() {
    let w = World::build().await;

    let real = w
        .app
        .post(
            "/api/v1/auth/password-reset/request",
            None,
            json!({"email": w.employee.email}),
        )
        .await;
    let fake = w
        .app
        .post(
            "/api/v1/auth/password-reset/request",
            None,
            json!({"email": "ghost@fixture.test"}),
        )
        .await;

    real.assert_status(StatusCode::ACCEPTED);
    fake.assert_status(StatusCode::ACCEPTED);
    assert_eq!(
        real.raw, fake.raw,
        "the reset request distinguishes a real address from a fake one"
    );

    // Only the real address actually queued anything — the difference is on the
    // server side, where the attacker cannot see it.
    let queued: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM outbox_events WHERE event_type = 'mail.password_reset'",
    )
    .fetch_one(&w.app.db)
    .await
    .expect("count queued mail");
    assert_eq!(
        queued.0, 1,
        "the reset flow queued the wrong number of mails"
    );
}

// ===========================================================================
// The second factor
// ===========================================================================

/// A wrong code never completes MFA, and the failure is the same generic one.
#[tokio::test]
async fn a_wrong_totp_code_never_completes_mfa() {
    let w = World::build().await;
    let hash = password_hash(&w.app).await;
    let user = seed_user(&w.app, "totp@fixture.test", "INTERNAL", &hash).await;
    let token = login(&w.app, "totp@fixture.test").await;
    let secret = enrol_and_keep_secret(&w.app, &token).await;

    let session: (Uuid,) = sqlx::query_as("SELECT id FROM sessions WHERE user_id = $1")
        .bind(user)
        .fetch_one(&w.app.db)
        .await
        .expect("the session");

    for code in [
        "000000", "999999", "12345", "1234567", "abcdef", "", "  1234",
    ] {
        reset_mfa_budget(&w.app, session.0, user).await;
        auth_failed(
            &w.app
                .post(
                    "/api/v1/auth/mfa/verify",
                    Some(&token),
                    json!({"code": code}),
                )
                .await,
            &format!("verifying with `{code}`"),
        );
    }

    // The control: a genuine code still works, so the refusals above are about the
    // code and not about the endpoint being broken.
    reset_mfa_budget(&w.app, session.0, user).await;
    w.app
        .post(
            "/api/v1/auth/mfa/verify",
            Some(&token),
            json!({"code": totp_code_at_offset(&secret, 1)}),
        )
        .await
        .assert_status(StatusCode::OK);
}

/// Guessing is bounded per session **and** per account. A per-session limit alone
/// is escaped by logging in again; a per-account limit alone lets one compromised
/// session burn another's budget.
#[tokio::test]
async fn repeated_second_factor_guesses_are_throttled_rather_than_ignored() {
    let w = World::build().await;
    let hash = password_hash(&w.app).await;
    seed_user(&w.app, "guess@fixture.test", "INTERNAL", &hash).await;
    let token = login(&w.app, "guess@fixture.test").await;
    let _secret = enrol_and_keep_secret(&w.app, &token).await;

    let mut throttled = 0;
    for n in 0..12 {
        let response = w
            .app
            .post(
                "/api/v1/auth/mfa/verify",
                Some(&token),
                json!({"code": format!("{:06}", n)}),
            )
            .await;
        match response.status {
            StatusCode::UNAUTHORIZED => {
                assert_eq!(response.error_code(), Some("AUTHENTICATION_FAILED"))
            }
            StatusCode::TOO_MANY_REQUESTS => {
                throttled += 1;
                assert_eq!(response.error_code(), Some("RATE_LIMITED"));
                assert!(
                    response.headers.contains_key("retry-after"),
                    "a throttled second factor must say when to retry"
                );
            }
            other => panic!("a wrong TOTP code produced {other}"),
        }
        response.assert_no_secrets();
    }
    assert!(
        throttled > 0,
        "twelve wrong second-factor codes were not throttled at all"
    );
}

/// A code is single use. Presenting a correct one twice is evidence of
/// interception, and is audited as such while telling the client nothing.
#[tokio::test]
async fn a_consumed_totp_code_cannot_be_replayed() {
    let w = World::build().await;
    let hash = password_hash(&w.app).await;
    let user = seed_user(&w.app, "replay@fixture.test", "INTERNAL", &hash).await;
    let token = login(&w.app, "replay@fixture.test").await;
    let secret = enrol_and_keep_secret(&w.app, &token).await;

    // Offset +1: inside the accepted skew window and strictly past the watermark
    // activation left behind, so the first presentation is reliably valid.
    let code = totp_code_at_offset(&secret, 1);

    w.app
        .post(
            "/api/v1/auth/mfa/verify",
            Some(&token),
            json!({"code": &code}),
        )
        .await
        .assert_status(StatusCode::OK);

    // The identical code, milliseconds later, from the same session.
    auth_failed(
        &w.app
            .post(
                "/api/v1/auth/mfa/verify",
                Some(&token),
                json!({"code": &code}),
            )
            .await,
        "replaying a consumed TOTP code",
    );

    // ...and from a *different* session of the same user, which is the interception
    // case that matters: the watermark is on the factor, not on the session.
    let second_token = login(&w.app, "replay@fixture.test").await;
    auth_failed(
        &w.app
            .post(
                "/api/v1/auth/mfa/verify",
                Some(&second_token),
                json!({"code": &code}),
            )
            .await,
        "replaying a consumed TOTP code from another session",
    );

    let replays: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM audit_events
          WHERE action_code = 'MFA.REPLAY_DETECTED' AND actor_user_id = $1",
    )
    .bind(user)
    .fetch_one(&w.app.db)
    .await
    .expect("count replay events");
    assert!(
        replays.0 >= 2,
        "a replayed code was refused but not recorded as a replay (found {})",
        replays.0
    );

    // The watermark never moves backwards, so the replay window cannot be reopened.
    let watermark: (Option<i64>,) =
        sqlx::query_as("SELECT last_used_step FROM mfa_factors WHERE user_id = $1")
            .bind(user)
            .fetch_one(&w.app.db)
            .await
            .expect("read the watermark");
    assert!(
        watermark.0.is_some(),
        "the replay watermark was never established"
    );
}

/// Recovery codes are single-use bypass credentials. The second presentation of
/// one must fail exactly like a wrong one.
#[tokio::test]
async fn a_recovery_code_cannot_be_used_twice() {
    let w = World::build().await;
    let hash = password_hash(&w.app).await;
    let user = seed_user(&w.app, "recovery@fixture.test", "INTERNAL", &hash).await;
    let token = login(&w.app, "recovery@fixture.test").await;
    let (_secret, codes) = enrol_and_keep_recovery_codes(&w.app, &token).await;

    let first_use = w
        .app
        .post(
            "/api/v1/auth/mfa/recovery/verify",
            Some(&token),
            json!({"code": codes[0]}),
        )
        .await;
    first_use.assert_status(StatusCode::OK);
    let remaining = first_use
        .json()
        .pointer("/recovery_codes_remaining")
        .and_then(Value::as_i64)
        .expect("the remaining count");
    assert_eq!(
        remaining,
        (codes.len() - 1) as i64,
        "consuming one code did not reduce the batch by one"
    );

    auth_failed(
        &w.app
            .post(
                "/api/v1/auth/mfa/recovery/verify",
                Some(&token),
                json!({"code": codes[0]}),
            )
            .await,
        "reusing a consumed recovery code",
    );

    // From a second session too — consumption is a property of the code, not of the
    // session that spent it.
    let other = login(&w.app, "recovery@fixture.test").await;
    auth_failed(
        &w.app
            .post(
                "/api/v1/auth/mfa/recovery/verify",
                Some(&other),
                json!({"code": codes[0]}),
            )
            .await,
        "reusing a consumed recovery code from another session",
    );

    // A code belonging to nobody, and one belonging to another account, both fail
    // the same way — the consumption UPDATE is scoped to the calling user.
    let stranger_token = login(&w.app, &w.employee.email).await;
    auth_failed(
        &w.app
            .post(
                "/api/v1/auth/mfa/recovery/verify",
                Some(&stranger_token),
                json!({"code": codes[1]}),
            )
            .await,
        "spending another account's recovery code",
    );

    let live: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM recovery_codes WHERE user_id = $1 AND consumed_at IS NULL",
    )
    .bind(user)
    .fetch_one(&w.app.db)
    .await
    .expect("count live codes");
    assert_eq!(
        live.0,
        (codes.len() - 1) as i64,
        "another account's attempt consumed a code"
    );
}

/// Disabling the second factor is how an attacker with a stolen session makes its
/// foothold permanent. It requires a *recent* proof of possession, and is refused
/// outright for an account where MFA is mandatory.
#[tokio::test]
async fn mfa_cannot_be_disabled_without_a_recent_second_factor() {
    let w = World::build().await;
    let hash = password_hash(&w.app).await;
    let user = seed_user(&w.app, "disable@fixture.test", "INTERNAL", &hash).await;
    let token = login(&w.app, "disable@fixture.test").await;
    let _secret = enrol_and_keep_secret(&w.app, &token).await;

    // A second session that never proved the factor: it authenticated with a
    // password only, so it has no step-up. This is the stolen-session case.
    let stale = login(&w.app, "disable@fixture.test").await;

    // Voluntary enrolment means the new session is MFA-pending, so it is refused
    // before step-up is even considered — an even stronger answer.
    let refused = w
        .app
        .post("/api/v1/auth/mfa/disable", Some(&stale), json!({}))
        .await;
    assert_eq!(
        refused.status,
        StatusCode::FORBIDDEN,
        "a session without a recent second factor disabled MFA: {}",
        String::from_utf8_lossy(&refused.raw)
    );
    assert!(
        matches!(
            refused.error_code(),
            Some("STEP_UP_REQUIRED") | Some("MFA_REQUIRED")
        ),
        "MFA disable was refused with `{:?}`",
        refused.error_code()
    );

    // Regenerating recovery codes is on the same list: a stolen session must not be
    // able to mint itself a set of permanent bypass credentials.
    let regen = w
        .app
        .post(
            "/api/v1/auth/mfa/recovery/regenerate",
            Some(&stale),
            json!({}),
        )
        .await;
    assert_eq!(
        regen.status,
        StatusCode::FORBIDDEN,
        "a session without a recent second factor regenerated recovery codes"
    );

    let still: (bool,) = sqlx::query_as("SELECT mfa_enrolled FROM users WHERE id = $1")
        .bind(user)
        .fetch_one(&w.app.db)
        .await
        .expect("read enrolment");
    assert!(still.0, "MFA was disabled by a session without step-up");

    // The owner, for whom MFA is mandatory, is refused even *with* a fresh factor.
    let mandatory = w
        .app
        .post("/api/v1/auth/mfa/disable", w.root.bearer(), json!({}))
        .await;
    mandatory.assert_error(StatusCode::CONFLICT, "MFA_MANDATORY");
    let owner: (bool, bool) =
        sqlx::query_as("SELECT mfa_required, mfa_enrolled FROM users WHERE id = $1")
            .bind(w.root.id)
            .fetch_one(&w.app.db)
            .await
            .expect("read the owner");
    assert!(owner.0 && owner.1, "the owner's MFA was weakened");
}

/// A privileged account whose login has not completed MFA reaches nothing.
///
/// The owner is the strongest case available: `mfa_required` is set, so its
/// password-only session is `pending_mfa` by construction and holds the widest
/// authority in the system. If the pending state leaked anywhere, it would leak
/// everything.
#[tokio::test]
async fn a_privileged_login_reaches_nothing_before_mfa_is_complete() {
    let w = World::build().await;

    let pending = w
        .app
        .post(
            "/api/v1/auth/login",
            None,
            json!({"email": w.root.email, "password": TEST_PASSWORD}),
        )
        .await;
    pending.assert_status(StatusCode::OK);
    assert_eq!(
        pending.json().get("mfa_required").and_then(Value::as_bool),
        Some(true),
        "a privileged login did not demand a second factor"
    );
    let token = pending.str_at("/access_token").to_string();

    // Everything the owner could otherwise do, refused.
    for path in [
        "/api/v1/users",
        "/api/v1/roles",
        "/api/v1/audit/events",
        "/api/v1/settings",
        "/api/v1/projects",
        "/api/v1/auth/sessions",
    ] {
        let response = w.app.get(path, Some(&token)).await;
        assert_eq!(
            response.status,
            StatusCode::FORBIDDEN,
            "a pending-MFA owner session reached {path}: {}",
            String::from_utf8_lossy(&response.raw)
        );
        assert_eq!(
            response.error_code(),
            Some("MFA_REQUIRED"),
            "{path} refused a pending session with the wrong code"
        );
        response.assert_no_secrets();
    }

    // Writes too — including the ones that would let the session escalate itself
    // out of the pending state.
    for (path, body) in [
        (
            format!("/api/v1/users/{}/permission-overrides", w.employee.id),
            json!({"permission_code": "audit.read", "effect": "ALLOW", "scope": "GLOBAL"}),
        ),
        (
            format!("/api/v1/users/{}/roles", w.employee.id),
            json!({"role_id": ROLE_EMPLOYEE}),
        ),
        ("/api/v1/auth/logout-all".into(), json!({})),
    ] {
        let response = w.app.post(&path, Some(&token), body).await;
        assert_eq!(
            response.status,
            StatusCode::FORBIDDEN,
            "a pending-MFA owner session reached POST {path}"
        );
    }

    // `/auth/me` is the one permitted endpoint, and it must say so rather than
    // pretending the session is complete.
    let me = w.app.get("/api/v1/auth/me", Some(&token)).await;
    me.assert_status(StatusCode::OK);
    assert_eq!(
        me.json().get("mfa_required").and_then(Value::as_bool),
        Some(true),
        "`/auth/me` reported a pending session as complete"
    );
    // And it must not hand a pending session the capability list it has not earned.
    let text = String::from_utf8_lossy(&me.raw);
    assert!(
        !text.contains("audit.read"),
        "a pending-MFA session was handed the owner's capability list: {text}"
    );
}

/// Granting a **dangerous** permission to an existing account does not set that
/// account's `mfa_required` flag, and this test pins down that the omission fails
/// **closed** rather than open.
///
/// The catalogue documents `is_dangerous` as "granting or exercising it requires a
/// recent step-up, and mandates that the holder has MFA enrolled". The mandate is
/// applied at invitation acceptance (`invitations.rs` computes `mfa_required` from
/// the invited roles) but not when authority is added to an account that already
/// exists. The safety of that gap rests entirely on one fact: step-up is derived
/// from `mfa_verified_at`, which only the genuine MFA endpoints can set, so an
/// account with no enrolled factor can never satisfy the step-up window and
/// therefore can never exercise the permission it was given.
///
/// That is a real property and it is asserted below. It is also fragile: any change
/// that lets `mfa_verified_at` be set without a factor — a "trusted device", an
/// SSO assertion, an administrative override — converts this from an onboarding
/// inconvenience into a privilege-escalation path with no test guarding it. Hence
/// this test, and the LOW finding it accompanies.
#[tokio::test]
async fn a_dangerous_permission_granted_without_mfa_fails_closed() {
    let w = World::build().await;
    let hash = password_hash(&w.app).await;
    let subject = seed_user(&w.app, "nomfa@fixture.test", "INTERNAL", &hash).await;

    // The full delegation kit, dangerous permissions included, on an account with
    // no second factor at all.
    for code in [
        "iam.permissions.delegate",
        "iam.roles.assign",
        "iam.roles.read",
    ] {
        grant_override(&w.app, subject, code, "ALLOW", "GLOBAL", w.root.id).await;
    }
    grant_override(&w.app, subject, "tasks.read", "ALLOW", "GLOBAL", w.root.id).await;

    // Granting dangerous authority did not mandate a second factor...
    let flags: (bool, bool) =
        sqlx::query_as("SELECT mfa_required, mfa_enrolled FROM users WHERE id = $1")
            .bind(subject)
            .fetch_one(&w.app.db)
            .await
            .expect("read the MFA flags");
    assert!(
        !flags.1,
        "the fixture account unexpectedly has an enrolled factor"
    );

    let token = login(&w.app, "nomfa@fixture.test").await;
    let bearer = Some(token.as_str());

    // ...and the session is *not* MFA-pending, so it is a fully authenticated
    // session holding a dangerous permission. This is the risky-looking state.
    let me = w.app.get("/api/v1/auth/me", bearer).await;
    me.assert_status(StatusCode::OK);
    assert_eq!(
        me.json().get("mfa_required").and_then(Value::as_bool),
        Some(false),
        "the session was pending MFA, which would make the rest of this test vacuous"
    );

    // The non-dangerous permission works, proving the session is genuinely live.
    w.app
        .get("/api/v1/tasks", bearer)
        .await
        .assert_status(StatusCode::OK);

    // Every use of the dangerous authority is refused for want of a step-up the
    // account can never obtain. This is the fail-closed property.
    for (path, body) in [
        (
            format!("/api/v1/users/{}/permission-overrides", w.employee.id),
            json!({"permission_code": "tasks.read", "effect": "ALLOW", "scope": "SELF"}),
        ),
        (
            format!("/api/v1/users/{}/roles", w.employee.id),
            json!({"role_id": ROLE_EMPLOYEE}),
        ),
    ] {
        let refused = w.app.post(&path, bearer, body).await;
        refused.assert_error(StatusCode::FORBIDDEN, "STEP_UP_REQUIRED");
    }

    // And nothing was written.
    let written: (i64,) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM user_permission_overrides WHERE granted_by = $1)
              + (SELECT count(*) FROM user_role_assignments WHERE granted_by = $1)",
    )
    .bind(subject)
    .fetch_one(&w.app.db)
    .await
    .expect("count what the account managed to grant");
    assert_eq!(
        written.0, 0,
        "an account with no second factor exercised a dangerous permission"
    );
}

// ===========================================================================
// Session credentials
// ===========================================================================

/// Every reason a bearer token can be invalid renders identically. A distinction
/// here tells an attacker holding a captured token whether it was ever real.
#[tokio::test]
async fn every_invalid_bearer_token_fails_in_exactly_the_same_way() {
    let w = World::build().await;

    // A token that was real and has been revoked.
    let revoked = login(&w.app, &w.employee.email).await;
    w.app
        .post("/api/v1/auth/logout", Some(&revoked), json!({}))
        .await
        .assert_status(StatusCode::OK);

    // A token that was real and has expired.
    let expired = login(&w.app, &w.employee.email).await;
    sqlx::query(
        "UPDATE sessions SET access_expires_at = now() - interval '1 second'
          WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(w.employee.id)
    .execute(&w.app.db)
    .await
    .expect("expire the session");

    // A token belonging to a suspended account.
    let suspended_token = login(&w.app, &w.manager.email).await;
    sqlx::query("UPDATE users SET status = 'SUSPENDED', suspended_at = now() WHERE id = $1")
        .bind(w.manager.id)
        .execute(&w.app.db)
        .await
        .expect("suspend");

    let random = "rb_at_0000000000000000000000000000000000000000000";

    let candidates = [
        ("a revoked token", revoked.as_str()),
        ("an expired token", expired.as_str()),
        ("a suspended user's token", suspended_token.as_str()),
        ("a well-formed random token", random),
        ("a malformed token", "not-a-token"),
        ("an empty token", ""),
        ("a refresh token used as an access token", "rb_rt_aaaaaaaa"),
        ("a token with the wrong prefix", "rb_xx_aaaaaaaaaaaaaaaa"),
    ];

    let mut baseline: Option<(StatusCode, Value)> = None;
    for (label, token) in candidates {
        let response = w.app.get("/api/v1/auth/me", Some(token)).await;
        auth_failed(&response, label);
        let observed = (response.status, comparable(&response));
        match &baseline {
            None => baseline = Some(observed),
            Some(expected) => assert_eq!(
                &observed, expected,
                "`{label}` is distinguishable from the other token failures"
            ),
        }
    }
}

/// A password reset is a credential rotation. Every session that existed before it
/// must be dead on the next request, including the one that performed the reset —
/// otherwise a reset performed *because* of a suspected compromise leaves the
/// attacker logged in.
#[tokio::test]
async fn a_password_reset_kills_every_session_that_predates_it() {
    let w = World::build().await;
    const NEW_PASSWORD: &str = "a completely different passphrase 77";

    let stolen_a = login(&w.app, &w.employee.email).await;
    let stolen_b = login(&w.app, &w.employee.email).await;
    w.app
        .get("/api/v1/auth/me", Some(&stolen_a))
        .await
        .assert_status(StatusCode::OK);

    w.app
        .post(
            "/api/v1/auth/password-reset/request",
            None,
            json!({"email": w.employee.email}),
        )
        .await
        .assert_status(StatusCode::ACCEPTED);

    let payload: (Value,) = sqlx::query_as(
        "SELECT payload FROM outbox_events WHERE event_type = 'mail.password_reset' ORDER BY id DESC LIMIT 1",
    )
    .fetch_one(&w.app.db)
    .await
    .expect("the queued reset");
    let link = payload.0["reset_url"]
        .as_str()
        .expect("the reset payload must carry a link");
    let reset_token = link
        .split_once("?token=")
        .map(|(_, t)| t.to_string())
        .expect("the link must carry a token");

    w.app
        .post(
            "/api/v1/auth/password-reset/confirm",
            None,
            json!({"token": reset_token, "new_password": NEW_PASSWORD}),
        )
        .await
        .assert_status(StatusCode::OK);

    for (label, token) in [("first session", &stolen_a), ("second session", &stolen_b)] {
        dead(
            &w.app.get("/api/v1/auth/me", Some(token)).await,
            &format!("{label} after a password reset"),
        );
    }

    // The reset token is single use.
    reset_login_budget(&w.app, &[&w.employee.email]).await;
    let reused = w
        .app
        .post(
            "/api/v1/auth/password-reset/confirm",
            None,
            json!({"token": reset_token, "new_password": "yet another passphrase 91"}),
        )
        .await;
    assert!(
        reused.status.is_client_error(),
        "a password reset token was accepted twice"
    );

    // The old password no longer works; the new one does.
    reset_login_budget(&w.app, &[&w.employee.email]).await;
    auth_failed(
        &w.app
            .post(
                "/api/v1/auth/login",
                None,
                json!({"email": w.employee.email, "password": TEST_PASSWORD}),
            )
            .await,
        "logging in with the pre-reset password",
    );
    reset_login_budget(&w.app, &[&w.employee.email]).await;
    w.app
        .post(
            "/api/v1/auth/login",
            None,
            json!({"email": w.employee.email, "password": NEW_PASSWORD}),
        )
        .await
        .assert_status(StatusCode::OK);
}

#[track_caller]
fn dead(response: &TestResponse, what: &str) {
    auth_failed(response, what);
}

/// Rotation, reuse and simultaneity, asserted together so the three cannot drift
/// apart: the new pair works, the old one is proof of compromise, and a hit on the
/// consumed token takes the whole family down rather than merely failing.
#[tokio::test]
async fn refresh_rotation_makes_the_previous_token_proof_of_compromise() {
    let w = World::build().await;

    let issued = w
        .app
        .post(
            "/api/v1/auth/login",
            None,
            json!({"email": w.employee.email, "password": TEST_PASSWORD}),
        )
        .await;
    issued.assert_status(StatusCode::OK);
    let first_refresh = issued.str_at("/refresh_token").to_string();
    let first_access = issued.str_at("/access_token").to_string();

    let rotated = w
        .app
        .post(
            "/api/v1/auth/refresh",
            None,
            json!({"refresh_token": first_refresh}),
        )
        .await;
    rotated.assert_status(StatusCode::OK);
    let second_refresh = rotated.str_at("/refresh_token").to_string();
    let second_access = rotated.str_at("/access_token").to_string();

    assert_ne!(
        first_refresh, second_refresh,
        "refreshing did not rotate the refresh token"
    );
    assert_ne!(
        first_access, second_access,
        "refreshing did not rotate the access token"
    );

    // The rotated pair works.
    w.app
        .get("/api/v1/auth/me", Some(&second_access))
        .await
        .assert_status(StatusCode::OK);

    // Replaying the consumed refresh token is treated as interception, not as a
    // racy client: the entire family dies, including the pair that is currently in
    // legitimate use.
    let replayed = w
        .app
        .post(
            "/api/v1/auth/refresh",
            None,
            json!({"refresh_token": first_refresh}),
        )
        .await;
    assert!(
        replayed.status.is_client_error(),
        "a consumed refresh token was accepted again"
    );

    dead(
        &w.app.get("/api/v1/auth/me", Some(&second_access)).await,
        "the live access token after a refresh replay",
    );
    let still_good = w
        .app
        .post(
            "/api/v1/auth/refresh",
            None,
            json!({"refresh_token": second_refresh}),
        )
        .await;
    assert!(
        still_good.status.is_client_error(),
        "the current refresh token survived a detected replay"
    );

    let reason: (Option<String>,) = sqlx::query_as(
        "SELECT revocation_reason FROM sessions
          WHERE user_id = $1 AND revoked_at IS NOT NULL ORDER BY revoked_at DESC LIMIT 1",
    )
    .bind(w.employee.id)
    .fetch_one(&w.app.db)
    .await
    .expect("read the revocation reason");
    assert!(
        reason.0.is_some(),
        "the family was revoked without recording why"
    );
}

// ===========================================================================
// THE test
// ===========================================================================

/// **Privilege freshness.** A change to a user's authority takes effect on the
/// very next request that user makes — no re-login, no new token, no waiting for
/// an access token to expire.
///
/// This is the single most important property in this file. Every "we cache the
/// permissions in the JWT" design fails it, and the failure is silent: a revoked
/// administrator keeps administering for the remaining lifetime of a token nobody
/// can see. The session below is issued **once**, at the top, and the same bearer
/// string is used for every request afterwards. Between requests the authority is
/// changed through the real HTTP surface, and the very next request must already
/// reflect it.
///
/// Six transitions are exercised in both directions: an override granted, an
/// override revoked, a DENY added, a DENY removed, a role assigned, a role
/// unassigned.
#[tokio::test]
async fn a_live_session_uses_the_new_permissions_on_the_very_next_request() {
    let w = World::build().await;

    let hash = password_hash(&w.app).await;
    let subject = seed_user(&w.app, "freshness@fixture.test", "INTERNAL", &hash).await;
    // One session. One token. Never re-issued below.
    let token = login(&w.app, "freshness@fixture.test").await;
    let bearer = Some(token.as_str());

    /// Reading the task collection needs `tasks.read@GLOBAL`, which makes it a
    /// clean yes/no probe of one permission with no membership or scope
    /// interaction to muddy the answer.
    const PROBE: &str = "/api/v1/tasks";

    let allowed = |r: &TestResponse| r.status == StatusCode::OK;

    // --- 0. the starting point: no authority at all ------------------------
    w.app
        .get(PROBE, bearer)
        .await
        .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");

    let version_before: (i32,) = sqlx::query_as("SELECT security_version FROM users WHERE id = $1")
        .bind(subject)
        .fetch_one(&w.app.db)
        .await
        .expect("read security_version");

    // --- 1. grant an override; the *next* request must succeed -------------
    let created = w
        .app
        .post(
            &format!("/api/v1/users/{subject}/permission-overrides"),
            w.root.bearer(),
            json!({"permission_code": "tasks.read", "effect": "ALLOW", "scope": "GLOBAL"}),
        )
        .await;
    created.assert_status(StatusCode::CREATED);
    let override_id = created.id_at("/id");

    assert!(
        allowed(&w.app.get(PROBE, bearer).await),
        "a granted permission did not apply to the live session's next request"
    );

    // The privilege change bumped the security version, and the session survived it:
    // a privilege change is not a session kill, and must not be implemented as one.
    let version_after: (i32,) = sqlx::query_as("SELECT security_version FROM users WHERE id = $1")
        .bind(subject)
        .fetch_one(&w.app.db)
        .await
        .expect("read security_version");
    assert!(
        version_after.0 > version_before.0,
        "granting authority did not bump the security version"
    );
    let live: (i64,) =
        sqlx::query_as("SELECT count(*) FROM sessions WHERE user_id = $1 AND revoked_at IS NULL")
            .bind(subject)
            .fetch_one(&w.app.db)
            .await
            .expect("count sessions");
    assert_eq!(live.0, 1, "a permission change revoked the session");

    // The capability list must move with the decision, not lag behind it.
    let me = w.app.get("/api/v1/auth/me", bearer).await;
    me.assert_status(StatusCode::OK);
    assert!(
        String::from_utf8_lossy(&me.raw).contains("tasks.read"),
        "`/auth/me` did not report a permission the evaluator now allows"
    );

    // --- 2. revoke the override; the next request must fail ----------------
    w.app
        .delete(
            &format!("/api/v1/users/{subject}/permission-overrides/{override_id}"),
            w.root.bearer(),
        )
        .await
        .assert_status(StatusCode::NO_CONTENT);

    w.app
        .get(PROBE, bearer)
        .await
        .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");

    let me = w.app.get("/api/v1/auth/me", bearer).await;
    assert!(
        !String::from_utf8_lossy(&me.raw).contains("tasks.read"),
        "`/auth/me` still advertises a permission that has been revoked"
    );

    // --- 3. a role grants it; the next request must succeed ----------------
    let role = w
        .app
        .post(
            "/api/v1/roles",
            w.root.bearer(),
            json!({
                "code": "freshness_reader",
                "name": "Freshness Reader",
                "allowed_principal_type": "INTERNAL",
                "permissions": [{"permission_code": "tasks.read", "scope": "GLOBAL"}],
            }),
        )
        .await;
    role.assert_status(StatusCode::CREATED);
    let role_id = role.id_at("/id");

    w.app
        .post(
            &format!("/api/v1/users/{subject}/roles"),
            w.root.bearer(),
            json!({"role_id": role_id}),
        )
        .await
        .assert_status(StatusCode::CREATED);

    assert!(
        allowed(&w.app.get(PROBE, bearer).await),
        "a role assignment did not apply to the live session's next request"
    );

    // --- 4. a DENY overrides the role; the next request must fail ----------
    let deny = w
        .app
        .post(
            &format!("/api/v1/users/{subject}/permission-overrides"),
            w.root.bearer(),
            json!({"permission_code": "tasks.read", "effect": "DENY", "scope": "GLOBAL"}),
        )
        .await;
    deny.assert_status(StatusCode::CREATED);
    let deny_id = deny.id_at("/id");

    w.app
        .get(PROBE, bearer)
        .await
        .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");

    // --- 5. remove the DENY; the role's grant is live again ----------------
    w.app
        .delete(
            &format!("/api/v1/users/{subject}/permission-overrides/{deny_id}"),
            w.root.bearer(),
        )
        .await
        .assert_status(StatusCode::NO_CONTENT);

    assert!(
        allowed(&w.app.get(PROBE, bearer).await),
        "removing a DENY did not apply to the live session's next request"
    );

    // --- 6. unassign the role; back to nothing -----------------------------
    w.app
        .delete(
            &format!("/api/v1/users/{subject}/roles/{role_id}"),
            w.root.bearer(),
        )
        .await
        .assert_status(StatusCode::NO_CONTENT);

    w.app
        .get(PROBE, bearer)
        .await
        .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");

    // The whole sequence used one token, and that token is still the live one — the
    // point being that authority was re-derived per request rather than carried in
    // the credential.
    let final_check = w.app.get("/api/v1/auth/me", bearer).await;
    final_check.assert_status(StatusCode::OK);
    assert_eq!(
        final_check.json().get("user_id").and_then(Value::as_str),
        Some(subject.to_string().as_str()),
        "the session changed identity during the test"
    );
}

/// The same freshness property for the *envelope* rather than for a grant:
/// suspending an account ends its authority on the next request, and a
/// department membership change moves a scoped grant's reach immediately.
#[tokio::test]
async fn scope_changes_also_apply_on_the_next_request() {
    let w = World::build().await;

    let hash = password_hash(&w.app).await;
    let subject = seed_user(&w.app, "scoped@fixture.test", "INTERNAL", &hash).await;
    // Department-scoped authority, with no department membership yet — so the grant
    // exists but reaches nothing.
    grant_override(
        &w.app,
        subject,
        "projects.read",
        "ALLOW",
        "DEPARTMENT",
        w.root.id,
    )
    .await;
    let token = login(&w.app, "scoped@fixture.test").await;
    let bearer = Some(token.as_str());
    let project_path = format!("/api/v1/projects/{}", w.internal_project);

    w.app
        .get(&project_path, bearer)
        .await
        .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");

    // Join the department that owns the project. No new token.
    w.app
        .post(
            &format!("/api/v1/departments/{}/members", w.department),
            w.admin.bearer(),
            json!({"user_id": subject, "role_in_department": "MEMBER"}),
        )
        .await
        .assert_status(StatusCode::CREATED);

    w.app
        .get(&project_path, bearer)
        .await
        .assert_status(StatusCode::OK);

    // Leave it again. The very next request loses the reach.
    w.app
        .delete(
            &format!("/api/v1/departments/{}/members/{subject}", w.department),
            w.admin.bearer(),
        )
        .await
        .assert_status(StatusCode::NO_CONTENT);

    w.app
        .get(&project_path, bearer)
        .await
        .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");

    // And suspension ends the session itself on the next request, without any
    // fan-out UPDATE that could fail independently.
    sqlx::query("UPDATE users SET status = 'SUSPENDED', suspended_at = now() WHERE id = $1")
        .bind(subject)
        .execute(&w.app.db)
        .await
        .expect("suspend");
    dead(
        &w.app.get("/api/v1/auth/me", bearer).await,
        "a suspended user's live session",
    );
}
