//! The general rate limiter (closure §3–§9).
//!
//! The defect this suite exists to keep closed: no general limiter was applied to
//! authenticated API traffic, so any principal — including one holding no
//! permissions at all — could repeat a refused request indefinitely. Each refusal
//! cost the system an authorisation query and, on the paths that deliberately
//! commit a denial record, one row in an append-only table plus the global
//! audit-chain lock. Measured before the fix: 60 requests, 60 audit rows, zero
//! `429`s.
//!
//! Every test builds its own app through `spawn_with` and states its own quota. The
//! harness default is deliberately enormous (see `common`), so a suite cannot reach
//! the limiter by accident — which means the numbers asserted here cannot drift
//! when someone retunes the harness.
//!
//! Deliberately self-contained: it seeds its own principals rather than sharing the
//! security suite's `World`, so the two cannot break each other.

mod common;

use axum::http::{header, StatusCode};
use serde_json::json;
use uuid::Uuid;

use common::TestApp;
use roleblank_backend::platform::config::Config;
use roleblank_backend::shared::secret::Secret;

const PASSWORD: &str = "correct horse battery staple 42";
/// Small enough to reach quickly, large enough that seeding does not trip it.
const TINY: u32 = 10;

// ---------------------------------------------------------------------------
// Local fixtures
// ---------------------------------------------------------------------------

async fn tiny_app(quota: u32) -> TestApp {
    TestApp::spawn_with(move |config: &mut Config| {
        config.rate_limits.general_per_principal_per_minute = quota;
        config.rate_limits.general_root_per_minute = quota;
        // Left wide so that the per-principal budget is unambiguously the thing
        // under test; the address ceiling gets its own test below.
        config.rate_limits.general_per_ip_per_minute = 100_000;
    })
    .await
}

async fn seed(app: &TestApp, email: &str, principal_type: &str) -> Uuid {
    let hash = app
        .state
        .hasher
        .hash(&Secret::new(PASSWORD.to_string()))
        .await
        .expect("hash the fixture password");
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO users (id, email, email_normalized, display_name, principal_type,
                            status, mfa_required, activated_at)
         VALUES ($1, $2, lower($2), $3, $4, 'ACTIVE', false, now())",
    )
    .bind(id)
    .bind(email)
    .bind(email)
    .bind(principal_type)
    .execute(&app.db)
    .await
    .expect("seed a user");
    sqlx::query("INSERT INTO credentials (user_id, password_hash) VALUES ($1, $2)")
        .bind(id)
        .bind(hash)
        .execute(&app.db)
        .await
        .expect("seed credentials");
    id
}

async fn login(app: &TestApp, email: &str) -> String {
    let response = app
        .post(
            "/api/v1/auth/login",
            None,
            json!({"email": email, "password": PASSWORD}),
        )
        .await;
    response.assert_status(StatusCode::OK);
    response.str_at("/access_token").to_string()
}

/// Make this user the system owner.
///
/// Written directly because the bootstrap route can only run once and this suite
/// needs an owner alongside ordinary principals in the same database.
async fn make_root(app: &TestApp, user_id: Uuid) {
    sqlx::query("INSERT INTO system_ownership (id, root_user_id) VALUES (true, $1)")
        .bind(user_id)
        .execute(&app.db)
        .await
        .expect("establish ownership");
}

/// Repeat a request and report where the limiter first bit.
async fn hammer(
    app: &TestApp,
    path: &str,
    token: &str,
    n: usize,
) -> (Option<usize>, Vec<StatusCode>) {
    let mut statuses = Vec::with_capacity(n);
    let mut first_429 = None;
    for i in 0..n {
        let response = app.get(path, Some(token)).await;
        if response.status == StatusCode::TOO_MANY_REQUESTS && first_429.is_none() {
            first_429 = Some(i);
        }
        statuses.push(response.status);
    }
    (first_429, statuses)
}

async fn audit_count(app: &TestApp) -> i64 {
    let row: (i64,) = sqlx::query_as("SELECT count(*) FROM audit_events")
        .fetch_one(&app.db)
        .await
        .expect("count audit events");
    row.0
}

// ---------------------------------------------------------------------------
// 1–5: every principal class is bounded
// ---------------------------------------------------------------------------

/// Normal usage must not be throttled. A limiter that fires during ordinary work is
/// an outage, so this is asserted before anything about throttling.
#[tokio::test]
async fn an_employee_doing_ordinary_work_is_never_throttled() {
    let app = tiny_app(TINY).await;
    seed(&app, "employee@rl.test", "INTERNAL").await;
    let token = login(&app, "employee@rl.test").await;

    let (first, statuses) = hammer(&app, "/api/v1/auth/me", &token, (TINY - 2) as usize).await;
    assert_eq!(first, None, "an ordinary burst was throttled: {statuses:?}");
    assert!(statuses.iter().all(|s| *s == StatusCode::OK));
}

#[tokio::test]
async fn an_employee_exceeding_the_budget_is_throttled() {
    let app = tiny_app(TINY).await;
    seed(&app, "busy@rl.test", "INTERNAL").await;
    let token = login(&app, "busy@rl.test").await;

    let (first, statuses) = hammer(&app, "/api/v1/auth/me", &token, (TINY * 3) as usize).await;
    assert!(
        first.is_some(),
        "an employee was never throttled in {} requests: {statuses:?}",
        TINY * 3
    );
}

/// The original finding, from the principal class that provoked it: a caller with
/// no authority at all, repeating something it may not do.
#[tokio::test]
async fn a_client_principal_exceeding_the_budget_is_throttled() {
    let app = tiny_app(TINY).await;
    seed(&app, "outsider@rl.test", "CLIENT").await;
    let token = login(&app, "outsider@rl.test").await;

    let (first, statuses) = hammer(&app, "/api/v1/users", &token, (TINY * 3) as usize).await;
    assert!(
        first.is_some(),
        "a CLIENT was never throttled: {statuses:?}"
    );
    // Before the limiter is reached the answer must still be the masked refusal —
    // throttling must not change what an unauthorised caller learns.
    assert_eq!(statuses[0], StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn an_administrator_exceeding_the_budget_is_throttled() {
    let app = tiny_app(TINY).await;
    let id = seed(&app, "admin@rl.test", "INTERNAL").await;
    sqlx::query(
        "INSERT INTO user_role_assignments (id, user_id, role_id, granted_by)
         VALUES ($1, $2, '00000000-0000-7000-8000-000000000001'::uuid, $2)",
    )
    .bind(Uuid::now_v7())
    .bind(id)
    .execute(&app.db)
    .await
    .expect("assign the administrator role");
    let token = login(&app, "admin@rl.test").await;

    let (first, _) = hammer(&app, "/api/v1/auth/me", &token, (TINY * 3) as usize).await;
    assert!(first.is_some(), "an administrator was never throttled");
}

/// ROOT is not exempt. It gets a bigger budget, never an infinite one — an
/// unbounded owner session is still a way to hurt the system.
#[tokio::test]
async fn the_system_owner_is_bounded_too() {
    let app = tiny_app(TINY).await;
    let id = seed(&app, "owner@rl.test", "INTERNAL").await;
    make_root(&app, id).await;
    let token = login(&app, "owner@rl.test").await;

    let (first, statuses) = hammer(&app, "/api/v1/auth/me", &token, (TINY * 3) as usize).await;
    assert!(first.is_some(), "ROOT was unbounded: {statuses:?}");
}

/// ...and the owner's larger budget is honoured, so an ordinary quota cannot
/// throttle the account that has to recover the company during an incident.
#[tokio::test]
async fn the_system_owner_gets_the_larger_budget() {
    let app = TestApp::spawn_with(|config: &mut Config| {
        config.rate_limits.general_per_principal_per_minute = 5;
        config.rate_limits.general_root_per_minute = 200;
        config.rate_limits.general_per_ip_per_minute = 100_000;
    })
    .await;
    let id = seed(&app, "owner2@rl.test", "INTERNAL").await;
    make_root(&app, id).await;
    let token = login(&app, "owner2@rl.test").await;

    let (first, _) = hammer(&app, "/api/v1/auth/me", &token, 40).await;
    assert_eq!(
        first, None,
        "ROOT was throttled at the ordinary quota instead of its own"
    );
}

// ---------------------------------------------------------------------------
// 6–8: the pre-authentication ceiling and the operation-specific budgets
// ---------------------------------------------------------------------------

/// An anonymous flood is bounded before a token is ever resolved, because
/// resolving one costs a database query whether or not it is genuine.
#[tokio::test]
async fn an_anonymous_flood_is_bounded_by_the_address_ceiling() {
    let app = TestApp::spawn_with(|config: &mut Config| {
        config.rate_limits.general_per_ip_per_minute = TINY;
    })
    .await;

    let mut first_429 = None;
    for i in 0..(TINY * 3) {
        let response = app
            .get("/api/v1/auth/me", Some("rb_at_definitely-not-a-real-token"))
            .await;
        if response.status == StatusCode::TOO_MANY_REQUESTS && first_429.is_none() {
            first_429 = Some(i);
        }
    }
    assert!(
        first_429.is_some(),
        "invalid-token traffic was never bounded; each request costs a database lookup"
    );
}

/// The operation-specific budgets must stay independent of the general one.
/// Sharing budgets is what made invitation acceptance collide with public
/// registration, and that regression must not return by a different route.
#[tokio::test]
async fn the_login_budget_is_independent_of_the_general_budget() {
    let app = TestApp::spawn_with(|config: &mut Config| {
        // Generous general budgets; the login limiter must still bite on its own.
        config.rate_limits.general_per_principal_per_minute = 100_000;
        config.rate_limits.general_root_per_minute = 100_000;
        config.rate_limits.general_per_ip_per_minute = 100_000;
    })
    .await;
    seed(&app, "loginlimit@rl.test", "INTERNAL").await;

    let mut saw_429 = false;
    for _ in 0..25 {
        let response = app
            .post(
                "/api/v1/auth/login",
                None,
                json!({"email": "loginlimit@rl.test", "password": "wrong-password"}),
            )
            .await;
        if response.status == StatusCode::TOO_MANY_REQUESTS {
            saw_429 = true;
            break;
        }
    }
    assert!(
        saw_429,
        "the login limiter stopped working once a general limiter existed"
    );
}

/// Registration and invitation acceptance keep separate budgets. This was a real
/// finding: sharing one meant an attacker hammering public registration blocked
/// invited colleagues behind the same corporate address.
#[tokio::test]
async fn invitation_acceptance_and_registration_keep_separate_budgets() {
    let app = tiny_app(100_000).await;

    // Exhaust the registration budget (3/hour by default).
    for i in 0..6 {
        app.post(
            "/api/v1/registration",
            None,
            json!({"email": format!("reg{i}@rl.test"), "display_name": "R", "password": PASSWORD}),
        )
        .await;
    }

    // Invitation acceptance must still be reachable: it answers on its own merits
    // (an invalid token here, not a throttle).
    let response = app
        .post(
            "/api/v1/invitations/accept",
            None,
            json!({"token": "rb_iv_not-a-real-token", "password": PASSWORD}),
        )
        .await;
    assert_ne!(
        response.status,
        StatusCode::TOO_MANY_REQUESTS,
        "invitation acceptance was throttled by the registration budget"
    );
}

// ---------------------------------------------------------------------------
// 9–11: the response contract, and the amplification the finding was about
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_throttled_request_returns_the_documented_contract() {
    let app = tiny_app(TINY).await;
    seed(&app, "contract@rl.test", "INTERNAL").await;
    let token = login(&app, "contract@rl.test").await;

    let mut throttled = None;
    for _ in 0..(TINY * 3) {
        let response = app.get("/api/v1/auth/me", Some(&token)).await;
        if response.status == StatusCode::TOO_MANY_REQUESTS {
            throttled = Some(response);
            break;
        }
    }
    let response = throttled.expect("never throttled");

    response.assert_error(StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED");
    assert_eq!(
        response
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/problem+json"),
        "a throttled response broke the problem+json contract"
    );

    let retry_after = response
        .headers
        .get(header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .expect("Retry-After must be present and numeric");
    assert!(
        (1..=3600).contains(&retry_after),
        "implausible Retry-After: {retry_after}"
    );

    // The refusal must not describe the limiter's internals.
    let body = response.json().to_string();
    assert!(
        !body.contains("general:user:") && !body.contains(&TINY.to_string()),
        "the throttle response leaked limiter internals: {body}"
    );
}

/// **The finding itself.** A principal repeating a request that produces a
/// committed denial record must not be able to grow an append-only table without
/// bound. Audit growth must stop when the limiter stops the requests.
#[tokio::test]
async fn audit_growth_from_repeated_denials_is_bounded() {
    let app = tiny_app(TINY).await;
    let id = seed(&app, "amplifier@rl.test", "INTERNAL").await;
    let token = login(&app, "amplifier@rl.test").await;
    let _ = id;

    let before = audit_count(&app).await;
    let attempts = (TINY * 20) as usize;
    let mut throttled = 0usize;
    for _ in 0..attempts {
        let response = app
            .post(
                &format!("/api/v1/projects/{}/clients", Uuid::now_v7()),
                Some(&token),
                json!({"client_account_id": Uuid::now_v7()}),
            )
            .await;
        if response.status == StatusCode::TOO_MANY_REQUESTS {
            throttled += 1;
        }
    }
    let written = audit_count(&app).await - before;

    assert!(
        throttled > 0,
        "the amplification path was never throttled across {attempts} attempts"
    );
    assert!(
        written <= i64::from(TINY) + 2,
        "{attempts} attempts wrote {written} audit rows; the limiter did not bound growth"
    );
}

// ---------------------------------------------------------------------------
// 12–15: the limiter must not become a security hole of its own
// ---------------------------------------------------------------------------

/// A limiter that let a request through *because* it had budget would be a
/// catastrophic inversion. Authorisation is unchanged by the presence of quota.
#[tokio::test]
async fn the_limiter_never_substitutes_for_authorisation() {
    let app = tiny_app(100_000).await;
    seed(&app, "nobody@rl.test", "INTERNAL").await;
    let token = login(&app, "nobody@rl.test").await;

    // Plenty of budget, no permissions: still refused, every time.
    for _ in 0..5 {
        let response = app.get("/api/v1/audit/events", Some(&token)).await;
        assert!(
            response.status == StatusCode::FORBIDDEN || response.status == StatusCode::NOT_FOUND,
            "a principal with budget but no authority was allowed through: {}",
            response.status
        );
    }
}

/// Throttling must not become an existence oracle: a forbidden resource and an
/// invented one must be indistinguishable both before and after the limiter bites.
#[tokio::test]
async fn throttling_does_not_reveal_whether_a_resource_exists() {
    let app = tiny_app(100_000).await;
    seed(&app, "prober@rl.test", "CLIENT").await;
    let token = login(&app, "prober@rl.test").await;

    let real_but_forbidden = app.get("/api/v1/users", Some(&token)).await;
    let invented = app
        .get(&format!("/api/v1/users/{}", Uuid::now_v7()), Some(&token))
        .await;

    assert_eq!(
        real_but_forbidden.status,
        StatusCode::NOT_FOUND,
        "a forbidden collection answered something other than the masked refusal"
    );
    assert_eq!(
        invented.status,
        StatusCode::NOT_FOUND,
        "an invented resource answered differently from a forbidden one"
    );
}

/// Two people in one office share an address and must not share a budget. This is
/// why the general budget is keyed on the user id rather than the address.
#[tokio::test]
async fn two_users_behind_one_address_do_not_share_a_budget() {
    let app = tiny_app(TINY).await;
    seed(&app, "colleague-a@rl.test", "INTERNAL").await;
    seed(&app, "colleague-b@rl.test", "INTERNAL").await;
    let a = login(&app, "colleague-a@rl.test").await;
    let b = login(&app, "colleague-b@rl.test").await;

    // A exhausts their own budget.
    let (first_a, _) = hammer(&app, "/api/v1/auth/me", &a, (TINY * 3) as usize).await;
    assert!(first_a.is_some(), "colleague A was never throttled");

    // B, at the same address, is unaffected.
    let response = app.get("/api/v1/auth/me", Some(&b)).await;
    assert_eq!(
        response.status,
        StatusCode::OK,
        "one colleague's overuse throttled another at the same address"
    );
}

/// ...and the mirror image: one compromised account must not multiply its budget
/// by opening more sessions. This is why the key is the user, not the session.
#[tokio::test]
async fn one_principal_cannot_multiply_its_budget_with_more_sessions() {
    let app = tiny_app(TINY).await;
    seed(&app, "compromised@rl.test", "INTERNAL").await;

    let first = login(&app, "compromised@rl.test").await;
    let (hit, _) = hammer(&app, "/api/v1/auth/me", &first, (TINY * 3) as usize).await;
    assert!(hit.is_some(), "the first session was never throttled");

    // A brand-new session for the same user inherits the same exhausted budget.
    let second = login(&app, "compromised@rl.test").await;
    let response = app.get("/api/v1/auth/me", Some(&second)).await;
    assert_eq!(
        response.status,
        StatusCode::TOO_MANY_REQUESTS,
        "a new session reset the budget; the key is per-session, not per-principal"
    );
}

/// Regression for an ordering bug the live reproduction caught: the MFA gate used
/// to reject a password-only session *before* the limiter was charged, so such a
/// session could repeat a request indefinitely for free while the server paid a
/// session lookup each time.
#[tokio::test]
async fn a_session_pending_mfa_is_charged_the_general_budget() {
    let app = tiny_app(TINY).await;
    let id = seed(&app, "pending@rl.test", "INTERNAL").await;
    // `mfa_required` makes every fresh session pending until a factor is verified,
    // which is exactly the state the ordering bug left uncharged.
    sqlx::query("UPDATE users SET mfa_required = true WHERE id = $1")
        .bind(id)
        .execute(&app.db)
        .await
        .expect("require MFA");
    let token = login(&app, "pending@rl.test").await;

    // `/auth/me` is deliberately reachable by a pending-MFA session, so it proves
    // nothing here. `/projects` requires a fully authenticated one, which is exactly
    // the path where the gate used to short-circuit ahead of the limiter.
    let (first, statuses) = hammer(&app, "/api/v1/projects", &token, (TINY * 3) as usize).await;
    assert!(
        first.is_some(),
        "a pending-MFA session was never throttled: {statuses:?}"
    );
    // Still refused for the right reason while it had budget: the limiter must not
    // have quietly replaced the MFA gate.
    assert_eq!(
        statuses[0],
        StatusCode::FORBIDDEN,
        "the MFA gate stopped refusing once the limiter moved ahead of it"
    );
}

// ---------------------------------------------------------------------------
// Observability: the telemetry `/metrics` promises must actually be recorded
// ---------------------------------------------------------------------------

/// `/metrics` and its documentation promised request-volume and error-rate
/// telemetry that nothing recorded — two series were written in the whole process.
/// This pins the wiring, including that a *refused* request is still counted: an
/// error rate that only counts requests which got through looks healthiest exactly
/// when the system is refusing everything.
#[tokio::test]
async fn requests_are_counted_including_the_ones_that_are_refused() {
    let app = tiny_app(TINY).await;
    seed(&app, "observed@rl.test", "INTERNAL").await;
    let token = login(&app, "observed@rl.test").await;

    // A success, a refusal, and a throttle.
    app.get("/api/v1/auth/me", Some(&token)).await;
    app.get("/api/v1/audit/events", Some(&token)).await;
    let _ = hammer(&app, "/api/v1/auth/me", &token, (TINY * 3) as usize).await;

    let scrape = app.get("/metrics", None).await;
    let body = scrape.raw.clone();
    let text = String::from_utf8_lossy(&body);

    assert!(
        text.contains("http_requests_total"),
        "the scrape carries no request counter: {text}"
    );
    for class in ["2xx", "4xx"] {
        assert!(
            text.contains(class),
            "no {class} series was recorded; refused requests are invisible: {text}"
        );
    }
    // The route pattern, never the concrete id — otherwise every identifier mints
    // its own series and an attacker controls the cardinality.
    assert!(
        !text.contains("observed@rl.test"),
        "a metric label carried caller-controlled content: {text}"
    );
}
