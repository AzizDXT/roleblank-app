//! Fixtures shared by the concurrency, lifecycle and failure-injection suites.
//!
//! These build the *preconditions* of a race, not the race itself. Everything a
//! test is actually asserting about still goes through the real router, the real
//! middleware and the real services; what is seeded directly is only the boring
//! part in front of it — an account exists, it holds a permission, it has a live
//! session.
//!
//! **Why seed the account and its grants with SQL rather than through the API.**
//! The only route to an `INTERNAL` account is bootstrap, an invitation, or
//! self-registration; the only route to a permission is a role created by somebody
//! who already holds it. Driving that chain for every test would mean each
//! concurrency test first re-tests invitation and role creation, would cost several
//! Argon2 hashes per test, and — the part that actually matters — would spend the
//! per-IP quotas on setup, so a test about a *race* would start failing because of
//! a *rate limit*. The one thing never faked here is the session: tokens come from
//! the real login endpoint, so every request in every test carries a credential the
//! application minted and can revoke.

#![allow(dead_code)] // each suite uses a different subset

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use axum::http::StatusCode;
use serde_json::{json, Value};
use uuid::Uuid;

use roleblank_backend::platform::http::rate_limit::keys;
use roleblank_backend::shared::secret::Secret;

use crate::common::{TestApp, TestResponse, TEST_PASSWORD};

/// The address the harness's requests appear to come from.
///
/// `ClientIp` falls back to loopback when `ConnectInfo` is absent, which it always
/// is when the router is driven with `oneshot`. Tests that need to clear a per-IP
/// bucket must key on the same value the application did.
pub const TEST_CLIENT_IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// A seeded, logged-in principal.
pub struct Actor {
    pub id: Uuid,
    pub email: String,
    /// A real access token minted by `POST /auth/login`.
    pub access_token: String,
    /// The refresh token issued alongside it.
    pub refresh_token: String,
    pub session_id: Uuid,
}

/// Create an `ACTIVE` `INTERNAL` account that can log in without MFA.
///
/// `mfa_required` and `mfa_enrolled` are both false, which is what makes the login
/// below produce a session that is *not* pending MFA. That is a real, reachable
/// state — an ordinary employee who holds nothing dangerous — not a special one.
pub async fn create_user(app: &TestApp, email: &str) -> Uuid {
    create_typed_user(app, email, "INTERNAL").await
}

pub async fn create_typed_user(app: &TestApp, email: &str, principal_type: &str) -> Uuid {
    let id = Uuid::now_v7();
    let normalized = email.trim().to_lowercase();

    sqlx::query(
        "INSERT INTO users
             (id, email, email_normalized, display_name, principal_type, status,
              mfa_required, mfa_enrolled, activated_at)
         VALUES ($1, $2, $3, $4, $5, 'ACTIVE', false, false, now())",
    )
    .bind(id)
    .bind(email)
    .bind(&normalized)
    .bind(format!("User {normalized}"))
    .bind(principal_type)
    .execute(&app.db)
    .await
    .expect("seed a user");

    // Hashed with the application's own hasher at the real production parameters,
    // so the login below exercises the same verification cost that ships.
    let hash = app
        .state
        .hasher
        .hash(&Secret::new(TEST_PASSWORD.to_string()))
        .await
        .expect("hash the fixture password");

    sqlx::query("INSERT INTO credentials (user_id, password_hash) VALUES ($1, $2)")
        .bind(id)
        .bind(&hash)
        .execute(&app.db)
        .await
        .expect("seed credentials");

    id
}

/// Give a user an unconditional `ALLOW` at `GLOBAL` scope.
///
/// A per-user override rather than a role: it is one row, it needs no role
/// creation, and `principal::load_actor` unions overrides with role grants, so the
/// evaluator sees exactly what it would see for a role-derived grant. The
/// `permission_code` is a foreign key into the seeded catalogue, so a typo is a
/// failing INSERT here rather than a test that silently authorises nothing.
pub async fn grant(app: &TestApp, user_id: Uuid, permission: &str) {
    sqlx::query(
        "INSERT INTO user_permission_overrides
             (id, user_id, permission_code, effect, scope_type, granted_by, reason)
         VALUES ($1, $2, $3, 'ALLOW', 'GLOBAL', $2, 'test fixture')",
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind(permission)
    .execute(&app.db)
    .await
    .unwrap_or_else(|e| panic!("grant `{permission}`: {e}"));
}

/// Grant the same authority a second time, through a role rather than an override.
///
/// Used to prove that a `DENY` cannot be escaped by acquiring *more* authority.
/// The unique index on overrides makes a second identical override impossible, so
/// the additional grant has to arrive by a different route — which is also the route
/// an administrator would actually use.
pub async fn grant_via_role(app: &TestApp, user_id: Uuid, code: &str, permission: &str) {
    let role_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO roles (id, code, name, allowed_principal_type)
         VALUES ($1, $2, $2, 'INTERNAL')",
    )
    .bind(role_id)
    .bind(code)
    .execute(&app.db)
    .await
    .expect("create a role");

    sqlx::query(
        "INSERT INTO role_permissions (role_id, permission_code, scope_type)
         VALUES ($1, $2, 'GLOBAL')",
    )
    .bind(role_id)
    .bind(permission)
    .execute(&app.db)
    .await
    .expect("attach the permission to the role");

    sqlx::query("INSERT INTO user_role_assignments (id, user_id, role_id) VALUES ($1, $2, $3)")
        .bind(Uuid::now_v7())
        .bind(user_id)
        .bind(role_id)
        .execute(&app.db)
        .await
        .expect("assign the role");
}

/// Remove a grant, as `DELETE /users/{id}/permission-overrides/{id}` would.
///
/// Returns how many rows went. Used by the TOCTOU tests, which need the revocation
/// to land at a controlled instant rather than through an endpoint that would also
/// need its own authority.
pub async fn revoke_grant(app: &TestApp, user_id: Uuid, permission: &str) -> u64 {
    sqlx::query("DELETE FROM user_permission_overrides WHERE user_id = $1 AND permission_code = $2")
        .bind(user_id)
        .bind(permission)
        .execute(&app.db)
        .await
        .expect("revoke a grant")
        .rows_affected()
}

/// Log in through the real endpoint and keep both tokens.
pub async fn login(app: &TestApp, email: &str) -> (String, String) {
    let response = app
        .post(
            "/api/v1/auth/login",
            None,
            json!({"email": email, "password": TEST_PASSWORD}),
        )
        .await;
    response.assert_status(StatusCode::OK);
    assert!(
        !response.json()["mfa_required"].as_bool().unwrap_or(true),
        "the fixture account must reach a complete session in one step"
    );
    (
        response.str_at("/access_token").to_string(),
        response.str_at("/refresh_token").to_string(),
    )
}

/// Seed an account, grant it every listed permission, and log it in.
pub async fn actor(app: &TestApp, email: &str, permissions: &[&str]) -> Actor {
    let id = create_user(app, email).await;
    for permission in permissions {
        grant(app, id, permission).await;
    }
    let (access_token, refresh_token) = login(app, email).await;
    let session_id = session_id_for_token(app, &access_token).await;
    Actor {
        id,
        email: email.to_string(),
        access_token,
        refresh_token,
        session_id,
    }
}

/// Resolve a session id from an access token, the same way the application does.
pub async fn session_id_for_token(app: &TestApp, access_token: &str) -> Uuid {
    let hash = roleblank_backend::platform::crypto::tokens::hash_token(access_token);
    let row: (Uuid,) = sqlx::query_as("SELECT id FROM sessions WHERE access_token_hash = $1")
        .bind(&hash)
        .fetch_one(&app.db)
        .await
        .expect("the login must have created a session");
    row.0
}

/// Mark a session as having verified a second factor just now.
///
/// Step-up recency is recomputed from `mfa_verified_at` on every request, so this is
/// the whole of what a successful `POST /auth/mfa/verify` leaves behind that matters
/// to `require_step_up`. Enrolling and verifying a real TOTP factor would take three
/// extra round trips and a time-step wait, and would test MFA rather than the race
/// under examination.
pub async fn grant_step_up(app: &TestApp, session_id: Uuid) {
    sqlx::query("UPDATE sessions SET mfa_verified_at = now() WHERE id = $1")
        .bind(session_id)
        .execute(&app.db)
        .await
        .expect("mark the session as recently verified");
}

/// Forget the per-IP login bucket.
///
/// Every request in a test binary appears to come from loopback, so ten logins
/// across one `TestApp` exhaust `login_per_ip_per_minute`. Called explicitly, never
/// implicitly, so that a test which *should* be rate limited still is.
pub async fn reset_login_limits(app: &TestApp, email: &str) {
    app.state
        .limiter
        .reset(&keys::login_ip(TEST_CLIENT_IP))
        .await;
    app.state
        .limiter
        .reset(&keys::login_account(&email.trim().to_lowercase()))
        .await;
}

/// Forget the per-IP account-creation bucket, which invitation acceptance shares
/// with self-registration.
pub async fn reset_registration_limits(app: &TestApp) {
    app.state
        .limiter
        .reset(&keys::registration_ip(TEST_CLIENT_IP))
        .await;
}

/// Forget the per-IP password-reset bucket, which `request` and `confirm` share.
pub async fn reset_password_reset_limits(app: &TestApp, email: &str) {
    app.state
        .limiter
        .reset(&keys::password_reset_ip(TEST_CLIENT_IP))
        .await;
    app.state
        .limiter
        .reset(&keys::password_reset_account(&email.trim().to_lowercase()))
        .await;
}

// ---------------------------------------------------------------------------
// Domain fixtures
// ---------------------------------------------------------------------------

/// Create a project through the real endpoint and return its id.
pub async fn create_project(app: &TestApp, actor: &Actor, code: &str) -> Uuid {
    let response = app
        .post(
            "/api/v1/projects",
            Some(&actor.access_token),
            json!({
                "code": code,
                "name": format!("Project {code}"),
                "manager_user_id": actor.id,
            }),
        )
        .await;
    response.assert_status(StatusCode::CREATED);
    response.id_at("/id")
}

pub async fn create_task(app: &TestApp, actor: &Actor, project_id: Uuid, title: &str) -> Uuid {
    let response = app
        .post(
            "/api/v1/tasks",
            Some(&actor.access_token),
            json!({ "project_id": project_id, "title": title }),
        )
        .await;
    response.assert_status(StatusCode::CREATED);
    response.id_at("/id")
}

// ---------------------------------------------------------------------------
// Reading what the outbox was asked to send
// ---------------------------------------------------------------------------

/// The payload of the single queued event of a given type.
///
/// Reading the token out of the outbox rather than out of the token table is
/// deliberate: it is the only place the *plaintext* exists after the response has
/// been sent, so a test that finds it here has proved the recipient would have been
/// able to use it. Reading `token_hash` instead would prove nothing about the link.
pub async fn only_outbox_payload(app: &TestApp, event_type: &str) -> Value {
    let rows: Vec<(Value,)> =
        sqlx::query_as("SELECT payload FROM outbox_events WHERE event_type = $1 ORDER BY id")
            .bind(event_type)
            .fetch_all(&app.db)
            .await
            .expect("read the outbox");
    assert_eq!(
        rows.len(),
        1,
        "expected exactly one queued `{event_type}` event, found {}",
        rows.len()
    );
    rows[0].0.clone()
}

/// Pull the `token` query parameter out of a link the outbox queued.
pub fn token_from_link(link: &str) -> String {
    link.split_once("?token=")
        .map(|(_, token)| token.to_string())
        .unwrap_or_else(|| panic!("`{link}` does not carry a token"))
}

/// The invitation token that was mailed for the single queued invitation.
pub async fn queued_invitation_token(app: &TestApp) -> String {
    let payload = only_outbox_payload(app, "mail.invitation").await;
    let url = payload["invite_url"]
        .as_str()
        .unwrap_or_else(|| panic!("the invitation payload has no invite_url: {payload}"));
    token_from_link(url)
}

/// The reset token that was mailed for the single queued password reset.
pub async fn queued_reset_token(app: &TestApp) -> String {
    let payload = only_outbox_payload(app, "mail.password_reset").await;
    let url = payload["reset_url"]
        .as_str()
        .unwrap_or_else(|| panic!("the reset payload has no reset_url: {payload}"));
    token_from_link(url)
}

/// Drop every queued event, so a later assertion sees only what happened next.
pub async fn clear_outbox(app: &TestApp) {
    sqlx::query("DELETE FROM outbox_events")
        .execute(&app.db)
        .await
        .expect("clear the outbox");
}

// ---------------------------------------------------------------------------
// Counting
// ---------------------------------------------------------------------------

pub async fn count(app: &TestApp, sql: &str) -> i64 {
    let row: (i64,) = sqlx::query_as(sqlx::AssertSqlSafe(sql.to_string()))
        .fetch_one(&app.db)
        .await
        .unwrap_or_else(|e| panic!("counting with `{sql}` failed: {e}"));
    row.0
}

/// How many audit events of one action code exist.
pub async fn audit_count(app: &TestApp, action_code: &str) -> i64 {
    let row: (i64,) = sqlx::query_as("SELECT count(*) FROM audit_events WHERE action_code = $1")
        .bind(action_code)
        .fetch_one(&app.db)
        .await
        .expect("count audit events");
    row.0
}

// ---------------------------------------------------------------------------
// Measured races
// ---------------------------------------------------------------------------

/// The outcome distribution of a race, counted rather than asserted away.
///
/// **Why counting matters.** "The test passed" is not evidence about a race: a
/// suite that spawns a hundred tasks and asserts `winners == 1` reports the same
/// green whether the losers were clean `409`s or ninety-nine `500`s that happened
/// to leave the database consistent. An audit needs the distribution, so this type
/// records every status and every stable `code` and prints them.
#[derive(Default, Debug, Clone)]
pub struct Tally {
    pub by_status: BTreeMap<u16, usize>,
    pub by_code: BTreeMap<String, usize>,
    pub total: usize,
}

impl Tally {
    pub fn record(&mut self, response: &TestResponse) {
        self.total += 1;
        *self.by_status.entry(response.status.as_u16()).or_insert(0) += 1;
        // Only failures carry a stable error `code`. A *success* body may happen to
        // have a field called `code` too — a project's code, for instance — and
        // counting that alongside the error codes produced evidence like
        // `codes={"VERSION_CONFLICT": 49, "race-proj-50": 1}`, which invites exactly
        // the wrong reading.
        if response.status.is_client_error() || response.status.is_server_error() {
            if let Some(code) = response.error_code() {
                *self.by_code.entry(code.to_string()).or_insert(0) += 1;
            }
        }
    }

    /// How many responses carried a given HTTP status.
    pub fn status(&self, status: StatusCode) -> usize {
        self.by_status
            .get(&status.as_u16())
            .copied()
            .unwrap_or_default()
    }

    /// How many responses carried a given stable error `code`.
    ///
    /// Tests assert on this rather than on the status alone, because a `409` that
    /// means "you lost the race" and a `409` that means "your body was malformed"
    /// are the same number and completely different claims.
    pub fn code(&self, code: &str) -> usize {
        self.by_code.get(code).copied().unwrap_or_default()
    }

    /// Every 5xx. A race may legitimately produce refusals; it may never produce a
    /// server error, which always means the application failed to anticipate a
    /// state it created for itself.
    pub fn server_errors(&self) -> usize {
        self.by_status
            .iter()
            .filter(|(status, _)| **status >= 500)
            .map(|(_, count)| *count)
            .sum()
    }

    /// Statuses outside an expected set, for an assertion message that says which.
    pub fn unexpected(&self, allowed: &[StatusCode]) -> BTreeMap<u16, usize> {
        let allowed: Vec<u16> = allowed.iter().map(StatusCode::as_u16).collect();
        self.by_status
            .iter()
            .filter(|(status, _)| !allowed.contains(status))
            .map(|(status, count)| (*status, *count))
            .collect()
    }

    /// Print the distribution, so `--nocapture` yields the measured evidence the
    /// audit report quotes rather than a re-derivation of it.
    pub fn report(&self, label: &str) {
        println!(
            "RACE-EVIDENCE {label}: n={} statuses={:?} codes={:?}",
            self.total, self.by_status, self.by_code
        );
    }
}

/// Run `concurrency` genuinely simultaneous operations and tally the outcomes.
///
/// **Why a barrier and not just a spawn loop.** Spawning N tasks in a loop usually
/// lets the first complete before the last is scheduled, so the "race" never
/// overlaps and the test passes without exercising anything. Every task here parks
/// on the barrier and is released only once all of them have arrived, which is the
/// closest a single process can get to N requests landing at the same instant.
pub async fn race<F, Fut>(concurrency: usize, op: F) -> Tally
where
    F: Fn(usize) -> Fut + Clone + Send + Sync + 'static,
    Fut: std::future::Future<Output = TestResponse> + Send + 'static,
{
    let barrier = Arc::new(tokio::sync::Barrier::new(concurrency));
    let mut handles = Vec::with_capacity(concurrency);
    for index in 0..concurrency {
        let barrier = barrier.clone();
        let op = op.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            op(index).await
        }));
    }

    let mut tally = Tally::default();
    for handle in handles {
        let response = handle.await.expect("a racing task must not panic");
        tally.record(&response);
    }
    tally
}
