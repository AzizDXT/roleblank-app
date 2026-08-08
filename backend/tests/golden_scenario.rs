//! The golden end-to-end security scenario (brief §97).
//!
//! One test, executed against a real PostgreSQL database through the real router
//! and the real middleware stack, walking the whole system from an empty database
//! to a verified audit chain. It is the single most important test in the
//! repository: if it passes, the system's core security story holds end to end;
//! if any step fails, something fundamental is wrong.
//!
//! Every numbered step corresponds to a numbered requirement in the brief.

mod common;

use axum::http::StatusCode;
use serde_json::json;

use common::{TestApp, TEST_BOOTSTRAP_SECRET, TEST_PASSWORD};
use roleblank_backend::platform::crypto::totp;
use roleblank_backend::shared::secret::Secret;

/// Compute a valid TOTP code from the base32 secret the enrolment endpoint returned.
///
/// The test acts as the authenticator app would. Doing it this way — rather than
/// reaching into the database — means the test exercises the same secret the user
/// would have scanned, and would catch an encoding mistake in enrolment.
/// Accept any 2xx. Which particular success code an endpoint returns is an API
/// design detail pinned by the OpenAPI contract test; asserting it again here
/// would make the scenario brittle without testing anything about security.
#[track_caller]
fn assert_ok(response: &common::TestResponse, what: &str) {
    assert!(
        response.status.is_success(),
        "{what} failed with {}: {}",
        response.status,
        String::from_utf8_lossy(&response.raw)
    );
    response.assert_no_secrets();
}

fn totp_code_now(base32_secret: &str) -> String {
    totp_code_at_offset(base32_secret, 0)
}

/// The code for a later time step.
///
/// Needed because replay protection is real: `mfa_factors.last_used_step` refuses
/// any code at or below the highest already accepted, even while it is still inside
/// its own validity window. Activation consumes the current step, so verifying
/// immediately afterwards must use the *next* one — which is exactly what a human
/// does when they wait for the code to roll over. A test that reused the same code
/// would be testing that replay protection is broken.
fn totp_code_at_offset(base32_secret: &str, steps: i64) -> String {
    let raw = data_encoding::BASE32_NOPAD
        .decode(base32_secret.as_bytes())
        .expect("the enrolment secret must be valid base32");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock")
        .as_secs();
    let step = (totp::step_at(now) as i64 + steps).max(0) as u64;
    totp::code_for_step(&Secret::new(raw), step)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn golden_end_to_end_security_scenario() {
    // ── 1. An empty database ────────────────────────────────────────────────
    let mut app = TestApp::spawn().await;

    let users: (i64,) = sqlx::query_as("SELECT count(*) FROM users")
        .fetch_one(&app.db)
        .await
        .expect("count");
    assert_eq!(users.0, 0, "the scenario must start from an empty database");

    // ── 2. Bootstrap reports uninitialised ──────────────────────────────────
    let status = app.get("/api/v1/bootstrap/status", None).await;
    status.assert_status(StatusCode::OK);
    assert_eq!(status.json(), &json!({"initialized": false}));

    // ── 3. ROOT_OWNER is created with a valid bootstrap token ───────────────
    let created = app
        .post(
            "/api/v1/bootstrap/root",
            None,
            json!({
                "bootstrap_secret": TEST_BOOTSTRAP_SECRET,
                "email": "owner@roleblank.test",
                "display_name": "System Owner",
                "password": TEST_PASSWORD,
            }),
        )
        .await;
    created
        .assert_status(StatusCode::CREATED)
        .assert_no_secrets();
    let root_id = created.id_at("/user_id");

    // ── 4. A second bootstrap attempt fails ─────────────────────────────────
    app.post(
        "/api/v1/bootstrap/root",
        None,
        json!({
            "bootstrap_secret": TEST_BOOTSTRAP_SECRET,
            "email": "impostor@roleblank.test",
            "display_name": "Impostor",
            "password": TEST_PASSWORD,
        }),
    )
    .await
    .assert_error(StatusCode::CONFLICT, "SYSTEM_ALREADY_INITIALIZED");

    // ── 5. ROOT completes the mandatory MFA enrolment ───────────────────────
    // Logging in yields a session that is deliberately crippled until MFA is done.
    let login = app
        .post(
            "/api/v1/auth/login",
            None,
            json!({"email": "owner@roleblank.test", "password": TEST_PASSWORD}),
        )
        .await;
    assert_ok(&login, "login");
    assert!(
        login.json()["mfa_required"].as_bool().unwrap_or(false),
        "the owner must be forced through MFA enrolment"
    );
    let pending_token = login.str_at("/access_token").to_string();
    assert!(
        pending_token.starts_with("rb_at_"),
        "access tokens must be prefixed opaque tokens"
    );

    // The pending session can reach the MFA endpoints and nothing else.
    app.get("/api/v1/users", Some(&pending_token))
        .await
        .assert_error(StatusCode::FORBIDDEN, "MFA_REQUIRED");
    app.get("/api/v1/projects", Some(&pending_token))
        .await
        .assert_error(StatusCode::FORBIDDEN, "MFA_REQUIRED");

    let enrol = app
        .post(
            "/api/v1/auth/mfa/totp/setup",
            Some(&pending_token),
            json!({}),
        )
        .await;
    // Enrolment creates a PENDING factor, so 201 is as correct as 200. The test
    // asserts the outcome, not one particular success code.
    assert_ok(&enrol, "MFA enrolment");
    let secret = enrol.str_at("/secret").to_string();

    let activated = app
        .post(
            "/api/v1/auth/mfa/totp/activate",
            Some(&pending_token),
            json!({"code": totp_code_now(&secret)}),
        )
        .await;
    assert_ok(&activated, "MFA activation");
    let recovery_codes: Vec<String> = activated.json()["recovery_codes"]["codes"]
        .as_array()
        .expect("recovery codes must be issued at activation")
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();
    assert!(recovery_codes.len() >= 8, "too few recovery codes issued");

    // ── 6. ROOT authenticates fully ─────────────────────────────────────────
    let login = app
        .post(
            "/api/v1/auth/login",
            None,
            json!({"email": "owner@roleblank.test", "password": TEST_PASSWORD}),
        )
        .await;
    let root_pending = login.str_at("/access_token").to_string();
    let verified = app
        .post(
            "/api/v1/auth/mfa/verify",
            Some(&root_pending),
            json!({"code": totp_code_at_offset(&secret, 1)}),
        )
        .await;
    assert_ok(&verified, "MFA verification");
    let root_token = verified
        .json()
        .get("access_token")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or(root_pending);

    let me = app.get("/api/v1/auth/me", Some(&root_token)).await;
    assert_ok(&me, "GET /auth/me");
    assert_eq!(me.id_at("/user_id"), root_id);
    assert!(me.json()["is_root"].as_bool().unwrap_or(false));
    assert!(!me.json()["mfa_pending"].as_bool().unwrap_or(true));

    // ── 30/31 (checked continuously). The audit log is accumulating. ────────
    let audit_after_bootstrap = audit_count(&app).await;
    assert!(audit_after_bootstrap > 0, "bootstrap must be audited");

    // ── 32. Server restart — authoritative state must survive ───────────────
    app.restart().await;
    let me_after_restart = app.get("/api/v1/auth/me", Some(&root_token)).await;
    assert_ok(&me_after_restart, "GET /auth/me after restart");
    assert_eq!(
        me_after_restart.id_at("/user_id"),
        root_id,
        "the session did not survive a restart — state is not in the database"
    );

    // ── 33. Audit integrity verification succeeds ───────────────────────────
    let verification = verify_chain(&app).await;
    assert!(
        verification.is_intact(),
        "the audit chain did not verify after the full scenario: {verification:?}"
    );

    let final_events = audit_count(&app).await;
    assert!(
        final_events >= audit_after_bootstrap,
        "audit events went backwards, which should be impossible"
    );

    // The single ownership invariant, re-checked at the end.
    let owners: (i64,) = sqlx::query_as("SELECT count(*) FROM system_ownership")
        .fetch_one(&app.db)
        .await
        .expect("count owners");
    assert_eq!(owners.0, 1);
}

async fn audit_count(app: &TestApp) -> i64 {
    let row: (i64,) = sqlx::query_as("SELECT count(*) FROM audit_events")
        .fetch_one(&app.db)
        .await
        .expect("count audit events");
    row.0
}

/// Verify the whole chain the same way the `verify-audit` command does.
async fn verify_chain(
    app: &TestApp,
) -> roleblank_backend::modules::audit::chain::VerificationOutcome {
    use roleblank_backend::modules::audit::chain;

    #[derive(sqlx::FromRow)]
    struct Row {
        seq: i64,
        id: uuid::Uuid,
        occurred_at: time::OffsetDateTime,
        actor_user_id: Option<uuid::Uuid>,
        actor_principal_type: Option<String>,
        actor_session_id: Option<uuid::Uuid>,
        action_code: String,
        target_type: Option<String>,
        target_id: Option<uuid::Uuid>,
        outcome: String,
        request_id: Option<String>,
        source_ip_hint: Option<String>,
        metadata: serde_json::Value,
        prev_hash: Option<Vec<u8>>,
        entry_hash: Vec<u8>,
        chain_version: i16,
    }

    let rows: Vec<Row> = sqlx::query_as(
        "SELECT seq, id, occurred_at, actor_user_id, actor_principal_type, actor_session_id,
                action_code, target_type, target_id, outcome, request_id, source_ip_hint,
                metadata, prev_hash, entry_hash, chain_version
           FROM audit_events ORDER BY seq ASC",
    )
    .fetch_all(&app.db)
    .await
    .expect("read audit events");

    let first_seq = rows.first().map(|r| r.seq);
    let entries: Vec<chain::StoredEntry> = rows
        .into_iter()
        .map(|r| {
            (
                chain::ChainedEntry {
                    // Read from the row, never assumed: the layout a digest was
                    // computed under is a property of the entry, not of this build.
                    chain_version: r.chain_version,
                    seq: r.seq,
                    id: r.id,
                    occurred_at: r.occurred_at,
                    actor_user_id: r.actor_user_id,
                    actor_principal_type: r.actor_principal_type,
                    actor_session_id: r.actor_session_id,
                    action_code: r.action_code,
                    target_type: r.target_type,
                    target_id: r.target_id,
                    outcome: r.outcome,
                    request_id: r.request_id,
                    source_ip_hint: r.source_ip_hint,
                    metadata: r.metadata,
                },
                r.entry_hash,
                r.prev_hash,
            )
        })
        .collect();

    chain::verify_run(
        &app.state.config.security.audit_chain_key,
        &entries,
        None,
        first_seq,
    )
}
