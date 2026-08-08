//! The world the hardening suites attack, plus the shared evidence helpers.
//!
//! This fixture is deliberately separate from `tests/security/fixtures.rs`. The
//! security suites attack the *authorisation* surface and need a world shaped for
//! scope resolution; these suites attack the *input* surface and need three things
//! that world does not offer:
//!
//!   1. the **real secret material** of the running instance — the Argon2 digest,
//!      the encrypted TOTP secret, the session and refresh token digests — so that
//!      §10 can assert on the actual bytes rather than only on field names;
//!   2. a **whole-database snapshot** so that §9 and §13 can prove state did not
//!      move by reading it back, rather than by trusting a status code;
//!   3. one principal of every kind holding a live token, because the leakage scan
//!      walks `ROUTE_TABLE` once per principal.
//!
//! Business rows are seeded with SQL for the same reason the security fixture does
//! it: composing thirty setup requests would burn rate-limit budget the attacks
//! need, and a fixture failure would read as a security failure. Identity is still
//! built through the genuine paths — ROOT via the bootstrap endpoint, MFA via the
//! real TOTP flow, every token via a real login.

#![allow(dead_code)] // each suite attacks a different part of the world

use std::collections::BTreeMap;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use serde_json::json;
use uuid::Uuid;

use crate::common::{TestApp, TEST_BOOTSTRAP_SECRET, TEST_PASSWORD};
use roleblank_backend::platform::crypto::totp;
use roleblank_backend::platform::http::rate_limit::keys;
use roleblank_backend::shared::secret::Secret;

pub const ROLE_SYSTEM_ADMINISTRATOR: &str = "00000000-0000-7000-8000-000000000001";
pub const ROLE_EMPLOYEE: &str = "00000000-0000-7000-8000-000000000002";
pub const ROLE_CLIENT_USER: &str = "00000000-0000-7000-8000-000000000003";

pub const ROOT_EMAIL: &str = "owner@hardening.test";
pub const ADMIN_EMAIL: &str = "admin@hardening.test";
pub const EMPLOYEE_EMAIL: &str = "employee@hardening.test";
pub const VICTIM_EMAIL: &str = "victim@hardening.test";
pub const CLIENT_EMAIL: &str = "external@clientfirm.test";

/// An authenticated principal and the bearer token it holds.
#[derive(Debug, Clone)]
pub struct Actor {
    pub id: Uuid,
    pub email: String,
    pub token: String,
}

impl Actor {
    pub fn bearer(&self) -> Option<&str> {
        Some(self.token.as_str())
    }
}

pub struct World {
    pub app: TestApp,

    /// The system owner. Bypasses the evaluator, so it is the actor that proves a
    /// refusal came from input validation rather than from a missing permission.
    pub root: Actor,
    /// `system_administrator` plus an explicit `iam.permissions.delegate@GLOBAL`,
    /// with a recent second factor so step-up routes are reachable.
    pub admin: Actor,
    /// The least-privileged internal principal.
    pub employee: Actor,
    /// The only external principal. Everything it can see is a client-portal read.
    pub client: Actor,

    /// Another internal account, never logged in: the object every mass-assignment
    /// probe aims at, so that a successful escalation would be visible in its row.
    pub victim: Uuid,

    pub department: Uuid,
    pub client_account: Uuid,
    /// Shared with `client_account`, so the portal has something to return.
    pub project: Uuid,
    /// In `project`, `client_visible = true`.
    pub task: Uuid,
    /// In `project`, `client_visible = false` — the row whose `internal_note` must
    /// never reach an external principal.
    pub hidden_task: Uuid,
}

impl World {
    pub async fn build() -> Self {
        let app = TestApp::spawn().await;

        let created = app
            .post(
                "/api/v1/bootstrap/root",
                None,
                json!({
                    "bootstrap_secret": TEST_BOOTSTRAP_SECRET,
                    "email": ROOT_EMAIL,
                    "display_name": "System Owner",
                    "password": TEST_PASSWORD,
                }),
            )
            .await;
        created.assert_status(StatusCode::CREATED);
        let root_id = created.id_at("/user_id");

        let root_token = login(&app, ROOT_EMAIL).await;
        enrol_totp(&app, &root_token).await;

        let hash = password_hash(&app).await;
        let admin_id = seed_user(&app, ADMIN_EMAIL, "INTERNAL", &hash).await;
        let employee_id = seed_user(&app, EMPLOYEE_EMAIL, "INTERNAL", &hash).await;
        let victim = seed_user(&app, VICTIM_EMAIL, "INTERNAL", &hash).await;
        let client_id = seed_user(&app, CLIENT_EMAIL, "CLIENT", &hash).await;

        assign_role(&app, admin_id, ROLE_SYSTEM_ADMINISTRATOR, root_id).await;
        assign_role(&app, employee_id, ROLE_EMPLOYEE, root_id).await;
        assign_role(&app, victim, ROLE_EMPLOYEE, root_id).await;
        assign_role(&app, client_id, ROLE_CLIENT_USER, root_id).await;

        // The built-in administrator role withholds delegation on purpose. Granting
        // it explicitly means a refusal on a delegation route is the control under
        // test rather than a missing permission.
        grant_override(
            &app,
            admin_id,
            "iam.permissions.delegate",
            "ALLOW",
            "GLOBAL",
            root_id,
        )
        .await;

        let department = seed_department(&app, "engineering", root_id).await;
        add_department_member(&app, department, employee_id, root_id).await;
        add_department_member(&app, department, victim, root_id).await;

        let client_account = seed_client_account(&app, "client-firm", root_id).await;
        add_client_member(&app, client_account, client_id, root_id).await;

        let project = seed_project(&app, "delivery", root_id, department).await;
        add_project_member(&app, project, employee_id, root_id).await;
        share_project(&app, project, client_account, root_id).await;

        let task = seed_task(&app, project, "visible work", true, root_id).await;
        let hidden_task = seed_task(&app, project, "hidden work", false, root_id).await;

        let admin_token = login(&app, ADMIN_EMAIL).await;
        enrol_totp(&app, &admin_token).await;
        let employee_token = login(&app, EMPLOYEE_EMAIL).await;
        let client_token = login(&app, CLIENT_EMAIL).await;

        reset_auth_limits(&app).await;

        World {
            root: Actor {
                id: root_id,
                email: ROOT_EMAIL.into(),
                token: root_token,
            },
            admin: Actor {
                id: admin_id,
                email: ADMIN_EMAIL.into(),
                token: admin_token,
            },
            employee: Actor {
                id: employee_id,
                email: EMPLOYEE_EMAIL.into(),
                token: employee_token,
            },
            client: Actor {
                id: client_id,
                email: CLIENT_EMAIL.into(),
                token: client_token,
            },
            victim,
            department,
            client_account,
            project,
            task,
            hidden_task,
            app,
        }
    }

    /// Every principal a suite may act as, including the absence of one.
    pub fn principals(&self) -> Vec<(&'static str, Option<&str>)> {
        vec![
            ("anonymous", None),
            ("root", self.root.bearer()),
            ("admin", self.admin.bearer()),
            ("employee", self.employee.bearer()),
            ("client", self.client.bearer()),
        ]
    }
}

// ===========================================================================
// Identity helpers
// ===========================================================================

pub async fn password_hash(app: &TestApp) -> String {
    app.state
        .hasher
        .hash(&Secret::new(TEST_PASSWORD.to_string()))
        .await
        .expect("hash the fixture password")
}

pub async fn seed_user(app: &TestApp, email: &str, principal_type: &str, hash: &str) -> Uuid {
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

pub async fn assign_role(app: &TestApp, user_id: Uuid, role_id: &str, granted_by: Uuid) {
    sqlx::query(
        "INSERT INTO user_role_assignments (id, user_id, role_id, granted_by)
         VALUES ($1, $2, $3::uuid, $4)",
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind(role_id)
    .bind(granted_by)
    .execute(&app.db)
    .await
    .expect("assign a role");
}

pub async fn grant_override(
    app: &TestApp,
    user_id: Uuid,
    permission_code: &str,
    effect: &str,
    scope: &str,
    granted_by: Uuid,
) {
    sqlx::query(
        "INSERT INTO user_permission_overrides
             (id, user_id, permission_code, effect, scope_type, granted_by)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind(permission_code)
    .bind(effect)
    .bind(scope)
    .bind(granted_by)
    .execute(&app.db)
    .await
    .expect("seed an override");
}

pub async fn login(app: &TestApp, email: &str) -> String {
    let response = app
        .post(
            "/api/v1/auth/login",
            None,
            json!({"email": email, "password": TEST_PASSWORD}),
        )
        .await;
    response.assert_status(StatusCode::OK);
    response.str_at("/access_token").to_string()
}

/// Enrol and activate TOTP through the genuine flow, which also stamps
/// `mfa_verified_at` and so satisfies the step-up window.
pub async fn enrol_totp(app: &TestApp, token: &str) {
    let enrol = app
        .post("/api/v1/auth/mfa/totp/setup", Some(token), json!({}))
        .await;
    assert!(
        enrol.status.is_success(),
        "TOTP enrolment failed with {}: {}",
        enrol.status,
        String::from_utf8_lossy(&enrol.raw)
    );
    let secret = enrol.str_at("/secret").to_string();

    let activated = app
        .post(
            "/api/v1/auth/mfa/totp/activate",
            Some(token),
            json!({"code": totp_code_now(&secret)}),
        )
        .await;
    assert!(
        activated.status.is_success(),
        "TOTP activation failed with {}: {}",
        activated.status,
        String::from_utf8_lossy(&activated.raw)
    );
}

pub fn totp_code_now(base32_secret: &str) -> String {
    let raw = data_encoding::BASE32_NOPAD
        .decode(base32_secret.as_bytes())
        .expect("the enrolment secret must be valid base32");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock")
        .as_secs();
    totp::code_for_step(&Secret::new(raw), totp::step_at(now))
}

/// Forget the per-IP and per-account buckets the fixture's own logins consumed, so
/// that a suite's deliberate probing is throttled by the control under test rather
/// than by the fixture.
pub async fn reset_auth_limits(app: &TestApp) {
    let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
    app.state.limiter.reset(&keys::login_ip(ip)).await;
    app.state.limiter.reset(&keys::refresh_ip(ip)).await;
    app.state.limiter.reset(&keys::password_reset_ip(ip)).await;
    app.state.limiter.reset(&keys::registration_ip(ip)).await;
    app.state
        .limiter
        .reset(&keys::invitation_accept_ip(ip))
        .await;
    for email in [
        ROOT_EMAIL,
        ADMIN_EMAIL,
        EMPLOYEE_EMAIL,
        VICTIM_EMAIL,
        CLIENT_EMAIL,
    ] {
        app.state.limiter.reset(&keys::login_account(email)).await;
        app.state
            .limiter
            .reset(&keys::password_reset_account(email))
            .await;
    }
}

// ===========================================================================
// Company structure helpers
// ===========================================================================

pub async fn seed_department(app: &TestApp, code: &str, created_by: Uuid) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO departments (id, code, name, status, created_by)
         VALUES ($1, $2, $3, 'ACTIVE', $4)",
    )
    .bind(id)
    .bind(code)
    .bind(code)
    .bind(created_by)
    .execute(&app.db)
    .await
    .expect("seed a department");
    id
}

pub async fn add_department_member(app: &TestApp, department_id: Uuid, user_id: Uuid, by: Uuid) {
    sqlx::query(
        "INSERT INTO department_memberships (id, department_id, user_id, role_in_department, added_by)
         VALUES ($1, $2, $3, 'MEMBER', $4)",
    )
    .bind(Uuid::now_v7())
    .bind(department_id)
    .bind(user_id)
    .bind(by)
    .execute(&app.db)
    .await
    .expect("seed a department membership");
}

pub async fn seed_client_account(app: &TestApp, code: &str, created_by: Uuid) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO client_accounts (id, code, name, status, created_by)
         VALUES ($1, $2, $3, 'ACTIVE', $4)",
    )
    .bind(id)
    .bind(code)
    .bind(code)
    .bind(created_by)
    .execute(&app.db)
    .await
    .expect("seed a client account");
    id
}

pub async fn add_client_member(app: &TestApp, client_account_id: Uuid, user_id: Uuid, by: Uuid) {
    sqlx::query(
        "INSERT INTO client_memberships (id, client_account_id, user_id, status, invited_by, activated_at)
         VALUES ($1, $2, $3, 'ACTIVE', $4, now())",
    )
    .bind(Uuid::now_v7())
    .bind(client_account_id)
    .bind(user_id)
    .bind(by)
    .execute(&app.db)
    .await
    .expect("seed a client membership");
}

pub async fn seed_project(
    app: &TestApp,
    code: &str,
    manager_user_id: Uuid,
    department_id: Uuid,
) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO projects (id, code, name, description, status, manager_user_id,
                               department_id, internal_note, created_by)
         VALUES ($1, $2, $3, 'a project', 'ACTIVE', $4, $5, $6, $4)",
    )
    .bind(id)
    .bind(code)
    .bind(code)
    .bind(manager_user_id)
    .bind(department_id)
    .bind(INTERNAL_NOTE_MARKER)
    .execute(&app.db)
    .await
    .expect("seed a project");
    id
}

pub async fn add_project_member(app: &TestApp, project_id: Uuid, user_id: Uuid, by: Uuid) {
    sqlx::query(
        "INSERT INTO project_memberships (id, project_id, user_id, role_in_project, added_by)
         VALUES ($1, $2, $3, 'MEMBER', $4)",
    )
    .bind(Uuid::now_v7())
    .bind(project_id)
    .bind(user_id)
    .bind(by)
    .execute(&app.db)
    .await
    .expect("seed a project membership");
}

pub async fn share_project(app: &TestApp, project_id: Uuid, client_account_id: Uuid, by: Uuid) {
    sqlx::query(
        "INSERT INTO project_client_links (id, project_id, client_account_id, shared_by)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(Uuid::now_v7())
    .bind(project_id)
    .bind(client_account_id)
    .bind(by)
    .execute(&app.db)
    .await
    .expect("share a project");
}

pub async fn seed_task(
    app: &TestApp,
    project_id: Uuid,
    title: &str,
    client_visible: bool,
    created_by: Uuid,
) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO tasks (id, project_id, title, description, status, client_visible,
                            internal_note, created_by)
         VALUES ($1, $2, $3, 'a task', 'TODO', $4, $5, $6)",
    )
    .bind(id)
    .bind(project_id)
    .bind(title)
    .bind(client_visible)
    .bind(INTERNAL_NOTE_MARKER)
    .bind(created_by)
    .execute(&app.db)
    .await
    .expect("seed a task");
    id
}

/// A distinctive string written into every `internal_note`. An external principal
/// seeing it anywhere is a confidentiality failure, and a literal marker is easier
/// to assert on than the column name.
pub const INTERNAL_NOTE_MARKER: &str = "INTERNAL-ONLY-CANARY-9f2c";

// ===========================================================================
// Raw request construction
// ===========================================================================

/// Build a request the ordinary helpers cannot express: a chosen content type, raw
/// (possibly non-UTF-8) bytes, extra headers.
pub fn raw_request(
    method: Method,
    path: &str,
    token: Option<&str>,
    content_type: Option<&str>,
    headers: &[(&str, &str)],
    body: Vec<u8>,
) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(t) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    if let Some(ct) = content_type {
        builder = builder.header(header::CONTENT_TYPE, ct);
    }
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    builder.body(Body::from(body)).expect("build a request")
}

// ===========================================================================
// Database snapshots — the evidence that state did not move
// ===========================================================================

/// Every table in the public schema with its exact row count.
///
/// `count(*)` rather than `pg_stat_user_tables.n_live_tup`: the statistics view
/// lags behind the transaction and would make a successful injection look like no
/// change at all, which is precisely the failure this snapshot exists to catch.
///
/// **The `AssertSqlSafe` audit for this helper:** the only interpolated value is a
/// table name read back from `information_schema.tables`, passed through
/// `quote_ident`. No request data reaches it, and it is test-only code.
pub async fn snapshot(app: &TestApp) -> BTreeMap<String, i64> {
    let tables: Vec<(String,)> = sqlx::query_as(
        "SELECT quote_ident(table_name)
           FROM information_schema.tables
          WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
          ORDER BY table_name",
    )
    .fetch_all(&app.db)
    .await
    .expect("list the tables");

    let mut counts = BTreeMap::new();
    for (table,) in tables {
        let (n,): (i64,) = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT count(*) FROM public.{table}"
        )))
        .fetch_one(&app.db)
        .await
        .unwrap_or_else(|e| panic!("count {table}: {e}"));
        counts.insert(table, n);
    }
    counts
}

/// The columns of a user row that decide what the account *is*. A mass-assignment
/// success would move at least one of them.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct UserEnvelope {
    pub email: String,
    pub display_name: String,
    pub principal_type: String,
    pub status: String,
    pub mfa_required: bool,
    pub mfa_enrolled: bool,
    pub security_version: i32,
    pub version: i32,
}

pub async fn user_envelope(app: &TestApp, id: Uuid) -> UserEnvelope {
    sqlx::query_as(
        "SELECT email, display_name, principal_type, status, mfa_required, mfa_enrolled,
                security_version, version
           FROM users WHERE id = $1",
    )
    .bind(id)
    .fetch_one(&app.db)
    .await
    .expect("read the user envelope")
}

/// Which roles and overrides a user actually holds, ordered so the comparison is
/// stable.
pub async fn authority_of(app: &TestApp, id: Uuid) -> (Vec<Uuid>, Vec<String>) {
    let roles: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT role_id FROM user_role_assignments WHERE user_id = $1 ORDER BY role_id",
    )
    .bind(id)
    .fetch_all(&app.db)
    .await
    .expect("read role assignments");

    let overrides: Vec<(String,)> = sqlx::query_as(
        "SELECT permission_code || '/' || effect || '/' || scope_type
           FROM user_permission_overrides
          WHERE user_id = $1 ORDER BY 1",
    )
    .bind(id)
    .fetch_all(&app.db)
    .await
    .expect("read overrides");

    (
        roles.into_iter().map(|(r,)| r).collect(),
        overrides.into_iter().map(|(o,)| o).collect(),
    )
}

/// Is this user the system owner, according to the only table that decides it?
pub async fn is_root_in_db(app: &TestApp, id: Uuid) -> bool {
    let found: Option<(Uuid,)> =
        sqlx::query_as("SELECT root_user_id FROM system_ownership WHERE root_user_id = $1")
            .bind(id)
            .fetch_optional(&app.db)
            .await
            .expect("read system ownership");
    found.is_some()
}

// ===========================================================================
// The forbidden-material scanner (§10)
// ===========================================================================

/// Substrings that must never appear in a response body, whatever the endpoint and
/// whatever the principal.
///
/// Two kinds are mixed deliberately. The **structural** entries (`password_hash`,
/// `token_hash`, …) catch a DTO that started serialising a row struct; they are
/// column and field names, so they fire the moment a projection widens. The
/// **material** entries (`$argon2`, `postgres://`, the development passwords) catch
/// the value itself arriving by some other name. Neither alone is sufficient: a
/// leak renamed to `digest` passes the first, and a leak of an empty column passes
/// the second.
pub const FORBIDDEN_SUBSTRINGS: &[&str] = &[
    // --- credential material -------------------------------------------------
    //
    // The bare word "credentials" is deliberately *not* here: it appears in the
    // authentication-failure prose ("The credentials or token supplied are not
    // valid"), so including it would make the scan fire on the correct behaviour
    // and force somebody to weaken it later. The column name is what matters.
    "password_hash",
    "$argon2",
    "argon2id",
    // --- token digests of every kind ----------------------------------------
    "token_hash",
    "access_token_hash",
    "refresh_token_hash",
    // The digest column, not the words "recovery code": `MFA.RECOVERY_CODES_
    // GENERATED` is an audit action code that an auditor is meant to read, and
    // `POST /auth/mfa/recovery/regenerate` returns the plaintext codes once by
    // design. Forbidding the phrase would make the scan fire on both.
    "code_hash",
    // --- MFA material --------------------------------------------------------
    "secret_ciphertext",
    "secret_nonce",
    "key_version",
    // --- audit chain material -----------------------------------------------
    "entry_hash",
    "prev_hash",
    "chain_key",
    // --- key and connection material ----------------------------------------
    "encryption_key",
    "bootstrap_secret",
    "postgres://",
    "dev_app_pw",
    "dev_migrator_pw",
    "dev_superuser_pw",
    "roleblank_migrator",
    "roleblank_app",
    "DATABASE_URL",
    // --- internals that would betray the implementation ----------------------
    "/work/src",
    "panicked",
    "RUST_BACKTRACE",
    "sqlx::",
    "SELECT ",
    "INSERT INTO",
    "pg_catalog",
    "information_schema",
];

/// Live secret values read out of the running instance.
///
/// Asserting on the real bytes is what makes the scan more than a name filter: a
/// response that leaked the Argon2 digest under the key `"h"` would pass every
/// structural check and fail this one.
pub struct LiveSecrets {
    pub values: Vec<(String, String)>,
}

impl LiveSecrets {
    pub async fn collect(app: &TestApp) -> Self {
        let mut values = Vec::new();

        let hashes: Vec<(String,)> = sqlx::query_as("SELECT password_hash FROM credentials")
            .fetch_all(&app.db)
            .await
            .expect("read credentials");
        for (h,) in hashes {
            values.push(("credentials.password_hash".to_string(), h));
        }

        // Digests and ciphertexts are `bytea`; both the hex and the base64 spelling
        // are checked because either is a plausible accidental encoding.
        let blobs: Vec<(String, Vec<u8>)> = sqlx::query_as(
            "SELECT 'sessions.access_token_hash', access_token_hash FROM sessions
             UNION ALL SELECT 'session_refresh_tokens.token_hash', token_hash FROM session_refresh_tokens
             UNION ALL SELECT 'mfa_factors.secret_ciphertext', secret_ciphertext FROM mfa_factors
             UNION ALL SELECT 'mfa_factors.secret_nonce', secret_nonce FROM mfa_factors
             UNION ALL SELECT 'recovery_codes.code_hash', code_hash FROM recovery_codes
             UNION ALL SELECT 'audit_events.entry_hash', entry_hash FROM audit_events",
        )
        .fetch_all(&app.db)
        .await
        .expect("read secret blobs");
        for (label, raw) in blobs {
            values.push((
                format!("{label} (hex)"),
                data_encoding::HEXLOWER.encode(&raw),
            ));
            values.push((
                format!("{label} (base64)"),
                data_encoding::BASE64.encode(&raw),
            ));
        }

        // `INTERNAL_NOTE_MARKER` is deliberately absent: an internal principal is
        // *supposed* to read `internal_note`, so it is not a secret everywhere —
        // only across the client envelope, which
        // `the_client_portal_never_returns_internal_columns` asserts on its own.

        Self { values }
    }
}

/// Assert that one response body carries no forbidden material.
///
/// `context` names the request so a failure identifies the endpoint and principal
/// without the caller having to format it into every call.
#[track_caller]
pub fn assert_body_is_clean(context: &str, body: &[u8], live: Option<&LiveSecrets>) {
    let text = String::from_utf8_lossy(body);
    let lowered = text.to_lowercase();

    for forbidden in FORBIDDEN_SUBSTRINGS {
        assert!(
            !lowered.contains(&forbidden.to_lowercase()),
            "{context} leaked `{forbidden}`\nbody: {}",
            truncate(&text)
        );
    }

    if let Some(live) = live {
        for (label, value) in &live.values {
            // A short or empty secret would match by accident; the fixture's are all
            // long, so a low bound is enough to keep the assertion honest.
            if value.len() < 16 {
                continue;
            }
            assert!(
                !text.contains(value.as_str()),
                "{context} leaked the live value of {label}\nbody: {}",
                truncate(&text)
            );
        }
    }
}

fn truncate(text: &str) -> String {
    if text.len() <= 2000 {
        return text.to_string();
    }
    let mut end = 2000;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}… ({} bytes)", &text[..end], text.len())
}

// ===========================================================================
// The attack corpus, shared by §11, §12 and §13
// ===========================================================================

/// Strings that try to break out of a log line.
pub fn log_injection_payloads() -> Vec<(&'static str, String)> {
    vec![
        (
            "crlf-forged-json-record",
            "victim\r\n{\"timestamp\":\"2020-01-01T00:00:00Z\",\"level\":\"ERROR\",\
             \"message\":\"root password changed\"}"
                .to_string(),
        ),
        (
            "bare-newline-forged-text-record",
            "victim\n2020-01-01T00:00:00Z ERROR roleblank_backend: chain verification failed"
                .to_string(),
        ),
        ("carriage-return-overwrite", "victim\rADMIN".to_string()),
        ("ansi-escape", "victim\u{1b}[31mRED\u{1b}[0m".to_string()),
        (
            "ansi-erase-line",
            "victim\u{1b}[2K\u{1b}[1Gforged".to_string(),
        ),
        ("nul-byte", "victim\u{0}truncated".to_string()),
        ("vertical-tab-and-formfeed", "victim\u{b}\u{c}x".to_string()),
        (
            "unicode-line-separators",
            "victim\u{2028}forged\u{2029}forged".to_string(),
        ),
        (
            "json-structure-break",
            "victim\",\"level\":\"CRITICAL\",\"x\":\"".to_string(),
        ),
        (
            "bearer-token-smuggling",
            "Bearer rb_at_deadbeefdeadbeefdeadbeefdeadbeef".to_string(),
        ),
        (
            "authorization-header-forgery",
            "authorization: Bearer rb_at_0123456789abcdef".to_string(),
        ),
        ("very-long", "A".repeat(20_000)),
        (
            "long-with-crlf",
            format!("{}\r\nINJECTED", "B".repeat(5_000)),
        ),
    ]
}

/// Strings that try to change the meaning of a SQL statement.
pub fn sql_injection_payloads() -> Vec<&'static str> {
    vec![
        "' OR '1'='1",
        "' OR 1=1--",
        "'; DROP TABLE users; --",
        "'; DELETE FROM audit_events; --",
        "'); DROP TABLE tasks; --",
        "\" OR \"\"=\"",
        "1; TRUNCATE users CASCADE",
        "1 UNION SELECT password_hash, null, null FROM credentials",
        "' UNION ALL SELECT password_hash FROM credentials--",
        "admin'--",
        "admin'/*",
        "%' OR principal_type='INTERNAL' --",
        "_",
        "%",
        "\\",
        "' || (SELECT password_hash FROM credentials LIMIT 1) || '",
        "$$; DROP TABLE users; SELECT $$",
        "1;SELECT pg_sleep(10)--",
        "'||pg_sleep(10)||'",
        "' AND 1=(SELECT count(*) FROM pg_stat_activity)--",
        "COPY users TO PROGRAM 'id'",
        "'; SET ROLE postgres; --",
        "\u{0}' OR 1=1--",
        "created_at; DROP TABLE users--",
        "(SELECT password_hash FROM credentials)",
        "*",
        "u.email_normalized",
    ]
}
