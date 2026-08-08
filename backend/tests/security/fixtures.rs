//! The adversarial world every attack suite is run against.
//!
//! One small company, two unrelated client firms, and one principal of every kind
//! that matters. Built once per test so that a suite can attack it from any
//! direction without each test re-deriving what "another client's project" means.
//!
//! **Why the business rows are seeded with SQL rather than through HTTP.** The
//! thing under attack is the *authorisation* surface, not the creation endpoints,
//! and composing thirty setup requests per test would (a) burn the login rate-limit
//! budget the suites need for their own attacks and (b) make a fixture failure look
//! like a security failure. Identity itself is still built through the real paths
//! where it matters: ROOT is created by the genuine bootstrap endpoint, MFA is
//! enrolled through the genuine TOTP flow, and every principal obtains its token by
//! logging in. The attacks themselves are *always* HTTP.

#![allow(dead_code)] // each suite attacks a different part of the world

use axum::http::StatusCode;
use serde_json::json;
use uuid::Uuid;

use crate::common::{TestApp, TEST_BOOTSTRAP_SECRET, TEST_PASSWORD};
use roleblank_backend::platform::crypto::totp;
use roleblank_backend::platform::http::rate_limit::keys;
use roleblank_backend::shared::secret::Secret;

/// The built-in roles seeded by migration 0008. Their identifiers are fixed, which
/// is what makes them usable as fixture constants.
pub const ROLE_SYSTEM_ADMINISTRATOR: &str = "00000000-0000-7000-8000-000000000001";
pub const ROLE_EMPLOYEE: &str = "00000000-0000-7000-8000-000000000002";
pub const ROLE_CLIENT_USER: &str = "00000000-0000-7000-8000-000000000003";

pub const ROOT_EMAIL: &str = "owner@fixture.test";
pub const ADMIN_EMAIL: &str = "admin@fixture.test";
pub const EMPLOYEE_EMAIL: &str = "employee@fixture.test";
pub const MANAGER_EMAIL: &str = "manager@fixture.test";
pub const OTHER_EMPLOYEE_EMAIL: &str = "colleague@fixture.test";
pub const CLIENT_A_EMAIL: &str = "a@clientfirm-a.test";
pub const CLIENT_B_EMAIL: &str = "b@clientfirm-b.test";

/// A UUID that names nothing. Used for "guess an identifier" probes, where the
/// correct answer must be indistinguishable from "you may not see this one".
pub fn unknown_id() -> Uuid {
    Uuid::now_v7()
}

/// An authenticated principal: who they are and the bearer token they hold.
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

/// The whole world, plus the app it lives in.
pub struct World {
    pub app: TestApp,

    pub root: Actor,
    /// Broad administrator: the built-in `system_administrator` role plus an
    /// explicit `iam.permissions.delegate@GLOBAL` override, so that when it is
    /// refused on ROOT the refusal is the ROOT guard and not a missing permission.
    pub admin: Actor,
    /// Baseline employee: the built-in `employee` role and nothing else.
    pub employee: Actor,
    /// The same baseline role, but an active member of `internal_project` and of
    /// the department — so `ASSIGNED` and `DEPARTMENT` scopes actually resolve.
    pub manager: Actor,
    pub client_a: Actor,
    pub client_b: Actor,

    /// An internal colleague who never logs in: the "another employee" resource.
    pub other_employee: Uuid,

    pub department: Uuid,
    pub client_account_a: Uuid,
    pub client_account_b: Uuid,

    /// Shared with nobody.
    pub internal_project: Uuid,
    /// Shared with client account A only.
    pub project_shared_a: Uuid,
    /// Shared with client account B only.
    pub project_shared_b: Uuid,

    /// In `project_shared_a`, `client_visible = false`.
    pub hidden_task: Uuid,
    /// In `project_shared_a`, `client_visible = true`.
    pub visible_task: Uuid,
    /// In `internal_project`, `client_visible = false`.
    pub internal_task: Uuid,
    /// In `project_shared_b`, `client_visible = true` — visible to B, never to A.
    pub task_of_b: Uuid,
}

impl World {
    /// Build the world. Roughly six logins and two TOTP enrolments.
    pub async fn build() -> Self {
        let app = TestApp::spawn().await;

        // ---- ROOT, through the genuine bootstrap and MFA paths ----------------
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
        let root = Actor {
            id: root_id,
            email: ROOT_EMAIL.into(),
            token: root_token,
        };

        // ---- everyone else ----------------------------------------------------
        let hash = password_hash(&app).await;

        let admin_id = seed_user(&app, ADMIN_EMAIL, "INTERNAL", &hash).await;
        let employee_id = seed_user(&app, EMPLOYEE_EMAIL, "INTERNAL", &hash).await;
        let manager_id = seed_user(&app, MANAGER_EMAIL, "INTERNAL", &hash).await;
        let other_employee = seed_user(&app, OTHER_EMPLOYEE_EMAIL, "INTERNAL", &hash).await;
        let client_a_id = seed_user(&app, CLIENT_A_EMAIL, "CLIENT", &hash).await;
        let client_b_id = seed_user(&app, CLIENT_B_EMAIL, "CLIENT", &hash).await;

        assign_role(&app, admin_id, ROLE_SYSTEM_ADMINISTRATOR, root_id).await;
        assign_role(&app, employee_id, ROLE_EMPLOYEE, root_id).await;
        assign_role(&app, manager_id, ROLE_EMPLOYEE, root_id).await;
        assign_role(&app, other_employee, ROLE_EMPLOYEE, root_id).await;
        assign_role(&app, client_a_id, ROLE_CLIENT_USER, root_id).await;
        assign_role(&app, client_b_id, ROLE_CLIENT_USER, root_id).await;

        // The built-in administrator role deliberately excludes delegation. Adding
        // it explicitly is what makes the ROOT attacks meaningful: the administrator
        // genuinely holds the authority, and only the ROOT guard stops it.
        grant_override(
            &app,
            admin_id,
            "iam.permissions.delegate",
            "ALLOW",
            "GLOBAL",
            root_id,
        )
        .await;

        // ---- company structure ------------------------------------------------
        let department = seed_department(&app, "engineering", root_id).await;
        add_department_member(&app, department, manager_id, root_id).await;

        let client_account_a = seed_client_account(&app, "client-a", root_id).await;
        let client_account_b = seed_client_account(&app, "client-b", root_id).await;
        add_client_member(&app, client_account_a, client_a_id, "ACTIVE", root_id).await;
        add_client_member(&app, client_account_b, client_b_id, "ACTIVE", root_id).await;

        let internal_project = seed_project(&app, "internal-only", root_id, Some(department)).await;
        let project_shared_a = seed_project(&app, "shared-with-a", root_id, Some(department)).await;
        let project_shared_b = seed_project(&app, "shared-with-b", root_id, None).await;

        add_project_member(&app, internal_project, manager_id, root_id).await;
        share_project(&app, project_shared_a, client_account_a, root_id).await;
        share_project(&app, project_shared_b, client_account_b, root_id).await;

        let hidden_task = seed_task(&app, project_shared_a, "hidden work", false, root_id).await;
        let visible_task = seed_task(&app, project_shared_a, "visible work", true, root_id).await;
        let internal_task =
            seed_task(&app, internal_project, "internal work", false, root_id).await;
        let task_of_b = seed_task(&app, project_shared_b, "b's work", true, root_id).await;

        // ---- sessions ----------------------------------------------------------
        let admin_token = login(&app, ADMIN_EMAIL).await;
        // The administrator needs a recent second factor: every delegation route it
        // attacks is step-up gated, and without it the refusals would all be
        // STEP_UP_REQUIRED rather than the authorisation decision under test.
        enrol_totp(&app, &admin_token).await;

        let employee_token = login(&app, EMPLOYEE_EMAIL).await;
        let manager_token = login(&app, MANAGER_EMAIL).await;
        let client_a_token = login(&app, CLIENT_A_EMAIL).await;
        let client_b_token = login(&app, CLIENT_B_EMAIL).await;

        // Six logins from one address is most of the per-IP minute budget. Clear it
        // so a suite's own login attacks start from a known state.
        reset_login_limits(&app).await;

        World {
            app,
            root,
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
            manager: Actor {
                id: manager_id,
                email: MANAGER_EMAIL.into(),
                token: manager_token,
            },
            client_a: Actor {
                id: client_a_id,
                email: CLIENT_A_EMAIL.into(),
                token: client_a_token,
            },
            client_b: Actor {
                id: client_b_id,
                email: CLIENT_B_EMAIL.into(),
                token: client_b_token,
            },
            other_employee,
            department,
            client_account_a,
            client_account_b,
            internal_project,
            project_shared_a,
            project_shared_b,
            hidden_task,
            visible_task,
            internal_task,
            task_of_b,
        }
    }
}

// ===========================================================================
// Identity helpers
// ===========================================================================

/// Hash the fixture password once and reuse the digest.
///
/// Argon2id runs at production parameters in tests deliberately, so hashing seven
/// accounts separately would cost hundreds of milliseconds per test for no
/// additional coverage — the password verification path is exercised by every
/// login regardless.
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

/// Seed a permission override directly, so a suite can construct an actor holding
/// exactly the authority it wants to attack from.
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

/// Enrol and activate a TOTP factor on this session.
///
/// Activation both completes MFA for the session and stamps `mfa_verified_at`, so
/// the returned session satisfies the step-up window. This is the real flow, not a
/// database poke: a fixture that wrote `mfa_verified_at` directly would not notice
/// if enrolment stopped granting step-up.
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

/// Compute the code an authenticator app would show right now.
pub fn totp_code_now(base32_secret: &str) -> String {
    totp_code_at_offset(base32_secret, 0)
}

pub fn totp_code_at_offset(base32_secret: &str, steps: i64) -> String {
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

/// Forget the per-IP and per-account login buckets.
///
/// The fixture's own logins would otherwise consume most of the per-minute budget
/// and a suite's deliberate brute-force attack would be throttled by the fixture
/// rather than by the control under test.
pub async fn reset_login_limits(app: &TestApp) {
    let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
    app.state.limiter.reset(&keys::login_ip(ip)).await;
    for email in [
        ROOT_EMAIL,
        ADMIN_EMAIL,
        EMPLOYEE_EMAIL,
        MANAGER_EMAIL,
        CLIENT_A_EMAIL,
        CLIENT_B_EMAIL,
    ] {
        app.state.limiter.reset(&keys::login_account(email)).await;
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

pub async fn add_department_member(
    app: &TestApp,
    department_id: Uuid,
    user_id: Uuid,
    added_by: Uuid,
) {
    sqlx::query(
        "INSERT INTO department_memberships (id, department_id, user_id, role_in_department, added_by)
         VALUES ($1, $2, $3, 'MEMBER', $4)",
    )
    .bind(Uuid::now_v7())
    .bind(department_id)
    .bind(user_id)
    .bind(added_by)
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

pub async fn add_client_member(
    app: &TestApp,
    client_account_id: Uuid,
    user_id: Uuid,
    status: &str,
    invited_by: Uuid,
) {
    sqlx::query(
        "INSERT INTO client_memberships (id, client_account_id, user_id, status, invited_by, activated_at)
         VALUES ($1, $2, $3, $4, $5, now())",
    )
    .bind(Uuid::now_v7())
    .bind(client_account_id)
    .bind(user_id)
    .bind(status)
    .bind(invited_by)
    .execute(&app.db)
    .await
    .expect("seed a client membership");
}

pub async fn seed_project(
    app: &TestApp,
    code: &str,
    manager_user_id: Uuid,
    department_id: Option<Uuid>,
) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO projects (id, code, name, description, status, manager_user_id,
                               department_id, internal_note, created_by)
         VALUES ($1, $2, $3, 'a project', 'ACTIVE', $4, $5, 'internal only', $4)",
    )
    .bind(id)
    .bind(code)
    .bind(code)
    .bind(manager_user_id)
    .bind(department_id)
    .execute(&app.db)
    .await
    .expect("seed a project");
    id
}

pub async fn add_project_member(app: &TestApp, project_id: Uuid, user_id: Uuid, added_by: Uuid) {
    sqlx::query(
        "INSERT INTO project_memberships (id, project_id, user_id, role_in_project, added_by)
         VALUES ($1, $2, $3, 'MEMBER', $4)",
    )
    .bind(Uuid::now_v7())
    .bind(project_id)
    .bind(user_id)
    .bind(added_by)
    .execute(&app.db)
    .await
    .expect("seed a project membership");
}

pub async fn share_project(
    app: &TestApp,
    project_id: Uuid,
    client_account_id: Uuid,
    shared_by: Uuid,
) {
    sqlx::query(
        "INSERT INTO project_client_links (id, project_id, client_account_id, shared_by)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(Uuid::now_v7())
    .bind(project_id)
    .bind(client_account_id)
    .bind(shared_by)
    .execute(&app.db)
    .await
    .expect("share a project");
}

pub async fn revoke_share(app: &TestApp, project_id: Uuid, client_account_id: Uuid, by: Uuid) {
    sqlx::query(
        "UPDATE project_client_links
            SET revoked_at = now(), revoked_by = $3
          WHERE project_id = $1 AND client_account_id = $2 AND revoked_at IS NULL",
    )
    .bind(project_id)
    .bind(client_account_id)
    .bind(by)
    .execute(&app.db)
    .await
    .expect("revoke a share");
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
         VALUES ($1, $2, $3, 'a task', 'TODO', $4, 'internal only', $5)",
    )
    .bind(id)
    .bind(project_id)
    .bind(title)
    .bind(client_visible)
    .bind(created_by)
    .execute(&app.db)
    .await
    .expect("seed a task");
    id
}
