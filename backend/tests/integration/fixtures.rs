//! Shared setup for the integration suite. **No `#[test]` lives here.**
//!
//! Every helper drives the *real* HTTP surface rather than seeding rows directly,
//! because a fixture that inserts a user behind the API's back would also bypass
//! the invariants the API enforces — and a test built on such a fixture proves
//! things about a state the system can never actually reach. The two exceptions are
//! reading the invitation token back out of the outbox (there is no endpoint that
//! discloses it, deliberately) and resetting a rate-limit bucket (see
//! [`relax_ip_quotas`]).

#![allow(dead_code)] // each suite file uses a different subset

use axum::http::StatusCode;
use serde_json::{json, Value};
use std::net::{IpAddr, Ipv4Addr};
use uuid::Uuid;

use crate::common::{TestApp, TestResponse, TEST_BOOTSTRAP_SECRET, TEST_PASSWORD};
use roleblank_backend::platform::crypto::totp;
use roleblank_backend::platform::http::rate_limit::keys;
use roleblank_backend::shared::secret::Secret;

/// The built-in roles seeded by migration 0008, at their fixed identifiers.
pub const ROLE_SYSTEM_ADMINISTRATOR: &str = "00000000-0000-7000-8000-000000000001";
pub const ROLE_EMPLOYEE: &str = "00000000-0000-7000-8000-000000000002";
pub const ROLE_CLIENT_USER: &str = "00000000-0000-7000-8000-000000000003";

/// An authenticated participant in a test.
#[derive(Debug, Clone)]
pub struct Actor {
    pub user_id: Uuid,
    pub email: String,
    /// A bearer token for a session that has completed MFA where MFA applies.
    pub token: String,
}

impl Actor {
    pub fn bearer(&self) -> Option<&str> {
        Some(&self.token)
    }
}

// ---------------------------------------------------------------------------
// TOTP
// ---------------------------------------------------------------------------

/// The code an authenticator app would show, `steps` time steps from now.
///
/// Computed from the base32 secret the enrolment endpoint returned rather than
/// from the database, so an encoding mistake in enrolment would fail here. A
/// non-zero offset exists because replay protection is real: `last_used_step`
/// refuses any code at or below the highest already accepted, so a second
/// verification in the same test must use a later step — exactly what a human does
/// when they wait for the code to roll over.
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

pub fn totp_code_now(base32_secret: &str) -> String {
    totp_code_at_offset(base32_secret, 0)
}

// ---------------------------------------------------------------------------
// Rate limits
// ---------------------------------------------------------------------------

/// The address every request in this harness appears to come from.
///
/// `ClientIp` falls back to loopback when there is no `ConnectInfo`, which is what
/// calling the router directly produces.
const HARNESS_IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// Forget the per-IP login, registration and bootstrap buckets.
///
/// The per-IP quotas exist to bound one *attacker*, and they are asserted directly
/// by the security suite. Here every request shares one loopback address, so those
/// quotas would bound the fixture instead: three accepted invitations per hour is
/// fewer people than several of these scenarios need. Clearing the bucket is
/// exactly equivalent to the next request arriving from a different address, which
/// is what any real deployment sees, and it does not weaken a single assertion —
/// no test in this suite claims anything about rate limiting.
pub async fn relax_ip_quotas(app: &TestApp) {
    for key in [
        keys::login_ip(HARNESS_IP),
        keys::registration_ip(HARNESS_IP),
        keys::bootstrap_ip(HARNESS_IP),
        keys::password_reset_ip(HARNESS_IP),
    ] {
        app.state.limiter.reset(&key).await;
    }
}

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

pub const ROOT_EMAIL: &str = "owner@roleblank.test";

/// Create the system owner and return a fully authenticated, step-up-active token.
///
/// One login, not two: activating the TOTP factor also completes MFA on the
/// session that activated it, so the token minted at login is the token that comes
/// back. Every dangerous permission in the catalogue additionally demands a recent
/// second factor — ownership bypasses *permission evaluation*, never step-up — so
/// this token is only usable for sharing, delegation and role assignment because
/// the activation happened moments ago.
pub async fn bootstrap_root(app: &TestApp) -> Actor {
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
    let user_id = created.id_at("/user_id");

    let login = app
        .post(
            "/api/v1/auth/login",
            None,
            json!({"email": ROOT_EMAIL, "password": TEST_PASSWORD}),
        )
        .await;
    login.assert_status(StatusCode::OK);
    let token = login.str_at("/access_token").to_string();

    let enrol = app
        .post("/api/v1/auth/mfa/totp/setup", Some(&token), json!({}))
        .await;
    assert!(
        enrol.status.is_success(),
        "MFA enrolment failed: {}",
        String::from_utf8_lossy(&enrol.raw)
    );
    let secret = enrol.str_at("/secret").to_string();

    let activated = app
        .post(
            "/api/v1/auth/mfa/totp/activate",
            Some(&token),
            json!({"code": totp_code_now(&secret)}),
        )
        .await;
    assert!(
        activated.status.is_success(),
        "MFA activation failed: {}",
        String::from_utf8_lossy(&activated.raw)
    );

    Actor {
        user_id,
        email: ROOT_EMAIL.to_string(),
        token,
    }
}

/// Enrol and activate a TOTP factor on an existing session.
///
/// Afterwards the same token satisfies the step-up window, because activation
/// records `mfa_verified_at` on the session that performed it. Needed wherever a
/// test has to reach a dangerous permission as somebody other than the owner — or,
/// more interestingly, has to prove that *satisfying* step-up still does not get an
/// unauthorised principal past the permission check behind it.
pub async fn enrol_mfa(app: &TestApp, token: &str) {
    let enrol = app
        .post("/api/v1/auth/mfa/totp/setup", Some(token), json!({}))
        .await;
    assert!(
        enrol.status.is_success(),
        "MFA enrolment failed: {}",
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
        "MFA activation failed: {}",
        String::from_utf8_lossy(&activated.raw)
    );
}

// ---------------------------------------------------------------------------
// Roles
// ---------------------------------------------------------------------------

/// Create a custom role carrying `permissions`, given as `(code, scope)` pairs.
pub async fn create_role(
    app: &TestApp,
    token: &str,
    code: &str,
    allowed_principal_type: &str,
    permissions: &[(&str, &str)],
) -> Uuid {
    let items: Vec<Value> = permissions
        .iter()
        .map(|(code, scope)| json!({"permission_code": code, "scope": scope}))
        .collect();
    let created = app
        .post(
            "/api/v1/roles",
            Some(token),
            json!({
                "code": code,
                "name": code,
                "allowed_principal_type": allowed_principal_type,
                "permissions": items,
            }),
        )
        .await;
    created.assert_status(StatusCode::CREATED);
    created.id_at("/id")
}

// ---------------------------------------------------------------------------
// Invitations and accounts
// ---------------------------------------------------------------------------

/// Issue an invitation and return the raw response, so a caller can assert on a
/// refusal as easily as on the happy path.
#[allow(clippy::too_many_arguments)]
pub async fn invite(
    app: &TestApp,
    token: &str,
    email: &str,
    display_name: &str,
    principal_type: &str,
    role_ids: &[Uuid],
    department_id: Option<Uuid>,
    client_account_id: Option<Uuid>,
) -> TestResponse {
    let mut body = json!({
        "email": email,
        "display_name": display_name,
        "principal_type": principal_type,
        "role_ids": role_ids,
    });
    // Absent rather than explicitly null: the service refuses a `client_account_id`
    // on an INTERNAL invitation, and `null` would be indistinguishable from a value
    // in a body a future DTO change might read differently.
    if let Some(id) = department_id {
        body["department_id"] = json!(id);
    }
    if let Some(id) = client_account_id {
        body["client_account_id"] = json!(id);
    }
    app.post("/api/v1/invitations", Some(token), body).await
}

/// Recover the plaintext invitation token from the transactional outbox.
///
/// There is deliberately no endpoint that returns it — it exists in memory once, at
/// creation, and afterwards only as a SHA-256 digest plus the outbox payload bound
/// for the mail provider. Reading that payload is what the mail worker does, so
/// this is the invitee's real path to the token rather than a back door around it.
pub async fn invitation_token_for(app: &TestApp, email: &str) -> String {
    let url: String = sqlx::query_scalar(
        "SELECT payload ->> 'invite_url' FROM outbox_events
          WHERE event_type = 'mail.invitation' AND payload ->> 'to' = $1
          ORDER BY id DESC LIMIT 1",
    )
    .bind(email)
    .fetch_one(&app.db)
    .await
    .expect("an invitation mail must have been enqueued in the same transaction");

    url.split_once("?token=")
        .map(|(_, token)| token.to_string())
        .unwrap_or_else(|| panic!("the invite link carried no token: {url}"))
}

/// Log in and return the access token. The session is fully authenticated unless
/// the account requires MFA, in which case the caller must complete enrolment.
pub async fn login(app: &TestApp, email: &str) -> TestResponse {
    app.post(
        "/api/v1/auth/login",
        None,
        json!({"email": email, "password": TEST_PASSWORD}),
    )
    .await
}

/// Invite a person, accept on their behalf, and log them in.
///
/// The result is an ordinary account with no second factor unless one of its roles
/// carries a dangerous permission, which mirrors what the invitation flow actually
/// produces: `mfa_required` is derived from the role set, not chosen.
#[allow(clippy::too_many_arguments)]
pub async fn create_user(
    app: &TestApp,
    root_token: &str,
    email: &str,
    display_name: &str,
    principal_type: &str,
    role_ids: &[Uuid],
    department_id: Option<Uuid>,
    client_account_id: Option<Uuid>,
) -> Actor {
    let invited = invite(
        app,
        root_token,
        email,
        display_name,
        principal_type,
        role_ids,
        department_id,
        client_account_id,
    )
    .await;
    invited.assert_status(StatusCode::CREATED);

    relax_ip_quotas(app).await;
    let token = invitation_token_for(app, email).await;
    let accepted = app
        .post(
            "/api/v1/invitations/accept",
            None,
            json!({"token": token, "password": TEST_PASSWORD}),
        )
        .await;
    accepted.assert_status(StatusCode::CREATED);
    let user_id = accepted.id_at("/user_id");

    relax_ip_quotas(app).await;
    let session = login(app, email).await;
    session.assert_status(StatusCode::OK);
    assert!(
        !session.json()["mfa_required"].as_bool().unwrap_or(true),
        "this fixture only builds accounts whose roles carry no dangerous permission"
    );

    Actor {
        user_id,
        email: email.to_string(),
        token: session.str_at("/access_token").to_string(),
    }
}

/// An internal employee holding exactly the seeded `employee` role.
pub async fn create_employee(
    app: &TestApp,
    root_token: &str,
    email: &str,
    department_id: Option<Uuid>,
) -> Actor {
    create_user(
        app,
        root_token,
        email,
        "Employee",
        "INTERNAL",
        &[Uuid::parse_str(ROLE_EMPLOYEE).expect("seeded role id")],
        department_id,
        None,
    )
    .await
}

/// An external client user holding the seeded `client_user` role.
///
/// `client_account_id` is deliberately optional: passing `None` produces an account
/// with no membership at all, which is the state a self-registered stranger lands
/// in and the one that must see nothing.
pub async fn create_client_user(
    app: &TestApp,
    root_token: &str,
    email: &str,
    client_account_id: Option<Uuid>,
) -> Actor {
    create_user(
        app,
        root_token,
        email,
        "Client Contact",
        "CLIENT",
        &[Uuid::parse_str(ROLE_CLIENT_USER).expect("seeded role id")],
        None,
        client_account_id,
    )
    .await
}

// ---------------------------------------------------------------------------
// Business objects
// ---------------------------------------------------------------------------

pub async fn create_department(app: &TestApp, token: &str, code: &str, name: &str) -> Uuid {
    let created = app
        .post(
            "/api/v1/departments",
            Some(token),
            json!({"code": code, "name": name}),
        )
        .await;
    created.assert_status(StatusCode::CREATED);
    created.id_at("/id")
}

pub async fn create_client_account(app: &TestApp, token: &str, code: &str, name: &str) -> Uuid {
    let created = app
        .post(
            "/api/v1/clients",
            Some(token),
            json!({"code": code, "name": name}),
        )
        .await;
    created.assert_status(StatusCode::CREATED);
    created.id_at("/id")
}

pub async fn create_project(
    app: &TestApp,
    token: &str,
    code: &str,
    manager_user_id: Uuid,
    department_id: Option<Uuid>,
) -> Uuid {
    let mut body = json!({
        "code": code,
        "name": code,
        "manager_user_id": manager_user_id,
    });
    if let Some(id) = department_id {
        body["department_id"] = json!(id);
    }
    let created = app.post("/api/v1/projects", Some(token), body).await;
    created.assert_status(StatusCode::CREATED);
    created.id_at("/id")
}

pub async fn create_task(app: &TestApp, token: &str, project_id: Uuid, title: &str) -> Uuid {
    let created = app
        .post(
            "/api/v1/tasks",
            Some(token),
            json!({"project_id": project_id, "title": title}),
        )
        .await;
    created.assert_status(StatusCode::CREATED);
    created.id_at("/id")
}

// ---------------------------------------------------------------------------
// Database assertions
// ---------------------------------------------------------------------------

/// How many audit events carry this action code. Used to assert that an operation
/// left a record, and that a *distinct* operation left a *distinct* record.
pub async fn audit_count(app: &TestApp, action_code: &str) -> i64 {
    let (count,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM audit_events WHERE action_code = $1")
            .bind(action_code)
            .fetch_one(&app.db)
            .await
            .expect("count audit events");
    count
}

/// The same, narrowed to one target — so "this project was shared" cannot be
/// satisfied by a different project having been shared.
pub async fn audit_count_for(app: &TestApp, action_code: &str, target_id: Uuid) -> i64 {
    let (count,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM audit_events WHERE action_code = $1 AND target_id = $2",
    )
    .bind(action_code)
    .bind(target_id)
    .fetch_one(&app.db)
    .await
    .expect("count audit events");
    count
}

/// Every `id` in a page envelope, in order.
pub fn ids_in(response: &TestResponse) -> Vec<Uuid> {
    response.json()["items"]
        .as_array()
        .expect("a page envelope with an `items` array")
        .iter()
        .map(|item| {
            Uuid::parse_str(item["id"].as_str().expect("each item carries an id")).expect("a UUID")
        })
        .collect()
}

/// The `user_id` of every member in a page envelope.
pub fn member_ids_in(response: &TestResponse) -> Vec<Uuid> {
    response.json()["items"]
        .as_array()
        .expect("a page envelope with an `items` array")
        .iter()
        .map(|item| {
            Uuid::parse_str(
                item["user_id"]
                    .as_str()
                    .expect("each member carries a user_id"),
            )
            .expect("a UUID")
        })
        .collect()
}
