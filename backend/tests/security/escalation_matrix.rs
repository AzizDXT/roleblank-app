//! §4 — privilege escalation, from a **deliberately limited** administrator.
//!
//! `delegation_matrix.rs` attacks the derivation lattice from an actor built to
//! probe it. This suite attacks from the account an organisation actually creates:
//! a real administrator with a real job, whose permission set was chosen to be
//! *nearly* enough. The interesting escalations are the ones that need only one
//! more step — a role, an override, a second account, a DENY that could be
//! escaped — and each of them gets its own named test so a regression names itself.
//!
//! `LIMITED` below is the whole of the actor's authority. What it does **not**
//! hold is the point:
//!
//!   * `audit.read` — the record of what it did;
//!   * `settings.security.write` — the security configuration (dangerous);
//!   * `projects.clients.share` — the external trust boundary (dangerous);
//!   * `clients.*`, `departments.*`, `projects.update`, `iam.users.archive`;
//!   * `projects.read` anywhere wider than `DEPARTMENT`.
//!
//! Every refusal is followed by a database assertion. A `403` that still wrote the
//! grant is the failure mode this file exists to catch.

use axum::http::StatusCode;
use serde_json::json;
use uuid::Uuid;

use crate::common::TestResponse;
use crate::fixtures::{
    enrol_totp, grant_override, login, password_hash, seed_department, seed_user, Actor, World,
    ROLE_CLIENT_USER, ROLE_EMPLOYEE, ROLE_SYSTEM_ADMINISTRATOR,
};

/// Exactly what the limited administrator holds. Nothing else.
const LIMITED: &[(&str, &str)] = &[
    // The delegation machinery — so that every refusal below is about *what* it may
    // hand out, never about whether it may use the endpoint at all.
    ("iam.roles.read", "GLOBAL"),
    ("iam.roles.create", "GLOBAL"),
    ("iam.roles.update", "GLOBAL"),
    ("iam.roles.delete", "GLOBAL"),
    ("iam.roles.assign", "GLOBAL"),
    ("iam.permissions.read", "GLOBAL"),
    ("iam.permissions.delegate", "GLOBAL"),
    // A plausible day job.
    ("iam.users.read", "GLOBAL"),
    ("iam.users.update", "GLOBAL"),
    ("iam.users.suspend", "GLOBAL"),
    ("tasks.read", "GLOBAL"),
    // Bounded on purpose: DEPARTMENT, never GLOBAL.
    ("projects.read", "DEPARTMENT"),
];

/// Permissions the limited administrator does not hold at any scope.
const UNHELD_ORDINARY: &[&str] = &[
    "audit.read",
    "clients.read",
    "departments.create",
    "projects.update",
    "iam.users.archive",
    "settings.features.write",
];

/// Unheld **and** dangerous: reaching either of these is the worst outcome in this
/// file, because both are a route to manufacturing arbitrary authority.
const UNHELD_DANGEROUS: &[&str] = &["settings.security.write", "projects.clients.share"];

// ===========================================================================
// Fixtures
// ===========================================================================

/// Build the limited administrator on top of the standard world.
///
/// No built-in role: the baseline `employee` role carries `projects.read@ASSIGNED`
/// and `tasks.read@ASSIGNED`, and an actor holding a permission at `ASSIGNED` may
/// legitimately hand it out at `ASSIGNED` — which would make several cases below
/// pass for the wrong reason.
async fn limited_admin(w: &World, email: &str) -> Actor {
    let hash = password_hash(&w.app).await;
    let id = seed_user(&w.app, email, "INTERNAL", &hash).await;
    for (code, scope) in LIMITED {
        grant_override(&w.app, id, code, "ALLOW", scope, w.root.id).await;
    }
    let token = login(&w.app, email).await;
    // Every delegation route is step-up gated. Without a recent second factor every
    // refusal below would be `STEP_UP_REQUIRED` and none of them would say anything
    // about escalation.
    enrol_totp(&w.app, &token).await;
    Actor {
        id,
        email: email.into(),
        token,
    }
}

/// An ordinary INTERNAL colleague to aim grants at.
async fn victim(w: &World, email: &str) -> Uuid {
    let hash = password_hash(&w.app).await;
    seed_user(&w.app, email, "INTERNAL", &hash).await
}

#[track_caller]
fn escalation_denied(response: &TestResponse, what: &str) {
    assert_eq!(
        response.status,
        StatusCode::FORBIDDEN,
        "{what} produced {} instead of a refusal: {}",
        response.status,
        String::from_utf8_lossy(&response.raw)
    );
    // `DELEGATION_DENIED` is the escalation refusal; `STEP_UP_REQUIRED` is the
    // dangerous-permission gate firing first. Both are correct refusals, and both
    // are distinguishable from `AUTHORIZATION_DENIED`, which would mean the actor
    // was stopped for want of the endpoint rather than for want of the authority.
    let code = response.error_code();
    assert!(
        matches!(code, Some("DELEGATION_DENIED") | Some("STEP_UP_REQUIRED")),
        "{what} was refused with `{code:?}` rather than an escalation refusal: {}",
        String::from_utf8_lossy(&response.raw)
    );
    response.assert_no_secrets();
}

/// Every grant this user holds, from either source, as `code@scope` strings.
async fn effective_grants(w: &World, user_id: Uuid) -> Vec<String> {
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT rp.permission_code, rp.scope_type, 'ALLOW'
           FROM user_role_assignments ura
           JOIN role_permissions rp ON rp.role_id = ura.role_id
          WHERE ura.user_id = $1
          UNION ALL
         SELECT o.permission_code, o.scope_type, o.effect
           FROM user_permission_overrides o
          WHERE o.user_id = $1",
    )
    .bind(user_id)
    .fetch_all(&w.app.db)
    .await
    .expect("read effective grants");
    let mut out: Vec<String> = rows
        .into_iter()
        .map(|(code, scope, effect)| format!("{effect}:{code}@{scope}"))
        .collect();
    out.sort();
    out
}

fn grant(code: &str, scope: &str) -> serde_json::Value {
    json!({"permission_code": code, "effect": "ALLOW", "scope": scope})
}

// ===========================================================================
// 1 — granting a permission it does not hold
// ===========================================================================

#[tokio::test]
async fn a_limited_admin_cannot_grant_a_permission_it_does_not_hold() {
    let w = World::build().await;
    let admin = limited_admin(&w, "limited-1@fixture.test").await;
    let subject = victim(&w, "victim-1@fixture.test").await;
    let path = format!("/api/v1/users/{subject}/permission-overrides");

    // The control: what it holds, at the scope it holds it, goes through. Without
    // this the file would pass equally well against an endpoint that refuses
    // everything.
    w.app
        .post(&path, admin.bearer(), grant("tasks.read", "GLOBAL"))
        .await
        .assert_status(StatusCode::CREATED);

    for code in UNHELD_ORDINARY.iter().chain(UNHELD_DANGEROUS.iter()) {
        for scope in ["GLOBAL", "DEPARTMENT", "ASSIGNED", "SELF"] {
            escalation_denied(
                &w.app.post(&path, admin.bearer(), grant(code, scope)).await,
                &format!("granting the unheld `{code}` at {scope}"),
            );
        }
        // A DENY needs the same authority as the matching ALLOW: creating one is a
        // change to somebody's authority, and removing it later would be an
        // escalation performed by whoever created it.
        escalation_denied(
            &w.app
                .post(
                    &path,
                    admin.bearer(),
                    json!({"permission_code": code, "effect": "DENY", "scope": "GLOBAL"}),
                )
                .await,
            &format!("creating a DENY for the unheld `{code}`"),
        );
    }

    assert_eq!(
        effective_grants(&w, subject).await,
        vec!["ALLOW:tasks.read@GLOBAL".to_string()],
        "an unheld permission reached the database despite the refusals"
    );
}

// ===========================================================================
// 2 — laundering the same grant through a role
// ===========================================================================

#[tokio::test]
async fn a_limited_admin_cannot_create_a_role_containing_a_permission_it_lacks() {
    let w = World::build().await;
    let admin = limited_admin(&w, "limited-2@fixture.test").await;

    for code in UNHELD_ORDINARY.iter().chain(UNHELD_DANGEROUS.iter()) {
        let response = w
            .app
            .post(
                "/api/v1/roles",
                admin.bearer(),
                json!({
                    "code": format!("smuggle_{}", code.replace('.', "_")),
                    "name": "Innocuous",
                    "allowed_principal_type": "INTERNAL",
                    "permissions": [{"permission_code": code, "scope": "GLOBAL"}],
                }),
            )
            .await;
        escalation_denied(&response, &format!("authoring a role containing `{code}`"));
    }

    let created: (i64,) = sqlx::query_as("SELECT count(*) FROM roles WHERE is_system = false")
        .fetch_one(&w.app.db)
        .await
        .expect("count custom roles");
    assert_eq!(created.0, 0, "a role carrying unheld authority was written");
}

/// The composition attack in its purest form: author a role that is legal (it
/// contains only held permissions), then edit it to add the permission that is not.
#[tokio::test]
async fn a_limited_admin_cannot_widen_a_role_after_creating_it() {
    let w = World::build().await;
    let admin = limited_admin(&w, "limited-3@fixture.test").await;

    let created = w
        .app
        .post(
            "/api/v1/roles",
            admin.bearer(),
            json!({
                "code": "reader",
                "name": "Reader",
                "allowed_principal_type": "INTERNAL",
                "permissions": [{"permission_code": "tasks.read", "scope": "GLOBAL"}],
            }),
        )
        .await;
    created.assert_status(StatusCode::CREATED);
    let role_id = created.id_at("/id");
    let version = created
        .json()
        .pointer("/version")
        .and_then(serde_json::Value::as_i64)
        .expect("a version");

    for code in ["audit.read", "settings.security.write"] {
        escalation_denied(
            &w.app
                .patch(
                    &format!("/api/v1/roles/{role_id}"),
                    admin.bearer(),
                    json!({
                        "version": version,
                        "permissions": [
                            {"permission_code": "tasks.read", "scope": "GLOBAL"},
                            {"permission_code": code, "scope": "GLOBAL"},
                        ],
                    }),
                )
                .await,
            &format!("widening an owned role with `{code}`"),
        );
    }

    let contents: Vec<(String,)> = sqlx::query_as(
        "SELECT permission_code FROM role_permissions WHERE role_id = $1 ORDER BY permission_code",
    )
    .bind(role_id)
    .fetch_all(&w.app.db)
    .await
    .expect("read the role");
    let codes: Vec<&str> = contents.iter().map(|c| c.0.as_str()).collect();
    assert_eq!(
        codes,
        vec!["tasks.read"],
        "the role was widened despite the refusal"
    );
}

// ===========================================================================
// 3 — widening the scope of something it does hold
// ===========================================================================

#[tokio::test]
async fn a_limited_admin_cannot_grant_a_wider_scope_than_it_holds() {
    let w = World::build().await;
    let admin = limited_admin(&w, "limited-4@fixture.test").await;
    let subject = victim(&w, "victim-4@fixture.test").await;
    let path = format!("/api/v1/users/{subject}/permission-overrides");

    // `projects.read` is held at DEPARTMENT. GLOBAL is a widening; ASSIGNED is a
    // sideways move into an incomparable scope — the grantee could be assigned to a
    // project in a different department, which is a silent lateral escalation.
    for scope in ["GLOBAL", "ASSIGNED"] {
        escalation_denied(
            &w.app
                .post(&path, admin.bearer(), grant("projects.read", scope))
                .await,
            &format!("widening projects.read from DEPARTMENT to {scope}"),
        );
    }

    // RESOURCE is unreachable from DEPARTMENT for the same reason: the actor cannot
    // establish that the named object is inside its own department.
    escalation_denied(
        &w.app
            .post(
                &path,
                admin.bearer(),
                json!({
                    "permission_code": "projects.read",
                    "effect": "ALLOW",
                    "scope": "RESOURCE",
                    "resource_type": "PROJECT",
                    "resource_id": w.project_shared_b,
                }),
            )
            .await,
        "deriving RESOURCE from DEPARTMENT",
    );

    // The same widening, laundered through a role.
    escalation_denied(
        &w.app
            .post(
                "/api/v1/roles",
                admin.bearer(),
                json!({
                    "code": "wide_reader",
                    "name": "Wide Reader",
                    "allowed_principal_type": "INTERNAL",
                    "permissions": [{"permission_code": "projects.read", "scope": "GLOBAL"}],
                }),
            )
            .await,
        "authoring a role that widens projects.read to GLOBAL",
    );

    let scopes: Vec<(String,)> = sqlx::query_as(
        "SELECT scope_type FROM user_permission_overrides
          WHERE user_id = $1 AND permission_code = 'projects.read'",
    )
    .bind(subject)
    .fetch_all(&w.app.db)
    .await
    .expect("read written scopes");
    assert!(
        scopes.is_empty(),
        "a widened scope reached the database: {scopes:?}"
    );
}

// ===========================================================================
// 4 — promoting itself
// ===========================================================================

/// Rule 3 is a flat refusal, not an analysis of whether a particular self-change
/// is an escalation. Deciding that is subtle, and subtlety is where the bugs live.
#[tokio::test]
async fn a_limited_admin_cannot_promote_itself_through_any_route() {
    let w = World::build().await;
    let admin = limited_admin(&w, "limited-5@fixture.test").await;
    let before = effective_grants(&w, admin.id).await;

    // An override on itself — even of something it already holds.
    for code in ["audit.read", "tasks.read"] {
        escalation_denied(
            &w.app
                .post(
                    &format!("/api/v1/users/{}/permission-overrides", admin.id),
                    admin.bearer(),
                    grant(code, "GLOBAL"),
                )
                .await,
            &format!("granting itself `{code}`"),
        );
    }

    // A built-in role for itself.
    for role in [ROLE_SYSTEM_ADMINISTRATOR, ROLE_EMPLOYEE] {
        escalation_denied(
            &w.app
                .post(
                    &format!("/api/v1/users/{}/roles", admin.id),
                    admin.bearer(),
                    json!({"role_id": role}),
                )
                .await,
            "assigning itself a built-in role",
        );
    }

    // Removing a restriction from itself is a self-modification too. Seed a DENY
    // the actor would dearly like to be rid of, and prove it cannot delete it.
    grant_override(
        &w.app,
        admin.id,
        "iam.users.suspend",
        "DENY",
        "GLOBAL",
        w.root.id,
    )
    .await;
    let deny_id: (Uuid,) = sqlx::query_as(
        "SELECT id FROM user_permission_overrides
          WHERE user_id = $1 AND effect = 'DENY' AND permission_code = 'iam.users.suspend'",
    )
    .bind(admin.id)
    .fetch_one(&w.app.db)
    .await
    .expect("the seeded DENY");
    escalation_denied(
        &w.app
            .delete(
                &format!(
                    "/api/v1/users/{}/permission-overrides/{}",
                    admin.id, deny_id.0
                ),
                admin.bearer(),
            )
            .await,
        "deleting a DENY placed on itself",
    );

    let mut after = effective_grants(&w, admin.id).await;
    after.retain(|g| !g.starts_with("DENY:"));
    assert_eq!(
        after, before,
        "the limited administrator's own authority changed"
    );
}

/// Creating a role is legal; assigning it to yourself is not. Two legal-looking
/// steps that compose into self-promotion is the shape this test pins down.
#[tokio::test]
async fn a_limited_admin_cannot_create_a_role_and_then_assign_it_to_itself() {
    let w = World::build().await;
    let admin = limited_admin(&w, "limited-6@fixture.test").await;

    let created = w
        .app
        .post(
            "/api/v1/roles",
            admin.bearer(),
            json!({
                "code": "self_service",
                "name": "Self Service",
                "allowed_principal_type": "INTERNAL",
                // Only permissions it genuinely holds, so the role itself is legal.
                "permissions": [{"permission_code": "tasks.read", "scope": "GLOBAL"}],
            }),
        )
        .await;
    created.assert_status(StatusCode::CREATED);
    let role_id = created.id_at("/id");

    escalation_denied(
        &w.app
            .post(
                &format!("/api/v1/users/{}/roles", admin.id),
                admin.bearer(),
                json!({"role_id": role_id}),
            )
            .await,
        "assigning a self-authored role to itself",
    );

    let held: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM user_role_assignments WHERE user_id = $1 AND role_id = $2",
    )
    .bind(admin.id)
    .bind(role_id)
    .fetch_one(&w.app.db)
    .await
    .expect("count");
    assert_eq!(held.0, 0, "the actor assigned itself its own role");
}

/// Two accounts, one attacker. If A can grant B and B can grant A, the pair can
/// only ever exchange the union of what they already hold — never manufacture
/// something neither has.
#[tokio::test]
async fn two_limited_admins_cannot_launder_authority_through_each_other() {
    let w = World::build().await;
    let alice = limited_admin(&w, "alice@fixture.test").await;
    let bob = limited_admin(&w, "bob@fixture.test").await;

    // Alice hands Bob something she genuinely holds, at a scope he does not already
    // have it at. Legitimate, and the control.
    w.app
        .post(
            &format!("/api/v1/users/{}/permission-overrides", bob.id),
            alice.bearer(),
            grant("tasks.read", "SELF"),
        )
        .await
        .assert_status(StatusCode::CREATED);

    // Bob now holds delegation authority *and* a grant from Alice. He still cannot
    // hand Alice anything neither of them holds: authority is not created by being
    // passed between accounts.
    for code in ["audit.read", "settings.security.write"] {
        escalation_denied(
            &w.app
                .post(
                    &format!("/api/v1/users/{}/permission-overrides", alice.id),
                    bob.bearer(),
                    grant(code, "GLOBAL"),
                )
                .await,
            &format!("Bob granting Alice the unheld `{code}`"),
        );
    }

    // Nor can Bob widen Alice's DEPARTMENT-bounded grant to GLOBAL.
    escalation_denied(
        &w.app
            .post(
                &format!("/api/v1/users/{}/permission-overrides", alice.id),
                bob.bearer(),
                grant("projects.read", "GLOBAL"),
            )
            .await,
        "Bob widening Alice's projects.read to GLOBAL",
    );

    for (who, id) in [("Alice", alice.id), ("Bob", bob.id)] {
        let grants = effective_grants(&w, id).await;
        for forbidden in [
            "audit.read",
            "settings.security.write",
            "projects.read@GLOBAL",
        ] {
            assert!(
                !grants.iter().any(|g| g.contains(forbidden)),
                "{who} ended up holding `{forbidden}`: {grants:?}"
            );
        }
    }
}

// ===========================================================================
// 5 — escaping a DENY
// ===========================================================================

/// Denials are evaluated before the allow set is consulted and never look at it,
/// so "add another role until something allows it" is structurally impossible.
/// Proven from the *victim's* own session, not from the shape of the data.
#[tokio::test]
async fn a_deny_cannot_be_escaped_by_adding_another_role() {
    let w = World::build().await;
    let admin = limited_admin(&w, "limited-7@fixture.test").await;

    let hash = password_hash(&w.app).await;
    let denied_id = seed_user(&w.app, "denied@fixture.test", "INTERNAL", &hash).await;
    // A GLOBAL DENY on reading tasks, and an ALLOW that would otherwise cover it.
    grant_override(&w.app, denied_id, "tasks.read", "DENY", "GLOBAL", w.root.id).await;
    grant_override(
        &w.app,
        denied_id,
        "tasks.read",
        "ALLOW",
        "GLOBAL",
        w.root.id,
    )
    .await;
    let denied_token = login(&w.app, "denied@fixture.test").await;

    let before = w.app.get("/api/v1/tasks", Some(&denied_token)).await;
    before.assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");

    // Now pile on more authority through every channel available: the built-in
    // employee role (which carries `tasks.read@ASSIGNED`), a self-authored role,
    // and a fresh ALLOW override.
    //
    // The built-in role is assigned by the world's *over-equipped* administrator,
    // not by the limited one. The limited actor cannot assign `employee` at all —
    // that role also contains `departments.read`, which it does not hold, and
    // assignment is validated permission by permission. Using the stronger actor
    // here makes the test harder: it proves the DENY survives authority piled on by
    // someone who really does hold it.
    w.app
        .post(
            &format!("/api/v1/users/{denied_id}/roles"),
            w.admin.bearer(),
            json!({"role_id": ROLE_EMPLOYEE}),
        )
        .await
        .assert_status(StatusCode::CREATED);

    let role = w
        .app
        .post(
            "/api/v1/roles",
            admin.bearer(),
            json!({
                "code": "task_reader",
                "name": "Task Reader",
                "allowed_principal_type": "INTERNAL",
                "permissions": [{"permission_code": "tasks.read", "scope": "GLOBAL"}],
            }),
        )
        .await;
    role.assert_status(StatusCode::CREATED);
    w.app
        .post(
            &format!("/api/v1/users/{denied_id}/roles"),
            admin.bearer(),
            json!({"role_id": role.id_at("/id")}),
        )
        .await
        .assert_status(StatusCode::CREATED);

    // A fresh ALLOW at a scope the victim does not already hold, so this is a
    // genuinely new grant rather than a duplicate the unique index would refuse.
    w.app
        .post(
            &format!("/api/v1/users/{denied_id}/permission-overrides"),
            admin.bearer(),
            grant("tasks.read", "SELF"),
        )
        .await
        .assert_status(StatusCode::CREATED);

    // Four additional sources of `tasks.read`, and the answer has not moved.
    let after = w.app.get("/api/v1/tasks", Some(&denied_token)).await;
    after.assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");
    w.app
        .get(
            &format!("/api/v1/tasks/{}", w.visible_task),
            Some(&denied_token),
        )
        .await
        .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");

    // The capability list must agree with the evaluator — a frontend that showed
    // the button would be reporting authority the backend will refuse.
    let me = w.app.get("/api/v1/auth/me", Some(&denied_token)).await;
    me.assert_status(StatusCode::OK);
    let text = String::from_utf8_lossy(&me.raw);
    assert!(
        !text.contains("tasks.read"),
        "the capability list advertises a permission a GLOBAL DENY removes: {text}"
    );
}

// ===========================================================================
// 6 — crossing the client envelope
// ===========================================================================

/// The envelope is checked before any grant is consulted, so no amount of
/// authority can move a CLIENT principal inside it.
#[tokio::test]
async fn a_limited_admin_cannot_convert_a_client_into_an_internal_principal() {
    let w = World::build().await;
    let admin = limited_admin(&w, "limited-8@fixture.test").await;

    // A smuggled field is a parse failure, not a silently ignored key.
    w.app
        .patch(
            &format!("/api/v1/users/{}", w.client_a.id),
            admin.bearer(),
            json!({"version": 1, "principal_type": "INTERNAL"}),
        )
        .await
        .assert_error(StatusCode::BAD_REQUEST, "BAD_REQUEST");

    // An INTERNAL-only role cannot be attached to a CLIENT.
    escalation_denied(
        &w.app
            .post(
                &format!("/api/v1/users/{}/roles", w.client_a.id),
                admin.bearer(),
                json!({"role_id": ROLE_EMPLOYEE}),
            )
            .await,
        "assigning an INTERNAL role to a CLIENT",
    );

    // Nor can an INTERNAL-only permission be handed to one directly.
    for code in ["tasks.read", "iam.users.read"] {
        escalation_denied(
            &w.app
                .post(
                    &format!("/api/v1/users/{}/permission-overrides", w.client_a.id),
                    admin.bearer(),
                    grant(code, "GLOBAL"),
                )
                .await,
            &format!("granting the INTERNAL-only `{code}` to a CLIENT"),
        );
    }

    // The database refuses the same thing independently: even a direct write as the
    // migrator — a stronger identity than the application ever holds — is rejected
    // by the envelope trigger.
    let smuggled = sqlx::query(
        "INSERT INTO user_permission_overrides (id, user_id, permission_code, effect, scope_type, granted_by)
         VALUES ($1, $2, 'iam.users.read', 'ALLOW', 'GLOBAL', $3)",
    )
    .bind(Uuid::now_v7())
    .bind(w.client_a.id)
    .bind(w.root.id)
    .execute(&w.app.db)
    .await;
    assert!(
        smuggled.is_err(),
        "an INTERNAL-only permission was written onto a CLIENT at the database"
    );

    // And the client's world did not move.
    let row: (String,) = sqlx::query_as("SELECT principal_type FROM users WHERE id = $1")
        .bind(w.client_a.id)
        .fetch_one(&w.app.db)
        .await
        .expect("read the client");
    assert_eq!(row.0, "CLIENT", "a CLIENT crossed the envelope");
    w.app
        .get("/api/v1/users", w.client_a.bearer())
        .await
        .assert_error(StatusCode::NOT_FOUND, "RESOURCE_NOT_FOUND");
}

/// The reverse direction is refused too: an INTERNAL user cannot be given a
/// CLIENT role, which would otherwise be a way to smuggle portal authority.
#[tokio::test]
async fn a_limited_admin_cannot_give_an_employee_a_client_role() {
    let w = World::build().await;
    let admin = limited_admin(&w, "limited-9@fixture.test").await;

    escalation_denied(
        &w.app
            .post(
                &format!("/api/v1/users/{}/roles", w.employee.id),
                admin.bearer(),
                json!({"role_id": ROLE_CLIENT_USER}),
            )
            .await,
        "assigning a CLIENT role to an INTERNAL principal",
    );

    let held: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM user_role_assignments WHERE user_id = $1 AND role_id = $2::uuid",
    )
    .bind(w.employee.id)
    .bind(ROLE_CLIENT_USER)
    .fetch_one(&w.app.db)
    .await
    .expect("count");
    assert_eq!(held.0, 0, "a CLIENT role was attached to an employee");
}

// ===========================================================================
// 7 — manufacturing another administrator
// ===========================================================================

/// The built-in `system_administrator` role contains `audit.read`,
/// `clients.*`, `projects.clients.share` and more that the limited administrator
/// does not hold. Assignment is validated permission by permission, so the whole
/// role is refused rather than partially applied.
#[tokio::test]
async fn a_limited_admin_cannot_make_another_user_an_administrator() {
    let w = World::build().await;
    let admin = limited_admin(&w, "limited-10@fixture.test").await;
    let subject = victim(&w, "victim-10@fixture.test").await;

    escalation_denied(
        &w.app
            .post(
                &format!("/api/v1/users/{subject}/roles"),
                admin.bearer(),
                json!({"role_id": ROLE_SYSTEM_ADMINISTRATOR}),
            )
            .await,
        "assigning the built-in administrator role",
    );

    // Not even to itself, and not even one permission at a time.
    escalation_denied(
        &w.app
            .post(
                &format!("/api/v1/users/{}/roles", admin.id),
                admin.bearer(),
                json!({"role_id": ROLE_SYSTEM_ADMINISTRATOR}),
            )
            .await,
        "assigning itself the built-in administrator role",
    );

    assert!(
        effective_grants(&w, subject).await.is_empty(),
        "the subject acquired authority"
    );

    // Editing the built-in role instead is refused for everyone, the owner included:
    // changing `system_administrator` for one person changes it for every holder.
    for actor in [admin.bearer(), w.root.bearer()] {
        let response = w
            .app
            .patch(
                &format!("/api/v1/roles/{ROLE_SYSTEM_ADMINISTRATOR}"),
                actor,
                json!({"version": 1, "permissions": []}),
            )
            .await;
        assert_eq!(
            response.status,
            StatusCode::FORBIDDEN,
            "a system role was editable: {}",
            String::from_utf8_lossy(&response.raw)
        );
    }
}

// ===========================================================================
// 8 — the owner
// ===========================================================================

/// Rule 4 outranks everything the limited administrator holds. This is the same
/// property `root_attack` proves for an over-equipped administrator; asserting it
/// here as well is what stops a future "narrow actors take a different code path"
/// refactor from opening a hole only the under-privileged can walk through.
#[tokio::test]
async fn a_limited_admin_cannot_affect_the_owner() {
    let w = World::build().await;
    let admin = limited_admin(&w, "limited-11@fixture.test").await;

    for (path, body) in [
        (
            format!("/api/v1/users/{}/roles", w.root.id),
            json!({"role_id": ROLE_EMPLOYEE}),
        ),
        (
            format!("/api/v1/users/{}/permission-overrides", w.root.id),
            grant("tasks.read", "GLOBAL"),
        ),
        (
            format!("/api/v1/users/{}/permission-overrides", w.root.id),
            json!({"permission_code": "tasks.read", "effect": "DENY", "scope": "GLOBAL"}),
        ),
        (
            format!("/api/v1/users/{}/suspend", w.root.id),
            json!({"version": 1}),
        ),
    ] {
        w.app
            .post(&path, admin.bearer(), body)
            .await
            .assert_error(StatusCode::FORBIDDEN, "ROOT_PROTECTED")
            .assert_no_secrets();
    }

    assert!(
        effective_grants(&w, w.root.id).await.is_empty(),
        "the owner acquired a grant"
    );
}

// ===========================================================================
// 9 — the odd corners
// ===========================================================================

/// Three shapes that look like an oversight rather than an attack, and are the
/// kind of thing a permission system quietly accepts.
#[tokio::test]
async fn malformed_and_out_of_band_grants_are_refused_rather_than_coerced() {
    let w = World::build().await;
    let admin = limited_admin(&w, "limited-12@fixture.test").await;
    let subject = victim(&w, "victim-12@fixture.test").await;
    let path = format!("/api/v1/users/{subject}/permission-overrides");

    // A permission code that is not in the catalogue is a probe of the
    // authorisation surface, and is reported as such rather than as a plain
    // validation error.
    for code in [
        "tasks.read.admin",
        "*",
        "iam.*",
        "TASKS.READ",
        "system.root",
    ] {
        let response = w
            .app
            .post(&path, admin.bearer(), grant(code, "GLOBAL"))
            .await;
        assert_eq!(
            response.error_code(),
            Some("UNKNOWN_PERMISSION"),
            "`{code}` was not reported as an uncatalogued code: {}",
            String::from_utf8_lossy(&response.raw)
        );
    }

    // RESOURCE scope on a *role* is meaningless — a role is shared, an object is
    // not — and is refused at validation rather than stored and ignored.
    let role = w
        .app
        .post(
            "/api/v1/roles",
            admin.bearer(),
            json!({
                "code": "object_bound",
                "name": "Object Bound",
                "allowed_principal_type": "INTERNAL",
                "permissions": [{
                    "permission_code": "tasks.read",
                    "scope": "RESOURCE",
                    "resource_type": "PROJECT",
                    "resource_id": w.internal_project,
                }],
            }),
        )
        .await;
    assert_eq!(
        role.status,
        StatusCode::BAD_REQUEST,
        "a RESOURCE-scoped role permission was accepted: {}",
        String::from_utf8_lossy(&role.raw)
    );

    // An already-expired override would be a grant that is audited as given and is
    // dead on arrival — an operator would believe an authority exists that does not.
    let expired = w
        .app
        .post(
            &path,
            admin.bearer(),
            json!({
                "permission_code": "tasks.read",
                "effect": "ALLOW",
                "scope": "GLOBAL",
                "expires_at": "2000-01-01T00:00:00Z",
            }),
        )
        .await;
    assert_eq!(
        expired.status,
        StatusCode::BAD_REQUEST,
        "an override expiring in the past was accepted"
    );

    assert!(
        effective_grants(&w, subject).await.is_empty(),
        "a malformed grant reached the database"
    );
}

/// Authority handed to a closed account is a dormant backdoor: the account is
/// reactivated later by someone who has no idea what it accumulated meanwhile.
#[tokio::test]
async fn a_limited_admin_cannot_arm_an_archived_account() {
    let w = World::build().await;
    let admin = limited_admin(&w, "limited-13@fixture.test").await;

    let hash = password_hash(&w.app).await;
    let dormant = seed_user(&w.app, "dormant@fixture.test", "INTERNAL", &hash).await;
    sqlx::query("UPDATE users SET status = 'ARCHIVED', archived_at = now() WHERE id = $1")
        .bind(dormant)
        .execute(&w.app.db)
        .await
        .expect("archive the account");

    let refused = w
        .app
        .post(
            &format!("/api/v1/users/{dormant}/permission-overrides"),
            admin.bearer(),
            grant("tasks.read", "GLOBAL"),
        )
        .await;
    refused.assert_error(StatusCode::CONFLICT, "SUBJECT_ARCHIVED");

    // Also through a role. Assigned by the over-equipped administrator, because the
    // limited one cannot delegate every permission `employee` contains and would be
    // refused one step earlier — which would prove nothing about the archive guard.
    let role_refused = w
        .app
        .post(
            &format!("/api/v1/users/{dormant}/roles"),
            w.admin.bearer(),
            json!({"role_id": ROLE_EMPLOYEE}),
        )
        .await;
    role_refused.assert_error(StatusCode::CONFLICT, "SUBJECT_ARCHIVED");

    assert!(
        effective_grants(&w, dormant).await.is_empty(),
        "an archived account was armed"
    );
}

// =============================================================================
// Placement through an invitation (regression: F-05)
// =============================================================================
//
// An invitation carries `department_id` and `client_account_id` in its body, and
// on acceptance both become real memberships — a department membership resolves
// DEPARTMENT scope, and a client membership is written ACTIVE. For a while both
// fields were validated for *coherence* and never authorised against the thing
// they named, so `iam.users.invite` alone was enough to place an account wherever
// the caller liked.
//
// That is escalation by proxy rather than in place: the attacker never gains a
// permission, they mint a second account that holds one, at an address they
// control. `scripts/exploit_department_placement.sh` walks the whole chain against
// a live server; these tests pin the decision itself.

/// An inviter holding `iam.users.invite` and nothing about departments.
async fn inviter_only(w: &World, email: &str) -> Actor {
    let hash = password_hash(&w.app).await;
    let id = seed_user(&w.app, email, "INTERNAL", &hash).await;
    grant_override(&w.app, id, "iam.users.invite", "ALLOW", "GLOBAL", w.root.id).await;
    let token = login(&w.app, email).await;
    // Placement is step-up gated, exactly as the direct membership routes are.
    // Without a second factor the refusal below would be STEP_UP_REQUIRED and would
    // say nothing about authority.
    enrol_totp(&w.app, &token).await;
    Actor {
        id,
        email: email.into(),
        token,
    }
}

async fn invitation_count(w: &World) -> i64 {
    let row: (i64,) = sqlx::query_as("SELECT count(*) FROM invitations")
        .fetch_one(&w.app.db)
        .await
        .expect("count invitations");
    row.0
}

#[tokio::test]
async fn an_invitation_cannot_place_an_account_into_an_unmanaged_department() {
    let w = World::build().await;
    let inviter = inviter_only(&w, "placement-dept@roleblank.test").await;
    // A department the inviter is not in and has no authority over.
    let foreign = seed_department(&w.app, "finance", w.root.id).await;

    let before = invitation_count(&w).await;
    let refused = w
        .app
        .post(
            "/api/v1/invitations",
            inviter.bearer(),
            json!({
                "email": "proxy@roleblank.test",
                "display_name": "Proxy",
                "principal_type": "INTERNAL",
                "role_ids": [],
                "department_id": foreign,
                "client_account_id": null,
            }),
        )
        .await;
    // Not `escalation_denied`: that helper is for the delegation lattice, where the
    // actor holds the permission but not at the requested scope. Here the inviter
    // holds `departments.members.manage` at no scope whatsoever, so the accurate
    // refusal is the plain authorisation denial — and asserting the *accurate* code
    // is the point. Widening the shared helper to accept this would blunt the
    // fourteen lattice tests above, which rely on `AUTHORIZATION_DENIED` being
    // distinguishable from a delegation refusal.
    refused.assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");
    refused.assert_no_secrets();

    assert_eq!(
        invitation_count(&w).await,
        before,
        "a refused placement still wrote an invitation"
    );
}

#[tokio::test]
async fn an_invitation_cannot_attach_an_account_to_an_unmanaged_client() {
    let w = World::build().await;
    let inviter = inviter_only(&w, "placement-client@roleblank.test").await;

    let before = invitation_count(&w).await;
    let refused = w
        .app
        .post(
            "/api/v1/invitations",
            inviter.bearer(),
            json!({
                "email": "outsider@roleblank.test",
                "display_name": "Outsider",
                "principal_type": "CLIENT",
                "role_ids": [],
                "department_id": null,
                "client_account_id": w.client_account_a,
            }),
        )
        .await;
    // `clients.*` is INTERNAL-only, so an inviter with no clients authority at all
    // is refused; the point is that it is refused *here*, at placement, and not
    // waved through to become an ACTIVE membership on acceptance.
    assert!(
        refused.status == StatusCode::FORBIDDEN || refused.status == StatusCode::NOT_FOUND,
        "attaching an account to an unmanaged client returned {}: {}",
        refused.status,
        refused.json(),
    );

    assert_eq!(
        invitation_count(&w).await,
        before,
        "a refused placement still wrote an invitation"
    );
}

/// The other half of the claim. A guard that refuses everything is not an
/// authorisation check, so the same request must succeed once the inviter holds
/// the authority the refusal was asking for.
#[tokio::test]
async fn an_invitation_may_place_an_account_into_a_managed_department() {
    let w = World::build().await;
    let inviter = inviter_only(&w, "placement-allowed@roleblank.test").await;
    grant_override(
        &w.app,
        inviter.id,
        "departments.members.manage",
        "ALLOW",
        "GLOBAL",
        w.root.id,
    )
    .await;

    let accepted = w
        .app
        .post(
            "/api/v1/invitations",
            inviter.bearer(),
            json!({
                "email": "legitimate@roleblank.test",
                "display_name": "Legitimate",
                "principal_type": "INTERNAL",
                "role_ids": [],
                "department_id": w.department,
                "client_account_id": null,
            }),
        )
        .await;
    assert_eq!(
        accepted.status,
        StatusCode::CREATED,
        "an authorised placement was refused: {}",
        accepted.json(),
    );
}

// =============================================================================
// Object decision vs listing predicate (parity)
// =============================================================================

/// A targeted DENY that hides a department from `GET /departments/{id}` must also
/// hide it from `GET /departments`.
///
/// The evaluator resolves a narrow denial per object; the listing builds its SQL
/// predicate from `effective_scopes`, which by construction strips only *GLOBAL*
/// denials ("a narrower denial removes only what it covers, and is handled
/// per-object at `evaluate` time"). A listing has no per-object `evaluate`, so the
/// two answers can disagree — and the row an administrator explicitly denied is
/// returned, with its fields, by the collection route.
///
/// `projects/visibility.rs` already does this correctly: it carries
/// `denied_resource_ids` into the predicate. This test states the same requirement
/// for departments so the two cannot drift apart silently.
#[tokio::test]
async fn a_targeted_denial_hides_the_department_from_the_listing_too() {
    let w = World::build().await;

    // The administrator holds departments.read@GLOBAL; deny exactly one department.
    sqlx::query(
        "INSERT INTO user_permission_overrides
             (id, user_id, permission_code, effect, scope_type, resource_type, resource_id, granted_by)
         VALUES ($1, $2, 'departments.read', 'DENY', 'RESOURCE', 'DEPARTMENT', $3, $4)",
    )
    .bind(Uuid::now_v7())
    .bind(w.admin.id)
    .bind(w.department)
    .bind(w.root.id)
    .execute(&w.app.db)
    .await
    .expect("seed a targeted denial");

    // The object decision honours it.
    let object = w
        .app
        .get(
            &format!("/api/v1/departments/{}", w.department),
            w.admin.bearer(),
        )
        .await;
    assert!(
        object.status == StatusCode::FORBIDDEN || object.status == StatusCode::NOT_FOUND,
        "the object route ignored a targeted denial: {}",
        object.status
    );

    // The listing must agree.
    let listing = w.app.get("/api/v1/departments", w.admin.bearer()).await;
    assert_eq!(listing.status, StatusCode::OK, "listing failed");
    let body = listing.json().to_string();
    assert!(
        !body.contains(&w.department.to_string()),
        "the listing returned a department the object decision denies: {body}"
    );
}

/// Same requirement as `a_targeted_denial_hides_the_department_from_the_listing_too`,
/// for the other two listings that build their predicate from `effective_scopes`.
#[tokio::test]
async fn a_targeted_denial_hides_the_client_account_from_the_listing_too() {
    let w = World::build().await;
    sqlx::query(
        "INSERT INTO user_permission_overrides
             (id, user_id, permission_code, effect, scope_type, resource_type, resource_id, granted_by)
         VALUES ($1, $2, 'clients.read', 'DENY', 'RESOURCE', 'CLIENT_ACCOUNT', $3, $4)",
    )
    .bind(Uuid::now_v7())
    .bind(w.admin.id)
    .bind(w.client_account_a)
    .bind(w.root.id)
    .execute(&w.app.db)
    .await
    .expect("seed a targeted denial");

    let object = w
        .app
        .get(
            &format!("/api/v1/clients/{}", w.client_account_a),
            w.admin.bearer(),
        )
        .await;
    assert!(
        object.status == StatusCode::FORBIDDEN || object.status == StatusCode::NOT_FOUND,
        "the object route ignored a targeted denial: {}",
        object.status
    );

    let listing = w.app.get("/api/v1/clients", w.admin.bearer()).await;
    assert_eq!(listing.status, StatusCode::OK, "listing failed");
    assert!(
        !listing
            .json()
            .to_string()
            .contains(&w.client_account_a.to_string()),
        "the listing returned a client account the object decision denies"
    );
}

#[tokio::test]
async fn a_targeted_denial_hides_the_user_from_the_listing_too() {
    let w = World::build().await;
    sqlx::query(
        "INSERT INTO user_permission_overrides
             (id, user_id, permission_code, effect, scope_type, resource_type, resource_id, granted_by)
         VALUES ($1, $2, 'iam.users.read', 'DENY', 'RESOURCE', 'USER', $3, $4)",
    )
    .bind(Uuid::now_v7())
    .bind(w.admin.id)
    .bind(w.other_employee)
    .bind(w.root.id)
    .execute(&w.app.db)
    .await
    .expect("seed a targeted denial");

    let object = w
        .app
        .get(
            &format!("/api/v1/users/{}", w.other_employee),
            w.admin.bearer(),
        )
        .await;
    assert!(
        object.status == StatusCode::FORBIDDEN || object.status == StatusCode::NOT_FOUND,
        "the object route ignored a targeted denial: {}",
        object.status
    );

    let listing = w.app.get("/api/v1/users?limit=100", w.admin.bearer()).await;
    assert_eq!(listing.status, StatusCode::OK, "listing failed");
    assert!(
        !listing
            .json()
            .to_string()
            .contains(&w.other_employee.to_string()),
        "the listing returned a user the object decision denies"
    );
}

/// The narrow-denial parity property, for the `ASSIGNED` scope.
///
/// The first round of this fix handled `RESOURCE` denials (and `DEPARTMENT` for
/// departments) and missed `ASSIGNED`, so an `ASSIGNED`-scoped DENY still blocked
/// `GET /clients/{id}` while leaving the row in `GET /clients`. `ASSIGNED` means
/// "the accounts I manage" on the allow side, so it has to mean the same on the
/// deny side; it cannot be expressed as a list of ids, which is why it was easy to
/// forget.
#[tokio::test]
async fn an_assigned_scoped_denial_hides_managed_clients_from_the_listing() {
    let w = World::build().await;

    // Make the administrator the account manager, so ASSIGNED actually resolves.
    sqlx::query("UPDATE client_accounts SET account_manager_user_id = $1 WHERE id = $2")
        .bind(w.admin.id)
        .bind(w.client_account_a)
        .execute(&w.app.db)
        .await
        .expect("assign the account manager");

    sqlx::query(
        "INSERT INTO user_permission_overrides
             (id, user_id, permission_code, effect, scope_type, granted_by)
         VALUES ($1, $2, 'clients.read', 'DENY', 'ASSIGNED', $3)",
    )
    .bind(Uuid::now_v7())
    .bind(w.admin.id)
    .bind(w.root.id)
    .execute(&w.app.db)
    .await
    .expect("seed an ASSIGNED denial");

    let object = w
        .app
        .get(
            &format!("/api/v1/clients/{}", w.client_account_a),
            w.admin.bearer(),
        )
        .await;
    assert!(
        object.status == StatusCode::FORBIDDEN || object.status == StatusCode::NOT_FOUND,
        "the object route ignored an ASSIGNED denial: {}",
        object.status
    );

    let listing = w.app.get("/api/v1/clients", w.admin.bearer()).await;
    assert_eq!(listing.status, StatusCode::OK, "listing failed");
    assert!(
        !listing
            .json()
            .to_string()
            .contains(&w.client_account_a.to_string()),
        "the listing returned a managed client the object decision denies"
    );
}

/// The same property for departments, where `ASSIGNED` and `DEPARTMENT` both
/// resolve to the actor's own departments.
#[tokio::test]
async fn an_assigned_scoped_denial_hides_the_department_from_the_listing() {
    let w = World::build().await;

    // The manager is a member of `w.department`, so ASSIGNED resolves to it.
    sqlx::query(
        "INSERT INTO user_permission_overrides
             (id, user_id, permission_code, effect, scope_type, granted_by)
         VALUES ($1, $2, 'departments.read', 'DENY', 'ASSIGNED', $3)",
    )
    .bind(Uuid::now_v7())
    .bind(w.manager.id)
    .bind(w.root.id)
    .execute(&w.app.db)
    .await
    .expect("seed an ASSIGNED denial");

    let listing = w.app.get("/api/v1/departments", w.manager.bearer()).await;
    // Either a refusal or an empty page is correct — what must never happen is the
    // denied department coming back in the body.
    if listing.status == StatusCode::OK {
        assert!(
            !listing
                .json()
                .to_string()
                .contains(&w.department.to_string()),
            "the listing returned a department an ASSIGNED denial covers"
        );
    }
}

/// Department membership resolves DEPARTMENT scope, so adding someone to a
/// department is a privilege operation — and the delegation guard already refuses
/// an actor to hand *themselves* a role for exactly that reason. The same rule has
/// to hold here, or a holder of `departments.members.manage` walks into any
/// department and self-grants whatever DEPARTMENT-scoped visibility their other
/// permissions imply.
#[tokio::test]
async fn an_administrator_cannot_add_themselves_to_a_department() {
    let w = World::build().await;
    let foreign = seed_department(&w.app, "finance-self", w.root.id).await;

    let refused = w
        .app
        .post(
            &format!("/api/v1/departments/{foreign}/members"),
            w.admin.bearer(),
            json!({"user_id": w.admin.id}),
        )
        .await;
    assert_eq!(
        refused.status,
        StatusCode::FORBIDDEN,
        "an administrator added themselves to a department: {}",
        refused.json()
    );

    let members: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM department_memberships
          WHERE department_id = $1 AND user_id = $2 AND removed_at IS NULL",
    )
    .bind(foreign)
    .bind(w.admin.id)
    .fetch_one(&w.app.db)
    .await
    .expect("count memberships");
    assert_eq!(members.0, 0, "the refusal still wrote a membership");

    // The capability itself still works when it targets somebody else.
    let allowed = w
        .app
        .post(
            &format!("/api/v1/departments/{foreign}/members"),
            w.admin.bearer(),
            json!({"user_id": w.other_employee}),
        )
        .await;
    assert_eq!(
        allowed.status,
        StatusCode::CREATED,
        "the guard blocked a legitimate placement too: {}",
        allowed.json()
    );
}
