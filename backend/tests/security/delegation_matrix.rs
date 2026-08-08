//! The escalation boundary, driven through HTTP.
//!
//! `delegation::derivable` is exhaustively unit- and property-tested. What those
//! tests cannot show is that the *route* reaches the guard: a handler that
//! authorises the endpoint and then writes the row would pass every unit test in
//! the module while shipping privilege escalation. Everything below therefore goes
//! through the real router, and every refusal is followed by a database assertion
//! that nothing was written.
//!
//! The actor is bounded on purpose. It holds delegation authority — `iam.roles.*`
//! and `iam.permissions.delegate` at `GLOBAL` — but its *business* authority is
//! deliberately narrow: `projects.read@DEPARTMENT` and `tasks.read@GLOBAL`, and
//! nothing else. Every refusal below is therefore about what it may hand out, not
//! about whether it may use the endpoint.

use axum::http::StatusCode;
use serde_json::json;
use uuid::Uuid;

use crate::common::TestResponse;
use crate::fixtures::{
    enrol_totp, grant_override, login, password_hash, seed_user, Actor, World, ROLE_EMPLOYEE,
    ROLE_SYSTEM_ADMINISTRATOR,
};

/// A permission the actor holds at `DEPARTMENT`, and nothing wider.
const NARROW: &str = "projects.read";
/// A permission the actor holds at `GLOBAL`.
const WIDE: &str = "tasks.read";
/// A permission the actor does not hold at all.
const UNHELD: &str = "projects.update";

/// The delegation authority itself, without any business authority attached.
const DELEGATION_GRANTS: &[(&str, &str)] = &[
    ("iam.roles.read", "GLOBAL"),
    ("iam.roles.create", "GLOBAL"),
    ("iam.roles.update", "GLOBAL"),
    ("iam.roles.delete", "GLOBAL"),
    ("iam.roles.assign", "GLOBAL"),
    ("iam.permissions.read", "GLOBAL"),
    ("iam.permissions.delegate", "GLOBAL"),
];

/// Build a bounded delegator on top of the standard world.
///
/// `with_step_up` exists because every delegation route is step-up gated: without
/// a recent second factor every refusal would be `STEP_UP_REQUIRED` and none of
/// them would say anything about the lattice.
async fn granter(w: &World, email: &str, with_step_up: bool) -> Actor {
    let hash = password_hash(&w.app).await;
    let id = seed_user(&w.app, email, "INTERNAL", &hash).await;

    // Deliberately **no** built-in role. The baseline `employee` role carries
    // `projects.read@ASSIGNED` and `tasks.read@ASSIGNED`, and an actor that holds a
    // permission at ASSIGNED may legitimately hand it out at ASSIGNED — which would
    // make the DEPARTMENT-to-ASSIGNED cases below pass for the wrong reason. The
    // actor's authority is exactly the overrides listed here and nothing else.
    for (code, scope) in DELEGATION_GRANTS {
        grant_override(&w.app, id, code, "ALLOW", scope, w.root.id).await;
    }
    grant_override(&w.app, id, NARROW, "ALLOW", "DEPARTMENT", w.root.id).await;
    grant_override(&w.app, id, WIDE, "ALLOW", "GLOBAL", w.root.id).await;

    let token = login(&w.app, email).await;
    if with_step_up {
        enrol_totp(&w.app, &token).await;
    }
    Actor {
        id,
        email: email.into(),
        token,
    }
}

#[track_caller]
fn delegation_denied(response: &TestResponse, what: &str) {
    assert_eq!(
        response.status,
        StatusCode::FORBIDDEN,
        "{what} produced {} instead of a delegation refusal: {}",
        response.status,
        String::from_utf8_lossy(&response.raw)
    );
    assert_eq!(
        response.error_code(),
        Some("DELEGATION_DENIED"),
        "{what}: {}",
        String::from_utf8_lossy(&response.raw)
    );
    response.assert_no_secrets();
}

async fn override_count(w: &World, user_id: Uuid, code: &str) -> i64 {
    let row: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM user_permission_overrides
          WHERE user_id = $1 AND permission_code = $2",
    )
    .bind(user_id)
    .bind(code)
    .fetch_one(&w.app.db)
    .await
    .expect("count overrides");
    row.0
}

fn grant_body(code: &str, scope: &str) -> serde_json::Value {
    json!({"permission_code": code, "effect": "ALLOW", "scope": scope})
}

// ===========================================================================
// Rule 1 — an actor cannot grant what it does not hold
// ===========================================================================

#[tokio::test]
async fn an_actor_holding_a_and_b_cannot_grant_c() {
    let w = World::build().await;
    let actor = granter(&w, "granter@fixture.test", true).await;
    let subject = w.other_employee;

    // The control: what it holds, at the scope it holds it, goes through. Without
    // this the test would pass just as well against an endpoint that refuses
    // everything.
    w.app
        .post(
            &format!("/api/v1/users/{subject}/permission-overrides"),
            actor.bearer(),
            grant_body(WIDE, "GLOBAL"),
        )
        .await
        .assert_status(StatusCode::CREATED);

    for scope in ["GLOBAL", "DEPARTMENT", "ASSIGNED", "SELF"] {
        delegation_denied(
            &w.app
                .post(
                    &format!("/api/v1/users/{subject}/permission-overrides"),
                    actor.bearer(),
                    grant_body(UNHELD, scope),
                )
                .await,
            &format!("granting an unheld permission at {scope}"),
        );
    }
    assert_eq!(
        override_count(&w, subject, UNHELD).await,
        0,
        "an unheld permission was written despite the refusal"
    );

    // A DENY is refused on the same authority: §6 rule 6 says removing a DENY is an
    // escalation, so creating one must need the authority to grant the ALLOW.
    delegation_denied(
        &w.app
            .post(
                &format!("/api/v1/users/{subject}/permission-overrides"),
                actor.bearer(),
                json!({"permission_code": UNHELD, "effect": "DENY", "scope": "GLOBAL"}),
            )
            .await,
        "creating a DENY for an unheld permission",
    );
}

// ===========================================================================
// Rule 2 — the derivation lattice
// ===========================================================================

/// `DEPARTMENT` may reproduce itself or narrow to `SELF`. It may not widen to
/// `GLOBAL`, and it may not move sideways to `ASSIGNED` — the grantee could then be
/// assigned to a project in another department.
#[tokio::test]
async fn an_actor_bounded_by_department_cannot_mint_global_or_assigned() {
    let w = World::build().await;
    let actor = granter(&w, "lattice@fixture.test", true).await;
    let subject = w.other_employee;
    let path = format!("/api/v1/users/{subject}/permission-overrides");

    for scope in ["GLOBAL", "ASSIGNED"] {
        delegation_denied(
            &w.app
                .post(&path, actor.bearer(), grant_body(NARROW, scope))
                .await,
            &format!("widening DEPARTMENT to {scope}"),
        );
    }

    // RESOURCE is also unreachable from DEPARTMENT: the actor cannot verify the
    // named object is inside its department.
    delegation_denied(
        &w.app
            .post(
                &path,
                actor.bearer(),
                json!({
                    "permission_code": NARROW,
                    "effect": "ALLOW",
                    "scope": "RESOURCE",
                    "resource_type": "PROJECT",
                    "resource_id": w.internal_project,
                }),
            )
            .await,
        "deriving RESOURCE from DEPARTMENT",
    );

    // The two that are legitimate.
    w.app
        .post(&path, actor.bearer(), grant_body(NARROW, "DEPARTMENT"))
        .await
        .assert_status(StatusCode::CREATED);
    w.app
        .post(&path, actor.bearer(), grant_body(NARROW, "SELF"))
        .await
        .assert_status(StatusCode::CREATED);

    let scopes: Vec<(String,)> = sqlx::query_as(
        "SELECT scope_type FROM user_permission_overrides
          WHERE user_id = $1 AND permission_code = $2 ORDER BY scope_type",
    )
    .bind(subject)
    .bind(NARROW)
    .fetch_all(&w.app.db)
    .await
    .expect("read the written scopes");
    let written: Vec<&str> = scopes.iter().map(|s| s.0.as_str()).collect();
    assert_eq!(
        written,
        vec!["DEPARTMENT", "SELF"],
        "a scope outside the lattice reached the database"
    );
}

// ===========================================================================
// Rule 3 — no self-modification of privilege
// ===========================================================================

#[tokio::test]
async fn an_actor_cannot_modify_its_own_privileges() {
    let w = World::build().await;
    let actor = granter(&w, "selfserve@fixture.test", true).await;

    delegation_denied(
        &w.app
            .post(
                &format!("/api/v1/users/{}/permission-overrides", actor.id),
                actor.bearer(),
                // Something it genuinely holds — the refusal is the self-target,
                // not the authority.
                grant_body(WIDE, "GLOBAL"),
            )
            .await,
        "granting itself a permission it already holds",
    );
    delegation_denied(
        &w.app
            .post(
                &format!("/api/v1/users/{}/roles", actor.id),
                actor.bearer(),
                json!({"role_id": ROLE_EMPLOYEE}),
            )
            .await,
        "assigning itself a role",
    );
    delegation_denied(
        &w.app
            .delete(
                &format!("/api/v1/users/{}/roles/{}", actor.id, ROLE_EMPLOYEE),
                actor.bearer(),
            )
            .await,
        "removing a role from itself",
    );

    assert_eq!(
        override_count(&w, actor.id, WIDE).await,
        1,
        "the actor's own override set changed"
    );
}

// ===========================================================================
// Rule 7 — a DENY on the actor blocks delegation, not merely access
// ===========================================================================

#[tokio::test]
async fn a_deny_on_the_actor_removes_its_ability_to_delegate() {
    let w = World::build().await;
    let actor = granter(&w, "denied@fixture.test", true).await;
    let subject = w.other_employee;
    let path = format!("/api/v1/users/{subject}/permission-overrides");

    // Before: the actor can hand out what it holds.
    w.app
        .post(&path, actor.bearer(), grant_body(WIDE, "GLOBAL"))
        .await
        .assert_status(StatusCode::CREATED);
    // Clean up so the second attempt is not refused as a duplicate row.
    sqlx::query(
        "DELETE FROM user_permission_overrides WHERE user_id = $1 AND permission_code = $2",
    )
    .bind(subject)
    .bind(WIDE)
    .execute(&w.app.db)
    .await
    .expect("remove the granted override");

    grant_override(&w.app, actor.id, WIDE, "DENY", "GLOBAL", w.root.id).await;

    delegation_denied(
        &w.app
            .post(&path, actor.bearer(), grant_body(WIDE, "GLOBAL"))
            .await,
        "delegating a permission the actor is explicitly denied",
    );
    assert_eq!(
        override_count(&w, subject, WIDE).await,
        0,
        "a denied permission was delegated anyway"
    );

    // The DENY also removes access, and adding more allows cannot overturn it.
    grant_override(&w.app, actor.id, WIDE, "ALLOW", "ASSIGNED", w.root.id).await;
    w.app
        .get("/api/v1/tasks", actor.bearer())
        .await
        .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");
}

// ===========================================================================
// Role authoring and assignment
// ===========================================================================

#[tokio::test]
async fn an_actor_cannot_author_a_role_more_powerful_than_itself() {
    let w = World::build().await;
    let actor = granter(&w, "author@fixture.test", true).await;

    let attempts = [
        ("a permission it does not hold", UNHELD, "GLOBAL"),
        ("a scope it cannot derive", NARROW, "GLOBAL"),
        ("a lateral scope", NARROW, "ASSIGNED"),
    ];
    for (what, code, scope) in attempts {
        delegation_denied(
            &w.app
                .post(
                    "/api/v1/roles",
                    actor.bearer(),
                    json!({
                        "code": "escalation",
                        "name": "Escalation",
                        "allowed_principal_type": "INTERNAL",
                        "permissions": [{"permission_code": code, "scope": scope}],
                    }),
                )
                .await,
            &format!("authoring a role containing {what}"),
        );
    }

    // Reproducing exactly what it holds is legitimate.
    w.app
        .post(
            "/api/v1/roles",
            actor.bearer(),
            json!({
                "code": "reader",
                "name": "Reader",
                "allowed_principal_type": "INTERNAL",
                "permissions": [
                    {"permission_code": NARROW, "scope": "DEPARTMENT"},
                    {"permission_code": WIDE, "scope": "GLOBAL"},
                ],
            }),
        )
        .await
        .assert_status(StatusCode::CREATED);

    let escalations: (i64,) =
        sqlx::query_as("SELECT count(*) FROM roles WHERE code = 'escalation'")
            .fetch_one(&w.app.db)
            .await
            .expect("count");
    assert_eq!(escalations.0, 0, "an over-powered role was created");
}

/// The classic composition hole: hold `iam.roles.assign`, then assign a role that
/// contains what you could never grant directly.
#[tokio::test]
async fn a_role_cannot_be_used_to_smuggle_authority_the_actor_lacks() {
    let w = World::build().await;
    let actor = granter(&w, "smuggler@fixture.test", true).await;
    let subject = w.other_employee;

    delegation_denied(
        &w.app
            .post(
                &format!("/api/v1/users/{subject}/roles"),
                actor.bearer(),
                json!({"role_id": ROLE_SYSTEM_ADMINISTRATOR}),
            )
            .await,
        "assigning the administrator role",
    );

    // Even the baseline `employee` role is out of reach: it carries
    // `projects.read@ASSIGNED`, and DEPARTMENT cannot derive ASSIGNED.
    delegation_denied(
        &w.app
            .post(
                &format!("/api/v1/users/{subject}/roles"),
                actor.bearer(),
                json!({"role_id": ROLE_EMPLOYEE}),
            )
            .await,
        "assigning a role whose scopes it cannot derive",
    );

    let assigned: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM user_role_assignments WHERE user_id = $1 AND role_id = $2::uuid",
    )
    .bind(subject)
    .bind(ROLE_SYSTEM_ADMINISTRATOR)
    .fetch_one(&w.app.db)
    .await
    .expect("count");
    assert_eq!(assigned.0, 0, "the administrator role was assigned");
}

/// Rule 5. Built-in roles are immutable through the API for everyone, including the
/// owner: changing `employee` for one person changes it for every employee.
#[tokio::test]
async fn system_roles_cannot_be_edited_or_deleted_even_by_the_owner() {
    let w = World::build().await;

    for actor in [&w.root, &w.admin] {
        w.app
            .patch(
                &format!("/api/v1/roles/{ROLE_EMPLOYEE}"),
                actor.bearer(),
                json!({"version": 1, "name": "Employee (compromised)"}),
            )
            .await
            .assert_error(StatusCode::FORBIDDEN, "DELEGATION_DENIED");

        w.app
            .patch(
                &format!("/api/v1/roles/{ROLE_EMPLOYEE}"),
                actor.bearer(),
                json!({"version": 1, "permissions": [
                    {"permission_code": "audit.read", "scope": "GLOBAL"}
                ]}),
            )
            .await
            .assert_error(StatusCode::FORBIDDEN, "DELEGATION_DENIED");

        w.app
            .delete(&format!("/api/v1/roles/{ROLE_EMPLOYEE}"), actor.bearer())
            .await
            .assert_error(StatusCode::FORBIDDEN, "DELEGATION_DENIED");
    }

    let contents: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM role_permissions WHERE role_id = $1::uuid AND permission_code = 'audit.read'",
    )
    .bind(ROLE_EMPLOYEE)
    .fetch_one(&w.app.db)
    .await
    .expect("count");
    assert_eq!(contents.0, 0, "a built-in role gained a permission");
}

// ===========================================================================
// Step-up and probing
// ===========================================================================

/// TH-28. `iam.permissions.delegate` and `iam.roles.assign` are dangerous, so a
/// session with no recent second factor cannot exercise them however it was
/// authenticated.
#[tokio::test]
async fn delegation_without_a_recent_second_factor_is_refused() {
    let w = World::build().await;
    let actor = granter(&w, "nostepup@fixture.test", false).await;
    let subject = w.other_employee;

    for (path, body) in [
        (
            format!("/api/v1/users/{subject}/permission-overrides"),
            grant_body(WIDE, "GLOBAL"),
        ),
        (
            format!("/api/v1/users/{subject}/roles"),
            json!({"role_id": ROLE_EMPLOYEE}),
        ),
    ] {
        let response = w.app.post(&path, actor.bearer(), body).await;
        response
            .assert_error(StatusCode::FORBIDDEN, "STEP_UP_REQUIRED")
            .assert_no_secrets();
        // The client is told the window, so it can prompt rather than give up.
        let window = response.json()["step_up"]["window_seconds"]
            .as_u64()
            .expect("the step-up hint must carry the window");
        assert!(window > 0, "a client cannot act on a zero-second window");
    }

    // Authoring a role is gated the same way.
    w.app
        .post(
            "/api/v1/roles",
            actor.bearer(),
            json!({
                "code": "quiet",
                "name": "Quiet",
                "allowed_principal_type": "INTERNAL",
                "permissions": [],
            }),
        )
        .await
        .assert_error(StatusCode::FORBIDDEN, "STEP_UP_REQUIRED");

    assert_eq!(override_count(&w, subject, WIDE).await, 0);
}

/// A permission code that is not in the catalogue means the caller is probing the
/// authorisation surface, and is reported as such rather than as a plain field error.
#[tokio::test]
async fn an_uncatalogued_permission_code_is_reported_as_a_probe() {
    let w = World::build().await;
    let actor = granter(&w, "prober@fixture.test", true).await;
    let path = format!("/api/v1/users/{}/permission-overrides", w.other_employee);

    for bogus in [
        "iam.users.delete",
        "projects.*",
        "*",
        "PROJECTS.READ",
        "system.ownership.transfer",
        "iam.users.delete ",
    ] {
        let response = w
            .app
            .post(&path, actor.bearer(), grant_body(bogus, "GLOBAL"))
            .await;
        assert!(
            response.status.is_client_error(),
            "`{bogus}` was accepted with {}",
            response.status
        );
        response.assert_no_secrets();
        assert!(
            !String::from_utf8_lossy(&response.raw).contains("projects.*"),
            "the probed code was reflected back to the caller"
        );
    }

    w.app
        .post(
            &path,
            actor.bearer(),
            grant_body("not.a.permission", "GLOBAL"),
        )
        .await
        .assert_error(StatusCode::BAD_REQUEST, "UNKNOWN_PERMISSION");

    // A malformed scope is a validation failure, never a silently normalised grant.
    for scope in ["global", "EVERYTHING", "", "GLOBAL; DROP TABLE roles"] {
        let response = w
            .app
            .post(&path, actor.bearer(), grant_body(WIDE, scope))
            .await;
        assert_eq!(
            response.status,
            StatusCode::BAD_REQUEST,
            "scope `{scope}` was accepted"
        );
    }
    assert_eq!(override_count(&w, w.other_employee, WIDE).await, 0);
}
