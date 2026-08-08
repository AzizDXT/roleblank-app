//! `/api/v1/permissions`, `/api/v1/roles`, role assignment and per-user overrides.
//!
//! This is the surface that moves authority, so almost every test here has a
//! refusal in it. Two properties are load-bearing and are asserted by name:
//!
//! * **a built-in role cannot be authored, edited or deleted by anyone, including
//!   the system owner** — changing `employee` for one person changes it for every
//!   employee, which is what custom roles are for;
//! * **an actor cannot hand out authority it does not itself hold**, and a role is
//!   validated permission by permission rather than as an opaque unit, because
//!   "may I assign roles?" is the classic escalation hole.

use axum::http::StatusCode;
use serde_json::json;
use uuid::Uuid;

use crate::common::TestApp;
use crate::fixtures::*;

async fn role_exists(app: &TestApp, id: Uuid) -> bool {
    let (count,): (i64,) = sqlx::query_as("SELECT count(*) FROM roles WHERE id = $1")
        .bind(id)
        .fetch_one(&app.db)
        .await
        .expect("count roles");
    count == 1
}

async fn assignment_count(app: &TestApp, user: Uuid, role: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM user_role_assignments WHERE user_id = $1 AND role_id = $2",
    )
    .bind(user)
    .bind(role)
    .fetch_one(&app.db)
    .await
    .expect("count assignments")
}

async fn security_version(app: &TestApp, user: Uuid) -> i32 {
    sqlx::query_scalar("SELECT security_version FROM users WHERE id = $1")
        .bind(user)
        .fetch_one(&app.db)
        .await
        .expect("the user row")
}

// ===========================================================================
// The catalogue
// ===========================================================================

/// The catalogue is served from the compiled table, not from the `permissions`
/// rows: the code table is what the evaluator actually enforces, and an
/// administrator must see what will happen rather than what a row claims.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_permission_catalogue_is_readable_and_marks_the_client_reachable_codes() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;

    let listed = app.get("/api/v1/permissions", Some(&root.token)).await;
    listed.assert_status(StatusCode::OK).assert_no_secrets();
    let items = listed.json()["items"].as_array().expect("items").clone();
    assert!(items.len() > 30, "the catalogue looks truncated");

    for item in &items {
        let code = item["code"].as_str().expect("a code");
        let client_reachable = item["max_principal_type"] == json!("ANY");
        assert_eq!(
            client_reachable,
            code.starts_with("client.portal."),
            "`{code}` reachability by a CLIENT principal does not match its namespace"
        );
        if client_reachable {
            assert_eq!(
                item["is_dangerous"],
                json!(false),
                "`{code}` is both client-reachable and dangerous"
            );
        }
    }

    let dangerous: Vec<&str> = items
        .iter()
        .filter(|i| i["is_dangerous"] == json!(true))
        .map(|i| i["code"].as_str().expect("a code"))
        .collect();
    let mut sorted = dangerous.clone();
    sorted.sort_unstable();
    assert_eq!(
        sorted,
        vec![
            "iam.permissions.delegate",
            "iam.roles.assign",
            "iam.sessions.revoke",
            "projects.clients.share",
            "settings.security.write",
        ],
        "the dangerous set changed; every one of these is behind step-up"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_employee_cannot_read_the_permission_catalogue() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let employee = create_employee(&app, &root.token, "dev@roleblank.test", None).await;

    app.get("/api/v1/permissions", Some(&employee.token))
        .await
        .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");
    app.get("/api/v1/roles", Some(&employee.token))
        .await
        .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");
}

// ===========================================================================
// Roles
// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_role_is_created_read_listed_updated_and_deleted() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;

    let created = app
        .post(
            "/api/v1/roles",
            Some(&root.token),
            json!({
                "code": "field_manager",
                "name": "Field Manager",
                "description": "Runs work in their own department",
                "allowed_principal_type": "INTERNAL",
                "permissions": [
                    {"permission_code": "projects.read", "scope": "DEPARTMENT"},
                    {"permission_code": "tasks.read", "scope": "ASSIGNED"},
                ],
            }),
        )
        .await;
    created
        .assert_status(StatusCode::CREATED)
        .assert_no_secrets();
    let id = created.id_at("/id");
    assert_eq!(created.json()["is_system"], json!(false));
    assert_eq!(created.json()["version"], json!(1));
    assert_eq!(
        created.json()["permissions"]
            .as_array()
            .expect("array")
            .len(),
        2
    );
    assert_eq!(audit_count_for(&app, "ROLE.CREATED", id).await, 1);

    let found = app
        .get(&format!("/api/v1/roles/{id}"), Some(&root.token))
        .await;
    found.assert_status(StatusCode::OK);
    assert_eq!(found.str_at("/code"), "field_manager");

    let listed = app
        .get("/api/v1/roles?sort=code&direction=asc", Some(&root.token))
        .await;
    listed.assert_status(StatusCode::OK);
    // The three seeded roles plus the new one.
    assert_eq!(ids_in(&listed).len(), 4);

    let renamed = app
        .patch(
            &format!("/api/v1/roles/{id}"),
            Some(&root.token),
            json!({"version": 1, "name": "Field Lead"}),
        )
        .await;
    renamed.assert_status(StatusCode::OK);
    assert_eq!(renamed.str_at("/name"), "Field Lead");
    assert_eq!(renamed.json()["version"], json!(2));
    assert_eq!(
        renamed.json()["permissions"]
            .as_array()
            .expect("array")
            .len(),
        2,
        "absent permissions must leave the set alone, not empty it"
    );

    // An explicit empty array is a real instruction: strip the role.
    let stripped = app
        .patch(
            &format!("/api/v1/roles/{id}"),
            Some(&root.token),
            json!({"version": 2, "permissions": []}),
        )
        .await;
    stripped.assert_status(StatusCode::OK);
    assert!(stripped.json()["permissions"]
        .as_array()
        .expect("array")
        .is_empty());

    app.delete(&format!("/api/v1/roles/{id}"), Some(&root.token))
        .await
        .assert_status(StatusCode::NO_CONTENT);
    assert!(!role_exists(&app, id).await);
    assert_eq!(audit_count_for(&app, "ROLE.DELETED", id).await, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn role_creation_validates_its_code_its_scopes_and_its_permission_codes() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;

    // A role code is stricter than a general code: no hyphens.
    app.post(
        "/api/v1/roles",
        Some(&root.token),
        json!({"code": "field-manager", "name": "X", "allowed_principal_type": "INTERNAL", "permissions": []}),
    )
    .await
    .assert_error(StatusCode::BAD_REQUEST, "VALIDATION_FAILED");

    // A role is a reusable template and cannot name a specific object, so the
    // fields a RESOURCE scope would need are absent from the type entirely.
    app.post(
        "/api/v1/roles",
        Some(&root.token),
        json!({
            "code": "namer", "name": "X", "allowed_principal_type": "INTERNAL",
            "permissions": [{
                "permission_code": "projects.read", "scope": "RESOURCE",
                "resource_type": "PROJECT", "resource_id": Uuid::now_v7(),
            }],
        }),
    )
    .await
    .assert_error(StatusCode::BAD_REQUEST, "BAD_REQUEST");

    app.post(
        "/api/v1/roles",
        Some(&root.token),
        json!({
            "code": "namer", "name": "X", "allowed_principal_type": "INTERNAL",
            "permissions": [{"permission_code": "projects.read", "scope": "RESOURCE"}],
        }),
    )
    .await
    .assert_error(StatusCode::BAD_REQUEST, "VALIDATION_FAILED");

    // An unknown permission code means the caller is probing the authorisation
    // surface, and is reported as such rather than as a validation nicety.
    app.post(
        "/api/v1/roles",
        Some(&root.token),
        json!({
            "code": "ghost", "name": "X", "allowed_principal_type": "INTERNAL",
            "permissions": [{"permission_code": "projects.destroy", "scope": "GLOBAL"}],
        }),
    )
    .await
    .assert_error(StatusCode::BAD_REQUEST, "UNKNOWN_PERMISSION");

    // The same permission twice would be a primary-key violation rendered as an
    // opaque conflict, or a role holding one permission at two scopes.
    app.post(
        "/api/v1/roles",
        Some(&root.token),
        json!({
            "code": "twice", "name": "X", "allowed_principal_type": "INTERNAL",
            "permissions": [
                {"permission_code": "projects.read", "scope": "GLOBAL"},
                {"permission_code": "projects.read", "scope": "DEPARTMENT"},
            ],
        }),
    )
    .await
    .assert_error(StatusCode::BAD_REQUEST, "VALIDATION_FAILED");

    // An internal permission cannot be part of a CLIENT role at all.
    app.post(
        "/api/v1/roles",
        Some(&root.token),
        json!({
            "code": "leaky", "name": "X", "allowed_principal_type": "CLIENT",
            "permissions": [{"permission_code": "audit.read", "scope": "GLOBAL"}],
        }),
    )
    .await
    .assert_error(StatusCode::FORBIDDEN, "DELEGATION_DENIED");

    for body in [
        json!({"code": "x", "name": "X", "allowed_principal_type": "INTERNAL", "permissions": [], "is_system": true}),
        json!({"code": "x", "name": "X", "allowed_principal_type": "INTERNAL", "permissions": [], "id": Uuid::now_v7()}),
    ] {
        app.post("/api/v1/roles", Some(&root.token), body)
            .await
            .assert_error(StatusCode::BAD_REQUEST, "BAD_REQUEST");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_duplicate_role_code_is_refused_and_a_stale_version_never_overwrites() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let id = create_role(
        &app,
        &root.token,
        "auditor",
        "INTERNAL",
        &[("audit.read", "GLOBAL")],
    )
    .await;

    app.post(
        "/api/v1/roles",
        Some(&root.token),
        json!({"code": "auditor", "name": "Again", "allowed_principal_type": "INTERNAL", "permissions": []}),
    )
    .await
    .assert_error(StatusCode::CONFLICT, "UNIQUE_VIOLATION");

    app.patch(
        &format!("/api/v1/roles/{id}"),
        Some(&root.token),
        json!({"version": 1, "name": "First writer"}),
    )
    .await
    .assert_status(StatusCode::OK);
    app.patch(
        &format!("/api/v1/roles/{id}"),
        Some(&root.token),
        json!({"version": 1, "name": "Second writer"}),
    )
    .await
    .assert_error(StatusCode::CONFLICT, "VERSION_CONFLICT");

    // `code` and `allowed_principal_type` are immutable: a different envelope means
    // a different role.
    for body in [
        json!({"version": 2, "code": "renamed"}),
        json!({"version": 2, "allowed_principal_type": "CLIENT"}),
        json!({"version": 2, "is_system": true}),
        json!({"name": "no version"}),
    ] {
        app.patch(&format!("/api/v1/roles/{id}"), Some(&root.token), body)
            .await
            .assert_error(StatusCode::BAD_REQUEST, "BAD_REQUEST");
    }
}

/// **Rule 5 of the delegation guard, stated at the HTTP boundary.** The owner
/// bypasses permission *evaluation*; it does not bypass this. Editing `employee`
/// for one person would edit it for every employee.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_system_role_cannot_be_edited_or_deleted_by_anyone_including_root() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;

    for role in [ROLE_SYSTEM_ADMINISTRATOR, ROLE_EMPLOYEE, ROLE_CLIENT_USER] {
        app.patch(
            &format!("/api/v1/roles/{role}"),
            Some(&root.token),
            json!({"version": 1, "name": "Rewritten"}),
        )
        .await
        .assert_error(StatusCode::FORBIDDEN, "DELEGATION_DENIED");

        app.delete(&format!("/api/v1/roles/{role}"), Some(&root.token))
            .await
            .assert_error(StatusCode::FORBIDDEN, "DELEGATION_DENIED");

        app.patch(
            &format!("/api/v1/roles/{role}"),
            Some(&root.token),
            json!({"version": 1, "permissions": [{"permission_code": "audit.read", "scope": "GLOBAL"}]}),
        )
        .await
        .assert_error(StatusCode::FORBIDDEN, "DELEGATION_DENIED");

        assert!(role_exists(&app, Uuid::parse_str(role).expect("seeded id")).await);
    }

    // The seeded permission sets are untouched.
    let (employee_permissions,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM role_permissions WHERE role_id = $1")
            .bind(Uuid::parse_str(ROLE_EMPLOYEE).expect("seeded id"))
            .fetch_one(&app.db)
            .await
            .expect("count");
    assert_eq!(employee_permissions, 5);
}

/// A role still held by somebody cannot be deleted: the count is read inside the
/// transaction with the role row locked, so "zero holders" cannot become "one"
/// between the check and the delete.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_role_with_live_assignments_cannot_be_deleted() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let employee = create_employee(&app, &root.token, "dev@roleblank.test", None).await;
    let role = create_role(
        &app,
        &root.token,
        "reader",
        "INTERNAL",
        &[("projects.read", "GLOBAL")],
    )
    .await;

    app.post(
        &format!("/api/v1/users/{}/roles", employee.user_id),
        Some(&root.token),
        json!({"role_id": role}),
    )
    .await
    .assert_status(StatusCode::CREATED);

    app.delete(&format!("/api/v1/roles/{role}"), Some(&root.token))
        .await
        .assert_error(StatusCode::CONFLICT, "ROLE_IN_USE");
    assert!(role_exists(&app, role).await);

    app.delete(
        &format!("/api/v1/users/{}/roles/{role}", employee.user_id),
        Some(&root.token),
    )
    .await
    .assert_status(StatusCode::NO_CONTENT);

    app.delete(&format!("/api/v1/roles/{role}"), Some(&root.token))
        .await
        .assert_status(StatusCode::NO_CONTENT);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unknown_role_is_not_found_and_a_malformed_id_is_a_field_error() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;

    app.get(
        &format!("/api/v1/roles/{}", Uuid::now_v7()),
        Some(&root.token),
    )
    .await
    .assert_error(StatusCode::NOT_FOUND, "RESOURCE_NOT_FOUND");

    // The authorization routes parse their path parameters by hand precisely so a
    // malformed one is `application/problem+json` like every other error here.
    app.get("/api/v1/roles/not-a-uuid", Some(&root.token))
        .await
        .assert_error(StatusCode::BAD_REQUEST, "VALIDATION_FAILED");
}

// ===========================================================================
// Assignment
// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_role_is_assigned_listed_and_unassigned() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let employee = create_employee(&app, &root.token, "dev@roleblank.test", None).await;
    let role = create_role(
        &app,
        &root.token,
        "reader",
        "INTERNAL",
        &[("projects.read", "GLOBAL")],
    )
    .await;
    let before = security_version(&app, employee.user_id).await;

    let assigned = app
        .post(
            &format!("/api/v1/users/{}/roles", employee.user_id),
            Some(&root.token),
            json!({"role_id": role}),
        )
        .await;
    assigned
        .assert_status(StatusCode::CREATED)
        .assert_no_secrets();
    let codes: Vec<&str> = assigned.json()["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|i| i["code"].as_str().expect("a code"))
        .collect();
    assert!(codes.contains(&"reader") && codes.contains(&"employee"));
    assert_eq!(assignment_count(&app, employee.user_id, role).await, 1);
    assert!(
        security_version(&app, employee.user_id).await > before,
        "a privilege change must move the security version"
    );
    assert_eq!(
        audit_count_for(&app, "ROLE.ASSIGNED", employee.user_id).await,
        1
    );

    // The authority is real on the very next request — nothing is cached.
    app.get("/api/v1/projects", Some(&employee.token))
        .await
        .assert_status(StatusCode::OK);

    app.post(
        &format!("/api/v1/users/{}/roles", employee.user_id),
        Some(&root.token),
        json!({"role_id": role}),
    )
    .await
    .assert_error(StatusCode::CONFLICT, "ROLE_ALREADY_ASSIGNED");

    let listed = app
        .get(
            &format!("/api/v1/users/{}/roles", employee.user_id),
            Some(&root.token),
        )
        .await;
    listed.assert_status(StatusCode::OK);
    assert_eq!(listed.json()["items"].as_array().expect("items").len(), 2);

    app.delete(
        &format!("/api/v1/users/{}/roles/{role}", employee.user_id),
        Some(&root.token),
    )
    .await
    .assert_status(StatusCode::NO_CONTENT);
    assert_eq!(assignment_count(&app, employee.user_id, role).await, 0);
    assert_eq!(
        audit_count_for(&app, "ROLE.UNASSIGNED", employee.user_id).await,
        1
    );

    // Removing a role nobody holds would tell an operator something changed when
    // nothing did.
    app.delete(
        &format!("/api/v1/users/{}/roles/{role}", employee.user_id),
        Some(&root.token),
    )
    .await
    .assert_error(StatusCode::NOT_FOUND, "RESOURCE_NOT_FOUND");
}

/// Rules 3, 4 and 6 of the delegation guard, at the HTTP boundary.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn assignment_refuses_the_owner_the_self_target_and_a_mismatched_envelope() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let contact = create_client_user(&app, &root.token, "contact@acme.test", None).await;
    let internal_role = create_role(
        &app,
        &root.token,
        "reader",
        "INTERNAL",
        &[("projects.read", "GLOBAL")],
    )
    .await;

    // Rule 4 — no authorisation operation may target the system owner.
    app.post(
        &format!("/api/v1/users/{}/roles", root.user_id),
        Some(&root.token),
        json!({"role_id": internal_role}),
    )
    .await
    .assert_error(StatusCode::FORBIDDEN, "ROOT_PROTECTED");

    // Rule 6 — an INTERNAL role can never land on an external principal, and the
    // refusal happens before any grant is examined.
    app.post(
        &format!("/api/v1/users/{}/roles", contact.user_id),
        Some(&root.token),
        json!({"role_id": internal_role}),
    )
    .await
    .assert_error(StatusCode::FORBIDDEN, "DELEGATION_DENIED");
    assert_eq!(
        assignment_count(&app, contact.user_id, internal_role).await,
        0
    );

    // Rule 3 — nobody changes their own privileges, whatever they hold.
    let admin = create_employee(&app, &root.token, "admin@roleblank.test", None).await;
    let assigner = create_role(
        &app,
        &root.token,
        "assigner",
        "INTERNAL",
        &[("iam.roles.assign", "GLOBAL"), ("iam.roles.read", "GLOBAL")],
    )
    .await;
    app.post(
        &format!("/api/v1/users/{}/roles", admin.user_id),
        Some(&root.token),
        json!({"role_id": assigner}),
    )
    .await
    .assert_status(StatusCode::CREATED);
    enrol_mfa(&app, &admin.token).await;

    app.post(
        &format!("/api/v1/users/{}/roles", admin.user_id),
        Some(&admin.token),
        json!({"role_id": internal_role}),
    )
    .await
    .assert_error(StatusCode::FORBIDDEN, "DELEGATION_DENIED");
}

/// The classic escalation hole: an administrator with `iam.roles.assign` but
/// without `settings.security.write` assigns a role that *contains* it. Validating
/// a role permission by permission is what closes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_role_cannot_be_used_to_smuggle_a_permission_the_assigner_lacks() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let admin = create_employee(&app, &root.token, "admin@roleblank.test", None).await;
    let victim = create_employee(&app, &root.token, "victim@roleblank.test", None).await;

    let assigner = create_role(
        &app,
        &root.token,
        "assigner",
        "INTERNAL",
        &[("iam.roles.assign", "GLOBAL"), ("iam.roles.read", "GLOBAL")],
    )
    .await;
    let powerful = create_role(
        &app,
        &root.token,
        "powerful",
        "INTERNAL",
        &[("settings.security.write", "GLOBAL")],
    )
    .await;

    app.post(
        &format!("/api/v1/users/{}/roles", admin.user_id),
        Some(&root.token),
        json!({"role_id": assigner}),
    )
    .await
    .assert_status(StatusCode::CREATED);
    enrol_mfa(&app, &admin.token).await;

    app.post(
        &format!("/api/v1/users/{}/roles", victim.user_id),
        Some(&admin.token),
        json!({"role_id": powerful}),
    )
    .await
    .assert_error(StatusCode::FORBIDDEN, "DELEGATION_DENIED");
    assert_eq!(assignment_count(&app, victim.user_id, powerful).await, 0);

    // ...and the refused attempt is recorded against the subject.
    assert!(
        audit_count_for(&app, "AUTHORIZATION.DENIED", victim.user_id).await >= 1,
        "a probe against the delegation guard must leave a trace"
    );
}

/// `iam.roles.assign` is dangerous, so holding it is not enough — the session must
/// also have proved a second factor recently.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn assignment_demands_a_recent_second_factor() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let admin = create_employee(&app, &root.token, "admin@roleblank.test", None).await;
    let victim = create_employee(&app, &root.token, "victim@roleblank.test", None).await;
    let assigner = create_role(
        &app,
        &root.token,
        "assigner",
        "INTERNAL",
        &[
            ("iam.roles.assign", "GLOBAL"),
            ("iam.roles.read", "GLOBAL"),
            ("projects.read", "GLOBAL"),
        ],
    )
    .await;
    let reader = create_role(
        &app,
        &root.token,
        "reader",
        "INTERNAL",
        &[("projects.read", "GLOBAL")],
    )
    .await;

    app.post(
        &format!("/api/v1/users/{}/roles", admin.user_id),
        Some(&root.token),
        json!({"role_id": assigner}),
    )
    .await
    .assert_status(StatusCode::CREATED);

    app.post(
        &format!("/api/v1/users/{}/roles", victim.user_id),
        Some(&admin.token),
        json!({"role_id": reader}),
    )
    .await
    .assert_error(StatusCode::FORBIDDEN, "STEP_UP_REQUIRED");

    enrol_mfa(&app, &admin.token).await;
    app.post(
        &format!("/api/v1/users/{}/roles", victim.user_id),
        Some(&admin.token),
        json!({"role_id": reader}),
    )
    .await
    .assert_status(StatusCode::CREATED);
}

/// An archived account that quietly accumulates grants is what a dormant backdoor
/// looks like, so authority may be removed from one but never added.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_archived_account_cannot_receive_authority() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let leaver = create_employee(&app, &root.token, "leaver@roleblank.test", None).await;
    let role = create_role(
        &app,
        &root.token,
        "reader",
        "INTERNAL",
        &[("projects.read", "GLOBAL")],
    )
    .await;

    app.post(
        &format!("/api/v1/users/{}/archive", leaver.user_id),
        Some(&root.token),
        json!({"version": 1}),
    )
    .await
    .assert_status(StatusCode::OK);

    app.post(
        &format!("/api/v1/users/{}/roles", leaver.user_id),
        Some(&root.token),
        json!({"role_id": role}),
    )
    .await
    .assert_error(StatusCode::CONFLICT, "SUBJECT_ARCHIVED");

    app.post(
        &format!("/api/v1/users/{}/permission-overrides", leaver.user_id),
        Some(&root.token),
        json!({"permission_code": "audit.read", "effect": "ALLOW", "scope": "GLOBAL"}),
    )
    .await
    .assert_error(StatusCode::CONFLICT, "SUBJECT_ARCHIVED");
}

// ===========================================================================
// Effective permissions
// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn effective_permissions_report_what_the_evaluator_will_actually_see() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let employee = create_employee(&app, &root.token, "dev@roleblank.test", None).await;

    let effective = app
        .get(
            &format!("/api/v1/users/{}/permissions", employee.user_id),
            Some(&root.token),
        )
        .await;
    effective.assert_status(StatusCode::OK).assert_no_secrets();
    assert_eq!(effective.id_at("/user_id"), employee.user_id);
    assert_eq!(effective.str_at("/principal_type"), "INTERNAL");
    assert_eq!(effective.json()["is_root"], json!(false));

    let items = effective.json()["items"].as_array().expect("items").clone();
    let find = |code: &str| {
        items
            .iter()
            .find(|i| i["permission_code"] == json!(code))
            .cloned()
    };
    assert_eq!(
        find("iam.users.read").expect("held")["scopes"],
        json!(["SELF"])
    );
    assert_eq!(
        find("projects.read").expect("held")["scopes"],
        json!(["ASSIGNED"])
    );
    assert!(
        find("audit.read").is_none(),
        "a permission the subject does not hold must not be listed"
    );

    // The owner's report is global by construction, not by enumeration of grants.
    let owner = app
        .get(
            &format!("/api/v1/users/{}/permissions", root.user_id),
            Some(&root.token),
        )
        .await;
    owner.assert_status(StatusCode::OK);
    assert_eq!(owner.json()["is_root"], json!(true));

    // An external principal is confined to the two portal codes however it is
    // granted, and the capability list must say so.
    let contact = create_client_user(&app, &root.token, "contact@acme.test", None).await;
    let client_caps = app
        .get(
            &format!("/api/v1/users/{}/permissions", contact.user_id),
            Some(&root.token),
        )
        .await;
    let codes: Vec<&str> = client_caps.json()["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|i| i["permission_code"].as_str().expect("a code"))
        .collect();
    assert_eq!(
        codes,
        vec!["client.portal.projects.read", "client.portal.tasks.read"]
    );
}

// ===========================================================================
// Per-user overrides
// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_allow_override_widens_authority_and_deleting_it_takes_it_back() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let ops = create_department(&app, &root.token, "ops", "Operations").await;
    let sales = create_department(&app, &root.token, "sales", "Sales").await;
    let employee = create_employee(&app, &root.token, "dev@roleblank.test", Some(ops)).await;

    // Before: `departments.read@DEPARTMENT` reaches exactly the one they are in.
    let before = app.get("/api/v1/departments", Some(&employee.token)).await;
    before.assert_status(StatusCode::OK);
    assert_eq!(ids_in(&before), vec![ops]);

    let created = app
        .post(
            &format!("/api/v1/users/{}/permission-overrides", employee.user_id),
            Some(&root.token),
            json!({
                "permission_code": "departments.read",
                "effect": "ALLOW",
                "scope": "GLOBAL",
                "reason": "covering for the ops lead",
            }),
        )
        .await;
    created
        .assert_status(StatusCode::CREATED)
        .assert_no_secrets();
    let override_id = created.id_at("/id");
    assert_eq!(created.str_at("/effect"), "ALLOW");
    assert_eq!(created.str_at("/scope"), "GLOBAL");
    assert_eq!(
        audit_count_for(&app, "PERMISSION.OVERRIDE_CREATED", employee.user_id).await,
        1
    );

    // After: a GLOBAL grant reaches the collection, and the department they are not
    // a member of comes into view.
    let after = app.get("/api/v1/departments", Some(&employee.token)).await;
    after.assert_status(StatusCode::OK);
    let mut widened = ids_in(&after);
    widened.sort();
    let mut expected = vec![ops, sales];
    expected.sort();
    assert_eq!(widened, expected);

    let listed = app
        .get(
            &format!("/api/v1/users/{}/permission-overrides", employee.user_id),
            Some(&root.token),
        )
        .await;
    listed.assert_status(StatusCode::OK);
    assert_eq!(listed.json()["items"].as_array().expect("items").len(), 1);

    app.delete(
        &format!(
            "/api/v1/users/{}/permission-overrides/{override_id}",
            employee.user_id
        ),
        Some(&root.token),
    )
    .await
    .assert_status(StatusCode::NO_CONTENT);
    assert_eq!(
        audit_count_for(&app, "PERMISSION.OVERRIDE_REMOVED", employee.user_id).await,
        1
    );

    let reverted = app.get("/api/v1/departments", Some(&employee.token)).await;
    reverted.assert_status(StatusCode::OK);
    assert_eq!(
        ids_in(&reverted),
        vec![ops],
        "removing the override must put the narrower scope back"
    );

    app.delete(
        &format!(
            "/api/v1/users/{}/permission-overrides/{override_id}",
            employee.user_id
        ),
        Some(&root.token),
    )
    .await
    .assert_error(StatusCode::NOT_FOUND, "RESOURCE_NOT_FOUND");
}

/// A DENY is evaluated before the allow set and is never consulted afterwards, so
/// "add another role to escape it" is structurally impossible.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_deny_override_removes_authority_that_a_role_still_grants() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let employee = create_employee(&app, &root.token, "dev@roleblank.test", None).await;
    let project = create_project(&app, &root.token, "rollout", root.user_id, None).await;
    let task = create_task(&app, &root.token, project, "Ship it").await;
    app.post(
        &format!("/api/v1/tasks/{task}/assignees"),
        Some(&root.token),
        json!({"user_id": employee.user_id}),
    )
    .await
    .assert_status(StatusCode::NO_CONTENT);

    app.get(&format!("/api/v1/tasks/{task}"), Some(&employee.token))
        .await
        .assert_status(StatusCode::OK);

    app.post(
        &format!("/api/v1/users/{}/permission-overrides", employee.user_id),
        Some(&root.token),
        json!({"permission_code": "tasks.read", "effect": "DENY", "scope": "GLOBAL"}),
    )
    .await
    .assert_status(StatusCode::CREATED);

    app.get(&format!("/api/v1/tasks/{task}"), Some(&employee.token))
        .await
        .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");
    app.get("/api/v1/tasks", Some(&employee.token))
        .await
        .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");

    // Granting the permission again at any scope does not overturn it.
    app.post(
        &format!("/api/v1/users/{}/permission-overrides", employee.user_id),
        Some(&root.token),
        json!({"permission_code": "tasks.read", "effect": "ALLOW", "scope": "GLOBAL"}),
    )
    .await
    .assert_status(StatusCode::CREATED);
    app.get(&format!("/api/v1/tasks/{task}"), Some(&employee.token))
        .await
        .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");
}

/// A `RESOURCE` scope names one object, and the fields that name it are required
/// with it and forbidden without it — a non-RESOURCE scope carrying an object is
/// incoherent and is refused rather than silently narrowed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_override_scope_must_be_coherent_and_an_expiry_must_be_in_the_future() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let employee = create_employee(&app, &root.token, "dev@roleblank.test", None).await;
    let project = create_project(&app, &root.token, "rollout", root.user_id, None).await;
    let path = format!("/api/v1/users/{}/permission-overrides", employee.user_id);

    let ok = app
        .post(
            &path,
            Some(&root.token),
            json!({
                "permission_code": "projects.read",
                "effect": "ALLOW",
                "scope": "RESOURCE",
                "resource_type": "PROJECT",
                "resource_id": project,
                "expires_at": "2099-01-01T00:00:00Z",
            }),
        )
        .await;
    ok.assert_status(StatusCode::CREATED);
    assert_eq!(ok.str_at("/resource_type"), "PROJECT");

    // The named object is reachable and nothing else is.
    app.get(
        &format!("/api/v1/projects/{project}"),
        Some(&employee.token),
    )
    .await
    .assert_status(StatusCode::OK);

    for body in [
        json!({"permission_code": "projects.read", "effect": "ALLOW", "scope": "RESOURCE"}),
        json!({"permission_code": "projects.read", "effect": "ALLOW", "scope": "RESOURCE", "resource_type": "PROJECT"}),
        json!({"permission_code": "projects.read", "effect": "ALLOW", "scope": "GLOBAL", "resource_id": project}),
        json!({"permission_code": "projects.read", "effect": "ALLOW", "scope": "RESOURCE", "resource_type": "ROLE", "resource_id": project}),
        json!({"permission_code": "projects.read", "effect": "MAYBE", "scope": "GLOBAL"}),
        json!({"permission_code": "projects.read", "effect": "ALLOW", "scope": "EVERYTHING"}),
        json!({"permission_code": "projects.read", "effect": "ALLOW", "scope": "GLOBAL", "expires_at": "2000-01-01T00:00:00Z"}),
        json!({"permission_code": "projects.read", "effect": "ALLOW", "scope": "GLOBAL", "expires_at": "tomorrow"}),
    ] {
        app.post(&path, Some(&root.token), body)
            .await
            .assert_error(StatusCode::BAD_REQUEST, "VALIDATION_FAILED");
    }

    app.post(
        &path,
        Some(&root.token),
        json!({"permission_code": "not.a.permission", "effect": "ALLOW", "scope": "GLOBAL"}),
    )
    .await
    .assert_error(StatusCode::BAD_REQUEST, "UNKNOWN_PERMISSION");

    // The subject comes from the path, never from the body.
    app.post(
        &path,
        Some(&root.token),
        json!({"permission_code": "projects.read", "effect": "ALLOW", "scope": "GLOBAL", "user_id": root.user_id}),
    )
    .await
    .assert_error(StatusCode::BAD_REQUEST, "BAD_REQUEST");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn overrides_never_target_the_owner_and_reading_them_is_not_delegating_them() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let auditor = create_employee(&app, &root.token, "auditor@roleblank.test", None).await;

    app.post(
        &format!("/api/v1/users/{}/permission-overrides", root.user_id),
        Some(&root.token),
        json!({"permission_code": "audit.read", "effect": "DENY", "scope": "GLOBAL"}),
    )
    .await
    .assert_error(StatusCode::FORBIDDEN, "ROOT_PROTECTED");

    // Seeing which exceptions exist is an inspection, not a grant: it needs
    // `iam.permissions.read`, not `iam.permissions.delegate`.
    let inspector = create_role(
        &app,
        &root.token,
        "inspector",
        "INTERNAL",
        &[("iam.permissions.read", "GLOBAL")],
    )
    .await;
    app.post(
        &format!("/api/v1/users/{}/roles", auditor.user_id),
        Some(&root.token),
        json!({"role_id": inspector}),
    )
    .await
    .assert_status(StatusCode::CREATED);

    app.get(
        &format!("/api/v1/users/{}/permission-overrides", auditor.user_id),
        Some(&auditor.token),
    )
    .await
    .assert_status(StatusCode::OK);

    // ...but it is not the authority to create one, even with a second factor.
    enrol_mfa(&app, &auditor.token).await;
    app.post(
        &format!("/api/v1/users/{}/permission-overrides", auditor.user_id),
        Some(&auditor.token),
        json!({"permission_code": "audit.read", "effect": "ALLOW", "scope": "GLOBAL"}),
    )
    .await
    .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");
}
