//! The adversarial authorisation matrix: every actor against every resource.
//!
//! Broken object-level authorisation is not a bug you find by reading one handler.
//! It is found by asking the same question of every (actor, object, operation)
//! triple and noticing the one cell whose answer is wrong. That is what this file
//! is: a table, driven through the real router, where **adding a case is one call**.
//!
//! Two conventions the expectations follow, both from
//! `docs/backend/04-authorization.md` §10:
//!
//! * an INTERNAL principal that lacks authority over an object that exists gets
//!   `403 AUTHORIZATION_DENIED` — existence disclosure inside the company is
//!   acceptable and a blanket `404` would make operational support impossible;
//! * an external CLIENT principal gets `404 RESOURCE_NOT_FOUND` for everything it
//!   may not see, because a `403` would confirm the object exists.
//!
//! The refusal cells and every read cell live in the table. Mutations that are
//! *expected to succeed* are in a second test, ordered, so that the table stays
//! independent of execution order — and so that the refusals above cannot be
//! passing simply because the endpoints refuse everybody.

use axum::http::StatusCode;
use serde_json::{json, Value};

use crate::fixtures::{World, ROLE_EMPLOYEE};

/// One cell of the matrix.
struct Cell {
    actor: &'static str,
    method: &'static str,
    path: String,
    body: Option<Value>,
    status: StatusCode,
    /// `None` where only the status is contractually fixed (a success).
    code: Option<&'static str>,
}

/// A read cell: actor, path, expected status, expected code.
fn read(actor: &'static str, path: String, status: StatusCode, code: Option<&'static str>) -> Cell {
    Cell {
        actor,
        method: "GET",
        path,
        body: None,
        status,
        code,
    }
}

/// A write cell: actor, method, path, body, expected status, expected code.
fn write(
    actor: &'static str,
    method: &'static str,
    path: String,
    body: Value,
    status: StatusCode,
    code: Option<&'static str>,
) -> Cell {
    Cell {
        actor,
        method,
        path,
        body: Some(body),
        status,
        code,
    }
}

const DENIED: Option<&str> = Some("AUTHORIZATION_DENIED");
const HIDDEN: Option<&str> = Some("RESOURCE_NOT_FOUND");
const ANON: Option<&str> = Some("AUTHENTICATION_FAILED");
const ROOT_GUARD: Option<&str> = Some("ROOT_PROTECTED");

const OK: StatusCode = StatusCode::OK;
const UNAUTHORIZED: StatusCode = StatusCode::UNAUTHORIZED;
const FORBIDDEN: StatusCode = StatusCode::FORBIDDEN;
const NOT_FOUND: StatusCode = StatusCode::NOT_FOUND;

fn token_for<'a>(w: &'a World, actor: &str) -> Option<&'a str> {
    match actor {
        "anonymous" => None,
        "client_a" => w.client_a.bearer(),
        "client_b" => w.client_b.bearer(),
        "employee" => w.employee.bearer(),
        "manager" => w.manager.bearer(),
        "admin" => w.admin.bearer(),
        "root" => w.root.bearer(),
        other => panic!("unknown actor `{other}` in the matrix"),
    }
}

// ===========================================================================
// The table
// ===========================================================================

#[tokio::test]
async fn the_authorisation_matrix_holds_for_every_actor_and_object() {
    let w = World::build().await;

    let me = w.employee.id;
    let colleague = w.other_employee;
    let root = w.root.id;
    let ca = w.client_account_a;
    let cb = w.client_account_b;
    let internal = w.internal_project;
    let shared_a = w.project_shared_a;
    let shared_b = w.project_shared_b;
    let hidden = w.hidden_task;
    let visible = w.visible_task;
    let dept = w.department;

    let cells: Vec<Cell> = vec![
        // ---- anonymous: the whole authenticated surface is one answer ---------
        read("anonymous", "/api/v1/auth/me".into(), UNAUTHORIZED, ANON),
        read("anonymous", "/api/v1/users".into(), UNAUTHORIZED, ANON),
        read(
            "anonymous",
            format!("/api/v1/users/{me}"),
            UNAUTHORIZED,
            ANON,
        ),
        read(
            "anonymous",
            format!("/api/v1/users/{root}"),
            UNAUTHORIZED,
            ANON,
        ),
        read("anonymous", "/api/v1/projects".into(), UNAUTHORIZED, ANON),
        read(
            "anonymous",
            format!("/api/v1/projects/{internal}"),
            UNAUTHORIZED,
            ANON,
        ),
        read(
            "anonymous",
            format!("/api/v1/tasks/{visible}"),
            UNAUTHORIZED,
            ANON,
        ),
        read("anonymous", "/api/v1/roles".into(), UNAUTHORIZED, ANON),
        read(
            "anonymous",
            "/api/v1/permissions".into(),
            UNAUTHORIZED,
            ANON,
        ),
        read("anonymous", "/api/v1/settings".into(), UNAUTHORIZED, ANON),
        read(
            "anonymous",
            "/api/v1/audit/events".into(),
            UNAUTHORIZED,
            ANON,
        ),
        read(
            "anonymous",
            format!("/api/v1/clients/{ca}"),
            UNAUTHORIZED,
            ANON,
        ),
        read(
            "anonymous",
            "/api/v1/client-portal/projects".into(),
            UNAUTHORIZED,
            ANON,
        ),
        read(
            "anonymous",
            "/api/v1/system/info".into(),
            UNAUTHORIZED,
            ANON,
        ),
        write(
            "anonymous",
            "POST",
            "/api/v1/projects".into(),
            json!({"code": "anon", "name": "Anon", "manager_user_id": me}),
            UNAUTHORIZED,
            ANON,
        ),
        write(
            "anonymous",
            "POST",
            format!("/api/v1/users/{colleague}/roles"),
            json!({"role_id": ROLE_EMPLOYEE}),
            UNAUTHORIZED,
            ANON,
        ),
        // ---- CLIENT A: everything internal is invisible -----------------------
        read("client_a", "/api/v1/users".into(), NOT_FOUND, HIDDEN),
        read("client_a", format!("/api/v1/users/{me}"), NOT_FOUND, HIDDEN),
        read(
            "client_a",
            format!("/api/v1/users/{root}"),
            NOT_FOUND,
            HIDDEN,
        ),
        read(
            "client_a",
            format!("/api/v1/users/{}", w.client_a.id),
            NOT_FOUND,
            HIDDEN,
        ),
        read("client_a", "/api/v1/projects".into(), NOT_FOUND, HIDDEN),
        read(
            "client_a",
            format!("/api/v1/projects/{shared_a}"),
            NOT_FOUND,
            HIDDEN,
        ),
        read(
            "client_a",
            format!("/api/v1/tasks/{visible}"),
            NOT_FOUND,
            HIDDEN,
        ),
        read("client_a", "/api/v1/roles".into(), NOT_FOUND, HIDDEN),
        read("client_a", "/api/v1/permissions".into(), NOT_FOUND, HIDDEN),
        read("client_a", "/api/v1/settings".into(), NOT_FOUND, HIDDEN),
        read("client_a", "/api/v1/audit/events".into(), NOT_FOUND, HIDDEN),
        read(
            "client_a",
            format!("/api/v1/clients/{ca}"),
            NOT_FOUND,
            HIDDEN,
        ),
        read(
            "client_a",
            format!("/api/v1/departments/{dept}"),
            NOT_FOUND,
            HIDDEN,
        ),
        // ...and the portal shows exactly its own world.
        read(
            "client_a",
            "/api/v1/client-portal/projects".into(),
            OK,
            None,
        ),
        read(
            "client_a",
            format!("/api/v1/client-portal/projects/{shared_a}"),
            OK,
            None,
        ),
        read(
            "client_a",
            format!("/api/v1/client-portal/projects/{shared_b}"),
            NOT_FOUND,
            HIDDEN,
        ),
        read(
            "client_a",
            format!("/api/v1/client-portal/projects/{internal}"),
            NOT_FOUND,
            HIDDEN,
        ),
        read(
            "client_a",
            format!("/api/v1/client-portal/tasks/{visible}"),
            OK,
            None,
        ),
        read(
            "client_a",
            format!("/api/v1/client-portal/tasks/{hidden}"),
            NOT_FOUND,
            HIDDEN,
        ),
        read(
            "client_a",
            format!("/api/v1/client-portal/tasks/{}", w.task_of_b),
            NOT_FOUND,
            HIDDEN,
        ),
        read("client_a", "/api/v1/system/info".into(), OK, None),
        read("client_a", "/api/v1/auth/me".into(), OK, None),
        write(
            "client_a",
            "POST",
            "/api/v1/projects".into(),
            json!({"code": "escape", "name": "Escape", "manager_user_id": me}),
            NOT_FOUND,
            HIDDEN,
        ),
        write(
            "client_a",
            "PATCH",
            format!("/api/v1/tasks/{hidden}"),
            json!({"version": 1, "client_visible": true}),
            NOT_FOUND,
            HIDDEN,
        ),
        write(
            "client_a",
            "POST",
            format!("/api/v1/users/{}/roles", w.client_a.id),
            json!({"role_id": ROLE_EMPLOYEE}),
            NOT_FOUND,
            HIDDEN,
        ),
        // ---- CLIENT B: the mirror image ---------------------------------------
        read(
            "client_b",
            format!("/api/v1/client-portal/projects/{shared_b}"),
            OK,
            None,
        ),
        read(
            "client_b",
            format!("/api/v1/client-portal/projects/{shared_a}"),
            NOT_FOUND,
            HIDDEN,
        ),
        read(
            "client_b",
            format!("/api/v1/client-portal/tasks/{visible}"),
            NOT_FOUND,
            HIDDEN,
        ),
        read(
            "client_b",
            format!("/api/v1/clients/{cb}"),
            NOT_FOUND,
            HIDDEN,
        ),
        // ---- employee: `employee` role, member of nothing ---------------------
        read("employee", format!("/api/v1/users/{me}"), OK, None),
        read(
            "employee",
            format!("/api/v1/users/{colleague}"),
            FORBIDDEN,
            DENIED,
        ),
        read(
            "employee",
            format!("/api/v1/users/{root}"),
            FORBIDDEN,
            DENIED,
        ),
        // A SELF grant turns the collection into a filtered query rather than a
        // refusal — and the filter is a WHERE clause, not a loop in Rust.
        read("employee", "/api/v1/users".into(), OK, None),
        read("employee", "/api/v1/projects".into(), OK, None),
        read(
            "employee",
            format!("/api/v1/projects/{internal}"),
            FORBIDDEN,
            DENIED,
        ),
        read(
            "employee",
            format!("/api/v1/projects/{shared_a}"),
            FORBIDDEN,
            DENIED,
        ),
        read("employee", "/api/v1/tasks".into(), OK, None),
        read(
            "employee",
            format!("/api/v1/tasks/{visible}"),
            FORBIDDEN,
            DENIED,
        ),
        read("employee", "/api/v1/roles".into(), FORBIDDEN, DENIED),
        read("employee", "/api/v1/permissions".into(), FORBIDDEN, DENIED),
        read("employee", "/api/v1/departments".into(), FORBIDDEN, DENIED),
        read(
            "employee",
            format!("/api/v1/departments/{dept}"),
            FORBIDDEN,
            DENIED,
        ),
        read("employee", "/api/v1/clients".into(), FORBIDDEN, DENIED),
        read(
            "employee",
            format!("/api/v1/clients/{ca}"),
            FORBIDDEN,
            DENIED,
        ),
        read("employee", "/api/v1/settings".into(), FORBIDDEN, DENIED),
        read(
            "employee",
            "/api/v1/feature-flags".into(),
            FORBIDDEN,
            DENIED,
        ),
        read("employee", "/api/v1/audit/events".into(), FORBIDDEN, DENIED),
        read("employee", "/api/v1/audit/verify".into(), FORBIDDEN, DENIED),
        read("employee", "/api/v1/invitations".into(), FORBIDDEN, DENIED),
        // An internal principal holds no portal permission: the envelope is a
        // ceiling, not a floor.
        read(
            "employee",
            "/api/v1/client-portal/projects".into(),
            FORBIDDEN,
            DENIED,
        ),
        read("employee", "/api/v1/system/info".into(), OK, None),
        read("employee", "/api/v1/auth/sessions".into(), OK, None),
        write(
            "employee",
            "POST",
            "/api/v1/projects".into(),
            json!({"code": "employee-made", "name": "Employee made", "manager_user_id": me}),
            FORBIDDEN,
            DENIED,
        ),
        write(
            "employee",
            "PATCH",
            format!("/api/v1/projects/{internal}"),
            json!({"version": 1, "name": "Renamed"}),
            FORBIDDEN,
            DENIED,
        ),
        write(
            "employee",
            "POST",
            format!("/api/v1/projects/{internal}/archive"),
            json!({"version": 1}),
            FORBIDDEN,
            DENIED,
        ),
        write(
            "employee",
            "POST",
            "/api/v1/tasks".into(),
            json!({"project_id": internal, "title": "Injected"}),
            FORBIDDEN,
            DENIED,
        ),
        write(
            "employee",
            "POST",
            format!("/api/v1/tasks/{visible}/assignees"),
            json!({"user_id": me}),
            FORBIDDEN,
            DENIED,
        ),
        write(
            "employee",
            "POST",
            format!("/api/v1/users/{colleague}/roles"),
            json!({"role_id": ROLE_EMPLOYEE}),
            FORBIDDEN,
            DENIED,
        ),
        write(
            "employee",
            "POST",
            format!("/api/v1/users/{colleague}/permission-overrides"),
            json!({"permission_code": "audit.read", "effect": "ALLOW", "scope": "GLOBAL"}),
            FORBIDDEN,
            DENIED,
        ),
        write(
            "employee",
            "PUT",
            "/api/v1/settings/registration.mode".into(),
            json!({"version": 1, "value": "CLIENT_SELF_REGISTRATION"}),
            FORBIDDEN,
            DENIED,
        ),
        write(
            "employee",
            "POST",
            "/api/v1/invitations".into(),
            json!({"email": "friend@fixture.test", "display_name": "Friend",
                     "principal_type": "INTERNAL", "role_ids": []}),
            FORBIDDEN,
            DENIED,
        ),
        write(
            "employee",
            "POST",
            format!("/api/v1/users/{colleague}/suspend"),
            json!({"version": 1}),
            FORBIDDEN,
            DENIED,
        ),
        // ---- manager: same role, but a real member of a project and a department
        read("manager", format!("/api/v1/projects/{internal}"), OK, None),
        read(
            "manager",
            format!("/api/v1/projects/{shared_a}"),
            FORBIDDEN,
            DENIED,
        ),
        read("manager", "/api/v1/departments".into(), OK, None),
        read("manager", format!("/api/v1/departments/{dept}"), OK, None),
        // Membership of the project is not assignment to its tasks, and treating it
        // as one would widen every `tasks.*@ASSIGNED` grant to the whole project.
        read(
            "manager",
            format!("/api/v1/tasks/{}", w.internal_task),
            FORBIDDEN,
            DENIED,
        ),
        read(
            "manager",
            format!("/api/v1/users/{colleague}"),
            FORBIDDEN,
            DENIED,
        ),
        write(
            "manager",
            "PATCH",
            format!("/api/v1/projects/{internal}"),
            json!({"version": 1, "name": "Renamed by a member"}),
            FORBIDDEN,
            DENIED,
        ),
        write(
            "manager",
            "POST",
            format!("/api/v1/projects/{internal}/archive"),
            json!({"version": 1}),
            FORBIDDEN,
            DENIED,
        ),
        // Sharing across the external boundary is authorised *before* the second
        // factor is demanded, so an unauthorised member is told it lacks the
        // permission rather than which control it would have to defeat next.
        write(
            "manager",
            "POST",
            format!("/api/v1/projects/{internal}/clients"),
            json!({"client_account_id": ca}),
            FORBIDDEN,
            DENIED,
        ),
        // ---- administrator: broad, and still subordinate ----------------------
        read("admin", "/api/v1/users".into(), OK, None),
        read("admin", format!("/api/v1/users/{root}"), OK, None),
        read("admin", format!("/api/v1/users/{colleague}"), OK, None),
        read(
            "admin",
            format!("/api/v1/users/{colleague}/roles"),
            OK,
            None,
        ),
        read(
            "admin",
            format!("/api/v1/users/{colleague}/permissions"),
            OK,
            None,
        ),
        read("admin", format!("/api/v1/projects/{internal}"), OK, None),
        read("admin", format!("/api/v1/projects/{shared_b}"), OK, None),
        read("admin", format!("/api/v1/tasks/{hidden}"), OK, None),
        read("admin", "/api/v1/roles".into(), OK, None),
        read("admin", "/api/v1/permissions".into(), OK, None),
        read("admin", "/api/v1/settings".into(), OK, None),
        read("admin", "/api/v1/audit/events".into(), OK, None),
        read("admin", "/api/v1/audit/verify".into(), OK, None),
        read("admin", format!("/api/v1/clients/{ca}"), OK, None),
        read(
            "admin",
            "/api/v1/client-portal/projects".into(),
            FORBIDDEN,
            DENIED,
        ),
        write(
            "admin",
            "PATCH",
            format!("/api/v1/users/{root}"),
            json!({"version": 1, "display_name": "Owned"}),
            FORBIDDEN,
            ROOT_GUARD,
        ),
        write(
            "admin",
            "POST",
            format!("/api/v1/users/{root}/suspend"),
            json!({"version": 1}),
            FORBIDDEN,
            ROOT_GUARD,
        ),
        write(
            "admin",
            "POST",
            format!("/api/v1/users/{root}/archive"),
            json!({"version": 1}),
            FORBIDDEN,
            ROOT_GUARD,
        ),
        write(
            "admin",
            "POST",
            format!("/api/v1/users/{root}/roles"),
            json!({"role_id": ROLE_EMPLOYEE}),
            FORBIDDEN,
            ROOT_GUARD,
        ),
        write(
            "admin",
            "POST",
            format!("/api/v1/users/{root}/permission-overrides"),
            json!({"permission_code": "audit.read", "effect": "DENY", "scope": "GLOBAL"}),
            FORBIDDEN,
            ROOT_GUARD,
        ),
        // The built-in administrator deliberately lacks `settings.security.write`,
        // so a security-sensitive setting is out of reach however broad it is.
        write(
            "admin",
            "PUT",
            "/api/v1/settings/registration.mode".into(),
            json!({"version": 1, "value": "CLIENT_SELF_REGISTRATION"}),
            FORBIDDEN,
            DENIED,
        ),
        write(
            "admin",
            "PUT",
            "/api/v1/feature-flags/client_portal".into(),
            json!({"version": 1, "enabled": false}),
            FORBIDDEN,
            DENIED,
        ),
        // ---- ROOT: the one bypass, and what it does not bypass ----------------
        read("root", "/api/v1/users".into(), OK, None),
        read("root", format!("/api/v1/users/{colleague}"), OK, None),
        read("root", format!("/api/v1/projects/{internal}"), OK, None),
        read("root", format!("/api/v1/tasks/{hidden}"), OK, None),
        read("root", "/api/v1/roles".into(), OK, None),
        read("root", "/api/v1/settings".into(), OK, None),
        read("root", "/api/v1/audit/events".into(), OK, None),
        read("root", "/api/v1/audit/verify".into(), OK, None),
        // Ownership bypasses permission *evaluation* and nothing else. The portal
        // query is keyed on the caller's own ACTIVE client memberships, of which
        // the owner has none, so the owner is admitted to the endpoint and sees an
        // empty world — layer 4 does not consult the evaluator's answer. The
        // emptiness is asserted below rather than merely implied by the status.
        read("root", "/api/v1/client-portal/projects".into(), OK, None),
        write(
            "root",
            "PATCH",
            format!("/api/v1/users/{root}"),
            json!({"version": 1, "display_name": "Owner"}),
            FORBIDDEN,
            ROOT_GUARD,
        ),
        write(
            "root",
            "POST",
            format!("/api/v1/users/{root}/permission-overrides"),
            json!({"permission_code": "audit.read", "effect": "ALLOW", "scope": "GLOBAL"}),
            FORBIDDEN,
            ROOT_GUARD,
        ),
    ];

    let mut failures: Vec<String> = Vec::new();
    for cell in &cells {
        let token = token_for(&w, cell.actor);
        let response = match (cell.method, cell.body.clone()) {
            ("GET", _) => w.app.get(&cell.path, token).await,
            ("POST", Some(body)) => w.app.post(&cell.path, token, body).await,
            ("PATCH", Some(body)) => w.app.patch(&cell.path, token, body).await,
            ("PUT", Some(body)) => w.app.put(&cell.path, token, body).await,
            ("DELETE", _) => w.app.delete(&cell.path, token).await,
            (other, _) => panic!("unhandled method {other}"),
        };

        response.assert_no_secrets();
        if response.status != cell.status {
            failures.push(format!(
                "  {} {} {} -> {} (expected {})  body: {}",
                cell.actor,
                cell.method,
                cell.path,
                response.status,
                cell.status,
                String::from_utf8_lossy(&response.raw)
            ));
            continue;
        }
        if let Some(expected) = cell.code {
            if response.error_code() != Some(expected) {
                failures.push(format!(
                    "  {} {} {} -> code {:?} (expected {expected})",
                    cell.actor,
                    cell.method,
                    cell.path,
                    response.error_code()
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} authorisation matrix cells are wrong:\n{}",
        failures.len(),
        cells.len(),
        failures.join("\n")
    );
}

// ===========================================================================
// The positive half
// ===========================================================================

/// The refusals above would all pass against an API that refuses everybody, so the
/// operations an authorised actor *must* be able to perform are walked here, in
/// order, on objects created by the test itself.
#[tokio::test]
async fn an_authorised_actor_can_still_do_its_job() {
    let w = World::build().await;

    // CREATE — the administrator holds `projects.create@GLOBAL`.
    let created = w
        .app
        .post(
            "/api/v1/projects",
            w.admin.bearer(),
            json!({"code": "admin-made", "name": "Admin made", "manager_user_id": w.employee.id}),
        )
        .await;
    created
        .assert_status(StatusCode::CREATED)
        .assert_no_secrets();
    let project = created.id_at("/id");
    let version = created.json()["version"].as_i64().expect("version");

    // UPDATE
    let updated = w
        .app
        .patch(
            &format!("/api/v1/projects/{project}"),
            w.admin.bearer(),
            json!({"version": version, "name": "Admin renamed"}),
        )
        .await;
    updated.assert_status(StatusCode::OK);
    let version = updated.json()["version"].as_i64().expect("version");

    // ASSIGN — a project member, and then a task assignee.
    w.app
        .post(
            &format!("/api/v1/projects/{project}/members"),
            w.admin.bearer(),
            json!({"user_id": w.employee.id}),
        )
        .await
        .assert_status(StatusCode::NO_CONTENT);

    let task = w
        .app
        .post(
            "/api/v1/tasks",
            w.admin.bearer(),
            json!({"project_id": project, "title": "Real work"}),
        )
        .await;
    task.assert_status(StatusCode::CREATED);
    let task_id = task.id_at("/id");
    // A task is never client-visible at creation, whatever anyone asked for.
    assert_eq!(task.json()["client_visible"], json!(false));

    w.app
        .post(
            &format!("/api/v1/tasks/{task_id}/assignees"),
            w.admin.bearer(),
            json!({"user_id": w.employee.id}),
        )
        .await
        .assert_status(StatusCode::NO_CONTENT);

    // The assignment is a real privilege change: the employee can now read the
    // task it could not read a moment ago.
    w.app
        .get(&format!("/api/v1/tasks/{task_id}"), w.employee.bearer())
        .await
        .assert_status(StatusCode::OK);

    // DELEGATE — the administrator holds `iam.permissions.delegate` in this world.
    w.app
        .post(
            &format!("/api/v1/users/{}/permission-overrides", w.other_employee),
            w.admin.bearer(),
            json!({"permission_code": "projects.read", "effect": "ALLOW", "scope": "GLOBAL"}),
        )
        .await
        .assert_status(StatusCode::CREATED);

    // ARCHIVE
    w.app
        .post(
            &format!("/api/v1/projects/{project}/archive"),
            w.admin.bearer(),
            json!({"version": version, "reason": "finished"}),
        )
        .await
        .assert_status(StatusCode::OK);

    // ROOT can write a security-sensitive setting; the administrator could not.
    let settings = w.app.get("/api/v1/settings", w.root.bearer()).await;
    settings.assert_status(StatusCode::OK);
    // The settings listing is a bare array, not a paged envelope.
    let setting_version = settings
        .json()
        .as_array()
        .expect("a settings array")
        .iter()
        .find(|s| s["key"] == json!("registration.mode"))
        .and_then(|s| s["version"].as_i64())
        .expect("the registration mode setting");
    w.app
        .put(
            "/api/v1/settings/registration.mode",
            w.root.bearer(),
            json!({"version": setting_version, "value": "DISABLED"}),
        )
        .await
        .assert_status(StatusCode::OK);
}
