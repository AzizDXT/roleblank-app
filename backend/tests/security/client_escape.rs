//! Adversary T2: a CLIENT principal with valid credentials trying every way out
//! of the client envelope.
//!
//! The governing rule for this whole file, from `docs/backend/04-authorization.md`
//! §10: **an external principal is refused with `404`, never `403`.** A `403`
//! confirms that the identifier names something real, which is exactly what an
//! enumerating client is trying to establish. Every assertion below therefore
//! checks the status *and* the stable code, because a `404` produced by a route
//! that does not exist and a `404` produced by a deliberate refusal must be
//! indistinguishable to the caller — and they are only indistinguishable if both
//! carry `RESOURCE_NOT_FOUND`.

use axum::http::StatusCode;
use serde_json::json;

use crate::common::TestResponse;
use crate::fixtures::{unknown_id, World};

/// The only acceptable answer to a client asking about something it may not see.
#[track_caller]
fn invisible(response: &TestResponse, what: &str) {
    assert_eq!(
        response.status,
        StatusCode::NOT_FOUND,
        "{what} answered {} instead of 404 — a client learned this object exists: {}",
        response.status,
        String::from_utf8_lossy(&response.raw)
    );
    assert_eq!(
        response.error_code(),
        Some("RESOURCE_NOT_FOUND"),
        "{what} used a distinguishable code: {}",
        String::from_utf8_lossy(&response.raw)
    );
    response.assert_no_secrets();
}

// ===========================================================================
// Cross-client reads
// ===========================================================================

/// TH-11. The single most important cell in the matrix.
#[tokio::test]
async fn a_client_cannot_read_another_clients_shared_project() {
    let w = World::build().await;

    // A's own project is visible — the control, so that a blanket 404 caused by a
    // broken fixture cannot masquerade as a passing security test.
    let mine = w
        .app
        .get(
            &format!("/api/v1/client-portal/projects/{}", w.project_shared_a),
            w.client_a.bearer(),
        )
        .await;
    mine.assert_status(StatusCode::OK);

    invisible(
        &w.app
            .get(
                &format!("/api/v1/client-portal/projects/{}", w.project_shared_b),
                w.client_a.bearer(),
            )
            .await,
        "client A reading client B's project",
    );
    invisible(
        &w.app
            .get(
                &format!("/api/v1/client-portal/projects/{}", w.project_shared_a),
                w.client_b.bearer(),
            )
            .await,
        "client B reading client A's project",
    );
    invisible(
        &w.app
            .get(
                &format!(
                    "/api/v1/client-portal/projects/{}/tasks",
                    w.project_shared_b
                ),
                w.client_a.bearer(),
            )
            .await,
        "client A listing the tasks of client B's project",
    );
    invisible(
        &w.app
            .get(
                &format!("/api/v1/client-portal/tasks/{}", w.task_of_b),
                w.client_a.bearer(),
            )
            .await,
        "client A reading a task belonging to client B",
    );
}

#[tokio::test]
async fn a_client_cannot_read_a_project_that_was_never_shared() {
    let w = World::build().await;

    invisible(
        &w.app
            .get(
                &format!("/api/v1/client-portal/projects/{}", w.internal_project),
                w.client_a.bearer(),
            )
            .await,
        "an unshared project through the portal",
    );
    invisible(
        &w.app
            .get(
                &format!(
                    "/api/v1/client-portal/projects/{}/tasks",
                    w.internal_project
                ),
                w.client_a.bearer(),
            )
            .await,
        "the tasks of an unshared project",
    );
    invisible(
        &w.app
            .get(
                &format!("/api/v1/client-portal/tasks/{}", w.internal_task),
                w.client_a.bearer(),
            )
            .await,
        "a task in an unshared project",
    );
}

/// Sharing a project does **not** share its tasks. `tasks.client_visible` is
/// per-task and defaults to false.
#[tokio::test]
async fn sharing_a_project_does_not_expose_its_hidden_tasks() {
    let w = World::build().await;

    // The project is shared and one task is deliberately visible, so this really
    // does exercise "same project, different flag" rather than "no access at all".
    let listed = w
        .app
        .get(
            &format!(
                "/api/v1/client-portal/projects/{}/tasks",
                w.project_shared_a
            ),
            w.client_a.bearer(),
        )
        .await;
    listed.assert_status(StatusCode::OK);
    let ids: Vec<String> = listed.json()["items"]
        .as_array()
        .expect("items")
        .iter()
        .filter_map(|item| item["id"].as_str().map(str::to_string))
        .collect();
    assert!(
        ids.contains(&w.visible_task.to_string()),
        "the client-visible task was not returned; the fixture is not exercising the flag"
    );
    assert!(
        !ids.contains(&w.hidden_task.to_string()),
        "a task with client_visible = false leaked into a client's task list"
    );

    invisible(
        &w.app
            .get(
                &format!("/api/v1/client-portal/tasks/{}", w.hidden_task),
                w.client_a.bearer(),
            )
            .await,
        "a hidden task in a shared project, fetched directly",
    );
}

/// Revocation takes effect on the next query, with no cache to invalidate.
#[tokio::test]
async fn revoking_a_share_or_a_membership_takes_effect_immediately() {
    let w = World::build().await;

    w.app
        .get(
            &format!("/api/v1/client-portal/projects/{}", w.project_shared_a),
            w.client_a.bearer(),
        )
        .await
        .assert_status(StatusCode::OK);

    crate::fixtures::revoke_share(&w.app, w.project_shared_a, w.client_account_a, w.root.id).await;

    invisible(
        &w.app
            .get(
                &format!("/api/v1/client-portal/projects/{}", w.project_shared_a),
                w.client_a.bearer(),
            )
            .await,
        "a project whose share was revoked one request ago",
    );

    // The same for a membership that stops being ACTIVE: the token is unchanged and
    // still authenticates, but the world it can see is empty.
    sqlx::query("UPDATE client_memberships SET status = 'SUSPENDED' WHERE user_id = $1")
        .bind(w.client_b.id)
        .execute(&w.app.db)
        .await
        .expect("suspend the membership");

    invisible(
        &w.app
            .get(
                &format!("/api/v1/client-portal/projects/{}", w.project_shared_b),
                w.client_b.bearer(),
            )
            .await,
        "a project reached through a membership that is no longer ACTIVE",
    );
    let list = w
        .app
        .get("/api/v1/client-portal/projects", w.client_b.bearer())
        .await;
    list.assert_status(StatusCode::OK);
    assert_eq!(
        list.json()["items"].as_array().map(Vec::len),
        Some(0),
        "a suspended membership still listed projects"
    );
}

// ===========================================================================
// Enumeration
// ===========================================================================

#[tokio::test]
async fn guessing_identifiers_teaches_a_client_nothing() {
    let w = World::build().await;
    let nowhere = unknown_id();

    // For each pair the two answers must be byte-identical apart from the request
    // id: one names a real object the client may not see, the other names nothing.
    let pairs = [
        (
            "/api/v1/client-portal/projects",
            w.project_shared_b,
            nowhere,
        ),
        ("/api/v1/client-portal/tasks", w.task_of_b, nowhere),
    ];
    for (base, real, fake) in pairs {
        let hidden = w
            .app
            .get(&format!("{base}/{real}"), w.client_a.bearer())
            .await;
        let missing = w
            .app
            .get(&format!("{base}/{fake}"), w.client_a.bearer())
            .await;
        invisible(&hidden, base);
        invisible(&missing, base);
        assert_eq!(
            hidden.json().get("detail"),
            missing.json().get("detail"),
            "{base} distinguishes a hidden object from a missing one"
        );
        assert_eq!(hidden.json().get("title"), missing.json().get("title"));
    }

    // A malformed identifier must not be a third, distinguishable answer that says
    // "the ones you sent before at least parsed".
    for bad in [
        "not-a-uuid",
        "00000000-0000-0000-0000-000000000000",
        "1",
        "%00",
    ] {
        let response = w
            .app
            .get(
                &format!("/api/v1/client-portal/projects/{bad}"),
                w.client_a.bearer(),
            )
            .await;
        assert!(
            response.status.is_client_error(),
            "`{bad}` produced {}",
            response.status
        );
        response.assert_no_secrets();
    }
}

// ===========================================================================
// The internal surface
// ===========================================================================

/// Every internal route must be `404` for a client — including the ones whose
/// existence a client could otherwise infer from a `403`.
#[tokio::test]
async fn every_internal_read_route_is_invisible_to_a_client() {
    let w = World::build().await;

    let paths = [
        "/api/v1/users",
        "/api/v1/roles",
        "/api/v1/permissions",
        "/api/v1/departments",
        "/api/v1/clients",
        "/api/v1/projects",
        "/api/v1/tasks",
        "/api/v1/invitations",
        "/api/v1/settings",
        "/api/v1/feature-flags",
        "/api/v1/audit/events",
    ];
    for path in paths {
        invisible(&w.app.get(path, w.client_a.bearer()).await, path);
    }

    // ...and the object-level forms, aimed at identifiers that really exist.
    let objects = [
        format!("/api/v1/users/{}", w.employee.id),
        format!("/api/v1/users/{}/roles", w.employee.id),
        format!("/api/v1/users/{}/permissions", w.employee.id),
        format!("/api/v1/users/{}/permission-overrides", w.employee.id),
        format!("/api/v1/projects/{}", w.project_shared_a),
        format!("/api/v1/projects/{}/members", w.project_shared_a),
        format!("/api/v1/projects/{}/clients", w.project_shared_a),
        format!("/api/v1/projects/{}/tasks", w.project_shared_a),
        format!("/api/v1/tasks/{}", w.visible_task),
        format!("/api/v1/tasks/{}/assignees", w.visible_task),
        format!("/api/v1/departments/{}", w.department),
        format!("/api/v1/departments/{}/members", w.department),
        format!("/api/v1/clients/{}", w.client_account_a),
        format!("/api/v1/clients/{}/members", w.client_account_a),
    ];
    for path in &objects {
        invisible(&w.app.get(path, w.client_a.bearer()).await, path);
    }

    // Even the client's *own* client account, through the internal route. The
    // portal is the only surface a client may reach.
    invisible(
        &w.app
            .get(
                &format!("/api/v1/clients/{}", w.client_account_a),
                w.client_a.bearer(),
            )
            .await,
        "a client reading its own account through the internal route",
    );
}

/// The audit log is the record of who did what. A client reading it would learn the
/// company's entire internal structure.
#[tokio::test]
async fn a_client_cannot_read_or_verify_the_audit_log() {
    let w = World::build().await;

    invisible(
        &w.app.get("/api/v1/audit/events", w.client_a.bearer()).await,
        "the audit event list",
    );
    invisible(
        &w.app
            .get(
                &format!("/api/v1/audit/events/{}", unknown_id()),
                w.client_a.bearer(),
            )
            .await,
        "a single audit event",
    );
    invisible(
        &w.app.get("/api/v1/audit/verify", w.client_a.bearer()).await,
        "audit chain verification",
    );
}

/// Every internal *write* route, aimed at real objects.
#[tokio::test]
async fn every_internal_write_route_is_invisible_to_a_client() {
    let w = World::build().await;

    let attacks: Vec<(&str, String, serde_json::Value)> = vec![
        (
            "POST",
            "/api/v1/projects".into(),
            json!({"code": "stolen", "name": "Stolen", "manager_user_id": w.employee.id}),
        ),
        (
            "POST",
            "/api/v1/tasks".into(),
            json!({"project_id": w.project_shared_a, "title": "Injected"}),
        ),
        (
            "PATCH",
            format!("/api/v1/projects/{}", w.project_shared_a),
            json!({"version": 1, "name": "Renamed by a client"}),
        ),
        (
            "PATCH",
            format!("/api/v1/tasks/{}", w.hidden_task),
            json!({"version": 1, "client_visible": true}),
        ),
        (
            "POST",
            format!("/api/v1/projects/{}/archive", w.project_shared_a),
            json!({"version": 1}),
        ),
        (
            "POST",
            format!("/api/v1/projects/{}/members", w.internal_project),
            json!({"user_id": w.client_a.id}),
        ),
        (
            "POST",
            format!("/api/v1/projects/{}/clients", w.internal_project),
            json!({"client_account_id": w.client_account_a}),
        ),
        (
            "POST",
            format!("/api/v1/tasks/{}/assignees", w.visible_task),
            json!({"user_id": w.client_a.id}),
        ),
        (
            "POST",
            "/api/v1/invitations".into(),
            json!({"email": "accomplice@evil.test", "display_name": "Accomplice",
                   "principal_type": "INTERNAL", "role_ids": []}),
        ),
        (
            "POST",
            "/api/v1/roles".into(),
            json!({"code": "escalation", "name": "Escalation",
                   "allowed_principal_type": "CLIENT", "permissions": []}),
        ),
        (
            "POST",
            format!("/api/v1/users/{}/roles", w.client_a.id),
            json!({"role_id": crate::fixtures::ROLE_SYSTEM_ADMINISTRATOR}),
        ),
        (
            "POST",
            format!("/api/v1/users/{}/permission-overrides", w.client_a.id),
            json!({"permission_code": "audit.read", "effect": "ALLOW", "scope": "GLOBAL"}),
        ),
        (
            "PUT",
            "/api/v1/settings/registration.mode".into(),
            json!({"version": 1, "value": "CLIENT_SELF_REGISTRATION"}),
        ),
        (
            "PUT",
            "/api/v1/feature-flags/client_portal".into(),
            json!({"version": 1, "enabled": false}),
        ),
    ];

    for (method, path, body) in attacks {
        let response = match method {
            "POST" => w.app.post(&path, w.client_a.bearer(), body).await,
            "PATCH" => w.app.patch(&path, w.client_a.bearer(), body).await,
            "PUT" => w.app.put(&path, w.client_a.bearer(), body).await,
            other => panic!("unhandled method {other}"),
        };
        invisible(&response, &format!("{method} {path}"));
    }

    // Deletions have no body and are attacked separately.
    for path in [
        format!("/api/v1/tasks/{}", w.visible_task),
        format!("/api/v1/roles/{}", crate::fixtures::ROLE_EMPLOYEE),
        format!(
            "/api/v1/projects/{}/members/{}",
            w.internal_project, w.manager.id
        ),
        format!(
            "/api/v1/projects/{}/clients/{}",
            w.project_shared_a, w.client_account_a
        ),
    ] {
        invisible(
            &w.app.delete(&path, w.client_a.bearer()).await,
            &format!("DELETE {path}"),
        );
    }

    // Nothing was actually written.
    let tasks: (i64,) = sqlx::query_as("SELECT count(*) FROM tasks WHERE title = 'Injected'")
        .fetch_one(&w.app.db)
        .await
        .expect("count");
    assert_eq!(tasks.0, 0, "a client created a task");
    let roles: (i64,) = sqlx::query_as("SELECT count(*) FROM roles WHERE code = 'escalation'")
        .fetch_one(&w.app.db)
        .await
        .expect("count");
    assert_eq!(roles.0, 0, "a client created a role");
}

/// A refusal that targets the system owner must not become an existence oracle for
/// an external principal.
///
/// `docs/backend/04-authorization.md` §10 says a ROOT-targeting refusal is an
/// unmistakable `403 ROOT_PROTECTED`. That is right *inside the company*, where
/// existence disclosure is acceptable — but a CLIENT that can tell `403` from `404`
/// can walk a list of identifiers and pick out the system owner's. The rule that
/// wins across the trust boundary is the client envelope.
#[tokio::test]
async fn a_client_cannot_identify_the_system_owner_by_probing() {
    let w = World::build().await;

    let probes: Vec<(&str, String, serde_json::Value)> = vec![
        (
            "PATCH",
            format!("/api/v1/users/{}", w.root.id),
            json!({"version": 1, "display_name": "Owned"}),
        ),
        (
            "POST",
            format!("/api/v1/users/{}/suspend", w.root.id),
            json!({"version": 1}),
        ),
        (
            "POST",
            format!("/api/v1/users/{}/archive", w.root.id),
            json!({"version": 1}),
        ),
        (
            "POST",
            format!("/api/v1/users/{}/reactivate", w.root.id),
            json!({"version": 1}),
        ),
    ];

    for (method, path, body) in probes {
        let against_root = match method {
            "POST" => w.app.post(&path, w.client_a.bearer(), body.clone()).await,
            _ => w.app.patch(&path, w.client_a.bearer(), body.clone()).await,
        };
        let ordinary_path = path.replace(&w.root.id.to_string(), &w.employee.id.to_string());
        let against_an_employee = match method {
            "POST" => w.app.post(&ordinary_path, w.client_a.bearer(), body).await,
            _ => w.app.patch(&ordinary_path, w.client_a.bearer(), body).await,
        };

        invisible(&against_root, &format!("{method} {path} (the owner)"));
        invisible(&against_an_employee, &format!("{method} {ordinary_path}"));
        assert_eq!(
            against_root.error_code(),
            against_an_employee.error_code(),
            "a client can tell the system owner apart from an ordinary employee via {method} {path}"
        );
    }
}

// ===========================================================================
// Tampering with the request itself
// ===========================================================================

/// TH-12. Every privileged field is refused as an unknown field rather than
/// silently ignored — an ignored field is a caller who believes something happened.
#[tokio::test]
async fn a_client_cannot_smuggle_privileged_fields_into_a_body() {
    let w = World::build().await;

    let payloads = vec![
        (
            format!("/api/v1/users/{}", w.client_a.id),
            json!({"version": 1, "principal_type": "INTERNAL"}),
        ),
        (
            format!("/api/v1/users/{}", w.client_a.id),
            json!({"version": 1, "role_ids": [crate::fixtures::ROLE_SYSTEM_ADMINISTRATOR]}),
        ),
        (
            format!("/api/v1/users/{}", w.client_a.id),
            json!({"version": 1, "is_root": true}),
        ),
        (
            format!("/api/v1/users/{}", w.client_a.id),
            json!({"version": 1, "status": "ACTIVE", "security_version": 99}),
        ),
        (
            format!("/api/v1/users/{}", w.client_a.id),
            json!({"version": 1, "client_visible": true}),
        ),
        (
            format!("/api/v1/users/{}", w.client_a.id),
            json!({"version": 1, "permissions": ["audit.read"]}),
        ),
    ];

    for (path, body) in payloads {
        let response = w.app.patch(&path, w.client_a.bearer(), body.clone()).await;
        assert_eq!(
            response.status,
            StatusCode::BAD_REQUEST,
            "a privileged field was not rejected outright: {body}"
        );
        assert_eq!(response.error_code(), Some("BAD_REQUEST"));
        response.assert_no_secrets();
    }

    // The envelope is unchanged in the database, which is the fact that matters.
    let principal_type: (String,) =
        sqlx::query_as("SELECT principal_type FROM users WHERE id = $1")
            .bind(w.client_a.id)
            .fetch_one(&w.app.db)
            .await
            .expect("read the principal type");
    assert_eq!(
        principal_type.0, "CLIENT",
        "a client changed its own envelope"
    );

    let elevated: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM user_role_assignments ura
           JOIN roles r ON r.id = ura.role_id
          WHERE ura.user_id = $1 AND r.allowed_principal_type = 'INTERNAL'",
    )
    .bind(w.client_a.id)
    .fetch_one(&w.app.db)
    .await
    .expect("count internal roles");
    assert_eq!(elevated.0, 0, "a client acquired an internal role");
}

/// Pagination and filtering are not an authorisation bypass: the visibility
/// predicate is in the query, so widening the page cannot widen the result set.
#[tokio::test]
async fn pagination_and_filter_manipulation_does_not_widen_a_clients_world() {
    let w = World::build().await;

    for query in ["", "?limit=100", "?limit=1", "?limit=25"] {
        let response = w
            .app
            .get(
                &format!("/api/v1/client-portal/projects{query}"),
                w.client_a.bearer(),
            )
            .await;
        response.assert_status(StatusCode::OK);
        let items = response.json()["items"].as_array().expect("items").clone();
        let ids: Vec<String> = items
            .iter()
            .filter_map(|i| i["id"].as_str().map(str::to_string))
            .collect();
        assert!(
            !ids.contains(&w.project_shared_b.to_string()),
            "`{query}` leaked client B's project into client A's listing"
        );
        assert!(
            !ids.contains(&w.internal_project.to_string()),
            "`{query}` leaked an unshared project into a client listing"
        );
        assert!(
            ids.len() <= 1,
            "`{query}` returned more than A's one project"
        );
    }

    // Out-of-range and injected pagination values are refused, and the rejected
    // value is not echoed back.
    for query in [
        "limit=0",
        "limit=-1",
        "limit=101",
        "limit=999999999",
        "limit=abc",
    ] {
        let response = w
            .app
            .get(
                &format!("/api/v1/client-portal/projects?{query}"),
                w.client_a.bearer(),
            )
            .await;
        assert!(
            response.status.is_client_error(),
            "`{query}` was accepted with {}",
            response.status
        );
    }

    // The portal query accepts `cursor` and `limit` and nothing else, so a sort or
    // an ordering parameter is refused as an unrecognised field rather than being
    // parsed — there is no allowlist to get wrong because there is no allowlist.
    for query in [
        "sort=id%3B%20DROP%20TABLE%20projects",
        "sort=created_at",
        "direction=backward",
        "department_id=00000000-0000-7000-8000-000000000001",
        "client_account_id=00000000-0000-7000-8000-000000000001",
    ] {
        let injected = w
            .app
            .get(
                &format!("/api/v1/client-portal/projects?{query}"),
                w.client_a.bearer(),
            )
            .await;
        assert_eq!(
            injected.status,
            StatusCode::BAD_REQUEST,
            "`{query}` was accepted by the portal listing"
        );
        assert!(
            !String::from_utf8_lossy(&injected.raw).contains("DROP"),
            "the rejected parameter was reflected back"
        );
    }
}

// ===========================================================================
// The projection itself
// ===========================================================================

/// The client projection is a separate struct, not a filtered serialisation of the
/// internal one. If it ever became the latter, an added column would leak.
#[tokio::test]
async fn the_client_projection_contains_no_internal_field() {
    let w = World::build().await;

    let project = w
        .app
        .get(
            &format!("/api/v1/client-portal/projects/{}", w.project_shared_a),
            w.client_a.bearer(),
        )
        .await;
    project.assert_status(StatusCode::OK).assert_no_secrets();
    let body = project.json().as_object().expect("an object").clone();
    for forbidden in [
        "internal_note",
        "department_id",
        "manager_user_id",
        "created_by",
        "version",
    ] {
        assert!(
            !body.contains_key(forbidden),
            "the client project projection exposes `{forbidden}`"
        );
    }
    assert!(
        !String::from_utf8_lossy(&project.raw).contains("internal only"),
        "the internal note leaked into a client response"
    );

    let task = w
        .app
        .get(
            &format!("/api/v1/client-portal/tasks/{}", w.visible_task),
            w.client_a.bearer(),
        )
        .await;
    task.assert_status(StatusCode::OK).assert_no_secrets();
    let body = task.json().as_object().expect("an object").clone();
    for forbidden in ["client_visible", "internal_note", "created_by", "version"] {
        assert!(
            !body.contains_key(forbidden),
            "the client task projection exposes `{forbidden}`"
        );
    }

    // `/auth/me` for a client must carry only the two portal capabilities.
    let me = w.app.get("/api/v1/auth/me", w.client_a.bearer()).await;
    me.assert_status(StatusCode::OK).assert_no_secrets();
    let capabilities = me.json()["capabilities"].as_array().expect("capabilities");
    for capability in capabilities {
        let code = capability["permission"].as_str().unwrap_or_default();
        assert!(
            code.starts_with("client.portal."),
            "the capability list handed `{code}` to an external principal"
        );
    }
    assert_eq!(capabilities.len(), 2, "exactly the two portal permissions");
    assert_eq!(me.json()["is_root"], json!(false));

    // `/system/info` is deliberately reachable by a client. Its whole protection is
    // the field list, so the field list is pinned.
    let info = w.app.get("/api/v1/system/info", w.client_a.bearer()).await;
    info.assert_status(StatusCode::OK).assert_no_secrets();
    let keys: Vec<&String> = info
        .json()
        .as_object()
        .expect("an object")
        .keys()
        .collect::<Vec<_>>();
    assert_eq!(
        keys.len(),
        3,
        "the authenticated system probe grew a field: {:?}",
        keys
    );
}
