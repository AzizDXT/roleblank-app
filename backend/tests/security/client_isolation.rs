//! §5 — client isolation, judged on **indistinguishability** rather than on refusal.
//!
//! `client_escape.rs` establishes that a client is refused everywhere it should be.
//! That is necessary and not sufficient. The property this file tests is stricter:
//!
//! > A resource that exists but is hidden, and a resource that does not exist at
//! > all, must produce **byte-identical** responses.
//!
//! A suite that only checks `status == 404` passes happily against a system whose
//! two 404s differ in `detail`, in the `errors` array, in the header set, or in
//! `content-length`. Each of those is a working existence oracle, and the last two
//! are invisible to any assertion written against the parsed JSON. Everything below
//! therefore compares whole responses, with only the correlation id removed.
//!
//! The second half attacks the *shape* of the request rather than its target:
//! identifier encodings, HTTP methods, forged cursors and smuggled query
//! parameters — the ways a caller tries to reach a different code path in the hope
//! that one of them forgot to filter.

use axum::http::{header, Method, StatusCode};
use serde_json::{json, Value};

use crate::common::{TestApp, TestResponse};
use crate::fixtures::{unknown_id, World};

// ===========================================================================
// Comparison machinery
// ===========================================================================

/// A response reduced to everything an attacker can observe, minus the one field
/// that is legitimately unique per request.
///
/// Deliberately includes the **header set** and the **body length**: two refusals
/// that differ only in `content-length` are still an oracle, and no assertion
/// written against parsed JSON would ever see it.
fn observable(response: &TestResponse) -> (StatusCode, Vec<String>, usize, Value) {
    let mut headers: Vec<String> = response
        .headers
        .iter()
        .filter(|(name, _)| {
            // `x-request-id` is unique by design and `date` moves on its own.
            *name != "x-request-id" && *name != "date"
        })
        .map(|(name, value)| {
            format!(
                "{name}: {}",
                value.to_str().unwrap_or("<non-ascii>").to_owned()
            )
        })
        .collect();
    headers.sort();

    let mut body = response
        .body
        .clone()
        .unwrap_or_else(|| Value::String(String::from_utf8_lossy(&response.raw).into_owned()));
    if let Some(object) = body.as_object_mut() {
        object.remove("request_id");
    }

    // The raw length is compared with the request id's own length subtracted, since
    // that field is the only permitted difference and UUIDs are fixed width.
    (response.status, headers, response.raw.len(), body)
}

/// Assert that a hidden resource is indistinguishable from a missing one.
#[track_caller]
fn indistinguishable(hidden: &TestResponse, missing: &TestResponse, what: &str) {
    let a = observable(hidden);
    let b = observable(missing);
    assert_eq!(
        a.0, b.0,
        "{what}: a hidden resource and a missing one differ in status"
    );
    assert_eq!(
        a.1, b.1,
        "{what}: a hidden resource and a missing one differ in their headers"
    );
    assert_eq!(
        a.3, b.3,
        "{what}: a hidden resource and a missing one differ in their bodies"
    );
    assert_eq!(
        a.2, b.2,
        "{what}: a hidden resource and a missing one differ in body length — \
         an oracle invisible to a JSON comparison"
    );
    assert_eq!(
        hidden.error_code(),
        Some("RESOURCE_NOT_FOUND"),
        "{what}: the refusal used a distinguishable code"
    );
    hidden.assert_no_secrets();
}

/// Send a request whose path is used verbatim, without the helpers' formatting.
async fn raw_get(app: &TestApp, path: &str, token: Option<&str>) -> TestResponse {
    let mut builder = axum::http::Request::builder().method(Method::GET).uri(path);
    if let Some(t) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    let request = builder
        .body(axum::body::Body::empty())
        .expect("a well-formed request");
    app.request(request).await
}

// ===========================================================================
// The core property
// ===========================================================================

/// Every object a client can name, in three flavours: one it may see, one that
/// exists but is another tenant's, and one that does not exist at all. The last
/// two must be identical down to the byte.
#[tokio::test]
async fn a_hidden_resource_and_a_missing_one_are_byte_identical() {
    let w = World::build().await;
    let nowhere = unknown_id();

    // (base path, an object client A must not see, the control it may see)
    let cases: Vec<(&str, String, Option<String>)> = vec![
        (
            "/api/v1/client-portal/projects",
            w.project_shared_b.to_string(),
            Some(w.project_shared_a.to_string()),
        ),
        (
            "/api/v1/client-portal/projects",
            w.internal_project.to_string(),
            None,
        ),
        (
            "/api/v1/client-portal/tasks",
            w.task_of_b.to_string(),
            Some(w.visible_task.to_string()),
        ),
        (
            "/api/v1/client-portal/tasks",
            // Hidden *inside* a project A can see: `client_visible = false`.
            w.hidden_task.to_string(),
            None,
        ),
        (
            "/api/v1/client-portal/tasks",
            w.internal_task.to_string(),
            None,
        ),
    ];

    for (base, hidden_id, control) in cases {
        // The control proves the endpoint is capable of answering, so a blanket 404
        // from a broken fixture cannot masquerade as a passing security test.
        if let Some(visible) = control {
            raw_get(&w.app, &format!("{base}/{visible}"), w.client_a.bearer())
                .await
                .assert_status(StatusCode::OK);
        }

        let hidden = raw_get(&w.app, &format!("{base}/{hidden_id}"), w.client_a.bearer()).await;
        let missing = raw_get(&w.app, &format!("{base}/{nowhere}"), w.client_a.bearer()).await;
        indistinguishable(&hidden, &missing, &format!("{base}/{{id}}"));
    }

    // The nested collection form as well: listing the tasks of a project that
    // exists but is not yours must match listing the tasks of a project that is not.
    let hidden = raw_get(
        &w.app,
        &format!(
            "/api/v1/client-portal/projects/{}/tasks",
            w.project_shared_b
        ),
        w.client_a.bearer(),
    )
    .await;
    let missing = raw_get(
        &w.app,
        &format!("/api/v1/client-portal/projects/{nowhere}/tasks"),
        w.client_a.bearer(),
    )
    .await;
    indistinguishable(&hidden, &missing, "the nested task listing");
}

/// The internal surface, judged the same way.
///
/// An employee's user record, a department, a client account, a project: each
/// exists, and each must look to a client exactly like an identifier that names
/// nothing — including on the routes the client has no business knowing exist.
#[tokio::test]
async fn the_whole_internal_surface_looks_empty_rather_than_forbidden() {
    let w = World::build().await;
    let nowhere = unknown_id();

    let objects: Vec<(&str, String)> = vec![
        ("/api/v1/users", w.employee.id.to_string()),
        ("/api/v1/users", w.root.id.to_string()),
        ("/api/v1/users", w.other_employee.to_string()),
        ("/api/v1/projects", w.internal_project.to_string()),
        ("/api/v1/projects", w.project_shared_a.to_string()),
        ("/api/v1/tasks", w.visible_task.to_string()),
        ("/api/v1/tasks", w.internal_task.to_string()),
        ("/api/v1/departments", w.department.to_string()),
        ("/api/v1/clients", w.client_account_a.to_string()),
        ("/api/v1/clients", w.client_account_b.to_string()),
        ("/api/v1/roles", crate::fixtures::ROLE_EMPLOYEE.to_string()),
    ];

    for (base, real) in objects {
        let hidden = raw_get(&w.app, &format!("{base}/{real}"), w.client_a.bearer()).await;
        let missing = raw_get(&w.app, &format!("{base}/{nowhere}"), w.client_a.bearer()).await;
        indistinguishable(&hidden, &missing, &format!("{base}/{{id}}"));
    }

    // Sub-resources too: the existence of a membership list is as much a disclosure
    // as the existence of the parent.
    let subresources: Vec<(String, String)> = vec![
        (
            format!("/api/v1/projects/{}/members", w.internal_project),
            format!("/api/v1/projects/{nowhere}/members"),
        ),
        (
            format!("/api/v1/projects/{}/clients", w.project_shared_a),
            format!("/api/v1/projects/{nowhere}/clients"),
        ),
        (
            format!("/api/v1/clients/{}/members", w.client_account_a),
            format!("/api/v1/clients/{nowhere}/members"),
        ),
        (
            format!("/api/v1/departments/{}/members", w.department),
            format!("/api/v1/departments/{nowhere}/members"),
        ),
        (
            format!("/api/v1/users/{}/roles", w.employee.id),
            format!("/api/v1/users/{nowhere}/roles"),
        ),
        (
            format!("/api/v1/users/{}/permissions", w.employee.id),
            format!("/api/v1/users/{nowhere}/permissions"),
        ),
        (
            format!("/api/v1/tasks/{}/assignees", w.visible_task),
            format!("/api/v1/tasks/{nowhere}/assignees"),
        ),
    ];
    for (real_path, fake_path) in subresources {
        let hidden = raw_get(&w.app, &real_path, w.client_a.bearer()).await;
        let missing = raw_get(&w.app, &fake_path, w.client_a.bearer()).await;
        indistinguishable(&hidden, &missing, &real_path);
    }
}

// ===========================================================================
// Reaching a different code path
// ===========================================================================

/// Identifier spelling. Each of these is the same UUID written differently, and a
/// route that normalises one of them differently reaches a different query.
#[tokio::test]
async fn identifier_spelling_tricks_do_not_reach_another_tenants_data() {
    let w = World::build().await;
    let target = w.project_shared_b.to_string();

    let spellings = vec![
        target.to_uppercase(),
        format!("urn:uuid:{target}"),
        target.replace('-', ""),
        format!("{target}%00"),
        format!("{target}%20"),
        format!("%20{target}"),
        format!("{target}."),
        format!("{target}/"),
        format!("{target}?"),
        format!("{target}#fragment"),
        format!("{target}%2F..%2F{}", w.project_shared_a),
        format!("..%2F..%2Fprojects%2F{target}"),
    ];

    for spelling in spellings {
        let response = raw_get(
            &w.app,
            &format!("/api/v1/client-portal/projects/{spelling}"),
            w.client_a.bearer(),
        )
        .await;
        assert!(
            response.status.is_client_error(),
            "`{spelling}` produced {} — a spelling of another client's id was accepted: {}",
            response.status,
            String::from_utf8_lossy(&response.raw)
        );
        // Whatever the answer, it must never contain the object.
        let text = String::from_utf8_lossy(&response.raw);
        assert!(
            !text.contains("shared-with-b"),
            "`{spelling}` returned client B's project: {text}"
        );
        response.assert_no_secrets();
    }

    // The uppercase form of the client's *own* project must also not become a
    // second, more permissive path — either it works exactly as the canonical form
    // does, or it is refused. What it must not be is a route that skips a filter.
    let own_upper = raw_get(
        &w.app,
        &format!(
            "/api/v1/client-portal/projects/{}",
            w.project_shared_a.to_string().to_uppercase()
        ),
        w.client_a.bearer(),
    )
    .await;
    assert!(
        own_upper.status == StatusCode::OK || own_upper.status.is_client_error(),
        "an uppercase identifier produced {}",
        own_upper.status
    );
}

/// Method probing. A route that answers `405` for a real object and `404` for an
/// invented one has told the caller the object exists.
#[tokio::test]
async fn method_probing_does_not_reveal_that_a_resource_exists() {
    let w = World::build().await;
    let nowhere = unknown_id();

    let pairs = [
        (
            format!("/api/v1/client-portal/projects/{}", w.project_shared_b),
            format!("/api/v1/client-portal/projects/{nowhere}"),
        ),
        (
            format!("/api/v1/client-portal/tasks/{}", w.task_of_b),
            format!("/api/v1/client-portal/tasks/{nowhere}"),
        ),
        (
            format!("/api/v1/projects/{}", w.internal_project),
            format!("/api/v1/projects/{nowhere}"),
        ),
        (
            format!("/api/v1/users/{}", w.employee.id),
            format!("/api/v1/users/{nowhere}"),
        ),
    ];

    for (real, fake) in pairs {
        for method in [Method::POST, Method::PUT, Method::PATCH, Method::DELETE] {
            let against_real = match method {
                Method::POST => w.app.post(&real, w.client_a.bearer(), json!({})).await,
                Method::PUT => w.app.put(&real, w.client_a.bearer(), json!({})).await,
                Method::PATCH => w.app.patch(&real, w.client_a.bearer(), json!({})).await,
                _ => w.app.delete(&real, w.client_a.bearer()).await,
            };
            let against_fake = match method {
                Method::POST => w.app.post(&fake, w.client_a.bearer(), json!({})).await,
                Method::PUT => w.app.put(&fake, w.client_a.bearer(), json!({})).await,
                Method::PATCH => w.app.patch(&fake, w.client_a.bearer(), json!({})).await,
                _ => w.app.delete(&fake, w.client_a.bearer()).await,
            };

            assert_eq!(
                against_real.status, against_fake.status,
                "{method} on `{real}` answered {} but `{fake}` answered {} — \
                 the method probe confirmed the object exists",
                against_real.status, against_fake.status
            );
            assert_eq!(
                observable(&against_real).3,
                observable(&against_fake).3,
                "{method} produced distinguishable bodies for a real and a fake id"
            );
            against_real.assert_no_secrets();
        }
    }
}

/// A cursor is opaque but unsigned, and the code comments say so. That is only
/// safe if a forged cursor can reposition a query the caller was **already**
/// authorised to run — never widen it. This test forges one from another tenant's
/// listing and proves exactly that.
#[tokio::test]
async fn a_forged_pagination_cursor_cannot_widen_a_clients_world() {
    let w = World::build().await;

    // Client B's own listing, from which a cursor into B's data can be taken.
    let bs_page = w
        .app
        .get(
            "/api/v1/client-portal/projects?limit=1",
            w.client_b.bearer(),
        )
        .await;
    bs_page.assert_status(StatusCode::OK);
    let bs_cursor = bs_page
        .json()
        .pointer("/page/next_cursor")
        .and_then(Value::as_str)
        .map(str::to_string);

    // Whether or not B has a next page, a cursor built from B's world must not open
    // it for A. Construct one unconditionally from B's project id so the test does
    // not depend on B having enough rows to paginate.
    let forged = {
        let mut raw = Vec::with_capacity(24);
        raw.extend_from_slice(&0i64.to_be_bytes());
        raw.extend_from_slice(w.project_shared_b.as_bytes());
        data_encoding::BASE64URL_NOPAD.encode(&raw)
    };

    let mut cursors = vec![forged];
    if let Some(c) = bs_cursor {
        cursors.push(c);
    }

    for cursor in cursors {
        let response = w
            .app
            .get(
                &format!("/api/v1/client-portal/projects?cursor={cursor}"),
                w.client_a.bearer(),
            )
            .await;
        // Either the cursor is rejected or it repositions A's own query. What it
        // must never do is return a row A cannot see.
        if response.status == StatusCode::OK {
            let text = String::from_utf8_lossy(&response.raw);
            assert!(
                !text.contains(&w.project_shared_b.to_string()),
                "a forged cursor returned client B's project to client A: {text}"
            );
            assert!(
                !text.contains(&w.internal_project.to_string()),
                "a forged cursor returned an internal project to a client: {text}"
            );
            assert!(
                !text.contains("internal only"),
                "a forged cursor leaked an internal note"
            );
        } else {
            assert!(
                response.status.is_client_error(),
                "a forged cursor produced {}",
                response.status
            );
        }
        response.assert_no_secrets();
    }

    // Paging all the way through, with the smallest page size, still only ever
    // yields A's own world. A filter applied to page one but not to page two is a
    // classic and completely invisible bug.
    let mut seen: Vec<String> = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..10 {
        let path = match &cursor {
            None => "/api/v1/client-portal/projects?limit=1".to_string(),
            Some(c) => format!("/api/v1/client-portal/projects?limit=1&cursor={c}"),
        };
        let page = w.app.get(&path, w.client_a.bearer()).await;
        page.assert_status(StatusCode::OK);
        for item in page.json()["items"].as_array().expect("items") {
            if let Some(id) = item["id"].as_str() {
                seen.push(id.to_string());
            }
        }
        match page
            .json()
            .pointer("/page/next_cursor")
            .and_then(Value::as_str)
        {
            Some(next) => cursor = Some(next.to_string()),
            None => break,
        }
    }
    assert_eq!(
        seen,
        vec![w.project_shared_a.to_string()],
        "paging through the portal listing yielded something other than A's own project"
    );
}

/// Smuggled query parameters, on the theory that one of them selects a wider
/// projection or a different filter.
#[tokio::test]
async fn a_client_cannot_request_a_wider_projection_or_a_different_filter() {
    let w = World::build().await;

    let probes = [
        "include=internal_note",
        "fields=*",
        "fields=internal_note,created_by",
        "expand=members",
        "expand=client_account",
        "client_account_id=00000000-0000-7000-8000-000000000000",
        "all=true",
        "internal=true",
        "principal_type=INTERNAL",
        "client_visible=false",
        "status=ARCHIVED",
        "project_id=00000000-0000-7000-8000-000000000000",
    ];

    for probe in probes {
        let response = w
            .app
            .get(
                &format!("/api/v1/client-portal/projects?{probe}"),
                w.client_a.bearer(),
            )
            .await;
        // Unknown query fields are a parse failure, not a silently ignored key: an
        // ignored parameter is a caller who believes something happened.
        assert_eq!(
            response.status,
            StatusCode::BAD_REQUEST,
            "`{probe}` was accepted rather than refused as an unknown parameter: {}",
            String::from_utf8_lossy(&response.raw)
        );
        assert!(
            !String::from_utf8_lossy(&response.raw).contains("internal only"),
            "`{probe}` leaked an internal note"
        );
        response.assert_no_secrets();
    }

    // The same on the single-object route, where a widened projection would leak
    // the fields the client projection deliberately omits.
    for probe in ["include=internal_note", "fields=*", "expand=members"] {
        let response = w
            .app
            .get(
                &format!(
                    "/api/v1/client-portal/projects/{}?{probe}",
                    w.project_shared_a
                ),
                w.client_a.bearer(),
            )
            .await;
        let text = String::from_utf8_lossy(&response.raw);
        for forbidden in [
            "internal_note",
            "internal only",
            "manager_user_id",
            "created_by",
        ] {
            assert!(
                !text.contains(forbidden),
                "`{probe}` widened the client projection with `{forbidden}`: {text}"
            );
        }
    }
}

// ===========================================================================
// Self-service escalation
// ===========================================================================

/// A client acting on its own account. Every one of these is a legitimate-looking
/// self-service request, and each would be an escalation if it worked.
#[tokio::test]
async fn a_client_cannot_grant_itself_anything_through_its_own_account() {
    let w = World::build().await;

    let attempts: Vec<(&str, String, Value)> = vec![
        (
            "granting itself a permission",
            format!("/api/v1/users/{}/permission-overrides", w.client_a.id),
            json!({"permission_code": "projects.read", "effect": "ALLOW", "scope": "GLOBAL"}),
        ),
        (
            "granting itself a portal permission it already has",
            format!("/api/v1/users/{}/permission-overrides", w.client_a.id),
            json!({"permission_code": "client.portal.projects.read", "effect": "ALLOW", "scope": "GLOBAL"}),
        ),
        (
            "assigning itself an internal role",
            format!("/api/v1/users/{}/roles", w.client_a.id),
            json!({"role_id": crate::fixtures::ROLE_EMPLOYEE}),
        ),
        (
            "assigning itself the administrator role",
            format!("/api/v1/users/{}/roles", w.client_a.id),
            json!({"role_id": crate::fixtures::ROLE_SYSTEM_ADMINISTRATOR}),
        ),
        (
            "joining another client account",
            format!("/api/v1/clients/{}/members", w.client_account_b),
            json!({"user_id": w.client_a.id}),
        ),
        (
            "sharing an internal project with itself",
            format!("/api/v1/projects/{}/clients", w.internal_project),
            json!({"client_account_id": w.client_account_a}),
        ),
        (
            "adding itself to an internal project",
            format!("/api/v1/projects/{}/members", w.internal_project),
            json!({"user_id": w.client_a.id}),
        ),
        (
            "creating a role for itself",
            "/api/v1/roles".into(),
            json!({
                "code": "client_admin",
                "name": "Client Admin",
                "allowed_principal_type": "CLIENT",
                "permissions": [{"permission_code": "client.portal.projects.read", "scope": "GLOBAL"}],
            }),
        ),
        (
            "inviting an accomplice",
            "/api/v1/invitations".into(),
            json!({
                "email": "accomplice@evil.test",
                "display_name": "Accomplice",
                "principal_type": "INTERNAL",
                "role_ids": [],
            }),
        ),
    ];

    for (label, path, body) in attempts {
        let response = w.app.post(&path, w.client_a.bearer(), body).await;
        assert_eq!(
            response.status,
            StatusCode::NOT_FOUND,
            "{label} answered {} — a client learned this route exists: {}",
            response.status,
            String::from_utf8_lossy(&response.raw)
        );
        assert_eq!(
            response.error_code(),
            Some("RESOURCE_NOT_FOUND"),
            "{label} used a distinguishable code"
        );
        response.assert_no_secrets();
    }

    // Nothing reached the database, from any of them.
    let grants: (i64,) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM user_permission_overrides WHERE user_id = $1)
              + (SELECT count(*) FROM user_role_assignments WHERE user_id = $1)",
    )
    .bind(w.client_a.id)
    .fetch_one(&w.app.db)
    .await
    .expect("count the client's grants");
    // Exactly the one `client_user` role the fixture assigned, and no overrides.
    assert_eq!(grants.0, 1, "a client acquired authority");

    let custom_roles: (i64,) = sqlx::query_as("SELECT count(*) FROM roles WHERE is_system = false")
        .fetch_one(&w.app.db)
        .await
        .expect("count custom roles");
    assert_eq!(custom_roles.0, 0, "a client created a role");

    let invitations: (i64,) = sqlx::query_as("SELECT count(*) FROM invitations")
        .fetch_one(&w.app.db)
        .await
        .expect("count invitations");
    assert_eq!(invitations.0, 0, "a client issued an invitation");

    // And the client's own world is unchanged: it still sees exactly one project.
    let listing = w
        .app
        .get("/api/v1/client-portal/projects", w.client_a.bearer())
        .await;
    listing.assert_status(StatusCode::OK);
    assert_eq!(
        listing.json()["items"].as_array().map(Vec::len),
        Some(1),
        "the client's visible world changed size"
    );
}

/// Enumeration by counting. Even when every individual read is refused, a
/// collection that reports a total, or a listing that returns an empty page rather
/// than a refusal, tells the caller how large the company is.
#[tokio::test]
async fn no_collection_leaks_a_count_or_an_empty_page_to_a_client() {
    let w = World::build().await;

    for path in [
        "/api/v1/users",
        "/api/v1/roles",
        "/api/v1/permissions",
        "/api/v1/departments",
        "/api/v1/clients",
        "/api/v1/projects",
        "/api/v1/tasks",
        "/api/v1/invitations",
        "/api/v1/audit/events",
        "/api/v1/settings",
        "/api/v1/feature-flags",
    ] {
        let response = w.app.get(path, w.client_a.bearer()).await;
        assert_eq!(
            response.status,
            StatusCode::NOT_FOUND,
            "{path} answered {} rather than being invisible",
            response.status
        );
        // An empty `items` array would be a *successful* answer, and would confirm
        // the collection exists and that the client is simply not in it.
        let text = String::from_utf8_lossy(&response.raw);
        assert!(
            !text.contains("\"items\""),
            "{path} returned a collection shape to a client: {text}"
        );
        assert!(
            !text.contains("\"total\"") && !text.contains("\"count\""),
            "{path} returned a count to a client: {text}"
        );
        response.assert_no_secrets();
    }

    // `/system/info` is authenticated but permissionless, so a client reaches it.
    // It must therefore carry no population figures or internal topology.
    let info = w.app.get("/api/v1/system/info", w.client_a.bearer()).await;
    if info.status == StatusCode::OK {
        let text = String::from_utf8_lossy(&info.raw).to_lowercase();
        for forbidden in [
            "user_count",
            "users",
            "project_count",
            "department",
            "client_count",
            "root",
            "database",
            "host",
        ] {
            assert!(
                !text.contains(forbidden),
                "`/system/info` exposes `{forbidden}` to a client: {text}"
            );
        }
        info.assert_no_secrets();
    }
}
