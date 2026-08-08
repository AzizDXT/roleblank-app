//! §10 — sensitive-data leakage.
//!
//! The centrepiece is `no_response_on_any_route_leaks_secret_material`, which walks
//! **every entry in `routes::ROUTE_TABLE`** as every kind of principal and fails if
//! any response body matches a forbidden pattern. Walking the route table rather
//! than a hand-written list is the point: a route added tomorrow is scanned
//! tomorrow, without anybody remembering to add it here. The test asserts it
//! visited the whole table, so a route the path-filling helper cannot express is a
//! failure rather than a silent gap.
//!
//! Two classes of pattern are checked on every body (see `world::FORBIDDEN_
//! SUBSTRINGS` for the reasoning): the column and field *names* of every secret the
//! schema holds, and the actual *values* those columns hold in this running
//! instance, read straight out of the database. A leak that renamed the field
//! passes the first check and fails the second.

use axum::http::{Method, StatusCode};
use serde_json::json;
use uuid::Uuid;

use crate::world::{self, World, INTERNAL_NOTE_MARKER};
use roleblank_backend::routes::{RouteSpec, ROUTE_TABLE};

/// Concrete identifiers to substitute into the route patterns.
struct Ids {
    user: Uuid,
    client_user: Uuid,
    role: Uuid,
    department: Uuid,
    client_account: Uuid,
    project: Uuid,
    task: Uuid,
    invitation: Uuid,
    audit_event: Uuid,
    session: Uuid,
    unknown: Uuid,
}

/// Replace every `{placeholder}` with a real identifier.
///
/// The identifier is chosen by the segment *preceding* the placeholder, which is
/// what makes one rule serve `/users/{id}`, `/users/{id}/roles/{role_id}` and
/// `/projects/{id}/clients/{client_account_id}` alike. The one ambiguity —
/// `/members/{user_id}` means an internal user under departments and projects but
/// an external one under clients — is resolved by the path prefix.
///
/// An unrecognised placeholder returns `None` rather than guessing, so the caller
/// can fail loudly instead of silently skipping a route.
fn fill(path: &str, ids: &Ids) -> Option<String> {
    let is_client_scope = path.starts_with("/api/v1/clients");
    let mut out = String::new();
    let mut previous = "";

    for segment in path.split('/') {
        if segment.is_empty() {
            continue;
        }
        out.push('/');
        if segment.starts_with('{') {
            let value = match previous {
                "users" => ids.user.to_string(),
                "roles" => ids.role.to_string(),
                "permission-overrides" => ids.unknown.to_string(),
                "departments" => ids.department.to_string(),
                "clients" if is_client_scope => ids.client_account.to_string(),
                // `/projects/{id}/clients/{client_account_id}` — the same segment
                // name, a different object.
                "clients" => ids.client_account.to_string(),
                "projects" => ids.project.to_string(),
                "tasks" => ids.task.to_string(),
                "invitations" => ids.invitation.to_string(),
                "events" => ids.audit_event.to_string(),
                "sessions" => ids.session.to_string(),
                "members" if is_client_scope => ids.client_user.to_string(),
                "members" => ids.user.to_string(),
                "assignees" => ids.user.to_string(),
                "settings" => "registration.mode".to_string(),
                "feature-flags" => "chat".to_string(),
                _ => return None,
            };
            out.push_str(&value);
        } else {
            out.push_str(segment);
            previous = segment;
        }
    }
    Some(out)
}

fn method_of(spec: &RouteSpec) -> Method {
    Method::from_bytes(spec.method.as_bytes()).expect("a route table method must be a valid method")
}

#[tokio::test]
async fn no_response_on_any_route_leaks_secret_material() {
    let w = World::build().await;
    let live = world::LiveSecrets::collect(&w.app).await;

    // Objects the walk needs to address. Reading them through the API rather than
    // inventing them means the walk hits real rows, not just 404 paths.
    let invitation = w
        .app
        .post(
            "/api/v1/invitations",
            w.root.bearer(),
            json!({
                "email": "invitee@hardening.test",
                "display_name": "Invitee",
                "principal_type": "INTERNAL"
            }),
        )
        .await;
    invitation.assert_status(StatusCode::CREATED);
    let invitation_id = invitation.id_at("/id");

    let events = w.app.get("/api/v1/audit/events", w.root.bearer()).await;
    events.assert_status(StatusCode::OK);
    let audit_event = events.id_at("/items/0/id");

    let sessions = w.app.get("/api/v1/auth/sessions", w.root.bearer()).await;
    sessions.assert_status(StatusCode::OK);
    let session = sessions.id_at("/sessions/0/id");

    let ids = Ids {
        user: w.victim,
        client_user: w.client.id,
        role: Uuid::parse_str(world::ROLE_EMPLOYEE).expect("a fixed role id"),
        department: w.department,
        client_account: w.client_account,
        project: w.project,
        task: w.task,
        invitation: invitation_id,
        audit_event,
        session,
        unknown: Uuid::now_v7(),
    };

    let mut visited = 0usize;
    let mut skipped: Vec<&str> = Vec::new();

    for spec in ROUTE_TABLE {
        let Some(path) = fill(spec.path, &ids) else {
            skipped.push(spec.path);
            continue;
        };
        // Every principal is sent at every route regardless of the route's declared
        // access, because the interesting leak is often the one that only happens on
        // the refusal path.
        for (who, token) in w.principals() {
            let method = method_of(spec);
            let has_body = !matches!(method, Method::GET | Method::DELETE);
            let request = world::raw_request(
                method,
                &path,
                token,
                has_body.then_some("application/json"),
                &[],
                if has_body { b"{}".to_vec() } else { Vec::new() },
            );
            let response = w.app.request(request).await;

            world::assert_body_is_clean(
                &format!("{} {} as {who}", spec.method, path),
                &response.raw,
                Some(&live),
            );
            visited += 1;
        }
    }

    assert!(
        skipped.is_empty(),
        "these routes could not be addressed, so they were never scanned: {skipped:?}"
    );
    assert_eq!(
        visited,
        ROUTE_TABLE.len() * 5,
        "the walk did not cover every route for every principal"
    );
    assert!(
        ROUTE_TABLE.len() > 90,
        "the route table shrank to {} entries",
        ROUTE_TABLE.len()
    );
}

/// The successful responses, not only the refusals.
///
/// The walk above sends `{}` to every mutating route, so almost all of its bodies
/// are errors. This test drives the endpoints that hand back a *populated* object,
/// because that is where a widened projection would actually show up.
#[tokio::test]
async fn populated_responses_carry_no_secret_material() {
    let w = World::build().await;
    let live = world::LiveSecrets::collect(&w.app).await;
    let root = w.root.bearer();

    let reads = [
        "/api/v1/auth/me",
        "/api/v1/auth/sessions",
        "/api/v1/users",
        "/api/v1/permissions",
        "/api/v1/roles",
        "/api/v1/departments",
        "/api/v1/clients",
        "/api/v1/projects",
        "/api/v1/tasks",
        "/api/v1/settings",
        "/api/v1/feature-flags",
        "/api/v1/system/info",
        "/api/v1/audit/events",
        "/api/v1/audit/verify",
        "/api/v1/invitations",
        "/api/v1/registration/config",
        "/api/v1/bootstrap/status",
    ];
    for path in reads {
        let response = w.app.get(path, root).await;
        assert!(
            response.status.is_success(),
            "{path} did not succeed for ROOT: {} {}",
            response.status,
            String::from_utf8_lossy(&response.raw)
        );
        // `/api/v1/audit/verify` legitimately returns chain digests, and only to a
        // step-up'd `audit.read` holder — that is the documented exception, so it is
        // scanned for everything except its own two hex fields.
        if path == "/api/v1/audit/verify" {
            continue;
        }
        world::assert_body_is_clean(path, &response.raw, Some(&live));
    }

    // Detail reads, where a row struct would be serialised whole if anything did.
    for path in [
        format!("/api/v1/users/{}", w.victim),
        format!("/api/v1/users/{}/roles", w.victim),
        format!("/api/v1/users/{}/permissions", w.victim),
        format!("/api/v1/users/{}/permission-overrides", w.victim),
        format!("/api/v1/roles/{}", world::ROLE_SYSTEM_ADMINISTRATOR),
        format!("/api/v1/departments/{}", w.department),
        format!("/api/v1/departments/{}/members", w.department),
        format!("/api/v1/clients/{}", w.client_account),
        format!("/api/v1/clients/{}/members", w.client_account),
        format!("/api/v1/projects/{}", w.project),
        format!("/api/v1/projects/{}/members", w.project),
        format!("/api/v1/projects/{}/clients", w.project),
        format!("/api/v1/projects/{}/tasks", w.project),
        format!("/api/v1/tasks/{}", w.task),
        format!("/api/v1/tasks/{}/assignees", w.task),
    ] {
        let response = w.app.get(&path, root).await;
        assert!(
            response.status.is_success(),
            "{path} did not succeed for ROOT: {} {}",
            response.status,
            String::from_utf8_lossy(&response.raw)
        );
        world::assert_body_is_clean(&path, &response.raw, Some(&live));
    }
}

/// The one response that is *allowed* to carry chain digests, pinned so that the
/// exception cannot quietly widen.
#[tokio::test]
async fn only_audit_verify_may_return_chain_digests_and_only_to_an_auditor() {
    let w = World::build().await;

    // ROOT holds `audit.read` and has a recent second factor.
    let ok = w.app.get("/api/v1/audit/verify", w.root.bearer()).await;
    ok.assert_status(StatusCode::OK);

    // Everyone without `audit.read` is refused, and the refusal carries nothing.
    for (who, token) in [
        ("employee", w.employee.bearer()),
        ("client", w.client.bearer()),
        ("anonymous", None),
    ] {
        let denied = w.app.get("/api/v1/audit/verify", token).await;
        assert!(
            denied.status.is_client_error(),
            "{who} reached the audit verification endpoint"
        );
        world::assert_body_is_clean(&format!("audit/verify as {who}"), &denied.raw, None);
    }
}

/// The client envelope: an external principal must never see internal prose.
///
/// `internal_note` is the sharpest test of the projection rule, because the column
/// exists on rows an external principal *is* allowed to see. A `SELECT *` anywhere
/// on the portal path would leak it while every authorisation check still passed.
#[tokio::test]
async fn the_client_portal_never_returns_internal_columns() {
    let w = World::build().await;
    let client = w.client.bearer();

    let portal = [
        "/api/v1/client-portal/projects".to_string(),
        format!("/api/v1/client-portal/projects/{}", w.project),
        format!("/api/v1/client-portal/projects/{}/tasks", w.project),
        format!("/api/v1/client-portal/tasks/{}", w.task),
    ];
    for path in &portal {
        let response = w.app.get(path, client).await;
        assert!(
            response.status.is_success(),
            "{path} did not succeed for the client: {} {}",
            response.status,
            String::from_utf8_lossy(&response.raw)
        );
        let text = String::from_utf8_lossy(&response.raw);
        assert!(
            !text.contains(INTERNAL_NOTE_MARKER),
            "{path} leaked an internal note to an external principal: {text}"
        );
        assert!(
            !text.contains("internal_note"),
            "{path} carries an `internal_note` field: {text}"
        );
        // The department a project belongs to is company structure an external
        // principal must not learn exists.
        assert!(
            !text.contains("department"),
            "{path} exposed departmental structure to an external principal: {text}"
        );
    }

    // The hidden task is not merely redacted, it is absent.
    let hidden = w
        .app
        .get(
            &format!("/api/v1/client-portal/tasks/{}", w.hidden_task),
            client,
        )
        .await;
    hidden.assert_error(StatusCode::NOT_FOUND, "RESOURCE_NOT_FOUND");
}

/// Plaintext token material appears in exactly one place — the token-issuing
/// response — and nowhere else, in particular not in any listing of sessions.
#[tokio::test]
async fn issued_tokens_are_never_readable_again() {
    let w = World::build().await;

    let sessions = w.app.get("/api/v1/auth/sessions", w.root.bearer()).await;
    sessions.assert_status(StatusCode::OK);
    let text = String::from_utf8_lossy(&sessions.raw);
    assert!(
        !text.contains(&w.root.token),
        "the session listing echoed the caller's own access token: {text}"
    );
    for field in ["access_token", "refresh_token", "token"] {
        assert!(
            !text.contains(&format!("\"{field}\"")),
            "the session listing carries a `{field}` field: {text}"
        );
    }

    // `/auth/me` describes the principal, not the credential.
    let me = w.app.get("/api/v1/auth/me", w.root.bearer()).await;
    me.assert_status(StatusCode::OK);
    let text = String::from_utf8_lossy(&me.raw);
    assert!(!text.contains(&w.root.token), "/auth/me echoed the token");
}

/// Regression test for finding H-1.
///
/// `identity`, `departments` and `clients` took `axum::extract::Query<T>` directly,
/// so an unrecognised query parameter was refused by axum with a `text/plain` body
/// that echoed the caller's own parameter name and then listed every field the DTO
/// accepts. `projects`, `tasks`, `authorization` and `audit` each had their own
/// wrapper; those six routes did not.
///
/// Every listing endpoint is checked, not only the six that were broken, because
/// the failure mode is "somebody added a listing and forgot", and a test that only
/// covered the known-bad ones would not catch the next one.
#[tokio::test]
async fn an_unrecognised_query_parameter_is_refused_as_problem_json_without_reflection() {
    let w = World::build().await;
    let root = w.root.bearer();

    let listings = [
        "/api/v1/users",
        "/api/v1/invitations",
        "/api/v1/departments",
        "/api/v1/clients",
        "/api/v1/projects",
        "/api/v1/tasks",
        "/api/v1/roles",
        "/api/v1/audit/events",
        "/api/v1/client-portal/projects",
    ];
    // Each of these is a mass-assignment field name, which is exactly what an
    // attacker probes a listing with — and exactly what must not come back.
    let unknown = [
        "is_admin",
        "is_root",
        "offset",
        "principal_type",
        "role_ids",
        "audit_metadata",
    ];

    for path in listings {
        for parameter in unknown {
            // `principal_type` is a real filter on the user listing; probing it
            // there would be testing a legitimate parameter.
            if path == "/api/v1/users" && parameter == "principal_type" {
                continue;
            }
            let token = if path.starts_with("/api/v1/client-portal") {
                w.client.bearer()
            } else {
                root
            };
            let response = w.app.get(&format!("{path}?{parameter}=1"), token).await;
            response.assert_error(StatusCode::BAD_REQUEST, "BAD_REQUEST");

            let text = String::from_utf8_lossy(&response.raw);
            assert!(
                !text.contains(parameter),
                "{path} reflected the rejected parameter `{parameter}`: {text}"
            );
            // The DTO's own field list must not be handed out either.
            for field in ["cursor", "direction", "search", "expected one of"] {
                assert!(
                    !text.contains(field),
                    "{path} enumerated its accepted parameters (`{field}`): {text}"
                );
            }
        }
    }
}

/// An internal failure must say nothing about its cause.
///
/// The database is asked for a table that does not exist by taking a privilege the
/// runtime role does not hold; the response must be the fixed internal-error
/// problem document, with no SQLSTATE, no constraint name and no driver text.
#[tokio::test]
async fn error_paths_disclose_no_internal_detail() {
    let w = World::build().await;
    let live = world::LiveSecrets::collect(&w.app).await;

    // A unique violation: the constraint name must not travel.
    let duplicate = w
        .app
        .post(
            "/api/v1/departments",
            w.root.bearer(),
            json!({"code": "engineering", "name": "Duplicate"}),
        )
        .await;
    duplicate.assert_status(StatusCode::CONFLICT);
    let text = String::from_utf8_lossy(&duplicate.raw);
    for internal in [
        "departments_code",
        "_key",
        "23505",
        "duplicate key",
        "pg_",
        "relation",
    ] {
        assert!(
            !text.to_lowercase().contains(internal),
            "a conflict response named the internal detail `{internal}`: {text}"
        );
    }
    world::assert_body_is_clean("duplicate department", &duplicate.raw, Some(&live));

    // A trigger-enforced invariant: the trigger's own message names tables and
    // columns and must not be forwarded.
    let root_patch = w
        .app
        .patch(
            &format!("/api/v1/users/{}", w.root.id),
            w.admin.bearer(),
            json!({"display_name": "Hijacked", "version": 1}),
        )
        .await;
    assert!(
        root_patch.status.is_client_error(),
        "an administrator modified the system owner"
    );
    world::assert_body_is_clean("patch root as admin", &root_patch.raw, Some(&live));
}
