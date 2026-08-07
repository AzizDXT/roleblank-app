//! What each scope actually returns from every list endpoint.
//!
//! This is where a filtering bug becomes a data leak. A narrower-than-`GLOBAL`
//! grant does not authorise "list everything" — it turns the listing into a
//! *filtered query*, and the filter is a SQL predicate rather than a loop in Rust.
//! So the assertions here are exact set equality: not "contains what it should"
//! but "contains what it should **and nothing else**". A test that only checked
//! the positive half would pass against an endpoint that returned the whole table.
//!
//! # The fixture is deliberately awkward
//!
//! The subject is a member of department **alpha**, a member of project **beta**
//! (which belongs to department *beta*), and the assignee of a task in project
//! **orphan** (which belongs to no department at all). Nothing lines up. That is
//! the point: with a tidier world, `DEPARTMENT` and `ASSIGNED` would return the
//! same rows and a bug that confused the two would pass every test.
//!
//! # `SELF` is the trap
//!
//! `SELF` names the actor's own *user record*. A project is not a user, so a
//! `projects.read@SELF` grant must reach no project at all. The failure mode it
//! guards against is treating "this scope contributes no rows" as "this scope
//! imposes no filter", which turns a self-service grant into an
//! organisation-wide one in a single missing `else`.

use axum::http::StatusCode;
use serde_json::json;
use uuid::Uuid;

use crate::common::{TestApp, TestResponse};
use crate::fixtures::*;

/// Every permission the scope tests need, granted at exactly one scope.
const SCOPED_PERMISSIONS: &[&str] = &[
    "departments.read",
    "projects.read",
    "tasks.read",
    "clients.read",
    "iam.users.read",
];

struct World {
    alpha: Uuid,
    beta: Uuid,
    project_alpha: Uuid,
    project_beta: Uuid,
    project_orphan: Uuid,
    task_alpha: Uuid,
    task_beta: Uuid,
    task_orphan: Uuid,
    client_managed: Uuid,
    client_other: Uuid,
}

async fn build_world(app: &TestApp, root: &Actor) -> World {
    let alpha = create_department(app, &root.token, "alpha", "Alpha").await;
    let beta = create_department(app, &root.token, "beta", "Beta").await;

    let project_alpha =
        create_project(app, &root.token, "p-alpha", root.user_id, Some(alpha)).await;
    let project_beta = create_project(app, &root.token, "p-beta", root.user_id, Some(beta)).await;
    let project_orphan = create_project(app, &root.token, "p-orphan", root.user_id, None).await;

    let task_alpha = create_task(app, &root.token, project_alpha, "Alpha work").await;
    let task_beta = create_task(app, &root.token, project_beta, "Beta work").await;
    let task_orphan = create_task(app, &root.token, project_orphan, "Orphan work").await;

    let client_managed = create_client_account(app, &root.token, "managed", "Managed").await;
    let client_other = create_client_account(app, &root.token, "other", "Other").await;

    World {
        alpha,
        beta,
        project_alpha,
        project_beta,
        project_orphan,
        task_alpha,
        task_beta,
        task_orphan,
        client_managed,
        client_other,
    }
}

/// Build a subject holding [`SCOPED_PERMISSIONS`] at exactly `scope` and nothing
/// else.
///
/// The seeded `employee` role is deliberately **not** used: it already carries
/// `projects.read@ASSIGNED` and `departments.read@DEPARTMENT`, and the union of
/// those with the scope under test would make every result explainable by two
/// different grants at once.
async fn subject_with(app: &TestApp, root: &Actor, world: &World, scope: &str) -> Actor {
    let permissions: Vec<(&str, &str)> = SCOPED_PERMISSIONS
        .iter()
        .map(|code| (*code, scope))
        .collect();
    let role = create_role(
        app,
        &root.token,
        &format!("scoped_{}", scope.to_lowercase()),
        "INTERNAL",
        &permissions,
    )
    .await;

    let subject = create_user(
        app,
        &root.token,
        "subject@roleblank.test",
        "Subject",
        "INTERNAL",
        &[role],
        // Member of alpha — and of nothing else.
        Some(world.alpha),
        None,
    )
    .await;

    // Member of a project in the *other* department, so `DEPARTMENT` and
    // `ASSIGNED` can never be satisfied by the same row.
    app.post(
        &format!("/api/v1/projects/{}/members", world.project_beta),
        Some(&root.token),
        json!({"user_id": subject.user_id}),
    )
    .await
    .assert_status(StatusCode::NO_CONTENT);

    // Assignee of a task in a *third* project. Being a member of a project is not
    // an assignment, and treating it as one would widen every `tasks.*@ASSIGNED`
    // grant to the whole project.
    app.post(
        &format!("/api/v1/tasks/{}/assignees", world.task_orphan),
        Some(&root.token),
        json!({"user_id": subject.user_id}),
    )
    .await
    .assert_status(StatusCode::NO_CONTENT);

    // "Assigned" for a client account means account manager: the membership table
    // holds external users only, so that column is the only relationship an
    // internal actor can have with the row.
    app.patch(
        &format!("/api/v1/clients/{}", world.client_managed),
        Some(&root.token),
        json!({"version": 1, "account_manager_user_id": subject.user_id}),
    )
    .await
    .assert_status(StatusCode::OK);

    subject
}

#[track_caller]
fn assert_exactly(response: &TestResponse, expected: &[Uuid], what: &str) {
    response.assert_status(StatusCode::OK).assert_no_secrets();
    let mut got = ids_in(response);
    got.sort();
    let mut want = expected.to_vec();
    want.sort();
    assert_eq!(got, want, "{what} returned the wrong set of rows");
}

// ===========================================================================
// GLOBAL
// ===========================================================================

/// The control case. `GLOBAL` is the only scope that covers `Target::Collection`,
/// so it is the only one that produces an unfiltered listing — every other test in
/// this file is a statement about how much *less* than this a narrower grant sees.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_global_grant_lists_every_row_and_nothing_more() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let world = build_world(&app, &root).await;
    let subject = subject_with(&app, &root, &world, "GLOBAL").await;
    let token = Some(subject.token.as_str());

    assert_exactly(
        &app.get("/api/v1/departments", token).await,
        &[world.alpha, world.beta],
        "departments@GLOBAL",
    );
    assert_exactly(
        &app.get("/api/v1/projects", token).await,
        &[
            world.project_alpha,
            world.project_beta,
            world.project_orphan,
        ],
        "projects@GLOBAL",
    );
    assert_exactly(
        &app.get("/api/v1/tasks", token).await,
        &[world.task_alpha, world.task_beta, world.task_orphan],
        "tasks@GLOBAL",
    );
    assert_exactly(
        &app.get("/api/v1/clients", token).await,
        &[world.client_managed, world.client_other],
        "clients@GLOBAL",
    );
    assert_exactly(
        &app.get("/api/v1/users", token).await,
        &[root.user_id, subject.user_id],
        "users@GLOBAL",
    );
}

// ===========================================================================
// DEPARTMENT
// ===========================================================================

/// `DEPARTMENT` reaches the rows whose department the actor is a live member of —
/// and, importantly, *not* the project they happen to be a member of, because that
/// project belongs to a department they are not in.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_department_grant_lists_only_the_actors_own_department() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let world = build_world(&app, &root).await;
    let subject = subject_with(&app, &root, &world, "DEPARTMENT").await;
    let token = Some(subject.token.as_str());

    assert_exactly(
        &app.get("/api/v1/departments", token).await,
        &[world.alpha],
        "departments@DEPARTMENT",
    );

    // Project *beta* is one the subject is a member of. A DEPARTMENT grant does not
    // reach it: DEPARTMENT and ASSIGNED are incomparable, and confusing them is a
    // silent lateral escalation.
    assert_exactly(
        &app.get("/api/v1/projects", token).await,
        &[world.project_alpha],
        "projects@DEPARTMENT",
    );

    // A task has no department of its own; the decision resolves through its
    // project. The orphan project has none, so its task is out of reach even though
    // the subject is its assignee.
    assert_exactly(
        &app.get("/api/v1/tasks", token).await,
        &[world.task_alpha],
        "tasks@DEPARTMENT",
    );

    // A user listing filtered by department reaches the department's members. Root
    // belongs to no department, so it is not among them.
    assert_exactly(
        &app.get("/api/v1/users", token).await,
        &[subject.user_id],
        "users@DEPARTMENT",
    );

    // A client account belongs to no department at all, so a DEPARTMENT grant
    // reaches none — and that is a refusal rather than a silently empty page.
    app.get("/api/v1/clients", token)
        .await
        .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");
}

/// The object-level decision and the listing must agree. A row the listing hides
/// must also be unreachable by its identifier, or the filter is cosmetic.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_department_grant_cannot_reach_a_hidden_row_by_its_identifier() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let world = build_world(&app, &root).await;
    let subject = subject_with(&app, &root, &world, "DEPARTMENT").await;
    let token = Some(subject.token.as_str());

    app.get(&format!("/api/v1/departments/{}", world.alpha), token)
        .await
        .assert_status(StatusCode::OK);
    app.get(&format!("/api/v1/departments/{}", world.beta), token)
        .await
        .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");

    app.get(&format!("/api/v1/projects/{}", world.project_alpha), token)
        .await
        .assert_status(StatusCode::OK);
    app.get(&format!("/api/v1/projects/{}", world.project_beta), token)
        .await
        .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");
    app.get(&format!("/api/v1/projects/{}", world.project_orphan), token)
        .await
        .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");

    app.get(&format!("/api/v1/tasks/{}", world.task_alpha), token)
        .await
        .assert_status(StatusCode::OK);
    app.get(&format!("/api/v1/tasks/{}", world.task_beta), token)
        .await
        .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");
    app.get(&format!("/api/v1/tasks/{}", world.task_orphan), token)
        .await
        .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");
}

/// Leaving the department must remove the authority immediately: the actor context
/// is loaded fresh on every request and there is nothing to invalidate.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn leaving_the_department_empties_a_department_scoped_listing_at_once() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let world = build_world(&app, &root).await;
    let subject = subject_with(&app, &root, &world, "DEPARTMENT").await;
    let token = Some(subject.token.as_str());

    assert_exactly(
        &app.get("/api/v1/projects", token).await,
        &[world.project_alpha],
        "projects@DEPARTMENT before removal",
    );

    app.delete(
        &format!(
            "/api/v1/departments/{}/members/{}",
            world.alpha, subject.user_id
        ),
        Some(&root.token),
    )
    .await
    .assert_status(StatusCode::NO_CONTENT);

    // A department-scoped actor who is in no department sees nothing — never "no
    // filter", which is how a narrow grant becomes a global one.
    let projects = app.get("/api/v1/projects", token).await;
    projects.assert_status(StatusCode::OK);
    assert!(ids_in(&projects).is_empty());

    // The departments module makes the stricter choice for the same state: a
    // listing that can match nothing is a denial rather than an empty page.
    app.get("/api/v1/departments", token)
        .await
        .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");
}

// ===========================================================================
// ASSIGNED
// ===========================================================================

/// `ASSIGNED` reaches the rows the actor is actually attached to — a live project
/// membership for a project, a live *task assignment* for a task. Project
/// membership is not a task assignment: treating it as one would widen every
/// `tasks.*@ASSIGNED` grant to the whole project.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_assigned_grant_lists_only_the_rows_the_actor_is_attached_to() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let world = build_world(&app, &root).await;
    let subject = subject_with(&app, &root, &world, "ASSIGNED").await;
    let token = Some(subject.token.as_str());

    assert_exactly(
        &app.get("/api/v1/projects", token).await,
        &[world.project_beta],
        "projects@ASSIGNED",
    );

    // The subject is a *member of project beta* and the *assignee of the orphan
    // task*. Only the second one counts here.
    assert_exactly(
        &app.get("/api/v1/tasks", token).await,
        &[world.task_orphan],
        "tasks@ASSIGNED",
    );

    // "Assigned" for a client account means the account manager column.
    assert_exactly(
        &app.get("/api/v1/clients", token).await,
        &[world.client_managed],
        "clients@ASSIGNED",
    );

    // A department has no membership relation of its own that differs from
    // department membership, so ASSIGNED resolves through the same set as
    // DEPARTMENT there.
    assert_exactly(
        &app.get("/api/v1/departments", token).await,
        &[world.alpha],
        "departments@ASSIGNED",
    );

    // A user record has no assignment relation at all, so the grant reaches no
    // user — and the listing refuses rather than returning an empty page.
    app.get("/api/v1/users", token)
        .await
        .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_assigned_grant_cannot_reach_a_row_it_is_not_attached_to() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let world = build_world(&app, &root).await;
    let subject = subject_with(&app, &root, &world, "ASSIGNED").await;
    let token = Some(subject.token.as_str());

    app.get(&format!("/api/v1/projects/{}", world.project_beta), token)
        .await
        .assert_status(StatusCode::OK);
    for hidden in [world.project_alpha, world.project_orphan] {
        app.get(&format!("/api/v1/projects/{hidden}"), token)
            .await
            .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");
    }

    app.get(&format!("/api/v1/tasks/{}", world.task_orphan), token)
        .await
        .assert_status(StatusCode::OK);
    for hidden in [world.task_alpha, world.task_beta] {
        app.get(&format!("/api/v1/tasks/{hidden}"), token)
            .await
            .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");
    }

    app.get(&format!("/api/v1/clients/{}", world.client_managed), token)
        .await
        .assert_status(StatusCode::OK);
    app.get(&format!("/api/v1/clients/{}", world.client_other), token)
        .await
        .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");
}

/// Removal takes the authority away on the very next query — the assignment is the
/// authority, and nothing caches it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unassigning_removes_an_assigned_row_from_the_listing_at_once() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let world = build_world(&app, &root).await;
    let subject = subject_with(&app, &root, &world, "ASSIGNED").await;
    let token = Some(subject.token.as_str());

    assert_exactly(
        &app.get("/api/v1/tasks", token).await,
        &[world.task_orphan],
        "tasks@ASSIGNED before unassignment",
    );

    app.delete(
        &format!(
            "/api/v1/tasks/{}/assignees/{}",
            world.task_orphan, subject.user_id
        ),
        Some(&root.token),
    )
    .await
    .assert_status(StatusCode::NO_CONTENT);

    let tasks = app.get("/api/v1/tasks", token).await;
    tasks.assert_status(StatusCode::OK);
    assert!(ids_in(&tasks).is_empty());
    app.get(&format!("/api/v1/tasks/{}", world.task_orphan), token)
        .await
        .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");
}

// ===========================================================================
// SELF
// ===========================================================================

/// `SELF` names the actor's own user record and nothing else. A project is not a
/// user, so a `projects.read@SELF` grant reaches **no project at all** — not every
/// project, which is what "this scope contributes no rows" silently becomes if it
/// is ever read as "this scope imposes no filter".
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_self_grant_reaches_the_actors_own_record_and_no_business_row() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let world = build_world(&app, &root).await;
    let subject = subject_with(&app, &root, &world, "SELF").await;
    let token = Some(subject.token.as_str());

    assert_exactly(
        &app.get("/api/v1/users", token).await,
        &[subject.user_id],
        "users@SELF",
    );

    // Even though the subject is a member of project beta and the assignee of the
    // orphan task: the scope does not reach a project or a task at all, so those
    // relationships contribute nothing.
    let projects = app.get("/api/v1/projects", token).await;
    projects.assert_status(StatusCode::OK).assert_no_secrets();
    assert!(
        ids_in(&projects).is_empty(),
        "a SELF grant listed a project"
    );

    let tasks = app.get("/api/v1/tasks", token).await;
    tasks.assert_status(StatusCode::OK);
    assert!(ids_in(&tasks).is_empty(), "a SELF grant listed a task");

    // The departments and clients modules make the stricter choice for the same
    // state: nothing reachable is a denial rather than an empty page.
    app.get("/api/v1/departments", token)
        .await
        .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");
    app.get("/api/v1/clients", token)
        .await
        .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_self_grant_cannot_reach_another_persons_record_or_any_business_row() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let world = build_world(&app, &root).await;
    let subject = subject_with(&app, &root, &world, "SELF").await;
    let token = Some(subject.token.as_str());

    app.get(&format!("/api/v1/users/{}", subject.user_id), token)
        .await
        .assert_status(StatusCode::OK);
    app.get(&format!("/api/v1/users/{}", root.user_id), token)
        .await
        .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");

    for path in [
        format!("/api/v1/departments/{}", world.alpha),
        format!("/api/v1/projects/{}", world.project_beta),
        format!("/api/v1/tasks/{}", world.task_orphan),
        format!("/api/v1/clients/{}", world.client_managed),
    ] {
        app.get(&path, token)
            .await
            .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");
    }
}

// ===========================================================================
// Cross-cutting
// ===========================================================================

/// A `RESOURCE`-scoped override names exactly one object of exactly one type. It
/// cannot live on a role — a role is a reusable template — so it is the one scope
/// that only reaches a listing through a per-user exception.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_resource_grant_lists_exactly_the_object_it_names() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let world = build_world(&app, &root).await;
    let subject = subject_with(&app, &root, &world, "SELF").await;
    let token = Some(subject.token.as_str());

    app.post(
        &format!("/api/v1/users/{}/permission-overrides", subject.user_id),
        Some(&root.token),
        json!({
            "permission_code": "projects.read",
            "effect": "ALLOW",
            "scope": "RESOURCE",
            "resource_type": "PROJECT",
            "resource_id": world.project_alpha,
        }),
    )
    .await
    .assert_status(StatusCode::CREATED);

    assert_exactly(
        &app.get("/api/v1/projects", token).await,
        &[world.project_alpha],
        "projects@RESOURCE",
    );

    // A grant naming a project says nothing about a task, even one inside it.
    let tasks = app.get("/api/v1/tasks", token).await;
    tasks.assert_status(StatusCode::OK);
    assert!(ids_in(&tasks).is_empty());
}

/// Pagination must not widen the filter. A caller cannot page past the end of what
/// their scope covers into rows it does not.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn paging_never_walks_out_of_the_scope() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let world = build_world(&app, &root).await;
    let subject = subject_with(&app, &root, &world, "DEPARTMENT").await;
    let token = Some(subject.token.as_str());

    // The whole scope holds one project; asking for a page of one must still report
    // that there is no more, rather than offering a cursor into the rest of the
    // table.
    let page = app
        .get(
            "/api/v1/projects?sort=created_at&direction=asc&limit=1",
            token,
        )
        .await;
    assert_exactly(&page, &[world.project_alpha], "projects@DEPARTMENT page 1");
    assert_eq!(page.json()["has_more"], json!(false));
    assert_eq!(page.json()["next_cursor"], json!(null));

    // A cursor minted by an unrestricted reader does not widen a narrow one: the
    // scope predicate is applied to every page, not only the first.
    let root_page = app
        .get(
            "/api/v1/projects?sort=created_at&direction=asc&limit=1",
            Some(&root.token),
        )
        .await;
    let cursor = root_page.str_at("/next_cursor").to_string();
    let borrowed = app
        .get(
            &format!("/api/v1/projects?sort=created_at&direction=asc&cursor={cursor}"),
            token,
        )
        .await;
    borrowed.assert_status(StatusCode::OK);
    for id in ids_in(&borrowed) {
        assert_eq!(
            id, world.project_alpha,
            "a borrowed cursor let a DEPARTMENT-scoped reader out of its scope"
        );
    }
}

/// An explicit `DENY` is evaluated before the allow set and is never overturned by
/// it, in the listing exactly as in the single-row decision.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_resource_deny_removes_exactly_one_row_from_a_global_listing() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let world = build_world(&app, &root).await;
    let subject = subject_with(&app, &root, &world, "GLOBAL").await;
    let token = Some(subject.token.as_str());

    app.post(
        &format!("/api/v1/users/{}/permission-overrides", subject.user_id),
        Some(&root.token),
        json!({
            "permission_code": "projects.read",
            "effect": "DENY",
            "scope": "RESOURCE",
            "resource_type": "PROJECT",
            "resource_id": world.project_beta,
        }),
    )
    .await
    .assert_status(StatusCode::CREATED);

    assert_exactly(
        &app.get("/api/v1/projects", token).await,
        &[world.project_alpha, world.project_orphan],
        "projects@GLOBAL with one row denied",
    );
    app.get(&format!("/api/v1/projects/{}", world.project_beta), token)
        .await
        .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");
    app.get(&format!("/api/v1/projects/{}", world.project_alpha), token)
        .await
        .assert_status(StatusCode::OK);
}

/// The nested listing is a *filter* on the same query, not a second authorisation
/// path: narrowing to one project must never show a task the unnested listing
/// would have hidden.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_nested_project_task_listing_applies_the_same_scope() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let world = build_world(&app, &root).await;
    let subject = subject_with(&app, &root, &world, "ASSIGNED").await;
    let token = Some(subject.token.as_str());

    // The subject is a member of project beta but is assigned to none of its tasks.
    let nested = app
        .get(
            &format!("/api/v1/projects/{}/tasks", world.project_beta),
            token,
        )
        .await;
    nested.assert_status(StatusCode::OK);
    assert!(
        ids_in(&nested).is_empty(),
        "project membership must not stand in for a task assignment"
    );

    // And the project they cannot see at all yields nothing rather than an error
    // that would confirm the project exists.
    let hidden = app
        .get(
            &format!("/api/v1/projects/{}/tasks", world.project_alpha),
            token,
        )
        .await;
    hidden.assert_status(StatusCode::OK);
    assert!(ids_in(&hidden).is_empty());

    let own = app
        .get(
            &format!("/api/v1/projects/{}/tasks", world.project_orphan),
            token,
        )
        .await;
    assert_exactly(&own, &[world.task_orphan], "nested tasks@ASSIGNED");
}

/// A grant is meaningless without a scope that reaches the target, and the two
/// sides of the system must agree about that. The listing and the object-level
/// decision are derived from the same facts, so a row that the filter admits must
/// also survive `require`, and vice versa — this walks every scope and checks both
/// directions in one place.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_listing_and_the_object_decision_never_disagree_about_projects() {
    // A separate world per scope, because the subject's grants are what differ and
    // two subjects in one world would each have to be told to ignore the other's.
    for scope in ["GLOBAL", "DEPARTMENT", "ASSIGNED", "SELF"] {
        let app = TestApp::spawn().await;
        let root = bootstrap_root(&app).await;
        let world = build_world(&app, &root).await;
        let subject = subject_with(&app, &root, &world, scope).await;
        let token = Some(subject.token.as_str());

        let listed = app.get("/api/v1/projects", token).await;
        listed.assert_status(StatusCode::OK);
        let visible = ids_in(&listed);

        for project in [
            world.project_alpha,
            world.project_beta,
            world.project_orphan,
        ] {
            let detail = app.get(&format!("/api/v1/projects/{project}"), token).await;
            if visible.contains(&project) {
                assert_eq!(
                    detail.status,
                    StatusCode::OK,
                    "{scope}: the listing showed {project} but the detail endpoint refused it"
                );
            } else {
                assert_eq!(
                    detail.status,
                    StatusCode::FORBIDDEN,
                    "{scope}: the listing hid {project} but the detail endpoint served it"
                );
            }
        }
    }
}
