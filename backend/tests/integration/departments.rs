//! `/api/v1/departments` — every endpoint, every documented refusal.
//!
//! Department membership is not an organisational nicety: it is what resolves
//! `DEPARTMENT` scope, so adding and removing a member is an authorisation
//! operation. That is why the membership tests here assert against the row rather
//! than against the response — a `204` says the request was accepted, and only
//! `removed_at IS NOT NULL` says the authority actually went away.

use axum::http::StatusCode;
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::common::TestApp;
use crate::fixtures::*;

// ---------------------------------------------------------------------------
// Row readers
// ---------------------------------------------------------------------------

async fn status_of(app: &TestApp, id: Uuid) -> String {
    sqlx::query_scalar("SELECT status FROM departments WHERE id = $1")
        .bind(id)
        .fetch_one(&app.db)
        .await
        .expect("the department row")
}

async fn version_of(app: &TestApp, id: Uuid) -> i32 {
    sqlx::query_scalar("SELECT version FROM departments WHERE id = $1")
        .bind(id)
        .fetch_one(&app.db)
        .await
        .expect("the department row")
}

async fn live_membership_count(app: &TestApp, department_id: Uuid, user_id: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM department_memberships
          WHERE department_id = $1 AND user_id = $2 AND removed_at IS NULL",
    )
    .bind(department_id)
    .bind(user_id)
    .fetch_one(&app.db)
    .await
    .expect("count live memberships")
}

async fn total_membership_rows(app: &TestApp, department_id: Uuid, user_id: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM department_memberships WHERE department_id = $1 AND user_id = $2",
    )
    .bind(department_id)
    .bind(user_id)
    .fetch_one(&app.db)
    .await
    .expect("count membership rows")
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_stores_an_active_department_at_version_one() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;

    let created = app
        .post(
            "/api/v1/departments",
            Some(&root.token),
            json!({"code": "OPS", "name": "Operations", "description": "Runs things"}),
        )
        .await;
    created
        .assert_status(StatusCode::CREATED)
        .assert_no_secrets();

    // `code` is a machine identifier and is normalised to lower case, so a saved
    // link cannot be broken by the case a human happened to type.
    assert_eq!(created.str_at("/code"), "ops");
    assert_eq!(created.str_at("/status"), "ACTIVE");
    assert_eq!(created.json()["version"], json!(1));
    assert_eq!(created.id_at("/created_by"), root.user_id);
    assert_eq!(created.json()["archived_at"], json!(null));

    let id = created.id_at("/id");
    assert_eq!(status_of(&app, id).await, "ACTIVE");
    assert_eq!(audit_count_for(&app, "DEPARTMENT.CREATED", id).await, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn read_returns_the_stored_row() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let id = create_department(&app, &root.token, "ops", "Operations").await;

    let found = app
        .get(&format!("/api/v1/departments/{id}"), Some(&root.token))
        .await;
    found.assert_status(StatusCode::OK).assert_no_secrets();
    assert_eq!(found.id_at("/id"), id);
    assert_eq!(found.str_at("/name"), "Operations");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn read_of_an_unknown_department_is_not_found() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    app.get(
        &format!("/api/v1/departments/{}", Uuid::now_v7()),
        Some(&root.token),
    )
    .await
    .assert_error(StatusCode::NOT_FOUND, "RESOURCE_NOT_FOUND");
}

/// A malformed path parameter must be refused before any handler runs, so it can
/// never reach a query or a permission decision.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_malformed_identifier_never_reaches_the_handler() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let response = app
        .get("/api/v1/departments/not-a-uuid", Some(&root.token))
        .await;
    response
        .assert_status(StatusCode::BAD_REQUEST)
        .assert_no_secrets();

    // Nothing was read and nothing was written: the request died in the extractor.
    let (count,): (i64,) = sqlx::query_as("SELECT count(*) FROM departments")
        .fetch_one(&app.db)
        .await
        .expect("count departments");
    assert_eq!(count, 0);

    // The `code`/`application/problem+json` contract is deliberately NOT asserted
    // here, and that is a finding rather than an omission: this route extracts
    // `Path<Uuid>`, so the rejection is axum's own `text/plain` body, which names
    // the Rust field and echoes the caller's value back. `authorization::routes`
    // and `audit::routes` parse `Path<String>` by hand precisely to avoid that —
    // see the comments there — and the same treatment has not reached the
    // departments, clients, projects, tasks, identity or settings routers. Pinning
    // the current shape here would cement the deviation; asserting the intended one
    // would fail. Reported instead.
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_paginates_and_honours_the_allowlisted_sort() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;

    let first = create_department(&app, &root.token, "alpha", "Alpha").await;
    let second = create_department(&app, &root.token, "beta", "Beta").await;
    let third = create_department(&app, &root.token, "gamma", "Gamma").await;

    // `created_at` ascending is the only sort the allowlist offers, and the cursor
    // is `(created_at, id)`, so the order is total even for rows created in the
    // same microsecond.
    let page = app
        .get(
            "/api/v1/departments?sort=created_at&direction=asc&limit=2",
            Some(&root.token),
        )
        .await;
    page.assert_status(StatusCode::OK);
    assert_eq!(ids_in(&page), vec![first, second]);
    assert_eq!(page.json()["has_more"], json!(true));

    let cursor = page.str_at("/next_cursor").to_string();
    let rest = app
        .get(
            &format!("/api/v1/departments?sort=created_at&direction=asc&limit=2&cursor={cursor}"),
            Some(&root.token),
        )
        .await;
    rest.assert_status(StatusCode::OK);
    assert_eq!(ids_in(&rest), vec![third]);
    assert_eq!(rest.json()["has_more"], json!(false));
    assert_eq!(rest.json()["next_cursor"], json!(null));
}

/// A sort field outside the allowlist is refused rather than silently ignored: a
/// caller who believes they ordered a page must not be handed a differently
/// ordered one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_refuses_a_sort_field_outside_the_allowlist() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    app.get("/api/v1/departments?sort=name", Some(&root.token))
        .await
        .assert_error(StatusCode::BAD_REQUEST, "VALIDATION_FAILED");
    app.get(
        "/api/v1/departments?sort=created_at;DROP%20TABLE%20users",
        Some(&root.token),
    )
    .await
    .assert_error(StatusCode::BAD_REQUEST, "VALIDATION_FAILED");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_refuses_an_out_of_range_limit_and_a_malformed_cursor() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    for query in ["limit=0", "limit=101", "limit=abc", "cursor=!!!!"] {
        app.get(&format!("/api/v1/departments?{query}"), Some(&root.token))
            .await
            .assert_error(StatusCode::BAD_REQUEST, "VALIDATION_FAILED");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn patch_with_the_current_version_applies_and_advances_it() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let id = create_department(&app, &root.token, "ops", "Operations").await;

    let patched = app
        .patch(
            &format!("/api/v1/departments/{id}"),
            Some(&root.token),
            json!({"version": 1, "name": "Operations and Delivery"}),
        )
        .await;
    patched.assert_status(StatusCode::OK);
    assert_eq!(patched.str_at("/name"), "Operations and Delivery");
    assert_eq!(patched.json()["version"], json!(2));
    assert_eq!(version_of(&app, id).await, 2);
}

/// The lost-update defence. Two clients read version 1; the second write must be
/// refused rather than silently overwriting the first.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn patch_with_a_stale_version_is_a_conflict_and_changes_nothing() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let id = create_department(&app, &root.token, "ops", "Operations").await;

    app.patch(
        &format!("/api/v1/departments/{id}"),
        Some(&root.token),
        json!({"version": 1, "name": "First writer"}),
    )
    .await
    .assert_status(StatusCode::OK);

    app.patch(
        &format!("/api/v1/departments/{id}"),
        Some(&root.token),
        json!({"version": 1, "name": "Second writer"}),
    )
    .await
    .assert_error(StatusCode::CONFLICT, "VERSION_CONFLICT");

    let name: String = sqlx::query_scalar("SELECT name FROM departments WHERE id = $1")
        .bind(id)
        .fetch_one(&app.db)
        .await
        .expect("the department row");
    assert_eq!(name, "First writer", "the stale write must not have landed");
    assert_eq!(version_of(&app, id).await, 2);
}

/// `code` is immutable and `status` is not a field: both are refused by the closed
/// DTO rather than being quietly ignored, which is the mass-assignment defence.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn patch_refuses_an_unknown_or_privileged_field() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let id = create_department(&app, &root.token, "ops", "Operations").await;

    for body in [
        json!({"version": 1, "code": "renamed"}),
        json!({"version": 1, "status": "ARCHIVED"}),
        json!({"version": 1, "created_by": Uuid::now_v7()}),
        json!({"name": "no version at all"}),
    ] {
        app.patch(
            &format!("/api/v1/departments/{id}"),
            Some(&root.token),
            body,
        )
        .await
        .assert_error(StatusCode::BAD_REQUEST, "BAD_REQUEST");
    }
    assert_eq!(
        version_of(&app, id).await,
        1,
        "nothing may have been applied"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_oversized_name_is_refused() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    app.post(
        "/api/v1/departments",
        Some(&root.token),
        json!({"code": "ops", "name": "x".repeat(151)}),
    )
    .await
    .assert_error(StatusCode::BAD_REQUEST, "VALIDATION_FAILED");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn archive_sets_the_status_and_the_timestamp_together() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let id = create_department(&app, &root.token, "ops", "Operations").await;

    let archived = app
        .post(
            &format!("/api/v1/departments/{id}/archive"),
            Some(&root.token),
            json!({"version": 1}),
        )
        .await;
    archived.assert_status(StatusCode::OK);
    assert_eq!(archived.str_at("/status"), "ARCHIVED");
    assert_ne!(archived.json()["archived_at"], json!(null));

    let (status, archived_at): (String, Option<OffsetDateTime>) =
        sqlx::query_as("SELECT status, archived_at FROM departments WHERE id = $1")
            .bind(id)
            .fetch_one(&app.db)
            .await
            .expect("the department row");
    assert_eq!(status, "ARCHIVED");
    assert!(
        archived_at.is_some(),
        "the archive CHECK ties the status and the timestamp together"
    );
    assert_eq!(audit_count_for(&app, "DEPARTMENT.ARCHIVED", id).await, 1);
}

/// Archiving twice would rewrite `archived_at` and destroy the record of when the
/// unit actually closed, so the second attempt is a conflict rather than a no-op.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn archiving_twice_is_refused() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let id = create_department(&app, &root.token, "ops", "Operations").await;

    app.post(
        &format!("/api/v1/departments/{id}/archive"),
        Some(&root.token),
        json!({"version": 1}),
    )
    .await
    .assert_status(StatusCode::OK);

    app.post(
        &format!("/api/v1/departments/{id}/archive"),
        Some(&root.token),
        json!({"version": 2}),
    )
    .await
    .assert_error(StatusCode::CONFLICT, "DEPARTMENT_ALREADY_ARCHIVED");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_archived_department_can_no_longer_be_edited() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let id = create_department(&app, &root.token, "ops", "Operations").await;

    app.post(
        &format!("/api/v1/departments/{id}/archive"),
        Some(&root.token),
        json!({"version": 1}),
    )
    .await
    .assert_status(StatusCode::OK);

    app.patch(
        &format!("/api/v1/departments/{id}"),
        Some(&root.token),
        json!({"version": 2, "name": "Reopened"}),
    )
    .await
    .assert_error(StatusCode::CONFLICT, "DEPARTMENT_ARCHIVED");
}

// ---------------------------------------------------------------------------
// Membership
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_member_can_be_added_listed_removed_and_added_again() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let id = create_department(&app, &root.token, "ops", "Operations").await;
    let employee = create_employee(&app, &root.token, "member@roleblank.test", None).await;

    let added = app
        .post(
            &format!("/api/v1/departments/{id}/members"),
            Some(&root.token),
            json!({"user_id": employee.user_id, "role_in_department": "LEAD"}),
        )
        .await;
    added.assert_status(StatusCode::CREATED).assert_no_secrets();
    assert_eq!(added.str_at("/role_in_department"), "LEAD");
    assert_eq!(live_membership_count(&app, id, employee.user_id).await, 1);

    let members = app
        .get(
            &format!("/api/v1/departments/{id}/members"),
            Some(&root.token),
        )
        .await;
    members.assert_status(StatusCode::OK);
    assert_eq!(member_ids_in(&members), vec![employee.user_id]);

    app.delete(
        &format!("/api/v1/departments/{id}/members/{}", employee.user_id),
        Some(&root.token),
    )
    .await
    .assert_status(StatusCode::NO_CONTENT);

    // Removal is `removed_at = now()`, never a DELETE: the row is the evidence that
    // this person held the department's authority between two dates.
    assert_eq!(live_membership_count(&app, id, employee.user_id).await, 0);
    assert_eq!(total_membership_rows(&app, id, employee.user_id).await, 1);

    let listed_after = app
        .get(
            &format!("/api/v1/departments/{id}/members"),
            Some(&root.token),
        )
        .await;
    assert!(member_ids_in(&listed_after).is_empty());

    // The partial unique index is on `removed_at IS NULL`, so re-adding must work
    // and must leave both periods of membership in the history.
    app.post(
        &format!("/api/v1/departments/{id}/members"),
        Some(&root.token),
        json!({"user_id": employee.user_id}),
    )
    .await
    .assert_status(StatusCode::CREATED);
    assert_eq!(live_membership_count(&app, id, employee.user_id).await, 1);
    assert_eq!(
        total_membership_rows(&app, id, employee.user_id).await,
        2,
        "re-adding must create a second row, not resurrect the first"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adding_the_same_member_twice_is_a_conflict() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let id = create_department(&app, &root.token, "ops", "Operations").await;
    let employee = create_employee(&app, &root.token, "member@roleblank.test", None).await;

    app.post(
        &format!("/api/v1/departments/{id}/members"),
        Some(&root.token),
        json!({"user_id": employee.user_id}),
    )
    .await
    .assert_status(StatusCode::CREATED);

    app.post(
        &format!("/api/v1/departments/{id}/members"),
        Some(&root.token),
        json!({"user_id": employee.user_id}),
    )
    .await
    .assert_error(StatusCode::CONFLICT, "ALREADY_A_MEMBER");
}

/// The external trust boundary, stated from the inside: a CLIENT principal has no
/// place in an internal organisational unit, and department membership resolves
/// `DEPARTMENT` scope — so admitting one would hand an outsider internal authority.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_principal_cannot_be_a_department_member() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let id = create_department(&app, &root.token, "ops", "Operations").await;
    let outsider = create_client_user(&app, &root.token, "outsider@client.test", None).await;

    app.post(
        &format!("/api/v1/departments/{id}/members"),
        Some(&root.token),
        json!({"user_id": outsider.user_id}),
    )
    .await
    .assert_error(StatusCode::CONFLICT, "PRINCIPAL_TYPE_MISMATCH");

    assert_eq!(live_membership_count(&app, id, outsider.user_id).await, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adding_an_unknown_user_is_a_conflict_and_an_invalid_role_is_a_validation_error() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let id = create_department(&app, &root.token, "ops", "Operations").await;
    let employee = create_employee(&app, &root.token, "member@roleblank.test", None).await;

    app.post(
        &format!("/api/v1/departments/{id}/members"),
        Some(&root.token),
        json!({"user_id": Uuid::now_v7()}),
    )
    .await
    .assert_error(StatusCode::CONFLICT, "UNKNOWN_USER");

    app.post(
        &format!("/api/v1/departments/{id}/members"),
        Some(&root.token),
        json!({"user_id": employee.user_id, "role_in_department": "OWNER"}),
    )
    .await
    .assert_error(StatusCode::BAD_REQUEST, "VALIDATION_FAILED");

    app.post(
        &format!("/api/v1/departments/{id}/members"),
        Some(&root.token),
        json!({"user_id": employee.user_id, "removed_at": null}),
    )
    .await
    .assert_error(StatusCode::BAD_REQUEST, "BAD_REQUEST");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn removing_someone_who_is_not_a_member_is_not_found() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let id = create_department(&app, &root.token, "ops", "Operations").await;
    let employee = create_employee(&app, &root.token, "member@roleblank.test", None).await;

    app.delete(
        &format!("/api/v1/departments/{id}/members/{}", employee.user_id),
        Some(&root.token),
    )
    .await
    .assert_error(StatusCode::NOT_FOUND, "RESOURCE_NOT_FOUND");
}

// ---------------------------------------------------------------------------
// Refusals that protect other rows
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_duplicate_code_is_refused() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    create_department(&app, &root.token, "ops", "Operations").await;

    let duplicate = app
        .post(
            "/api/v1/departments",
            Some(&root.token),
            json!({"code": "OPS", "name": "Operations Again"}),
        )
        .await;
    duplicate.assert_error(StatusCode::CONFLICT, "UNIQUE_VIOLATION");

    let (count,): (i64,) = sqlx::query_as("SELECT count(*) FROM departments")
        .fetch_one(&app.db)
        .await
        .expect("count departments");
    assert_eq!(count, 1);
}

/// Refusing is the deliberate choice: silently detaching the projects would leave
/// rows pointing at an archived unit, and nulling them would destroy the record of
/// which unit owned the work.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_department_with_live_projects_cannot_be_archived() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let id = create_department(&app, &root.token, "ops", "Operations").await;
    let project = create_project(&app, &root.token, "rollout", root.user_id, Some(id)).await;

    app.post(
        &format!("/api/v1/departments/{id}/archive"),
        Some(&root.token),
        json!({"version": 1}),
    )
    .await
    .assert_error(StatusCode::CONFLICT, "DEPARTMENT_HAS_LIVE_PROJECTS");
    assert_eq!(status_of(&app, id).await, "ACTIVE");

    // Archiving the project clears the obstruction, which is what makes the refusal
    // a workflow rather than a dead end.
    app.post(
        &format!("/api/v1/projects/{project}/archive"),
        Some(&root.token),
        json!({"version": 1}),
    )
    .await
    .assert_status(StatusCode::OK);

    app.post(
        &format!("/api/v1/departments/{id}/archive"),
        Some(&root.token),
        json!({"version": 1}),
    )
    .await
    .assert_status(StatusCode::OK);
    assert_eq!(status_of(&app, id).await, "ARCHIVED");
}

// ---------------------------------------------------------------------------
// Authorisation
// ---------------------------------------------------------------------------

/// The seeded `employee` role holds `departments.read@DEPARTMENT` and nothing
/// else, so every write is refused — and the refusal is a `403`, not a `404`,
/// because an internal principal may learn that the resource exists.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_employee_holds_no_write_authority_over_departments() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let id = create_department(&app, &root.token, "ops", "Operations").await;
    let employee = create_employee(&app, &root.token, "member@roleblank.test", Some(id)).await;

    app.post(
        "/api/v1/departments",
        Some(&employee.token),
        json!({"code": "shadow", "name": "Shadow"}),
    )
    .await
    .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");

    app.patch(
        &format!("/api/v1/departments/{id}"),
        Some(&employee.token),
        json!({"version": 1, "name": "Renamed"}),
    )
    .await
    .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");

    app.post(
        &format!("/api/v1/departments/{id}/archive"),
        Some(&employee.token),
        json!({"version": 1}),
    )
    .await
    .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");

    app.post(
        &format!("/api/v1/departments/{id}/members"),
        Some(&employee.token),
        json!({"user_id": employee.user_id}),
    )
    .await
    .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");

    // The read they do hold still works, and only for their own department.
    app.get(&format!("/api/v1/departments/{id}"), Some(&employee.token))
        .await
        .assert_status(StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_anonymous_caller_reaches_nothing() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let id = create_department(&app, &root.token, "ops", "Operations").await;

    app.get("/api/v1/departments", None)
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "AUTHENTICATION_FAILED");
    app.get(&format!("/api/v1/departments/{id}"), None)
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "AUTHENTICATION_FAILED");
    app.post(
        "/api/v1/departments",
        None,
        json!({"code": "x", "name": "X"}),
    )
    .await
    .assert_error(StatusCode::UNAUTHORIZED, "AUTHENTICATION_FAILED");
}
