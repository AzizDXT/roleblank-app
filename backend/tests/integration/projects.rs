//! `/api/v1/projects` — lifecycle, membership, and the external trust boundary.
//!
//! Sharing is the most consequential business operation in the system: it is the
//! one that moves company data outside the company. So the sharing tests assert
//! three things every time — the response, the row (`revoked_at`, never a
//! `DELETE`), and the audit record. Any one of the three alone would let a real
//! regression through.

use axum::http::StatusCode;
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::common::TestApp;
use crate::fixtures::*;

// ---------------------------------------------------------------------------
// Row readers
// ---------------------------------------------------------------------------

async fn project_status(app: &TestApp, id: Uuid) -> String {
    sqlx::query_scalar("SELECT status FROM projects WHERE id = $1")
        .bind(id)
        .fetch_one(&app.db)
        .await
        .expect("the project row")
}

async fn link_rows(app: &TestApp, project: Uuid, account: Uuid) -> Vec<Option<OffsetDateTime>> {
    sqlx::query_scalar(
        "SELECT revoked_at FROM project_client_links
          WHERE project_id = $1 AND client_account_id = $2 ORDER BY shared_at",
    )
    .bind(project)
    .bind(account)
    .fetch_all(&app.db)
    .await
    .expect("the link rows")
}

async fn live_member_count(app: &TestApp, project: Uuid, user: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM project_memberships
          WHERE project_id = $1 AND user_id = $2 AND removed_at IS NULL",
    )
    .bind(project)
    .bind(user)
    .fetch_one(&app.db)
    .await
    .expect("count live memberships")
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_always_starts_active_whatever_the_body_says() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let department = create_department(&app, &root.token, "ops", "Operations").await;

    let created = app
        .post(
            "/api/v1/projects",
            Some(&root.token),
            json!({
                "code": "ROLLOUT",
                "name": "Acme rollout",
                "manager_user_id": root.user_id,
                "department_id": department,
                "start_date": "2026-01-01",
                "target_date": "2026-06-30",
                "internal_note": "do not tell the client",
            }),
        )
        .await;
    created
        .assert_status(StatusCode::CREATED)
        .assert_no_secrets();
    assert_eq!(created.str_at("/code"), "rollout");
    assert_eq!(created.str_at("/status"), "ACTIVE");
    assert_eq!(created.str_at("/start_date"), "2026-01-01");
    assert_eq!(created.json()["version"], json!(1));
    assert_eq!(created.json()["completed_at"], json!(null));
    assert_eq!(created.json()["archived_at"], json!(null));

    let id = created.id_at("/id");
    assert_eq!(project_status(&app, id).await, "ACTIVE");
    assert_eq!(audit_count_for(&app, "PROJECT.CREATED", id).await, 1);

    // A caller cannot create a project that is already archived, which would make
    // it invisible to the very people who would have reviewed it.
    app.post(
        "/api/v1/projects",
        Some(&root.token),
        json!({
            "code": "sneaky",
            "name": "Sneaky",
            "manager_user_id": root.user_id,
            "status": "ARCHIVED",
        }),
    )
    .await
    .assert_error(StatusCode::BAD_REQUEST, "BAD_REQUEST");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_manager_must_be_an_existing_internal_user() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let outsider = create_client_user(&app, &root.token, "contact@acme.test", None).await;

    app.post(
        "/api/v1/projects",
        Some(&root.token),
        json!({"code": "p1", "name": "P1", "manager_user_id": outsider.user_id}),
    )
    .await
    .assert_error(StatusCode::CONFLICT, "EXTERNAL_PRINCIPAL");

    app.post(
        "/api/v1/projects",
        Some(&root.token),
        json!({"code": "p2", "name": "P2", "manager_user_id": Uuid::now_v7()}),
    )
    .await
    .assert_error(StatusCode::BAD_REQUEST, "VALIDATION_FAILED");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_target_date_before_the_start_date_is_refused_as_a_field_error() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;

    app.post(
        "/api/v1/projects",
        Some(&root.token),
        json!({
            "code": "p1", "name": "P1", "manager_user_id": root.user_id,
            "start_date": "2026-06-01", "target_date": "2026-01-01",
        }),
    )
    .await
    .assert_error(StatusCode::BAD_REQUEST, "VALIDATION_FAILED");

    // And a date that is not `YYYY-MM-DD` never reaches the service at all.
    app.post(
        "/api/v1/projects",
        Some(&root.token),
        json!({
            "code": "p2", "name": "P2", "manager_user_id": root.user_id,
            "start_date": "01/06/2026",
        }),
    )
    .await
    .assert_error(StatusCode::BAD_REQUEST, "BAD_REQUEST");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn read_returns_the_internal_projection_and_an_unknown_id_is_not_found() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let id = create_project(&app, &root.token, "rollout", root.user_id, None).await;

    let found = app
        .get(&format!("/api/v1/projects/{id}"), Some(&root.token))
        .await;
    found.assert_status(StatusCode::OK).assert_no_secrets();
    // The internal projection keeps the fields the external one has no room for.
    for key in ["internal_note", "manager_user_id", "version", "created_by"] {
        assert!(found.json().get(key).is_some(), "lost `{key}`");
    }

    app.get(
        &format!("/api/v1/projects/{}", Uuid::now_v7()),
        Some(&root.token),
    )
    .await
    .assert_error(StatusCode::NOT_FOUND, "RESOURCE_NOT_FOUND");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_filters_by_status_and_department_and_paginates() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let ops = create_department(&app, &root.token, "ops", "Operations").await;
    let sales = create_department(&app, &root.token, "sales", "Sales").await;

    let in_ops = create_project(&app, &root.token, "ops-one", root.user_id, Some(ops)).await;
    let in_sales = create_project(&app, &root.token, "sales-one", root.user_id, Some(sales)).await;
    let unfiled = create_project(&app, &root.token, "unfiled", root.user_id, None).await;

    let all = app
        .get(
            "/api/v1/projects?sort=created_at&direction=asc",
            Some(&root.token),
        )
        .await;
    all.assert_status(StatusCode::OK);
    assert_eq!(ids_in(&all), vec![in_ops, in_sales, unfiled]);

    let by_department = app
        .get(
            &format!("/api/v1/projects?department_id={ops}"),
            Some(&root.token),
        )
        .await;
    by_department.assert_status(StatusCode::OK);
    assert_eq!(ids_in(&by_department), vec![in_ops]);

    // Pause one, then filter on it: the filter is applied by the query, not after.
    app.patch(
        &format!("/api/v1/projects/{unfiled}"),
        Some(&root.token),
        json!({"version": 1, "status": "PAUSED"}),
    )
    .await
    .assert_status(StatusCode::OK);

    let paused = app
        .get("/api/v1/projects?status=PAUSED", Some(&root.token))
        .await;
    paused.assert_status(StatusCode::OK);
    assert_eq!(ids_in(&paused), vec![unfiled]);

    let page = app
        .get(
            "/api/v1/projects?sort=created_at&direction=asc&limit=1",
            Some(&root.token),
        )
        .await;
    assert_eq!(ids_in(&page), vec![in_ops]);
    assert_eq!(page.json()["has_more"], json!(true));
}

/// A query parameter this endpoint does not accept is refused, not ignored: a
/// caller who believes they filtered must never receive an unfiltered page.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_refuses_an_unrecognised_query_parameter_and_an_invalid_status() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;

    app.get("/api/v1/projects?internal_note=x", Some(&root.token))
        .await
        .assert_error(StatusCode::BAD_REQUEST, "BAD_REQUEST");
    app.get("/api/v1/projects?status=DELETED", Some(&root.token))
        .await
        .assert_error(StatusCode::BAD_REQUEST, "VALIDATION_FAILED");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn patch_moves_the_status_through_the_permitted_transitions() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let id = create_project(&app, &root.token, "rollout", root.user_id, None).await;

    let paused = app
        .patch(
            &format!("/api/v1/projects/{id}"),
            Some(&root.token),
            json!({"version": 1, "status": "PAUSED", "name": "Acme rollout (paused)"}),
        )
        .await;
    paused.assert_status(StatusCode::OK);
    assert_eq!(paused.str_at("/status"), "PAUSED");
    assert_eq!(paused.json()["version"], json!(2));

    // COMPLETED derives `completed_at`; the caller never supplies it.
    let completed = app
        .patch(
            &format!("/api/v1/projects/{id}"),
            Some(&root.token),
            json!({"version": 2, "status": "COMPLETED"}),
        )
        .await;
    completed.assert_status(StatusCode::OK);
    assert_ne!(completed.json()["completed_at"], json!(null));

    // Reopening is legitimate, and it must clear the completion instant again or
    // the `projects` CHECK constraint would be the thing that noticed.
    let reopened = app
        .patch(
            &format!("/api/v1/projects/{id}"),
            Some(&root.token),
            json!({"version": 3, "status": "ACTIVE"}),
        )
        .await;
    reopened.assert_status(StatusCode::OK);
    assert_eq!(reopened.json()["completed_at"], json!(null));
}

/// Archiving removes a project from everyone's view, so it carries its own
/// permission and its own endpoint. Allowing it through the update path would let
/// `projects.update` alone do it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn patch_cannot_archive_and_cannot_set_an_unknown_status() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let id = create_project(&app, &root.token, "rollout", root.user_id, None).await;

    app.patch(
        &format!("/api/v1/projects/{id}"),
        Some(&root.token),
        json!({"version": 1, "status": "ARCHIVED"}),
    )
    .await
    .assert_error(StatusCode::BAD_REQUEST, "VALIDATION_FAILED");

    app.patch(
        &format!("/api/v1/projects/{id}"),
        Some(&root.token),
        json!({"version": 1, "status": "DELETED"}),
    )
    .await
    .assert_error(StatusCode::BAD_REQUEST, "VALIDATION_FAILED");

    assert_eq!(project_status(&app, id).await, "ACTIVE");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn patch_with_a_stale_version_is_a_conflict_and_changes_nothing() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let id = create_project(&app, &root.token, "rollout", root.user_id, None).await;

    app.patch(
        &format!("/api/v1/projects/{id}"),
        Some(&root.token),
        json!({"version": 1, "name": "First writer"}),
    )
    .await
    .assert_status(StatusCode::OK);

    app.patch(
        &format!("/api/v1/projects/{id}"),
        Some(&root.token),
        json!({"version": 1, "name": "Second writer"}),
    )
    .await
    .assert_error(StatusCode::CONFLICT, "VERSION_CONFLICT");

    let name: String = sqlx::query_scalar("SELECT name FROM projects WHERE id = $1")
        .bind(id)
        .fetch_one(&app.db)
        .await
        .expect("the project row");
    assert_eq!(name, "First writer");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn patch_refuses_a_field_it_does_not_own() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let id = create_project(&app, &root.token, "rollout", root.user_id, None).await;

    for body in [
        json!({"version": 1, "code": "renamed"}),
        json!({"version": 1, "client_visible": true}),
        json!({"version": 1, "completed_at": "2026-01-01T00:00:00Z"}),
        json!({"name": "no version"}),
    ] {
        app.patch(&format!("/api/v1/projects/{id}"), Some(&root.token), body)
            .await
            .assert_error(StatusCode::BAD_REQUEST, "BAD_REQUEST");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn archive_is_terminal() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let id = create_project(&app, &root.token, "rollout", root.user_id, None).await;

    let archived = app
        .post(
            &format!("/api/v1/projects/{id}/archive"),
            Some(&root.token),
            json!({"version": 1, "reason": "cancelled by the customer"}),
        )
        .await;
    archived.assert_status(StatusCode::OK);
    assert_eq!(archived.str_at("/status"), "ARCHIVED");
    assert_ne!(archived.json()["archived_at"], json!(null));
    assert_eq!(audit_count_for(&app, "PROJECT.ARCHIVED", id).await, 1);

    app.post(
        &format!("/api/v1/projects/{id}/archive"),
        Some(&root.token),
        json!({"version": 2}),
    )
    .await
    .assert_error(StatusCode::CONFLICT, "ALREADY_ARCHIVED");

    // Nothing leaves ARCHIVED, because the archive timestamp and the status are
    // tied together and an "unarchive" would rewrite when the project ended.
    app.patch(
        &format!("/api/v1/projects/{id}"),
        Some(&root.token),
        json!({"version": 2, "status": "ACTIVE"}),
    )
    .await
    .assert_error(StatusCode::CONFLICT, "INVALID_STATE_TRANSITION");
}

// ---------------------------------------------------------------------------
// Membership
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_member_can_be_added_listed_and_removed() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let project = create_project(&app, &root.token, "rollout", root.user_id, None).await;
    let employee = create_employee(&app, &root.token, "dev@roleblank.test", None).await;

    app.post(
        &format!("/api/v1/projects/{project}/members"),
        Some(&root.token),
        json!({"user_id": employee.user_id, "role_in_project": "LEAD"}),
    )
    .await
    .assert_status(StatusCode::NO_CONTENT);
    assert_eq!(live_member_count(&app, project, employee.user_id).await, 1);
    assert_eq!(
        audit_count_for(&app, "PROJECT.MEMBER_ADDED", project).await,
        1
    );

    let members = app
        .get(
            &format!("/api/v1/projects/{project}/members"),
            Some(&root.token),
        )
        .await;
    members.assert_status(StatusCode::OK).assert_no_secrets();
    let listed = members.json().as_array().expect("a plain array").clone();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["role_in_project"], json!("LEAD"));

    app.post(
        &format!("/api/v1/projects/{project}/members"),
        Some(&root.token),
        json!({"user_id": employee.user_id}),
    )
    .await
    .assert_error(StatusCode::CONFLICT, "ALREADY_A_MEMBER");

    app.delete(
        &format!("/api/v1/projects/{project}/members/{}", employee.user_id),
        Some(&root.token),
    )
    .await
    .assert_status(StatusCode::NO_CONTENT);
    assert_eq!(live_member_count(&app, project, employee.user_id).await, 0);

    app.delete(
        &format!("/api/v1/projects/{project}/members/{}", employee.user_id),
        Some(&root.token),
    )
    .await
    .assert_error(StatusCode::NOT_FOUND, "RESOURCE_NOT_FOUND");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn project_membership_is_internal_only_and_an_archived_project_gains_none() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let project = create_project(&app, &root.token, "rollout", root.user_id, None).await;
    let outsider = create_client_user(&app, &root.token, "contact@acme.test", None).await;
    let employee = create_employee(&app, &root.token, "dev@roleblank.test", None).await;

    app.post(
        &format!("/api/v1/projects/{project}/members"),
        Some(&root.token),
        json!({"user_id": outsider.user_id}),
    )
    .await
    .assert_error(StatusCode::CONFLICT, "EXTERNAL_PRINCIPAL");

    app.post(
        &format!("/api/v1/projects/{project}/members"),
        Some(&root.token),
        json!({"user_id": employee.user_id, "role_in_project": "OWNER"}),
    )
    .await
    .assert_error(StatusCode::BAD_REQUEST, "VALIDATION_FAILED");

    app.post(
        &format!("/api/v1/projects/{project}/archive"),
        Some(&root.token),
        json!({"version": 1}),
    )
    .await
    .assert_status(StatusCode::OK);

    app.post(
        &format!("/api/v1/projects/{project}/members"),
        Some(&root.token),
        json!({"user_id": employee.user_id}),
    )
    .await
    .assert_error(StatusCode::CONFLICT, "PROJECT_ARCHIVED");
}

// ---------------------------------------------------------------------------
// Client sharing — the external trust boundary
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sharing_creates_a_live_link_and_is_audited_as_carrying_no_tasks() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let account = create_client_account(&app, &root.token, "acme", "Acme").await;
    let project = create_project(&app, &root.token, "rollout", root.user_id, None).await;

    app.post(
        &format!("/api/v1/projects/{project}/clients"),
        Some(&root.token),
        json!({"client_account_id": account, "note": "phase two"}),
    )
    .await
    .assert_status(StatusCode::NO_CONTENT);

    assert_eq!(link_rows(&app, project, account).await, vec![None]);
    assert_eq!(
        audit_count_for(&app, "PROJECT.SHARED_WITH_CLIENT", project).await,
        1
    );

    // The record states explicitly that the tasks did not travel with the project,
    // because that is the single most misunderstood property of sharing.
    let meta: serde_json::Value = sqlx::query_scalar(
        "SELECT metadata FROM audit_events
          WHERE action_code = 'PROJECT.SHARED_WITH_CLIENT' AND target_id = $1",
    )
    .bind(project)
    .fetch_one(&app.db)
    .await
    .expect("the audit row");
    assert_eq!(meta["tasks_included"], json!(false));
    assert_eq!(meta["client_account_id"], json!(account.to_string()));

    let links = app
        .get(
            &format!("/api/v1/projects/{project}/clients"),
            Some(&root.token),
        )
        .await;
    links.assert_status(StatusCode::OK).assert_no_secrets();
    let items = links.json().as_array().expect("a plain array").clone();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["client_account_id"], json!(account.to_string()));
    assert_eq!(items[0]["note"], json!("phase two"));
}

/// Revocation is an `UPDATE`, never a `DELETE`. The record of what was once shared
/// with whom is exactly what a client dispute later turns on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unsharing_revokes_the_row_rather_than_deleting_it_and_is_audited() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let account = create_client_account(&app, &root.token, "acme", "Acme").await;
    let project = create_project(&app, &root.token, "rollout", root.user_id, None).await;

    app.post(
        &format!("/api/v1/projects/{project}/clients"),
        Some(&root.token),
        json!({"client_account_id": account}),
    )
    .await
    .assert_status(StatusCode::NO_CONTENT);

    app.delete(
        &format!("/api/v1/projects/{project}/clients/{account}"),
        Some(&root.token),
    )
    .await
    .assert_status(StatusCode::NO_CONTENT);

    let rows = link_rows(&app, project, account).await;
    assert_eq!(rows.len(), 1, "the link row must survive revocation");
    assert!(
        rows[0].is_some(),
        "unsharing must set `revoked_at`, not remove the row"
    );
    let (revoked_by,): (Option<Uuid>,) = sqlx::query_as(
        "SELECT revoked_by FROM project_client_links
          WHERE project_id = $1 AND client_account_id = $2",
    )
    .bind(project)
    .bind(account)
    .fetch_one(&app.db)
    .await
    .expect("the link row");
    assert_eq!(revoked_by, Some(root.user_id));

    assert_eq!(
        audit_count_for(&app, "PROJECT.UNSHARED_FROM_CLIENT", project).await,
        1
    );

    // The revoked link disappears from the listing, and a second revocation has
    // nothing to act on.
    let links = app
        .get(
            &format!("/api/v1/projects/{project}/clients"),
            Some(&root.token),
        )
        .await;
    assert!(links.json().as_array().expect("array").is_empty());
    app.delete(
        &format!("/api/v1/projects/{project}/clients/{account}"),
        Some(&root.token),
    )
    .await
    .assert_error(StatusCode::NOT_FOUND, "RESOURCE_NOT_FOUND");

    // The partial unique index is on `revoked_at IS NULL`, so the pair can be
    // shared again and both episodes survive in the history.
    app.post(
        &format!("/api/v1/projects/{project}/clients"),
        Some(&root.token),
        json!({"client_account_id": account}),
    )
    .await
    .assert_status(StatusCode::NO_CONTENT);
    let rows = link_rows(&app, project, account).await;
    assert_eq!(rows.len(), 2);
    assert!(rows[0].is_some() && rows[1].is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sharing_the_same_account_twice_is_refused() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let account = create_client_account(&app, &root.token, "acme", "Acme").await;
    let project = create_project(&app, &root.token, "rollout", root.user_id, None).await;

    app.post(
        &format!("/api/v1/projects/{project}/clients"),
        Some(&root.token),
        json!({"client_account_id": account}),
    )
    .await
    .assert_status(StatusCode::NO_CONTENT);
    app.post(
        &format!("/api/v1/projects/{project}/clients"),
        Some(&root.token),
        json!({"client_account_id": account}),
    )
    .await
    .assert_error(StatusCode::CONFLICT, "UNIQUE_VIOLATION");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sharing_refuses_an_unknown_account_an_inactive_account_and_an_archived_project() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let account = create_client_account(&app, &root.token, "acme", "Acme").await;
    let project = create_project(&app, &root.token, "rollout", root.user_id, None).await;

    app.post(
        &format!("/api/v1/projects/{project}/clients"),
        Some(&root.token),
        json!({"client_account_id": Uuid::now_v7()}),
    )
    .await
    .assert_error(StatusCode::BAD_REQUEST, "VALIDATION_FAILED");

    app.post(
        &format!("/api/v1/clients/{account}/archive"),
        Some(&root.token),
        json!({"version": 1}),
    )
    .await
    .assert_status(StatusCode::OK);
    app.post(
        &format!("/api/v1/projects/{project}/clients"),
        Some(&root.token),
        json!({"client_account_id": account}),
    )
    .await
    .assert_error(StatusCode::CONFLICT, "CLIENT_ACCOUNT_NOT_ACTIVE");

    let live = create_client_account(&app, &root.token, "globex", "Globex").await;
    app.post(
        &format!("/api/v1/projects/{project}/archive"),
        Some(&root.token),
        json!({"version": 1}),
    )
    .await
    .assert_status(StatusCode::OK);
    app.post(
        &format!("/api/v1/projects/{project}/clients"),
        Some(&root.token),
        json!({"client_account_id": live}),
    )
    .await
    .assert_error(StatusCode::CONFLICT, "PROJECT_ARCHIVED");
}

/// Sharing never accepts a task flag. A task becomes visible only through its own
/// `client_visible` edit, so there is no field on this body that could publish one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_share_body_has_no_field_that_could_carry_tasks() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let account = create_client_account(&app, &root.token, "acme", "Acme").await;
    let project = create_project(&app, &root.token, "rollout", root.user_id, None).await;

    for body in [
        json!({"client_account_id": account, "include_tasks": true}),
        json!({"client_account_id": account, "client_visible": true}),
        json!({"client_account_id": account, "tasks": ["x"]}),
    ] {
        app.post(
            &format!("/api/v1/projects/{project}/clients"),
            Some(&root.token),
            body,
        )
        .await
        .assert_error(StatusCode::BAD_REQUEST, "BAD_REQUEST");
    }
    assert!(link_rows(&app, project, account).await.is_empty());
}

/// `projects.clients.share` is flagged dangerous, so a session with no recent
/// second factor cannot reach it — whatever else it holds. A stolen session with
/// broad project permissions must not be enough to publish a project.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sharing_demands_a_recent_second_factor() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let account = create_client_account(&app, &root.token, "acme", "Acme").await;
    let project = create_project(&app, &root.token, "rollout", root.user_id, None).await;
    let employee = create_employee(&app, &root.token, "dev@roleblank.test", None).await;

    // The actor must *genuinely hold* `projects.clients.share`, or the refusal
    // below would be about authority and this test would prove nothing about the
    // second factor. The grant is an override rather than a role because a role
    // carrying a dangerous permission forces MFA enrolment at invitation time, and
    // the session under test has to be password-only.
    //
    // Previously this test used a plain employee, which passed only because the
    // step-up gate ran *before* authorisation. That ordering told an unauthorised
    // caller which control it would have to defeat next, and told an external
    // CLIENT principal — which can never hold this permission at all — that it had
    // found an internal route, in violation of `docs/backend/04-authorization.md`
    // §10. The service now authorises first; the property this test names is
    // unchanged and is now asserted against an actor it actually applies to.
    app.post(
        &format!("/api/v1/users/{}/permission-overrides", employee.user_id),
        Some(&root.token),
        json!({
            "permission_code": "projects.clients.share",
            "effect": "ALLOW",
            "scope": "GLOBAL",
        }),
    )
    .await
    .assert_status(StatusCode::CREATED);

    app.post(
        &format!("/api/v1/projects/{project}/clients"),
        Some(&employee.token),
        json!({"client_account_id": account}),
    )
    .await
    .assert_error(StatusCode::FORBIDDEN, "STEP_UP_REQUIRED");

    app.delete(
        &format!("/api/v1/projects/{project}/clients/{account}"),
        Some(&employee.token),
    )
    .await
    .assert_error(StatusCode::FORBIDDEN, "STEP_UP_REQUIRED");

    assert!(link_rows(&app, project, account).await.is_empty());
}

/// Satisfying step-up is not authority. An employee who has enrolled a second
/// factor still cannot share, and the refusal is recorded — a probe against the
/// external boundary is exactly the event an intrusion feed wants.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_step_up_satisfied_employee_still_cannot_share_and_the_denial_is_recorded() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let account = create_client_account(&app, &root.token, "acme", "Acme").await;
    let project = create_project(&app, &root.token, "rollout", root.user_id, None).await;
    let employee = create_employee(&app, &root.token, "dev@roleblank.test", None).await;
    enrol_mfa(&app, &employee.token).await;

    app.post(
        &format!("/api/v1/projects/{project}/clients"),
        Some(&employee.token),
        json!({"client_account_id": account}),
    )
    .await
    .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");

    assert!(link_rows(&app, project, account).await.is_empty());
    assert_eq!(
        audit_count_for(&app, "AUTHORIZATION.DENIED", project).await,
        1,
        "a refused attempt on the external boundary must leave a trace"
    );
}

/// An external principal cannot reach the internal project surface at all: the
/// envelope refuses `projects.*` before any grant is consulted, and the refusal is
/// shaped as a `404` so the route does not confirm its own existence.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_principal_cannot_reach_the_internal_project_surface() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let account = create_client_account(&app, &root.token, "acme", "Acme").await;
    let project = create_project(&app, &root.token, "rollout", root.user_id, None).await;
    app.post(
        &format!("/api/v1/projects/{project}/clients"),
        Some(&root.token),
        json!({"client_account_id": account}),
    )
    .await
    .assert_status(StatusCode::NO_CONTENT);

    let contact = create_client_user(&app, &root.token, "contact@acme.test", Some(account)).await;
    // Step-up is satisfied, so the refusal below is about authority rather than
    // about a second factor.
    enrol_mfa(&app, &contact.token).await;

    // Even for a project this principal *can* see through the portal.
    app.get(&format!("/api/v1/projects/{project}"), Some(&contact.token))
        .await
        .assert_error(StatusCode::NOT_FOUND, "RESOURCE_NOT_FOUND");
    app.get("/api/v1/projects", Some(&contact.token))
        .await
        .assert_error(StatusCode::NOT_FOUND, "RESOURCE_NOT_FOUND");
    app.get(
        &format!("/api/v1/projects/{project}/members"),
        Some(&contact.token),
    )
    .await
    .assert_error(StatusCode::NOT_FOUND, "RESOURCE_NOT_FOUND");
    app.get(
        &format!("/api/v1/projects/{project}/clients"),
        Some(&contact.token),
    )
    .await
    .assert_error(StatusCode::NOT_FOUND, "RESOURCE_NOT_FOUND");
    app.post(
        &format!("/api/v1/projects/{project}/clients"),
        Some(&contact.token),
        json!({"client_account_id": account}),
    )
    .await
    .assert_error(StatusCode::NOT_FOUND, "RESOURCE_NOT_FOUND");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_employee_cannot_create_or_archive_a_project() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let project = create_project(&app, &root.token, "rollout", root.user_id, None).await;
    let employee = create_employee(&app, &root.token, "dev@roleblank.test", None).await;

    app.post(
        "/api/v1/projects",
        Some(&employee.token),
        json!({"code": "mine", "name": "Mine", "manager_user_id": employee.user_id}),
    )
    .await
    .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");

    app.post(
        &format!("/api/v1/projects/{project}/archive"),
        Some(&employee.token),
        json!({"version": 1}),
    )
    .await
    .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");

    app.post(
        &format!("/api/v1/projects/{project}/members"),
        Some(&employee.token),
        json!({"user_id": employee.user_id}),
    )
    .await
    .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");
}
