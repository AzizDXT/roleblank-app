//! `/api/v1/tasks` — lifecycle, assignment, and the per-task client flag.
//!
//! Two properties this file exists to hold down:
//!
//! * **A task is not shared when its project is.** `client_visible` starts `false`,
//!   cannot be set at creation, and changing it is recorded under its own action
//!   code so that "when did this become visible to the client, and who decided
//!   that" is answerable without reading every update event's changed-field list.
//! * **`completed_at` is derived, never supplied.** The database enforces
//!   `(status = 'DONE') = (completed_at IS NOT NULL)`, so the interesting direction
//!   is the one that is easy to forget: moving a task *out* of `DONE` must clear it.

use axum::http::StatusCode;
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::common::TestApp;
use crate::fixtures::*;

// ---------------------------------------------------------------------------
// Row readers
// ---------------------------------------------------------------------------

async fn task_row(app: &TestApp, id: Uuid) -> (String, Option<OffsetDateTime>, bool) {
    sqlx::query_as("SELECT status, completed_at, client_visible FROM tasks WHERE id = $1")
        .bind(id)
        .fetch_one(&app.db)
        .await
        .expect("the task row")
}

async fn live_assignee_count(app: &TestApp, task: Uuid, user: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM task_assignees
          WHERE task_id = $1 AND user_id = $2 AND removed_at IS NULL",
    )
    .bind(task)
    .bind(user)
    .fetch_one(&app.db)
    .await
    .expect("count live assignees")
}

// ---------------------------------------------------------------------------
// Creation
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_new_task_starts_todo_and_invisible_to_clients() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let project = create_project(&app, &root.token, "rollout", root.user_id, None).await;

    let created = app
        .post(
            "/api/v1/tasks",
            Some(&root.token),
            json!({
                "project_id": project,
                "title": "Ship phase two",
                "description": "The client-facing description",
                "priority": "HIGH",
                "due_date": "2026-03-01",
                "internal_note": "do not tell the client",
            }),
        )
        .await;
    created
        .assert_status(StatusCode::CREATED)
        .assert_no_secrets();
    assert_eq!(created.str_at("/status"), "TODO");
    assert_eq!(created.str_at("/priority"), "HIGH");
    assert_eq!(created.str_at("/due_date"), "2026-03-01");
    assert_eq!(created.json()["client_visible"], json!(false));
    assert_eq!(created.json()["completed_at"], json!(null));
    assert_eq!(created.json()["version"], json!(1));

    let id = created.id_at("/id");
    let (status, completed_at, client_visible) = task_row(&app, id).await;
    assert_eq!(status, "TODO");
    assert!(completed_at.is_none());
    assert!(!client_visible);

    // The creation record states the visibility explicitly, so a later reader does
    // not have to infer it from the absence of a flag.
    let meta: serde_json::Value = sqlx::query_scalar(
        "SELECT metadata FROM audit_events WHERE action_code = 'TASK.CREATED' AND target_id = $1",
    )
    .bind(id)
    .fetch_one(&app.db)
    .await
    .expect("the audit row");
    assert_eq!(meta["client_visible"], json!(false));
}

/// The single most dangerous field this module could accept on a create body: a
/// bulk import or a copied request must not be able to publish internal work to a
/// client as a side effect of creating it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_never_accepts_client_visibility_status_or_assignees() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let project = create_project(&app, &root.token, "rollout", root.user_id, None).await;

    for extra in [
        json!({"client_visible": true}),
        json!({"status": "DONE"}),
        json!({"assignees": []}),
        json!({"completed_at": "2026-01-01T00:00:00Z"}),
        json!({"version": 1}),
    ] {
        let mut body = json!({"project_id": project, "title": "t"});
        for (key, value) in extra.as_object().expect("object") {
            body[key] = value.clone();
        }
        app.post("/api/v1/tasks", Some(&root.token), body)
            .await
            .assert_error(StatusCode::BAD_REQUEST, "BAD_REQUEST");
    }

    let (count,): (i64,) = sqlx::query_as("SELECT count(*) FROM tasks")
        .fetch_one(&app.db)
        .await
        .expect("count tasks");
    assert_eq!(count, 0);
}

/// A missing project is a `404`, deliberately not a field-level `400`: the check
/// runs before the permission decision, so a distinguishable answer would let a
/// caller enumerate project identifiers through the create endpoint.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn creating_against_an_unknown_or_archived_project_is_refused() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let project = create_project(&app, &root.token, "rollout", root.user_id, None).await;

    app.post(
        "/api/v1/tasks",
        Some(&root.token),
        json!({"project_id": Uuid::now_v7(), "title": "t"}),
    )
    .await
    .assert_error(StatusCode::NOT_FOUND, "RESOURCE_NOT_FOUND");

    app.post(
        &format!("/api/v1/projects/{project}/archive"),
        Some(&root.token),
        json!({"version": 1}),
    )
    .await
    .assert_status(StatusCode::OK);

    app.post(
        "/api/v1/tasks",
        Some(&root.token),
        json!({"project_id": project, "title": "t"}),
    )
    .await
    .assert_error(StatusCode::CONFLICT, "PROJECT_ARCHIVED");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_bounds_its_text_and_closes_its_enums() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let project = create_project(&app, &root.token, "rollout", root.user_id, None).await;

    app.post(
        "/api/v1/tasks",
        Some(&root.token),
        json!({"project_id": project, "title": "x".repeat(301)}),
    )
    .await
    .assert_error(StatusCode::BAD_REQUEST, "VALIDATION_FAILED");

    app.post(
        "/api/v1/tasks",
        Some(&root.token),
        json!({"project_id": project, "title": "t", "priority": "CRITICAL"}),
    )
    .await
    .assert_error(StatusCode::BAD_REQUEST, "VALIDATION_FAILED");

    app.post(
        "/api/v1/tasks",
        Some(&root.token),
        json!({"project_id": project, "title": "   "}),
    )
    .await
    .assert_error(StatusCode::BAD_REQUEST, "VALIDATION_FAILED");
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn read_list_and_the_nested_project_listing_agree() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let first_project = create_project(&app, &root.token, "one", root.user_id, None).await;
    let second_project = create_project(&app, &root.token, "two", root.user_id, None).await;
    let a = create_task(&app, &root.token, first_project, "A").await;
    let b = create_task(&app, &root.token, first_project, "B").await;
    let c = create_task(&app, &root.token, second_project, "C").await;

    app.get(&format!("/api/v1/tasks/{a}"), Some(&root.token))
        .await
        .assert_status(StatusCode::OK)
        .assert_no_secrets();
    app.get(
        &format!("/api/v1/tasks/{}", Uuid::now_v7()),
        Some(&root.token),
    )
    .await
    .assert_error(StatusCode::NOT_FOUND, "RESOURCE_NOT_FOUND");

    let all = app
        .get(
            "/api/v1/tasks?sort=created_at&direction=asc",
            Some(&root.token),
        )
        .await;
    assert_eq!(ids_in(&all), vec![a, b, c]);

    // The query filter and the nested route must give the same answer: the path
    // parameter is a filter, not a widening of what may be seen.
    let by_query = app
        .get(
            &format!("/api/v1/tasks?project_id={first_project}&sort=created_at&direction=asc"),
            Some(&root.token),
        )
        .await;
    let by_path = app
        .get(
            &format!("/api/v1/projects/{first_project}/tasks?sort=created_at&direction=asc"),
            Some(&root.token),
        )
        .await;
    assert_eq!(ids_in(&by_query), vec![a, b]);
    assert_eq!(ids_in(&by_path), vec![a, b]);

    let page = app
        .get(
            "/api/v1/tasks?sort=created_at&direction=asc&limit=2",
            Some(&root.token),
        )
        .await;
    assert_eq!(ids_in(&page), vec![a, b]);
    assert_eq!(page.json()["has_more"], json!(true));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_filters_by_status_and_refuses_an_unknown_parameter() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let project = create_project(&app, &root.token, "rollout", root.user_id, None).await;
    let done = create_task(&app, &root.token, project, "Done").await;
    create_task(&app, &root.token, project, "Todo").await;

    app.patch(
        &format!("/api/v1/tasks/{done}"),
        Some(&root.token),
        json!({"version": 1, "status": "DONE"}),
    )
    .await
    .assert_status(StatusCode::OK);

    let filtered = app
        .get("/api/v1/tasks?status=DONE", Some(&root.token))
        .await;
    assert_eq!(ids_in(&filtered), vec![done]);

    app.get("/api/v1/tasks?status=ABANDONED", Some(&root.token))
        .await
        .assert_error(StatusCode::BAD_REQUEST, "VALIDATION_FAILED");
    app.get("/api/v1/tasks?client_visible=true", Some(&root.token))
        .await
        .assert_error(StatusCode::BAD_REQUEST, "BAD_REQUEST");
    app.get("/api/v1/tasks?sort=title", Some(&root.token))
        .await
        .assert_error(StatusCode::BAD_REQUEST, "VALIDATION_FAILED");
}

// ---------------------------------------------------------------------------
// Updating and completion coherence
// ---------------------------------------------------------------------------

/// The invariant the database also enforces, driven from both directions through
/// the API: reaching `DONE` sets the completion instant, and leaving `DONE` clears
/// it. Getting the second half wrong turns a business action into a `500`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn completed_at_appears_when_a_task_is_done_and_disappears_when_it_is_not() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let project = create_project(&app, &root.token, "rollout", root.user_id, None).await;
    let task = create_task(&app, &root.token, project, "Ship it").await;

    let done = app
        .patch(
            &format!("/api/v1/tasks/{task}"),
            Some(&root.token),
            json!({"version": 1, "status": "DONE"}),
        )
        .await;
    done.assert_status(StatusCode::OK);
    assert_eq!(done.str_at("/status"), "DONE");
    assert_ne!(done.json()["completed_at"], json!(null));
    let (status, completed_at, _) = task_row(&app, task).await;
    assert_eq!(status, "DONE");
    let first_completion = completed_at.expect("the completion instant was stored");

    // Re-saving a finished task must not restate when it finished.
    let resaved = app
        .patch(
            &format!("/api/v1/tasks/{task}"),
            Some(&root.token),
            json!({"version": 2, "title": "Ship it (renamed)"}),
        )
        .await;
    resaved.assert_status(StatusCode::OK);
    let (_, still, _) = task_row(&app, task).await;
    assert_eq!(still, Some(first_completion));

    // Reopening is legitimate, and it must clear the instant.
    let reopened = app
        .patch(
            &format!("/api/v1/tasks/{task}"),
            Some(&root.token),
            json!({"version": 3, "status": "IN_PROGRESS"}),
        )
        .await;
    reopened.assert_status(StatusCode::OK);
    assert_eq!(reopened.json()["completed_at"], json!(null));
    let (status, completed_at, _) = task_row(&app, task).await;
    assert_eq!(status, "IN_PROGRESS");
    assert!(
        completed_at.is_none(),
        "leaving DONE must clear the completion instant"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_finished_task_can_be_reopened_but_not_retroactively_cancelled() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let project = create_project(&app, &root.token, "rollout", root.user_id, None).await;
    let task = create_task(&app, &root.token, project, "Ship it").await;

    app.patch(
        &format!("/api/v1/tasks/{task}"),
        Some(&root.token),
        json!({"version": 1, "status": "DONE"}),
    )
    .await
    .assert_status(StatusCode::OK);

    app.patch(
        &format!("/api/v1/tasks/{task}"),
        Some(&root.token),
        json!({"version": 2, "status": "CANCELLED"}),
    )
    .await
    .assert_error(StatusCode::CONFLICT, "INVALID_STATE_TRANSITION");

    // The dedicated cancellation endpoint refuses it too — one rule, two doors.
    app.delete(&format!("/api/v1/tasks/{task}"), Some(&root.token))
        .await
        .assert_error(StatusCode::CONFLICT, "INVALID_STATE_TRANSITION");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn patch_with_a_stale_version_is_a_conflict_and_changes_nothing() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let project = create_project(&app, &root.token, "rollout", root.user_id, None).await;
    let task = create_task(&app, &root.token, project, "Ship it").await;

    app.patch(
        &format!("/api/v1/tasks/{task}"),
        Some(&root.token),
        json!({"version": 1, "title": "First writer"}),
    )
    .await
    .assert_status(StatusCode::OK);
    app.patch(
        &format!("/api/v1/tasks/{task}"),
        Some(&root.token),
        json!({"version": 1, "title": "Second writer"}),
    )
    .await
    .assert_error(StatusCode::CONFLICT, "VERSION_CONFLICT");

    let title: String = sqlx::query_scalar("SELECT title FROM tasks WHERE id = $1")
        .bind(task)
        .fetch_one(&app.db)
        .await
        .expect("the task row");
    assert_eq!(title, "First writer");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn patch_refuses_a_field_it_does_not_own() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let project = create_project(&app, &root.token, "rollout", root.user_id, None).await;
    let task = create_task(&app, &root.token, project, "Ship it").await;

    for body in [
        // Moving a task between projects would move it across a different set of
        // client links: a share operation wearing an edit's clothes.
        json!({"version": 1, "project_id": Uuid::now_v7()}),
        json!({"version": 1, "completed_at": "2026-01-01T00:00:00Z"}),
        json!({"version": 1, "assignees": []}),
        json!({"title": "no version"}),
    ] {
        app.patch(&format!("/api/v1/tasks/{task}"), Some(&root.token), body)
            .await
            .assert_error(StatusCode::BAD_REQUEST, "BAD_REQUEST");
    }
}

// ---------------------------------------------------------------------------
// Cancellation
// ---------------------------------------------------------------------------

/// `DELETE` cancels; it never removes a row. A deleted task is a piece of history
/// that no longer exists, and cancellation records that the work was dropped.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_keeps_the_row_and_honours_the_version_query_parameter() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let project = create_project(&app, &root.token, "rollout", root.user_id, None).await;
    let task = create_task(&app, &root.token, project, "Drop this").await;

    // A stale concurrency token is honoured when supplied.
    app.delete(
        &format!("/api/v1/tasks/{task}?version=99"),
        Some(&root.token),
    )
    .await
    .assert_error(StatusCode::CONFLICT, "VERSION_CONFLICT");
    assert_eq!(task_row(&app, task).await.0, "TODO");

    app.delete(
        &format!("/api/v1/tasks/{task}?version=1"),
        Some(&root.token),
    )
    .await
    .assert_status(StatusCode::NO_CONTENT);

    let (status, completed_at, _) = task_row(&app, task).await;
    assert_eq!(status, "CANCELLED");
    assert!(completed_at.is_none());
    let (count,): (i64,) = sqlx::query_as("SELECT count(*) FROM tasks WHERE id = $1")
        .bind(task)
        .fetch_one(&app.db)
        .await
        .expect("count");
    assert_eq!(count, 1, "the row must survive cancellation");

    app.delete(&format!("/api/v1/tasks/{task}"), Some(&root.token))
        .await
        .assert_error(StatusCode::CONFLICT, "ALREADY_CANCELLED");

    // Cancellation is terminal: nothing brings the work back.
    app.patch(
        &format!("/api/v1/tasks/{task}"),
        Some(&root.token),
        json!({"version": 2, "status": "TODO"}),
    )
    .await
    .assert_error(StatusCode::CONFLICT, "INVALID_STATE_TRANSITION");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_cancellation_query_string_is_closed() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let project = create_project(&app, &root.token, "rollout", root.user_id, None).await;
    let task = create_task(&app, &root.token, project, "Drop this").await;

    app.delete(
        &format!("/api/v1/tasks/{task}?force=true"),
        Some(&root.token),
    )
    .await
    .assert_error(StatusCode::BAD_REQUEST, "BAD_REQUEST");
    assert_eq!(task_row(&app, task).await.0, "TODO");
}

// ---------------------------------------------------------------------------
// Assignees
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_assignee_can_be_added_listed_and_removed() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let project = create_project(&app, &root.token, "rollout", root.user_id, None).await;
    let task = create_task(&app, &root.token, project, "Ship it").await;
    let employee = create_employee(&app, &root.token, "dev@roleblank.test", None).await;

    app.post(
        &format!("/api/v1/tasks/{task}/assignees"),
        Some(&root.token),
        json!({"user_id": employee.user_id}),
    )
    .await
    .assert_status(StatusCode::NO_CONTENT);
    assert_eq!(live_assignee_count(&app, task, employee.user_id).await, 1);
    assert_eq!(audit_count_for(&app, "TASK.ASSIGNED", task).await, 1);

    let listed = app
        .get(
            &format!("/api/v1/tasks/{task}/assignees"),
            Some(&root.token),
        )
        .await;
    listed.assert_status(StatusCode::OK).assert_no_secrets();
    let items = listed.json().as_array().expect("a plain array").clone();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["user_id"], json!(employee.user_id.to_string()));

    app.post(
        &format!("/api/v1/tasks/{task}/assignees"),
        Some(&root.token),
        json!({"user_id": employee.user_id}),
    )
    .await
    .assert_error(StatusCode::CONFLICT, "ALREADY_ASSIGNED");

    app.delete(
        &format!("/api/v1/tasks/{task}/assignees/{}", employee.user_id),
        Some(&root.token),
    )
    .await
    .assert_status(StatusCode::NO_CONTENT);
    assert_eq!(live_assignee_count(&app, task, employee.user_id).await, 0);
    assert_eq!(audit_count_for(&app, "TASK.UNASSIGNED", task).await, 1);

    app.delete(
        &format!("/api/v1/tasks/{task}/assignees/{}", employee.user_id),
        Some(&root.token),
    )
    .await
    .assert_error(StatusCode::NOT_FOUND, "RESOURCE_NOT_FOUND");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn assignment_is_internal_only_and_a_cancelled_task_takes_none() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let project = create_project(&app, &root.token, "rollout", root.user_id, None).await;
    let task = create_task(&app, &root.token, project, "Ship it").await;
    let outsider = create_client_user(&app, &root.token, "contact@acme.test", None).await;
    let employee = create_employee(&app, &root.token, "dev@roleblank.test", None).await;

    app.post(
        &format!("/api/v1/tasks/{task}/assignees"),
        Some(&root.token),
        json!({"user_id": outsider.user_id}),
    )
    .await
    .assert_error(StatusCode::CONFLICT, "EXTERNAL_PRINCIPAL");

    app.post(
        &format!("/api/v1/tasks/{task}/assignees"),
        Some(&root.token),
        json!({"user_id": Uuid::now_v7()}),
    )
    .await
    .assert_error(StatusCode::BAD_REQUEST, "VALIDATION_FAILED");

    app.post(
        &format!("/api/v1/tasks/{task}/assignees"),
        Some(&root.token),
        json!({"user_id": employee.user_id, "role": "LEAD"}),
    )
    .await
    .assert_error(StatusCode::BAD_REQUEST, "BAD_REQUEST");

    app.delete(&format!("/api/v1/tasks/{task}"), Some(&root.token))
        .await
        .assert_status(StatusCode::NO_CONTENT);
    app.post(
        &format!("/api/v1/tasks/{task}/assignees"),
        Some(&root.token),
        json!({"user_id": employee.user_id}),
    )
    .await
    .assert_error(StatusCode::CONFLICT, "TASK_CANCELLED");
}

// ---------------------------------------------------------------------------
// Client visibility
// ---------------------------------------------------------------------------

/// Toggling the flag produces **two** records: the ordinary update, and a distinct
/// `TASK.CLIENT_VISIBILITY_CHANGED`. "Who decided this could leave the company,
/// and when" is a different question from "who edited this task", and it must be
/// answerable without reading every update event's changed-field list.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn toggling_client_visibility_is_audited_under_its_own_action() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let project = create_project(&app, &root.token, "rollout", root.user_id, None).await;
    let task = create_task(&app, &root.token, project, "Ship it").await;

    let published = app
        .patch(
            &format!("/api/v1/tasks/{task}"),
            Some(&root.token),
            json!({"version": 1, "client_visible": true}),
        )
        .await;
    published.assert_status(StatusCode::OK);
    assert_eq!(published.json()["client_visible"], json!(true));
    assert!(task_row(&app, task).await.2);
    assert_eq!(
        audit_count_for(&app, "TASK.CLIENT_VISIBILITY_CHANGED", task).await,
        1
    );
    assert_eq!(audit_count_for(&app, "TASK.UPDATED", task).await, 1);

    // Setting the flag to the value it already holds is not a visibility change and
    // must not manufacture a record that says one happened.
    app.patch(
        &format!("/api/v1/tasks/{task}"),
        Some(&root.token),
        json!({"version": 2, "client_visible": true}),
    )
    .await
    .assert_status(StatusCode::OK);
    assert_eq!(
        audit_count_for(&app, "TASK.CLIENT_VISIBILITY_CHANGED", task).await,
        1,
        "a no-op toggle must not be recorded as a visibility change"
    );

    // Withdrawing it is just as much a visibility decision as granting it.
    app.patch(
        &format!("/api/v1/tasks/{task}"),
        Some(&root.token),
        json!({"version": 3, "client_visible": false}),
    )
    .await
    .assert_status(StatusCode::OK);
    assert!(!task_row(&app, task).await.2);
    assert_eq!(
        audit_count_for(&app, "TASK.CLIENT_VISIBILITY_CHANGED", task).await,
        2
    );

    let previous: Vec<serde_json::Value> = sqlx::query_scalar(
        "SELECT metadata FROM audit_events
          WHERE action_code = 'TASK.CLIENT_VISIBILITY_CHANGED' AND target_id = $1
          ORDER BY seq",
    )
    .bind(task)
    .fetch_all(&app.db)
    .await
    .expect("the audit rows");
    assert_eq!(previous[0]["previous_client_visible"], json!(false));
    assert_eq!(previous[0]["client_visible"], json!(true));
    assert_eq!(previous[1]["previous_client_visible"], json!(true));
    assert_eq!(previous[1]["client_visible"], json!(false));
}

/// **Sharing a project does not share its tasks.** Both conditions are in the SQL
/// predicate, and a shared project with no visible tasks returns an empty page —
/// the correct answer, and not an error, because the client is not told that
/// hidden tasks exist.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_task_reaches_the_client_portal_only_when_it_is_individually_flagged() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let account = create_client_account(&app, &root.token, "acme", "Acme").await;
    let project = create_project(&app, &root.token, "rollout", root.user_id, None).await;
    let hidden = create_task(&app, &root.token, project, "Internal only").await;
    let shown = create_task(&app, &root.token, project, "Client facing").await;

    app.post(
        &format!("/api/v1/projects/{project}/clients"),
        Some(&root.token),
        json!({"client_account_id": account}),
    )
    .await
    .assert_status(StatusCode::NO_CONTENT);
    let contact = create_client_user(&app, &root.token, "contact@acme.test", Some(account)).await;

    // The project is shared; the tasks are not.
    let none_yet = app
        .get(
            &format!("/api/v1/client-portal/projects/{project}/tasks"),
            Some(&contact.token),
        )
        .await;
    none_yet.assert_status(StatusCode::OK);
    assert!(ids_in(&none_yet).is_empty());
    app.get(
        &format!("/api/v1/client-portal/tasks/{shown}"),
        Some(&contact.token),
    )
    .await
    .assert_error(StatusCode::NOT_FOUND, "RESOURCE_NOT_FOUND");

    app.patch(
        &format!("/api/v1/tasks/{shown}"),
        Some(&root.token),
        json!({"version": 1, "client_visible": true}),
    )
    .await
    .assert_status(StatusCode::OK);

    let now_one = app
        .get(
            &format!("/api/v1/client-portal/projects/{project}/tasks"),
            Some(&contact.token),
        )
        .await;
    now_one.assert_status(StatusCode::OK).assert_no_secrets();
    assert_eq!(ids_in(&now_one), vec![shown]);

    let detail = app
        .get(
            &format!("/api/v1/client-portal/tasks/{shown}"),
            Some(&contact.token),
        )
        .await;
    detail.assert_status(StatusCode::OK);
    // The external projection has no field for these, so nothing tells the client
    // which of the project's tasks were deliberately hidden from it.
    for forbidden in ["internal_note", "created_by", "version", "client_visible"] {
        assert!(
            detail.json().get(forbidden).is_none(),
            "the client task projection leaked `{forbidden}`"
        );
    }

    // The hidden task stays invisible however it is addressed.
    app.get(
        &format!("/api/v1/client-portal/tasks/{hidden}"),
        Some(&contact.token),
    )
    .await
    .assert_error(StatusCode::NOT_FOUND, "RESOURCE_NOT_FOUND");

    // Unsharing the project takes the visible task away again on the next query.
    app.delete(
        &format!("/api/v1/projects/{project}/clients/{account}"),
        Some(&root.token),
    )
    .await
    .assert_status(StatusCode::NO_CONTENT);
    app.get(
        &format!("/api/v1/client-portal/tasks/{shown}"),
        Some(&contact.token),
    )
    .await
    .assert_error(StatusCode::NOT_FOUND, "RESOURCE_NOT_FOUND");
}

/// An unshared project id must be a `404` rather than an empty page: an empty page
/// and a missing project would otherwise be distinguishable, and the difference is
/// enumerable.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_portal_task_listing_refuses_an_unshared_project_outright() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let account = create_client_account(&app, &root.token, "acme", "Acme").await;
    let shared = create_project(&app, &root.token, "shared", root.user_id, None).await;
    let secret = create_project(&app, &root.token, "secret", root.user_id, None).await;
    app.post(
        &format!("/api/v1/projects/{shared}/clients"),
        Some(&root.token),
        json!({"client_account_id": account}),
    )
    .await
    .assert_status(StatusCode::NO_CONTENT);
    let contact = create_client_user(&app, &root.token, "contact@acme.test", Some(account)).await;

    app.get(
        &format!("/api/v1/client-portal/projects/{shared}/tasks"),
        Some(&contact.token),
    )
    .await
    .assert_status(StatusCode::OK);
    app.get(
        &format!("/api/v1/client-portal/projects/{secret}/tasks"),
        Some(&contact.token),
    )
    .await
    .assert_error(StatusCode::NOT_FOUND, "RESOURCE_NOT_FOUND");
}

// ---------------------------------------------------------------------------
// Authorisation
// ---------------------------------------------------------------------------

/// `tasks.*` is INTERNAL-only, so an external principal is refused at the envelope
/// and the refusal is a `404` — the internal task surface does not confirm its own
/// existence to the client portal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_principal_cannot_reach_the_internal_task_surface() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let account = create_client_account(&app, &root.token, "acme", "Acme").await;
    let project = create_project(&app, &root.token, "rollout", root.user_id, None).await;
    let task = create_task(&app, &root.token, project, "Ship it").await;
    app.post(
        &format!("/api/v1/projects/{project}/clients"),
        Some(&root.token),
        json!({"client_account_id": account}),
    )
    .await
    .assert_status(StatusCode::NO_CONTENT);
    app.patch(
        &format!("/api/v1/tasks/{task}"),
        Some(&root.token),
        json!({"version": 1, "client_visible": true}),
    )
    .await
    .assert_status(StatusCode::OK);
    let contact = create_client_user(&app, &root.token, "contact@acme.test", Some(account)).await;

    // The portal shows it; the internal surface does not acknowledge it.
    app.get(
        &format!("/api/v1/client-portal/tasks/{task}"),
        Some(&contact.token),
    )
    .await
    .assert_status(StatusCode::OK);

    app.get("/api/v1/tasks", Some(&contact.token))
        .await
        .assert_error(StatusCode::NOT_FOUND, "RESOURCE_NOT_FOUND");
    app.get(&format!("/api/v1/tasks/{task}"), Some(&contact.token))
        .await
        .assert_error(StatusCode::NOT_FOUND, "RESOURCE_NOT_FOUND");
    app.patch(
        &format!("/api/v1/tasks/{task}"),
        Some(&contact.token),
        json!({"version": 2, "client_visible": false}),
    )
    .await
    .assert_error(StatusCode::NOT_FOUND, "RESOURCE_NOT_FOUND");
    app.delete(&format!("/api/v1/tasks/{task}"), Some(&contact.token))
        .await
        .assert_error(StatusCode::NOT_FOUND, "RESOURCE_NOT_FOUND");
    app.get(
        &format!("/api/v1/tasks/{task}/assignees"),
        Some(&contact.token),
    )
    .await
    .assert_error(StatusCode::NOT_FOUND, "RESOURCE_NOT_FOUND");
}

/// The seeded `employee` role holds `tasks.read@ASSIGNED` and
/// `tasks.update@ASSIGNED`, so being assigned is what makes a task reachable —
/// and nothing wider follows from it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_assigned_employee_may_read_and_update_only_their_own_tasks() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let project = create_project(&app, &root.token, "rollout", root.user_id, None).await;
    let mine = create_task(&app, &root.token, project, "Mine").await;
    let theirs = create_task(&app, &root.token, project, "Theirs").await;
    let employee = create_employee(&app, &root.token, "dev@roleblank.test", None).await;

    app.post(
        &format!("/api/v1/tasks/{mine}/assignees"),
        Some(&root.token),
        json!({"user_id": employee.user_id}),
    )
    .await
    .assert_status(StatusCode::NO_CONTENT);

    app.get(&format!("/api/v1/tasks/{mine}"), Some(&employee.token))
        .await
        .assert_status(StatusCode::OK);
    app.get(&format!("/api/v1/tasks/{theirs}"), Some(&employee.token))
        .await
        .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");

    let listed = app.get("/api/v1/tasks", Some(&employee.token)).await;
    listed.assert_status(StatusCode::OK);
    assert_eq!(
        ids_in(&listed),
        vec![mine],
        "an ASSIGNED grant lists exactly the assigned rows"
    );

    app.patch(
        &format!("/api/v1/tasks/{mine}"),
        Some(&employee.token),
        json!({"version": 1, "status": "IN_PROGRESS"}),
    )
    .await
    .assert_status(StatusCode::OK);
    app.patch(
        &format!("/api/v1/tasks/{theirs}"),
        Some(&employee.token),
        json!({"version": 1, "status": "IN_PROGRESS"}),
    )
    .await
    .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");

    // `tasks.create`, `tasks.assign` and `tasks.delete` are not in the role at all.
    app.post(
        "/api/v1/tasks",
        Some(&employee.token),
        json!({"project_id": project, "title": "Mine to make"}),
    )
    .await
    .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");
    app.post(
        &format!("/api/v1/tasks/{mine}/assignees"),
        Some(&employee.token),
        json!({"user_id": employee.user_id}),
    )
    .await
    .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");
    app.delete(&format!("/api/v1/tasks/{mine}"), Some(&employee.token))
        .await
        .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");
}
