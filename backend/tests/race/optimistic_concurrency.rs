//! Concurrency: two writers, one row, one `version`.
//!
//! **Why this race is dangerous.** The failure mode is silent. Two editors load a
//! project at version 4, both change a different field, both save. Without the
//! version predicate the second write simply overwrites the first, and *nobody is
//! told*: both clients get a `200`, both believe their change landed, and the change
//! that vanished is only noticed later, if ever. That is TH-44, and it is worse than
//! an error because there is no signal to act on.
//!
//! The defence has two halves and this suite exercises both. The row is re-read
//! `FOR UPDATE` inside the transaction, so the loser blocks and then sees the
//! *committed* version rather than the one it loaded; and the `UPDATE` itself
//! carries `WHERE version = $expected`, so even if the lock were refactored away the
//! write would affect zero rows rather than silently win.

use std::sync::Arc;

use axum::http::StatusCode;
use serde_json::json;
use uuid::Uuid;

use crate::common::TestApp;
use crate::fixtures::{self, Actor};

const EDITOR: &str = "editor@race.test";

async fn editor(app: &TestApp) -> Actor {
    fixtures::actor(
        app,
        EDITOR,
        &[
            "projects.create",
            "projects.read",
            "projects.update",
            "tasks.create",
            "tasks.read",
            "tasks.update",
        ],
    )
    .await
}

/// The outcome of one racing PATCH, reduced to what the assertions need.
struct Outcome {
    status: StatusCode,
    code: Option<String>,
    expected: Option<i64>,
    actual: Option<i64>,
}

async fn patch(app: &TestApp, token: &str, path: &str, body: serde_json::Value) -> Outcome {
    let response = app.patch(path, Some(token), body).await;
    Outcome {
        status: response.status,
        code: response.error_code().map(str::to_string),
        expected: response
            .body
            .as_ref()
            .and_then(|b| b.pointer("/version_conflict/expected"))
            .and_then(serde_json::Value::as_i64),
        actual: response
            .body
            .as_ref()
            .and_then(|b| b.pointer("/version_conflict/actual"))
            .and_then(serde_json::Value::as_i64),
    }
}

/// The row's current name and version, read straight from the table.
async fn project_state(app: &TestApp, id: Uuid) -> (String, i32) {
    sqlx::query_as("SELECT name, version FROM projects WHERE id = $1")
        .bind(id)
        .fetch_one(&app.db)
        .await
        .expect("read the project")
}

async fn task_state(app: &TestApp, id: Uuid) -> (String, i32) {
    sqlx::query_as("SELECT title, version FROM tasks WHERE id = $1")
        .bind(id)
        .fetch_one(&app.db)
        .await
        .expect("read the task")
}

// ===========================================================================
// Projects
// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_simultaneous_project_patches_at_the_same_version_lose_nothing() {
    let app = Arc::new(TestApp::spawn().await);
    let actor = editor(&app).await;
    let project_id = fixtures::create_project(&app, &actor, "race-proj").await;

    let (original_name, original_version) = project_state(&app, project_id).await;
    assert_eq!(original_version, 1);

    // Both writers loaded version 1 and are changing the *same* field to different
    // values, so a lost update is directly observable in the row afterwards.
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let mut handles = Vec::with_capacity(2);
    for name in ["Renamed by A", "Renamed by B"] {
        let app = app.clone();
        let barrier = barrier.clone();
        let token = actor.access_token.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let outcome = patch(
                &app,
                &token,
                &format!("/api/v1/projects/{project_id}"),
                json!({ "version": 1, "name": name }),
            )
            .await;
            (name, outcome)
        }));
    }

    let mut winner: Option<&str> = None;
    let mut conflicts = 0usize;
    for handle in handles {
        let (name, outcome) = handle.await.expect("task must not panic");
        match outcome.status {
            StatusCode::OK => {
                assert!(winner.is_none(), "both patches succeeded — a lost update");
                winner = Some(name);
            }
            StatusCode::CONFLICT => {
                assert_eq!(outcome.code.as_deref(), Some("VERSION_CONFLICT"));
                // The two numbers a client needs in order to re-read and retry,
                // asserted as data. They are also in `detail`, but `detail` is prose
                // and prose is not a contract.
                assert_eq!(
                    outcome.expected,
                    Some(1),
                    "the conflict must report the version the client sent"
                );
                assert_eq!(
                    outcome.actual,
                    Some(2),
                    "the conflict must report the version the row now holds"
                );
                conflicts += 1;
            }
            other => panic!("a patch returned {other} with code {:?}", outcome.code),
        }
    }

    let winner = winner.expect("exactly one patch must succeed");
    assert_eq!(conflicts, 1);

    // The database, not the two responses, decides what actually happened.
    let (name, version) = project_state(&app, project_id).await;
    assert_eq!(
        name, winner,
        "the row holds neither writer's value, or holds the loser's"
    );
    assert_ne!(name, original_name);
    assert_eq!(
        version,
        2,
        "the version moved by {} — it must move exactly once per landed write",
        version - original_version
    );

    // Exactly one update was audited. Two would mean the losing transaction wrote an
    // audit record for a change that never landed.
    assert_eq!(fixtures::audit_count(&app, "PROJECT.UPDATED").await, 1);
}

/// What a losing PATCH reported, gathered during the race.
///
/// Collected rather than asserted inside the spawned task so that a failure is
/// reported as "seventeen losers were told the wrong current version" rather than
/// as an opaque panic inside a task the harness merely observes died.
type ConflictReports = Arc<std::sync::Mutex<Vec<(Option<i64>, Option<i64>)>>>;

/// Race `writers` PATCHes at the same version against one URL.
///
/// Returns the tally, which racer (if any) landed its write, and what every loser
/// was told to re-read.
async fn race_patches(
    app: Arc<TestApp>,
    token: String,
    path: String,
    field: &'static str,
    writers: usize,
) -> (fixtures::Tally, Vec<usize>, Vec<(Option<i64>, Option<i64>)>) {
    let winners: Arc<std::sync::Mutex<Vec<usize>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let conflicts: ConflictReports = Arc::new(std::sync::Mutex::new(Vec::new()));

    let tally = {
        let winners = winners.clone();
        let conflicts = conflicts.clone();
        fixtures::race(writers, move |n| {
            let app = app.clone();
            let token = token.clone();
            let path = path.clone();
            let winners = winners.clone();
            let conflicts = conflicts.clone();
            async move {
                // Every writer sends the *same* expected version and a *different*
                // value, so a lost update is visible in the surviving row.
                let response = app
                    .patch(
                        &path,
                        Some(&token),
                        json!({ "version": 1, field: format!("Writer {n}") }),
                    )
                    .await;
                if response.status == StatusCode::OK {
                    winners.lock().expect("winners").push(n);
                } else if response.status == StatusCode::CONFLICT {
                    let expected = response
                        .body
                        .as_ref()
                        .and_then(|b| b.pointer("/version_conflict/expected"))
                        .and_then(serde_json::Value::as_i64);
                    let actual = response
                        .body
                        .as_ref()
                        .and_then(|b| b.pointer("/version_conflict/actual"))
                        .and_then(serde_json::Value::as_i64);
                    conflicts
                        .lock()
                        .expect("conflicts")
                        .push((expected, actual));
                }
                response
            }
        })
        .await
    };

    let winners = winners.lock().expect("winners").clone();
    let conflicts = conflicts.lock().expect("conflicts").clone();
    (tally, winners, conflicts)
}

/// Assert the shape every versioned-update race must have, whatever the resource.
///
/// Kept in one place because the project and task assertions are identical claims
/// about different tables, and a divergence between them would be an accident
/// rather than a decision.
fn assert_exactly_one_write(
    label: &str,
    tally: &fixtures::Tally,
    winners: &[usize],
    conflicts: &[(Option<i64>, Option<i64>)],
    writers: usize,
) {
    tally.report(label);

    assert_eq!(
        tally.server_errors(),
        0,
        "{label}: concurrent PATCH produced server errors: {:?}",
        tally.by_status
    );
    assert!(
        tally
            .unexpected(&[StatusCode::OK, StatusCode::CONFLICT])
            .is_empty(),
        "{label}: every loser must be a clean 409, got: {:?}",
        tally.by_status
    );
    assert_eq!(
        winners.len(),
        1,
        "{label}: {} of {writers} patches landed — a lost update",
        winners.len()
    );
    assert_eq!(
        tally.code("VERSION_CONFLICT"),
        writers - 1,
        "{label}: a loser was refused for some reason other than the version: {:?}",
        tally.by_code
    );
    // Every loser must be told the *same* current version. A loser told a stale
    // "actual" would re-read, re-send, and lose again — a livelock that looks like
    // a flaky client.
    for (expected, actual) in conflicts {
        assert_eq!(
            *expected,
            Some(1),
            "{label}: a loser was told the wrong expected version"
        );
        assert_eq!(
            *actual,
            Some(2),
            "{label}: every loser must be told the same current version"
        );
    }
}

/// Fifty writers at the same version on a **project**. One lands; the other
/// forty-nine are told precisely what to re-read, and `version` moves exactly once.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn fifty_simultaneous_project_patches_produce_exactly_one_write() {
    const WRITERS: usize = 50;

    let app = Arc::new(TestApp::spawn().await);
    let actor = editor(&app).await;
    let project_id = fixtures::create_project(&app, &actor, "race-proj-50").await;

    let (_, original_version) = project_state(&app, project_id).await;
    assert_eq!(original_version, 1);

    let (tally, winners, conflicts) = race_patches(
        app.clone(),
        actor.access_token.clone(),
        format!("/api/v1/projects/{project_id}"),
        "name",
        WRITERS,
    )
    .await;
    assert_exactly_one_write("project_patch x50", &tally, &winners, &conflicts, WRITERS);

    // Re-read the row: exactly one change landed, and it is the winner's.
    let (name, version) = project_state(&app, project_id).await;
    assert_eq!(
        name,
        format!("Writer {}", winners[0]),
        "the surviving name is not the winner's — a losing write landed on top"
    );
    assert_eq!(
        version,
        original_version + 1,
        "the version moved by {} — it must move exactly once per landed write",
        version - original_version
    );
    assert_eq!(fixtures::audit_count(&app, "PROJECT.UPDATED").await, 1);
}

/// A stale version is refused even with no contention — the predicate is not merely
/// a tie-breaker for simultaneous writers.
#[tokio::test]
async fn a_stale_version_is_refused_sequentially_too() {
    let app = TestApp::spawn().await;
    let actor = editor(&app).await;
    let project_id = fixtures::create_project(&app, &actor, "stale-proj").await;

    let first = patch(
        &app,
        &actor.access_token,
        &format!("/api/v1/projects/{project_id}"),
        json!({ "version": 1, "name": "First" }),
    )
    .await;
    assert_eq!(first.status, StatusCode::OK);

    let stale = patch(
        &app,
        &actor.access_token,
        &format!("/api/v1/projects/{project_id}"),
        json!({ "version": 1, "name": "Second" }),
    )
    .await;
    assert_eq!(stale.status, StatusCode::CONFLICT);
    assert_eq!(stale.code.as_deref(), Some("VERSION_CONFLICT"));
    assert_eq!(stale.expected, Some(1));
    assert_eq!(stale.actual, Some(2));

    // Re-reading and retrying with the reported version is the documented recovery,
    // so it has to actually work.
    let retried = patch(
        &app,
        &actor.access_token,
        &format!("/api/v1/projects/{project_id}"),
        json!({ "version": 2, "name": "Second" }),
    )
    .await;
    assert_eq!(retried.status, StatusCode::OK);

    let (name, version) = project_state(&app, project_id).await;
    assert_eq!(name, "Second");
    assert_eq!(version, 3);
}

// ===========================================================================
// Tasks
// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_simultaneous_task_patches_at_the_same_version_lose_nothing() {
    let app = Arc::new(TestApp::spawn().await);
    let actor = editor(&app).await;
    let project_id = fixtures::create_project(&app, &actor, "race-task-proj").await;
    let task_id = fixtures::create_task(&app, &actor, project_id, "Original title").await;

    let (_, original_version) = task_state(&app, task_id).await;
    assert_eq!(original_version, 1);

    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let mut handles = Vec::with_capacity(2);
    for title in ["Retitled by A", "Retitled by B"] {
        let app = app.clone();
        let barrier = barrier.clone();
        let token = actor.access_token.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let outcome = patch(
                &app,
                &token,
                &format!("/api/v1/tasks/{task_id}"),
                json!({ "version": 1, "title": title }),
            )
            .await;
            (title, outcome)
        }));
    }

    let mut winner: Option<&str> = None;
    let mut conflicts = 0usize;
    for handle in handles {
        let (title, outcome) = handle.await.expect("task must not panic");
        match outcome.status {
            StatusCode::OK => {
                assert!(winner.is_none(), "both patches succeeded — a lost update");
                winner = Some(title);
            }
            StatusCode::CONFLICT => {
                assert_eq!(outcome.code.as_deref(), Some("VERSION_CONFLICT"));
                assert_eq!(outcome.expected, Some(1));
                assert_eq!(outcome.actual, Some(2));
                conflicts += 1;
            }
            other => panic!("a patch returned {other} with code {:?}", outcome.code),
        }
    }

    let winner = winner.expect("exactly one patch must succeed");
    assert_eq!(conflicts, 1);

    let (title, version) = task_state(&app, task_id).await;
    assert_eq!(title, winner, "the surviving title is not the winner's");
    assert_eq!(version, 2);
    assert_eq!(fixtures::audit_count(&app, "TASK.UPDATED").await, 1);
}

/// Fifty writers at the same version on a **task**.
///
/// Tasks carry their own `version` column and their own update path, so the
/// project result above says nothing about them. A guard that exists on one
/// resource and not the other is the ordinary way this defect ships.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn fifty_simultaneous_task_patches_produce_exactly_one_write() {
    const WRITERS: usize = 50;

    let app = Arc::new(TestApp::spawn().await);
    let actor = editor(&app).await;
    let project_id = fixtures::create_project(&app, &actor, "race-task-proj-50").await;
    let task_id = fixtures::create_task(&app, &actor, project_id, "Original title").await;

    let (_, original_version) = task_state(&app, task_id).await;
    assert_eq!(original_version, 1);

    let (tally, winners, conflicts) = race_patches(
        app.clone(),
        actor.access_token.clone(),
        format!("/api/v1/tasks/{task_id}"),
        "title",
        WRITERS,
    )
    .await;
    assert_exactly_one_write("task_patch x50", &tally, &winners, &conflicts, WRITERS);

    let (title, version) = task_state(&app, task_id).await;
    assert_eq!(
        title,
        format!("Writer {}", winners[0]),
        "the surviving title is not the winner's — a losing write landed on top"
    );
    assert_eq!(
        version,
        original_version + 1,
        "the version moved by {} — it must move exactly once per landed write",
        version - original_version
    );
    assert_eq!(fixtures::audit_count(&app, "TASK.UPDATED").await, 1);
}

/// The dangerous variant: two writers changing *different* fields. This is where a
/// missing version predicate hides best, because neither client's change looks
/// obviously wrong afterwards — one of them has simply reverted to the value the
/// other loaded.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_edits_to_different_fields_still_conflict_rather_than_merge() {
    let app = Arc::new(TestApp::spawn().await);
    let actor = editor(&app).await;
    let project_id = fixtures::create_project(&app, &actor, "diff-fields").await;

    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let bodies = [
        json!({ "version": 1, "name": "Name only" }),
        json!({ "version": 1, "description": "Description only" }),
    ];
    let mut handles = Vec::with_capacity(2);
    for body in bodies {
        let app = app.clone();
        let barrier = barrier.clone();
        let token = actor.access_token.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            patch(
                &app,
                &token,
                &format!("/api/v1/projects/{project_id}"),
                body,
            )
            .await
        }));
    }

    let mut succeeded = 0usize;
    for handle in handles {
        let outcome = handle.await.expect("task must not panic");
        match outcome.status {
            StatusCode::OK => succeeded += 1,
            StatusCode::CONFLICT => {
                assert_eq!(outcome.code.as_deref(), Some("VERSION_CONFLICT"));
            }
            other => panic!("a patch returned {other} with code {:?}", outcome.code),
        }
    }

    assert_eq!(
        succeeded, 1,
        "disjoint field edits were silently merged; PATCH here is a whole-row write \
         and must not pretend otherwise"
    );

    let row: (String, String, i32) =
        sqlx::query_as("SELECT name, description, version FROM projects WHERE id = $1")
            .bind(project_id)
            .fetch_one(&app.db)
            .await
            .expect("read the project");
    assert_eq!(row.2, 2, "exactly one write must have landed");
    // Exactly one of the two intended changes is present. Both would mean the writes
    // merged; neither would mean both were lost.
    let name_changed = row.0 == "Name only";
    let description_changed = row.1 == "Description only";
    assert!(
        name_changed ^ description_changed,
        "expected exactly one change to have landed, got name={:?} description={:?}",
        row.0,
        row.1
    );
}
