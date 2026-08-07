//! Concurrency and failure handling in the transactional outbox worker.
//!
//! **Why the claim race is dangerous.** The outbox delivers password-reset and
//! invitation links. Every replica runs a worker, there is no leader election, and
//! there is deliberately no locking beyond what the claim statement itself takes —
//! so if two workers can claim one row, two identical reset links go out, or (worse,
//! because it is invisible) two workers both drive the same row's `attempts` counter
//! and dead-letter a deliverable message at half the intended budget. The defence is
//! `FOR UPDATE SKIP LOCKED` inside the claiming `UPDATE`: each worker locks the rows
//! it takes and steps over rows another worker already holds.
//!
//! That property cannot be observed through `run`, which claims, delivers and marks
//! each row terminal within microseconds — two workers racing through `run` would
//! agree whether or not `SKIP LOCKED` were there. So these tests drive `claim`
//! directly against the pool, once per worker, behind a barrier: with exactly one
//! claim per worker there is no second round in which a row could legitimately be
//! re-claimed, so a duplicate id can only mean two statements locked the same row.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

use roleblank_backend::modules::outbox::{
    self, mail, CancellationToken, OutboxWorker, MAX_BACKOFF_SECONDS,
};

use crate::common::TestApp;

/// A payload the worker can actually dispatch, so a test about *retries* is not
/// accidentally a test about malformed payloads.
fn deliverable_payload(n: usize) -> serde_json::Value {
    json!({
        "to": format!("recipient{n}@outbox.test"),
        "invite_url": "https://os.example.com/invitations/accept?token=rb_iv_x",
        "inviter_display_name": "Alice Admin",
        "expires_in_hours": 72,
    })
}

/// Insert an event directly. Used where the test needs a specific `event_type`,
/// `attempts` or `available_at` that no producer would ever create — including the
/// unknown-type case, which `outbox::enqueue` refuses at the call site by design and
/// which therefore can only arise from a row written by a *different* build.
async fn insert_event(app: &TestApp, event_type: &str, payload: serde_json::Value) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO outbox_events (id, event_type, payload) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(event_type)
        .bind(&payload)
        .execute(&app.db)
        .await
        .expect("insert an outbox event");
    id
}

#[derive(Debug, sqlx::FromRow)]
struct EventState {
    status: String,
    attempts: i32,
    available_at: OffsetDateTime,
    claimed_by: Option<String>,
    last_error: Option<String>,
    completed_at: Option<OffsetDateTime>,
}

async fn state_of(app: &TestApp, id: Uuid) -> EventState {
    sqlx::query_as(
        "SELECT status, attempts, available_at, claimed_by, last_error, completed_at
           FROM outbox_events WHERE id = $1",
    )
    .bind(id)
    .fetch_one(&app.db)
    .await
    .expect("read the outbox event")
}

/// Poll until an event reaches `attempts >= n`, or give up.
///
/// A poll rather than a fixed sleep: the worker's own poll interval is the thing
/// being waited on, and a sleep long enough to be safe would make this suite slow
/// while still being a race.
async fn wait_for_attempts(app: &TestApp, id: Uuid, n: i32) -> EventState {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let state = state_of(app, id).await;
        if state.attempts >= n {
            return state;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the worker never reached attempt {n} (stuck at {}, status {})",
            state.attempts,
            state.status
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn worker(app: &TestApp, provider: Arc<dyn mail::MailProvider>, id: &str) -> OutboxWorker {
    OutboxWorker::new(
        app.db.clone(),
        provider,
        // Below the 100 ms floor the constructor imposes, deliberately: the clamp is
        // what stops a misconfiguration becoming a busy loop, and relying on it here
        // means the suite notices if it is ever removed.
        Duration::from_millis(10),
        50,
        id,
    )
}

// ===========================================================================
// The claim race
// ===========================================================================

/// Six workers claiming at the same instant. Every event is claimed exactly once.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_workers_never_claim_the_same_event_twice() {
    const EVENTS: usize = 300;
    const WORKERS: usize = 6;

    let app = Arc::new(TestApp::spawn().await);

    let mut queued = Vec::with_capacity(EVENTS);
    for n in 0..EVENTS {
        queued.push(insert_event(&app, "mail.invitation", deliverable_payload(n)).await);
    }

    // Each worker asks for *every* event, so they are competing for the same rows
    // rather than being handed disjoint slices by a small batch size.
    let barrier = Arc::new(tokio::sync::Barrier::new(WORKERS));
    let mut handles = Vec::with_capacity(WORKERS);
    for n in 0..WORKERS {
        let app = app.clone();
        let barrier = barrier.clone();
        handles.push(tokio::spawn(async move {
            let worker = OutboxWorker::new(
                app.db.clone(),
                Arc::new(mail::LogSinkProvider),
                Duration::from_millis(100),
                EVENTS as u32,
                format!("racer-{n}"),
            );
            barrier.wait().await;
            // Exactly one claim per worker. With no second round, a row appearing in
            // two results can only mean two statements locked it simultaneously.
            worker
                .claim()
                .await
                .expect("claiming must not fail")
                .into_iter()
                .map(|e| e.id)
                .collect::<Vec<Uuid>>()
        }));
    }

    let mut all: Vec<Uuid> = Vec::new();
    for handle in handles {
        all.extend(handle.await.expect("task must not panic"));
    }

    let unique: HashSet<Uuid> = all.iter().copied().collect();
    assert_eq!(
        unique.len(),
        all.len(),
        "{} event(s) were claimed by more than one worker",
        all.len() - unique.len()
    );
    assert_eq!(
        unique.len(),
        EVENTS,
        "the workers between them claimed {} of {EVENTS} events",
        unique.len()
    );
    for id in &queued {
        assert!(unique.contains(id), "event {id} was never claimed");
    }

    // Every row now carries exactly one worker's name.
    let claimed: i64 = crate::fixtures::count(
        &app,
        "SELECT count(*) FROM outbox_events WHERE claimed_by IS NOT NULL",
    )
    .await;
    assert_eq!(claimed, EVENTS as i64);
}

/// A claim must not pick up work that is not due yet, however many workers ask.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_future_dated_event_is_never_claimed() {
    let app = TestApp::spawn().await;

    let due = insert_event(&app, "mail.invitation", deliverable_payload(1)).await;
    let not_due = insert_event(&app, "mail.invitation", deliverable_payload(2)).await;
    sqlx::query("UPDATE outbox_events SET available_at = now() + interval '1 hour' WHERE id = $1")
        .bind(not_due)
        .execute(&app.db)
        .await
        .expect("push the second event into the future");

    let claimed = worker(&app, Arc::new(mail::LogSinkProvider), "solo")
        .claim()
        .await
        .expect("claim");

    let ids: Vec<Uuid> = claimed.iter().map(|e| e.id).collect();
    assert_eq!(
        ids,
        vec![due],
        "a backed-off event was claimed before it was due, which would defeat the \
         retry schedule entirely"
    );
}

// ===========================================================================
// Retry schedule
// ===========================================================================

/// Each failure pushes the next attempt further out, on the schedule the pure
/// functions describe, and the delay is capped.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retry_backoff_grows_between_attempts_and_is_capped() {
    let app = TestApp::spawn().await;

    // The disabled provider fails every message with a *retryable* error, which is
    // exactly the shape of a real provider outage.
    let id = insert_event(&app, "mail.invitation", deliverable_payload(1)).await;

    let shutdown = CancellationToken::new();
    // Recorded *before* the worker exists, because the event is already due: the
    // first attempt happens spontaneously, and a `released` captured afterwards
    // would be later than the reschedule it is being compared against.
    let mut released = OffsetDateTime::now_utc();
    let handle = tokio::spawn(
        worker(&app, Arc::new(mail::DisabledProvider), "backoff").run(shutdown.clone()),
    );

    let mut previous = 0i64;
    for attempt in 1..=3i32 {
        if attempt > 1 {
            // Pull the row forward so the next attempt happens now rather than after
            // the real backoff, which the suite must not wait through. `released` is
            // taken first, so the reschedule that follows is measured from it.
            released = OffsetDateTime::now_utc();
            sqlx::query("UPDATE outbox_events SET available_at = now() WHERE id = $1")
                .bind(id)
                .execute(&app.db)
                .await
                .expect("make the event due again");
        }

        let state = wait_for_attempts(&app, id, attempt).await;
        assert_eq!(state.status, "FAILED", "attempt {attempt}");
        assert_eq!(
            state.claimed_by, None,
            "a rescheduled event must not stay claimed, or an operator cannot tell \
             it from one being worked on right now"
        );
        assert_eq!(
            state.completed_at, None,
            "a rescheduled event is not complete"
        );

        let expected = outbox::next_delay_seconds(id, attempt) as i64;
        let observed = (state.available_at - released).whole_seconds();
        assert!(
            (observed - expected).abs() <= 2,
            "attempt {attempt} was rescheduled {observed}s out; the schedule says \
             {expected}s"
        );
        assert!(
            observed > previous,
            "attempt {attempt} was rescheduled {observed}s out, no later than the \
             previous {previous}s — this is not backing off"
        );
        previous = observed;
    }

    // The cap, without waiting through eleven doublings. `attempts = 19` with a
    // raised budget means the next failure computes the delay for attempt 20, which
    // is far past the point where doubling would exceed the ceiling.
    sqlx::query(
        "UPDATE outbox_events
            SET attempts = 19, max_attempts = 30, available_at = now(), status = 'FAILED'
          WHERE id = $1",
    )
    .bind(id)
    .execute(&app.db)
    .await
    .expect("fast-forward the attempt counter");

    let released = OffsetDateTime::now_utc();
    let state = wait_for_attempts(&app, id, 20).await;
    let observed = (state.available_at - released).whole_seconds();
    let ceiling = MAX_BACKOFF_SECONDS as i64 + MAX_BACKOFF_SECONDS as i64 * 20 / 100;
    assert!(
        observed <= ceiling,
        "attempt 20 was rescheduled {observed}s out, past the {ceiling}s ceiling — \
         an unbounded exponent would push a retry years into the future"
    );
    assert_eq!(
        observed,
        outbox::next_delay_seconds(id, 20) as i64,
        "the stored schedule does not match the documented one"
    );

    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .expect("the worker must stop when cancelled")
        .expect("the worker task must not panic");
}

/// The attempt budget is a budget: reaching it is terminal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exhausting_the_attempt_budget_moves_the_row_to_dead() {
    let app = TestApp::spawn().await;
    let id = insert_event(&app, "mail.invitation", deliverable_payload(1)).await;

    // One attempt short of the budget, and due now.
    sqlx::query(
        "UPDATE outbox_events
            SET attempts = max_attempts - 1, status = 'FAILED', available_at = now()
          WHERE id = $1",
    )
    .bind(id)
    .execute(&app.db)
    .await
    .expect("bring the event to the edge of its budget");
    let budget: (i32,) = sqlx::query_as("SELECT max_attempts FROM outbox_events WHERE id = $1")
        .bind(id)
        .fetch_one(&app.db)
        .await
        .expect("read the budget");

    let shutdown = CancellationToken::new();
    let handle = tokio::spawn(
        worker(&app, Arc::new(mail::DisabledProvider), "budget").run(shutdown.clone()),
    );

    let state = wait_for_attempts(&app, id, budget.0).await;
    assert_eq!(
        state.status, "DEAD",
        "a row at its attempt budget was rescheduled instead of dead-lettered; it \
         would retry forever and look like a healthy backlog on every dashboard"
    );
    assert!(
        state.completed_at.is_some(),
        "a terminal row must record when it became terminal"
    );
    assert_eq!(state.claimed_by, None);
    assert!(
        state
            .last_error
            .as_deref()
            .unwrap_or_default()
            .contains("provider"),
        "the dead row must say why: {:?}",
        state.last_error
    );

    // And it stays dead: a DEAD row is not claimable.
    sqlx::query("UPDATE outbox_events SET available_at = now() WHERE id = $1")
        .bind(id)
        .execute(&app.db)
        .await
        .expect("make it due");
    tokio::time::sleep(Duration::from_millis(400)).await;
    let after = state_of(&app, id).await;
    assert_eq!(after.status, "DEAD");
    assert_eq!(
        after.attempts, budget.0,
        "a dead-lettered row was picked up again"
    );

    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .expect("the worker must stop when cancelled")
        .expect("the worker task must not panic");
}

/// An event type this build has no handler for goes straight to `DEAD`.
///
/// It can only arise during a rolling deploy, when an older worker reads a row a
/// newer one wrote. Retrying it eight times cannot make a handler appear, and a row
/// that retries forever hides the deployment mistake instead of surfacing it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unknown_event_type_is_dead_lettered_on_the_first_attempt() {
    let app = TestApp::spawn().await;

    let unknown = insert_event(&app, "mail.carrier_pigeon", deliverable_payload(1)).await;
    // A known type with a payload the handler cannot parse is the same class of
    // permanent failure, and is included so both branches are covered.
    let malformed = insert_event(&app, "mail.password_reset", json!({"nonsense": true})).await;
    let deliverable = insert_event(&app, "mail.invitation", deliverable_payload(2)).await;

    let shutdown = CancellationToken::new();
    let handle = tokio::spawn(
        worker(&app, Arc::new(mail::LogSinkProvider), "unknown").run(shutdown.clone()),
    );

    for id in [unknown, malformed] {
        let state = wait_for_attempts(&app, id, 1).await;
        assert_eq!(
            state.status, "DEAD",
            "a permanently undeliverable event was scheduled for retry"
        );
        assert_eq!(
            state.attempts, 1,
            "a permanent failure must cost exactly one attempt, not the whole budget"
        );
        assert!(state.completed_at.is_some());
        assert_eq!(state.claimed_by, None);
    }

    // The permanent failures must not poison the batch they arrived in.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let state = state_of(&app, deliverable).await;
        if state.status == "SENT" {
            assert!(state.completed_at.is_some());
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "a deliverable event queued alongside two dead-lettered ones never went \
             out (status {})",
            state.status
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let last_error: (Option<String>,) =
        sqlx::query_as("SELECT last_error FROM outbox_events WHERE id = $1")
            .bind(unknown)
            .fetch_one(&app.db)
            .await
            .expect("read the error");
    assert!(
        last_error
            .0
            .as_deref()
            .unwrap_or_default()
            .contains("no handler"),
        "the dead row must name the reason: {:?}",
        last_error.0
    );

    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .expect("the worker must stop when cancelled")
        .expect("the worker task must not panic");
}

// ===========================================================================
// Shutdown
// ===========================================================================

/// A cancelled worker stops, and leaves nothing claimed-but-abandoned.
///
/// A row that is still PENDING or FAILED while carrying a dead process's
/// `claimed_by` is the worst state to be in operationally: it will be redelivered
/// eventually, but an operator triaging a stuck queue cannot tell it from a row
/// being worked on right now, so the natural response is to wait for a worker that
/// no longer exists.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cancelled_worker_stops_without_abandoning_a_claim() {
    const EVENTS: usize = 200;

    let app = TestApp::spawn().await;
    for n in 0..EVENTS {
        insert_event(&app, "mail.invitation", deliverable_payload(n)).await;
    }

    let shutdown = CancellationToken::new();
    let handle = tokio::spawn(
        worker(&app, Arc::new(mail::LogSinkProvider), "quitter").run(shutdown.clone()),
    );

    // Cancel while the worker is part-way through a batch, so the mid-batch release
    // path — not merely the "cancelled before it started" path — is the one taken.
    tokio::time::sleep(Duration::from_millis(30)).await;
    shutdown.cancel();

    tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .expect("a cancelled worker must stop promptly, not finish the whole queue")
        .expect("the worker task must not panic");

    let abandoned: i64 = crate::fixtures::count(
        &app,
        "SELECT count(*) FROM outbox_events
          WHERE status IN ('PENDING', 'FAILED') AND claimed_by IS NOT NULL",
    )
    .await;
    assert_eq!(
        abandoned, 0,
        "{abandoned} row(s) are claimed by a worker that has stopped"
    );

    // Nothing was lost: every event is either delivered or still waiting.
    let accounted: i64 = crate::fixtures::count(
        &app,
        "SELECT count(*) FROM outbox_events WHERE status IN ('PENDING', 'SENT')",
    )
    .await;
    assert_eq!(accounted, EVENTS as i64);
}

/// A worker cancelled before it ever polls claims nothing at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_worker_cancelled_before_starting_claims_nothing() {
    let app = TestApp::spawn().await;
    for n in 0..10 {
        insert_event(&app, "mail.invitation", deliverable_payload(n)).await;
    }

    let shutdown = CancellationToken::new();
    shutdown.cancel();

    tokio::time::timeout(
        Duration::from_secs(5),
        worker(&app, Arc::new(mail::LogSinkProvider), "stillborn").run(shutdown),
    )
    .await
    .expect("an already-cancelled worker must return immediately");

    let touched: i64 = crate::fixtures::count(
        &app,
        "SELECT count(*) FROM outbox_events WHERE status <> 'PENDING' OR claimed_by IS NOT NULL",
    )
    .await;
    assert_eq!(touched, 0);
}

// ===========================================================================
// The producers and the worker must agree
// ===========================================================================

/// Every event the application actually enqueues must be one the worker can
/// deliver.
///
/// This is the test that would have caught the real defect: both producers built
/// their payloads with a free `json!` rather than from the type the worker
/// deserialises, so the password-reset producer wrote an event type with no
/// registered handler and the invitation producer wrote a payload the handler could
/// not parse. Both are *permanent* failures, so every message either flow ever
/// queued was dead-lettered on its first attempt — silently, because the endpoints
/// themselves returned success and the rows sat in a table nobody watches.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_event_the_application_enqueues_is_deliverable() {
    use axum::http::StatusCode;
    use serde_json::json as j;

    let app = TestApp::spawn().await;

    // A real password-reset request, through the real endpoint.
    let subject = crate::fixtures::actor(&app, "outbox-subject@race.test", &[]).await;
    app.post(
        "/api/v1/auth/password-reset/request",
        None,
        j!({ "email": subject.email }),
    )
    .await
    .assert_status(StatusCode::ACCEPTED);

    // A real invitation, through the real endpoint.
    let inviter =
        crate::fixtures::actor(&app, "outbox-inviter@race.test", &["iam.users.invite"]).await;
    app.post(
        "/api/v1/invitations",
        Some(&inviter.access_token),
        j!({
            "email": "outbox-invitee@race.test",
            "display_name": "Invitee",
            "principal_type": "INTERNAL",
            "role_ids": [],
        }),
    )
    .await
    .assert_status(StatusCode::CREATED);

    let queued: i64 = crate::fixtures::count(&app, "SELECT count(*) FROM outbox_events").await;
    assert_eq!(queued, 2, "both flows must have queued exactly one event");

    let shutdown = CancellationToken::new();
    let handle = tokio::spawn(
        worker(&app, Arc::new(mail::LogSinkProvider), "contract").run(shutdown.clone()),
    );

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let sent: i64 = crate::fixtures::count(
            &app,
            "SELECT count(*) FROM outbox_events WHERE status = 'SENT'",
        )
        .await;
        if sent == 2 {
            break;
        }
        let dead: Vec<(String, Option<String>)> = sqlx::query_as(
            "SELECT event_type, last_error FROM outbox_events WHERE status = 'DEAD'",
        )
        .fetch_all(&app.db)
        .await
        .expect("read dead rows");
        assert!(
            dead.is_empty(),
            "an event the application enqueued was dead-lettered: {dead:?}"
        );
        assert!(
            std::time::Instant::now() < deadline,
            "only {sent} of 2 queued events were delivered"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .expect("the worker must stop when cancelled")
        .expect("the worker task must not panic");
}
