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
        app.state.metrics.clone(),
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
                app.state.metrics.clone(),
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

// ===========================================================================
// The transactional guarantee itself (§15)
//
// The tests above are about the *worker*: who claims what, how often it retries,
// when it gives up. These are about the property the whole pattern exists to
// provide — that the side effect and the state change share a fate, and that a
// provider outage delays delivery rather than losing it.
// ===========================================================================

/// The row and the state change roll back together.
///
/// **Why this is the load-bearing test for the pattern.** If the outbox row were
/// written outside the caller's transaction — on the pool, or in a `tokio::spawn`
/// after commit — then a transaction that failed *after* enqueuing would still
/// send the mail. For a password reset that means a user receives a working reset
/// link for a reset the database rolled back: a live credential for a state change
/// that never happened. `enqueue` takes `&mut Transaction` precisely so that this
/// cannot be expressed, and this test is what proves the signature is honoured.
#[tokio::test]
async fn an_outbox_row_shares_the_fate_of_its_transaction() {
    let app = TestApp::spawn().await;

    // ---- rolled back: the queued side effect must vanish with it -----------
    let mut tx = app.db.begin().await.expect("begin");
    outbox::enqueue(&mut tx, "mail.invitation", deliverable_payload(1))
        .await
        .expect("enqueue inside the transaction");
    tx.rollback().await.expect("roll back");

    let after_rollback: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox_events")
        .fetch_one(&app.db)
        .await
        .expect("count");
    assert_eq!(
        after_rollback.0, 0,
        "a rolled-back transaction left a deliverable side effect queued — the mail \
         would be sent for a state change that never happened"
    );

    // ---- committed: it must survive, with no in-memory step in between -----
    let mut tx = app.db.begin().await.expect("begin");
    let id = outbox::enqueue(&mut tx, "mail.invitation", deliverable_payload(2))
        .await
        .expect("enqueue");
    tx.commit().await.expect("commit");

    let state = state_of(&app, id).await;
    assert_eq!(state.status, "PENDING");
    assert_eq!(state.attempts, 0);
    assert!(
        state.completed_at.is_none(),
        "a freshly committed event must not be marked complete"
    );
}

/// A provider outage delays the work; it never loses it.
///
/// **The scenario.** The database commit succeeds — the reset token exists, the
/// user's request genuinely happened — and the mail provider is then unavailable.
/// The naive implementations lose the message here: an in-process send fails and
/// the task is gone, and nothing anywhere records that a reset was owed. What must
/// happen instead is that the row stays queued, records its failure, and is
/// delivered once the provider returns.
///
/// This is also the test that makes the delivery guarantee legible: the row is
/// re-attempted after a failure with no way to know whether the *previous* attempt
/// reached the provider, which is exactly why the guarantee is at-least-once and
/// never exactly-once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_mail_provider_outage_does_not_lose_the_work() {
    let app = TestApp::spawn().await;

    // The state change and its side effect, committed together.
    let mut tx = app.db.begin().await.expect("begin");
    let id = outbox::enqueue(&mut tx, "mail.invitation", deliverable_payload(7))
        .await
        .expect("enqueue");
    tx.commit().await.expect("commit");

    // ---- the provider is down -------------------------------------------
    // `DisabledProvider` reports `ProviderNotConfigured`, which is deliberately
    // classified retryable: the provider is chosen by configuration, so a redeploy
    // can make it succeed, and dead-lettering loudly beats discarding a reset.
    let shutdown = CancellationToken::new();
    let failing = tokio::spawn(
        worker(&app, Arc::new(mail::DisabledProvider), "outage").run(shutdown.clone()),
    );
    let after_failure = wait_for_attempts(&app, id, 1).await;
    shutdown.cancel();
    failing.await.expect("the worker must not panic");

    assert_ne!(
        after_failure.status, "SENT",
        "the event was marked delivered although the provider failed"
    );
    assert_ne!(
        after_failure.status, "DEAD",
        "one transient failure must not exhaust an eight-attempt budget"
    );
    assert!(
        after_failure.completed_at.is_none(),
        "a failed attempt must not stamp a completion time"
    );
    assert!(
        after_failure.last_error.is_some(),
        "the failure must be recorded so an operator can triage it"
    );
    // Still on the books: the work is queued, not lost.
    let queued: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM outbox_events WHERE id = $1 AND status IN ('PENDING','FAILED')",
    )
    .bind(id)
    .fetch_one(&app.db)
    .await
    .expect("count");
    assert_eq!(queued.0, 1, "the event was lost when the provider failed");
    println!(
        "OUTBOX-EVIDENCE after provider outage: status={} attempts={} last_error={:?}",
        after_failure.status, after_failure.attempts, after_failure.last_error
    );

    // ---- the provider comes back ----------------------------------------
    // The row carries `available_at` in the future after a failure, so the backoff
    // is cleared to make the recovery observable without waiting out the delay.
    sqlx::query("UPDATE outbox_events SET available_at = now() WHERE id = $1")
        .bind(id)
        .execute(&app.db)
        .await
        .expect("clear the backoff");

    let shutdown = CancellationToken::new();
    let recovering = tokio::spawn(
        worker(&app, Arc::new(mail::LogSinkProvider), "recovered").run(shutdown.clone()),
    );

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let delivered = loop {
        let state = state_of(&app, id).await;
        if state.status == "SENT" {
            break state;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the event was never delivered after the provider recovered (status {}, \
             attempts {})",
            state.status,
            state.attempts
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    shutdown.cancel();
    recovering.await.expect("the worker must not panic");

    assert!(
        delivered.completed_at.is_some(),
        "a delivered event must record when it completed"
    );
    // The attempt that failed is still counted. `mark_sent` deliberately does not
    // touch `attempts` — only failures increment it — so the outage stays visible in
    // the row after recovery rather than being tidied away by the success.
    assert_eq!(
        delivered.attempts, 1,
        "the failed attempt was erased from the record by the eventual success"
    );
    println!(
        "OUTBOX-EVIDENCE after recovery: status={} attempts={}",
        delivered.status, delivered.attempts
    );
}

/// A handler must be idempotent, because the worker cannot promise it will not
/// re-deliver.
///
/// **What this test pins down is a limitation, not a defence.** A row is claimed,
/// the provider is called, and only then is the row marked `SENT`. A crash in that
/// window leaves a row that was delivered but is still claimable, and the next
/// worker will deliver it again — there is no way to avoid this without a
/// distributed transaction across PostgreSQL and a third-party mail API, which
/// neither side offers. The test simulates precisely that crash window by
/// resetting a delivered row to the state a killed worker would have left, and
/// asserts the second delivery happens.
///
/// The consequence is the contract every handler must be written against: **the
/// same event may be dispatched more than once**, so a handler must be safe to run
/// twice. It is asserted here rather than only documented, so that a future change
/// which quietly assumed exactly-once would have to delete a test to ship.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delivery_is_at_least_once_so_a_redelivery_is_possible() {
    let app = TestApp::spawn().await;

    let mut tx = app.db.begin().await.expect("begin");
    let id = outbox::enqueue(&mut tx, "mail.invitation", deliverable_payload(9))
        .await
        .expect("enqueue");
    tx.commit().await.expect("commit");

    let shutdown = CancellationToken::new();
    let first =
        tokio::spawn(worker(&app, Arc::new(mail::LogSinkProvider), "once").run(shutdown.clone()));
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if state_of(&app, id).await.status == "SENT" {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "never delivered");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    shutdown.cancel();
    first.await.expect("the worker must not panic");

    let after_first = state_of(&app, id).await;
    assert_eq!(after_first.status, "SENT");

    // Exactly the state a worker killed between "provider accepted" and "row marked
    // SENT" leaves behind: the mail is gone out, the row still looks deliverable.
    sqlx::query(
        "UPDATE outbox_events
            SET status = 'PENDING', completed_at = NULL, claimed_at = NULL,
                claimed_by = NULL, available_at = now()
          WHERE id = $1",
    )
    .bind(id)
    .execute(&app.db)
    .await
    .expect("simulate a crash between delivery and the status write");

    let shutdown = CancellationToken::new();
    let second =
        tokio::spawn(worker(&app, Arc::new(mail::LogSinkProvider), "twice").run(shutdown.clone()));
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let redelivered = loop {
        let state = state_of(&app, id).await;
        if state.status == "SENT" {
            break state;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the crash-window row was never re-delivered, which would mean a message \
             the provider never confirmed is silently dropped"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    shutdown.cancel();
    second.await.expect("the worker must not panic");

    // Two dispatches of one event. `attempts` cannot show this — only failures
    // increment it — so the evidence is `claimed_by`, which `mark_sent` leaves in
    // place precisely so the row records which instance delivered it. Two different
    // worker identities across two terminal deliveries is two dispatches.
    assert!(
        after_first.claimed_by.is_some() && redelivered.claimed_by.is_some(),
        "a delivered row must record which worker delivered it"
    );
    assert_ne!(
        after_first.claimed_by, redelivered.claimed_by,
        "the event was dispatched only once across a simulated crash — a message the \
         provider never confirmed would be silently dropped"
    );
    println!(
        "OUTBOX-EVIDENCE at-least-once: one event delivered twice, by {:?} then {:?}",
        after_first.claimed_by, redelivered.claimed_by
    );
}
