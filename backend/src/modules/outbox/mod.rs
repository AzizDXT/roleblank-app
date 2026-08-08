//! Transactional outbox and its worker.
//!
//! **Why an outbox at all.** A side effect that must happen "because" a database
//! change happened has exactly three naive implementations, and two of them are
//! wrong:
//!
//! - *Send inside the transaction.* The email goes out, then the transaction rolls
//!   back. A user receives a password-reset link for a reset that never happened.
//! - *`tokio::spawn` after commit.* The commit lands, the process is SIGKILLed (a
//!   deploy, an OOM kill, a node eviction) a microsecond later, and the task is
//!   gone. The user's reset silently never arrives, and nothing anywhere records
//!   that it was owed.
//! - *Write a row in the same transaction and deliver it later.* The row and the
//!   state change commit or roll back together, atomically, with no window. A
//!   crash at any point leaves the work durably queued.
//!
//! Only the third is correct, and it is what `enqueue` implements — which is why it
//! takes `&mut Transaction` and not a pool. There is no code path that can create
//! the side effect without the state change, or the state change without the side
//! effect.
//!
//! The delivery guarantee is **at-least-once**, not exactly-once. Exactly-once
//! across a database and a third-party mail API would need a distributed
//! transaction that neither side offers; a crash between "provider accepted" and
//! "row marked SENT" therefore re-sends. A duplicate password-reset email is an
//! acceptable outcome; a missing one is not.

pub mod idempotency;
pub mod mail;

use serde::{Deserialize, Serialize};
use sqlx::postgres::PgPool;
use sqlx::{Postgres, Transaction};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

/// Re-exported so a caller of [`OutboxWorker::run`] — `cli.rs`, or a test that
/// needs to prove the worker shuts down without abandoning a claim — does not have
/// to take a direct dependency on `tokio-util` just to name the argument this
/// module's own public API demands.
pub use tokio_util::sync::CancellationToken;

use crate::platform::errors::AppError;
use crate::platform::observability::sanitize;
use mail::{MailKind, MailProvider, OutboundMail};

/// Canonical event types.
///
/// Constants rather than free strings so a typo becomes a compile error instead of
/// a row that no handler claims and that therefore dead-letters at 03:00.
pub mod event_type {
    pub const MAIL_PASSWORD_RESET: &str = "mail.password_reset";
    pub const MAIL_INVITATION: &str = "mail.invitation";

    /// Every type this build knows how to handle.
    pub const ALL: &[&str] = &[MAIL_PASSWORD_RESET, MAIL_INVITATION];
}

/// Matches `outbox_events.event_type`'s `CHECK (length(event_type) BETWEEN 1 AND 100)`.
const MAX_EVENT_TYPE_LEN: usize = 100;

/// First retry delay. Short enough that a brief provider blip costs seconds, long
/// enough that a hard outage is not hammered.
pub const BASE_BACKOFF_SECONDS: u64 = 5;

/// Ceiling on the exponential term. Beyond an hour the schedule is no longer
/// meaningfully "backing off"; it is just a slow poll, and the attempt budget will
/// dead-letter the row soon anyway.
pub const MAX_BACKOFF_SECONDS: u64 = 3600;

/// Jitter as a percentage of the backoff. ±20% is enough to break up a thundering
/// herd without materially changing the schedule an operator reads off a dashboard.
pub const JITTER_PERCENT: u64 = 20;

/// How long a claim is respected by other workers before the row is claimable again.
///
/// **Why this exists.** `FOR UPDATE SKIP LOCKED` only excludes workers that are
/// claiming at the *same instant*: the claiming `UPDATE` is a single autocommit
/// statement, so its row locks are gone the moment it returns. Without a lease, a
/// second worker polling a few milliseconds later sees rows that are still `PENDING`
/// — the claim does not move them out of that status — and claims them again while
/// the first worker is still delivering them. That was measured, not theorised: six
/// workers claiming 300 events took 601 claims between them.
///
/// The visible consequence is a duplicated password-reset or invitation email, which
/// at-least-once delivery tolerates. The invisible one is worse: both workers then
/// call `mark_failed` on the same row, `attempts` is incremented twice per real
/// attempt, and a deliverable message is dead-lettered at half its intended budget
/// during exactly the provider outage the budget exists to survive.
///
/// Sixty seconds is chosen so that it comfortably exceeds one delivery attempt
/// (which is bounded by the provider's own timeout) while keeping recovery from a
/// killed worker to one minute. A row whose worker died mid-attempt is re-claimable
/// once the lease lapses; a row whose worker shut down cleanly was already released.
pub const CLAIM_LEASE_SECONDS: i64 = 60;

/// Budget for `last_error`.
///
/// The column is `CHECK (length(last_error) <= 2000)` and `sanitize_bounded`
/// appends a one-character ellipsis when it truncates. A budget of 2000 would
/// therefore produce a 2001-character string and the constraint would reject the
/// very UPDATE that is trying to record a failure — turning a retryable delivery
/// error into a row stuck in a claimed state forever. 1999 leaves room for the
/// marker.
pub const MAX_LAST_ERROR_CHARS: usize = 1999;

// ---------------------------------------------------------------------------
// enqueue
// ---------------------------------------------------------------------------

/// Queue an event **inside the caller's transaction**.
///
/// Taking `&mut Transaction<'_, Postgres>` is the entire design (see the module
/// docs). A pool-taking variant would compile and would be wrong, so it does not
/// exist.
pub async fn enqueue(
    tx: &mut Transaction<'_, Postgres>,
    event_type: &str,
    payload: serde_json::Value,
) -> Result<Uuid, AppError> {
    // Rejected here as well as handled at dispatch. An unknown type at *enqueue*
    // time is always a programming error in this build, and catching it at the
    // call site turns it into a failing test rather than a dead-lettered row
    // discovered by a user who never got their invitation. Dispatch still handles
    // the unknown case, because a row written by a newer deployment can be read by
    // an older worker during a rolling deploy.
    if !event_type::ALL.contains(&event_type) {
        return Err(AppError::internal(format!(
            "refusing to enqueue an outbox event with no registered handler: `{}`",
            sanitize::sanitize_bounded(event_type, MAX_EVENT_TYPE_LEN)
        )));
    }

    let id = Uuid::now_v7();
    // Explicit column list: a `SELECT *`-shaped insert breaks silently when the
    // schema gains a column. `status`, `attempts`, `max_attempts` and `available_at`
    // deliberately take their database defaults, so the retry policy lives in one
    // place (the migration) rather than being restated at every call site.
    sqlx::query("INSERT INTO outbox_events (id, event_type, payload) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(event_type)
        .bind(&payload)
        .execute(&mut **tx)
        .await
        .map_err(AppError::from)?;

    Ok(id)
}

// ---------------------------------------------------------------------------
// payloads
// ---------------------------------------------------------------------------

/// Payload for `mail.password_reset`.
///
/// Note what is *absent*: the raw token. The URL already contains it, and carrying
/// it twice would mean two places to redact. The payload sits in a `jsonb` column
/// that an operator with read access to the database can see — that is an accepted
/// exposure for the lifetime of the row (the worker marks it SENT within seconds
/// and the token is single-use and short-lived), and it is why nothing here is ever
/// logged.
///
/// Deliberately **not** `deny_unknown_fields`: during a rolling deploy an old
/// worker will read rows written by a new one. Rejecting an unrecognised optional
/// field would dead-letter every in-flight message for the duration of the rollout.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordResetPayload {
    pub to: String,
    pub reset_url: String,
    pub expires_in_minutes: u32,
}

/// Payload for `mail.invitation`. Same forward-compatibility rule as above.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvitationPayload {
    pub to: String,
    pub invite_url: String,
    pub inviter_display_name: String,
    pub expires_in_hours: u32,
}

/// The longest address the API accepts, mirroring `shared::validation::MAX_EMAIL_LEN`.
const MAX_RECIPIENT_LEN: usize = 254;

/// Build the link a recipient clicks.
///
/// One helper rather than a `format!` at each call site, because the two call sites
/// (a password reset and an invitation) must agree on how the base URL's trailing
/// slash is handled — `https://os.example.com/` and `https://os.example.com` must
/// produce the same link, or one deployment's links silently gain a `//`.
///
/// The token needs no percent-encoding: it is an ASCII prefix followed by
/// base64url-no-pad, whose alphabet is `[A-Za-z0-9_-]` and contains no character
/// that is special in a query string. That is a property of `tokens::generate`, not
/// an assumption, and the unit test below pins it — a future token format that used
/// standard base64 would otherwise produce URLs silently truncated at the first `+`.
pub fn action_link(base_url: &str, path: &str, token: &str) -> String {
    format!("{}{path}?token={token}", base_url.trim_end_matches('/'))
}

/// Structural check on a recipient read back out of a payload.
///
/// The address was validated when it was enqueued, but this worker may be
/// processing a row written by a different build, or by a path that changed. A
/// malformed address cannot become deliverable by waiting, so it is a *permanent*
/// failure — retrying it eight times just delays the operator noticing.
fn validate_recipient(to: &str) -> Result<(), HandlerError> {
    if to.is_empty() || to.len() > MAX_RECIPIENT_LEN {
        return Err(HandlerError::Permanent(
            "outbox payload recipient has an invalid length",
        ));
    }
    if !to.contains('@') {
        return Err(HandlerError::Permanent(
            "outbox payload recipient is not an address",
        ));
    }
    // A CR/LF in an address is SMTP header injection against any future real
    // provider, and log injection against this one.
    if to.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(HandlerError::Permanent(
            "outbox payload recipient contains control or whitespace characters",
        ));
    }
    Ok(())
}

impl PasswordResetPayload {
    fn into_mail(self) -> Result<OutboundMail, HandlerError> {
        validate_recipient(&self.to)?;
        Ok(OutboundMail {
            subject: "Reset your RoleBlank password".to_string(),
            // The body carries a live single-use token. It is built here and handed
            // straight to the provider; it is never logged, never put in an audit
            // event, and never written to `last_error`.
            body_text: format!(
                "A password reset was requested for your RoleBlank account.\n\n\
                 Open this link to choose a new password:\n{}\n\n\
                 The link can be used once and expires in {} minutes.\n\
                 If you did not request this, you can ignore this message.\n",
                self.reset_url, self.expires_in_minutes
            ),
            to: self.to,
            kind: MailKind::PasswordReset,
        })
    }
}

impl InvitationPayload {
    fn into_mail(self) -> Result<OutboundMail, HandlerError> {
        validate_recipient(&self.to)?;
        Ok(OutboundMail {
            subject: "You have been invited to RoleBlank".to_string(),
            body_text: format!(
                "{} has invited you to RoleBlank.\n\n\
                 Open this link to accept the invitation and create your account:\n{}\n\n\
                 The invitation can be used once and expires in {} hours.\n",
                sanitize::sanitize_bounded(&self.inviter_display_name, 200),
                self.invite_url,
                self.expires_in_hours
            ),
            to: self.to,
            kind: MailKind::Invitation,
        })
    }
}

// ---------------------------------------------------------------------------
// dispatch
// ---------------------------------------------------------------------------

/// Why a delivery attempt failed, and — the only part the retry policy cares about
/// — whether waiting could help.
///
/// Both variants carry a `&'static str`, never a formatted message. That is the
/// mechanism, not a convention: because the type cannot hold a `String`, no
/// serde error text, no provider message and no fragment of a payload can reach
/// `outbox_events.last_error`, which is a column an operator reads casually and
/// which is not covered by any secret-scrubbing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HandlerError {
    /// No amount of retrying can change the outcome. Straight to `DEAD`.
    Permanent(&'static str),
    /// May succeed later. Scheduled with exponential backoff.
    Transient(&'static str),
}

impl HandlerError {
    fn message(self) -> &'static str {
        match self {
            HandlerError::Permanent(m) | HandlerError::Transient(m) => m,
        }
    }
    fn is_permanent(self) -> bool {
        matches!(self, HandlerError::Permanent(_))
    }
}

/// Turn a stored event into the message it describes.
///
/// Pure, so the whole dispatch table — including the unknown-type and
/// malformed-payload paths — is unit-testable without a database or a provider.
fn build_mail(event_type: &str, payload: &serde_json::Value) -> Result<OutboundMail, HandlerError> {
    match event_type {
        event_type::MAIL_PASSWORD_RESET => {
            let parsed: PasswordResetPayload = serde_json::from_value(payload.clone())
                // The serde error is discarded rather than recorded: it quotes the
                // offending JSON, which for this event type is a live reset URL.
                .map_err(|_| {
                    HandlerError::Permanent("payload does not match the mail.password_reset schema")
                })?;
            parsed.into_mail()
        }
        event_type::MAIL_INVITATION => {
            let parsed: InvitationPayload =
                serde_json::from_value(payload.clone()).map_err(|_| {
                    HandlerError::Permanent("payload does not match the mail.invitation schema")
                })?;
            parsed.into_mail()
        }
        // An unknown type goes to DEAD **immediately**. Retrying it eight times
        // cannot make a handler appear, and a row that retries forever is
        // indistinguishable from a healthy backlog on every dashboard — it hides
        // the deployment mistake that caused it instead of surfacing it.
        _ => Err(HandlerError::Permanent(
            "no handler is registered for this event type",
        )),
    }
}

/// Bound and de-fang a string before it is written to `last_error`.
///
/// Every caller currently passes a compile-time constant, so this is belt and
/// braces — but `last_error` is displayed in operator tooling and a future variant
/// that interpolates something dynamic must not be able to forge a log record
/// (TH-32) or blow the column's length constraint.
pub fn sanitise_last_error(input: &str) -> String {
    sanitize::sanitize_bounded(input, MAX_LAST_ERROR_CHARS)
}

// ---------------------------------------------------------------------------
// retry schedule
// ---------------------------------------------------------------------------

/// Exponential backoff for the Nth attempt, before jitter.
///
/// `attempts` is the number of attempts already made, so the first retry (after
/// one failure) waits `BASE_BACKOFF_SECONDS`. Doubling is capped both by
/// `MAX_BACKOFF_SECONDS` and by clamping the exponent, so no shift can overflow
/// regardless of what a corrupt `attempts` value in the database says.
pub fn backoff_seconds(attempts: i32) -> u64 {
    let exponent = attempts.clamp(1, 20) as u32 - 1;
    let multiplier = 1u64.checked_shl(exponent).unwrap_or(u64::MAX);
    BASE_BACKOFF_SECONDS
        .saturating_mul(multiplier)
        .min(MAX_BACKOFF_SECONDS)
}

/// Jitter derived from the event id, not from a random source.
///
/// Two properties are wanted at once. *De-synchronisation*: a thousand events that
/// fail in the same batch must not all retry in the same second, or the provider
/// gets the same thundering herd that knocked it over. *Reproducibility*: a test
/// that asserts a schedule must be able to compute the expected instant, and an
/// operator reading `available_at` must be able to explain it. Seeding from the
/// UUID gives both — UUIDv7's low bytes are random, so the spread across events is
/// uniform, while the value for any single event is fixed forever.
pub fn jitter_seconds(id: Uuid, base_seconds: u64) -> u64 {
    let bytes = id.as_bytes();
    // The last two bytes. In UUIDv7 the tail is CSPRNG output, so this is a
    // uniform draw across events; in any other UUID version it is at worst a
    // constant, which degrades to "no jitter" rather than to a wrong schedule.
    let raw = u64::from(u16::from_be_bytes([bytes[14], bytes[15]]));
    let span = base_seconds.saturating_mul(JITTER_PERCENT) / 100;
    if span == 0 {
        0
    } else {
        raw % (span + 1)
    }
}

/// The full delay before the next attempt.
pub fn next_delay_seconds(id: Uuid, attempts: i32) -> u64 {
    let base = backoff_seconds(attempts);
    base.saturating_add(jitter_seconds(id, base))
}

// ---------------------------------------------------------------------------
// worker
// ---------------------------------------------------------------------------

/// One claimed row. Explicit columns, explicit types — the worker never does
/// `SELECT *`, so adding a column to the table cannot change what it reads.
///
/// Public, together with [`OutboxWorker::claim`], because the no-double-claim
/// property is the single most important thing about running more than one worker
/// and it cannot be demonstrated through `run`: `run` delivers and marks each row
/// terminal within microseconds, so two workers racing through it would pass
/// whether or not `SKIP LOCKED` were present. A test has to be able to hold several
/// claims open at once and compare the sets.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ClaimedEvent {
    pub id: Uuid,
    pub event_type: String,
    pub payload: serde_json::Value,
    pub attempts: i32,
}

/// Rows removed per sweep. Bounded so a long-neglected table drains over several
/// polls instead of one statement locking a large range.
const SWEEP_BATCH: i64 = 500;

pub struct OutboxWorker {
    pool: PgPool,
    mail: Arc<dyn MailProvider>,
    /// So a delivery failure is visible to an operator as a number, not only as a
    /// log line and a `last_error` column somebody has to go and read.
    metrics: Arc<crate::platform::observability::metrics::Metrics>,
    poll_interval: Duration,
    batch_size: u32,
    /// Recorded in `claimed_by` so an operator can tell which instance is stuck.
    /// Bounded to the column's `length(claimed_by) <= 100`.
    worker_id: String,
}

/// Bound a caller-supplied worker id.
///
/// `claimed_by` is `CHECK (claimed_by IS NULL OR length(claimed_by) <= 100)`, and
/// the id also reaches every log line the worker emits. `cli.rs` builds it from
/// `HOSTNAME` and the pid, both of which come from the environment rather than from
/// a request — but an over-long `HOSTNAME` would otherwise fail the claim UPDATE
/// itself, taking the whole worker down rather than one row.
fn normalise_worker_id(raw: &str) -> String {
    sanitize::sanitize_bounded(raw, 99)
}

/// Identify *this process* in `claimed_by`.
///
/// Derived here rather than passed in by the caller: an id the caller invents is
/// one more thing to forget, and copy-pasting a deployment manifest would give two
/// replicas the same id — precisely when `claimed_by` stops being able to answer
/// the only question it exists for, "which process is sitting on this row?".
///
/// `HOSTNAME` is the container id under Docker and the pod name under Kubernetes,
/// so it is the part an operator can act on; the pid narrows it to a process they
/// can actually signal. Both come from the environment rather than from a request,
/// but they are bounded anyway — an over-long `HOSTNAME` would otherwise fail the
/// claim UPDATE's length CHECK and take the whole worker down rather than one row.
fn default_worker_id() -> String {
    let host = std::env::var("HOSTNAME")
        .ok()
        .filter(|h| !h.trim().is_empty())
        .unwrap_or_else(|| "roleblank-api".to_string());
    // The host is bounded first so the pid cannot be the part that gets truncated
    // away — an id ending in "…" identifies nothing.
    let host = sanitize::sanitize_bounded(host.trim(), 60);
    normalise_worker_id(&format!("{host}-{}", std::process::id()))
}

impl OutboxWorker {
    /// Construct with an explicit worker id.
    ///
    /// The id is a constructor parameter rather than something derived internally
    /// because a caller that already knows its instance name (a Nomad alloc id, a
    /// systemd unit instance) should be able to use it — `claimed_by` is only
    /// useful if it names something the operator recognises. Callers with nothing
    /// better to offer should use [`OutboxWorker::with_derived_id`].
    pub fn new(
        pool: PgPool,
        mail: Arc<dyn MailProvider>,
        metrics: Arc<crate::platform::observability::metrics::Metrics>,
        poll_interval: Duration,
        batch_size: u32,
        worker_id: impl Into<String>,
    ) -> Self {
        let raw_worker_id: String = worker_id.into();
        Self {
            pool,
            mail,
            metrics,
            // A zero poll interval would spin the CPU and hammer the database; a
            // misconfigured value must degrade to "poll often", not to "busy loop".
            poll_interval: poll_interval.max(Duration::from_millis(100)),
            // Likewise a zero batch would claim nothing and never make progress.
            batch_size: batch_size.clamp(1, 500),
            worker_id: normalise_worker_id(&raw_worker_id),
        }
    }

    /// Construct with the worker id derived from `HOSTNAME` and the pid.
    ///
    /// The right choice for the ordinary in-process worker in `cli.rs`, where there
    /// is no better name available and an id the caller has to invent is one more
    /// thing to get wrong.
    pub fn with_derived_id(
        pool: PgPool,
        mail: Arc<dyn MailProvider>,
        metrics: Arc<crate::platform::observability::metrics::Metrics>,
        poll_interval: Duration,
        batch_size: u32,
    ) -> Self {
        Self::new(
            pool,
            mail,
            metrics,
            poll_interval,
            batch_size,
            default_worker_id(),
        )
    }

    /// The supervised loop.
    ///
    /// Cancellation is observed only *between* rows, never in the middle of one:
    /// a row that has been handed to the provider is followed through to its
    /// terminal or scheduled state before the loop looks at the token again. Rows
    /// that were claimed but not yet attempted when cancellation arrives are
    /// explicitly released, so shutdown never leaves a row in an ambiguous
    /// "claimed by a process that no longer exists" state.
    pub async fn run(self, shutdown: CancellationToken) {
        tracing::info!(
            worker_id = %self.worker_id,
            provider = self.mail.name(),
            poll_interval_ms = self.poll_interval.as_millis() as u64,
            batch_size = self.batch_size,
            "outbox worker started"
        );

        loop {
            if shutdown.is_cancelled() {
                break;
            }

            // Idempotency records expire on their own schedule and belong to no
            // other loop; the worker is the one background task this process runs,
            // so it owns the sweep. Best-effort: a failure here must not stop mail.
            match idempotency::sweep_expired(&self.pool, SWEEP_BATCH).await {
                Ok(0) => {}
                Ok(n) => tracing::debug!(
                    worker_id = %self.worker_id,
                    removed = n,
                    "swept expired idempotency records"
                ),
                Err(e) => tracing::warn!(
                    worker_id = %self.worker_id,
                    error = %sanitize::log_value(e.to_string()),
                    "idempotency sweep failed; retrying next poll"
                ),
            }

            let processed = match self.process_batch(&shutdown).await {
                Ok(n) => n,
                Err(e) => {
                    // A database failure here must not kill the worker: the pool
                    // may simply be reconnecting. Log, wait one interval, retry.
                    // The `AppError::Internal` text is already free of driver
                    // detail (see `impl From<sqlx::Error>`), but it is sanitised
                    // again because it reaches a log line.
                    tracing::error!(
                        worker_id = %self.worker_id,
                        error = %sanitize::log_value(e.to_string()),
                        "outbox batch failed; retrying after the poll interval"
                    );
                    0
                }
            };

            if shutdown.is_cancelled() {
                break;
            }

            // A full batch means there is very likely more work waiting; going
            // straight round again drains a backlog at the speed of the provider
            // rather than at the speed of the poll interval.
            if processed >= self.batch_size as usize {
                continue;
            }

            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = tokio::time::sleep(self.poll_interval) => {}
            }
        }

        tracing::info!(worker_id = %self.worker_id, "outbox worker stopped cleanly");
    }

    /// Claim up to `batch_size` rows and attempt each one.
    ///
    /// Returns the number of rows *attempted* (not the number delivered).
    async fn process_batch(&self, shutdown: &CancellationToken) -> Result<usize, AppError> {
        let claimed = self.claim().await?;
        if claimed.is_empty() {
            return Ok(0);
        }

        let mut attempted = 0usize;
        for (index, event) in claimed.iter().enumerate() {
            if shutdown.is_cancelled() {
                // Hand the untouched remainder back rather than abandoning it. The
                // rows are still PENDING and still due, so leaving them would work
                // — but they would carry this worker's `claimed_by`, and an
                // operator triaging a stuck queue cannot distinguish "claimed by a
                // dead process" from "being worked on right now". Releasing makes
                // the state unambiguous.
                let remaining: Vec<Uuid> = claimed[index..].iter().map(|e| e.id).collect();
                self.release(&remaining).await?;
                tracing::info!(
                    worker_id = %self.worker_id,
                    released = remaining.len(),
                    "shutdown requested mid-batch; released the unattempted claims"
                );
                break;
            }

            attempted += 1;
            match self.attempt(event).await {
                Ok(()) => self.mark_sent(event.id).await?,
                Err(err) => self.mark_failed(event, err).await?,
            }
        }

        Ok(attempted)
    }

    /// Atomically take ownership of a batch.
    ///
    /// Two mechanisms, and both are needed.
    ///
    /// `FOR UPDATE SKIP LOCKED` handles *simultaneous* claims: each worker's inner
    /// `SELECT` locks the rows it picks and steps over rows another worker's
    /// in-flight statement already holds, so two claims running at the same instant
    /// partition the queue and neither blocks on the other. The alternative designs
    /// — an advisory lock making one instance the leader, or a `SELECT` followed by
    /// a conditional `UPDATE` — either serialise all delivery through one process or
    /// reintroduce the race they were meant to remove.
    ///
    /// The `claimed_at` predicate handles *consecutive* claims, and is the part that
    /// is easy to leave out. This is one autocommit statement, so its row locks are
    /// released the moment it returns, and a claimed row is still `PENDING` — the
    /// claim deliberately does not move it to a separate status, because a crash
    /// between claiming and delivering would then strand it in a state nothing
    /// sweeps. So without the lease a worker polling milliseconds later re-claims
    /// rows the first worker is at that moment delivering. See
    /// [`CLAIM_LEASE_SECONDS`] for what that costs.
    ///
    /// `ORDER BY available_at, id` keeps delivery roughly FIFO and makes the scan
    /// match `outbox_events_claimable_idx` exactly.
    pub async fn claim(&self) -> Result<Vec<ClaimedEvent>, AppError> {
        let rows: Vec<ClaimedEvent> = sqlx::query_as(
            "UPDATE outbox_events
                SET status = 'PENDING',
                    claimed_at = now(),
                    claimed_by = $1
              WHERE id IN (
                    SELECT id
                      FROM outbox_events
                     WHERE status IN ('PENDING', 'FAILED')
                       AND available_at <= now()
                       AND (claimed_at IS NULL
                            OR claimed_at <= now() - ($3::bigint * interval '1 second'))
                     ORDER BY available_at, id
                     LIMIT $2
                     FOR UPDATE SKIP LOCKED
              )
          RETURNING id, event_type, payload, attempts",
        )
        .bind(&self.worker_id)
        .bind(i64::from(self.batch_size))
        .bind(CLAIM_LEASE_SECONDS)
        .fetch_all(&self.pool)
        .await
        .map_err(AppError::from)?;

        Ok(rows)
    }

    /// Deliver one event. All the interesting logic is in the pure `build_mail`.
    async fn attempt(&self, event: &ClaimedEvent) -> Result<(), HandlerError> {
        let message = build_mail(&event.event_type, &event.payload)?;
        self.mail.send(&message).await.map_err(|e| {
            if e.is_retryable() {
                HandlerError::Transient(match e {
                    mail::MailError::ProviderNotConfigured => "no mail provider is configured",
                    _ => "the mail provider could not deliver the message",
                })
            } else {
                HandlerError::Permanent("the mail provider rejected the recipient")
            }
        })
    }

    async fn mark_sent(&self, id: Uuid) -> Result<(), AppError> {
        // `claimed_by` is deliberately left in place on success: it is the record of
        // which instance delivered the message, and the row is terminal so nothing
        // can mistake it for an in-flight claim.
        sqlx::query(
            "UPDATE outbox_events
                SET status = 'SENT', completed_at = now()
              WHERE id = $1",
        )
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(AppError::from)?;
        Ok(())
    }

    async fn mark_failed(&self, event: &ClaimedEvent, err: HandlerError) -> Result<(), AppError> {
        let stored = sanitise_last_error(err.message());
        self.metrics.outbox_failure();

        if err.is_permanent() {
            sqlx::query(
                "UPDATE outbox_events
                    SET status = 'DEAD',
                        attempts = attempts + 1,
                        last_error = $2,
                        completed_at = now(),
                        claimed_at = NULL,
                        claimed_by = NULL
                  WHERE id = $1",
            )
            .bind(event.id)
            .bind(&stored)
            .execute(&self.pool)
            .await
            .map_err(AppError::from)?;

            // Error level, not warn: a permanent failure means a user-visible
            // action (a reset, an invitation) will never happen and no retry will
            // rescue it. Somebody has to look at this.
            tracing::error!(
                worker_id = %self.worker_id,
                event.id = %event.id,
                event.kind = %sanitize::log_value(&event.event_type),
                reason = %stored,
                "outbox event dead-lettered immediately: the failure is permanent"
            );
            return Ok(());
        }

        // `attempts` is re-read and incremented *in the database* rather than
        // computed from the claimed copy: another worker cannot have this row (the
        // claim is exclusive), but a retried statement could otherwise double-count
        // and cut the attempt budget in half.
        let delay = i64::try_from(next_delay_seconds(event.id, event.attempts + 1))
            .unwrap_or(i64::from(u32::MAX));

        let outcome: (String, i32) = sqlx::query_as(
            "UPDATE outbox_events
                SET attempts     = attempts + 1,
                    last_error   = $2,
                    status       = CASE WHEN attempts + 1 >= max_attempts THEN 'DEAD' ELSE 'FAILED' END,
                    available_at = CASE WHEN attempts + 1 >= max_attempts
                                        THEN available_at
                                        ELSE now() + ($3::bigint * interval '1 second') END,
                    completed_at = CASE WHEN attempts + 1 >= max_attempts THEN now() ELSE NULL END,
                    claimed_at   = NULL,
                    claimed_by   = NULL
              WHERE id = $1
          RETURNING status, attempts",
        )
        .bind(event.id)
        .bind(&stored)
        .bind(delay)
        .fetch_one(&self.pool)
        .await
        .map_err(AppError::from)?;

        let (status, attempts) = outcome;
        if status == "DEAD" {
            tracing::error!(
                worker_id = %self.worker_id,
                event.id = %event.id,
                event.kind = %sanitize::log_value(&event.event_type),
                attempts,
                reason = %stored,
                "outbox event dead-lettered: the attempt budget is exhausted"
            );
        } else {
            tracing::warn!(
                worker_id = %self.worker_id,
                event.id = %event.id,
                event.kind = %sanitize::log_value(&event.event_type),
                attempts,
                retry_in_seconds = delay,
                reason = %stored,
                "outbox delivery failed; rescheduled"
            );
        }
        Ok(())
    }

    /// Give back rows that were claimed but never attempted.
    ///
    /// `available_at` is untouched, so a released row is immediately due again —
    /// releasing must not push work further into the future than it already was.
    /// The `status = 'PENDING'` predicate makes this a no-op for anything that has
    /// since reached a terminal state.
    async fn release(&self, ids: &[Uuid]) -> Result<(), AppError> {
        if ids.is_empty() {
            return Ok(());
        }
        sqlx::query(
            "UPDATE outbox_events
                SET claimed_at = NULL, claimed_by = NULL
              WHERE id = ANY($1) AND status = 'PENDING'",
        )
        .bind(ids)
        .execute(&self.pool)
        .await
        .map_err(AppError::from)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn uuid_with_tail(a: u8, b: u8) -> Uuid {
        let mut bytes = [0u8; 16];
        bytes[14] = a;
        bytes[15] = b;
        Uuid::from_bytes(bytes)
    }

    // ---- backoff schedule -------------------------------------------------

    #[test]
    fn the_backoff_schedule_is_monotonic_and_capped() {
        let schedule: Vec<u64> = (1..=30).map(backoff_seconds).collect();
        assert!(
            schedule.windows(2).all(|w| w[0] <= w[1]),
            "backoff must never decrease: {schedule:?}"
        );
        assert!(
            schedule.iter().all(|s| *s <= MAX_BACKOFF_SECONDS),
            "backoff must be capped: {schedule:?}"
        );
        assert_eq!(
            schedule[0], BASE_BACKOFF_SECONDS,
            "the first retry uses the base delay"
        );
        assert_eq!(schedule[1], BASE_BACKOFF_SECONDS * 2);
        assert_eq!(schedule[2], BASE_BACKOFF_SECONDS * 4);
        // It must actually grow before it flattens, or it is not backing off.
        assert!(schedule[5] > schedule[2]);
        assert_eq!(*schedule.last().unwrap(), MAX_BACKOFF_SECONDS);
    }

    /// A corrupt or absurd `attempts` value must not overflow the shift or wrap.
    #[test]
    fn the_backoff_survives_hostile_attempt_counts() {
        for attempts in [i32::MIN, -5, 0, 1, 63, 64, 1000, i32::MAX] {
            let s = backoff_seconds(attempts);
            assert!(s >= BASE_BACKOFF_SECONDS, "attempts={attempts} gave {s}");
            assert!(s <= MAX_BACKOFF_SECONDS, "attempts={attempts} gave {s}");
        }
    }

    // ---- jitter -----------------------------------------------------------

    #[test]
    fn jitter_is_deterministic_for_a_given_uuid() {
        let id = Uuid::now_v7();
        let first = jitter_seconds(id, 3600);
        for _ in 0..100 {
            assert_eq!(
                jitter_seconds(id, 3600),
                first,
                "jitter must be reproducible"
            );
        }
        // And so is the full delay, which is what a test asserting a schedule uses.
        assert_eq!(next_delay_seconds(id, 4), next_delay_seconds(id, 4));
    }

    #[test]
    fn jitter_stays_within_the_declared_bounds() {
        for base in [0u64, 1, 5, 100, MAX_BACKOFF_SECONDS] {
            let span = base * JITTER_PERCENT / 100;
            for a in 0..=255u8 {
                for b in [0u8, 1, 127, 255] {
                    let j = jitter_seconds(uuid_with_tail(a, b), base);
                    assert!(
                        j <= span,
                        "jitter {j} exceeded the {span}s span for base {base}"
                    );
                }
            }
        }
        // A base too small to have a jitter span degrades to no jitter rather than
        // to a division by zero.
        assert_eq!(jitter_seconds(uuid_with_tail(255, 255), 4), 0);
    }

    #[test]
    fn jitter_actually_de_synchronises_distinct_events() {
        // A thousand events failing in the same batch must not all come back at the
        // same instant.
        let delays: std::collections::HashSet<u64> = (0..1000u16)
            .map(|i| {
                let [a, b] = i.to_be_bytes();
                next_delay_seconds(uuid_with_tail(a, b), 10)
            })
            .collect();
        assert!(
            delays.len() > 100,
            "jitter spread only {} distinct delays over 1000 events",
            delays.len()
        );
    }

    /// The lease has to be longer than a delivery attempt and shorter than an
    /// operator's patience. Pinned so a future edit has to think about both ends.
    #[test]
    fn the_claim_lease_sits_between_one_attempt_and_one_retry() {
        // `const` blocks: these compare two constants, so the check belongs at
        // compile time and clippy is right to refuse a runtime assertion for it.
        const {
            assert!(
                CLAIM_LEASE_SECONDS > 0,
                "a zero lease reinstates the double-claim"
            )
        };
        const {
            assert!(
                CLAIM_LEASE_SECONDS >= 30,
                "the lease must comfortably exceed one delivery attempt"
            )
        };
        const {
            assert!(
                (CLAIM_LEASE_SECONDS as u64) <= MAX_BACKOFF_SECONDS,
                "a lease longer than the maximum backoff would delay recovery from a \
                 killed worker beyond the retry schedule itself"
            )
        };
    }

    #[test]
    fn the_total_delay_is_bounded() {
        let ceiling = MAX_BACKOFF_SECONDS + MAX_BACKOFF_SECONDS * JITTER_PERCENT / 100;
        for attempts in [1, 2, 8, 20, i32::MAX] {
            for tail in [0u8, 128, 255] {
                let d = next_delay_seconds(uuid_with_tail(tail, tail), attempts);
                assert!(d <= ceiling, "delay {d} exceeded the ceiling {ceiling}");
            }
        }
    }

    // ---- dispatch ---------------------------------------------------------

    fn reset_payload() -> serde_json::Value {
        json!({
            "to": "alice@example.com",
            "reset_url": "https://os.example.com/reset?token=rb_secret_token_value",
            "expires_in_minutes": 30
        })
    }

    #[test]
    fn a_well_formed_password_reset_becomes_a_message() {
        let m = build_mail(event_type::MAIL_PASSWORD_RESET, &reset_payload())
            .expect("a valid payload should dispatch");
        assert_eq!(m.kind, MailKind::PasswordReset);
        assert_eq!(m.to, "alice@example.com");
        assert!(m.body_text.contains("rb_secret_token_value"));
        assert!(m.body_text.contains("30 minutes"));
    }

    #[test]
    fn a_well_formed_invitation_becomes_a_message() {
        let payload = json!({
            "to": "bob@example.com",
            "invite_url": "https://os.example.com/invite?token=abc",
            "inviter_display_name": "Alice Admin",
            "expires_in_hours": 72
        });
        let m = build_mail(event_type::MAIL_INVITATION, &payload).expect("should dispatch");
        assert_eq!(m.kind, MailKind::Invitation);
        assert!(m.body_text.contains("Alice Admin"));
        assert!(m.body_text.contains("72 hours"));
    }

    /// An inviter display name is user-controlled and ends up in a message body.
    #[test]
    fn a_hostile_inviter_name_is_sanitised_and_bounded() {
        let payload = json!({
            "to": "bob@example.com",
            "invite_url": "https://os.example.com/invite?token=abc",
            "inviter_display_name": format!("Mallory\r\nBcc: attacker@evil.test{}", "x".repeat(5000)),
            "expires_in_hours": 1
        });
        let m = build_mail(event_type::MAIL_INVITATION, &payload).expect("should dispatch");
        // The name is folded into one line, so it cannot inject a header into any
        // future real provider.
        assert!(!m.body_text.lines().any(|l| l.starts_with("Bcc:")));
        assert!(m.body_text.len() < 1000, "the name was not bounded");
    }

    #[test]
    fn an_unknown_event_type_is_permanent_and_never_retried() {
        for unknown in [
            "",
            "mail.password_resets",
            "MAIL.PASSWORD_RESET",
            "billing.charge",
            "🙂",
        ] {
            let err = build_mail(unknown, &reset_payload())
                .expect_err("an unknown type must not dispatch");
            assert!(
                err.is_permanent(),
                "`{unknown}` produced a retryable error; it would retry forever"
            );
            assert!(err.message().contains("no handler"));
        }
    }

    #[test]
    fn malformed_payloads_are_rejected_permanently() {
        let cases: Vec<serde_json::Value> = vec![
            json!({}),                                                              // nothing
            json!({"to": "a@b.com"}),                   // missing fields
            json!({"to": "a@b.com", "reset_url": "u"}), // still missing
            json!({"to": 42, "reset_url": "u", "expires_in_minutes": 1}), // wrong type
            json!({"to": "a@b.com", "reset_url": "u", "expires_in_minutes": -1}), // negative u32
            json!({"to": "a@b.com", "reset_url": "u", "expires_in_minutes": "30"}), // string
            json!(null),
            json!("a string, not an object"),
            json!([1, 2, 3]),
        ];
        for payload in cases {
            match build_mail(event_type::MAIL_PASSWORD_RESET, &payload) {
                Ok(m) => panic!("payload {payload} should not have dispatched: {m:?}"),
                Err(err) => {
                    assert!(
                        err.is_permanent(),
                        "payload {payload} should be a permanent failure"
                    )
                }
            }
        }
    }

    /// Forward compatibility during a rolling deploy: an old worker reading a row
    /// written by a newer build must deliver it, not dead-letter it.
    #[test]
    fn an_unrecognised_extra_field_does_not_dead_letter_the_message() {
        let payload = json!({
            "to": "alice@example.com",
            "reset_url": "https://os.example.com/reset?token=t",
            "expires_in_minutes": 15,
            "locale": "en-GB",
            "future_field": {"nested": true}
        });
        assert!(build_mail(event_type::MAIL_PASSWORD_RESET, &payload).is_ok());
    }

    #[test]
    fn hostile_recipients_are_rejected_permanently() {
        let bad = [
            "",
            "no-at-sign",
            "alice@example.com\r\nBcc: attacker@evil.test",
            "alice @example.com",
            "alice@example.com\u{0}",
        ];
        for to in bad {
            let payload = json!({
                "to": to,
                "reset_url": "https://os.example.com/reset?token=t",
                "expires_in_minutes": 15
            });
            let err = build_mail(event_type::MAIL_PASSWORD_RESET, &payload)
                .expect_err("a hostile recipient should have been rejected");
            assert!(
                err.is_permanent(),
                "recipient `{to}` should be a permanent failure"
            );
        }
        // Over the length bound.
        let long = format!("{}@example.com", "a".repeat(MAX_RECIPIENT_LEN));
        let payload = json!({ "to": long, "reset_url": "u", "expires_in_minutes": 1 });
        assert!(build_mail(event_type::MAIL_PASSWORD_RESET, &payload).is_err());
    }

    // ---- last_error -------------------------------------------------------

    #[test]
    fn the_stored_error_cannot_forge_a_log_record() {
        let attack = "delivery failed\r\n{\"level\":\"INFO\",\"msg\":\"all mail delivered\"}";
        let stored = sanitise_last_error(attack);
        assert!(!stored.contains('\n'));
        assert!(!stored.contains('\r'));
        assert!(stored.starts_with("delivery failed··"));
    }

    /// The column is `CHECK (length(last_error) <= 2000)`. Exceeding it would make
    /// the failure-recording UPDATE itself fail.
    #[test]
    fn the_stored_error_fits_the_column_constraint() {
        for len in [0usize, 1, 1998, 1999, 2000, 2001, 100_000] {
            let stored = sanitise_last_error(&"x".repeat(len));
            assert!(
                stored.chars().count() <= 2000,
                "a {len}-character error produced {} characters",
                stored.chars().count()
            );
        }
        // Multi-byte input must not be cut mid-sequence.
        let stored = sanitise_last_error(&"é".repeat(5000));
        assert!(stored.chars().count() <= 2000);
        assert!(std::str::from_utf8(stored.as_bytes()).is_ok());
    }

    /// The type system is the guarantee: `HandlerError` cannot hold a `String`, so
    /// nothing dynamic can reach the column. This test pins that behaviour for the
    /// paths that are most tempting to make dynamic.
    #[test]
    fn no_payload_content_can_reach_the_stored_error() {
        let payload = json!({
            "to": "alice@example.com",
            "reset_url": "https://os.example.com/reset?token=SUPER_SECRET_TOKEN",
            "expires_in_minutes": "not a number"
        });
        let err = build_mail(event_type::MAIL_PASSWORD_RESET, &payload).expect_err("malformed");
        let stored = sanitise_last_error(err.message());
        assert!(
            !stored.contains("SUPER_SECRET_TOKEN"),
            "the token leaked: {stored}"
        );
        assert!(!stored.contains("alice"), "the recipient leaked: {stored}");
    }

    // ---- worker identity --------------------------------------------------

    /// `claimed_by` is `CHECK (claimed_by IS NULL OR length(claimed_by) <= 100)`,
    /// and the id also reaches every log line the worker emits. An over-long or
    /// control-bearing id must be bounded here, not discovered when the claim
    /// UPDATE fails and takes the whole worker down.
    #[test]
    fn the_worker_id_is_bounded_and_log_safe() {
        let ordinary = normalise_worker_id("roleblank-api-1234");
        assert_eq!(
            ordinary, "roleblank-api-1234",
            "an ordinary id must pass through intact"
        );

        // The derived id: bounded, log-safe, and stable for the life of the process
        // so `claimed_by` keeps pointing at the same signallable pid.
        let derived = default_worker_id();
        assert!(!derived.is_empty());
        assert!(
            derived.chars().count() <= 100,
            "derived id too long: {derived}"
        );
        assert!(!derived.contains('\n') && !derived.contains('\r'));
        assert!(
            derived.ends_with(&format!("-{}", std::process::id())),
            "pid missing: {derived}"
        );
        assert_eq!(
            derived,
            default_worker_id(),
            "the derived id must be stable"
        );

        for hostile in [
            "host\r\n{\"level\":\"INFO\",\"msg\":\"queue drained\"}",
            &"x".repeat(5000),
            "host\u{0}\u{1b}[31m",
        ] {
            let id = normalise_worker_id(hostile);
            assert!(
                id.chars().count() <= 100,
                "id was not bounded: {} chars",
                id.chars().count()
            );
            assert!(
                !id.contains('\n') && !id.contains('\r'),
                "id can forge a log record: {id}"
            );
            assert!(!id.contains('\u{0}'));
        }
    }

    // ---- event types ------------------------------------------------------

    // ---- links ------------------------------------------------------------

    #[test]
    fn an_action_link_is_built_the_same_way_whatever_the_base_url_looks_like() {
        let token = "rb_pr_AbC-123_xyz";
        for base in ["https://os.example.com", "https://os.example.com/"] {
            assert_eq!(
                action_link(base, "/password-reset/confirm", token),
                "https://os.example.com/password-reset/confirm?token=rb_pr_AbC-123_xyz"
            );
        }
    }

    /// The reason `action_link` may skip percent-encoding. If the token alphabet
    /// ever gains `+`, `/` or `=`, this fails here rather than producing links that
    /// truncate in a mail client.
    #[test]
    fn generated_tokens_are_url_safe_without_encoding() {
        for prefix in [
            crate::platform::crypto::tokens::RESET_TOKEN_PREFIX,
            crate::platform::crypto::tokens::INVITE_TOKEN_PREFIX,
        ] {
            for _ in 0..50 {
                let t = crate::platform::crypto::tokens::generate(prefix).expect("csprng");
                let plaintext = t.plaintext.expose();
                assert!(
                    plaintext
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
                    "token `{plaintext}` contains a character that must be percent-encoded"
                );
            }
        }
    }

    #[test]
    fn event_types_are_unique_and_fit_the_column_constraint() {
        let unique: std::collections::HashSet<&&str> = event_type::ALL.iter().collect();
        assert_eq!(
            unique.len(),
            event_type::ALL.len(),
            "two event types collide"
        );
        for t in event_type::ALL {
            assert!(
                !t.is_empty() && t.len() <= MAX_EVENT_TYPE_LEN,
                "`{t}` breaks the CHECK"
            );
            assert!(t.is_ascii(), "`{t}` is not ASCII");
            // Every registered type must actually dispatch — a constant with no
            // handler would dead-letter every event of that type.
            assert!(
                !matches!(build_mail(t, &json!({})), Err(HandlerError::Permanent(m)) if m.contains("no handler")),
                "`{t}` has no handler"
            );
        }
    }
}
