//! Request idempotency.
//!
//! The problem: a client POSTs "create project", the response is lost to a network
//! blip, the client retries. Without a record of the first attempt the second one
//! creates a second project. With money or invitations involved the duplicate is
//! not merely untidy.
//!
//! The design is `(principal_id, operation, idempotency_key)` → one record, plus a
//! SHA-256 fingerprint of the request body. The scoping is load-bearing: an
//! unscoped key namespace would let one principal replay another principal's
//! response by guessing a key, which is a cross-tenant information leak. The
//! fingerprint turns "same key, different body" — a client bug, or a deliberate
//! attempt to have a stored response attributed to a different request — into a
//! deterministic 409 rather than a silently wrong replay.

use sha2::{Digest, Sha256};
use sqlx::postgres::PgPool;
use uuid::Uuid;

use crate::platform::errors::{AppError, AppResult};
use crate::platform::observability::sanitize;

/// Mirrors `idempotency_records.idempotency_key`'s
/// `CHECK (length(idempotency_key) BETWEEN 8 AND 200)`. Kept in sync deliberately:
/// a bound enforced only in Rust is a bound that a future `psql` import ignores.
pub const MIN_KEY_LEN: usize = 8;
pub const MAX_KEY_LEN: usize = 200;

/// Mirrors `CHECK (length(operation) BETWEEN 1 AND 100)`.
const MAX_OPERATION_LEN: usize = 100;

/// SHA-256 output size, which the column pins with
/// `CHECK (octet_length(request_fingerprint) = 32)`.
pub const FINGERPRINT_LEN: usize = 32;

/// How long a key stays reserved.
///
/// Long enough to cover any realistic client retry (including a human retrying the
/// next morning), short enough that the table does not grow without bound.
/// [`sweep_expired`] is what actually deletes on `expires_at`; the outbox worker
/// calls it on its own poll loop.
pub const RETENTION_HOURS: i64 = 24;

/// Cap on a stored replay body. The API's own request limit is 256 KiB and
/// responses are small; a document larger than this is a bug, and storing it would
/// turn one oversized response into permanent storage growth multiplied by every
/// retrying client.
pub const MAX_REPLAY_BODY_BYTES: usize = 262_144;

/// A validated `Idempotency-Key`.
///
/// A newtype rather than a `&str` so that the validation cannot be skipped by a
/// call site that "knows" the value is fine. Every construction goes through
/// `parse`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IdempotencyKey(String);

impl IdempotencyKey {
    /// Validate a client-supplied key.
    ///
    /// Rules, and the concrete failure each prevents:
    ///
    /// - **Length 8..=200.** Below 8 the key space is small enough to collide (or
    ///   be guessed) between concurrent clients; above 200 the database `CHECK`
    ///   rejects it, and an oversized key is also an unbounded string that reaches
    ///   logs and an index.
    /// - **ASCII printable, excluding space.** Control characters are the real
    ///   target: this value is echoed into structured logs, into audit metadata and
    ///   potentially into an error response. A `\n` or `\r` in it forges an
    ///   additional log record — an attacker sets the header to
    ///   `abc\n{"level":"INFO","msg":"admin approved"}` and the operational log now
    ///   contains a line nobody wrote (TH-32). It is *rejected* rather than
    ///   sanitised, because a sanitised key is a different key and would silently
    ///   defeat the deduplication the caller asked for. Space is excluded with the
    ///   control characters because a leading or trailing one produces two keys
    ///   that are indistinguishable in every log and console an operator will look
    ///   at.
    pub fn parse(raw: &str) -> Result<Self, AppError> {
        if raw.len() < MIN_KEY_LEN {
            return Err(AppError::field(
                "Idempotency-Key",
                "TOO_SHORT",
                format!("The Idempotency-Key must be at least {MIN_KEY_LEN} characters."),
            ));
        }
        if raw.len() > MAX_KEY_LEN {
            return Err(AppError::field(
                "Idempotency-Key",
                "TOO_LONG",
                format!("The Idempotency-Key must be at most {MAX_KEY_LEN} characters."),
            ));
        }
        // 0x21..=0x7E: printable ASCII without space. The length checks above are
        // byte-based, which is exact here precisely because non-ASCII is refused.
        if !raw.bytes().all(|b| (0x21..=0x7E).contains(&b)) {
            return Err(AppError::field(
                "Idempotency-Key",
                "INVALID_FORMAT",
                "The Idempotency-Key must contain only printable ASCII characters \
                 (no spaces, no control characters).",
            ));
        }
        Ok(Self(raw.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// SHA-256 of the raw request body.
///
/// A plain digest, not a keyed MAC: this detects *collision* between two requests
/// from the same principal, it does not authenticate anything, and there is no
/// adversary who benefits from forging a fingerprint they could equally produce by
/// sending the body. Comparison is likewise an ordinary `==` — the fingerprint is
/// not a secret, so there is no timing channel worth closing.
///
/// The body itself is never stored, only this digest. A create-user body contains a
/// password; a 24-hour retention table is not a place for one.
pub fn fingerprint(body: &[u8]) -> Vec<u8> {
    Sha256::digest(body).to_vec()
}

/// What the caller should do next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdempotencyOutcome {
    /// This is the first request with this key. Do the work, then call `complete`.
    Proceed { record_id: Uuid },
    /// The work was already done. Return this stored response verbatim.
    Replay {
        status: i32,
        body: serde_json::Value,
    },
    /// An identical request is in flight right now. The caller should answer 409
    /// and let the client retry — completing the work a second time is exactly what
    /// idempotency exists to prevent.
    InProgress,
}

/// Reserve the key, or discover what happened to it last time.
///
/// The `INSERT ... ON CONFLICT DO NOTHING RETURNING id` followed by a `SELECT` is
/// the part that makes concurrency deterministic. Two identical requests arriving
/// at the same instant both run the INSERT; PostgreSQL's unique index on
/// `(principal_id, operation, idempotency_key)` guarantees **exactly one** of them
/// gets a row back, so exactly one is told to `Proceed`. The loser's `RETURNING`
/// yields nothing and it falls through to the SELECT, which shows it the winner's
/// record. A `SELECT`-then-`INSERT` would have both find nothing and both proceed —
/// the duplicate this module exists to prevent.
pub async fn begin(
    pool: &PgPool,
    principal_id: Uuid,
    operation: &str,
    key: &IdempotencyKey,
    fingerprint: &[u8],
) -> Result<IdempotencyOutcome, AppError> {
    // These are supplied by our own handlers, never by a client, so a violation is
    // a programming error and is reported as one rather than as a validation
    // failure the client could act on.
    if operation.is_empty() || operation.len() > MAX_OPERATION_LEN {
        return Err(AppError::internal(
            "idempotency operation name is out of bounds",
        ));
    }
    if fingerprint.len() != FINGERPRINT_LEN {
        return Err(AppError::internal(
            "idempotency fingerprint is not a SHA-256 digest",
        ));
    }

    // Two iterations, not a loop with no bound. The only way round twice is the
    // narrow race where the retention sweep deletes the conflicting row between the
    // INSERT and the SELECT; a second pass then wins the INSERT outright. An
    // unbounded loop here would be a spin under a pathological sweep.
    for _ in 0..2 {
        let inserted: Option<(Uuid,)> = sqlx::query_as(
            "INSERT INTO idempotency_records
                 (id, principal_id, operation, idempotency_key, request_fingerprint,
                  status, expires_at)
             VALUES ($1, $2, $3, $4, $5, 'IN_PROGRESS',
                     now() + ($6::bigint * interval '1 hour'))
             ON CONFLICT (principal_id, operation, idempotency_key) DO NOTHING
             RETURNING id",
        )
        .bind(Uuid::now_v7())
        .bind(principal_id)
        .bind(operation)
        .bind(key.as_str())
        .bind(fingerprint)
        .bind(RETENTION_HOURS)
        .fetch_optional(pool)
        .await
        .map_err(AppError::from)?;

        if let Some((record_id,)) = inserted {
            return Ok(IdempotencyOutcome::Proceed { record_id });
        }

        let existing: Option<RecordRow> = sqlx::query_as(
            "SELECT id, request_fingerprint, status, response_status, response_body
               FROM idempotency_records
              WHERE principal_id = $1 AND operation = $2 AND idempotency_key = $3",
        )
        .bind(principal_id)
        .bind(operation)
        .bind(key.as_str())
        .fetch_optional(pool)
        .await
        .map_err(AppError::from)?;

        let Some(row) = existing else {
            // Swept between the two statements. Go round once more.
            continue;
        };

        // Same key, different body. This is either a client that is reusing keys
        // incorrectly — in which case a silent replay of the *wrong* response is
        // far worse than an error — or a deliberate attempt to have a stored
        // response attributed to a different request.
        if row.request_fingerprint != fingerprint {
            tracing::warn!(
                operation = %sanitize::log_value(operation),
                // The principal id is a log field, not a metrics label: logs are
                // access-controlled and correlating an abuse pattern to an actor is
                // the entire point of having them.
                principal_id = %principal_id,
                "idempotency key reused with a different request body"
            );
            return Err(AppError::IdempotencyKeyReused);
        }

        return match row.status.as_str() {
            "COMPLETED" => Ok(IdempotencyOutcome::Replay {
                // The completion constraint on the table
                // (`idempotency_completion_consistent`) guarantees `response_status`
                // is present whenever status is COMPLETED, so the fallback below is
                // unreachable — but it is a fallback rather than an unwrap, because
                // a panic here would be reachable from a plain client retry.
                status: row.response_status.unwrap_or(500),
                body: row.response_body.unwrap_or(serde_json::Value::Null),
            }),
            "IN_PROGRESS" => Ok(IdempotencyOutcome::InProgress),
            other => {
                // A status outside the CHECK constraint means the row was written by
                // something that is not this code. Fail closed.
                Err(AppError::internal(format!(
                    "idempotency record has an unrecognised status `{}`",
                    sanitize::sanitize_bounded(other, 40)
                )))
            }
        };
    }

    // Both passes lost their race. Vanishingly unlikely, and honestly reported as a
    // conflict the client can simply retry rather than as a 500.
    Err(AppError::conflict(
        "IDEMPOTENCY_RACE",
        "The idempotency record could not be reserved. Retry the request.",
    ))
}

/// Explicit column list, explicit types.
#[derive(Debug, sqlx::FromRow)]
struct RecordRow {
    #[allow(dead_code)]
    id: Uuid,
    request_fingerprint: Vec<u8>,
    status: String,
    response_status: Option<i32>,
    response_body: Option<serde_json::Value>,
}

/// Store the response so a later retry replays it.
///
/// Called *after* the business transaction has committed. If this fails, the work
/// has still happened; the caller must not surface that as a failure to the client,
/// which is why the "row not found" case is a warning rather than an error.
pub async fn complete(
    pool: &PgPool,
    record_id: Uuid,
    status: i32,
    body: &serde_json::Value,
) -> Result<(), AppError> {
    // Mirrors `CHECK (response_status BETWEEN 100 AND 599)`. Caught here so a
    // programming error surfaces as a clear message rather than as an opaque
    // constraint violation.
    if !(100..=599).contains(&status) {
        return Err(AppError::internal(format!(
            "idempotency response status {status} is not a valid HTTP status"
        )));
    }

    // Bound the stored document. An oversized body is recorded as COMPLETED with a
    // sentinel rather than dropped: the key must stay consumed (otherwise a retry
    // would re-run the work, which is the whole failure this module prevents), but
    // the replay honestly says the body was not kept instead of pretending an empty
    // response was the real one.
    let stored: serde_json::Value = match serde_json::to_vec(body) {
        Ok(bytes) if bytes.len() <= MAX_REPLAY_BODY_BYTES => body.clone(),
        Ok(bytes) => {
            tracing::warn!(
                bytes = bytes.len(),
                limit = MAX_REPLAY_BODY_BYTES,
                "response body is too large to store for idempotent replay; storing a sentinel"
            );
            serde_json::json!({ "_replay_body_omitted": true })
        }
        Err(_) => {
            // A `Value` that cannot be serialised (a non-finite float reached it).
            tracing::warn!("response body could not be serialised for idempotent replay");
            serde_json::json!({ "_replay_body_omitted": true })
        }
    };

    let result = sqlx::query(
        "UPDATE idempotency_records
            SET status = 'COMPLETED',
                response_status = $2,
                response_body = $3,
                completed_at = now()
          WHERE id = $1 AND status = 'IN_PROGRESS'",
    )
    .bind(record_id)
    .bind(status)
    .bind(&stored)
    .execute(pool)
    .await
    .map_err(AppError::from)?;

    if result.rows_affected() == 0 {
        // The record was swept, or another path already completed it. Turning this
        // into an error would fail a request whose work has already succeeded —
        // the client would retry and, with the record gone, do the work twice.
        tracing::warn!(
            record_id = %record_id,
            "idempotency record was not in IN_PROGRESS at completion; the replay was not stored"
        );
    }
    Ok(())
}

/// Release a reservation whose work did not happen.
///
/// The counterpart to `complete`. `begin` reserves the key *before* the work runs,
/// which is what makes two simultaneous requests deterministic — but it also means a
/// request that then fails validation, authorisation or a database constraint has
/// consumed a key for work that did not occur. Leaving the reservation would make a
/// client's corrected retry, with the same key and a corrected body, a `409` for the
/// next 24 hours; and a retry with the *same* body would be told the work was
/// already done when it was not.
///
/// `status = 'IN_PROGRESS'` in the predicate means this can never delete a record
/// that has already stored a response, so a late or duplicated call is a no-op
/// rather than a way to erase a completed reservation.
///
/// Infallible by signature: the caller is already returning an error, and replacing
/// the real failure with "the cleanup failed" would tell the client nothing useful.
/// A failure is logged and the record is left to the retention sweep.
pub async fn abandon(pool: &PgPool, record_id: Uuid) {
    let result =
        sqlx::query("DELETE FROM idempotency_records WHERE id = $1 AND status = 'IN_PROGRESS'")
            .bind(record_id)
            .execute(pool)
            .await;

    if let Err(e) = result {
        tracing::warn!(
            record_id = %record_id,
            error.kind = ?std::mem::discriminant(&e),
            "could not release an idempotency reservation for work that failed; \
             the key stays reserved until it expires"
        );
    }
}

/// Delete idempotency records whose reservation has expired.
///
/// **This did not exist for the whole of the build.** `expires_at` was written on
/// every insert and read by no predicate anywhere, three documents asserted that a
/// sweep deleted on it, and the two-pass retry loop in `reserve` justified itself
/// entirely by a race against a sweep that was never running. The table therefore
/// grew forever: one row per mutating request that carried an `Idempotency-Key`,
/// with no path that ever removed one.
///
/// Cheap by construction — `idempotency_records_expiry_idx` covers exactly this
/// predicate — and bounded per call so a long-neglected table is drained over
/// several polls rather than in one statement that locks a large range.
///
/// Best-effort by design: the caller logs and carries on. A sweep that fails is a
/// table that stays large for another poll interval, which is not worth stopping
/// mail delivery for.
pub async fn sweep_expired(pool: &PgPool, limit: i64) -> AppResult<u64> {
    let deleted = sqlx::query(
        "DELETE FROM idempotency_records
          WHERE id IN (
              SELECT id FROM idempotency_records
               WHERE expires_at < now()
               ORDER BY expires_at
               LIMIT $1
          )",
    )
    .bind(limit)
    .execute(pool)
    .await
    .map_err(AppError::from)?;
    Ok(deleted.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- key validation ---------------------------------------------------

    #[test]
    fn well_formed_keys_are_accepted() {
        for good in [
            "abcd1234",                             // exactly the minimum
            "018f3a1e-6b7c-7f2a-9c31-2b4d5e6f7a8b", // a UUID, the usual choice
            "01HQ8Z5J9K7M3N2P4Q6R8S0T1V",           // a ULID
            "req_2024-01-01T00:00:00Z_abc",
            "~!#$%^&*()_+{}|:<>?",    // all printable ASCII
            &"k".repeat(MAX_KEY_LEN), // exactly the maximum
        ] {
            let parsed = IdempotencyKey::parse(good)
                .unwrap_or_else(|e| panic!("`{good}` should be accepted: {e}"));
            assert_eq!(parsed.as_str(), good, "parsing must not alter the key");
        }
    }

    #[test]
    fn keys_outside_the_length_bounds_are_rejected() {
        for bad in ["", "a", "abcdefg"] {
            assert!(IdempotencyKey::parse(bad).is_err(), "`{bad}` is too short");
        }
        assert!(IdempotencyKey::parse(&"k".repeat(MAX_KEY_LEN + 1)).is_err());
        assert!(IdempotencyKey::parse(&"k".repeat(100_000)).is_err());
    }

    /// The log-injection case. A key containing CR/LF must not be accepted and then
    /// echoed into a structured log, where it would terminate the record and let the
    /// attacker append one of their own.
    #[test]
    fn control_characters_are_rejected_rather_than_sanitised() {
        let attacks = [
            "abcd1234\r\n{\"level\":\"INFO\",\"msg\":\"admin approved\"}",
            "abcd1234\nINFO forged",
            "abcd\u{0}1234",
            "abcd1234\x1b[31m",
            "abcd1234\t",
            "abcd\x7f1234",
        ];
        for attack in attacks {
            let err = IdempotencyKey::parse(attack);
            assert!(
                err.is_err(),
                "control characters must be rejected: {attack:?}"
            );
        }
        // And the rejection is not a sanitisation: no variant of `parse` returns a
        // modified key, so two distinct client keys can never collapse into one.
        assert!(IdempotencyKey::parse("abcd1234\n").is_err());
    }

    #[test]
    fn spaces_and_non_ascii_are_rejected() {
        for bad in [
            "abcd 1234",         // interior space
            " abcd1234",         // leading space — invisible in a log
            "abcd1234 ",         // trailing space
            "clé-de-requête-12", // non-ASCII
            "abcd1234🙂",
            "abcd1234\u{00a0}", // non-breaking space
            "abcd1234\u{2028}", // Unicode line separator
        ] {
            assert!(
                IdempotencyKey::parse(bad).is_err(),
                "`{bad}` should be rejected"
            );
        }
    }

    #[test]
    fn key_rejection_never_echoes_the_rejected_value() {
        // A validation message that quoted the key back would make the endpoint a
        // reflection gadget.
        let err = IdempotencyKey::parse("abcd1234\r\nforged").expect_err("must reject");
        let rendered = err.to_string();
        assert!(
            !rendered.contains("forged"),
            "the rejected value was echoed: {rendered}"
        );
        assert!(!rendered.contains('\n'));
    }

    /// The Rust bound and the database `CHECK` must agree, or one of them is dead
    /// code that a direct SQL path would bypass.
    #[test]
    fn the_key_bounds_match_the_database_constraint() {
        assert_eq!(
            MIN_KEY_LEN, 8,
            "migration 0006: length(idempotency_key) BETWEEN 8 AND 200"
        );
        assert_eq!(
            MAX_KEY_LEN, 200,
            "migration 0006: length(idempotency_key) BETWEEN 8 AND 200"
        );
        assert_eq!(
            FINGERPRINT_LEN, 32,
            "migration 0006: octet_length(request_fingerprint) = 32"
        );
    }

    // ---- fingerprint ------------------------------------------------------

    #[test]
    fn the_fingerprint_is_a_32_byte_sha256() {
        let f = fingerprint(b"{}");
        assert_eq!(f.len(), FINGERPRINT_LEN);
        // Known SHA-256 of the empty input, so a future change of hash function is
        // caught rather than silently invalidating every stored fingerprint.
        let empty = fingerprint(b"");
        assert_eq!(
            empty,
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55,
            ]
        );
    }

    #[test]
    fn the_fingerprint_is_stable() {
        let body = br#"{"name":"Acme","client_id":"018f3a1e-6b7c-7f2a-9c31-2b4d5e6f7a8b"}"#;
        let first = fingerprint(body);
        for _ in 0..50 {
            assert_eq!(
                fingerprint(body),
                first,
                "the fingerprint must be deterministic"
            );
        }
    }

    #[test]
    fn different_bodies_produce_different_fingerprints() {
        let cases: [&[u8]; 8] = [
            b"",
            b"{}",
            b"{ }",
            br#"{"a":1}"#,
            br#"{"a":2}"#,
            br#"{"a":1,"b":null}"#,
            br#"{"b":null,"a":1}"#, // key order matters: it is a byte digest, not a semantic one
            b"\x00\x01\x02",
        ];
        let digests: std::collections::HashSet<Vec<u8>> =
            cases.iter().map(|b| fingerprint(b)).collect();
        assert_eq!(digests.len(), cases.len(), "two distinct bodies collided");
    }

    /// A single flipped bit must change the digest — the property the whole
    /// "same key, different body" check rests on.
    #[test]
    fn a_one_bit_change_changes_the_fingerprint() {
        let a = fingerprint(br#"{"amount":1000}"#);
        let b = fingerprint(br#"{"amount":1001}"#);
        assert_ne!(a, b);
        let differing = a.iter().zip(b.iter()).filter(|(x, y)| x != y).count();
        assert!(
            differing > 8,
            "the digest barely changed: {differing} of 32 bytes"
        );
    }

    #[test]
    fn the_fingerprint_handles_a_large_body_without_panicking() {
        let big = vec![0xABu8; 4 * 1024 * 1024];
        assert_eq!(fingerprint(&big).len(), FINGERPRINT_LEN);
    }

    // ---- outcome ----------------------------------------------------------

    #[test]
    fn the_three_outcomes_are_distinguishable() {
        let id = Uuid::now_v7();
        let proceed = IdempotencyOutcome::Proceed { record_id: id };
        let replay = IdempotencyOutcome::Replay {
            status: 201,
            body: serde_json::json!({"id": "x"}),
        };
        assert_ne!(proceed, replay);
        assert_ne!(replay, IdempotencyOutcome::InProgress);
        assert_ne!(proceed, IdempotencyOutcome::InProgress);
        // A caller matching on the outcome cannot confuse two records.
        assert_ne!(
            proceed,
            IdempotencyOutcome::Proceed {
                record_id: Uuid::now_v7()
            }
        );
    }
}
