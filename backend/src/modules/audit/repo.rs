//! Audit read queries.
//!
//! Two things this file does that are controls rather than tidiness:
//!
//! 1. **Two separate column lists.** The reading statements do not select
//!    `entry_hash` or `prev_hash`, so the chain material is never loaded into this
//!    process on the reading path at all. A future response DTO cannot accidentally
//!    serialise a field that was never fetched. Only `CHAIN_RUN` — used by the one
//!    step-up-gated verify function — reads them.
//! 2. **Every statement is a `&'static str` literal.** Nothing is assembled at run
//!    time. Sort direction selects between two complete, compile-time statements
//!    rather than interpolating a keyword, so there is no string concatenation
//!    anywhere near a caller's value. sqlx's `SqlSafeStr` bound enforces this.
//!
//! There is no `INSERT`, `UPDATE` or `DELETE` here. Appends go through
//! `modules::audit::append`, which writes the hash chain in the same transaction;
//! the database refuses the other two unconditionally (ADR-006).

use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::modules::audit::chain::{ChainedEntry, StoredEntry};
use crate::platform::errors::{AppError, AppResult};
use crate::shared::pagination::{PageRequest, SortDirection};

use super::service::AuditFilter;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuditEventRow {
    pub seq: i64,
    pub id: Uuid,
    pub occurred_at: OffsetDateTime,
    pub actor_user_id: Option<Uuid>,
    pub actor_principal_type: Option<String>,
    pub actor_session_id: Option<Uuid>,
    pub action_code: String,
    pub target_type: Option<String>,
    pub target_id: Option<Uuid>,
    pub outcome: String,
    pub request_id: Option<String>,
    pub source_ip_hint: Option<String>,
    pub metadata: serde_json::Value,
}

/// A row plus its chain material. Only the verifier ever sees this shape.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ChainRow {
    pub chain_version: i16,
    pub seq: i64,
    pub id: Uuid,
    pub occurred_at: OffsetDateTime,
    pub actor_user_id: Option<Uuid>,
    pub actor_principal_type: Option<String>,
    pub actor_session_id: Option<Uuid>,
    pub action_code: String,
    pub target_type: Option<String>,
    pub target_id: Option<Uuid>,
    pub outcome: String,
    pub request_id: Option<String>,
    pub source_ip_hint: Option<String>,
    pub metadata: serde_json::Value,
    pub prev_hash: Option<Vec<u8>>,
    pub entry_hash: Vec<u8>,
}

impl ChainRow {
    /// Split into the shape `chain::verify_run` consumes.
    ///
    /// Every column the chain covers is carried across verbatim, including
    /// `chain_version`, which selects the layout the digest was computed under.
    /// The version must come from the row and never from `CURRENT_CHAIN_VERSION`:
    /// assuming the current layout would make every entry written under an earlier
    /// one report as tampered, which is the failure mode that teaches an auditor to
    /// ignore the verifier.
    pub fn into_verifiable(self) -> StoredEntry {
        let entry = ChainedEntry {
            chain_version: self.chain_version,
            seq: self.seq,
            id: self.id,
            occurred_at: self.occurred_at,
            actor_user_id: self.actor_user_id,
            actor_principal_type: self.actor_principal_type,
            actor_session_id: self.actor_session_id,
            action_code: self.action_code,
            target_type: self.target_type,
            target_id: self.target_id,
            outcome: self.outcome,
            request_id: self.request_id,
            source_ip_hint: self.source_ip_hint,
            metadata: self.metadata,
        };
        (entry, self.entry_hash, self.prev_hash)
    }
}

/// Newest first — the default, and the ordering the `(occurred_at DESC, seq DESC)`
/// index serves.
///
/// Every filter is a bound parameter guarded by an `IS NULL` test, so the statement
/// text is identical for every request: there is no branch that appends a
/// predicate, which is the whole class of bug this shape removes.
///
/// The keyset predicate compares `(occurred_at, id)` and must stay in step with the
/// `ORDER BY`. That is safe only because the service's sort allowlist has exactly
/// one entry; a second sortable column would need its own comparison, and
/// mismatching the two silently skips or repeats rows at page boundaries.
const LIST_NEWEST_FIRST: &str = "\
    SELECT a.seq, a.id, a.occurred_at, a.actor_user_id, a.actor_principal_type, \
           a.actor_session_id, a.action_code, a.target_type, a.target_id, a.outcome, \
           a.request_id, a.source_ip_hint, a.metadata \
      FROM audit_events a \
     WHERE ($1::uuid        IS NULL OR a.actor_user_id = $1::uuid) \
       AND ($2::text        IS NULL OR a.action_code   = $2::text) \
       AND ($3::text        IS NULL OR a.target_type   = $3::text) \
       AND ($4::uuid        IS NULL OR a.target_id     = $4::uuid) \
       AND ($5::text        IS NULL OR a.outcome       = $5::text) \
       AND ($6::timestamptz IS NULL OR a.occurred_at  >= $6::timestamptz) \
       AND ($7::timestamptz IS NULL OR a.occurred_at  <= $7::timestamptz) \
       AND ($8::timestamptz IS NULL \
            OR (a.occurred_at, a.id) < ($8::timestamptz, $9::uuid)) \
     ORDER BY a.occurred_at DESC, a.id DESC \
     LIMIT $10";

/// Oldest first. A complete second statement rather than an interpolated keyword:
/// two literals are cheaper to review than one template.
const LIST_OLDEST_FIRST: &str = "\
    SELECT a.seq, a.id, a.occurred_at, a.actor_user_id, a.actor_principal_type, \
           a.actor_session_id, a.action_code, a.target_type, a.target_id, a.outcome, \
           a.request_id, a.source_ip_hint, a.metadata \
      FROM audit_events a \
     WHERE ($1::uuid        IS NULL OR a.actor_user_id = $1::uuid) \
       AND ($2::text        IS NULL OR a.action_code   = $2::text) \
       AND ($3::text        IS NULL OR a.target_type   = $3::text) \
       AND ($4::uuid        IS NULL OR a.target_id     = $4::uuid) \
       AND ($5::text        IS NULL OR a.outcome       = $5::text) \
       AND ($6::timestamptz IS NULL OR a.occurred_at  >= $6::timestamptz) \
       AND ($7::timestamptz IS NULL OR a.occurred_at  <= $7::timestamptz) \
       AND ($8::timestamptz IS NULL \
            OR (a.occurred_at, a.id) > ($8::timestamptz, $9::uuid)) \
     ORDER BY a.occurred_at ASC, a.id ASC \
     LIMIT $10";

const FIND_EVENT: &str = "\
    SELECT a.seq, a.id, a.occurred_at, a.actor_user_id, a.actor_principal_type, \
           a.actor_session_id, a.action_code, a.target_type, a.target_id, a.outcome, \
           a.request_id, a.source_ip_hint, a.metadata \
      FROM audit_events a \
     WHERE a.id = $1";

/// The only statement that reads chain material.
const CHAIN_RUN: &str = "\
    SELECT a.chain_version, a.seq, a.id, a.occurred_at, a.actor_user_id, \
           a.actor_principal_type, a.actor_session_id, a.action_code, a.target_type, \
           a.target_id, a.outcome, a.request_id, a.source_ip_hint, a.metadata, \
           a.prev_hash, a.entry_hash \
      FROM audit_events a \
     WHERE a.seq >= $1 \
     ORDER BY a.seq ASC \
     LIMIT $2";

const CHAIN_HEAD: &str = "SELECT last_seq, last_hash FROM audit_chain_head WHERE id";

const PREDECESSOR: &str =
    "SELECT seq, entry_hash FROM audit_events WHERE seq < $1 ORDER BY seq DESC LIMIT 1";

/// The sort column the two listing statements are written against.
const SORT_COLUMN: &str = "a.occurred_at";

/// List events. The statement is chosen from two compile-time literals; nothing is
/// interpolated.
pub async fn list_events(
    pool: &PgPool,
    filter: &AuditFilter,
    page: &PageRequest,
) -> AppResult<Vec<AuditEventRow>> {
    let statement: &'static str = match (page.sort_column, page.direction) {
        (SORT_COLUMN, SortDirection::Desc) => LIST_NEWEST_FIRST,
        (SORT_COLUMN, SortDirection::Asc) => LIST_OLDEST_FIRST,
        // `PageRequest::resolve` can only return a column from the caller's
        // allowlist, which has exactly one entry, so this arm is unreachable. It
        // fails closed rather than guessing which statement was meant.
        _ => return Err(AppError::internal("unrecognised audit sort column")),
    };

    let cursor_timestamp = match &page.cursor {
        None => None,
        Some(cursor) => Some(
            OffsetDateTime::from_unix_timestamp_nanos(i128::from(cursor.timestamp_micros) * 1_000)
                .map_err(|_| {
                    AppError::field("cursor", "INVALID", "Malformed pagination cursor.")
                })?,
        ),
    };
    let cursor_id = page.cursor.as_ref().map(|cursor| cursor.id);

    sqlx::query_as::<_, AuditEventRow>(statement)
        .bind(filter.actor_user_id)
        .bind(filter.action_code.as_deref())
        .bind(filter.target_type.as_deref())
        .bind(filter.target_id)
        .bind(filter.outcome.as_deref())
        .bind(filter.occurred_from)
        .bind(filter.occurred_to)
        .bind(cursor_timestamp)
        .bind(cursor_id)
        .bind(page.fetch_limit())
        .fetch_all(pool)
        .await
        .map_err(AppError::from)
}

/// One event by its public `id` (there is a unique index on it).
pub async fn find_event(pool: &PgPool, id: Uuid) -> AppResult<Option<AuditEventRow>> {
    sqlx::query_as::<_, AuditEventRow>(FIND_EVENT)
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(AppError::from)
}

/// The recorded chain head: the sequence number and digest of the last append.
pub async fn chain_head(pool: &PgPool) -> AppResult<(i64, Option<Vec<u8>>)> {
    let row: (i64, Option<Vec<u8>>) = sqlx::query_as(CHAIN_HEAD)
        .fetch_one(pool)
        .await
        .map_err(AppError::from)?;
    Ok(row)
}

/// The entry immediately preceding `seq`, used to anchor a window that does not
/// start at the beginning of the chain.
///
/// Without this anchor the first entry of the window could not be link-checked, and
/// a run spliced in at a window boundary would pass verification.
pub async fn predecessor(pool: &PgPool, seq: i64) -> AppResult<Option<(i64, Vec<u8>)>> {
    let row: Option<(i64, Vec<u8>)> = sqlx::query_as(PREDECESSOR)
        .bind(seq)
        .fetch_optional(pool)
        .await
        .map_err(AppError::from)?;
    Ok(row)
}

/// A contiguous, ascending run of entries with their chain material.
///
/// `limit` is bounded by the service before it gets here; that bound is what stops
/// the verify endpoint being a denial-of-service lever against its own database.
pub async fn chain_run(pool: &PgPool, from_seq: i64, limit: i64) -> AppResult<Vec<ChainRow>> {
    sqlx::query_as::<_, ChainRow>(CHAIN_RUN)
        .bind(from_seq)
        .bind(limit)
        .fetch_all(pool)
        .await
        .map_err(AppError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    const READER_STATEMENTS: &[&str] = &[LIST_NEWEST_FIRST, LIST_OLDEST_FIRST, FIND_EVENT];

    /// The control this file exists to enforce: the reading path cannot return
    /// chain material, because it never selects it.
    #[test]
    fn no_reading_statement_touches_chain_material() {
        for statement in READER_STATEMENTS {
            assert!(
                !statement.contains("entry_hash"),
                "chain material in a read: {statement}"
            );
            assert!(
                !statement.contains("prev_hash"),
                "chain material in a read: {statement}"
            );
            assert!(!statement.contains('*'), "never SELECT *");
        }
        // ...and the verifier's statement does, which is the point of having two.
        assert!(CHAIN_RUN.contains("a.entry_hash"));
        assert!(CHAIN_RUN.contains("a.prev_hash"));
    }

    /// Every chain-covered field must be fetched by the verifier, or verification
    /// would recompute a digest over a field it invented.
    #[test]
    fn the_verifier_fetches_every_chain_covered_field() {
        for field in [
            "a.seq",
            "a.id",
            "a.occurred_at",
            "a.actor_user_id",
            "a.actor_principal_type",
            "a.actor_session_id",
            "a.action_code",
            "a.target_type",
            "a.target_id",
            "a.outcome",
            "a.request_id",
            // Covered from chain version 2. `chain_version` itself is covered too:
            // it selects the layout, so a verifier that did not fetch it would
            // either assume the current one — reporting every older entry as
            // tampered — or leave the marker outside the digest, where an attacker
            // could edit it to select the weaker layout.
            "a.source_ip_hint",
            "a.chain_version",
            "a.metadata",
        ] {
            assert!(
                CHAIN_RUN.contains(field),
                "`{field}` is not fetched for verification"
            );
        }
    }

    /// Filters must be placeholders. A literal or a comment marker appearing here
    /// would mean someone had begun assembling the clause from input.
    #[test]
    fn the_listing_statements_are_placeholders_only() {
        for statement in [LIST_NEWEST_FIRST, LIST_OLDEST_FIRST] {
            assert!(
                !statement.contains('\''),
                "no literal may appear in a filter clause"
            );
            assert!(!statement.contains(';'), "one statement per query");
            assert!(!statement.contains("--"), "no comment marker");
            // Seven filters, each guarded and compared once, plus the two cursor
            // placeholders and the limit.
            for index in 1..=7 {
                // The `::` suffix is part of the needle so that `$1` does not also
                // match inside `$10`.
                let placeholder = format!("${index}::");
                assert_eq!(
                    statement.matches(&placeholder).count(),
                    2,
                    "`{placeholder}` is not guarded and compared exactly once each"
                );
            }
            assert!(statement.contains("$9::uuid"));
            assert!(statement.ends_with("LIMIT $10"));
        }
    }

    /// The keyset comparison must point the same way as the `ORDER BY`, or a page
    /// boundary silently skips or repeats rows.
    #[test]
    fn the_cursor_comparison_matches_the_ordering() {
        assert!(LIST_NEWEST_FIRST.contains("a.id) < ($8::timestamptz"));
        assert!(LIST_NEWEST_FIRST.contains("ORDER BY a.occurred_at DESC, a.id DESC"));
        assert!(LIST_OLDEST_FIRST.contains("a.id) > ($8::timestamptz"));
        assert!(LIST_OLDEST_FIRST.contains("ORDER BY a.occurred_at ASC, a.id ASC"));
        // Both are written against the one allowlisted sort column.
        assert!(LIST_NEWEST_FIRST.contains(SORT_COLUMN));
        assert!(LIST_OLDEST_FIRST.contains(SORT_COLUMN));
    }
}
