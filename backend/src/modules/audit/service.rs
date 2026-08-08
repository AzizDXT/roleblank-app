//! Audit read service: filter validation, listing, single fetch, chain verification.
//!
//! # The API surface is read-only, deliberately and permanently
//!
//! This service exposes three operations: list, get, verify. There is **no**
//! create, no update, no delete, no bulk operation, and no "export" that has a side
//! effect (no marking as reviewed, no retention job, no archive-and-purge). That is
//! the first of the four controls in ADR-006 and it is load-bearing: an
//! administrator who can edit audit history can erase their own escalation, so
//! there is deliberately nothing here to negotiate with. The database refuses
//! `UPDATE`, `DELETE` and `TRUNCATE` unconditionally, the runtime role holds only
//! `SELECT, INSERT`, and the hash chain makes an out-of-band edit detectable — but
//! those are the *other three* controls. This one is the absence of a handler, and
//! it only stays true if nobody adds one. Adding a mutating audit endpoint needs a
//! new ADR, not a new function in this file.

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::app::AppState;
use crate::modules::audit::chain::{self, VerificationOutcome};
use crate::modules::authentication::principal::Principal;
use crate::modules::authorization::domain::Target;
use crate::platform::errors::{AppError, AppResult};
use crate::shared::pagination::{Cursor, Page, PageQuery, PageRequest};
use crate::shared::validation as v;

use super::dto::{
    AuditEventQuery, AuditEventResponse, ChainDiagnostics, VerifyQuery, VerifyResponse,
};
use super::repo;

pub const PERM_READ: &str = "audit.read";

/// The single sortable field.
///
/// One entry, on purpose. The cursor comparison in `repo::list_events` is written
/// against `(occurred_at, id)`; a second sortable column would need its own keyset
/// predicate, and mismatching the two silently skips or repeats rows at page
/// boundaries. The user's string is only ever *compared* against the left-hand
/// value — the right-hand `&'static str` is what reaches the query.
const ALLOWED_SORTS: &[(&str, &str)] = &[("occurred_at", "a.occurred_at")];
const DEFAULT_SORT: &str = "a.occurred_at";

/// Outcomes are a genuinely closed set, mirroring the `CHECK` on the column.
pub const OUTCOMES: &[&str] = &["SUCCESS", "DENIED", "FAILURE"];

/// Matches the `action_code` `CHECK` in `0007_audit.sql`.
const MAX_ACTION_CODE_LEN: usize = 100;
/// Matches `CHECK (target_type IS NULL OR length(target_type) <= 50)`.
const MAX_TARGET_TYPE_LEN: usize = 50;

/// Verification window defaults. Bounding this is what stops `/audit/verify` from
/// being a denial-of-service lever against its own database: without a cap, one
/// request would recompute an HMAC over every row ever written, holding a
/// connection for as long as that takes.
pub const DEFAULT_VERIFY_WINDOW: i64 = 10_000;
pub const MAX_VERIFY_WINDOW: i64 = 100_000;

/// A validated filter. Constructing one is the only way to reach the query.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AuditFilter {
    pub actor_user_id: Option<Uuid>,
    pub action_code: Option<String>,
    pub target_type: Option<String>,
    pub target_id: Option<Uuid>,
    pub outcome: Option<String>,
    pub occurred_from: Option<OffsetDateTime>,
    pub occurred_to: Option<OffsetDateTime>,
}

// ---------------------------------------------------------------------------
// Filter validation — pure, so the adversarial cases need no database
// ---------------------------------------------------------------------------

fn parse_uuid(field: &'static str, raw: &str) -> AppResult<Uuid> {
    Uuid::parse_str(raw.trim())
        // The rejected value is never echoed: it is attacker-controlled and this
        // message reaches both the response and the log.
        .map_err(|_| AppError::field(field, "INVALID", "Must be a UUID."))
}

fn parse_timestamp(field: &'static str, raw: &str) -> AppResult<OffsetDateTime> {
    // Bound before parsing. An unbounded string is free work for an attacker even
    // when the parser rejects it.
    let trimmed = raw.trim();
    if trimmed.len() > 64 {
        return Err(AppError::field(
            field,
            "INVALID",
            "Must be an RFC 3339 timestamp.",
        ));
    }
    OffsetDateTime::parse(trimmed, &Rfc3339)
        .map_err(|_| AppError::field(field, "INVALID", "Must be an RFC 3339 timestamp."))
}

/// `action_code` against the same strict pattern the database enforces:
/// `^[A-Z][A-Z0-9_]*(\.[A-Z][A-Z0-9_]*)*$`.
///
/// A **pattern** rather than the `modules::audit::action` constant list, and the
/// choice is deliberate: the constants are added module by module as the system is
/// built, and validating against a snapshot of them would make a legitimately
/// recorded action silently unfilterable — the reader would get an empty page and
/// conclude nothing had happened. The pattern is exactly as tight as the column's
/// own `CHECK`, so nothing filterable is excluded and nothing unstorable is
/// accepted. The value is a bind parameter in any case; this is the bound and the
/// shape check, not the injection defence.
fn validate_action_code(raw: &str) -> AppResult<String> {
    let code = raw.trim();
    if code.is_empty() {
        return Err(AppError::field(
            "action_code",
            "REQUIRED",
            "An action code is required.",
        ));
    }
    if code.len() > MAX_ACTION_CODE_LEN {
        return Err(AppError::field(
            "action_code",
            "TOO_LONG",
            format!("Must be at most {MAX_ACTION_CODE_LEN} characters."),
        ));
    }
    let well_formed = code.split('.').all(|segment| {
        let mut chars = segment.chars();
        matches!(chars.next(), Some(c) if c.is_ascii_uppercase())
            && segment
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
    });
    if !well_formed {
        return Err(AppError::field(
            "action_code",
            "INVALID_FORMAT",
            "An action code is dot-separated uppercase segments, e.g. `USER.CREATED`.",
        ));
    }
    Ok(code.to_string())
}

/// `target_type` against `^[A-Z][A-Z0-9_]*$`, bounded at the column's own limit.
///
/// Same reasoning as `action_code`: the set of target types grows as modules are
/// added, and a hard-coded list here would make a real record unfilterable.
fn validate_target_type(raw: &str) -> AppResult<String> {
    let value = raw.trim();
    if value.is_empty() {
        return Err(AppError::field(
            "target_type",
            "REQUIRED",
            "A target type is required.",
        ));
    }
    if value.len() > MAX_TARGET_TYPE_LEN {
        return Err(AppError::field(
            "target_type",
            "TOO_LONG",
            format!("Must be at most {MAX_TARGET_TYPE_LEN} characters."),
        ));
    }
    let mut chars = value.chars();
    let well_formed = matches!(chars.next(), Some(c) if c.is_ascii_uppercase())
        && value
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
    if !well_formed {
        return Err(AppError::field(
            "target_type",
            "INVALID_FORMAT",
            "A target type is a single uppercase segment, e.g. `PROJECT`.",
        ));
    }
    Ok(value.to_string())
}

/// Validate every filter. Anything not on this list is refused by
/// `deny_unknown_fields` before it reaches here.
pub fn parse_filter(query: &AuditEventQuery) -> AppResult<AuditFilter> {
    let filter = AuditFilter {
        actor_user_id: query
            .actor_user_id
            .as_deref()
            .map(|raw| parse_uuid("actor_user_id", raw))
            .transpose()?,
        action_code: query
            .action_code
            .as_deref()
            .map(validate_action_code)
            .transpose()?,
        target_type: query
            .target_type
            .as_deref()
            .map(validate_target_type)
            .transpose()?,
        target_id: query
            .target_id
            .as_deref()
            .map(|raw| parse_uuid("target_id", raw))
            .transpose()?,
        outcome: query
            .outcome
            .as_deref()
            .map(|raw| {
                v::parse_enum(
                    "outcome",
                    raw,
                    |candidate| {
                        OUTCOMES
                            .iter()
                            .find(|allowed| **allowed == candidate)
                            .map(|s| (*s).to_string())
                    },
                    OUTCOMES,
                )
            })
            .transpose()?,
        occurred_from: query
            .occurred_from
            .as_deref()
            .map(|raw| parse_timestamp("occurred_from", raw))
            .transpose()?,
        occurred_to: query
            .occurred_to
            .as_deref()
            .map(|raw| parse_timestamp("occurred_to", raw))
            .transpose()?,
    };

    if let (Some(from), Some(to)) = (filter.occurred_from, filter.occurred_to) {
        if from > to {
            return Err(AppError::field(
                "occurred_from",
                "OUT_OF_RANGE",
                "`occurred_from` must not be later than `occurred_to`.",
            ));
        }
    }

    Ok(filter)
}

/// Micros since the epoch, for the keyset cursor. `timestamptz` is
/// microsecond-precision, so this round-trips exactly.
fn cursor_micros(value: OffsetDateTime) -> i64 {
    i64::try_from(value.unix_timestamp_nanos() / 1_000).unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

/// `GET /api/v1/audit/events`.
///
/// `Target::Collection`, which only a `GLOBAL` grant covers: audit history has no
/// department and no owner, so there is no narrower scope that could sensibly
/// filter it. Reading it is all-or-nothing by design.
pub async fn list_events(
    state: &AppState,
    principal: &Principal,
    query: &AuditEventQuery,
) -> AppResult<Page<AuditEventResponse>> {
    state.require(principal, PERM_READ, &Target::Collection)?;

    let filter = parse_filter(query)?;
    let page_query = PageQuery {
        cursor: query.cursor.clone(),
        limit: query.limit.clone(),
        sort: query.sort.clone(),
        direction: query.direction.clone(),
    };
    // Newest first unless the caller asks otherwise: `PageRequest::resolve`
    // defaults `direction` to `desc`.
    let page = PageRequest::resolve(
        &page_query,
        ALLOWED_SORTS,
        DEFAULT_SORT,
        state.config.limits.max_page_size,
    )?;

    let rows = repo::list_events(&state.db, &filter, &page).await?;
    let rows = Page::build(rows, &page, |row| Cursor {
        timestamp_micros: cursor_micros(row.occurred_at),
        id: row.id,
    });

    Ok(Page {
        items: rows
            .items
            .into_iter()
            .map(AuditEventResponse::from_row)
            .collect(),
        next_cursor: rows.next_cursor,
        has_more: rows.has_more,
    })
}

/// `GET /api/v1/audit/events/{id}`.
pub async fn get_event(
    state: &AppState,
    principal: &Principal,
    raw_id: &str,
) -> AppResult<AuditEventResponse> {
    state.require(principal, PERM_READ, &Target::Collection)?;

    // A malformed id cannot name a record, so it is `NotFound` rather than a
    // validation error: the two are indistinguishable to the caller and the former
    // does not reflect their input.
    //
    // The segment is **not** trimmed, matching `extract::parse_path_uuid` exactly.
    // It used to be, which made this the third of three path parsers in the
    // codebase with two different acceptance sets — `/audit/events/%20{uuid}%20`
    // resolved while `/departments/%20{uuid}%20` was refused. `PathId` is not used
    // directly here only because this route's contract is "a malformed id is a
    // `404`", and `PathId` correctly raises a `400`; the acceptance set is now
    // identical either way.
    let Ok(id) = Uuid::parse_str(raw_id) else {
        return Err(AppError::NotFound);
    };

    repo::find_event(&state.db, id)
        .await?
        .map(AuditEventResponse::from_row)
        .ok_or(AppError::NotFound)
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// Resolve the window to verify. Pure, so the bounding can be tested directly.
///
/// Returns `(first_seq, limit)`. Without a bound here, one request would recompute
/// an HMAC over the entire table — the endpoint would be its own denial of service,
/// and a permission held by every auditor would be enough to trigger it.
pub fn resolve_verify_window(
    raw_from_seq: Option<&str>,
    raw_limit: Option<&str>,
    head_seq: i64,
) -> AppResult<(i64, i64)> {
    let limit = match raw_limit {
        None => DEFAULT_VERIFY_WINDOW,
        Some(raw) => {
            let parsed: i64 = raw.trim().parse().map_err(|_| {
                AppError::field("limit", "INVALID", "`limit` must be a positive integer.")
            })?;
            if parsed < 1 {
                return Err(AppError::field(
                    "limit",
                    "OUT_OF_RANGE",
                    "`limit` must be at least 1.",
                ));
            }
            if parsed > MAX_VERIFY_WINDOW {
                return Err(AppError::field(
                    "limit",
                    "OUT_OF_RANGE",
                    format!("`limit` must not exceed {MAX_VERIFY_WINDOW}."),
                ));
            }
            parsed
        }
    };

    let from_seq = match raw_from_seq {
        Some(raw) => {
            let parsed: i64 = raw.trim().parse().map_err(|_| {
                AppError::field(
                    "from_seq",
                    "INVALID",
                    "`from_seq` must be a positive integer.",
                )
            })?;
            if parsed < 1 {
                return Err(AppError::field(
                    "from_seq",
                    "OUT_OF_RANGE",
                    "`from_seq` must be at least 1.",
                ));
            }
            parsed
        }
        // Default window: the most recent `limit` entries. `saturating_*` because
        // a head of 0 (an empty chain) must not wrap.
        None => head_seq.saturating_sub(limit).saturating_add(1).max(1),
    };

    Ok((from_seq, limit))
}

fn hex(bytes: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(bytes)
}

/// `GET /api/v1/audit/verify` — requires `audit.read` **and** a recent step-up.
///
/// The step-up is unconditional rather than routed through `require_step_up_for`:
/// `audit.read` is not a dangerous permission (an auditor reads history all day),
/// but *this* operation is a bulk cryptographic scan of the integrity record, and
/// running it is how one would learn whether tampering has already been noticed.
/// Requiring a second factor for it costs an auditor one prompt and costs a
/// stolen-session attacker the whole capability.
///
/// The run is **not** audited. There is no action code for it in the closed
/// `audit::action` list, and appending an entry to the chain one is verifying is a
/// confusing thing to do; the read is visible in operational logs against the
/// request id.
pub async fn verify(
    state: &AppState,
    principal: &Principal,
    query: &VerifyQuery,
) -> AppResult<VerifyResponse> {
    state.require(principal, PERM_READ, &Target::Collection)?;
    state.require_step_up(principal)?;

    let (head_seq, head_hash) = repo::chain_head(&state.db).await?;
    let (first_seq, limit) =
        resolve_verify_window(query.from_seq.as_deref(), query.limit.as_deref(), head_seq)?;

    // Anchor the window. Verifying a run that does not start at the beginning of
    // the chain requires the preceding entry's digest, or the first link cannot be
    // checked and a spliced-in run at a window boundary would pass.
    let predecessor = repo::predecessor(&state.db, first_seq).await?;
    let expected_first_prev = predecessor.as_ref().map(|(_, hash)| hash.clone());
    let expected_first_seq = Some(predecessor.as_ref().map(|(seq, _)| seq + 1).unwrap_or(1));

    let rows = repo::chain_run(&state.db, first_seq, limit).await?;
    // Fewer rows than asked for means there is nothing after this window.
    let reached_chain_head = (rows.len() as i64) < limit;
    let last_row_seq = rows.last().map(|row| row.seq).unwrap_or(0);
    let last_row_hash = rows.last().map(|row| row.entry_hash.clone());
    let checked_from_seq = rows.first().map(|row| row.seq).unwrap_or(first_seq);

    let entries: Vec<_> = rows
        .into_iter()
        .map(repo::ChainRow::into_verifiable)
        .collect();
    let mut outcome = chain::verify_run(
        &state.chain_key,
        &entries,
        expected_first_prev,
        expected_first_seq,
    );

    // The run can be internally consistent and still be a truncated tail — that is
    // precisely what an attacker who deletes the most recent entries produces. The
    // head record is the independent witness, so it is compared whenever the window
    // reached the end of the table.
    if outcome.is_intact() && reached_chain_head {
        if last_row_seq != head_seq {
            outcome = VerificationOutcome::HeadMismatch {
                head_seq,
                last_row_seq,
            };
        } else if last_row_hash.is_some() && last_row_hash != head_hash {
            // Same class of failure: the recorded head disagrees with the row it
            // claims to describe.
            outcome = VerificationOutcome::HeadMismatch {
                head_seq,
                last_row_seq,
            };
        }
    }

    let (label, first_divergent_seq, entries_checked) = match &outcome {
        VerificationOutcome::Intact {
            entries_checked, ..
        } => ("INTACT", None, *entries_checked),
        VerificationOutcome::HashMismatch {
            seq,
            entries_checked,
        } => ("HASH_MISMATCH", Some(*seq), *entries_checked),
        VerificationOutcome::BrokenLink {
            seq,
            entries_checked,
        } => ("BROKEN_LINK", Some(*seq), *entries_checked),
        VerificationOutcome::MissingSequence { expected, .. } => {
            // `verify_run` does not carry a count on this variant; the run is
            // contiguous up to the gap, so it is derivable.
            let checked = u64::try_from(expected - checked_from_seq).unwrap_or(0);
            ("MISSING_SEQUENCE", Some(*expected), checked)
        }
        VerificationOutcome::HeadMismatch { last_row_seq, .. } => (
            "HEAD_MISMATCH",
            Some(*last_row_seq),
            u64::try_from(entries.len()).unwrap_or(0),
        ),
    };

    // Hex chain material, only here, only for the divergent entry, and only for a
    // caller who has just proved a second factor.
    let diagnostics = first_divergent_seq.and_then(|seq| {
        entries
            .iter()
            .find(|(entry, _, _)| entry.seq == seq)
            .map(|(entry, hash, prev)| ChainDiagnostics {
                seq: entry.seq,
                stored_entry_hash_hex: hex(hash),
                stored_prev_hash_hex: prev.as_deref().map(hex),
            })
    });

    Ok(VerifyResponse {
        outcome: label,
        entries_checked,
        first_divergent_seq,
        checked_from_seq,
        checked_to_seq: last_row_seq,
        reached_chain_head,
        diagnostics,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query_with(field: &str, value: &str) -> AuditEventQuery {
        let mut q = AuditEventQuery::default();
        match field {
            "actor_user_id" => q.actor_user_id = Some(value.to_string()),
            "action_code" => q.action_code = Some(value.to_string()),
            "target_type" => q.target_type = Some(value.to_string()),
            "target_id" => q.target_id = Some(value.to_string()),
            "outcome" => q.outcome = Some(value.to_string()),
            "occurred_from" => q.occurred_from = Some(value.to_string()),
            "occurred_to" => q.occurred_to = Some(value.to_string()),
            other => panic!("unknown filter field `{other}`"),
        }
        q
    }

    fn message_of(err: &AppError) -> String {
        match err {
            AppError::Validation { errors } => errors[0].message.to_string(),
            other => panic!("expected a validation error, got {other}"),
        }
    }

    #[test]
    fn a_well_formed_filter_is_accepted() {
        let q = AuditEventQuery {
            actor_user_id: Some("00000000-0000-7000-8000-000000000001".into()),
            action_code: Some("PROJECT.SHARED_WITH_CLIENT".into()),
            target_type: Some("PROJECT".into()),
            target_id: Some("00000000-0000-7000-8000-000000000002".into()),
            outcome: Some("DENIED".into()),
            occurred_from: Some("2026-01-01T00:00:00Z".into()),
            occurred_to: Some("2026-12-31T23:59:59Z".into()),
            ..Default::default()
        };

        let filter = parse_filter(&q).expect("valid filter");
        assert_eq!(
            filter.action_code.as_deref(),
            Some("PROJECT.SHARED_WITH_CLIENT")
        );
        assert_eq!(filter.target_type.as_deref(), Some("PROJECT"));
        assert_eq!(filter.outcome.as_deref(), Some("DENIED"));
        assert!(filter.occurred_from.is_some() && filter.occurred_to.is_some());
    }

    #[test]
    fn an_empty_filter_is_valid_and_selects_everything() {
        assert_eq!(
            parse_filter(&AuditEventQuery::default()).expect("valid"),
            AuditFilter::default()
        );
    }

    /// The core adversarial test. Every one of these is a value that would be
    /// dangerous if it were ever interpolated into SQL, and each must be refused by
    /// the allowlist before it ever becomes a bind parameter.
    #[test]
    fn action_code_and_target_type_reject_injection_strings() {
        let attacks = [
            "USER.CREATED'; DROP TABLE audit_events--",
            "USER.CREATED' OR '1'='1",
            "' UNION SELECT entry_hash, prev_hash FROM audit_events--",
            "USER.CREATED\"; DELETE FROM audit_events; --",
            "1; TRUNCATE audit_events",
            "USER.CREATED/*comment*/",
            "%",
            "_",
            "*",
            "USER.CREATED\u{0}",
            "USER.CREATED\nUSER.DELETED",
            "user.created",
            "USER..CREATED",
            ".CREATED",
            "9USER.CREATED",
            "USER.CREATED; SELECT pg_sleep(30)",
            "",
            "   ",
        ];

        for attack in attacks {
            for field in ["action_code", "target_type"] {
                let err = parse_filter(&query_with(field, attack))
                    .expect_err(&format!("`{field}` accepted {attack:?}"));
                let message = message_of(&err);
                // The rejected value must never be reflected back: this message is
                // rendered by a client and written to a log.
                assert!(!message.contains("DROP"), "input echoed: {message}");
                assert!(!message.contains("UNION"), "input echoed: {message}");
                assert!(!message.contains("pg_sleep"), "input echoed: {message}");
            }
        }

        // `target_type` is a single segment; a dotted value is not one.
        assert!(parse_filter(&query_with("target_type", "PROJECT.TASK")).is_err());
        // ...and it is bounded at the column's own limit.
        assert!(parse_filter(&query_with("target_type", &"A".repeat(51))).is_err());
        assert!(parse_filter(&query_with("action_code", &"A".repeat(101))).is_err());
        assert!(parse_filter(&query_with("action_code", &"A".repeat(1_000_000))).is_err());
    }

    #[test]
    fn outcome_is_a_closed_set() {
        for good in OUTCOMES {
            assert_eq!(
                parse_filter(&query_with("outcome", good))
                    .expect("valid")
                    .outcome
                    .as_deref(),
                Some(*good)
            );
        }
        for bad in ["success", "OK", "", "SUCCESS'--", "SUCCESS OR 1=1", "ALL"] {
            let err = parse_filter(&query_with("outcome", bad)).expect_err("must reject");
            // The allowed set is public contract and IS named.
            assert!(message_of(&err).contains("SUCCESS"));
        }
    }

    #[test]
    fn identifier_filters_must_be_uuids() {
        for field in ["actor_user_id", "target_id"] {
            for bad in [
                "1",
                "abc",
                "",
                "00000000-0000-7000-8000-00000000000",
                "00000000-0000-7000-8000-000000000001'; DROP TABLE users--",
                "' OR 1=1--",
            ] {
                let err = parse_filter(&query_with(field, bad))
                    .expect_err(&format!("`{field}` accepted {bad:?}"));
                assert!(!message_of(&err).contains("DROP"));
            }
        }
    }

    #[test]
    fn time_bounds_must_be_rfc3339_and_ordered() {
        for bad in [
            "yesterday",
            "2026-13-01T00:00:00Z",
            "2026-01-01",
            "",
            "2026-01-01T00:00:00Z'; DROP TABLE audit_events--",
            &"9".repeat(10_000),
        ] {
            assert!(
                parse_filter(&query_with("occurred_from", bad)).is_err(),
                "accepted {bad:?}"
            );
        }

        let q = AuditEventQuery {
            occurred_from: Some("2026-06-01T00:00:00Z".into()),
            occurred_to: Some("2026-01-01T00:00:00Z".into()),
            ..Default::default()
        };
        let err = parse_filter(&q).expect_err("an inverted range must be refused");
        assert!(message_of(&err).contains("occurred_to"));
    }

    // ---- the verify window bound -----------------------------------------

    /// The bound that keeps `/audit/verify` from being its own denial of service.
    #[test]
    fn the_verify_window_defaults_to_the_last_ten_thousand_entries() {
        let (from, limit) = resolve_verify_window(None, None, 1_000_000).expect("valid");
        assert_eq!(limit, DEFAULT_VERIFY_WINDOW);
        assert_eq!(from, 1_000_000 - DEFAULT_VERIFY_WINDOW + 1);
    }

    #[test]
    fn the_verify_window_is_capped_at_one_hundred_thousand() {
        assert_eq!(
            resolve_verify_window(None, Some("100000"), 500_000)
                .expect("valid")
                .1,
            MAX_VERIFY_WINDOW
        );
        for over in ["100001", "1000000", "9223372036854775807"] {
            let err = resolve_verify_window(None, Some(over), 500_000)
                .expect_err(&format!("accepted limit {over}"));
            assert!(message_of(&err).contains("100000"), "the cap must be named");
        }
    }

    #[test]
    fn a_nonsensical_verify_window_is_refused_rather_than_clamped() {
        for bad in ["0", "-1", "abc", "", "1e6", "1_000", " ", "10.5"] {
            assert!(
                resolve_verify_window(None, Some(bad), 100).is_err(),
                "accepted limit {bad:?}"
            );
        }
        for bad in ["0", "-1", "abc", "", "-9223372036854775808"] {
            assert!(
                resolve_verify_window(Some(bad), None, 100).is_err(),
                "accepted from_seq {bad:?}"
            );
        }
    }

    /// A short or empty chain must not produce a negative or wrapping start.
    #[test]
    fn a_short_chain_starts_the_window_at_one() {
        assert_eq!(resolve_verify_window(None, None, 0).expect("valid").0, 1);
        assert_eq!(resolve_verify_window(None, None, 5).expect("valid").0, 1);
        assert_eq!(
            resolve_verify_window(None, Some("1"), 0).expect("valid").0,
            1
        );
        // A head value that should never occur must still not wrap.
        assert_eq!(
            resolve_verify_window(None, None, i64::MIN)
                .expect("valid")
                .0,
            1
        );
    }

    #[test]
    fn an_explicit_start_is_honoured_within_the_cap() {
        let (from, limit) = resolve_verify_window(Some("42"), Some("100"), 1_000).expect("valid");
        assert_eq!((from, limit), (42, 100));
    }

    #[test]
    fn the_permission_this_module_uses_exists() {
        use crate::modules::authorization::catalog;
        assert!(catalog::exists(PERM_READ));
    }

    /// One sortable field, matching the cursor comparison in the repository.
    #[test]
    fn the_sort_allowlist_has_exactly_one_entry() {
        assert_eq!(ALLOWED_SORTS.len(), 1);
        assert_eq!(ALLOWED_SORTS[0], ("occurred_at", DEFAULT_SORT));
    }
}
