//! Request and response types for reading audit history.
//!
//! # Why there is no create/update/delete request type here
//!
//! There is deliberately **no** `CreateAuditEventRequest`, no
//! `UpdateAuditEventRequest`, no delete, no bulk operation and no
//! export-with-side-effects. This is load-bearing, not an oversight (ADR-006 §1).
//! Audit records are written only by `modules::audit::append`, inside the
//! transaction of the change they describe; an HTTP endpoint that could append one
//! would let a caller manufacture history, and one that could remove one would let
//! an administrator erase their own escalation. The database refuses `UPDATE`,
//! `DELETE` and `TRUNCATE` independently, and the runtime role holds only
//! `SELECT, INSERT` — so this absence is the first of four controls, not the only
//! one. Adding a mutating route here needs a new ADR, not a new handler.
//!
//! # Why `entry_hash` and `prev_hash` are absent from the reader types
//!
//! They are **integrity material, not business data**. Publishing them to every
//! `audit.read` holder has no upside — a reader cannot check them without the
//! chain key, which never leaves the process — and two downsides: it hands an
//! attacker who is about to tamper the exact digests they must reproduce, and it
//! invites clients to build verification logic against a representation that is
//! free to change. They appear in exactly one place: the hex diagnostics of
//! `GET /api/v1/audit/verify`, which already requires a recent step-up.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use super::repo::AuditEventRow;

/// `GET /api/v1/audit/events` query parameters.
///
/// Every member is an `Option<String>` and every one is validated in the service
/// against an allowlist or a strict pattern. Taking typed values here would move
/// rejection into serde, whose message names Rust types, and would make an
/// unparseable filter a 400 with the wrong shape.
///
/// `deny_unknown_fields` matters more than usual on a filter DTO: a silently
/// ignored `?actor_user_id_like=%` reads to the caller as "the filter applied" and
/// returns a wider set than they asked for.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEventQuery {
    // --- pagination (mirrors `shared::pagination::PageQuery`) ---
    pub cursor: Option<String>,
    pub limit: Option<String>,
    pub sort: Option<String>,
    pub direction: Option<String>,

    // --- filters, all allowlisted ---
    pub actor_user_id: Option<String>,
    pub action_code: Option<String>,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    pub outcome: Option<String>,
    /// Inclusive lower bound, RFC 3339.
    pub occurred_from: Option<String>,
    /// Inclusive upper bound, RFC 3339.
    pub occurred_to: Option<String>,
}

/// One audit record as an ordinary reader sees it.
///
/// Hand-written, and deliberately *not* the row struct: the row carries
/// `entry_hash` and `prev_hash`, and a `#[derive]`-shaped response would publish
/// them the moment someone added the columns to the reading query.
#[derive(Debug, Serialize, PartialEq)]
pub struct AuditEventResponse {
    pub id: Uuid,
    /// Chain position. Exposed because gap detection is exactly what an auditor
    /// wants to do by hand; it reveals nothing a row count does not.
    pub seq: i64,
    pub occurred_at: String,
    pub actor_user_id: Option<Uuid>,
    pub actor_principal_type: Option<String>,
    pub actor_session_id: Option<Uuid>,
    pub action_code: String,
    pub target_type: Option<String>,
    pub target_id: Option<Uuid>,
    pub outcome: String,
    pub request_id: Option<String>,
    pub source_ip_hint: Option<String>,
    /// Written through the closed `AuditMetadata` builder, which refuses
    /// secret-bearing keys, so it is safe to return verbatim.
    pub metadata: Value,
}

impl AuditEventResponse {
    /// Built field by field from the reader row. Written out rather than derived so
    /// that adding a column to `AuditEventRow` does not silently publish it.
    pub fn from_row(row: AuditEventRow) -> Self {
        Self {
            id: row.id,
            seq: row.seq,
            // A timestamp that fails to format renders empty rather than failing the
            // whole listing; `timestamptz` cannot actually fail here.
            occurred_at: row.occurred_at.format(&Rfc3339).unwrap_or_default(),
            actor_user_id: row.actor_user_id,
            actor_principal_type: row.actor_principal_type,
            actor_session_id: row.actor_session_id,
            action_code: row.action_code,
            target_type: row.target_type,
            target_id: row.target_id,
            outcome: row.outcome,
            request_id: row.request_id,
            source_ip_hint: row.source_ip_hint,
            metadata: row.metadata,
        }
    }
}

/// `GET /api/v1/audit/verify` query parameters.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyQuery {
    /// First sequence number to check. Defaults to the start of the last window.
    pub from_seq: Option<String>,
    /// How many entries to check. Defaults to 10 000, capped at 100 000.
    pub limit: Option<String>,
}

/// The stored hashes of the entry where verification diverged, hex-encoded.
///
/// The **only** place raw chain material is exposed, and then only as hex to a
/// caller who holds `audit.read` and has completed a recent step-up. It exists
/// because "the chain broke at seq 4821" is not actionable on its own: an operator
/// comparing an offline backup needs the two digests to say which side moved.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct ChainDiagnostics {
    pub seq: i64,
    pub stored_entry_hash_hex: String,
    pub stored_prev_hash_hex: Option<String>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct VerifyResponse {
    /// `INTACT`, `HASH_MISMATCH`, `BROKEN_LINK`, `MISSING_SEQUENCE` or
    /// `HEAD_MISMATCH`. A stable, machine-readable vocabulary.
    pub outcome: &'static str,
    pub entries_checked: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_divergent_seq: Option<i64>,
    /// The window that was actually verified, so a caller knows what the answer
    /// covers. `INTACT` over the last 10 000 entries is not `INTACT` over history.
    pub checked_from_seq: i64,
    pub checked_to_seq: i64,
    /// Whether the window ran to the end of the table. `false` means older or newer
    /// entries were not examined.
    pub reached_chain_head: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnostics: Option<ChainDiagnostics>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A filter that is silently dropped is worse than one that is refused: the
    /// caller believes the result set was narrowed.
    #[test]
    fn unknown_query_parameters_are_refused_rather_than_ignored() {
        for query in [
            r#"{"action_code_like":"USER.%"}"#,
            r#"{"order_by":"seq"}"#,
            r#"{"actor_user_id":"x","offset":"100"}"#,
            r#"{"include_hashes":"true"}"#,
        ] {
            assert!(
                serde_json::from_str::<AuditEventQuery>(query).is_err(),
                "accepted an unknown filter: {query}"
            );
        }
        assert!(serde_json::from_str::<AuditEventQuery>(
            r#"{"action_code":"USER.CREATED","limit":"50"}"#
        )
        .is_ok());
    }

    /// The property ADR-006 asks for on the read path: chain material must not
    /// reach an ordinary reader.
    #[test]
    fn an_event_response_carries_no_chain_material() {
        let value = serde_json::to_value(AuditEventResponse {
            id: Uuid::from_u128(1),
            seq: 7,
            occurred_at: "2026-08-07T00:00:00Z".into(),
            actor_user_id: None,
            actor_principal_type: Some("INTERNAL".into()),
            actor_session_id: None,
            action_code: "USER.CREATED".into(),
            target_type: Some("USER".into()),
            target_id: None,
            outcome: "SUCCESS".into(),
            request_id: None,
            source_ip_hint: None,
            metadata: json!({}),
        })
        .expect("serialise");
        let object = value.as_object().expect("object");
        for forbidden in [
            "entry_hash",
            "prev_hash",
            "entry_hash_hex",
            "prev_hash_hex",
            "hash",
        ] {
            assert!(
                !object.contains_key(forbidden),
                "`{forbidden}` reached an ordinary audit reader"
            );
        }
    }

    #[test]
    fn a_verify_response_omits_absent_diagnostics_entirely() {
        let value = serde_json::to_value(VerifyResponse {
            outcome: "INTACT",
            entries_checked: 10,
            first_divergent_seq: None,
            checked_from_seq: 1,
            checked_to_seq: 10,
            reached_chain_head: true,
            diagnostics: None,
        })
        .expect("serialise");
        let object = value.as_object().expect("object");
        assert!(!object.contains_key("diagnostics"));
        assert!(!object.contains_key("first_divergent_seq"));
    }
}
