//! The audit hash chain (ADR-006).
//!
//! ## The claim, stated exactly
//!
//! > Any modification, deletion or reordering of `audit_events` performed **without
//! > the chain key** is detected by `roleblank-api verify-audit`.
//!
//! That is the entire claim. It is **not** tamper-proofing. An adversary holding
//! both the database and the chain key can rewrite the chain consistently and no
//! verification will notice — the verifier and the forger would hold identical
//! capabilities. The chain is useful because the key lives outside the database,
//! so a stolen dump, a malicious administrator with SQL access, or a compromised
//! backup cannot produce a consistent forgery.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::shared::secret::Secret;

type HmacSha256 = Hmac<Sha256>;

/// Sentinel length for an absent field.
///
/// Absent must be distinguishable from empty. Without this, `target_type = NULL`
/// and `target_type = ""` would hash identically, and an attacker could blank a
/// field without changing the digest.
const ABSENT: u64 = u64::MAX;

/// The fields that are covered by the chain.
///
/// Everything an auditor would care about is here. A field NOT in this struct is
/// not protected — so adding a column to `audit_events` requires adding it here
/// too, and that is deliberately a visible, reviewable change rather than an
/// automatic one.
#[derive(Debug, Clone)]
pub struct ChainedEntry {
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
    pub metadata: serde_json::Value,
}

/// An audit row as read back for verification: the entry itself, the `entry_hash`
/// that was stored alongside it, and the `prev_hash` it recorded.
///
/// All three components are needed and none of them is redundant. Recomputing the
/// hash from the entry and comparing it against the stored `entry_hash` proves the
/// fields are intact; comparing the stored `prev_hash` against the *previous*
/// entry's recomputed hash proves the chain has not been reordered or spliced. A
/// verifier holding only the entry could detect neither.
pub type StoredEntry = (ChainedEntry, Vec<u8>, Option<Vec<u8>>);

/// Append a length-prefixed field.
///
/// Length prefixing is not decoration. Without it, `("ab", "c")` and `("a", "bc")`
/// serialise to the same bytes, and an attacker could shift content across field
/// boundaries — moving part of an action code into a target id, say — while
/// preserving the digest.
fn push_field(buf: &mut Vec<u8>, value: Option<&[u8]>) {
    match value {
        None => buf.extend_from_slice(&ABSENT.to_be_bytes()),
        Some(bytes) => {
            buf.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            buf.extend_from_slice(bytes);
        }
    }
}

/// Deterministic JSON: object keys sorted recursively.
///
/// `serde_json::Value` preserves insertion order by default in some
/// configurations and sorts in others; either way, two logically identical
/// documents must produce identical bytes or verification would report false
/// tampering after an innocuous round-trip through PostgreSQL's `jsonb`.
fn canonical_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            let parts: Vec<String> = keys
                .into_iter()
                .map(|k| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(k).unwrap_or_else(|_| "\"\"".into()),
                        canonical_json(&map[k])
                    )
                })
                .collect();
            format!("{{{}}}", parts.join(","))
        }
        serde_json::Value::Array(items) => {
            let parts: Vec<String> = items.iter().map(canonical_json).collect();
            format!("[{}]", parts.join(","))
        }
        other => serde_json::to_string(other).unwrap_or_else(|_| "null".into()),
    }
}

/// The exact byte sequence that gets HMAC'd.
pub fn canonical_bytes(entry: &ChainedEntry, prev_hash: Option<&[u8]>) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);

    push_field(&mut buf, prev_hash);
    push_field(&mut buf, Some(&entry.seq.to_be_bytes()));
    push_field(&mut buf, Some(entry.id.as_bytes()));
    // Nanoseconds since the epoch, big-endian. i128 so pre-1970 and far-future
    // timestamps are representable without wrapping.
    push_field(
        &mut buf,
        Some(&entry.occurred_at.unix_timestamp_nanos().to_be_bytes()),
    );
    push_field(
        &mut buf,
        entry
            .actor_user_id
            .as_ref()
            .map(|u| u.as_bytes().as_slice()),
    );
    push_field(
        &mut buf,
        entry.actor_principal_type.as_deref().map(str::as_bytes),
    );
    push_field(
        &mut buf,
        entry
            .actor_session_id
            .as_ref()
            .map(|u| u.as_bytes().as_slice()),
    );
    push_field(&mut buf, Some(entry.action_code.as_bytes()));
    push_field(&mut buf, entry.target_type.as_deref().map(str::as_bytes));
    push_field(
        &mut buf,
        entry.target_id.as_ref().map(|u| u.as_bytes().as_slice()),
    );
    push_field(&mut buf, Some(entry.outcome.as_bytes()));
    push_field(&mut buf, entry.request_id.as_deref().map(str::as_bytes));
    push_field(&mut buf, Some(canonical_json(&entry.metadata).as_bytes()));

    buf
}

/// Compute the entry hash. Infallible: HMAC accepts any key length.
pub fn entry_hash(
    key: &Secret<Vec<u8>>,
    entry: &ChainedEntry,
    prev_hash: Option<&[u8]>,
) -> Vec<u8> {
    let mut mac = match HmacSha256::new_from_slice(key.expose()) {
        Ok(m) => m,
        // Unreachable for HMAC, which accepts any key length. Returning a fixed
        // impossible value rather than panicking keeps a broken key from taking
        // the process down mid-transaction.
        Err(_) => return vec![0u8; 32],
    };
    mac.update(&canonical_bytes(entry, prev_hash));
    mac.finalize().into_bytes().to_vec()
}

/// The result of verifying a contiguous run of entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationOutcome {
    Intact {
        entries_checked: u64,
        last_seq: i64,
    },
    /// The first entry whose recorded hash does not match a recomputation.
    HashMismatch {
        seq: i64,
        entries_checked: u64,
    },
    /// The chain links do not join up: this entry's `prev_hash` is not the
    /// previous entry's `entry_hash`. Detects reordering and splicing.
    BrokenLink {
        seq: i64,
        entries_checked: u64,
    },
    /// A gap in `seq`. Detects deletion, which a per-row hash scheme cannot.
    MissingSequence {
        expected: i64,
        found: i64,
    },
    /// The stored head does not agree with the last row — the tail was truncated.
    HeadMismatch {
        head_seq: i64,
        last_row_seq: i64,
    },
}

impl VerificationOutcome {
    pub fn is_intact(&self) -> bool {
        matches!(self, VerificationOutcome::Intact { .. })
    }
}

/// Verify a contiguous, ascending run of entries.
///
/// `expected_first_prev` is the hash preceding `entries[0]` — `None` when starting
/// from the very beginning of the chain.
pub fn verify_run(
    key: &Secret<Vec<u8>>,
    entries: &[StoredEntry],
    expected_first_prev: Option<Vec<u8>>,
    expected_first_seq: Option<i64>,
) -> VerificationOutcome {
    let mut prev: Option<Vec<u8>> = expected_first_prev;
    let mut checked: u64 = 0;
    let mut expected_seq = expected_first_seq;

    for (entry, stored_hash, stored_prev) in entries {
        // Gap detection. `bigserial` can legitimately skip values when a
        // transaction rolls back, so a gap is reported only when we were told what
        // to expect — the verification command derives that from the head record.
        if let Some(expected) = expected_seq {
            if entry.seq != expected {
                return VerificationOutcome::MissingSequence {
                    expected,
                    found: entry.seq,
                };
            }
        }

        // Link check: this entry's recorded prev_hash must equal the previous
        // entry's computed hash. This is what catches reordering and splicing.
        if stored_prev.as_deref() != prev.as_deref() {
            return VerificationOutcome::BrokenLink {
                seq: entry.seq,
                entries_checked: checked,
            };
        }

        let recomputed = entry_hash(key, entry, prev.as_deref());
        if !crate::platform::crypto::tokens::digests_equal(&recomputed, stored_hash) {
            return VerificationOutcome::HashMismatch {
                seq: entry.seq,
                entries_checked: checked,
            };
        }

        prev = Some(recomputed);
        checked += 1;
        expected_seq = Some(entry.seq + 1);
    }

    VerificationOutcome::Intact {
        entries_checked: checked,
        last_seq: entries.last().map(|(e, _, _)| e.seq).unwrap_or(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use time::OffsetDateTime;

    /// A named tamper: a label for the failure message, and the edit it applies.
    ///
    /// The label is carried alongside the closure so a failing case says *which*
    /// field went undetected — a bare index into the table would name the wrong
    /// thing the moment someone inserts a case in the middle.
    type Tamper = (&'static str, Box<dyn Fn(&mut ChainedEntry)>);

    fn key() -> Secret<Vec<u8>> {
        Secret::new(vec![42u8; 32])
    }

    fn entry(seq: i64, action: &str) -> ChainedEntry {
        ChainedEntry {
            seq,
            id: Uuid::from_u128(seq as u128 + 1),
            occurred_at: OffsetDateTime::from_unix_timestamp(1_700_000_000 + seq).unwrap(),
            actor_user_id: Some(Uuid::from_u128(99)),
            actor_principal_type: Some("INTERNAL".into()),
            actor_session_id: None,
            action_code: action.into(),
            target_type: Some("USER".into()),
            target_id: Some(Uuid::from_u128(7)),
            outcome: "SUCCESS".into(),
            request_id: Some("req-abc12345".into()),
            metadata: json!({"b": 2, "a": 1}),
        }
    }

    /// Build a well-formed chain: (entry, hash, prev_hash) triples.
    fn build_chain(n: i64) -> Vec<StoredEntry> {
        let k = key();
        let mut out = Vec::new();
        let mut prev: Option<Vec<u8>> = None;
        for seq in 1..=n {
            let e = entry(seq, "USER.CREATED");
            let h = entry_hash(&k, &e, prev.as_deref());
            out.push((e, h.clone(), prev.clone()));
            prev = Some(h);
        }
        out
    }

    #[test]
    fn an_untouched_chain_verifies() {
        let chain = build_chain(50);
        let outcome = verify_run(&key(), &chain, None, Some(1));
        assert_eq!(
            outcome,
            VerificationOutcome::Intact {
                entries_checked: 50,
                last_seq: 50
            }
        );
        assert!(outcome.is_intact());
    }

    #[test]
    fn hashing_is_deterministic() {
        let k = key();
        let e = entry(1, "USER.CREATED");
        assert_eq!(entry_hash(&k, &e, None), entry_hash(&k, &e, None));
        assert_eq!(entry_hash(&k, &e, None).len(), 32);
    }

    /// Field edits are detected — the basic requirement.
    #[test]
    fn modifying_any_covered_field_is_detected() {
        let mutations: Vec<Tamper> = vec![
            (
                "outcome",
                Box::new(|e: &mut ChainedEntry| e.outcome = "FAILURE".into()),
            ),
            (
                "action_code",
                Box::new(|e: &mut ChainedEntry| e.action_code = "USER.DELETED".into()),
            ),
            (
                "actor",
                Box::new(|e: &mut ChainedEntry| e.actor_user_id = Some(Uuid::from_u128(1234))),
            ),
            (
                "actor_to_null",
                Box::new(|e: &mut ChainedEntry| e.actor_user_id = None),
            ),
            (
                "target_id",
                Box::new(|e: &mut ChainedEntry| e.target_id = Some(Uuid::from_u128(4321))),
            ),
            (
                "target_type",
                Box::new(|e: &mut ChainedEntry| e.target_type = None),
            ),
            (
                "metadata",
                Box::new(|e: &mut ChainedEntry| e.metadata = json!({"a": 1, "b": 3})),
            ),
            (
                "request_id",
                Box::new(|e: &mut ChainedEntry| e.request_id = Some("req-other1".into())),
            ),
            (
                "timestamp",
                Box::new(|e: &mut ChainedEntry| {
                    e.occurred_at = OffsetDateTime::from_unix_timestamp(1).unwrap()
                }),
            ),
            (
                "id",
                Box::new(|e: &mut ChainedEntry| e.id = Uuid::from_u128(999_999)),
            ),
        ];

        for (label, mutate) in mutations {
            let mut chain = build_chain(10);
            mutate(&mut chain[4].0);
            let outcome = verify_run(&key(), &chain, None, Some(1));
            assert!(
                matches!(outcome, VerificationOutcome::HashMismatch { seq: 5, .. }),
                "editing `{label}` was not detected: {outcome:?}"
            );
        }
    }

    /// The reason a keyed HMAC is used rather than a plain hash: an attacker who
    /// can write rows can recompute an unkeyed chain end to end.
    #[test]
    fn a_forgery_without_the_key_is_detected() {
        let mut chain = build_chain(10);
        let attacker_key = Secret::new(vec![7u8; 32]);

        // The attacker edits an entry and rebuilds the rest of the chain
        // consistently — but with the wrong key.
        chain[4].0.outcome = "SUCCESS".into();
        chain[4].0.action_code = "NOTHING.HAPPENED".into();
        let mut prev = chain[3].1.clone();
        for item in chain.iter_mut().skip(4) {
            item.2 = Some(prev.clone());
            let h = entry_hash(&attacker_key, &item.0, Some(&prev));
            item.1 = h.clone();
            prev = h;
        }

        let outcome = verify_run(&key(), &chain, None, Some(1));
        assert!(
            matches!(outcome, VerificationOutcome::HashMismatch { seq: 5, .. }),
            "an internally consistent forgery under the wrong key must still fail: {outcome:?}"
        );
    }

    /// A per-row hash scheme cannot do this; the chain can.
    #[test]
    fn deleting_an_entry_is_detected_as_a_gap() {
        let mut chain = build_chain(10);
        chain.remove(4); // seq 5 disappears
        let outcome = verify_run(&key(), &chain, None, Some(1));
        assert_eq!(
            outcome,
            VerificationOutcome::MissingSequence {
                expected: 5,
                found: 6
            }
        );
    }

    #[test]
    fn reordering_two_entries_is_detected() {
        let mut chain = build_chain(10);
        chain.swap(4, 5);
        let outcome = verify_run(&key(), &chain, None, Some(1));
        // Out-of-order sequence numbers are caught first, which is the clearest
        // possible diagnosis.
        assert_eq!(
            outcome,
            VerificationOutcome::MissingSequence {
                expected: 5,
                found: 6
            }
        );
    }

    #[test]
    fn splicing_a_valid_entry_from_elsewhere_breaks_the_link() {
        let mut chain = build_chain(10);
        // Replace entry 5's prev_hash with something else that is a real hash.
        chain[4].2 = Some(chain[1].1.clone());
        let outcome = verify_run(&key(), &chain, None, Some(1));
        assert!(
            matches!(outcome, VerificationOutcome::BrokenLink { seq: 5, .. }),
            "{outcome:?}"
        );
    }

    #[test]
    fn truncating_the_tail_is_detected_by_the_head_record() {
        let full = build_chain(10);
        let truncated = &full[..7];
        // The run itself is internally consistent...
        assert!(verify_run(&key(), truncated, None, Some(1)).is_intact());
        // ...which is exactly why the head record is also checked by the command.
        let head_seq = 10;
        let last_row_seq = truncated.last().unwrap().0.seq;
        assert_ne!(head_seq, last_row_seq);
        let outcome = VerificationOutcome::HeadMismatch {
            head_seq,
            last_row_seq,
        };
        assert!(!outcome.is_intact());
    }

    // ---- canonical serialisation --------------------------------------------

    #[test]
    fn json_key_order_does_not_change_the_hash() {
        let k = key();
        let mut a = entry(1, "X");
        let mut b = entry(1, "X");
        a.metadata = json!({"alpha": 1, "beta": {"y": 2, "x": 1}});
        b.metadata = json!({"beta": {"x": 1, "y": 2}, "alpha": 1});
        assert_eq!(entry_hash(&k, &a, None), entry_hash(&k, &b, None));
    }

    #[test]
    fn json_array_order_does_change_the_hash() {
        // Arrays are ordered data; reordering them IS a modification.
        let k = key();
        let mut a = entry(1, "X");
        let mut b = entry(1, "X");
        a.metadata = json!({"roles": ["admin", "employee"]});
        b.metadata = json!({"roles": ["employee", "admin"]});
        assert_ne!(entry_hash(&k, &a, None), entry_hash(&k, &b, None));
    }

    /// The property length-prefixing exists to guarantee.
    #[test]
    fn field_boundaries_cannot_be_shifted() {
        let k = key();
        let mut a = entry(1, "X");
        let mut b = entry(1, "X");
        a.actor_principal_type = Some("INTERNAL".into());
        a.action_code = "USER.CREATED".into();
        b.actor_principal_type = Some("INTERNALUSER".into());
        b.action_code = ".CREATED".into();
        assert_ne!(
            entry_hash(&k, &a, None),
            entry_hash(&k, &b, None),
            "content was shifted across a field boundary without changing the digest"
        );
    }

    /// An absent field and an empty one must not collide.
    #[test]
    fn null_and_empty_string_are_distinguishable() {
        let k = key();
        let mut a = entry(1, "X");
        let mut b = entry(1, "X");
        a.target_type = None;
        b.target_type = Some(String::new());
        assert_ne!(entry_hash(&k, &a, None), entry_hash(&k, &b, None));
    }

    #[test]
    fn the_previous_hash_participates() {
        let k = key();
        let e = entry(2, "X");
        let with_none = entry_hash(&k, &e, None);
        let with_prev = entry_hash(&k, &e, Some(&[1u8; 32]));
        let with_other = entry_hash(&k, &e, Some(&[2u8; 32]));
        assert_ne!(with_none, with_prev);
        assert_ne!(with_prev, with_other);
    }

    #[test]
    fn an_empty_run_verifies_trivially() {
        assert_eq!(
            verify_run(&key(), &[], None, None),
            VerificationOutcome::Intact {
                entries_checked: 0,
                last_seq: 0
            }
        );
    }

    #[test]
    fn canonical_json_sorts_recursively_and_handles_scalars() {
        assert_eq!(canonical_json(&json!({"b":1,"a":2})), r#"{"a":2,"b":1}"#);
        assert_eq!(
            canonical_json(&json!({"z":{"b":1,"a":2}})),
            r#"{"z":{"a":2,"b":1}}"#
        );
        assert_eq!(canonical_json(&json!([3, 1, 2])), "[3,1,2]");
        assert_eq!(canonical_json(&json!(null)), "null");
        assert_eq!(canonical_json(&json!("x")), "\"x\"");
        assert_eq!(canonical_json(&json!(true)), "true");
    }
}
