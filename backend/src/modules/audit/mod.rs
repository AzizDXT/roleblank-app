//! Append-only audit log with a tamper-evident hash chain.
//!
//! Audit events are **business and security accountability records**, deliberately
//! separate from operational logs. Operational logs are rotated and discarded by
//! infrastructure; audit history is not. Someone with permission to clear logs has
//! no path to audit history — that separation is the point (ADR-006).

pub mod chain;
pub mod dto;
pub mod repo;
pub mod routes;
pub mod service;

use serde_json::{Map, Value};
use sqlx::{Postgres, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::modules::authorization::domain::PrincipalType;
use crate::platform::database;
use crate::platform::errors::AppError;
use crate::platform::observability::sanitize;
use crate::shared::secret::Secret;

/// Canonical action codes. `^[A-Z][A-Z0-9_]*(\.[A-Z][A-Z0-9_]*)*$` to match the
/// database CHECK. Centralised so a typo cannot create a second, near-identical
/// action that queries then miss.
pub mod action {
    pub const SYSTEM_BOOTSTRAPPED: &str = "SYSTEM.BOOTSTRAPPED";
    pub const SYSTEM_BOOTSTRAP_REJECTED: &str = "SYSTEM.BOOTSTRAP_REJECTED";

    pub const AUTH_LOGIN_SUCCEEDED: &str = "AUTH.LOGIN_SUCCEEDED";
    pub const AUTH_LOGIN_FAILED: &str = "AUTH.LOGIN_FAILED";
    pub const AUTH_LOGOUT: &str = "AUTH.LOGOUT";
    pub const AUTH_REFRESHED: &str = "AUTH.REFRESHED";
    pub const AUTH_REFRESH_REUSE_DETECTED: &str = "AUTH.REFRESH_REUSE_DETECTED";
    pub const AUTH_STEP_UP_COMPLETED: &str = "AUTH.STEP_UP_COMPLETED";

    pub const MFA_ENROLMENT_STARTED: &str = "MFA.ENROLMENT_STARTED";
    pub const MFA_ACTIVATED: &str = "MFA.ACTIVATED";
    pub const MFA_DISABLED: &str = "MFA.DISABLED";
    pub const MFA_VERIFICATION_FAILED: &str = "MFA.VERIFICATION_FAILED";
    pub const MFA_REPLAY_DETECTED: &str = "MFA.REPLAY_DETECTED";
    pub const MFA_RECOVERY_CODES_GENERATED: &str = "MFA.RECOVERY_CODES_GENERATED";
    pub const MFA_RECOVERY_CODE_CONSUMED: &str = "MFA.RECOVERY_CODE_CONSUMED";

    pub const PASSWORD_CHANGED: &str = "PASSWORD.CHANGED";
    pub const PASSWORD_RESET_REQUESTED: &str = "PASSWORD.RESET_REQUESTED";
    pub const PASSWORD_RESET_COMPLETED: &str = "PASSWORD.RESET_COMPLETED";

    pub const SESSION_REVOKED: &str = "SESSION.REVOKED";
    pub const SESSION_REVOKED_ALL: &str = "SESSION.REVOKED_ALL";

    pub const USER_CREATED: &str = "USER.CREATED";
    pub const USER_UPDATED: &str = "USER.UPDATED";
    pub const USER_SUSPENDED: &str = "USER.SUSPENDED";
    pub const USER_REACTIVATED: &str = "USER.REACTIVATED";
    pub const USER_ARCHIVED: &str = "USER.ARCHIVED";
    pub const USER_REGISTERED: &str = "USER.REGISTERED";

    pub const INVITATION_CREATED: &str = "INVITATION.CREATED";
    pub const INVITATION_ACCEPTED: &str = "INVITATION.ACCEPTED";
    pub const INVITATION_REVOKED: &str = "INVITATION.REVOKED";

    pub const ROLE_CREATED: &str = "ROLE.CREATED";
    pub const ROLE_UPDATED: &str = "ROLE.UPDATED";
    pub const ROLE_DELETED: &str = "ROLE.DELETED";
    pub const ROLE_ASSIGNED: &str = "ROLE.ASSIGNED";
    pub const ROLE_UNASSIGNED: &str = "ROLE.UNASSIGNED";
    pub const PERMISSION_OVERRIDE_CREATED: &str = "PERMISSION.OVERRIDE_CREATED";
    pub const PERMISSION_OVERRIDE_REMOVED: &str = "PERMISSION.OVERRIDE_REMOVED";

    pub const DEPARTMENT_CREATED: &str = "DEPARTMENT.CREATED";
    pub const DEPARTMENT_UPDATED: &str = "DEPARTMENT.UPDATED";
    pub const DEPARTMENT_ARCHIVED: &str = "DEPARTMENT.ARCHIVED";
    pub const DEPARTMENT_MEMBER_ADDED: &str = "DEPARTMENT.MEMBER_ADDED";
    pub const DEPARTMENT_MEMBER_REMOVED: &str = "DEPARTMENT.MEMBER_REMOVED";

    pub const CLIENT_CREATED: &str = "CLIENT.CREATED";
    pub const CLIENT_UPDATED: &str = "CLIENT.UPDATED";
    pub const CLIENT_ARCHIVED: &str = "CLIENT.ARCHIVED";
    pub const CLIENT_MEMBER_ADDED: &str = "CLIENT.MEMBER_ADDED";
    pub const CLIENT_MEMBER_ACTIVATED: &str = "CLIENT.MEMBER_ACTIVATED";
    pub const CLIENT_MEMBER_REMOVED: &str = "CLIENT.MEMBER_REMOVED";

    pub const PROJECT_CREATED: &str = "PROJECT.CREATED";
    pub const PROJECT_UPDATED: &str = "PROJECT.UPDATED";
    pub const PROJECT_ARCHIVED: &str = "PROJECT.ARCHIVED";
    pub const PROJECT_MEMBER_ADDED: &str = "PROJECT.MEMBER_ADDED";
    pub const PROJECT_MEMBER_REMOVED: &str = "PROJECT.MEMBER_REMOVED";
    /// Crossing the external trust boundary — one of the most important events here.
    pub const PROJECT_SHARED_WITH_CLIENT: &str = "PROJECT.SHARED_WITH_CLIENT";
    pub const PROJECT_UNSHARED_FROM_CLIENT: &str = "PROJECT.UNSHARED_FROM_CLIENT";

    pub const TASK_CREATED: &str = "TASK.CREATED";
    pub const TASK_UPDATED: &str = "TASK.UPDATED";
    /// Cancellation is a terminal state change, not an edit.
    ///
    /// It was previously recorded as `TASK.UPDATED` with the status in the
    /// metadata, because the tasks module correctly declined to extend a catalogue
    /// it does not own. The metadata did answer "who cancelled this, and when" —
    /// but only to a reader who already knew to look there. An auditor filtering
    /// `action_code = TASK.CANCELLED` got an empty page and the reasonable
    /// conclusion that nothing had been cancelled, which is exactly the failure
    /// `service::validate_action_code` argues against when it refuses to validate
    /// filters against a snapshot of this list.
    pub const TASK_CANCELLED: &str = "TASK.CANCELLED";
    pub const TASK_ASSIGNED: &str = "TASK.ASSIGNED";
    pub const TASK_UNASSIGNED: &str = "TASK.UNASSIGNED";
    pub const TASK_CLIENT_VISIBILITY_CHANGED: &str = "TASK.CLIENT_VISIBILITY_CHANGED";

    pub const SETTING_CHANGED: &str = "SETTING.CHANGED";
    pub const FEATURE_FLAG_CHANGED: &str = "FEATURE_FLAG.CHANGED";

    /// A denied attempt at something sensitive. Recording denials is what turns an
    /// audit log into an intrusion-detection input.
    pub const AUTHORIZATION_DENIED: &str = "AUTHORIZATION.DENIED";
    pub const ROOT_PROTECTION_TRIGGERED: &str = "ROOT.PROTECTION_TRIGGERED";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Success,
    Denied,
    Failure,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Success => "SUCCESS",
            Outcome::Denied => "DENIED",
            Outcome::Failure => "FAILURE",
        }
    }
}

/// Key fragments that must never appear in audit metadata.
///
/// Belt and braces on top of "only write what you meant to": a developer adding
/// `meta.insert("reset_token", ...)` gets a stripped value and a loud warning
/// rather than a permanent secret in an immutable table that has no delete path.
const FORBIDDEN_METADATA_KEYS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "credential",
    "authorization",
    "cookie",
    "session_token",
    "access_token",
    "refresh_token",
    "api_key",
    "private_key",
    "encryption_key",
    "totp",
    "otp",
    "recovery_code",
    "hash",
];

/// A closed, sanitised metadata builder.
///
/// Deliberately not `serde_json::Value` directly: the type system is what stops an
/// entire request body being dropped into an append-only table.
#[derive(Debug, Default, Clone)]
pub struct AuditMetadata(Map<String, Value>);

impl AuditMetadata {
    pub fn new() -> Self {
        Self(Map::new())
    }

    pub fn str(mut self, key: &str, value: impl AsRef<str>) -> Self {
        self.insert_checked(
            key,
            Value::String(sanitize::sanitize_bounded(value.as_ref(), 200)),
        );
        self
    }

    pub fn id(mut self, key: &str, value: Uuid) -> Self {
        self.insert_checked(key, Value::String(value.to_string()));
        self
    }

    pub fn opt_id(mut self, key: &str, value: Option<Uuid>) -> Self {
        match value {
            Some(v) => self.insert_checked(key, Value::String(v.to_string())),
            None => self.insert_checked(key, Value::Null),
        }
        self
    }

    pub fn bool(mut self, key: &str, value: bool) -> Self {
        self.insert_checked(key, Value::Bool(value));
        self
    }

    pub fn int(mut self, key: &str, value: i64) -> Self {
        self.insert_checked(key, Value::Number(value.into()));
        self
    }

    /// A list of short identifiers — role codes, permission codes, statuses.
    /// Bounded so a bulk operation cannot write an unbounded array.
    pub fn list(mut self, key: &str, values: impl IntoIterator<Item = String>) -> Self {
        let items: Vec<Value> = values
            .into_iter()
            .take(50)
            .map(|v| Value::String(sanitize::sanitize_bounded(&v, 100)))
            .collect();
        self.insert_checked(key, Value::Array(items));
        self
    }

    /// Record a field change without recording the values, for fields whose
    /// content is sensitive or simply too large to belong here.
    pub fn changed(mut self, field: &str) -> Self {
        let existing = self
            .0
            .entry("changed_fields")
            .or_insert_with(|| Value::Array(vec![]));
        if let Value::Array(items) = existing {
            if items.len() < 50 {
                items.push(Value::String(sanitize::sanitize_bounded(field, 100)));
            }
        }
        self
    }

    fn insert_checked(&mut self, key: &str, value: Value) {
        let lowered = key.to_lowercase();
        if FORBIDDEN_METADATA_KEYS.iter().any(|f| lowered.contains(f)) {
            tracing::error!(
                key = %sanitize::log_value(key),
                "refused to write a potentially secret-bearing key into audit metadata"
            );
            self.0.insert(
                format!("{}__redacted", sanitize::sanitize_bounded(key, 60)),
                Value::Bool(true),
            );
            return;
        }
        if self.0.len() >= 40 {
            return; // bound the document
        }
        self.0.insert(sanitize::sanitize_bounded(key, 60), value);
    }

    pub fn into_value(self) -> Value {
        Value::Object(self.0)
    }
}

/// Everything needed to write one audit event.
pub struct AuditEvent {
    pub actor_user_id: Option<Uuid>,
    pub actor_principal_type: Option<PrincipalType>,
    pub actor_session_id: Option<Uuid>,
    pub action_code: &'static str,
    pub target_type: Option<&'static str>,
    pub target_id: Option<Uuid>,
    pub outcome: Outcome,
    pub request_id: Option<String>,
    pub source_ip_hint: Option<String>,
    pub metadata: AuditMetadata,
}

impl AuditEvent {
    pub fn new(action_code: &'static str, outcome: Outcome) -> Self {
        Self {
            actor_user_id: None,
            actor_principal_type: None,
            actor_session_id: None,
            action_code,
            target_type: None,
            target_id: None,
            outcome,
            request_id: crate::platform::http::request_id::RequestId::current(),
            source_ip_hint: None,
            metadata: AuditMetadata::new(),
        }
    }

    pub fn actor(
        mut self,
        user_id: Uuid,
        principal_type: PrincipalType,
        session_id: Option<Uuid>,
    ) -> Self {
        self.actor_user_id = Some(user_id);
        self.actor_principal_type = Some(principal_type);
        self.actor_session_id = session_id;
        self
    }

    /// A system-initiated event with no human actor (the outbox worker, a
    /// scheduled sweep). Recorded as `SYSTEM` rather than as an absent actor so
    /// "who did this" always has an answer.
    pub fn system_actor(mut self) -> Self {
        self.actor_user_id = None;
        self.actor_principal_type = None;
        self
    }

    pub fn target(mut self, target_type: &'static str, target_id: Uuid) -> Self {
        self.target_type = Some(target_type);
        self.target_id = Some(target_id);
        self
    }

    pub fn source_ip(mut self, hint: Option<String>) -> Self {
        self.source_ip_hint = hint;
        self
    }

    pub fn meta(mut self, metadata: AuditMetadata) -> Self {
        self.metadata = metadata;
        self
    }
}

/// Append an event **inside the caller's transaction**.
///
/// Taking `&mut Transaction` rather than a pool is the whole design: the audit
/// record and the state change it describes commit or roll back together. There is
/// no code path that writes one without the other.
pub async fn append(
    tx: &mut Transaction<'_, Postgres>,
    chain_key: &Secret<Vec<u8>>,
    event: AuditEvent,
) -> Result<Uuid, AppError> {
    // Serialises chain appends. Held until this transaction commits.
    let (last_seq, last_hash) = database::lock_audit_chain(tx).await?;

    let id = Uuid::now_v7();
    // Truncated to microseconds BEFORE it is hashed.
    //
    // PostgreSQL `timestamptz` stores microseconds; `OffsetDateTime::now_utc()`
    // carries nanoseconds. Hashing the nanosecond value and storing the truncated
    // one makes every entry fail verification the moment it is read back — the
    // chain would report tampering on a database that had never been touched.
    // Hashing exactly what is stored is the whole requirement.
    let occurred_at = to_microsecond_precision(OffsetDateTime::now_utc());
    let next_seq = last_seq + 1;

    let entry = chain::ChainedEntry {
        chain_version: chain::CURRENT_CHAIN_VERSION,
        seq: next_seq,
        id,
        occurred_at,
        actor_user_id: event.actor_user_id,
        actor_principal_type: event
            .actor_principal_type
            .map(|p| p.as_str().to_string())
            .or_else(|| Some("SYSTEM".to_string())),
        actor_session_id: event.actor_session_id,
        action_code: event.action_code.to_string(),
        target_type: event.target_type.map(str::to_string),
        target_id: event.target_id,
        outcome: event.outcome.as_str().to_string(),
        request_id: event.request_id.clone(),
        source_ip_hint: event.source_ip_hint.clone(),
        metadata: event.metadata.clone().into_value(),
    };

    let entry_hash = chain::entry_hash(chain_key, &entry, last_hash.as_deref());

    // `seq` is supplied explicitly rather than left to the sequence default: the
    // hash covers `seq`, so the value that was hashed must be the value stored.
    // The advisory lock above guarantees no other writer can take it first.
    // `chain_version` is stored, not inferred. A verifier that assumed the current
    // layout would report every entry written under an earlier one as tampered, and
    // the marker is inside the digest from v2 onwards so it cannot be edited to
    // select a weaker layout — see `chain::canonical_bytes`.
    sqlx::query(
        "INSERT INTO audit_events (
             seq, id, occurred_at, actor_user_id, actor_principal_type, actor_session_id,
             action_code, target_type, target_id, outcome, request_id, source_ip_hint,
             metadata, prev_hash, entry_hash, chain_version
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)",
    )
    .bind(next_seq)
    .bind(id)
    .bind(occurred_at)
    .bind(entry.actor_user_id)
    .bind(&entry.actor_principal_type)
    .bind(entry.actor_session_id)
    .bind(&entry.action_code)
    .bind(&entry.target_type)
    .bind(entry.target_id)
    .bind(&entry.outcome)
    .bind(&entry.request_id)
    .bind(entry.source_ip_hint.as_deref())
    .bind(&entry.metadata)
    .bind(last_hash.as_deref())
    .bind(&entry_hash)
    .bind(entry.chain_version)
    .execute(&mut **tx)
    .await
    .map_err(AppError::from)?;

    // Keep the underlying sequence ahead of the value we inserted, so a future
    // insert that does rely on the default cannot collide.
    sqlx::query("SELECT setval('audit_events_seq_seq', $1, true)")
        .bind(next_seq)
        .execute(&mut **tx)
        .await
        .map_err(AppError::from)?;

    sqlx::query("UPDATE audit_chain_head SET last_seq = $1, last_hash = $2 WHERE id")
        .bind(next_seq)
        .bind(&entry_hash)
        .execute(&mut **tx)
        .await
        .map_err(AppError::from)?;

    Ok(id)
}

/// Round a timestamp down to the precision PostgreSQL actually stores.
///
/// `timestamptz` is microsecond-precision. Any sub-microsecond component is
/// silently discarded on write, so it must be discarded before hashing too — see
/// the call site in `append`.
fn to_microsecond_precision(t: OffsetDateTime) -> OffsetDateTime {
    let micros = t.unix_timestamp_nanos() / 1_000;
    OffsetDateTime::from_unix_timestamp_nanos(micros * 1_000).unwrap_or(t)
}

/// Convenience for the very common "audit a denial" case.
pub fn denial(action: &'static str, reason: &str) -> AuditEvent {
    AuditEvent::new(action, Outcome::Denied).meta(AuditMetadata::new().str("reason", reason))
}

#[cfg(test)]
mod tests {
    use super::*;
    // The `json!` macro is only used by these tests; importing it here rather than
    // at module scope keeps the production path's import list honest about what it
    // actually needs.
    use serde_json::json;

    fn value_of(m: AuditMetadata) -> Value {
        m.into_value()
    }

    #[test]
    fn ordinary_metadata_is_recorded() {
        let v = value_of(
            AuditMetadata::new()
                .str("role_code", "field_manager")
                .bool("was_dangerous", true)
                .int("count", 3)
                .list(
                    "permissions",
                    vec!["projects.read".into(), "tasks.read".into()],
                ),
        );
        assert_eq!(v["role_code"], json!("field_manager"));
        assert_eq!(v["was_dangerous"], json!(true));
        assert_eq!(v["count"], json!(3));
        assert_eq!(v["permissions"], json!(["projects.read", "tasks.read"]));
    }

    /// The property that matters most: no secret can enter an immutable table that
    /// has no delete path.
    #[test]
    fn secret_bearing_keys_are_refused() {
        for key in [
            "password",
            "new_password",
            "password_hash",
            "access_token",
            "refresh_token",
            "reset_token",
            "invitation_token",
            "totp_secret",
            "recovery_code",
            "encryption_key",
            "api_key",
            "Authorization",
            "Cookie",
            "session_token",
            "PASSWORD",
            "user_Password",
        ] {
            let v = value_of(AuditMetadata::new().str(key, "hunter2-actual-secret-value"));
            let serialised = serde_json::to_string(&v).unwrap();
            assert!(
                !serialised.contains("hunter2"),
                "key `{key}` allowed a secret into audit metadata: {serialised}"
            );
            assert!(
                serialised.contains("__redacted"),
                "key `{key}` was not marked redacted"
            );
        }
    }

    #[test]
    fn metadata_values_are_sanitised_and_bounded() {
        let v = value_of(AuditMetadata::new().str("note", "line one\r\nINFO forged line"));
        let s = v["note"].as_str().unwrap();
        assert!(!s.contains('\n'));
        assert!(!s.contains('\r'));

        let v = value_of(AuditMetadata::new().str("note", "x".repeat(10_000)));
        assert!(v["note"].as_str().unwrap().chars().count() <= 201);
    }

    #[test]
    fn the_document_and_its_arrays_are_bounded() {
        let mut m = AuditMetadata::new();
        for i in 0..200 {
            m = m.int(&format!("k{i}"), i);
        }
        let Value::Object(map) = value_of(m) else {
            panic!()
        };
        assert!(
            map.len() <= 40,
            "metadata document was not bounded: {}",
            map.len()
        );

        let v = value_of(AuditMetadata::new().list("ids", (0..500).map(|i| i.to_string())));
        assert!(v["ids"].as_array().unwrap().len() <= 50);
    }

    #[test]
    fn changed_fields_accumulate() {
        let v = value_of(
            AuditMetadata::new()
                .changed("name")
                .changed("status")
                .changed("name"),
        );
        assert_eq!(v["changed_fields"], json!(["name", "status", "name"]));
    }

    #[test]
    fn action_codes_match_the_database_constraint() {
        // `^[A-Z][A-Z0-9_]*(\.[A-Z][A-Z0-9_]*)*$`
        let codes = [
            action::SYSTEM_BOOTSTRAPPED,
            action::AUTH_LOGIN_SUCCEEDED,
            action::MFA_ACTIVATED,
            action::PASSWORD_RESET_COMPLETED,
            action::SESSION_REVOKED,
            action::USER_CREATED,
            action::INVITATION_ACCEPTED,
            action::ROLE_ASSIGNED,
            action::PERMISSION_OVERRIDE_CREATED,
            action::DEPARTMENT_MEMBER_ADDED,
            action::CLIENT_MEMBER_ACTIVATED,
            action::PROJECT_SHARED_WITH_CLIENT,
            action::TASK_CLIENT_VISIBILITY_CHANGED,
            action::SETTING_CHANGED,
            action::FEATURE_FLAG_CHANGED,
            action::AUTHORIZATION_DENIED,
            action::ROOT_PROTECTION_TRIGGERED,
            action::AUTH_REFRESH_REUSE_DETECTED,
        ];
        for code in codes {
            for segment in code.split('.') {
                assert!(!segment.is_empty(), "`{code}` has an empty segment");
                let first = segment.chars().next().unwrap();
                assert!(
                    first.is_ascii_uppercase(),
                    "`{code}` segment must start with A-Z"
                );
                assert!(
                    segment
                        .chars()
                        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'),
                    "`{code}` contains an illegal character"
                );
            }
        }
    }

    /// Regression: the audit chain hashes `occurred_at`, and PostgreSQL stores only
    /// microseconds. Hashing a nanosecond-precision value made every entry report
    /// as tampered the moment it was read back — caught by the golden scenario.
    #[test]
    fn timestamps_are_truncated_to_what_postgresql_stores() {
        let with_nanos = OffsetDateTime::from_unix_timestamp_nanos(1_700_000_000_123_456_789)
            .expect("valid timestamp");
        let truncated = to_microsecond_precision(with_nanos);
        assert_eq!(truncated.unix_timestamp_nanos(), 1_700_000_000_123_456_000);
        // Idempotent: truncating an already-truncated value changes nothing.
        assert_eq!(to_microsecond_precision(truncated), truncated);
        // A value with no sub-microsecond component is untouched.
        let exact = OffsetDateTime::from_unix_timestamp_nanos(1_700_000_000_000_000_000).unwrap();
        assert_eq!(to_microsecond_precision(exact), exact);
    }

    #[test]
    fn a_denial_event_carries_its_reason() {
        let e = denial(action::AUTHORIZATION_DENIED, "principal_envelope");
        assert_eq!(e.outcome, Outcome::Denied);
        assert_eq!(
            e.metadata.into_value()["reason"],
            json!("principal_envelope")
        );
    }
}
