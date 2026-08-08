//! Settings and feature-flag service: authorisation, validation, transaction
//! boundary and audit.
//!
//! # A feature flag is not an access control
//!
//! **Turning a flag off must never be the only thing preventing access.** Every
//! route protected by a flag is *independently* authorised, and the authorisation
//! decision does not consult the flag. A flag answers "is this product surface
//! built and switched on?"; a permission answers "may this person do this?". They
//! are different questions with different failure modes:
//!
//!   * a flag lives in a mutable row that `settings.features.write` can flip, and
//!     `settings.features.write` is deliberately *not* a dangerous permission — it
//!     is meant to be delegable to whoever runs the product;
//!   * a flag is read once per request at best and is trivially cacheable, so a
//!     stale `true` is a plausible state;
//!   * a flag has no scope, so "off for clients, on for staff" cannot be expressed
//!     by one.
//!
//! If a flag were load-bearing for access, flipping one row would grant authority
//! that no role review would ever show. So: `client_portal = false` hides the
//! portal; it is `client.portal.*` and the CLIENT principal envelope that stop an
//! external user reading a project.

use serde_json::Value;

use crate::app::AppState;
use crate::modules::audit::{action, AuditEvent, AuditMetadata, Outcome};
use crate::modules::authentication::principal::Principal;
use crate::modules::authorization::domain::{ActorContext, Target};
use crate::modules::authorization::evaluator;
use crate::platform::errors::{AppError, AppResult};

use super::dto::{
    FeatureFlagResponse, SettingResponse, UpdateFeatureFlagRequest, UpdateSettingRequest,
};
use super::repo;

pub const PERM_READ: &str = "settings.read";
pub const PERM_FEATURES_WRITE: &str = "settings.features.write";
/// Dangerous (see `authorization::catalog`): holding it requires MFA enrolment,
/// and exercising it requires a recent step-up.
pub const PERM_SECURITY_WRITE: &str = "settings.security.write";

/// Longest accepted setting or flag key. Matches the practical limit of the
/// `^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$` CHECK in `0006_platform.sql`.
const MAX_KEY_LEN: usize = 100;
/// Longest accepted STRING setting value. Bounded because the value is echoed into
/// audit metadata and into every subsequent listing.
const MAX_STRING_VALUE_LEN: usize = 1000;
/// INTEGER settings are bounded well inside `i32` so that a value read by a
/// consumer expecting a count cannot overflow it.
const MIN_INTEGER_VALUE: i64 = -1_000_000_000;
const MAX_INTEGER_VALUE: i64 = 1_000_000_000;

/// The registration mode is the switch that decides whether strangers may create
/// accounts at all, so its accepted values are a closed set held in code — not
/// whatever string happens to be in the row.
pub const REGISTRATION_MODE_KEY: &str = "registration.mode";
pub const REGISTRATION_MODES: &[&str] = &["DISABLED", "INVITE_ONLY", "CLIENT_SELF_REGISTRATION"];

/// Allowlists for `ENUM`-typed settings, keyed by setting key.
///
/// A key with no entry is **not editable through the API**. That is fail-closed on
/// purpose: an ENUM whose allowlist nobody registered would otherwise accept any
/// string, and an unrecognised value in a security setting is read by its consumer
/// as "not the safe mode" — or, worse, as a mode it does not handle.
fn enum_values_for(key: &str) -> Option<&'static [&'static str]> {
    match key {
        REGISTRATION_MODE_KEY => Some(REGISTRATION_MODES),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Validation — pure, so it is testable without a database
// ---------------------------------------------------------------------------

/// Validate a key taken from the URL path before it reaches any query.
///
/// The key is a bind parameter regardless, so this is not the injection defence —
/// it is the bound. An unvalidated path segment becomes an indexed lookup on a
/// 10 MB string, and the error it produces would echo the segment back.
pub fn validate_key(field: &'static str, raw: &str) -> AppResult<String> {
    let key = raw.trim();
    if key.is_empty() {
        return Err(AppError::field(field, "REQUIRED", "A key is required."));
    }
    if key.len() > MAX_KEY_LEN {
        return Err(AppError::field(
            field,
            "TOO_LONG",
            format!("A key must be at most {MAX_KEY_LEN} characters."),
        ));
    }
    let segments: Vec<&str> = key.split('.').collect();
    let well_formed = segments.iter().all(|segment| {
        let mut chars = segment.chars();
        matches!(chars.next(), Some(c) if c.is_ascii_lowercase())
            && segment
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    });
    if !well_formed {
        // The rejected value is not echoed: it is attacker-controlled and this
        // message reaches logs and, for a client, a rendered error.
        return Err(AppError::field(
            field,
            "INVALID_FORMAT",
            "A key is dot-separated lowercase segments, e.g. `registration.mode`.",
        ));
    }
    Ok(key.to_string())
}

/// Check a submitted value against the setting's declared `value_type`, returning
/// the normalised value that will be stored.
///
/// The type is read from the row, never from the request: a caller that could
/// choose the type could store a string where a consumer expects a boolean and
/// make that consumer's `as_bool().unwrap_or(false)` mean something new.
pub fn validate_value(key: &str, value_type: &str, value: &Value) -> AppResult<Value> {
    match value_type {
        "STRING" => {
            let text = value.as_str().ok_or_else(|| {
                AppError::field("value", "INVALID_TYPE", "This setting takes a JSON string.")
            })?;
            if text.chars().count() > MAX_STRING_VALUE_LEN {
                return Err(AppError::field(
                    "value",
                    "TOO_LONG",
                    format!("Must be at most {MAX_STRING_VALUE_LEN} characters."),
                ));
            }
            // Control characters in a stored setting reach logs, audit metadata and
            // any file this value is later rendered into.
            if text.chars().any(char::is_control) {
                return Err(AppError::field(
                    "value",
                    "INVALID_FORMAT",
                    "The value contains control characters.",
                ));
            }
            Ok(Value::String(text.to_string()))
        }

        "BOOLEAN" => {
            let flag = value.as_bool().ok_or_else(|| {
                // `"true"` and `1` are refused rather than coerced: a coercion here
                // is how a typo becomes a silently disabled security control.
                AppError::field(
                    "value",
                    "INVALID_TYPE",
                    "This setting takes a JSON boolean (`true` or `false`), not a string or a number.",
                )
            })?;
            Ok(Value::Bool(flag))
        }

        "INTEGER" => {
            let number = value.as_i64().ok_or_else(|| {
                AppError::field(
                    "value",
                    "INVALID_TYPE",
                    "This setting takes a whole JSON number.",
                )
            })?;
            if !(MIN_INTEGER_VALUE..=MAX_INTEGER_VALUE).contains(&number) {
                return Err(AppError::field(
                    "value",
                    "OUT_OF_RANGE",
                    format!("Must be between {MIN_INTEGER_VALUE} and {MAX_INTEGER_VALUE}."),
                ));
            }
            Ok(Value::Number(number.into()))
        }

        "ENUM" => {
            let text = value.as_str().ok_or_else(|| {
                AppError::field("value", "INVALID_TYPE", "This setting takes a JSON string.")
            })?;
            let allowed = enum_values_for(key).ok_or_else(|| {
                AppError::field(
                    "value",
                    "NOT_EDITABLE",
                    "This setting has no registered set of accepted values and cannot be \
                     changed through the API.",
                )
            })?;
            if !allowed.contains(&text) {
                // The allowed set IS public API surface, so it is named. The
                // rejected value is not echoed back.
                return Err(AppError::field(
                    "value",
                    "INVALID_VALUE",
                    format!("Must be one of: {}", allowed.join(", ")),
                ));
            }
            Ok(Value::String(text.to_string()))
        }

        // A `value_type` the code does not know means the database moved ahead of
        // this binary. Refusing the write is the only safe answer.
        _ => Err(AppError::field(
            "value",
            "NOT_EDITABLE",
            "This setting has a type this build does not know how to validate.",
        )),
    }
}

/// A compact, bounded rendering of a value for audit metadata.
fn render(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "<unrenderable>".to_string())
}

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

/// May this caller see security-sensitive configuration?
///
/// `settings.security.write` is used as the read gate for sensitive rows as well
/// as the write gate. There is no separate `settings.security.read` in the
/// catalogue, and inventing one here would be an ungoverned permission — a grant
/// nothing else in the system governs. Using the write permission is the
/// conservative direction: strictly fewer people see the sensitive rows than would
/// under a new, weaker read code.
///
/// Written against `ActorContext` rather than taking `AppState`. `AppState::decide`
/// is exactly this evaluator call (see `app.rs`), and expressing the rule as a pure
/// function is what lets the filter be tested without a database or a live session
/// — which matters, because this function is the only thing standing between an
/// ordinary settings reader and `registration.mode`.
fn actor_may_see_sensitive(actor: &ActorContext) -> bool {
    evaluator::evaluate(actor, PERM_SECURITY_WRITE, &Target::Collection).is_allowed()
}

/// `GET /api/v1/settings`.
///
/// `Target::Collection` is covered only by a `GLOBAL` scope (see the evaluator):
/// system configuration is a global singleton, so a department- or assigned-scoped
/// grant must not reach it.
pub async fn list_settings(
    state: &AppState,
    principal: &Principal,
) -> AppResult<Vec<SettingResponse>> {
    state.require(principal, PERM_READ, &Target::Collection)?;

    // Security-sensitive rows are excluded by the QUERY, not after it. A caller
    // without `settings.security.write` never has `registration.mode` in this
    // process's memory, let alone in the response.
    let include_sensitive = actor_may_see_sensitive(&principal.actor);
    let rows = repo::list_settings(&state.db, include_sensitive).await?;
    Ok(rows.into_iter().map(SettingResponse::from_row).collect())
}

/// `GET /api/v1/feature-flags`. Same sensitivity split as settings.
pub async fn list_feature_flags(
    state: &AppState,
    principal: &Principal,
) -> AppResult<Vec<FeatureFlagResponse>> {
    state.require(principal, PERM_READ, &Target::Collection)?;

    let include_sensitive = actor_may_see_sensitive(&principal.actor);
    let rows = repo::list_feature_flags(&state.db, include_sensitive).await?;
    Ok(rows
        .into_iter()
        .map(FeatureFlagResponse::from_row)
        .collect())
}

// ---------------------------------------------------------------------------
// Writes
// ---------------------------------------------------------------------------

/// A coarse gate taken *before* the row is loaded.
///
/// Its only job is to stop a principal with no settings-write authority at all
/// from telling an existing key from a missing one through the 404. The real,
/// specific decision is taken below against the loaded row's
/// `is_security_sensitive`, which is the value that actually selects the
/// permission.
fn require_some_write_authority(state: &AppState, principal: &Principal) -> AppResult<()> {
    if state
        .decide(principal, PERM_SECURITY_WRITE, &Target::Collection)
        .is_allowed()
    {
        return Ok(());
    }
    state.require(principal, PERM_FEATURES_WRITE, &Target::Collection)
}

/// Build the audit event for a configuration change.
///
/// **Security-sensitive settings record the key only — never the old or the new
/// value.** `audit_events` is append-only with no delete path anywhere in the
/// system (ADR-006), so a value written here is written permanently. The values of
/// security-sensitive settings are exactly the ones an attacker would most like a
/// permanent, widely-readable copy of, and `audit.read` is a broader grant than
/// `settings.security.write`. "The key changed, and who changed it" is what
/// accountability actually needs.
fn change_metadata(
    key: &str,
    key_field: &'static str,
    is_security_sensitive: bool,
    before: &Value,
    after: &Value,
) -> AuditMetadata {
    let meta = AuditMetadata::new()
        .str(key_field, key)
        .bool("security_sensitive", is_security_sensitive);
    if is_security_sensitive {
        meta.changed("value").bool("values_recorded", false)
    } else {
        meta.str("old_value", render(before))
            .str("new_value", render(after))
    }
}

fn actor_of(event: AuditEvent, principal: &Principal) -> AuditEvent {
    event.actor(
        principal.user_id(),
        principal.session.principal_type,
        Some(principal.session.session_id),
    )
}

/// `PUT /api/v1/settings/{key}`.
pub async fn update_setting(
    state: &AppState,
    principal: &Principal,
    raw_key: &str,
    request: UpdateSettingRequest,
) -> AppResult<SettingResponse> {
    let key = validate_key("key", raw_key)?;
    require_some_write_authority(state, principal)?;

    // Authorise, validate, write and audit inside one transaction, with the row
    // locked. Deciding before opening the transaction would leave a window in
    // which `is_security_sensitive` changes under the decision (TH-43).
    let mut tx = state.begin().await?;

    let row = repo::find_setting_for_update(&mut tx, &key)
        .await?
        .ok_or(AppError::NotFound)?;

    if row.is_security_sensitive {
        if let Err(denied) = state.require(principal, PERM_SECURITY_WRITE, &Target::Collection) {
            // A refused attempt on a security-sensitive setting is exactly the
            // signal an intrusion-detection reader is looking for, so it is
            // recorded rather than merely counted.
            state
                .audit(
                    &mut tx,
                    actor_of(
                        AuditEvent::new(action::SETTING_CHANGED, Outcome::Denied),
                        principal,
                    )
                    .meta(
                        AuditMetadata::new()
                            .str("setting_key", &key)
                            .str("reason", "authorization_denied"),
                    ),
                )
                .await?;
            tx.commit().await?;
            return Err(denied);
        }
        // `settings.security.write` is dangerous, so this always demands a recent
        // second factor. Routed through `require_step_up_for` rather than
        // `require_step_up` so the catalogue stays the single source of truth for
        // which permissions are dangerous.
        state.require_step_up_for(principal, PERM_SECURITY_WRITE)?;
    } else {
        state.require(principal, PERM_FEATURES_WRITE, &Target::Collection)?;
    }

    if row.version != request.version {
        return Err(AppError::VersionConflict {
            expected: request.version,
            actual: row.version,
        });
    }

    let new_value = validate_value(&key, &row.value_type, &request.value)?;

    let affected = repo::update_setting(
        &mut tx,
        &key,
        &new_value,
        request.version,
        principal.user_id(),
    )
    .await?;
    if affected == 0 {
        // Unreachable while the row lock is held, but never a silent overwrite.
        return Err(AppError::VersionConflict {
            expected: request.version,
            actual: row.version,
        });
    }

    state
        .audit(
            &mut tx,
            actor_of(
                AuditEvent::new(action::SETTING_CHANGED, Outcome::Success),
                principal,
            )
            .meta(change_metadata(
                &key,
                "setting_key",
                row.is_security_sensitive,
                &row.value,
                &new_value,
            )),
        )
        .await?;

    let updated = repo::get_setting(&mut tx, &key).await?.ok_or_else(|| {
        AppError::internal("a setting disappeared inside its own update transaction")
    })?;

    tx.commit().await?;
    Ok(SettingResponse::from_row(updated))
}

/// `PUT /api/v1/feature-flags/{key}`.
///
/// Same permission split as settings — and see the module header: switching a flag
/// changes what is *offered*, never who is *authorised*.
pub async fn update_feature_flag(
    state: &AppState,
    principal: &Principal,
    raw_key: &str,
    request: UpdateFeatureFlagRequest,
) -> AppResult<FeatureFlagResponse> {
    let key = validate_key("key", raw_key)?;
    require_some_write_authority(state, principal)?;

    let mut tx = state.begin().await?;

    let row = repo::find_flag_for_update(&mut tx, &key)
        .await?
        .ok_or(AppError::NotFound)?;

    if row.is_security_sensitive {
        if let Err(denied) = state.require(principal, PERM_SECURITY_WRITE, &Target::Collection) {
            state
                .audit(
                    &mut tx,
                    actor_of(
                        AuditEvent::new(action::FEATURE_FLAG_CHANGED, Outcome::Denied),
                        principal,
                    )
                    .meta(
                        AuditMetadata::new()
                            .str("flag_key", &key)
                            .str("reason", "authorization_denied"),
                    ),
                )
                .await?;
            tx.commit().await?;
            return Err(denied);
        }
        state.require_step_up_for(principal, PERM_SECURITY_WRITE)?;
    } else {
        state.require(principal, PERM_FEATURES_WRITE, &Target::Collection)?;
    }

    if row.version != request.version {
        return Err(AppError::VersionConflict {
            expected: request.version,
            actual: row.version,
        });
    }

    let affected = repo::update_flag(
        &mut tx,
        &key,
        request.enabled,
        request.version,
        principal.user_id(),
    )
    .await?;
    if affected == 0 {
        return Err(AppError::VersionConflict {
            expected: request.version,
            actual: row.version,
        });
    }

    state
        .audit(
            &mut tx,
            actor_of(
                AuditEvent::new(action::FEATURE_FLAG_CHANGED, Outcome::Success),
                principal,
            )
            .meta(change_metadata(
                &key,
                "flag_key",
                row.is_security_sensitive,
                &Value::Bool(row.enabled),
                &Value::Bool(request.enabled),
            )),
        )
        .await?;

    let updated = repo::get_flag(&mut tx, &key).await?.ok_or_else(|| {
        AppError::internal("a feature flag disappeared inside its own update transaction")
    })?;

    tx.commit().await?;
    Ok(FeatureFlagResponse::from_row(updated))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use uuid::Uuid;

    fn code_of(err: &AppError) -> String {
        match err {
            AppError::Validation { errors } => errors[0].code.to_string(),
            other => panic!("expected a validation error, got {other}"),
        }
    }

    fn message_of(err: &AppError) -> String {
        match err {
            AppError::Validation { errors } => errors[0].message.to_string(),
            other => panic!("expected a validation error, got {other}"),
        }
    }

    // ---- keys ------------------------------------------------------------

    #[test]
    fn keys_match_the_database_constraint() {
        assert_eq!(
            validate_key("key", " registration.mode ").expect("valid"),
            "registration.mode"
        );
        assert_eq!(validate_key("key", "chat").expect("valid"), "chat");
        assert_eq!(
            validate_key("key", "ai.assistant").expect("valid"),
            "ai.assistant"
        );
    }

    #[test]
    fn malformed_and_hostile_keys_are_refused_without_echoing_them() {
        for bad in [
            "",
            "   ",
            "Registration.Mode",
            "registration..mode",
            ".mode",
            "mode.",
            "1registration",
            "registration mode",
            "registration-mode",
            "registration.mode'; DROP TABLE system_settings--",
            "registration.mode\u{0}",
            "../../etc/passwd",
            "%2e%2e",
        ] {
            let err = validate_key("key", bad).expect_err("must reject");
            let rendered = message_of(&err);
            assert!(
                !rendered.contains("DROP"),
                "the rejected key was echoed back"
            );
            assert!(
                !rendered.contains("passwd"),
                "the rejected key was echoed back"
            );
        }
        assert!(validate_key("key", &"a".repeat(MAX_KEY_LEN + 1)).is_err());
        assert!(validate_key("key", &"a".repeat(1_000_000)).is_err());
    }

    // ---- value types -----------------------------------------------------

    #[test]
    fn string_settings_accept_only_strings() {
        assert_eq!(
            validate_value("some.text", "STRING", &json!("hello")).expect("valid"),
            json!("hello")
        );
        for bad in [json!(1), json!(true), json!(null), json!([]), json!({})] {
            let err = validate_value("some.text", "STRING", &bad).expect_err("must reject");
            assert_eq!(code_of(&err), "INVALID_TYPE");
        }
        assert!(validate_value("some.text", "STRING", &json!("a\nb")).is_err());
        assert!(validate_value(
            "some.text",
            "STRING",
            &json!("x".repeat(MAX_STRING_VALUE_LEN + 1))
        )
        .is_err());
    }

    /// A boolean setting that accepted `"false"` would be a security control
    /// disabled by a typo — `"false"` is a truthy string in every client language
    /// that would then read it.
    #[test]
    fn boolean_settings_are_not_coerced_from_strings_or_numbers() {
        assert_eq!(
            validate_value("f", "BOOLEAN", &json!(true)).expect("valid"),
            json!(true)
        );
        assert_eq!(
            validate_value("f", "BOOLEAN", &json!(false)).expect("valid"),
            json!(false)
        );
        for bad in [
            json!("true"),
            json!("false"),
            json!(1),
            json!(0),
            json!(null),
        ] {
            assert_eq!(
                code_of(&validate_value("f", "BOOLEAN", &bad).expect_err("must reject")),
                "INVALID_TYPE"
            );
        }
    }

    #[test]
    fn integer_settings_reject_floats_strings_and_absurd_magnitudes() {
        assert_eq!(
            validate_value("n", "INTEGER", &json!(72)).expect("valid"),
            json!(72)
        );
        assert_eq!(
            validate_value("n", "INTEGER", &json!(-5)).expect("valid"),
            json!(-5)
        );
        for bad in [json!(1.5), json!("72"), json!(true), json!(null)] {
            assert_eq!(
                code_of(&validate_value("n", "INTEGER", &bad).expect_err("must reject")),
                "INVALID_TYPE"
            );
        }
        for bad in [
            json!(MAX_INTEGER_VALUE + 1),
            json!(MIN_INTEGER_VALUE - 1),
            json!(i64::MAX),
        ] {
            assert_eq!(
                code_of(&validate_value("n", "INTEGER", &bad).expect_err("must reject")),
                "OUT_OF_RANGE"
            );
        }
    }

    /// The registration mode decides whether strangers can create accounts. Its
    /// accepted set is closed and lives in code.
    #[test]
    fn registration_mode_accepts_exactly_three_values() {
        for good in ["DISABLED", "INVITE_ONLY", "CLIENT_SELF_REGISTRATION"] {
            assert_eq!(
                validate_value(REGISTRATION_MODE_KEY, "ENUM", &json!(good)).expect("valid"),
                json!(good)
            );
        }
    }

    #[test]
    fn registration_mode_refuses_everything_else() {
        for bad in [
            "OPEN",
            "invite_only",
            "Invite_Only",
            "",
            " INVITE_ONLY",
            "INVITE_ONLY ",
            "ANY",
            "PUBLIC",
            "CLIENT_SELF_REGISTRATION; DROP TABLE users--",
            "INVITE_ONLY' OR '1'='1",
            "DISABLED\u{0}",
        ] {
            assert!(
                validate_value(REGISTRATION_MODE_KEY, "ENUM", &json!(bad)).is_err(),
                "`{bad}` must be rejected"
            );
        }
        // A non-string is refused before the allowlist is consulted.
        for bad in [json!(0), json!(true), json!(null), json!(["INVITE_ONLY"])] {
            assert!(validate_value(REGISTRATION_MODE_KEY, "ENUM", &bad).is_err());
        }
    }

    #[test]
    fn registration_mode_rejections_name_the_allowed_set_and_not_the_input() {
        for bad in [
            "OPEN",
            "invite_only",
            "CLIENT_SELF_REGISTRATION; DROP TABLE users--",
        ] {
            let err = validate_value(REGISTRATION_MODE_KEY, "ENUM", &json!(bad))
                .expect_err("must reject");
            assert_eq!(code_of(&err), "INVALID_VALUE");
            let message = message_of(&err);
            assert!(message.contains("DISABLED"), "{message}");
            assert!(message.contains("INVITE_ONLY"), "{message}");
            assert!(message.contains("CLIENT_SELF_REGISTRATION"), "{message}");
            assert!(
                !message.contains("DROP"),
                "the rejected value was echoed back"
            );
        }
        // Whitespace is NOT trimmed into a match: the stored value is compared
        // byte-for-byte by its consumer.
        assert!(validate_value(REGISTRATION_MODE_KEY, "ENUM", &json!(" INVITE_ONLY")).is_err());
    }

    /// Fail closed: an ENUM setting nobody registered an allowlist for cannot be
    /// written at all, rather than accepting any string.
    #[test]
    fn an_unregistered_enum_setting_is_not_editable() {
        let err = validate_value("some.future.enum", "ENUM", &json!("ANYTHING"))
            .expect_err("must reject");
        assert_eq!(code_of(&err), "NOT_EDITABLE");
        assert!(enum_values_for("some.future.enum").is_none());
    }

    #[test]
    fn an_unknown_value_type_is_refused_rather_than_guessed() {
        for value_type in ["JSON", "OBJECT", "string", "", "ENUM  "] {
            let err =
                validate_value("k", value_type, &json!("x")).expect_err("must reject {value_type}");
            assert_eq!(code_of(&err), "NOT_EDITABLE");
        }
    }

    // ---- audit metadata --------------------------------------------------

    /// The property ADR-006 cares about: an append-only table with no delete path
    /// must never receive the value of a security-sensitive setting.
    #[test]
    fn sensitive_changes_record_the_key_but_never_the_values() {
        let meta = change_metadata(
            REGISTRATION_MODE_KEY,
            "setting_key",
            true,
            &json!("INVITE_ONLY"),
            &json!("CLIENT_SELF_REGISTRATION"),
        )
        .into_value();
        let rendered = serde_json::to_string(&meta).expect("serialise");

        assert!(
            rendered.contains("registration.mode"),
            "the key must be recorded"
        );
        assert!(
            !rendered.contains("INVITE_ONLY"),
            "an old value leaked: {rendered}"
        );
        assert!(
            !rendered.contains("CLIENT_SELF_REGISTRATION"),
            "a new value leaked: {rendered}"
        );
        assert_eq!(meta["changed_fields"], json!(["value"]));
        assert_eq!(meta["values_recorded"], json!(false));
    }

    #[test]
    fn ordinary_changes_record_both_values_so_the_history_is_useful() {
        let meta = change_metadata(
            "invitations.ttl_hours",
            "setting_key",
            false,
            &json!(72),
            &json!(24),
        )
        .into_value();
        assert_eq!(meta["setting_key"], json!("invitations.ttl_hours"));
        assert_eq!(meta["old_value"], json!("72"));
        assert_eq!(meta["new_value"], json!("24"));
        assert_eq!(meta["security_sensitive"], json!(false));
    }

    #[test]
    fn a_sensitive_feature_flag_change_records_neither_boolean() {
        let meta = change_metadata(
            "ai.assistant",
            "flag_key",
            true,
            &json!(false),
            &json!(true),
        )
        .into_value();
        let object = meta.as_object().expect("object");
        assert!(!object.contains_key("old_enabled"));
        assert!(!object.contains_key("new_enabled"));
        assert!(!object.contains_key("old_value"));
        assert!(!object.contains_key("new_value"));
        assert_eq!(meta["flag_key"], json!("ai.assistant"));
    }

    #[test]
    fn rendering_a_value_never_panics() {
        for value in [
            json!(null),
            json!({"a":[1,2,{"b":true}]}),
            json!("x".repeat(10_000)),
        ] {
            assert!(!render(&value).is_empty());
        }
    }

    // ---- the security-sensitive filter -----------------------------------

    use crate::modules::authorization::domain::{Grant, PrincipalType, Scope, ScopeType};

    fn actor_holding(codes: &[(&str, ScopeType)]) -> ActorContext {
        let mut actor = ActorContext::empty(Uuid::from_u128(1), PrincipalType::Internal);
        actor.allows = codes
            .iter()
            .map(|(code, scope)| Grant {
                permission_code: (*code).to_string(),
                scope: Scope::simple(*scope),
            })
            .collect();
        actor
    }

    /// The test the whole module hinges on: a caller who may read settings but who
    /// does not hold `settings.security.write` must not receive
    /// `is_security_sensitive` rows. `false` here becomes the bound `$1` in the
    /// listing query, so the rows are never even loaded.
    #[test]
    fn an_ordinary_settings_reader_does_not_see_sensitive_rows() {
        let reader = actor_holding(&[(PERM_READ, ScopeType::Global)]);
        assert!(!actor_may_see_sensitive(&reader));

        // Nor does holding the ordinary write permission widen the read.
        let writer = actor_holding(&[
            (PERM_READ, ScopeType::Global),
            (PERM_FEATURES_WRITE, ScopeType::Global),
        ]);
        assert!(!actor_may_see_sensitive(&writer));
    }

    #[test]
    fn a_security_writer_sees_sensitive_rows() {
        let security = actor_holding(&[
            (PERM_READ, ScopeType::Global),
            (PERM_SECURITY_WRITE, ScopeType::Global),
        ]);
        assert!(actor_may_see_sensitive(&security));
    }

    /// Configuration is a global singleton, so it is a `Target::Collection` and only
    /// a `GLOBAL` grant reaches it. A department- or self-scoped
    /// `settings.security.write` — however it came to exist — must not unlock the
    /// sensitive rows.
    #[test]
    fn a_narrowly_scoped_security_grant_does_not_unlock_sensitive_rows() {
        for scope in [ScopeType::Department, ScopeType::Assigned, ScopeType::Own] {
            let actor = actor_holding(&[(PERM_SECURITY_WRITE, scope)]);
            assert!(
                !actor_may_see_sensitive(&actor),
                "a {scope} -scoped grant reached global configuration"
            );
        }
    }

    /// An explicit DENY override beats the allow, and the filter must honour it —
    /// otherwise "revoke this person's access to security settings" would remove
    /// their ability to write but not their ability to read.
    #[test]
    fn an_explicit_deny_removes_sensitive_visibility() {
        let mut actor = actor_holding(&[(PERM_SECURITY_WRITE, ScopeType::Global)]);
        actor.denies = vec![Grant {
            permission_code: PERM_SECURITY_WRITE.to_string(),
            scope: Scope::global(),
        }];
        assert!(!actor_may_see_sensitive(&actor));
    }

    /// An external principal can never reach settings at all: the catalogue caps
    /// every `settings.*` code at INTERNAL, so the envelope denies before any grant
    /// is consulted.
    #[test]
    fn an_external_principal_never_sees_sensitive_configuration() {
        let mut actor = actor_holding(&[(PERM_SECURITY_WRITE, ScopeType::Global)]);
        actor.principal_type = PrincipalType::Client;
        assert!(!actor_may_see_sensitive(&actor));
    }

    // ---- the permissions this module uses --------------------------------

    #[test]
    fn the_permissions_used_here_exist_and_have_the_expected_danger_level() {
        use crate::modules::authorization::catalog;
        for code in [PERM_READ, PERM_FEATURES_WRITE, PERM_SECURITY_WRITE] {
            assert!(
                catalog::exists(code),
                "`{code}` is not in the permission catalogue"
            );
        }
        // If this ever flips, a security-sensitive setting could be written without
        // a recent second factor.
        assert!(catalog::is_dangerous(PERM_SECURITY_WRITE));
        assert!(!catalog::is_dangerous(PERM_FEATURES_WRITE));
    }
}
