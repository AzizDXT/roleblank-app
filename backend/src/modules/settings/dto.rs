//! Request and response types for settings and feature flags.
//!
//! Requests are closed (`deny_unknown_fields`); responses are hand-written and are
//! never a database row struct. In particular `updated_by` is a plain id and there
//! is no join that would pull an email address into a configuration listing.

use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

use super::repo::{FeatureFlagRow, SettingRow};

/// `PUT /api/v1/settings/{key}`.
///
/// `key` is **not** a member: it comes from the path. A request DTO that also
/// carried the key would let a body silently retarget a URL-authorised write.
/// `is_security_sensitive`, `value_type` and `description` are likewise absent —
/// they describe the setting, and letting a caller change them would let them
/// downgrade a security-sensitive setting to an ordinary one and then write it
/// with the weaker permission.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateSettingRequest {
    /// Validated against the stored `value_type` before it is written; a raw
    /// `serde_json::Value` here is the transport, not the contract.
    pub value: serde_json::Value,
    /// Optimistic concurrency. Required, not optional: an absent version would
    /// make a blind overwrite the default behaviour.
    pub version: i32,
}

/// `PUT /api/v1/feature-flags/{key}`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateFeatureFlagRequest {
    pub enabled: bool,
    pub version: i32,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct SettingResponse {
    pub key: String,
    pub value: serde_json::Value,
    pub value_type: String,
    pub is_security_sensitive: bool,
    pub description: String,
    pub version: i32,
    pub updated_by: Option<Uuid>,
    pub updated_at: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct FeatureFlagResponse {
    pub key: String,
    pub enabled: bool,
    pub is_security_sensitive: bool,
    pub description: String,
    pub version: i32,
    pub updated_by: Option<Uuid>,
    pub updated_at: String,
}

/// A timestamp that failed to format is rendered as an empty string rather than
/// propagated: a formatting failure on a `timestamptz` is not reachable, and
/// panicking or 500-ing a whole listing over one field would be a worse outcome
/// than a blank one.
fn rfc3339(value: OffsetDateTime) -> String {
    value.format(&Rfc3339).unwrap_or_default()
}

impl SettingResponse {
    pub fn from_row(row: SettingRow) -> Self {
        Self {
            key: row.key,
            value: row.value,
            value_type: row.value_type,
            is_security_sensitive: row.is_security_sensitive,
            description: row.description,
            version: row.version,
            updated_by: row.updated_by,
            updated_at: rfc3339(row.updated_at),
        }
    }
}

impl FeatureFlagResponse {
    pub fn from_row(row: FeatureFlagRow) -> Self {
        Self {
            key: row.key,
            enabled: row.enabled,
            is_security_sensitive: row.is_security_sensitive,
            description: row.description,
            version: row.version,
            updated_by: row.updated_by,
            updated_at: rfc3339(row.updated_at),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_update_request_refuses_unknown_and_privileged_fields() {
        // The happy path.
        let ok: UpdateSettingRequest =
            serde_json::from_str(r#"{"value":"INVITE_ONLY","version":3}"#).expect("valid body");
        assert_eq!(ok.version, 3);

        // Mass assignment: each of these would let a caller re-describe the setting
        // and thereby pick which permission guards it.
        for body in [
            r#"{"value":"X","version":1,"is_security_sensitive":false}"#,
            r#"{"value":"X","version":1,"value_type":"STRING"}"#,
            r#"{"value":"X","version":1,"key":"other.setting"}"#,
            r#"{"value":"X","version":1,"updated_by":"00000000-0000-7000-8000-000000000001"}"#,
            r#"{"value":"X","version":1,"description":"anything"}"#,
        ] {
            assert!(
                serde_json::from_str::<UpdateSettingRequest>(body).is_err(),
                "accepted a body with an unknown field: {body}"
            );
        }

        // `version` is mandatory.
        assert!(serde_json::from_str::<UpdateSettingRequest>(r#"{"value":"X"}"#).is_err());
    }

    #[test]
    fn a_feature_flag_request_is_closed_too() {
        let ok: UpdateFeatureFlagRequest =
            serde_json::from_str(r#"{"enabled":true,"version":1}"#).expect("valid body");
        assert!(ok.enabled);
        for body in [
            r#"{"enabled":true,"version":1,"is_security_sensitive":false}"#,
            r#"{"enabled":true,"version":1,"key":"chat"}"#,
            r#"{"enabled":true}"#,
        ] {
            assert!(
                serde_json::from_str::<UpdateFeatureFlagRequest>(body).is_err(),
                "{body}"
            );
        }
    }
}
