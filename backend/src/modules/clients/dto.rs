//! Request and response types for the client-accounts module.
//!
//! Requests are closed (`deny_unknown_fields`) and carry no `id`, `status`,
//! `created_by` or `version` beyond the one that exists solely for optimistic
//! concurrency. In particular there is no way to set a membership's `status` from
//! a request body: `PENDING -> ACTIVE` is a separate, separately authorised,
//! separately audited endpoint, because it is the moment an external human starts
//! being able to see company data.

use serde::{Deserialize, Deserializer, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// Distinguish "field absent" from "field explicitly null" — serde's `Option`
/// deserialiser maps JSON `null` to `None`, which would make "clear the account
/// manager" indistinguishable from "leave it alone".
fn absent_or_null<'de, T, D>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    T: Deserialize<'de>,
    D: Deserializer<'de>,
{
    Deserialize::deserialize(deserializer).map(Some)
}

// ---------------------------------------------------------------------------
// Domain enums
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ClientAccountStatus {
    Active,
    Suspended,
    Archived,
}

impl ClientAccountStatus {
    pub const ALL: &'static [ClientAccountStatus] = &[
        ClientAccountStatus::Active,
        ClientAccountStatus::Suspended,
        ClientAccountStatus::Archived,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            ClientAccountStatus::Active => "ACTIVE",
            ClientAccountStatus::Suspended => "SUSPENDED",
            ClientAccountStatus::Archived => "ARCHIVED",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "ACTIVE" => Some(ClientAccountStatus::Active),
            "SUSPENDED" => Some(ClientAccountStatus::Suspended),
            "ARCHIVED" => Some(ClientAccountStatus::Archived),
            _ => None,
        }
    }
}

/// `PENDING -> ACTIVE -> SUSPENDED -> REMOVED`.
///
/// Only `ACTIVE` confers anything. `PENDING` exists so that a self-registered
/// external user has an account and no visibility whatsoever until a human inside
/// the company decides otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ClientMembershipStatus {
    Pending,
    Active,
    Suspended,
    Removed,
}

impl ClientMembershipStatus {
    pub const ALL: &'static [ClientMembershipStatus] = &[
        ClientMembershipStatus::Pending,
        ClientMembershipStatus::Active,
        ClientMembershipStatus::Suspended,
        ClientMembershipStatus::Removed,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            ClientMembershipStatus::Pending => "PENDING",
            ClientMembershipStatus::Active => "ACTIVE",
            ClientMembershipStatus::Suspended => "SUSPENDED",
            ClientMembershipStatus::Removed => "REMOVED",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "PENDING" => Some(ClientMembershipStatus::Pending),
            "ACTIVE" => Some(ClientMembershipStatus::Active),
            "SUSPENDED" => Some(ClientMembershipStatus::Suspended),
            "REMOVED" => Some(ClientMembershipStatus::Removed),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateClientRequest {
    pub code: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    /// The account manager is company staff; the service checks that before the
    /// insert so the failure names the field instead of surfacing a trigger.
    #[serde(default)]
    pub account_manager_user_id: Option<Uuid>,
}

/// No `status`: `ACTIVE -> ARCHIVED` has its own endpoint, and `code` is an
/// immutable machine identifier.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateClientRequest {
    pub version: i32,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    /// Absent leaves the manager alone; explicit `null` clears it.
    #[serde(default, deserialize_with = "absent_or_null")]
    pub account_manager_user_id: Option<Option<Uuid>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveClientRequest {
    pub version: i32,
}

/// There is deliberately no `status` here. A membership always starts `PENDING`,
/// whoever creates it: an administrator adding a client contact and a client
/// registering themselves must land in the same inert state, or the "activation is
/// a decision" property would hold for only one of the two paths.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddClientMemberRequest {
    pub user_id: Uuid,
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct ClientAccountResponse {
    pub id: Uuid,
    pub code: String,
    pub name: String,
    pub description: String,
    pub status: ClientAccountStatus,
    pub account_manager_user_id: Option<Uuid>,
    pub version: i32,
    pub created_by: Option<Uuid>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub archived_at: Option<OffsetDateTime>,
}

#[derive(Debug, Serialize)]
pub struct ClientMemberResponse {
    pub user_id: Uuid,
    pub display_name: String,
    pub email: String,
    pub status: ClientMembershipStatus,
    pub invited_by: Option<Uuid>,
    /// Whether this membership currently lets the person see anything at all.
    ///
    /// Reported explicitly because "the member is listed" and "the member can see
    /// our projects" are different facts, and an interface that conflates them is
    /// how a `PENDING` membership gets activated by accident.
    pub grants_visibility: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub activated_at: Option<OffsetDateTime>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_rejects_privileged_fields() {
        for body in [
            r#"{"code":"acme","name":"Acme","id":"00000000-0000-0000-0000-000000000001"}"#,
            r#"{"code":"acme","name":"Acme","status":"ACTIVE"}"#,
            r#"{"code":"acme","name":"Acme","version":2}"#,
            r#"{"code":"acme","name":"Acme","created_by":"00000000-0000-0000-0000-000000000001"}"#,
            r#"{"code":"acme","name":"Acme","archived_at":null}"#,
        ] {
            assert!(
                serde_json::from_str::<CreateClientRequest>(body).is_err(),
                "accepted a privileged field: {body}"
            );
        }
        assert!(
            serde_json::from_str::<CreateClientRequest>(r#"{"code":"acme","name":"Acme"}"#).is_ok()
        );
    }

    #[test]
    fn update_rejects_privileged_fields_but_accepts_the_concurrency_version() {
        for body in [
            r#"{"version":1,"status":"SUSPENDED"}"#,
            r#"{"version":1,"id":"00000000-0000-0000-0000-000000000001"}"#,
            r#"{"version":1,"code":"renamed"}"#,
            r#"{"version":1,"created_by":"00000000-0000-0000-0000-000000000001"}"#,
            r#"{"name":"Acme Ltd"}"#,
        ] {
            assert!(
                serde_json::from_str::<UpdateClientRequest>(body).is_err(),
                "accepted: {body}"
            );
        }
        assert!(
            serde_json::from_str::<UpdateClientRequest>(r#"{"version":2,"name":"Acme Ltd"}"#)
                .is_ok()
        );
    }

    /// The single most important DTO property in this module: nothing in a request
    /// body can put a membership straight into `ACTIVE`.
    #[test]
    fn a_membership_status_can_never_arrive_in_a_request_body() {
        for body in [
            r#"{"user_id":"00000000-0000-0000-0000-00000000000a","status":"ACTIVE"}"#,
            r#"{"user_id":"00000000-0000-0000-0000-00000000000a","activated_at":"2024-01-01T00:00:00Z"}"#,
            r#"{"user_id":"00000000-0000-0000-0000-00000000000a","grants_visibility":true}"#,
        ] {
            assert!(
                serde_json::from_str::<AddClientMemberRequest>(body).is_err(),
                "accepted: {body}"
            );
        }
        assert!(serde_json::from_str::<AddClientMemberRequest>(
            r#"{"user_id":"00000000-0000-0000-0000-00000000000a"}"#
        )
        .is_ok());
    }

    #[test]
    fn an_absent_account_manager_differs_from_an_explicit_null() {
        let absent: UpdateClientRequest =
            serde_json::from_str(r#"{"version":1,"name":"Acme"}"#).expect("absent");
        assert_eq!(absent.account_manager_user_id, None);

        let cleared: UpdateClientRequest =
            serde_json::from_str(r#"{"version":1,"account_manager_user_id":null}"#).expect("null");
        assert_eq!(cleared.account_manager_user_id, Some(None));
    }

    #[test]
    fn enums_round_trip_and_refuse_anything_outside_the_set() {
        for s in ClientAccountStatus::ALL {
            assert_eq!(ClientAccountStatus::parse(s.as_str()), Some(*s));
        }
        for s in ClientMembershipStatus::ALL {
            assert_eq!(ClientMembershipStatus::parse(s.as_str()), Some(*s));
        }
        for bad in ["", "active", "DELETED", "ACTIVE'; --", "PENDING "] {
            assert_eq!(ClientAccountStatus::parse(bad), None);
            assert_eq!(ClientMembershipStatus::parse(bad), None);
        }
        // The account and membership vocabularies are not interchangeable.
        assert_eq!(ClientAccountStatus::parse("PENDING"), None);
        assert_eq!(ClientMembershipStatus::parse("ARCHIVED"), None);
    }
}
