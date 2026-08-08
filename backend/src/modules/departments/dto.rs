//! Request and response types for the departments module.
//!
//! Request and response are never the same struct. A request type is *closed*
//! (`deny_unknown_fields`) and contains no field the endpoint does not explicitly
//! authorise changing — no `id`, no `status`, no `created_by`, and no `version`
//! except the one that exists solely to carry optimistic concurrency. That is the
//! mass-assignment defence (TH-12), and it is a property of the type rather than
//! of a handler remembering to strip fields.

use serde::{Deserialize, Deserializer, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// Distinguish "field absent" from "field explicitly null".
///
/// `Option<Option<T>>` alone cannot: serde's `Option` deserialiser maps JSON
/// `null` to `None`, so an explicit null and an omitted field would be
/// indistinguishable, and "clear the department lead" would silently become
/// "leave the lead unchanged".
fn absent_or_null<'de, T, D>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    T: Deserialize<'de>,
    D: Deserializer<'de>,
{
    Deserialize::deserialize(deserializer).map(Some)
}

// ---------------------------------------------------------------------------
// Domain enums (they are part of the wire contract, so they live with the DTOs)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum DepartmentStatus {
    Active,
    Archived,
}

impl DepartmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            DepartmentStatus::Active => "ACTIVE",
            DepartmentStatus::Archived => "ARCHIVED",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "ACTIVE" => Some(DepartmentStatus::Active),
            "ARCHIVED" => Some(DepartmentStatus::Archived),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum DepartmentRole {
    Member,
    Lead,
}

impl DepartmentRole {
    pub const ALLOWED: &'static [&'static str] = &["MEMBER", "LEAD"];

    pub fn as_str(self) -> &'static str {
        match self {
            DepartmentRole::Member => "MEMBER",
            DepartmentRole::Lead => "LEAD",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "MEMBER" => Some(DepartmentRole::Member),
            "LEAD" => Some(DepartmentRole::Lead),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateDepartmentRequest {
    pub code: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    /// The department lead must be an INTERNAL user; the service checks that
    /// before the insert so the failure is a field error rather than an opaque
    /// reference violation.
    #[serde(default)]
    pub lead_user_id: Option<Uuid>,
}

/// `code` is deliberately absent: it is a machine-facing identifier that saved
/// links and downstream systems refer to, so it is immutable after creation.
/// Renaming a department changes `name`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateDepartmentRequest {
    /// Optimistic concurrency. The only `version` any request DTO may carry.
    pub version: i32,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    /// Absent leaves the lead alone; explicit `null` clears it.
    #[serde(default, deserialize_with = "absent_or_null")]
    pub lead_user_id: Option<Option<Uuid>>,
}

/// Archiving carries a version for the same reason an update does: it is a state
/// transition, and applying it to a row someone else has since changed is exactly
/// the lost update optimistic concurrency exists to prevent.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveDepartmentRequest {
    pub version: i32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddDepartmentMemberRequest {
    pub user_id: Uuid,
    /// Defaults to `MEMBER`. Parsed through a closed enum, never stored raw.
    #[serde(default)]
    pub role_in_department: Option<String>,
}

// ---------------------------------------------------------------------------
// Responses — hand-written, never a database row struct
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct DepartmentResponse {
    pub id: Uuid,
    pub code: String,
    pub name: String,
    pub description: String,
    pub status: DepartmentStatus,
    pub lead_user_id: Option<Uuid>,
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
pub struct DepartmentMemberResponse {
    pub user_id: Uuid,
    pub display_name: String,
    pub email: String,
    pub role_in_department: DepartmentRole,
    #[serde(with = "time::serde::rfc3339")]
    pub joined_at: OffsetDateTime,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The mass-assignment defence. Every one of these fields exists on the row and
    /// none of them may be steerable from a request body.
    #[test]
    fn create_rejects_privileged_fields() {
        for body in [
            r#"{"code":"ops","name":"Ops","id":"00000000-0000-0000-0000-000000000001"}"#,
            r#"{"code":"ops","name":"Ops","status":"ARCHIVED"}"#,
            r#"{"code":"ops","name":"Ops","version":99}"#,
            r#"{"code":"ops","name":"Ops","created_by":"00000000-0000-0000-0000-000000000001"}"#,
            r#"{"code":"ops","name":"Ops","archived_at":null}"#,
            r#"{"code":"ops","name":"Ops","created_at":"2024-01-01T00:00:00Z"}"#,
        ] {
            assert!(
                serde_json::from_str::<CreateDepartmentRequest>(body).is_err(),
                "accepted a privileged field: {body}"
            );
        }
        assert!(serde_json::from_str::<CreateDepartmentRequest>(
            r#"{"code":"ops","name":"Operations","description":"x"}"#
        )
        .is_ok());
    }

    #[test]
    fn update_rejects_privileged_fields_but_accepts_the_concurrency_version() {
        for body in [
            r#"{"version":1,"id":"00000000-0000-0000-0000-000000000001"}"#,
            r#"{"version":1,"status":"ARCHIVED"}"#,
            r#"{"version":1,"created_by":"00000000-0000-0000-0000-000000000001"}"#,
            // `code` is immutable after creation.
            r#"{"version":1,"code":"renamed"}"#,
            // A missing version is a rejected request, not a silent overwrite.
            r#"{"name":"Operations"}"#,
        ] {
            assert!(
                serde_json::from_str::<UpdateDepartmentRequest>(body).is_err(),
                "accepted: {body}"
            );
        }
        assert!(
            serde_json::from_str::<UpdateDepartmentRequest>(r#"{"version":3,"name":"Ops"}"#)
                .is_ok()
        );
    }

    /// Absent and explicit-null must not collapse into the same value, or
    /// "clear the lead" becomes "leave the lead alone".
    #[test]
    fn an_absent_lead_differs_from_an_explicit_null_lead() {
        let absent: UpdateDepartmentRequest =
            serde_json::from_str(r#"{"version":1,"name":"Ops"}"#).expect("absent");
        assert_eq!(absent.lead_user_id, None);

        let cleared: UpdateDepartmentRequest =
            serde_json::from_str(r#"{"version":1,"lead_user_id":null}"#).expect("null");
        assert_eq!(cleared.lead_user_id, Some(None));

        let set: UpdateDepartmentRequest = serde_json::from_str(
            r#"{"version":1,"lead_user_id":"00000000-0000-0000-0000-00000000000a"}"#,
        )
        .expect("set");
        assert!(matches!(set.lead_user_id, Some(Some(_))));
    }

    #[test]
    fn member_and_archive_requests_are_closed_too() {
        assert!(serde_json::from_str::<AddDepartmentMemberRequest>(
            r#"{"user_id":"00000000-0000-0000-0000-00000000000a","removed_at":null}"#
        )
        .is_err());
        assert!(serde_json::from_str::<ArchiveDepartmentRequest>(
            r#"{"version":1,"status":"ACTIVE"}"#
        )
        .is_err());
        assert!(serde_json::from_str::<AddDepartmentMemberRequest>(
            r#"{"user_id":"00000000-0000-0000-0000-00000000000a"}"#
        )
        .is_ok());
    }

    #[test]
    fn enums_round_trip_and_refuse_anything_outside_the_set() {
        for s in [DepartmentStatus::Active, DepartmentStatus::Archived] {
            assert_eq!(DepartmentStatus::parse(s.as_str()), Some(s));
        }
        for r in [DepartmentRole::Member, DepartmentRole::Lead] {
            assert_eq!(DepartmentRole::parse(r.as_str()), Some(r));
        }
        for bad in ["", "active", "DELETED", "MEMBER; DROP TABLE users", "OWNER"] {
            assert_eq!(DepartmentStatus::parse(bad), None);
            assert_eq!(DepartmentRole::parse(bad), None);
        }
    }
}
