//! Identity request and response types.
//!
//! Request and response types are never the same struct. The rule that matters:
//! **a request DTO contains only what this endpoint is authorised to change.**
//! None of them carries `principal_type`, `status`, `role_ids` (except on the
//! invitation endpoint, where granting roles *is* the operation and is separately
//! guarded by `delegation::check_role_assignment`), `is_root`, `permissions`,
//! `security_version` or `id`. `deny_unknown_fields` makes that a parse failure
//! rather than a silently ignored field (TH-12).

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::platform::errors::AppError;
use crate::shared::pagination::PageQuery;

/// Render a timestamp for the wire. See the note in `bootstrap::dto`.
pub(crate) fn rfc3339(value: OffsetDateTime) -> String {
    value
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

pub(crate) fn opt_rfc3339(value: Option<OffsetDateTime>) -> Option<String> {
    value.map(rfc3339)
}

// =============================================================================
// Lifecycle
// =============================================================================

/// The four states an account can be in.
///
/// A closed enum rather than a string, so that adding a state is a compile error
/// at the transition matrix rather than a value that quietly falls through a
/// `match` arm into "allowed".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum UserStatus {
    Pending,
    Active,
    Suspended,
    Archived,
}

impl UserStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            UserStatus::Pending => "PENDING",
            UserStatus::Active => "ACTIVE",
            UserStatus::Suspended => "SUSPENDED",
            UserStatus::Archived => "ARCHIVED",
        }
    }

    /// Exact-case parsing. A lowercase `active` arriving from anywhere is a bug or
    /// a probe, never a value to be helpfully coerced.
    pub fn parse(input: &str) -> Option<Self> {
        match input {
            "PENDING" => Some(UserStatus::Pending),
            "ACTIVE" => Some(UserStatus::Active),
            "SUSPENDED" => Some(UserStatus::Suspended),
            "ARCHIVED" => Some(UserStatus::Archived),
            _ => None,
        }
    }

    /// A status read back out of the database that does not parse means the row
    /// violates its own `CHECK` constraint. That is a corrupt security-relevant
    /// value, so it fails the request rather than being guessed at.
    pub fn from_row(raw: &str) -> Result<Self, AppError> {
        Self::parse(raw)
            .ok_or_else(|| AppError::Internal("user row has an unrecognised status".into()))
    }

    pub const ALL: [UserStatus; 4] = [
        UserStatus::Pending,
        UserStatus::Active,
        UserStatus::Suspended,
        UserStatus::Archived,
    ];
}

impl std::fmt::Display for UserStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// =============================================================================
// Requests — users
// =============================================================================

/// Query parameters for `GET /api/v1/users`.
///
/// Every field is `Option<String>` and is validated in the service, so a malformed
/// value produces a field-level validation error rather than a serde rejection.
/// `sort` is resolved against a compile-time allowlist by `PageRequest::resolve`;
/// the caller's string never reaches SQL.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListUsersQuery {
    pub cursor: Option<String>,
    pub limit: Option<String>,
    pub sort: Option<String>,
    pub direction: Option<String>,
    pub principal_type: Option<String>,
    pub status: Option<String>,
    /// Case-insensitive substring match against the normalised email and the
    /// display name. Passed as a bound parameter to `strpos`, never interpolated.
    pub search: Option<String>,
}

impl ListUsersQuery {
    pub fn page(&self) -> PageQuery {
        PageQuery {
            cursor: self.cursor.clone(),
            limit: self.limit.clone(),
            sort: self.sort.clone(),
            direction: self.direction.clone(),
        }
    }
}

/// `PATCH /api/v1/users/{id}`.
///
/// Profile fields only. Changing what an account *is* — its principal type, its
/// status, its roles — is not an update; those are separate, separately
/// authorised, separately audited operations.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateUserRequest {
    pub display_name: Option<String>,
    pub email: Option<String>,
    /// Optimistic concurrency. A stale version is a `409 VERSION_CONFLICT`, never
    /// a silent overwrite of somebody else's edit.
    pub version: i32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuspendUserRequest {
    pub version: i32,
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReactivateUserRequest {
    pub version: i32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveUserRequest {
    pub version: i32,
    pub reason: Option<String>,
}

// =============================================================================
// Requests — invitations
// =============================================================================

/// `POST /api/v1/invitations`.
///
/// `principal_type` and `role_ids` are legitimate fields here — deciding what an
/// invitee will be *is* the operation. They are not trusted: every role is checked
/// against the inviter's own delegation authority at creation and **again** at
/// acceptance, and the principal type is constrained by the database CHECKs that
/// pair it with `client_account_id` / `department_id`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateInvitationRequest {
    pub email: String,
    pub display_name: String,
    /// `INTERNAL` or `CLIENT`.
    pub principal_type: String,
    #[serde(default)]
    pub role_ids: Vec<Uuid>,
    /// INTERNAL invitations only.
    pub department_id: Option<Uuid>,
    /// CLIENT invitations only.
    pub client_account_id: Option<Uuid>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListInvitationsQuery {
    pub cursor: Option<String>,
    pub limit: Option<String>,
    pub sort: Option<String>,
    pub direction: Option<String>,
    pub status: Option<String>,
}

impl ListInvitationsQuery {
    pub fn page(&self) -> PageQuery {
        PageQuery {
            cursor: self.cursor.clone(),
            limit: self.limit.clone(),
            sort: self.sort.clone(),
            direction: self.direction.clone(),
        }
    }
}

/// `POST /api/v1/invitations/accept` — anonymous, token in the body.
///
/// The token is in the body and not in the path or the query string on purpose:
/// query strings land in access logs, browser history and `Referer` headers
/// (TH-36).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptInvitationRequest {
    pub token: String,
    pub password: String,
    /// The invitee may correct the name the inviter typed. They may not change
    /// their email, their principal type, their roles or their status.
    pub display_name: Option<String>,
}

impl std::fmt::Debug for AcceptInvitationRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcceptInvitationRequest")
            .field("token", &"<redacted>")
            .field("password", &"<redacted>")
            .field("display_name", &self.display_name)
            .finish()
    }
}

// =============================================================================
// Requests — registration
// =============================================================================

/// `POST /api/v1/registration` — anonymous.
///
/// Three fields, and there is deliberately no fourth. `principal_type = CLIENT`,
/// `status = PENDING` and the `client_user` role are constructed in code; a body
/// carrying `principal_type`, `role_ids`, `status`, `is_root` or `permissions` is
/// rejected by `deny_unknown_fields` before the service is ever entered.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterRequest {
    pub email: String,
    pub display_name: String,
    pub password: String,
}

impl std::fmt::Debug for RegisterRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisterRequest")
            .field("email", &self.email)
            .field("display_name", &self.display_name)
            .field("password", &"<redacted>")
            .finish()
    }
}

// =============================================================================
// Responses
// =============================================================================

/// The internal view of a user.
///
/// Hand-written and field-by-field. It is **not** derived from the database row
/// struct, which is what keeps a future column — a password hash moved back into
/// `users`, a TOTP secret, an internal note — from appearing in an API response
/// because somebody added it to a table.
///
/// `email_normalized` is absent: it is an identity key, not a fact about the
/// person, and echoing it doubles the surface for no benefit.
#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub email: String,
    pub display_name: String,
    pub principal_type: String,
    pub status: String,
    pub mfa_required: bool,
    pub mfa_enrolled: bool,
    pub security_version: i32,
    pub version: i32,
    pub created_at: String,
    pub updated_at: String,
    pub activated_at: Option<String>,
    pub suspended_at: Option<String>,
    pub archived_at: Option<String>,
}

/// An invitation as an internal principal sees it.
///
/// The token is absent, and there is no field it could occupy. The plaintext
/// exists exactly twice in the system's lifetime: in memory during creation, and
/// in the outbox payload destined for the mail provider. It is never returned by
/// an API, never logged, and stored only as a SHA-256 digest.
#[derive(Debug, Serialize)]
pub struct InvitationResponse {
    pub id: Uuid,
    pub email: String,
    pub display_name: String,
    pub principal_type: String,
    pub status: String,
    pub invited_by: Uuid,
    pub department_id: Option<Uuid>,
    pub client_account_id: Option<Uuid>,
    pub role_ids: Vec<Uuid>,
    pub expires_at: String,
    pub created_at: String,
    pub accepted_at: Option<String>,
    pub accepted_user_id: Option<Uuid>,
}

/// What an invitee gets back. No session and no token: they must authenticate
/// through the ordinary login path, which is also where MFA enrolment is enforced.
#[derive(Debug, Serialize)]
pub struct AcceptInvitationResponse {
    pub user_id: Uuid,
    pub email: String,
    pub display_name: String,
    pub principal_type: String,
    pub status: String,
    pub mfa_enrolment_required: bool,
}

/// `GET /api/v1/registration/config` — anonymous.
///
/// Two fields and nothing more. A frontend needs to know whether to render a
/// signup form; it does not need the user count, the invitation policy or the
/// deployment's build id, and this endpoint answers to the open internet.
#[derive(Debug, Serialize)]
pub struct RegistrationConfigResponse {
    pub registration_available: bool,
    /// `"client"` when self-registration is on, `null` otherwise. Self-registration
    /// can only ever produce a CLIENT principal, so there is no other value.
    pub registration_type: Option<&'static str>,
}

/// The single response `POST /api/v1/registration` ever produces.
///
/// Byte-for-byte identical whether the address was free, already registered, or
/// belongs to an internal employee. A distinguishable response here is an account
/// enumeration oracle on an anonymous endpoint (TH-23), so the type carries no
/// id, no email echo and no variant.
#[derive(Debug, Serialize)]
pub struct RegistrationAcceptedResponse {
    pub registration_status: &'static str,
    pub message: &'static str,
}

impl RegistrationAcceptedResponse {
    pub const STATUS: &'static str = "SUBMITTED";
    pub const MESSAGE: &'static str =
        "If this address can be registered, the account is now pending review by the company.";

    pub fn new() -> Self {
        Self {
            registration_status: Self::STATUS,
            message: Self::MESSAGE,
        }
    }
}

impl Default for RegistrationAcceptedResponse {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- mass assignment ----------------------------------------------------

    /// The single most important test in this file. Each of these fields, if it
    /// were honoured, would let an anonymous caller choose their own security
    /// envelope: `principal_type` escapes the client boundary entirely,
    /// `role_ids`/`permissions` grant authority, `status` skips the PENDING review
    /// gate, and `is_root` is the whole system.
    #[test]
    fn registration_rejects_every_privileged_field() {
        for injected in [
            r#""principal_type":"INTERNAL""#,
            r#""principal_type":"CLIENT""#,
            r#""role_ids":["00000000-0000-7000-8000-000000000001"]"#,
            r#""role_id":"00000000-0000-7000-8000-000000000001""#,
            r#""status":"ACTIVE""#,
            r#""is_root":true"#,
            r#""permissions":["settings.security.write"]"#,
            r#""client_account_id":"00000000-0000-7000-8000-000000000009""#,
            r#""mfa_required":false"#,
            r#""security_version":99"#,
            r#""id":"00000000-0000-7000-8000-000000000009""#,
            r#""version":5"#,
        ] {
            let body = format!(
                r#"{{"email":"a@b.com","display_name":"A",
                     "password":"correct horse battery staple",{injected}}}"#
            );
            assert!(
                serde_json::from_str::<RegisterRequest>(&body).is_err(),
                "registration accepted a body carrying {injected}"
            );
        }
    }

    #[test]
    fn a_plain_registration_body_parses() {
        let r: RegisterRequest = serde_json::from_str(
            r#"{"email":"a@b.com","display_name":"A","password":"correct horse battery staple"}"#,
        )
        .expect("valid body");
        assert_eq!(r.email, "a@b.com");
    }

    #[test]
    fn the_user_update_dto_cannot_change_what_an_account_is() {
        for injected in [
            r#""principal_type":"INTERNAL""#,
            r#""status":"ACTIVE""#,
            r#""role_ids":[]"#,
            r#""is_root":true"#,
            r#""permissions":[]"#,
            r#""mfa_required":false"#,
            r#""mfa_enrolled":true"#,
            r#""security_version":2"#,
            r#""id":"00000000-0000-7000-8000-000000000009""#,
            r#""archived_at":null"#,
        ] {
            let body = format!(r#"{{"version":1,"display_name":"A",{injected}}}"#);
            assert!(
                serde_json::from_str::<UpdateUserRequest>(&body).is_err(),
                "the update DTO accepted {injected}"
            );
        }
        assert!(serde_json::from_str::<UpdateUserRequest>(
            r#"{"version":1,"display_name":"A","email":"a@b.com"}"#
        )
        .is_ok());
    }

    #[test]
    fn lifecycle_dtos_require_a_version_and_admit_nothing_privileged() {
        assert!(serde_json::from_str::<SuspendUserRequest>(r#"{}"#).is_err());
        assert!(serde_json::from_str::<ReactivateUserRequest>(r#"{}"#).is_err());
        assert!(serde_json::from_str::<ArchiveUserRequest>(r#"{}"#).is_err());
        assert!(serde_json::from_str::<SuspendUserRequest>(r#"{"version":1}"#).is_ok());
        assert!(
            serde_json::from_str::<SuspendUserRequest>(r#"{"version":1,"status":"ARCHIVED"}"#)
                .is_err()
        );
        assert!(
            serde_json::from_str::<ReactivateUserRequest>(r#"{"version":1,"is_root":true}"#)
                .is_err()
        );
    }

    #[test]
    fn the_invitation_acceptance_dto_cannot_choose_its_own_envelope() {
        for injected in [
            r#""principal_type":"INTERNAL""#,
            r#""role_ids":[]"#,
            r#""status":"ACTIVE""#,
            r#""is_root":true"#,
            r#""permissions":[]"#,
            r#""email":"someone.else@example.com""#,
            r#""client_account_id":"00000000-0000-7000-8000-000000000009""#,
        ] {
            let body = format!(
                r#"{{"token":"rb_iv_x","password":"correct horse battery staple",{injected}}}"#
            );
            assert!(
                serde_json::from_str::<AcceptInvitationRequest>(&body).is_err(),
                "acceptance accepted {injected}"
            );
        }
    }

    /// An invitation *may* carry roles — that is the operation — but nothing else
    /// that would bypass the delegation guard.
    #[test]
    fn the_invitation_creation_dto_admits_roles_but_not_permissions() {
        assert!(serde_json::from_str::<CreateInvitationRequest>(
            r#"{"email":"a@b.com","display_name":"A","principal_type":"INTERNAL",
                "role_ids":["00000000-0000-7000-8000-000000000002"]}"#
        )
        .is_ok());
        for injected in [
            r#""permissions":["settings.security.write"]"#,
            r#""is_root":true"#,
            r#""status":"ACCEPTED""#,
            r#""token":"rb_iv_x""#,
            r#""invited_by":"00000000-0000-7000-8000-000000000009""#,
            r#""expires_at":"2099-01-01T00:00:00Z""#,
            r#""accepted_user_id":"00000000-0000-7000-8000-000000000009""#,
        ] {
            let body = format!(
                r#"{{"email":"a@b.com","display_name":"A","principal_type":"INTERNAL",{injected}}}"#
            );
            assert!(
                serde_json::from_str::<CreateInvitationRequest>(&body).is_err(),
                "invitation creation accepted {injected}"
            );
        }
    }

    #[test]
    fn list_queries_reject_unknown_parameters() {
        assert!(serde_json::from_str::<ListUsersQuery>(r#"{"limit":"10"}"#).is_ok());
        assert!(serde_json::from_str::<ListUsersQuery>(r#"{"is_root":"true"}"#).is_err());
        assert!(serde_json::from_str::<ListInvitationsQuery>(r#"{"token":"x"}"#).is_err());
    }

    // ---- credential redaction ----------------------------------------------

    #[test]
    fn debug_never_reveals_a_password_or_an_invitation_token() {
        let r: RegisterRequest = serde_json::from_str(
            r#"{"email":"a@b.com","display_name":"A","password":"hunter2-the-password"}"#,
        )
        .expect("valid");
        assert!(!format!("{r:?}").contains("hunter2"));

        let a: AcceptInvitationRequest = serde_json::from_str(
            r#"{"token":"rb_iv_hunter2token","password":"hunter2-the-password"}"#,
        )
        .expect("valid");
        let rendered = format!("{a:?}");
        assert!(
            !rendered.contains("hunter2"),
            "a credential leaked through Debug: {rendered}"
        );
    }

    // ---- response shape -----------------------------------------------------

    fn sample_user_response() -> UserResponse {
        UserResponse {
            id: Uuid::now_v7(),
            email: "alice@example.com".into(),
            display_name: "Alice".into(),
            principal_type: "INTERNAL".into(),
            status: "ACTIVE".into(),
            mfa_required: true,
            mfa_enrolled: false,
            security_version: 1,
            version: 1,
            created_at: rfc3339(OffsetDateTime::UNIX_EPOCH),
            updated_at: rfc3339(OffsetDateTime::UNIX_EPOCH),
            activated_at: None,
            suspended_at: None,
            archived_at: None,
        }
    }

    /// A password hash cannot reach a `UserResponse`, because the type has no field
    /// that could hold one. This asserts the field set exhaustively: adding a field
    /// to the struct fails this test and forces a deliberate decision about whether
    /// it belongs in an API response.
    #[test]
    fn a_user_response_can_never_contain_a_credential() {
        let value = serde_json::to_value(sample_user_response()).expect("serialisable");
        let object = value.as_object().expect("object");

        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "activated_at",
                "archived_at",
                "created_at",
                "display_name",
                "email",
                "id",
                "mfa_enrolled",
                "mfa_required",
                "principal_type",
                "security_version",
                "status",
                "suspended_at",
                "updated_at",
                "version",
            ],
            "the user response field set changed; confirm the new field is safe to expose"
        );

        for key in object.keys() {
            let lowered = key.to_lowercase();
            for forbidden in [
                "password",
                "hash",
                "secret",
                "token",
                "credential",
                "totp",
                "recovery",
                "email_normalized",
            ] {
                assert!(
                    !lowered.contains(forbidden),
                    "`{key}` looks like a credential-bearing field"
                );
            }
        }

        // And nothing that looks like a stored hash can appear in the rendered body.
        let body = serde_json::to_string(&sample_user_response()).expect("serialisable");
        assert!(!body.contains("$argon2"));
        assert!(!body.contains("rb_at_"));
        assert!(!body.contains("rb_iv_"));
    }

    #[test]
    fn an_invitation_response_has_no_field_a_token_could_occupy() {
        let value = serde_json::to_value(InvitationResponse {
            id: Uuid::now_v7(),
            email: "a@b.com".into(),
            display_name: "A".into(),
            principal_type: "INTERNAL".into(),
            status: "PENDING".into(),
            invited_by: Uuid::now_v7(),
            department_id: None,
            client_account_id: None,
            role_ids: vec![],
            expires_at: rfc3339(OffsetDateTime::UNIX_EPOCH),
            created_at: rfc3339(OffsetDateTime::UNIX_EPOCH),
            accepted_at: None,
            accepted_user_id: None,
        })
        .expect("serialisable");
        for key in value.as_object().expect("object").keys() {
            let lowered = key.to_lowercase();
            assert!(
                !lowered.contains("token"),
                "`{key}` could carry the invitation token"
            );
            assert!(
                !lowered.contains("hash"),
                "`{key}` could carry the token digest"
            );
            assert!(!lowered.contains("password"));
        }
    }

    #[test]
    fn the_registration_config_response_discloses_two_fields_only() {
        let value = serde_json::to_value(RegistrationConfigResponse {
            registration_available: false,
            registration_type: None,
        })
        .expect("serialisable");
        let object = value.as_object().expect("object");
        assert_eq!(object.len(), 2);
        assert_eq!(object["registration_available"], serde_json::json!(false));
        assert_eq!(object["registration_type"], serde_json::Value::Null);
    }

    /// Two calls must be byte-identical, because the only way to keep an anonymous
    /// endpoint from being an enumeration oracle is for it to have one answer.
    #[test]
    fn the_registration_response_is_constant() {
        let a = serde_json::to_string(&RegistrationAcceptedResponse::new()).expect("serialisable");
        let b = serde_json::to_string(&RegistrationAcceptedResponse::default()).expect("ok");
        assert_eq!(a, b);
        assert!(
            !a.contains("@"),
            "the response must not echo the submitted address"
        );
        assert!(!a.to_lowercase().contains("exists"));
        assert!(!a.to_lowercase().contains("already"));
    }

    // ---- status enum --------------------------------------------------------

    #[test]
    fn statuses_round_trip_and_reject_anything_else() {
        for s in UserStatus::ALL {
            assert_eq!(UserStatus::parse(s.as_str()), Some(s));
            assert_eq!(
                serde_json::to_value(s).expect("ok"),
                serde_json::json!(s.as_str())
            );
        }
        for bad in [
            "",
            "active",
            "DELETED",
            "ACTIVE ",
            "ACTIVE; DROP TABLE users",
            "ROOT",
        ] {
            assert_eq!(UserStatus::parse(bad), None, "accepted `{bad}`");
        }
        assert!(UserStatus::from_row("NONSENSE").is_err());
    }
}
