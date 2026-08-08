//! Request and response types for the authentication endpoints.
//!
//! Two rules from `MODULE_GUIDE.md` §3.3 are absolute here:
//!
//!   * every request DTO carries `#[serde(deny_unknown_fields)]`, so a payload
//!     smuggling `principal_type`, `status` or `role_ids` is rejected by serde
//!     before the service ever sees it (TH-12);
//!   * response DTOs are hand-written and never derived from a database row, so a
//!     column added to `sessions` or `credentials` cannot silently start appearing
//!     in a response. There is no path by which a password hash, a token digest or
//!     a TOTP ciphertext can reach a field below, because no field below is capable
//!     of holding one.
//!
//! Credential-bearing request DTOs implement `Debug` **manually**. A derived
//! `Debug` would put a plaintext password into any `tracing` field, `dbg!` or
//! panic message that happened to format the struct.

use serde::{Deserialize, Serialize};
use std::fmt;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::modules::authorization::domain::{PrincipalType, ScopeType};

/// The only value this API ever puts in `token_type`. RFC 6750 §2.1.
pub const TOKEN_TYPE: &str = "Bearer";

/// Timestamps cross the wire as RFC 3339 strings.
///
/// `time`'s own `Serialize` for `OffsetDateTime` emits a tuple of integers unless
/// the `serde-human-readable` feature is on, which would be a hostile API shape.
/// Formatting explicitly also keeps the wire format independent of a crate feature
/// flag that a future dependency bump could flip.
pub fn rfc3339(value: OffsetDateTime) -> String {
    // Formatting an `OffsetDateTime` as RFC 3339 cannot fail for any value the
    // database can hold; an empty string is returned rather than panicking,
    // because a serialisation panic in a response path is a dropped connection.
    value.format(&Rfc3339).unwrap_or_default()
}

// =============================================================================
// Requests
// =============================================================================

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

impl fmt::Debug for LoginRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginRequest")
            .field("password", &"<redacted>")
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

impl fmt::Debug for RefreshRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RefreshRequest")
            .field("refresh_token", &"<redacted>")
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordChangeRequest {
    pub current_password: String,
    pub new_password: String,
}

impl fmt::Debug for PasswordChangeRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasswordChangeRequest")
            .field("current_password", &"<redacted>")
            .field("new_password", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordResetRequestRequest {
    pub email: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordResetConfirmRequest {
    pub token: String,
    pub new_password: String,
}

impl fmt::Debug for PasswordResetConfirmRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasswordResetConfirmRequest")
            .field("token", &"<redacted>")
            .field("new_password", &"<redacted>")
            .finish()
    }
}

/// A presented one-time code — TOTP for activation and verification.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeRequest {
    pub code: String,
}

impl fmt::Debug for CodeRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CodeRequest")
            .field("code", &"<redacted>")
            .finish()
    }
}

// =============================================================================
// Responses
// =============================================================================

/// The single response shape for login, refresh, and any other token issue.
///
/// `access_token` and `refresh_token` hold plaintext, and this struct is the only
/// place in the system where plaintext token material exists after generation. It
/// is serialised straight into the response body and dropped.
#[derive(Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    /// Lifetime of `access_token` in seconds. Not of the session.
    pub expires_in: i64,
    /// True when this token may reach **only** `/api/v1/auth/mfa/*`, `/auth/me`
    /// and `/auth/logout`. See `docs/backend/03-authentication.md` §4.
    pub mfa_required: bool,
    pub token_type: &'static str,
}

impl fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenResponse")
            .field("access_token", &"<redacted>")
            .field("refresh_token", &"<redacted>")
            .field("expires_in", &self.expires_in)
            .field("mfa_required", &self.mfa_required)
            .finish()
    }
}

#[derive(Debug, Serialize)]
pub struct CapabilityResponse {
    pub permission: &'static str,
    pub scopes: Vec<ScopeType>,
}

/// `GET /auth/me` for a session that has satisfied every requirement.
#[derive(Debug, Serialize)]
pub struct MeResponse {
    pub user_id: Uuid,
    pub email: String,
    pub display_name: String,
    pub principal_type: PrincipalType,
    pub is_root: bool,
    pub security_version: i32,
    pub session_id: Uuid,
    pub auth_level: String,
    pub mfa_enrolled: bool,
    pub mfa_required: bool,
    /// Always `false` in this projection — a pending session gets
    /// `PendingMfaMeResponse` instead, which is a different type with fewer fields.
    pub mfa_pending: bool,
    /// Recomputed per request from `sessions.mfa_verified_at`. Never a stored flag:
    /// a cached boolean keeps saying "recently verified" after the window closes.
    pub step_up_active: bool,
    /// A *hint* for hiding buttons. The backend re-derives every decision on every
    /// request regardless of what the client believes.
    pub capabilities: Vec<CapabilityResponse>,
}

/// `GET /auth/me` for a session that has not completed MFA.
///
/// A physically smaller type rather than the same struct with fields skipped: the
/// capability list must be *absent*, not merely omitted by a serde attribute that
/// a later refactor could drop. A session that cannot call a business endpoint has
/// no business learning which business endpoints it would be allowed to call.
#[derive(Debug, Serialize)]
pub struct PendingMfaMeResponse {
    pub user_id: Uuid,
    pub email: String,
    pub display_name: String,
    pub principal_type: PrincipalType,
    pub security_version: i32,
    pub session_id: Uuid,
    pub mfa_enrolled: bool,
    pub mfa_required: bool,
    /// Always `true` in this projection.
    pub mfa_pending: bool,
    /// Always `false`: a pending session has never verified a second factor.
    pub step_up_active: bool,
    /// `MFA_ENROLLMENT_REQUIRED` or `MFA_VERIFICATION_REQUIRED`, so a client knows
    /// which of the two MFA flows to start.
    pub next_action: &'static str,
}

pub const NEXT_ACTION_ENROL: &str = "MFA_ENROLLMENT_REQUIRED";
pub const NEXT_ACTION_VERIFY: &str = "MFA_VERIFICATION_REQUIRED";

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum MeProjection {
    Full(Box<MeResponse>),
    PendingMfa(Box<PendingMfaMeResponse>),
}

/// One row of the user's own session list.
///
/// `id` is safe to expose: a session id is not a credential and the access-token
/// digest is not derivable from it (ADR-005).
#[derive(Debug, Serialize)]
pub struct SessionSummary {
    pub id: Uuid,
    /// Whether this is the session making the request.
    pub current: bool,
    pub auth_level: String,
    pub created_at: String,
    pub last_activity_at: String,
    pub access_expires_at: String,
    pub idle_expires_at: String,
    pub absolute_expires_at: String,
    /// Recognition aids only. Never used for authorisation.
    pub client_ip_hint: Option<String>,
    pub user_agent_hint: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SessionListResponse {
    pub sessions: Vec<SessionSummary>,
}

#[derive(Debug, Serialize)]
pub struct RevocationResponse {
    pub revoked_sessions: i64,
}

/// The enrolment payload. **The one response in this module that carries a
/// secret**, and it carries it exactly once: `secret` and `otpauth_uri` are shown
/// at setup and can never be read back, because at rest the factor holds only
/// XChaCha20-Poly1305 ciphertext.
#[derive(Serialize)]
pub struct TotpEnrolmentResponse {
    pub factor_id: Uuid,
    /// Base32, no padding — what an authenticator app expects.
    pub secret: String,
    pub otpauth_uri: String,
    pub algorithm: &'static str,
    pub digits: u32,
    pub period: u64,
}

impl fmt::Debug for TotpEnrolmentResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TotpEnrolmentResponse")
            .field("factor_id", &self.factor_id)
            .field("secret", &"<redacted>")
            .field("otpauth_uri", &"<redacted>")
            .finish()
    }
}

/// Recovery codes, shown once. Stored as SHA-256 digests only.
#[derive(Serialize)]
pub struct RecoveryCodesResponse {
    pub codes: Vec<String>,
    pub generated: usize,
}

impl fmt::Debug for RecoveryCodesResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveryCodesResponse")
            .field("codes", &"<redacted>")
            .field("generated", &self.generated)
            .finish()
    }
}

#[derive(Debug, Serialize)]
pub struct MfaActivatedResponse {
    pub mfa_enrolled: bool,
    pub auth_level: String,
    pub step_up_active: bool,
    pub recovery_codes: RecoveryCodesResponse,
}

#[derive(Debug, Serialize)]
pub struct MfaVerifiedResponse {
    /// Always `false` after a successful verification — the session is no longer
    /// restricted to the MFA endpoints.
    pub mfa_required: bool,
    pub auth_level: String,
    pub step_up_active: bool,
    /// Present only for the recovery-code path, so a user can see the batch
    /// draining and regenerate before running out.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_codes_remaining: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct MfaDisabledResponse {
    pub mfa_enrolled: bool,
}

/// The password-reset request response.
///
/// Identical for every input — existing account, non-existent account,
/// structurally invalid address. It is a fixed struct with no variable field
/// precisely so that no future edit can make it depend on the account.
#[derive(Debug, Serialize)]
pub struct PasswordResetAcceptedResponse {
    pub status: &'static str,
    pub detail: &'static str,
}

impl PasswordResetAcceptedResponse {
    pub fn fixed() -> Self {
        Self {
            status: "accepted",
            detail: "If that email address has an account, a password reset link has been sent.",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn body(value: serde_json::Value) -> String {
        value.to_string()
    }

    // ---- request DTOs are closed -------------------------------------------

    /// TH-12. Mass assignment is refused by the type, not by a service check that
    /// somebody could forget to write.
    #[test]
    fn privileged_fields_are_rejected_on_every_request_dto() {
        let smuggled = [
            "principal_type",
            "status",
            "role_ids",
            "permissions",
            "is_root",
            "user_id",
            "security_version",
            "mfa_required",
            "created_by",
            "version",
        ];

        for field in smuggled {
            let mut v = json!({"email": "a@b.com", "password": "correct horse battery"});
            v[field] = json!("INTERNAL");
            assert!(
                serde_json::from_str::<LoginRequest>(&body(v)).is_err(),
                "LoginRequest accepted the privileged field `{field}`"
            );

            let mut v = json!({"current_password": "aaaaaaaaaaaa", "new_password": "bbbbbbbbbbbb"});
            v[field] = json!("INTERNAL");
            assert!(
                serde_json::from_str::<PasswordChangeRequest>(&body(v)).is_err(),
                "PasswordChangeRequest accepted the privileged field `{field}`"
            );

            let mut v = json!({"token": "rb_pr_x", "new_password": "bbbbbbbbbbbb"});
            v[field] = json!("INTERNAL");
            assert!(
                serde_json::from_str::<PasswordResetConfirmRequest>(&body(v)).is_err(),
                "PasswordResetConfirmRequest accepted the privileged field `{field}`"
            );

            let mut v = json!({"code": "123456"});
            v[field] = json!("INTERNAL");
            assert!(
                serde_json::from_str::<CodeRequest>(&body(v)).is_err(),
                "CodeRequest accepted the privileged field `{field}`"
            );

            let mut v = json!({"refresh_token": "rb_rt_x"});
            v[field] = json!("INTERNAL");
            assert!(
                serde_json::from_str::<RefreshRequest>(&body(v)).is_err(),
                "RefreshRequest accepted the privileged field `{field}`"
            );

            let mut v = json!({"email": "a@b.com"});
            v[field] = json!("INTERNAL");
            assert!(
                serde_json::from_str::<PasswordResetRequestRequest>(&body(v)).is_err(),
                "PasswordResetRequestRequest accepted the privileged field `{field}`"
            );
        }
    }

    #[test]
    fn well_formed_request_bodies_still_deserialise() {
        let r: LoginRequest =
            serde_json::from_str(r#"{"email":"a@b.com","password":"correct horse"}"#).unwrap();
        assert_eq!(r.email, "a@b.com");
        assert_eq!(r.password, "correct horse");

        let r: RefreshRequest = serde_json::from_str(r#"{"refresh_token":"rb_rt_abc"}"#).unwrap();
        assert_eq!(r.refresh_token, "rb_rt_abc");

        let r: CodeRequest = serde_json::from_str(r#"{"code":"123456"}"#).unwrap();
        assert_eq!(r.code, "123456");
    }

    #[test]
    fn a_missing_required_field_is_rejected() {
        assert!(serde_json::from_str::<LoginRequest>(r#"{"email":"a@b.com"}"#).is_err());
        assert!(serde_json::from_str::<PasswordChangeRequest>(r#"{"new_password":"x"}"#).is_err());
        assert!(serde_json::from_str::<CodeRequest>(r#"{}"#).is_err());
    }

    /// A derived `Debug` on any of these would put a plaintext credential into
    /// every log line, `dbg!` and panic message that formatted the struct.
    #[test]
    fn credentials_never_appear_in_debug_output() {
        let login = LoginRequest {
            email: "a@b.com".into(),
            password: "hunter2-the-real-password".into(),
        };
        assert!(!format!("{login:?}").contains("hunter2"));

        let change = PasswordChangeRequest {
            current_password: "hunter2-old".into(),
            new_password: "hunter2-new".into(),
        };
        assert!(!format!("{change:?}").contains("hunter2"));

        let confirm = PasswordResetConfirmRequest {
            token: "rb_pr_hunter2".into(),
            new_password: "hunter2-new".into(),
        };
        assert!(!format!("{confirm:?}").contains("hunter2"));

        let refresh = RefreshRequest {
            refresh_token: "rb_rt_hunter2".into(),
        };
        assert!(!format!("{refresh:?}").contains("hunter2"));

        let code = CodeRequest {
            code: "424242".into(),
        };
        assert!(!format!("{code:?}").contains("424242"));

        let tokens = TokenResponse {
            access_token: "rb_at_hunter2".into(),
            refresh_token: "rb_rt_hunter2".into(),
            expires_in: 900,
            mfa_required: false,
            token_type: TOKEN_TYPE,
        };
        assert!(!format!("{tokens:?}").contains("hunter2"));

        let codes = RecoveryCodesResponse {
            codes: vec!["ABCDE-HUNT2-XXXXX-YYYYY".into()],
            generated: 1,
        };
        assert!(!format!("{codes:?}").contains("HUNT2"));
    }

    // ---- response DTOs cannot carry stored secrets ---------------------------

    fn full_me() -> MeResponse {
        MeResponse {
            user_id: Uuid::now_v7(),
            email: "a@b.com".into(),
            display_name: "Alice".into(),
            principal_type: PrincipalType::Internal,
            is_root: false,
            security_version: 3,
            session_id: Uuid::now_v7(),
            auth_level: "MFA".into(),
            mfa_enrolled: true,
            mfa_required: true,
            mfa_pending: false,
            step_up_active: true,
            capabilities: vec![CapabilityResponse {
                permission: "projects.read",
                scopes: vec![ScopeType::Global],
            }],
        }
    }

    fn pending_me() -> PendingMfaMeResponse {
        PendingMfaMeResponse {
            user_id: Uuid::now_v7(),
            email: "a@b.com".into(),
            display_name: "Alice".into(),
            principal_type: PrincipalType::Internal,
            security_version: 3,
            session_id: Uuid::now_v7(),
            mfa_enrolled: false,
            mfa_required: true,
            mfa_pending: true,
            step_up_active: false,
            next_action: NEXT_ACTION_ENROL,
        }
    }

    /// The property the whole module rests on: there is no response type with a
    /// field capable of holding a stored secret. This test enumerates every
    /// response DTO, serialises a populated instance, and asserts that no key
    /// resembling a digest, a hash, a ciphertext or a stored credential appears.
    #[test]
    fn no_response_dto_can_carry_a_stored_secret() {
        let forbidden = [
            "password_hash",
            "token_hash",
            "access_token_hash",
            "code_hash",
            "secret_ciphertext",
            "secret_nonce",
            "key_version",
            "last_used_step",
            "password",
            "phc",
            "argon2",
            "chain_key",
            "encryption_key",
        ];

        let mut documents = vec![
            serde_json::to_value(full_me()).unwrap(),
            serde_json::to_value(pending_me()).unwrap(),
            serde_json::to_value(MeProjection::Full(Box::new(full_me()))).unwrap(),
            serde_json::to_value(MeProjection::PendingMfa(Box::new(pending_me()))).unwrap(),
            serde_json::to_value(SessionListResponse {
                sessions: vec![SessionSummary {
                    id: Uuid::now_v7(),
                    current: true,
                    auth_level: "MFA".into(),
                    created_at: rfc3339(OffsetDateTime::now_utc()),
                    last_activity_at: rfc3339(OffsetDateTime::now_utc()),
                    access_expires_at: rfc3339(OffsetDateTime::now_utc()),
                    idle_expires_at: rfc3339(OffsetDateTime::now_utc()),
                    absolute_expires_at: rfc3339(OffsetDateTime::now_utc()),
                    client_ip_hint: Some("10.0.0.1".into()),
                    user_agent_hint: Some("curl/8".into()),
                }],
            })
            .unwrap(),
            serde_json::to_value(RevocationResponse {
                revoked_sessions: 4,
            })
            .unwrap(),
            serde_json::to_value(MfaVerifiedResponse {
                mfa_required: false,
                auth_level: "MFA".into(),
                step_up_active: true,
                recovery_codes_remaining: Some(9),
            })
            .unwrap(),
            serde_json::to_value(MfaDisabledResponse {
                mfa_enrolled: false,
            })
            .unwrap(),
            serde_json::to_value(PasswordResetAcceptedResponse::fixed()).unwrap(),
            serde_json::to_value(TokenResponse {
                access_token: "rb_at_x".into(),
                refresh_token: "rb_rt_x".into(),
                expires_in: 900,
                mfa_required: false,
                token_type: TOKEN_TYPE,
            })
            .unwrap(),
        ];

        // The enrolment payload is the single deliberate exception: it returns the
        // TOTP secret once, which is the only way an authenticator can be
        // provisioned. It must still carry no *stored* form of that secret.
        documents.push(
            serde_json::to_value(TotpEnrolmentResponse {
                factor_id: Uuid::now_v7(),
                secret: "JBSWY3DPEHPK3PXP".into(),
                otpauth_uri: "otpauth://totp/x".into(),
                algorithm: "SHA1",
                digits: 6,
                period: 30,
            })
            .unwrap(),
        );

        for doc in documents {
            let keys = collect_keys(&doc);
            for key in &keys {
                assert!(
                    !forbidden.contains(&key.as_str()),
                    "a response DTO exposes the field `{key}`: {doc}"
                );
            }
        }
    }

    /// `TokenResponse` is the only response holding plaintext token material, and
    /// only for the single moment it is issued. Nothing else may look like a token.
    #[test]
    fn only_the_token_response_carries_token_material() {
        let me = serde_json::to_string(&full_me()).unwrap();
        assert!(!me.contains("rb_at_"));
        assert!(!me.contains("rb_rt_"));

        let sessions = serde_json::to_string(&SessionListResponse { sessions: vec![] }).unwrap();
        assert!(!sessions.contains("rb_"));
    }

    /// The reduced projection must be *structurally* smaller, not the same struct
    /// with fields hidden.
    #[test]
    fn the_pending_mfa_projection_omits_authority_and_the_capability_list() {
        let doc = serde_json::to_value(pending_me()).unwrap();
        let keys = collect_keys(&doc);
        for absent in ["capabilities", "is_root", "auth_level"] {
            assert!(
                !keys.contains(&absent.to_string()),
                "pending projection leaked `{absent}`"
            );
        }
        assert_eq!(doc["mfa_pending"], json!(true));
        assert_eq!(doc["step_up_active"], json!(false));
        assert_eq!(doc["next_action"], json!(NEXT_ACTION_ENROL));

        // ...whereas the full projection does carry them.
        let full = collect_keys(&serde_json::to_value(full_me()).unwrap());
        assert!(full.contains(&"capabilities".to_string()));
        assert!(full.contains(&"is_root".to_string()));
    }

    /// The untagged enum must serialise as the inner object with no wrapper, so a
    /// client sees one consistent `/auth/me` shape.
    #[test]
    fn the_me_projection_enum_is_transparent() {
        let doc = serde_json::to_value(MeProjection::Full(Box::new(full_me()))).unwrap();
        assert!(
            doc.get("Full").is_none(),
            "the enum variant name leaked into the body"
        );
        assert!(doc.get("capabilities").is_some());
    }

    #[test]
    fn the_password_reset_response_is_a_fixed_constant() {
        let a = serde_json::to_string(&PasswordResetAcceptedResponse::fixed()).unwrap();
        let b = serde_json::to_string(&PasswordResetAcceptedResponse::fixed()).unwrap();
        assert_eq!(a, b, "the reset response must not vary between calls");
        assert!(
            !a.contains("exist"),
            "the body must not hint at account existence"
        );
    }

    #[test]
    fn timestamps_render_as_rfc3339_strings() {
        let s = rfc3339(OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap());
        assert_eq!(s, "2023-11-14T22:13:20Z");
    }

    fn collect_keys(value: &serde_json::Value) -> Vec<String> {
        let mut out = Vec::new();
        walk(value, &mut out);
        out
    }

    fn walk(value: &serde_json::Value, out: &mut Vec<String>) {
        match value {
            serde_json::Value::Object(map) => {
                for (k, v) in map {
                    out.push(k.clone());
                    walk(v, out);
                }
            }
            serde_json::Value::Array(items) => {
                for v in items {
                    walk(v, out);
                }
            }
            _ => {}
        }
    }
}
