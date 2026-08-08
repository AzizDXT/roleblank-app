//! Bootstrap request and response types.
//!
//! The request type is the security-relevant one. It carries four fields and
//! **cannot** carry a fifth: `deny_unknown_fields` turns
//! `{"principal_type":"CLIENT"}` or `{"is_root":true}` into a `400` before the
//! service is entered, which is the mass-assignment defence (TH-12). The owner's
//! envelope — `INTERNAL`, `ACTIVE`, `mfa_required` — is written as SQL literals in
//! the service and is not derived from anything the caller sent.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// Render a timestamp for the wire.
///
/// RFC 3339 rather than `time`'s default serde representation, which is an
/// implementation detail of the crate rather than a stable API contract. A
/// formatting failure yields an empty string rather than a panic: a clock value
/// that cannot be formatted must not take the process down.
pub(crate) fn rfc3339(value: OffsetDateTime) -> String {
    value
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

/// `GET /api/v1/bootstrap/status`.
///
/// One boolean, and deliberately nothing else. This endpoint answers to anonymous
/// internet traffic on a system that has no owner yet, so every additional field —
/// version, hostname, user count, build id — would be free reconnaissance handed
/// to whoever finds the deployment first.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct BootstrapStatusResponse {
    pub initialized: bool,
}

/// `POST /api/v1/bootstrap/root`.
///
/// The email and the password come from the caller and are never defaulted: a
/// hardcoded owner credential would be a backdoor that survives every deployment
/// of this image.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapRootRequest {
    /// Compared against `RB_BOOTSTRAP_SECRET` in constant time. Never logged,
    /// never audited, never echoed.
    pub bootstrap_secret: String,
    pub email: String,
    pub display_name: String,
    pub password: String,
}

/// Hand-written so that a `#[derive(Debug)]` on this struct — or on anything
/// containing it — cannot print the operator secret or the owner's password into a
/// log line or a panic message.
impl std::fmt::Debug for BootstrapRootRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootstrapRootRequest")
            .field("bootstrap_secret", &"<redacted>")
            .field("email", &self.email)
            .field("display_name", &self.display_name)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// What the operator gets back. No token, no session: the owner must log in
/// through the ordinary authentication path and enrol a second factor before they
/// can do anything, which is what makes bootstrap incapable of minting a
/// privileged session by itself.
#[derive(Debug, Serialize)]
pub struct BootstrapRootResponse {
    pub user_id: Uuid,
    pub email: String,
    pub display_name: String,
    /// Always `true`. The owner is created in the `MFA_ENROLMENT_REQUIRED` state
    /// (`mfa_required = true`, `mfa_enrolled = false`), so their first session can
    /// reach nothing but the MFA endpoints.
    pub mfa_enrolment_required: bool,
    pub initialized_at: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(body: &str) -> Result<BootstrapRootRequest, serde_json::Error> {
        serde_json::from_str(body)
    }

    #[test]
    fn a_well_formed_request_parses() {
        let r = parse(
            r#"{"bootstrap_secret":"s","email":"owner@example.com",
                "display_name":"Owner","password":"correct horse battery staple"}"#,
        )
        .expect("valid body");
        assert_eq!(r.email, "owner@example.com");
    }

    /// The mass-assignment defence. Every one of these fields would, if honoured,
    /// let the caller choose their own security envelope.
    #[test]
    fn privileged_fields_are_refused_by_deny_unknown_fields() {
        for injected in [
            r#""principal_type":"CLIENT""#,
            r#""principal_type":"INTERNAL""#,
            r#""role_ids":["00000000-0000-7000-8000-000000000001"]"#,
            r#""status":"ACTIVE""#,
            r#""is_root":true"#,
            r#""permissions":["settings.security.write"]"#,
            r#""mfa_required":false"#,
            r#""security_version":99"#,
            r#""id":"00000000-0000-7000-8000-000000000001""#,
        ] {
            let body = format!(
                r#"{{"bootstrap_secret":"s","email":"a@b.com","display_name":"A",
                     "password":"correct horse battery staple",{injected}}}"#
            );
            assert!(
                parse(&body).is_err(),
                "accepted a request carrying {injected}"
            );
        }
    }

    #[test]
    fn every_field_is_mandatory() {
        for body in [
            r#"{"email":"a@b.com","display_name":"A","password":"correct horse battery"}"#,
            r#"{"bootstrap_secret":"s","display_name":"A","password":"correct horse battery"}"#,
            r#"{"bootstrap_secret":"s","email":"a@b.com","password":"correct horse battery"}"#,
            r#"{"bootstrap_secret":"s","email":"a@b.com","display_name":"A"}"#,
            r#"{}"#,
        ] {
            assert!(parse(body).is_err(), "accepted an incomplete body: {body}");
        }
    }

    #[test]
    fn debug_never_reveals_the_secret_or_the_password() {
        let r = parse(
            r#"{"bootstrap_secret":"hunter2-operator-secret","email":"a@b.com",
                "display_name":"A","password":"hunter2-owner-password"}"#,
        )
        .expect("valid body");
        let rendered = format!("{r:?}");
        assert!(
            !rendered.contains("hunter2"),
            "a credential leaked through Debug: {rendered}"
        );
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn the_status_response_carries_exactly_one_field() {
        let json = serde_json::to_value(BootstrapStatusResponse { initialized: false })
            .expect("serialisable");
        let object = json.as_object().expect("object");
        assert_eq!(
            object.len(),
            1,
            "the anonymous status endpoint must disclose nothing else"
        );
        assert_eq!(object["initialized"], serde_json::json!(false));
    }

    #[test]
    fn the_root_response_never_contains_a_credential() {
        let body = serde_json::to_string(&BootstrapRootResponse {
            user_id: Uuid::now_v7(),
            email: "owner@example.com".into(),
            display_name: "Owner".into(),
            mfa_enrolment_required: true,
            initialized_at: rfc3339(OffsetDateTime::UNIX_EPOCH),
        })
        .expect("serialisable");
        for forbidden in ["password", "secret", "hash", "token", "argon2"] {
            assert!(
                !body.contains(forbidden),
                "`{forbidden}` appeared in the response body"
            );
        }
    }

    #[test]
    fn timestamps_render_as_rfc3339() {
        assert_eq!(rfc3339(OffsetDateTime::UNIX_EPOCH), "1970-01-01T00:00:00Z");
    }
}
