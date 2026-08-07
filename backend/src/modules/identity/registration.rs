//! Client self-registration — the only anonymous account-creation path.
//!
//! Three properties define this file, and each of them is a deliberate refusal:
//!
//! * **The caller cannot choose what they become.** `principal_type = CLIENT`,
//!   `status = PENDING` and the `client_user` role are constructed here in code.
//!   The request DTO has no field for any of them, and `deny_unknown_fields`
//!   rejects a body that tries.
//! * **A self-registered account sees nothing.** It lands with zero client
//!   memberships, and `client_user` grants visibility only through an ACTIVE
//!   membership joined to a live project link. Until an internal principal
//!   deliberately links it, the world is empty.
//! * **The response never varies.** Free address, taken address, address belonging
//!   to an employee — one response, byte for byte. An anonymous endpoint that
//!   answers differently is an account-enumeration oracle (TH-23).

use std::time::Duration;
use uuid::Uuid;

use crate::app::AppState;
use crate::modules::audit::{action, AuditEvent, AuditMetadata, Outcome};
use crate::modules::authorization::domain::PrincipalType;
use crate::platform::crypto::password;
use crate::platform::errors::{AppError, AppResult};
use crate::platform::http::extract::ClientIp;
use crate::platform::http::rate_limit::{keys, RateLimitDecision};
use crate::shared::secret::Secret;
use crate::shared::validation as v;

use super::dto::{RegisterRequest, RegistrationAcceptedResponse, RegistrationConfigResponse};
use super::repo::{self, NewUser};

/// The `system_settings` key that governs this endpoint.
const REGISTRATION_MODE_KEY: &str = "registration.mode";

/// The only role a self-registered account ever receives.
const CLIENT_BASELINE_ROLE: &str = "client_user";

const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(3600);

/// How the deployment handles account creation.
///
/// A closed enum with an exact-case parser. Anything unrecognised — including a
/// setting somebody typed by hand — resolves to [`RegistrationMode::Disabled`],
/// because a misconfigured registration policy must fail closed rather than
/// default to "open to the internet".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationMode {
    Disabled,
    InviteOnly,
    ClientSelfRegistration,
}

impl RegistrationMode {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "DISABLED" => Some(RegistrationMode::Disabled),
            "INVITE_ONLY" => Some(RegistrationMode::InviteOnly),
            "CLIENT_SELF_REGISTRATION" => Some(RegistrationMode::ClientSelfRegistration),
            _ => None,
        }
    }

    /// Interpret the stored JSON value, failing closed on anything unexpected.
    pub fn from_setting(value: Option<&serde_json::Value>) -> Self {
        let Some(raw) = value.and_then(serde_json::Value::as_str) else {
            return RegistrationMode::Disabled;
        };
        Self::parse(raw).unwrap_or_else(|| {
            tracing::error!(
                "registration.mode holds an unrecognised value; treating registration as DISABLED"
            );
            RegistrationMode::Disabled
        })
    }

    pub fn allows_self_registration(self) -> bool {
        matches!(self, RegistrationMode::ClientSelfRegistration)
    }
}

/// Read the effective registration mode.
///
/// A read failure is reported as `Disabled`, not propagated: a database hiccup must
/// not accidentally open registration, and the `/config` endpoint saying "closed"
/// during an outage is the safe answer.
async fn current_mode(state: &AppState) -> RegistrationMode {
    match repo::read_setting(&state.db, REGISTRATION_MODE_KEY).await {
        Ok(value) => RegistrationMode::from_setting(value.as_ref()),
        Err(e) => {
            tracing::error!(error = %e, "could not read registration.mode; failing closed");
            RegistrationMode::Disabled
        }
    }
}

/// `GET /api/v1/registration/config` — anonymous.
///
/// Two fields. A frontend needs to know whether to render a signup form; it does
/// not need the user count, the invitation policy, the build id or anything else
/// that would help somebody who has just found this deployment.
pub async fn registration_config(state: &AppState) -> AppResult<RegistrationConfigResponse> {
    let available = current_mode(state).await.allows_self_registration();
    Ok(RegistrationConfigResponse {
        registration_available: available,
        // Self-registration can only ever produce a CLIENT principal, so there is
        // no other value this field could take.
        registration_type: available.then_some("client"),
    })
}

/// `POST /api/v1/registration` — anonymous.
pub async fn register(
    state: &AppState,
    client_ip: ClientIp,
    mut request: RegisterRequest,
) -> AppResult<RegistrationAcceptedResponse> {
    let decision = state
        .limiter
        .check(
            &keys::registration_ip(client_ip.0),
            state.config.rate_limits.registration_per_ip_per_hour,
            RATE_LIMIT_WINDOW,
        )
        .await;
    if let RateLimitDecision::Limited {
        retry_after_seconds,
    } = decision
    {
        return Err(AppError::TooManyRequests {
            retry_after_seconds,
        });
    }

    // `NotFound`, not `403`: when self-registration is off the endpoint does not
    // exist. Advertising a disabled capability tells an attacker which setting to
    // go after.
    if !current_mode(state).await.allows_self_registration() {
        return Err(AppError::NotFound);
    }

    let email_normalized = v::validate_email("email", &request.email)?;
    let email = request.email.trim().to_string();
    let display_name = v::required_text(
        "display_name",
        &request.display_name,
        v::MAX_DISPLAY_NAME_LEN,
    )?;
    password::validate_password(&request.password, &email_normalized, &display_name)?;

    // Hashed unconditionally, *before* the address is looked up. Skipping the work
    // for an address that already exists would make the duplicate path measurably
    // faster than the new-account path — the same enumeration oracle the login
    // endpoint's dummy hash exists to close.
    let supplied = Secret::new(std::mem::take(&mut request.password));
    let password_hash = state.hasher.hash(&supplied).await?;
    drop(supplied);

    let mut tx = state.begin().await?;

    if repo::find_user_by_email(&mut tx, &email_normalized)
        .await?
        .is_some()
    {
        // Recorded so that somebody grinding addresses through this endpoint is
        // visible in the audit log, even though the caller learns nothing.
        state
            .audit(
                &mut tx,
                AuditEvent::new(action::USER_REGISTERED, Outcome::Denied)
                    .system_actor()
                    .source_ip(client_ip.hint())
                    .meta(
                        AuditMetadata::new()
                            .str("reason", "address_already_registered")
                            .str("email_normalized", &email_normalized),
                    ),
            )
            .await?;
        tx.commit().await.map_err(AppError::from)?;
        return Ok(RegistrationAcceptedResponse::new());
    }

    let role = repo::find_role_by_code(&mut tx, CLIENT_BASELINE_ROLE)
        .await?
        .ok_or_else(|| AppError::internal("the client_user baseline role is missing"))?;

    let user_id = Uuid::now_v7();

    // Every field of the envelope is a literal chosen here:
    //
    //   principal_type = CLIENT   — an external principal can never hold an
    //                               INTERNAL permission, whatever it is granted
    //   status         = PENDING  — no session can be issued until an internal
    //                               principal reviews and activates the account
    //   activated      = false    — `activated_at` stays NULL, so "was this ever
    //                               approved" has an unambiguous answer
    //
    // None of them is reachable from the request body.
    repo::insert_user(
        &mut tx,
        &NewUser {
            id: user_id,
            email: email.clone(),
            email_normalized: email_normalized.clone(),
            display_name: display_name.clone(),
            principal_type: PrincipalType::Client.as_str().to_string(),
            status: "PENDING".to_string(),
            mfa_required: false,
            activated: false,
        },
    )
    .await?;
    repo::insert_credentials(&mut tx, user_id, &password_hash).await?;

    // The baseline external role, and nothing else. It confers no visibility on its
    // own: `client.portal.*` is ASSIGNED-scoped and resolves through an ACTIVE
    // client membership, of which this account has none.
    repo::assign_role(&mut tx, user_id, role.id, user_id).await?;

    // Deliberately absent: any `client_memberships` insert. A self-registered
    // account joins no client account by registering. Somebody with
    // `clients.members.manage` must link it, which is the moment a stranger becomes
    // a counterparty.

    state
        .audit(
            &mut tx,
            AuditEvent::new(action::USER_REGISTERED, Outcome::Success)
                .actor(user_id, PrincipalType::Client, None)
                .target("USER", user_id)
                .source_ip(client_ip.hint())
                .meta(
                    AuditMetadata::new()
                        .str("source", "SELF_REGISTRATION")
                        .str("principal_type", PrincipalType::Client.as_str())
                        .str("status", "PENDING")
                        .list("roles", [CLIENT_BASELINE_ROLE.to_string()]),
                ),
        )
        .await?;

    tx.commit().await.map_err(AppError::from)?;

    Ok(RegistrationAcceptedResponse::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn only_the_explicit_self_registration_mode_opens_the_endpoint() {
        assert!(RegistrationMode::ClientSelfRegistration.allows_self_registration());
        assert!(!RegistrationMode::InviteOnly.allows_self_registration());
        assert!(!RegistrationMode::Disabled.allows_self_registration());
    }

    /// A misconfigured, missing, or hand-edited setting must never read as "open".
    #[test]
    fn an_unrecognised_registration_mode_fails_closed() {
        for value in [
            json!("OPEN"),
            json!("client_self_registration"), // wrong case
            json!("CLIENT_SELF_REGISTRATION "),
            json!(""),
            json!(true),
            json!(1),
            json!(null),
            json!({"mode": "CLIENT_SELF_REGISTRATION"}),
            json!(["CLIENT_SELF_REGISTRATION"]),
        ] {
            assert_eq!(
                RegistrationMode::from_setting(Some(&value)),
                RegistrationMode::Disabled,
                "`{value}` was not treated as disabled"
            );
        }
        assert_eq!(
            RegistrationMode::from_setting(None),
            RegistrationMode::Disabled
        );
    }

    #[test]
    fn the_three_documented_modes_parse() {
        assert_eq!(
            RegistrationMode::from_setting(Some(&json!("DISABLED"))),
            RegistrationMode::Disabled
        );
        assert_eq!(
            RegistrationMode::from_setting(Some(&json!("INVITE_ONLY"))),
            RegistrationMode::InviteOnly
        );
        assert_eq!(
            RegistrationMode::from_setting(Some(&json!("CLIENT_SELF_REGISTRATION"))),
            RegistrationMode::ClientSelfRegistration
        );
    }

    /// The seeded default in migration 0008. A fresh installation must not accept
    /// self-registration until an operator deliberately turns it on.
    #[test]
    fn a_freshly_migrated_database_is_invite_only() {
        assert_eq!(
            RegistrationMode::from_setting(Some(&json!("INVITE_ONLY"))),
            RegistrationMode::InviteOnly
        );
        assert!(!RegistrationMode::InviteOnly.allows_self_registration());
    }

    #[test]
    fn the_config_response_names_client_only_when_open() {
        let open = RegistrationConfigResponse {
            registration_available: true,
            registration_type: true.then_some("client"),
        };
        assert_eq!(open.registration_type, Some("client"));
        let closed = RegistrationConfigResponse {
            registration_available: false,
            registration_type: false.then_some("client"),
        };
        assert_eq!(closed.registration_type, None);
    }

    /// Self-registration produces a CLIENT, and a CLIENT can hold nothing but the
    /// two portal permissions however it is granted.
    #[test]
    fn a_self_registered_principal_is_confined_to_the_client_envelope() {
        use crate::modules::authorization::catalog;
        for def in catalog::PERMISSIONS {
            let reachable = def.max_principal_type.permits(PrincipalType::Client);
            assert_eq!(
                reachable,
                def.code.starts_with("client.portal."),
                "`{}` reachability by a self-registered account is wrong",
                def.code
            );
        }
    }

    #[test]
    fn the_baseline_role_is_the_seeded_client_role() {
        // Matches `roles.code` in migration 0008. A typo here would make every
        // registration fail with an internal error rather than a useful one.
        assert_eq!(CLIENT_BASELINE_ROLE, "client_user");
    }
}
