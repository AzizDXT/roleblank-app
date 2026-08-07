//! TOTP enrolment, verification, recovery codes, and disablement.
//!
//! Three controls carry this module and are all easy to lose in a refactor:
//!
//!   * The TOTP secret is sealed with the **owning user's id as associated data**.
//!     An attacker with `UPDATE` on `mfa_factors` cannot move one user's encrypted
//!     factor onto another's row, because the AAD would no longer authenticate.
//!   * `last_used_step` is read under `FOR UPDATE` and advanced on every success.
//!     Without the lock, two concurrent verifications of the same code both read
//!     the same watermark and both succeed — the exact replay the column exists to
//!     stop.
//!   * A `TotpVerdict::Replayed` is audited as a **security event** and returns the
//!     same generic failure as a typo. The client learns nothing; the operator
//!     learns everything.

use serde_json::Value;
use sqlx::{Postgres, Transaction};
use std::time::Duration as StdDuration;
use uuid::Uuid;

use crate::app::AppState;
use crate::modules::audit::{action, AuditEvent, AuditMetadata, Outcome};
use crate::modules::authentication::principal::Principal;
use crate::modules::authentication::service::{enforce_limit, ClientHints};
use crate::modules::authentication::{dto, repo, sessions};
use crate::platform::crypto::{aead, tokens, totp};
use crate::platform::errors::{AppError, AppResult};
use crate::platform::http::rate_limit::keys;

const MINUTE: StdDuration = StdDuration::from_secs(60);

/// Ten codes is the industry norm: enough that losing a few to a bad printout is
/// survivable, few enough that the set stays memorable as a single sheet.
const RECOVERY_CODE_COUNT: usize = 10;

const STATUS_PENDING: &str = "PENDING";
const STATUS_ACTIVE: &str = "ACTIVE";

/// Both MFA limiters at once.
///
/// Per session **and** per account, because each defeats a different attack: a
/// per-session limit alone is escaped by logging in again, and a per-account limit
/// alone lets one compromised session burn another's budget.
async fn enforce_mfa_limits(state: &AppState, principal: &Principal) -> AppResult<()> {
    let quota = state.config.rate_limits.mfa_per_session_per_minute;
    enforce_limit(
        state,
        &keys::mfa_session(principal.session.session_id),
        quota,
        MINUTE,
    )
    .await?;
    enforce_limit(
        state,
        &keys::mfa_account(principal.user_id()),
        quota,
        MINUTE,
    )
    .await
}

fn now_unix() -> AppResult<u64> {
    u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp())
        .map_err(|_| AppError::Internal("system clock is before the Unix epoch".into()))
}

/// Rebuild the sealed value from its stored columns.
fn sealed_from(row: &repo::FactorRow) -> AppResult<aead::SealedSecret> {
    Ok(aead::SealedSecret {
        ciphertext: row.secret_ciphertext.clone(),
        nonce: row.secret_nonce.clone(),
        key_version: u32::try_from(row.key_version)
            .map_err(|_| AppError::Internal("stored key_version is out of range".into()))?,
    })
}

/// Audit a failed second-factor attempt.
///
/// Deliberately records the *kind* of failure. `MFA_REPLAY_DETECTED` means someone
/// presented a correct code for a step already consumed, which is evidence of
/// interception rather than of a user fumbling their phone.
async fn audit_mfa_failure(
    state: &AppState,
    tx: &mut Transaction<'_, Postgres>,
    principal: &Principal,
    hints: &ClientHints,
    action_code: &'static str,
    reason: &'static str,
) -> AppResult<()> {
    state
        .audit(
            tx,
            AuditEvent::new(action_code, Outcome::Failure)
                .actor(
                    principal.user_id(),
                    principal.session.principal_type,
                    Some(principal.session.session_id),
                )
                .target("USER", principal.user_id())
                .source_ip(hints.ip_hint.clone())
                .meta(AuditMetadata::new().str("reason", reason)),
        )
        .await
        .map(|_| ())
}

/// Mint a fresh batch of recovery codes, invalidating the previous one.
///
/// Returns the plaintexts for the single response that shows them. Only digests
/// reach the database.
async fn issue_recovery_codes(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
) -> AppResult<Vec<String>> {
    repo::consume_recovery_batch(tx, user_id).await?;

    let batch_id = Uuid::now_v7();
    let mut plaintexts = Vec::with_capacity(RECOVERY_CODE_COUNT);
    for _ in 0..RECOVERY_CODE_COUNT {
        let code = tokens::generate_recovery_code()?;
        repo::insert_recovery_code(tx, Uuid::now_v7(), user_id, batch_id, &code.hash).await?;
        plaintexts.push(code.plaintext.expose().clone());
    }
    Ok(plaintexts)
}

// =============================================================================
// Enrolment
// =============================================================================

/// `POST /auth/mfa/totp/setup`.
///
/// Produces a `PENDING` factor. It becomes `ACTIVE` only once the user proves a
/// correct code, so an interrupted enrolment can never leave an account locked
/// behind a factor nobody has.
pub async fn totp_setup(
    state: &AppState,
    principal: &Principal,
    hints: &ClientHints,
) -> AppResult<dto::TotpEnrolmentResponse> {
    enforce_mfa_limits(state, principal).await?;

    let user_id = principal.user_id();
    let secret = totp::generate_secret()?;

    // The user id as associated data is what binds this ciphertext to this row.
    let sealed = state.keyring.seal(secret.expose(), user_id.as_bytes())?;
    let factor_id = Uuid::now_v7();

    let mut tx = state.begin().await?;

    // Replacing a live factor must not be possible from an ordinary session:
    // otherwise anyone holding a stolen token could move the second factor onto
    // their own authenticator and lock the owner out. Disabling first is the
    // step-up-gated `POST /auth/mfa/disable`.
    if repo::lock_factor(&mut tx, user_id, STATUS_ACTIVE)
        .await?
        .is_some()
    {
        return Err(AppError::conflict(
            "MFA_ALREADY_ENROLLED",
            "An active authenticator is already enrolled. Disable it before enrolling another.",
        ));
    }
    // An abandoned enrolment is replaced rather than blocking a retry. The partial
    // unique index covers only PENDING and ACTIVE, so DISABLED frees the slot.
    repo::disable_factors(&mut tx, user_id, Some(STATUS_PENDING)).await?;

    repo::insert_pending_factor(
        &mut tx,
        repo::NewFactor {
            id: factor_id,
            user_id,
            secret_ciphertext: sealed.ciphertext.clone(),
            secret_nonce: sealed.nonce.clone(),
            key_version: i32::try_from(sealed.key_version)
                .map_err(|_| AppError::Internal("key_version is out of range".into()))?,
            label: hints.user_agent_hint.clone(),
        },
    )
    .await?;

    state
        .audit(
            &mut tx,
            AuditEvent::new(action::MFA_ENROLMENT_STARTED, Outcome::Success)
                .actor(
                    user_id,
                    principal.session.principal_type,
                    Some(principal.session.session_id),
                )
                .target("USER", user_id)
                .source_ip(hints.ip_hint.clone())
                .meta(
                    AuditMetadata::new()
                        .str("factor_type", "TOTP")
                        .id("factor_id", factor_id),
                ),
        )
        .await?;
    tx.commit().await?;

    // The only moment the secret is legible. After this it exists solely as
    // XChaCha20-Poly1305 ciphertext and can never be read back.
    Ok(dto::TotpEnrolmentResponse {
        factor_id,
        secret: totp::encode_secret(&secret).expose().clone(),
        otpauth_uri: totp::provisioning_uri(
            &state.config.security.totp_issuer,
            &principal.session.email,
            &secret,
        )
        .expose()
        .clone(),
        algorithm: "SHA1",
        digits: totp::DIGITS,
        period: totp::STEP_SECONDS,
    })
}

/// `POST /auth/mfa/totp/activate`.
///
/// Proving one correct code both activates the factor and completes MFA for the
/// calling session, so a user enrolling from an `MFA_ENROLLMENT_REQUIRED` state
/// lands in a fully usable session without a second round trip.
pub async fn totp_activate(
    state: &AppState,
    principal: &Principal,
    hints: &ClientHints,
    request: dto::CodeRequest,
) -> AppResult<dto::MfaActivatedResponse> {
    enforce_mfa_limits(state, principal).await?;

    let user_id = principal.user_id();
    let now = now_unix()?;

    let mut tx = state.begin().await?;
    let Some(factor) = repo::lock_factor(&mut tx, user_id, STATUS_PENDING).await? else {
        return Err(AppError::conflict(
            "MFA_NOT_PENDING",
            "There is no enrolment in progress. Start one with /auth/mfa/totp/setup.",
        ));
    };

    let secret = state
        .keyring
        .open(&sealed_from(&factor)?, user_id.as_bytes())?;

    match totp::verify(
        &secret,
        &request.code,
        now,
        factor.last_used_step.map(|s| s as u64),
    ) {
        totp::TotpVerdict::Valid { step } => {
            let step = i64::try_from(step)
                .map_err(|_| AppError::Internal("TOTP step is out of range".into()))?;
            if repo::activate_factor(&mut tx, factor.id, step).await? != 1 {
                return Err(AppError::AuthenticationFailed);
            }
            repo::set_mfa_enrolled(&mut tx, user_id, true).await?;
            repo::mark_mfa_verified(&mut tx, principal.session.session_id).await?;

            let codes = issue_recovery_codes(&mut tx, user_id).await?;

            state
                .audit(
                    &mut tx,
                    AuditEvent::new(action::MFA_ACTIVATED, Outcome::Success)
                        .actor(
                            user_id,
                            principal.session.principal_type,
                            Some(principal.session.session_id),
                        )
                        .target("USER", user_id)
                        .source_ip(hints.ip_hint.clone())
                        .meta(
                            AuditMetadata::new()
                                .id("factor_id", factor.id)
                                .str("factor_type", "TOTP"),
                        ),
                )
                .await?;
            state
                .audit(
                    &mut tx,
                    AuditEvent::new(action::MFA_RECOVERY_CODES_GENERATED, Outcome::Success)
                        .actor(
                            user_id,
                            principal.session.principal_type,
                            Some(principal.session.session_id),
                        )
                        .target("USER", user_id)
                        .meta(AuditMetadata::new().int("count", codes.len() as i64)),
                )
                .await?;
            tx.commit().await?;

            Ok(dto::MfaActivatedResponse {
                mfa_enrolled: true,
                auth_level: sessions::AUTH_LEVEL_MFA.to_string(),
                step_up_active: true,
                recovery_codes: dto::RecoveryCodesResponse {
                    generated: codes.len(),
                    codes,
                },
            })
        }
        totp::TotpVerdict::Replayed => {
            audit_mfa_failure(
                state,
                &mut tx,
                principal,
                hints,
                action::MFA_REPLAY_DETECTED,
                "totp_step_already_consumed",
            )
            .await?;
            tx.commit().await?;
            Err(AppError::AuthenticationFailed)
        }
        totp::TotpVerdict::Invalid => {
            audit_mfa_failure(
                state,
                &mut tx,
                principal,
                hints,
                action::MFA_VERIFICATION_FAILED,
                "totp_invalid_during_activation",
            )
            .await?;
            tx.commit().await?;
            Err(AppError::AuthenticationFailed)
        }
    }
}

// =============================================================================
// Verification
// =============================================================================

/// `POST /auth/mfa/verify`.
///
/// Serves two purposes with one implementation: completing a `pending_mfa` login,
/// and refreshing `mfa_verified_at` for a step-up. Both are "the user just proved
/// possession of the second factor", and giving them one code path means there is
/// one place where that fact is recorded.
pub async fn verify(
    state: &AppState,
    principal: &Principal,
    hints: &ClientHints,
    request: dto::CodeRequest,
) -> AppResult<dto::MfaVerifiedResponse> {
    enforce_mfa_limits(state, principal).await?;

    let user_id = principal.user_id();
    let now = now_unix()?;
    let was_pending = principal.session.pending_mfa;

    let mut tx = state.begin().await?;
    let Some(factor) = repo::lock_factor(&mut tx, user_id, STATUS_ACTIVE).await? else {
        // "No factor enrolled" is an authentication failure, not a 404: the caller
        // presented a credential and it did not work, and anything more specific
        // tells an attacker holding a stolen pending token what to try next.
        audit_mfa_failure(
            state,
            &mut tx,
            principal,
            hints,
            action::MFA_VERIFICATION_FAILED,
            "no_active_factor",
        )
        .await?;
        tx.commit().await?;
        return Err(AppError::AuthenticationFailed);
    };

    let secret = state
        .keyring
        .open(&sealed_from(&factor)?, user_id.as_bytes())?;

    match totp::verify(
        &secret,
        &request.code,
        now,
        factor.last_used_step.map(|s| s as u64),
    ) {
        totp::TotpVerdict::Valid { step } => {
            let step = i64::try_from(step)
                .map_err(|_| AppError::Internal("TOTP step is out of range".into()))?;
            // The watermark must move before the success is returned, or the code
            // just accepted is replayable for the rest of its window.
            repo::advance_last_used_step(&mut tx, factor.id, step).await?;
            repo::mark_mfa_verified(&mut tx, principal.session.session_id).await?;

            state
                .audit(
                    &mut tx,
                    AuditEvent::new(action::AUTH_STEP_UP_COMPLETED, Outcome::Success)
                        .actor(
                            user_id,
                            principal.session.principal_type,
                            Some(principal.session.session_id),
                        )
                        .target("SESSION", principal.session.session_id)
                        .source_ip(hints.ip_hint.clone())
                        .meta(
                            AuditMetadata::new()
                                .str("factor_type", "TOTP")
                                .bool("completed_pending_login", was_pending),
                        ),
                )
                .await?;
            tx.commit().await?;

            Ok(dto::MfaVerifiedResponse {
                mfa_required: false,
                auth_level: sessions::AUTH_LEVEL_MFA.to_string(),
                step_up_active: true,
                recovery_codes_remaining: None,
            })
        }
        totp::TotpVerdict::Replayed => {
            audit_mfa_failure(
                state,
                &mut tx,
                principal,
                hints,
                action::MFA_REPLAY_DETECTED,
                "totp_step_already_consumed",
            )
            .await?;
            tx.commit().await?;
            Err(AppError::AuthenticationFailed)
        }
        totp::TotpVerdict::Invalid => {
            audit_mfa_failure(
                state,
                &mut tx,
                principal,
                hints,
                action::MFA_VERIFICATION_FAILED,
                "totp_invalid",
            )
            .await?;
            tx.commit().await?;
            Err(AppError::AuthenticationFailed)
        }
    }
}

/// `POST /auth/mfa/recovery/verify`.
///
/// Consumption is a single `UPDATE ... WHERE consumed_at IS NULL` gated on rows
/// affected, scoped to the calling user. Two concurrent presentations of the same
/// code therefore have exactly one winner, and a code belonging to another account
/// matches nothing.
pub async fn recovery_verify(
    state: &AppState,
    principal: &Principal,
    hints: &ClientHints,
    request: dto::CodeRequest,
) -> AppResult<dto::MfaVerifiedResponse> {
    enforce_mfa_limits(state, principal).await?;

    let user_id = principal.user_id();
    // Normalising is safe here — unlike a password — because the value is a
    // server-generated code from a restricted alphabet, not user-chosen text.
    let normalised = tokens::normalize_recovery_code(&request.code);
    let code_hash = tokens::hash_token(&normalised);
    let was_pending = principal.session.pending_mfa;

    let mut tx = state.begin().await?;
    if repo::consume_recovery_code(&mut tx, user_id, &code_hash).await? != 1 {
        audit_mfa_failure(
            state,
            &mut tx,
            principal,
            hints,
            action::MFA_VERIFICATION_FAILED,
            "recovery_code_invalid_or_consumed",
        )
        .await?;
        tx.commit().await?;
        return Err(AppError::AuthenticationFailed);
    }

    repo::mark_mfa_verified(&mut tx, principal.session.session_id).await?;
    let remaining = repo::count_live_recovery_codes(&mut tx, user_id).await?;

    state
        .audit(
            &mut tx,
            AuditEvent::new(action::MFA_RECOVERY_CODE_CONSUMED, Outcome::Success)
                .actor(
                    user_id,
                    principal.session.principal_type,
                    Some(principal.session.session_id),
                )
                .target("USER", user_id)
                .source_ip(hints.ip_hint.clone())
                .meta(
                    AuditMetadata::new()
                        .int("remaining", remaining)
                        .bool("completed_pending_login", was_pending),
                ),
        )
        .await?;
    tx.commit().await?;

    Ok(dto::MfaVerifiedResponse {
        mfa_required: false,
        auth_level: sessions::AUTH_LEVEL_MFA.to_string(),
        step_up_active: true,
        // Surfaced so a user can see the batch draining and regenerate in time.
        recovery_codes_remaining: Some(remaining),
    })
}

// =============================================================================
// Recovery-code regeneration and disablement
// =============================================================================

/// `POST /auth/mfa/recovery/regenerate`.
///
/// On the step-up list (§8): a stolen session must not be able to mint itself a
/// set of permanent bypass credentials. `require_step_up` fails for a session that
/// has not verified a factor recently, which includes every `pending_mfa` session
/// by construction.
pub async fn recovery_regenerate(
    state: &AppState,
    principal: &Principal,
    hints: &ClientHints,
) -> AppResult<dto::RecoveryCodesResponse> {
    state.require_step_up(principal)?;
    enforce_mfa_limits(state, principal).await?;

    if !principal.session.mfa_enrolled {
        return Err(AppError::conflict(
            "MFA_NOT_ENROLLED",
            "Recovery codes exist only for an account with an enrolled authenticator.",
        ));
    }

    let user_id = principal.user_id();
    let mut tx = state.begin().await?;
    let codes = issue_recovery_codes(&mut tx, user_id).await?;

    state
        .audit(
            &mut tx,
            AuditEvent::new(action::MFA_RECOVERY_CODES_GENERATED, Outcome::Success)
                .actor(
                    user_id,
                    principal.session.principal_type,
                    Some(principal.session.session_id),
                )
                .target("USER", user_id)
                .source_ip(hints.ip_hint.clone())
                .meta(
                    AuditMetadata::new()
                        .int("count", codes.len() as i64)
                        .str("previous_batch", "invalidated"),
                ),
        )
        .await?;
    tx.commit().await?;

    Ok(dto::RecoveryCodesResponse {
        generated: codes.len(),
        codes,
    })
}

/// `POST /auth/mfa/disable`.
///
/// Two independent barriers: recent step-up, and a refusal for any account whose
/// `mfa_required` flag is set. The second covers ROOT and every holder of a
/// dangerous permission — for them MFA is mandatory, and a database trigger
/// independently refuses to clear `mfa_required` for the owner (ADR-004).
pub async fn disable(
    state: &AppState,
    principal: &Principal,
    hints: &ClientHints,
) -> AppResult<dto::MfaDisabledResponse> {
    state.require_step_up(principal)?;

    if principal.session.mfa_required {
        return Err(AppError::conflict(
            "MFA_MANDATORY",
            "Multi-factor authentication is mandatory for this account and cannot be disabled.",
        ));
    }

    let user_id = principal.user_id();
    let mut tx = state.begin().await?;

    let disabled = repo::disable_factors(&mut tx, user_id, None).await?;
    // The recovery codes belong to the factor that is going away. Leaving them
    // live would keep a set of single-use bypass credentials valid for an account
    // that no longer has a second factor at all.
    let codes_invalidated = repo::consume_recovery_batch(&mut tx, user_id).await?;
    repo::set_mfa_enrolled(&mut tx, user_id, false).await?;

    state
        .audit(
            &mut tx,
            AuditEvent::new(action::MFA_DISABLED, Outcome::Success)
                .actor(
                    user_id,
                    principal.session.principal_type,
                    Some(principal.session.session_id),
                )
                .target("USER", user_id)
                .source_ip(hints.ip_hint.clone())
                .meta(
                    AuditMetadata::new()
                        .int(
                            "factors_disabled",
                            i64::try_from(disabled).unwrap_or(i64::MAX),
                        )
                        .int(
                            "codes_invalidated",
                            i64::try_from(codes_invalidated).unwrap_or(i64::MAX),
                        )
                        .str("initiated_by", "self_service"),
                ),
        )
        .await?;
    tx.commit().await?;

    Ok(dto::MfaDisabledResponse {
        mfa_enrolled: false,
    })
}

/// Unused today; retained so a future factor type does not have to reinvent the
/// shape of a factor's public description.
#[allow(dead_code)]
fn _factor_summary(row: &repo::FactorRow) -> Value {
    serde_json::json!({ "id": row.id, "status": row.status })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::crypto::totp::{code_for_step, step_at, TotpVerdict};
    use crate::shared::secret::Secret;

    /// The rule the whole replay defence rests on, exercised end to end against
    /// the real construction: the watermark makes a code single-use even inside
    /// its own validity window.
    #[test]
    fn the_replay_watermark_makes_a_code_single_use() {
        let secret = totp::generate_secret().expect("csprng");
        let now = 1_700_000_000u64;
        let code = code_for_step(&secret, step_at(now));

        let TotpVerdict::Valid { step } = totp::verify(&secret, &code, now, None) else {
            panic!("the first presentation must succeed");
        };
        assert_eq!(
            totp::verify(&secret, &code, now, Some(step)),
            TotpVerdict::Replayed,
            "a code must not be usable twice"
        );
    }

    /// A code from the lower edge of the skew window must not be able to drag the
    /// watermark backwards and reopen a step that was already consumed. This is
    /// what `greatest(...)` in `advance_last_used_step` exists for; the assertion
    /// here is on the arithmetic the SQL performs.
    #[test]
    fn the_watermark_never_moves_backwards() {
        let advance = |current: Option<i64>, step: i64| current.unwrap_or(step).max(step);
        assert_eq!(advance(None, 100), 100);
        assert_eq!(advance(Some(100), 101), 101);
        assert_eq!(
            advance(Some(100), 99),
            100,
            "an earlier step must not lower the watermark"
        );
        assert_eq!(advance(Some(100), 100), 100);
    }

    /// The control that stops an attacker moving one user's encrypted factor onto
    /// another user's row.
    #[test]
    fn a_factor_sealed_for_one_user_does_not_open_for_another() {
        let ring = aead::KeyRing::new(1, Secret::new(vec![7u8; aead::KEY_BYTES])).expect("keyring");
        let alice = Uuid::now_v7();
        let bob = Uuid::now_v7();
        let secret = totp::generate_secret().expect("csprng");

        let sealed = ring.seal(secret.expose(), alice.as_bytes()).expect("seal");
        assert!(ring.open(&sealed, alice.as_bytes()).is_ok());
        assert!(
            ring.open(&sealed, bob.as_bytes()).is_err(),
            "a factor row moved between users must not decrypt"
        );
    }

    #[test]
    fn stored_factor_columns_round_trip_through_the_sealed_form() {
        let ring = aead::KeyRing::new(1, Secret::new(vec![3u8; aead::KEY_BYTES])).expect("keyring");
        let user_id = Uuid::now_v7();
        let secret = totp::generate_secret().expect("csprng");
        let sealed = ring
            .seal(secret.expose(), user_id.as_bytes())
            .expect("seal");

        let row = repo::FactorRow {
            id: Uuid::now_v7(),
            status: STATUS_ACTIVE.into(),
            secret_ciphertext: sealed.ciphertext.clone(),
            secret_nonce: sealed.nonce.clone(),
            key_version: i32::try_from(sealed.key_version).unwrap(),
            last_used_step: None,
        };

        let rebuilt = sealed_from(&row).expect("rebuild");
        let opened = ring.open(&rebuilt, user_id.as_bytes()).expect("open");
        assert_eq!(opened.expose(), secret.expose());
    }

    /// The ciphertext columns must satisfy the database CHECK constraints, or
    /// enrolment fails at the storage layer instead of in a test.
    #[test]
    fn sealed_columns_fit_the_schema_constraints() {
        let ring = aead::KeyRing::new(1, Secret::new(vec![5u8; aead::KEY_BYTES])).expect("keyring");
        let sealed = ring
            .seal(
                totp::generate_secret().unwrap().expose(),
                Uuid::now_v7().as_bytes(),
            )
            .expect("seal");
        assert_eq!(
            sealed.nonce.len(),
            24,
            "secret_nonce CHECK is exactly 24 bytes"
        );
        assert!(
            (17..=256).contains(&sealed.ciphertext.len()),
            "secret_ciphertext CHECK is 17..=256 bytes, got {}",
            sealed.ciphertext.len()
        );
        assert!(sealed.key_version > 0, "key_version CHECK is > 0");
    }

    /// A human retyping a recovery code with lowercase letters, spaces or no
    /// separators must still match the stored digest.
    #[test]
    fn recovery_codes_normalise_before_hashing() {
        let code = tokens::generate_recovery_code().expect("csprng");
        let plaintext = code.plaintext.expose().clone();

        for typed in [
            plaintext.clone(),
            plaintext.to_lowercase(),
            plaintext.replace('-', ""),
            plaintext.replace('-', " "),
            format!("  {}  ", plaintext.to_lowercase()),
        ] {
            let hashed = tokens::hash_token(&tokens::normalize_recovery_code(&typed));
            assert_eq!(hashed, code.hash, "normalisation failed for {typed:?}");
        }
    }

    #[test]
    fn a_wrong_recovery_code_never_matches() {
        let a = tokens::generate_recovery_code().expect("csprng");
        let b = tokens::generate_recovery_code().expect("csprng");
        assert_ne!(a.hash, b.hash);
        assert_ne!(
            tokens::hash_token(&tokens::normalize_recovery_code("")),
            a.hash
        );
    }

    #[test]
    fn a_batch_is_ten_distinct_codes() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..RECOVERY_CODE_COUNT {
            let c = tokens::generate_recovery_code().expect("csprng");
            assert!(
                seen.insert(c.plaintext.expose().clone()),
                "the CSPRNG repeated a code"
            );
        }
        assert_eq!(seen.len(), 10);
    }
}
