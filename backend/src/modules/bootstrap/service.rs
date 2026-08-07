//! Bootstrap: the transaction that establishes system ownership, exactly once.

use std::time::Duration;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::app::AppState;
use crate::modules::audit::{action, AuditEvent, AuditMetadata, Outcome};
use crate::modules::authorization::domain::PrincipalType;
use crate::platform::crypto::{password, tokens};
use crate::platform::database::{self, lock_keys};
use crate::platform::errors::{AppError, AppResult};
use crate::platform::http::extract::ClientIp;
use crate::platform::http::rate_limit::{keys, RateLimitDecision};
use crate::shared::secret::Secret;
use crate::shared::validation as v;

use super::dto::{rfc3339, BootstrapRootRequest, BootstrapRootResponse, BootstrapStatusResponse};

/// The bootstrap rate-limit window. Configured as "per IP per hour".
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(3600);

/// Has the system been initialised?
///
/// Reads the singleton `system_state` row and returns a single boolean. There is
/// no transaction and no lock: this answer is advisory, it is allowed to be stale
/// by microseconds, and the only decision that matters is re-made under a lock
/// inside [`create_root`].
pub async fn status(state: &AppState) -> AppResult<BootstrapStatusResponse> {
    let row: Option<(Option<OffsetDateTime>,)> =
        sqlx::query_as("SELECT initialized_at FROM system_state WHERE id")
            .fetch_optional(&state.db)
            .await
            .map_err(AppError::from)?;

    // A missing singleton row is a broken installation, but this endpoint must not
    // say so — "not initialised" is both the safe answer and the true one for a
    // database that has no state row.
    Ok(BootstrapStatusResponse {
        initialized: matches!(row, Some((Some(_),))),
    })
}

/// Create the single system owner.
///
/// Preconditions, in the order they are checked and for the reason given:
///
///  1. `RB_BOOTSTRAP_SECRET` must be configured. If it is not, the endpoint does
///     not exist — `404`, not `403`. Telling an anonymous caller "this capability
///     exists but is disabled" points them at exactly the lever to look for, and
///     the operator's documented procedure is to remove the secret after first run.
///  2. The per-IP rate limit is consumed *before* the comparison, so a caller
///     cannot grind the secret at line rate.
///  3. The secret is compared with [`tokens::secret_matches`], which digests both
///     sides and compares in constant time. A `==` on the raw strings would
///     short-circuit at the first differing byte and leak a position oracle.
///  4. Everything else happens under an advisory lock; see the comments inline.
pub async fn create_root(
    state: &AppState,
    client_ip: ClientIp,
    mut request: BootstrapRootRequest,
) -> AppResult<BootstrapRootResponse> {
    let Some(expected) = state.config.security.bootstrap_secret.as_ref() else {
        return Err(AppError::NotFound);
    };

    let decision = state
        .limiter
        .check(
            &keys::bootstrap_ip(client_ip.0),
            state.config.rate_limits.bootstrap_per_ip_per_hour,
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

    // Constant-time. The secret itself is never placed in an error, a log line or
    // an audit record — only the fact that a comparison failed.
    if !tokens::secret_matches(&request.bootstrap_secret, expected.expose()) {
        record_rejection(state, client_ip, "invalid_secret").await;
        // Undifferentiated on purpose: "wrong secret" and "already initialised"
        // must look the same to a caller who does not hold the secret.
        return Err(AppError::AuthenticationFailed);
    }

    // Validation happens after the secret check so that an attacker without the
    // secret cannot use field-level validation errors to probe anything.
    let email_normalized = v::validate_email("email", &request.email)?;
    let email = request.email.trim().to_string();
    let display_name = v::required_text(
        "display_name",
        &request.display_name,
        v::MAX_DISPLAY_NAME_LEN,
    )?;
    password::validate_password(&request.password, &email_normalized, &display_name)?;

    // Hashing happens *outside* the transaction. Argon2id deliberately costs tens
    // of milliseconds; doing it while holding the bootstrap advisory lock would
    // hand an attacker a way to hold that lock — and a database connection — for
    // as long as they like.
    let supplied_password = Secret::new(std::mem::take(&mut request.password));
    let password_hash = state.hasher.hash(&supplied_password).await?;
    drop(supplied_password);

    let mut tx = state.begin().await?;

    // ---- how "exactly one owner" is actually guaranteed ---------------------
    //
    // Three mechanisms, and each of them covers a case the others do not:
    //
    //  * `pg_advisory_xact_lock(BOOTSTRAP)` serialises concurrent attempts at this
    //    line. Without it a hundred simultaneous requests would each observe
    //    `initialized_at IS NULL` in the same instant and each proceed to insert.
    //    The lock is transaction-scoped, so it is released by COMMIT *or* ROLLBACK
    //    — a request that panics, times out or loses its connection cannot leave
    //    bootstrap permanently wedged.
    //
    //  * `SELECT ... FOR UPDATE` re-reads the singleton `system_state` row inside
    //    this transaction, after the lock is held. That is what closes the TOCTOU
    //    window: the decision is made against committed state as of *now*, not
    //    against a value that was read before anyone queued.
    //
    //  * `system_ownership.id boolean PRIMARY KEY CHECK (id)` admits one row, full
    //    stop. If both application mechanisms were somehow defeated, the second
    //    INSERT is a primary-key violation at the storage layer (ADR-004 layer 1).
    //
    // The advisory-lock key is a constant in `platform::database::lock_keys` so
    // that two call sites cannot collide on a number by accident.
    database::advisory_xact_lock(&mut tx, lock_keys::BOOTSTRAP).await?;

    let existing: Option<(Option<OffsetDateTime>,)> =
        sqlx::query_as("SELECT initialized_at FROM system_state WHERE id FOR UPDATE")
            .fetch_optional(&mut *tx)
            .await
            .map_err(AppError::from)?;

    match existing {
        // The row is inserted by migration 0001. Its absence means the schema is
        // not the schema this binary was built against; refusing is the only safe
        // response.
        None => {
            return Err(AppError::Internal(
                "system_state singleton row is missing".into(),
            ))
        }
        Some((Some(_),)) => return Err(AppError::AlreadyInitialized),
        Some((None,)) => {}
    }

    let user_id = Uuid::now_v7();

    // `principal_type`, `status`, `mfa_required` and `mfa_enrolled` are SQL
    // literals, not bound parameters. The owner's security envelope is a property
    // of this code path and is not derived from anything the caller sent — which is
    // why the request DTO has no field for any of them.
    //
    // `mfa_required = true, mfa_enrolled = false` is the MFA_ENROLMENT_REQUIRED
    // state: the owner's first session is `pending_mfa` and can reach nothing but
    // the MFA endpoints until a factor is activated.
    sqlx::query(
        r#"
        INSERT INTO users (
            id, email, email_normalized, display_name,
            principal_type, status, mfa_required, mfa_enrolled, activated_at
        ) VALUES ($1, $2, $3, $4, 'INTERNAL', 'ACTIVE', true, false, now())
        "#,
    )
    .bind(user_id)
    .bind(&email)
    .bind(&email_normalized)
    .bind(&display_name)
    .execute(&mut *tx)
    .await
    .map_err(AppError::from)?;

    sqlx::query("INSERT INTO credentials (user_id, password_hash) VALUES ($1, $2)")
        .bind(user_id)
        .bind(&password_hash)
        .execute(&mut *tx)
        .await
        .map_err(AppError::from)?;

    // Ownership is this row and nothing else — not a role, not a column on `users`.
    // The BEFORE INSERT trigger independently refuses a non-INTERNAL or non-ACTIVE
    // owner, and UPDATE/DELETE on this table are refused unconditionally, so this
    // statement is the only moment in the database's life when ownership can be
    // established.
    sqlx::query("INSERT INTO system_ownership (id, root_user_id) VALUES (true, $1)")
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::from)?;

    // `AND initialized_at IS NULL` is redundant with the FOR UPDATE read above and
    // is kept as a second gate: if it ever affects zero rows, something raced us
    // and the correct outcome is the permanent 409, not a silent second owner.
    let stamped = sqlx::query(
        "UPDATE system_state SET initialized_at = now() WHERE id AND initialized_at IS NULL",
    )
    .execute(&mut *tx)
    .await
    .map_err(AppError::from)?;
    if stamped.rows_affected() != 1 {
        return Err(AppError::AlreadyInitialized);
    }

    let (initialized_at,): (OffsetDateTime,) =
        sqlx::query_as("SELECT initialized_at FROM system_state WHERE id")
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::from)?;

    // Audited inside the transaction: the ownership row and the record of how it
    // came to exist commit or roll back together. The actor is the new owner
    // themselves — there is no other principal in the system at this instant.
    state
        .audit(
            &mut tx,
            AuditEvent::new(action::SYSTEM_BOOTSTRAPPED, Outcome::Success)
                .actor(user_id, PrincipalType::Internal, None)
                .target("USER", user_id)
                .source_ip(client_ip.hint())
                .meta(
                    AuditMetadata::new()
                        .str("email_normalized", &email_normalized)
                        .str("display_name", &display_name)
                        .bool("mfa_enrolment_required", true),
                ),
        )
        .await?;

    tx.commit().await.map_err(AppError::from)?;

    tracing::info!(
        user.id = %user_id,
        "system ownership established; bootstrap is now permanently closed"
    );

    Ok(BootstrapRootResponse {
        user_id,
        email,
        display_name,
        mfa_enrolment_required: true,
        initialized_at: rfc3339(initialized_at),
    })
}

/// Record a refused bootstrap attempt.
///
/// Written in its own transaction, because the request itself is about to fail and
/// there is no state change to attach the event to. Failure to write the audit
/// record is logged and swallowed: an attacker must not be able to tell "wrong
/// secret" from "wrong secret and the audit table was unavailable", and turning a
/// generic rejection into a `500` would be exactly that oracle.
///
/// The presented secret is **not** part of the metadata. `AuditMetadata` would
/// redact a key named `secret` anyway, but the value is never handed to it in the
/// first place — audit rows are append-only and have no delete path, so a secret
/// written there would be permanent.
async fn record_rejection(state: &AppState, client_ip: ClientIp, reason: &str) {
    let event = AuditEvent::new(action::SYSTEM_BOOTSTRAP_REJECTED, Outcome::Denied)
        .system_actor()
        .source_ip(client_ip.hint())
        .meta(AuditMetadata::new().str("reason", reason));

    let outcome = async {
        let mut tx = state.begin().await?;
        state.audit(&mut tx, event).await?;
        tx.commit().await.map_err(AppError::from)
    }
    .await;

    if let Err(e) = outcome {
        tracing::error!(error = %e, "failed to record a rejected bootstrap attempt");
    }
    tracing::warn!(reason = %reason, "bootstrap attempt refused");
}

#[cfg(test)]
mod tests {
    use crate::platform::crypto::tokens;

    /// The comparison used for the operator secret must be exact and
    /// length-insensitive in its cost. This asserts the *behaviour* contract that
    /// `create_root` depends on; the constant-time property itself is tested in
    /// `platform::crypto::tokens`.
    #[test]
    fn the_bootstrap_secret_comparison_is_exact() {
        let real = "aB3x9Qw7ZmK2pL5vR8tYnE4hJ6cD1sG0";
        assert!(tokens::secret_matches(real, real));
        for wrong in [
            "",
            "aB3x9Qw7ZmK2pL5vR8tYnE4hJ6cD1sG",   // one short
            "aB3x9Qw7ZmK2pL5vR8tYnE4hJ6cD1sG0 ", // trailing space
            "AB3X9QW7ZMK2PL5VR8TYNE4HJ6CD1SG0",  // case folded
            "aB3x9Qw7ZmK2pL5vR8tYnE4hJ6cD1sG01",
        ] {
            assert!(!tokens::secret_matches(wrong, real), "accepted `{wrong}`");
        }
    }
}
