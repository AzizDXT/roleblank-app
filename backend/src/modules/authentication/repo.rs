//! Explicit SQL for the authentication module.
//!
//! Rules from `MODULE_GUIDE.md` §4, applied without exception:
//!   * no `query!` macros (ADR-001), no `SELECT *` — an explicit column list is
//!     what guarantees the hot path physically cannot return a password hash;
//!   * every value is bound, never interpolated;
//!   * reads take `&PgPool`, writes take the caller's `&mut Transaction`, so the
//!     state change and its audit event commit or roll back together.
//!
//! Nothing in this file makes a decision. Every function is a statement plus its
//! parameters; the classification of "is this token reusable" lives in
//! `sessions.rs` where it can be tested without a database.

use serde_json::Value;
use sqlx::{PgPool, Postgres, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::platform::errors::{AppError, AppResult};

// =============================================================================
// Login
// =============================================================================

/// Everything the login path needs, in one round trip.
///
/// The join to `credentials` means a user who has been invited but has never set a
/// password simply does not match, and therefore takes the same dummy-hash path as
/// a non-existent account. That is deliberate: "invited but not activated" must not
/// be distinguishable from "no such account".
/// The login path never needs the display name or the stored form of the address,
/// so neither is selected. An explicit column list is the mechanism: a field that
/// is not loaded cannot be logged, audited or returned by mistake.
#[derive(Debug, sqlx::FromRow)]
pub struct LoginCandidate {
    pub user_id: Uuid,
    pub principal_type: String,
    pub status: String,
    pub password_hash: String,
    pub mfa_required: bool,
    pub mfa_enrolled: bool,
}

pub async fn find_login_candidate(
    pool: &PgPool,
    email_normalized: &str,
) -> AppResult<Option<LoginCandidate>> {
    sqlx::query_as::<_, LoginCandidate>(
        r#"
        SELECT u.id             AS user_id,
               u.principal_type AS principal_type,
               u.status         AS status,
               c.password_hash  AS password_hash,
               u.mfa_required   AS mfa_required,
               u.mfa_enrolled   AS mfa_enrolled
          FROM users u
          JOIN credentials c ON c.user_id = u.id
         WHERE u.email_normalized = $1
        "#,
    )
    .bind(email_normalized)
    .fetch_optional(pool)
    .await
    .map_err(AppError::from)
}

// =============================================================================
// Sessions
// =============================================================================

pub struct NewSession {
    pub id: Uuid,
    pub user_id: Uuid,
    pub access_token_hash: Vec<u8>,
    pub access_expires_at: OffsetDateTime,
    pub idle_expires_at: OffsetDateTime,
    pub absolute_expires_at: OffsetDateTime,
    pub auth_level: &'static str,
    pub pending_mfa: bool,
    pub client_ip_hint: Option<String>,
    pub user_agent_hint: Option<String>,
}

pub async fn insert_session(
    tx: &mut Transaction<'_, Postgres>,
    session: NewSession,
) -> AppResult<()> {
    sqlx::query(
        r#"
        INSERT INTO sessions (
            id, user_id, access_token_hash, access_expires_at, idle_expires_at,
            absolute_expires_at, auth_level, pending_mfa, client_ip_hint, user_agent_hint
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
        "#,
    )
    .bind(session.id)
    .bind(session.user_id)
    .bind(&session.access_token_hash)
    .bind(session.access_expires_at)
    .bind(session.idle_expires_at)
    .bind(session.absolute_expires_at)
    .bind(session.auth_level)
    .bind(session.pending_mfa)
    .bind(session.client_ip_hint.as_deref())
    .bind(session.user_agent_hint.as_deref())
    .execute(&mut **tx)
    .await
    .map_err(AppError::from)?;
    Ok(())
}

pub async fn count_live_sessions(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
) -> AppResult<i64> {
    let (count,): (i64,) = sqlx::query_as(
        r#"
        SELECT count(*)
          FROM sessions
         WHERE user_id = $1
           AND revoked_at IS NULL
           AND absolute_expires_at > now()
           AND idle_expires_at     > now()
        "#,
    )
    .bind(user_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::from)?;
    Ok(count)
}

/// The oldest live sessions, which are what the per-user cap evicts.
pub async fn oldest_live_session_ids(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    limit: i64,
) -> AppResult<Vec<Uuid>> {
    sqlx::query_scalar::<_, Uuid>(
        r#"
        SELECT id
          FROM sessions
         WHERE user_id = $1
           AND revoked_at IS NULL
           AND absolute_expires_at > now()
           AND idle_expires_at     > now()
         ORDER BY created_at ASC, id ASC
         LIMIT $2
        "#,
    )
    .bind(user_id)
    .bind(limit)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::from)
}

/// Revoke one session. Revocation is an UPDATE, never a DELETE: the row remains
/// for the audit trail and for the user's own session list.
pub async fn revoke_session(
    tx: &mut Transaction<'_, Postgres>,
    session_id: Uuid,
    reason: &str,
) -> AppResult<u64> {
    let result = sqlx::query(
        r#"
        UPDATE sessions
           SET revoked_at = now(), revocation_reason = $2
         WHERE id = $1 AND revoked_at IS NULL
        "#,
    )
    .bind(session_id)
    .bind(reason)
    .execute(&mut **tx)
    .await
    .map_err(AppError::from)?;
    Ok(result.rows_affected())
}

/// Revoke a session the caller owns. The `user_id` predicate is the object-level
/// authorisation: it is in the statement, so a caller cannot revoke a stranger's
/// session by guessing its id even if the handler forgot to check.
pub async fn revoke_own_session(
    tx: &mut Transaction<'_, Postgres>,
    session_id: Uuid,
    user_id: Uuid,
    reason: &str,
) -> AppResult<u64> {
    let result = sqlx::query(
        r#"
        UPDATE sessions
           SET revoked_at = now(), revocation_reason = $3
         WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL
        "#,
    )
    .bind(session_id)
    .bind(user_id)
    .bind(reason)
    .execute(&mut **tx)
    .await
    .map_err(AppError::from)?;
    Ok(result.rows_affected())
}

/// Revoke every live session of a user, optionally sparing one.
///
/// `except` is `Some` for a password change (all *other* sessions) and `None` for
/// a password reset, a reuse detection, and `logout-all`.
pub async fn revoke_user_sessions(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    reason: &str,
    except: Option<Uuid>,
) -> AppResult<u64> {
    let result = sqlx::query(
        r#"
        UPDATE sessions
           SET revoked_at = now(), revocation_reason = $2
         WHERE user_id = $1
           AND revoked_at IS NULL
           AND ($3::uuid IS NULL OR id <> $3)
        "#,
    )
    .bind(user_id)
    .bind(reason)
    .bind(except)
    .execute(&mut **tx)
    .await
    .map_err(AppError::from)?;
    Ok(result.rows_affected())
}

/// Rotate the session's access token and roll the idle window forward.
pub async fn rotate_access_token(
    tx: &mut Transaction<'_, Postgres>,
    session_id: Uuid,
    access_token_hash: &[u8],
    access_expires_at: OffsetDateTime,
    idle_expires_at: OffsetDateTime,
) -> AppResult<u64> {
    let result = sqlx::query(
        r#"
        UPDATE sessions
           SET access_token_hash = $2,
               access_expires_at = $3,
               idle_expires_at   = $4,
               last_activity_at  = now()
         WHERE id = $1 AND revoked_at IS NULL
        "#,
    )
    .bind(session_id)
    .bind(access_token_hash)
    .bind(access_expires_at)
    .bind(idle_expires_at)
    .execute(&mut **tx)
    .await
    .map_err(AppError::from)?;
    Ok(result.rows_affected())
}

/// Record that a second factor was verified for this session.
///
/// The three columns move together: a session that is no longer pending must have
/// `auth_level = 'MFA'` (the `sessions_mfa_consistent` CHECK enforces the
/// converse) and a `mfa_verified_at` that the step-up window is measured from.
pub async fn mark_mfa_verified(
    tx: &mut Transaction<'_, Postgres>,
    session_id: Uuid,
) -> AppResult<u64> {
    let result = sqlx::query(
        r#"
        UPDATE sessions
           SET pending_mfa      = false,
               auth_level       = 'MFA',
               mfa_verified_at  = now(),
               last_activity_at = now()
         WHERE id = $1 AND revoked_at IS NULL
        "#,
    )
    .bind(session_id)
    .execute(&mut **tx)
    .await
    .map_err(AppError::from)?;
    Ok(result.rows_affected())
}

#[derive(Debug, sqlx::FromRow)]
pub struct SessionListRow {
    pub id: Uuid,
    pub auth_level: String,
    pub created_at: OffsetDateTime,
    pub last_activity_at: OffsetDateTime,
    pub access_expires_at: OffsetDateTime,
    pub idle_expires_at: OffsetDateTime,
    pub absolute_expires_at: OffsetDateTime,
    pub client_ip_hint: Option<String>,
    pub user_agent_hint: Option<String>,
}

/// The caller's own live sessions. `access_token_hash` is deliberately absent from
/// the column list — the list endpoint has no need of it and cannot leak what it
/// never loads.
pub async fn list_live_sessions(
    pool: &PgPool,
    user_id: Uuid,
    limit: i64,
) -> AppResult<Vec<SessionListRow>> {
    sqlx::query_as::<_, SessionListRow>(
        r#"
        SELECT id, auth_level, created_at, last_activity_at,
               access_expires_at, idle_expires_at, absolute_expires_at,
               client_ip_hint, user_agent_hint
          FROM sessions
         WHERE user_id = $1
           AND revoked_at IS NULL
           AND absolute_expires_at > now()
           AND idle_expires_at     > now()
         ORDER BY created_at DESC, id DESC
         LIMIT $2
        "#,
    )
    .bind(user_id)
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(AppError::from)
}

// =============================================================================
// Refresh tokens
// =============================================================================

pub struct NewRefreshToken {
    pub id: Uuid,
    pub session_id: Uuid,
    pub token_hash: Vec<u8>,
    pub generation: i32,
    pub expires_at: OffsetDateTime,
}

pub async fn insert_refresh_token(
    tx: &mut Transaction<'_, Postgres>,
    token: NewRefreshToken,
) -> AppResult<()> {
    sqlx::query(
        r#"
        INSERT INTO session_refresh_tokens (id, session_id, token_hash, generation, expires_at)
        VALUES ($1,$2,$3,$4,$5)
        "#,
    )
    .bind(token.id)
    .bind(token.session_id)
    .bind(&token.token_hash)
    .bind(token.generation)
    .bind(token.expires_at)
    .execute(&mut **tx)
    .await
    .map_err(AppError::from)?;
    Ok(())
}

#[derive(Debug, sqlx::FromRow)]
pub struct RefreshLookup {
    pub token_id: Uuid,
    pub session_id: Uuid,
    pub generation: i32,
    pub token_expires_at: OffsetDateTime,
    pub consumed_at: Option<OffsetDateTime>,
    pub user_id: Uuid,
    pub principal_type: String,
    pub user_status: String,
    pub session_revoked_at: Option<OffsetDateTime>,
    pub idle_expires_at: OffsetDateTime,
    pub absolute_expires_at: OffsetDateTime,
    pub pending_mfa: bool,
}

/// Load a presented refresh token **and lock it**.
///
/// `FOR UPDATE OF rt, s` is what makes two concurrent refreshes deterministic:
/// exactly one transaction wins, and the loser reads a consumed row and triggers
/// family revocation. That strictness is the intended posture (ADR-005). `users`
/// is joined but not locked — the row is read for its status, never written here,
/// and locking it would serialise every refresh against every user update.
pub async fn lock_refresh_token(
    tx: &mut Transaction<'_, Postgres>,
    token_hash: &[u8],
) -> AppResult<Option<RefreshLookup>> {
    sqlx::query_as::<_, RefreshLookup>(
        r#"
        SELECT rt.id                  AS token_id,
               rt.session_id          AS session_id,
               rt.generation          AS generation,
               rt.expires_at          AS token_expires_at,
               rt.consumed_at         AS consumed_at,
               s.user_id              AS user_id,
               u.principal_type       AS principal_type,
               u.status               AS user_status,
               s.revoked_at           AS session_revoked_at,
               s.idle_expires_at      AS idle_expires_at,
               s.absolute_expires_at  AS absolute_expires_at,
               s.pending_mfa          AS pending_mfa
          FROM session_refresh_tokens rt
          JOIN sessions s ON s.id = rt.session_id
          JOIN users    u ON u.id = s.user_id
         WHERE rt.token_hash = $1
           FOR UPDATE OF rt, s
        "#,
    )
    .bind(token_hash)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::from)
}

/// Consume a refresh token, gated on rows affected.
///
/// The `consumed_at IS NULL` predicate is belt and braces on top of `FOR UPDATE`:
/// if the lock were ever removed by a refactor, single use would still hold.
pub async fn consume_refresh_token(
    tx: &mut Transaction<'_, Postgres>,
    token_id: Uuid,
) -> AppResult<u64> {
    let result = sqlx::query(
        "UPDATE session_refresh_tokens SET consumed_at = now() WHERE id = $1 AND consumed_at IS NULL",
    )
    .bind(token_id)
    .execute(&mut **tx)
    .await
    .map_err(AppError::from)?;
    Ok(result.rows_affected())
}

pub async fn link_replacement(
    tx: &mut Transaction<'_, Postgres>,
    token_id: Uuid,
    replaced_by: Uuid,
) -> AppResult<()> {
    sqlx::query("UPDATE session_refresh_tokens SET replaced_by = $2 WHERE id = $1")
        .bind(token_id)
        .bind(replaced_by)
        .execute(&mut **tx)
        .await
        .map_err(AppError::from)?;
    Ok(())
}

/// Kill every unconsumed token in a family.
///
/// Consumed rows are left exactly as they are: they *are* the theft detector, and
/// deleting or rewriting them would delete the signal (ADR-005).
pub async fn consume_family(
    tx: &mut Transaction<'_, Postgres>,
    session_id: Uuid,
) -> AppResult<u64> {
    let result = sqlx::query(
        "UPDATE session_refresh_tokens SET consumed_at = now() WHERE session_id = $1 AND consumed_at IS NULL",
    )
    .bind(session_id)
    .execute(&mut **tx)
    .await
    .map_err(AppError::from)?;
    Ok(result.rows_affected())
}

// =============================================================================
// Credentials
// =============================================================================

#[derive(Debug, sqlx::FromRow)]
pub struct CredentialRow {
    pub password_hash: String,
    pub email: String,
    pub display_name: String,
}

pub async fn load_credential(pool: &PgPool, user_id: Uuid) -> AppResult<Option<CredentialRow>> {
    sqlx::query_as::<_, CredentialRow>(
        r#"
        SELECT c.password_hash AS password_hash,
               u.email         AS email,
               u.display_name  AS display_name
          FROM credentials c
          JOIN users u ON u.id = c.user_id
         WHERE c.user_id = $1
        "#,
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .map_err(AppError::from)
}

pub async fn update_password(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    password_hash: &str,
) -> AppResult<u64> {
    let result = sqlx::query(
        r#"
        UPDATE credentials
           SET password_hash = $2, password_updated_at = now(), must_change = false
         WHERE user_id = $1
        "#,
    )
    .bind(user_id)
    .bind(password_hash)
    .execute(&mut **tx)
    .await
    .map_err(AppError::from)?;
    Ok(result.rows_affected())
}

// =============================================================================
// Password reset
// =============================================================================

#[derive(Debug, sqlx::FromRow)]
pub struct ResetSubject {
    pub user_id: Uuid,
    pub email: String,
    pub display_name: String,
    pub principal_type: String,
    pub status: String,
}

pub async fn find_reset_subject(
    pool: &PgPool,
    email_normalized: &str,
) -> AppResult<Option<ResetSubject>> {
    sqlx::query_as::<_, ResetSubject>(
        r#"
        SELECT u.id             AS user_id,
               u.email          AS email,
               u.display_name   AS display_name,
               u.principal_type AS principal_type,
               u.status         AS status
          FROM users u
          JOIN credentials c ON c.user_id = u.id
         WHERE u.email_normalized = $1
        "#,
    )
    .bind(email_normalized)
    .fetch_optional(pool)
    .await
    .map_err(AppError::from)
}

/// Invalidate any outstanding reset token before issuing a new one, so that a
/// stack of live tokens cannot accumulate from repeated requests.
pub async fn consume_live_reset_tokens(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
) -> AppResult<u64> {
    let result = sqlx::query(
        "UPDATE password_reset_tokens SET consumed_at = now() WHERE user_id = $1 AND consumed_at IS NULL",
    )
    .bind(user_id)
    .execute(&mut **tx)
    .await
    .map_err(AppError::from)?;
    Ok(result.rows_affected())
}

pub async fn insert_reset_token(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    user_id: Uuid,
    token_hash: &[u8],
    expires_at: OffsetDateTime,
    requested_ip_hint: Option<&str>,
) -> AppResult<()> {
    sqlx::query(
        r#"
        INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at, requested_ip_hint)
        VALUES ($1,$2,$3,$4,$5)
        "#,
    )
    .bind(id)
    .bind(user_id)
    .bind(token_hash)
    .bind(expires_at)
    .bind(requested_ip_hint)
    .execute(&mut **tx)
    .await
    .map_err(AppError::from)?;
    Ok(())
}

#[derive(Debug, sqlx::FromRow)]
pub struct ResetTokenLookup {
    pub token_id: Uuid,
    pub user_id: Uuid,
    pub expires_at: OffsetDateTime,
    pub consumed_at: Option<OffsetDateTime>,
    pub email: String,
    pub display_name: String,
    pub principal_type: String,
    pub user_status: String,
}

pub async fn lock_reset_token(
    tx: &mut Transaction<'_, Postgres>,
    token_hash: &[u8],
) -> AppResult<Option<ResetTokenLookup>> {
    sqlx::query_as::<_, ResetTokenLookup>(
        r#"
        SELECT t.id             AS token_id,
               t.user_id        AS user_id,
               t.expires_at     AS expires_at,
               t.consumed_at    AS consumed_at,
               u.email          AS email,
               u.display_name   AS display_name,
               u.principal_type AS principal_type,
               u.status         AS user_status
          FROM password_reset_tokens t
          JOIN users u ON u.id = t.user_id
         WHERE t.token_hash = $1
           FOR UPDATE OF t
        "#,
    )
    .bind(token_hash)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::from)
}

pub async fn consume_reset_token(
    tx: &mut Transaction<'_, Postgres>,
    token_id: Uuid,
) -> AppResult<u64> {
    let result = sqlx::query(
        "UPDATE password_reset_tokens SET consumed_at = now() WHERE id = $1 AND consumed_at IS NULL",
    )
    .bind(token_id)
    .execute(&mut **tx)
    .await
    .map_err(AppError::from)?;
    Ok(result.rows_affected())
}

// =============================================================================
// MFA factors
// =============================================================================

#[derive(Debug, sqlx::FromRow)]
pub struct FactorRow {
    pub id: Uuid,
    pub status: String,
    pub secret_ciphertext: Vec<u8>,
    pub secret_nonce: Vec<u8>,
    pub key_version: i32,
    pub last_used_step: Option<i64>,
}

/// Load and lock the user's live TOTP factor in one of the given statuses.
///
/// Locking matters: without it, two concurrent verifications of the same code
/// could both read the same `last_used_step` and both succeed, which is exactly
/// the replay the column exists to prevent.
pub async fn lock_factor(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    status: &str,
) -> AppResult<Option<FactorRow>> {
    sqlx::query_as::<_, FactorRow>(
        r#"
        SELECT id, status, secret_ciphertext, secret_nonce, key_version, last_used_step
          FROM mfa_factors
         WHERE user_id = $1 AND factor_type = 'TOTP' AND status = $2
           FOR UPDATE
        "#,
    )
    .bind(user_id)
    .bind(status)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::from)
}

/// Retire factors in the given status.
///
/// A DISABLED row rather than a deleted one: the runtime role holds no DELETE on
/// `mfa_factors`, and the history of a security factor is worth keeping. The
/// partial unique index only covers PENDING and ACTIVE, so disabling frees the slot.
pub async fn disable_factors(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    from_status: Option<&str>,
) -> AppResult<u64> {
    let result = sqlx::query(
        r#"
        UPDATE mfa_factors
           SET status = 'DISABLED', disabled_at = now()
         WHERE user_id = $1
           AND factor_type = 'TOTP'
           AND status IN ('PENDING', 'ACTIVE')
           AND ($2::text IS NULL OR status = $2)
        "#,
    )
    .bind(user_id)
    .bind(from_status)
    .execute(&mut **tx)
    .await
    .map_err(AppError::from)?;
    Ok(result.rows_affected())
}

pub struct NewFactor {
    pub id: Uuid,
    pub user_id: Uuid,
    pub secret_ciphertext: Vec<u8>,
    pub secret_nonce: Vec<u8>,
    pub key_version: i32,
    pub label: Option<String>,
}

pub async fn insert_pending_factor(
    tx: &mut Transaction<'_, Postgres>,
    factor: NewFactor,
) -> AppResult<()> {
    sqlx::query(
        r#"
        INSERT INTO mfa_factors (
            id, user_id, factor_type, status, secret_ciphertext, secret_nonce, key_version, label
        ) VALUES ($1,$2,'TOTP','PENDING',$3,$4,$5,$6)
        "#,
    )
    .bind(factor.id)
    .bind(factor.user_id)
    .bind(&factor.secret_ciphertext)
    .bind(&factor.secret_nonce)
    .bind(factor.key_version)
    .bind(factor.label.as_deref())
    .execute(&mut **tx)
    .await
    .map_err(AppError::from)?;
    Ok(())
}

pub async fn activate_factor(
    tx: &mut Transaction<'_, Postgres>,
    factor_id: Uuid,
    last_used_step: i64,
) -> AppResult<u64> {
    let result = sqlx::query(
        r#"
        UPDATE mfa_factors
           SET status = 'ACTIVE', activated_at = now(), last_used_step = $2
         WHERE id = $1 AND status = 'PENDING'
        "#,
    )
    .bind(factor_id)
    .bind(last_used_step)
    .execute(&mut **tx)
    .await
    .map_err(AppError::from)?;
    Ok(result.rows_affected())
}

/// Advance the replay watermark.
///
/// `greatest` rather than a plain assignment: a code accepted from the lower edge
/// of the skew window must never move the watermark backwards, or the step it
/// lowered past would become replayable again.
pub async fn advance_last_used_step(
    tx: &mut Transaction<'_, Postgres>,
    factor_id: Uuid,
    step: i64,
) -> AppResult<u64> {
    let result = sqlx::query(
        "UPDATE mfa_factors SET last_used_step = greatest(coalesce(last_used_step, $2), $2) WHERE id = $1",
    )
    .bind(factor_id)
    .bind(step)
    .execute(&mut **tx)
    .await
    .map_err(AppError::from)?;
    Ok(result.rows_affected())
}

pub async fn set_mfa_enrolled(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    enrolled: bool,
) -> AppResult<u64> {
    let result = sqlx::query("UPDATE users SET mfa_enrolled = $2 WHERE id = $1")
        .bind(user_id)
        .bind(enrolled)
        .execute(&mut **tx)
        .await
        .map_err(AppError::from)?;
    Ok(result.rows_affected())
}

// =============================================================================
// Recovery codes
// =============================================================================

/// Invalidate the whole outstanding batch.
///
/// Consumed rather than deleted: the runtime role holds no DELETE on
/// `recovery_codes`, and a consumed row keeps its digest reserved in the unique
/// index so a regenerated batch can never collide with a retired code.
pub async fn consume_recovery_batch(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
) -> AppResult<u64> {
    let result = sqlx::query(
        "UPDATE recovery_codes SET consumed_at = now() WHERE user_id = $1 AND consumed_at IS NULL",
    )
    .bind(user_id)
    .execute(&mut **tx)
    .await
    .map_err(AppError::from)?;
    Ok(result.rows_affected())
}

pub async fn insert_recovery_code(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    user_id: Uuid,
    batch_id: Uuid,
    code_hash: &[u8],
) -> AppResult<()> {
    sqlx::query(
        "INSERT INTO recovery_codes (id, user_id, batch_id, code_hash) VALUES ($1,$2,$3,$4)",
    )
    .bind(id)
    .bind(user_id)
    .bind(batch_id)
    .bind(code_hash)
    .execute(&mut **tx)
    .await
    .map_err(AppError::from)?;
    Ok(())
}

/// Single-use consumption, gated on rows affected.
///
/// The `user_id` predicate is not decoration: `code_hash` is globally unique, so
/// without it a code belonging to another account would be consumable by anyone
/// who obtained it, and the session it unlocked would be the wrong one.
pub async fn consume_recovery_code(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    code_hash: &[u8],
) -> AppResult<u64> {
    let result = sqlx::query(
        r#"
        UPDATE recovery_codes
           SET consumed_at = now()
         WHERE user_id = $1 AND code_hash = $2 AND consumed_at IS NULL
        "#,
    )
    .bind(user_id)
    .bind(code_hash)
    .execute(&mut **tx)
    .await
    .map_err(AppError::from)?;
    Ok(result.rows_affected())
}

pub async fn count_live_recovery_codes(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
) -> AppResult<i64> {
    let (count,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM recovery_codes WHERE user_id = $1 AND consumed_at IS NULL",
    )
    .bind(user_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::from)?;
    Ok(count)
}

// =============================================================================
// Outbox
// =============================================================================

/// Enqueue a mail event **inside the caller's transaction**.
///
/// The event and the state change it describes commit together: a `tokio::spawn`
/// after commit loses the side effect on a crash, and a send before commit produces
/// a side effect for a change that rolled back.
///
/// This lives here only because `modules::outbox` does not exist yet. When it
/// lands, this function moves to `outbox::service` and this module calls that,
/// per `MODULE_GUIDE.md` §1 — a module calls another module's service, never its
/// repository.
pub async fn enqueue_outbox_event(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    event_type: &str,
    payload: Value,
) -> AppResult<()> {
    sqlx::query("INSERT INTO outbox_events (id, event_type, payload) VALUES ($1,$2,$3)")
        .bind(id)
        .bind(event_type)
        .bind(payload)
        .execute(&mut **tx)
        .await
        .map_err(AppError::from)?;
    Ok(())
}
