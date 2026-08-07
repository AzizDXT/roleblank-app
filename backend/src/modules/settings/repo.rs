//! Settings and feature-flag persistence.
//!
//! Every statement in this file is a `&'static str` literal with bind parameters.
//! Nothing is assembled at run time, so there is no place for a caller's value to
//! be spliced into the statement text — sqlx enforces this at compile time via
//! `SqlSafeStr`, and the explicit column lists mean no `SELECT *` can pull a column
//! nobody reviewed into memory.
//!
//! The sensitivity filter is a **SQL predicate bound as a parameter**, never a
//! post-filter in Rust: a row the caller may not see is not loaded into this
//! process at all, so a later serialisation mistake cannot expose it.

use sqlx::PgPool;
use sqlx::{Postgres, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::platform::errors::{AppError, AppResult};

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SettingRow {
    pub key: String,
    pub value: serde_json::Value,
    pub value_type: String,
    pub is_security_sensitive: bool,
    pub description: String,
    pub version: i32,
    pub updated_by: Option<Uuid>,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct FeatureFlagRow {
    pub key: String,
    pub enabled: bool,
    pub is_security_sensitive: bool,
    pub description: String,
    pub version: i32,
    pub updated_by: Option<Uuid>,
    pub updated_at: OffsetDateTime,
}

// ---------------------------------------------------------------------------
// system_settings
// ---------------------------------------------------------------------------

/// `$1` is the caller's sensitivity entitlement. The `LIMIT` is a hard ceiling: the
/// table is operator-managed and tiny, so the bound exists only so that the cost of
/// this endpoint cannot be moved by seeding it with rows.
const LIST_SETTINGS: &str = "SELECT key, value, value_type, is_security_sensitive, description, \
            version, updated_by, updated_at \
       FROM system_settings \
      WHERE ($1 OR is_security_sensitive = false) \
      ORDER BY key \
      LIMIT 500";

/// `FOR UPDATE` is what closes the window between deciding on
/// `is_security_sensitive` and writing: without it, a concurrent change to the
/// sensitivity marker could let a write authorised as "ordinary" land on a row that
/// had become security-sensitive (TH-43).
const FIND_SETTING_FOR_UPDATE: &str =
    "SELECT key, value, value_type, is_security_sensitive, description, \
            version, updated_by, updated_at \
       FROM system_settings \
      WHERE key = $1 \
        FOR UPDATE";

const GET_SETTING: &str = "SELECT key, value, value_type, is_security_sensitive, description, \
            version, updated_by, updated_at \
       FROM system_settings \
      WHERE key = $1";

const UPDATE_SETTING: &str = "UPDATE system_settings \
        SET value = $1, version = version + 1, updated_by = $2, updated_at = now() \
      WHERE key = $3 AND version = $4";

pub async fn list_settings(pool: &PgPool, include_sensitive: bool) -> AppResult<Vec<SettingRow>> {
    sqlx::query_as::<_, SettingRow>(LIST_SETTINGS)
        .bind(include_sensitive)
        .fetch_all(pool)
        .await
        .map_err(AppError::from)
}

/// Load one setting and hold its row lock for the rest of the transaction.
pub async fn find_setting_for_update(
    tx: &mut Transaction<'_, Postgres>,
    key: &str,
) -> AppResult<Option<SettingRow>> {
    sqlx::query_as::<_, SettingRow>(FIND_SETTING_FOR_UPDATE)
        .bind(key)
        .fetch_optional(&mut **tx)
        .await
        .map_err(AppError::from)
}

/// Optimistic-concurrency update. Returns the number of rows affected; zero means
/// the caller's `version` was stale and nothing was overwritten.
pub async fn update_setting(
    tx: &mut Transaction<'_, Postgres>,
    key: &str,
    value: &serde_json::Value,
    expected_version: i32,
    updated_by: Uuid,
) -> AppResult<u64> {
    let result = sqlx::query(UPDATE_SETTING)
        .bind(value)
        .bind(updated_by)
        .bind(key)
        .bind(expected_version)
        .execute(&mut **tx)
        .await
        .map_err(AppError::from)?;
    Ok(result.rows_affected())
}

/// Re-read inside the transaction after the update, so the response carries the
/// committed version rather than one the service incremented for itself.
pub async fn get_setting(
    tx: &mut Transaction<'_, Postgres>,
    key: &str,
) -> AppResult<Option<SettingRow>> {
    sqlx::query_as::<_, SettingRow>(GET_SETTING)
        .bind(key)
        .fetch_optional(&mut **tx)
        .await
        .map_err(AppError::from)
}

// ---------------------------------------------------------------------------
// feature_flags
// ---------------------------------------------------------------------------

const LIST_FLAGS: &str =
    "SELECT key, enabled, is_security_sensitive, description, version, updated_by, updated_at \
       FROM feature_flags \
      WHERE ($1 OR is_security_sensitive = false) \
      ORDER BY key \
      LIMIT 500";

const FIND_FLAG_FOR_UPDATE: &str =
    "SELECT key, enabled, is_security_sensitive, description, version, updated_by, updated_at \
       FROM feature_flags \
      WHERE key = $1 \
        FOR UPDATE";

const GET_FLAG: &str =
    "SELECT key, enabled, is_security_sensitive, description, version, updated_by, updated_at \
       FROM feature_flags \
      WHERE key = $1";

const UPDATE_FLAG: &str = "UPDATE feature_flags \
        SET enabled = $1, version = version + 1, updated_by = $2, updated_at = now() \
      WHERE key = $3 AND version = $4";

pub async fn list_feature_flags(
    pool: &PgPool,
    include_sensitive: bool,
) -> AppResult<Vec<FeatureFlagRow>> {
    sqlx::query_as::<_, FeatureFlagRow>(LIST_FLAGS)
        .bind(include_sensitive)
        .fetch_all(pool)
        .await
        .map_err(AppError::from)
}

pub async fn find_flag_for_update(
    tx: &mut Transaction<'_, Postgres>,
    key: &str,
) -> AppResult<Option<FeatureFlagRow>> {
    sqlx::query_as::<_, FeatureFlagRow>(FIND_FLAG_FOR_UPDATE)
        .bind(key)
        .fetch_optional(&mut **tx)
        .await
        .map_err(AppError::from)
}

pub async fn update_flag(
    tx: &mut Transaction<'_, Postgres>,
    key: &str,
    enabled: bool,
    expected_version: i32,
    updated_by: Uuid,
) -> AppResult<u64> {
    let result = sqlx::query(UPDATE_FLAG)
        .bind(enabled)
        .bind(updated_by)
        .bind(key)
        .bind(expected_version)
        .execute(&mut **tx)
        .await
        .map_err(AppError::from)?;
    Ok(result.rows_affected())
}

pub async fn get_flag(
    tx: &mut Transaction<'_, Postgres>,
    key: &str,
) -> AppResult<Option<FeatureFlagRow>> {
    sqlx::query_as::<_, FeatureFlagRow>(GET_FLAG)
        .bind(key)
        .fetch_optional(&mut **tx)
        .await
        .map_err(AppError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_STATEMENTS: &[&str] = &[
        LIST_SETTINGS,
        FIND_SETTING_FOR_UPDATE,
        GET_SETTING,
        UPDATE_SETTING,
        LIST_FLAGS,
        FIND_FLAG_FOR_UPDATE,
        GET_FLAG,
        UPDATE_FLAG,
    ];

    #[test]
    fn no_statement_selects_a_wildcard_or_carries_a_literal() {
        for statement in ALL_STATEMENTS {
            assert!(!statement.contains('*'), "never SELECT *: {statement}");
            assert!(
                !statement.contains('\''),
                "no literal belongs in these statements"
            );
            assert!(!statement.contains(';'), "one statement per query");
            assert!(!statement.contains("--"), "no comment marker");
        }
    }

    /// A write without a `version` guard is a silent overwrite of somebody else's
    /// change. Both update statements must carry one.
    #[test]
    fn every_update_is_guarded_by_a_version() {
        for statement in [UPDATE_SETTING, UPDATE_FLAG] {
            assert!(statement.contains("version = version + 1"));
            assert!(statement.contains("AND version = $4"));
        }
    }

    /// The sensitivity filter must be part of the query, not something the service
    /// is trusted to apply afterwards.
    #[test]
    fn the_listings_filter_sensitive_rows_in_sql() {
        for statement in [LIST_SETTINGS, LIST_FLAGS] {
            assert!(statement.contains("($1 OR is_security_sensitive = false)"));
            assert!(statement.contains("LIMIT 500"));
        }
    }

    /// The decision that selects the required permission is read under a row lock.
    #[test]
    fn the_write_path_locks_the_row_it_authorises_against() {
        for statement in [FIND_SETTING_FOR_UPDATE, FIND_FLAG_FOR_UPDATE] {
            assert!(statement.contains("FOR UPDATE"));
            assert!(statement.contains("is_security_sensitive"));
        }
    }
}
