//! Reads backing the system endpoints. Explicit columns, parameterised always.

use sqlx::PgPool;

use crate::platform::errors::{AppError, AppResult};

/// Has bootstrap happened?
///
/// Read from `system_state.initialized_at` rather than from a cached flag: the
/// value is immutable once set, but a cache that is wrong once is wrong forever.
pub async fn is_initialized(pool: &PgPool) -> AppResult<bool> {
    let row: Option<(bool,)> =
        sqlx::query_as("SELECT (initialized_at IS NOT NULL) AS initialized FROM system_state")
            .fetch_optional(pool)
            .await
            .map_err(AppError::from)?;
    // No row at all means the migration that seeds the singleton has not run. That
    // is "not initialised", not an error to be surfaced to a caller.
    Ok(row.map(|(v,)| v).unwrap_or(false))
}

/// The keys of the feature flags that are currently on.
///
/// Keys only. `description` and `is_security_sensitive` stay in the database:
/// the descriptions name unbuilt modules and internal documents, and the
/// sensitivity marker tells a caller which toggles are worth attacking.
///
/// `LIMIT` is not a defensive guess — the table is operator-managed and tiny —
/// but it bounds the response of an endpoint that any authenticated principal can
/// call, which is cheap insurance against a mis-seeded environment.
pub async fn enabled_feature_flag_keys(pool: &PgPool) -> AppResult<Vec<String>> {
    let keys: Vec<String> = sqlx::query_scalar(
        "SELECT key FROM feature_flags WHERE enabled = true ORDER BY key LIMIT 200",
    )
    .fetch_all(pool)
    .await
    .map_err(AppError::from)?;
    Ok(keys)
}
