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

/// The keys of the non-sensitive feature flags that are currently on.
///
/// Keys only. `description` and `is_security_sensitive` stay in the database:
/// the descriptions name unbuilt modules and internal documents, and the
/// sensitivity marker tells a caller which toggles are worth attacking.
///
/// # Why the sensitivity filter is in the query
///
/// Withholding the marker while returning the key it marks was self-defeating:
/// the marker exists to say "this toggle is worth attacking", and the key is the
/// name of the thing to attack. `GET /api/v1/system/info` authenticates and
/// authorises nothing beyond that — it is served whole to an external CLIENT — so
/// this was the one place a security-sensitive flag name crossed the client
/// envelope. `GET /api/v1/feature-flags` has always applied the same split and
/// requires `settings.security.write` to see past it
/// (`settings::service::list_feature_flags`); this brings the unauthenticated-in-
/// all-but-name endpoint into line with it.
///
/// The filter is in the **query**, not applied to the result: a caller who may not
/// see a sensitive key never has it in this process's memory, let alone in a
/// response struct one refactor away from being serialised.
///
/// `LIMIT` is not a defensive guess — the table is operator-managed and tiny —
/// but it bounds the response of an endpoint that any authenticated principal can
/// call, which is cheap insurance against a mis-seeded environment.
pub async fn enabled_feature_flag_keys(pool: &PgPool) -> AppResult<Vec<String>> {
    let keys: Vec<String> = sqlx::query_scalar(
        "SELECT key FROM feature_flags \
          WHERE enabled = true AND is_security_sensitive = false \
          ORDER BY key LIMIT 200",
    )
    .fetch_all(pool)
    .await
    .map_err(AppError::from)?;
    Ok(keys)
}
