//! PostgreSQL connection pool, migrations and readiness.

use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions};
use sqlx::ConnectOptions;
use std::str::FromStr;
use std::time::Duration;

use crate::platform::config::DatabaseConfig;
use crate::platform::errors::AppError;

/// sqlx embeds `migrations/` at compile time, so the binary carries its own
/// schema history and a deployment cannot drift from the image it shipped with.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Build the pool.
///
/// Migrations are deliberately **not** run here. Running them implicitly at
/// startup means every rolling deploy races N replicas against the same schema
/// change, and a bad migration takes down the service rather than failing a
/// deliberate step. `roleblank-api migrate` is a separate command run by the
/// operator (brief §8).
pub async fn connect(config: &DatabaseConfig) -> Result<PgPool, AppError> {
    let mut options = PgConnectOptions::from_str(config.url.expose())
        .map_err(|_| AppError::Internal("DATABASE_URL is not a valid PostgreSQL URL".into()))?;

    // Statements are logged at TRACE only. At any higher level, parameter values —
    // including a password hash being written, or a token digest being looked up —
    // would reach the ordinary log stream.
    // Session parameters are sent in the startup packet rather than as an
    // `after_connect` hook running `SET`: they then apply to the very first
    // statement on the connection, with no window in which a query could run
    // unbounded.
    //
    // A runaway query is a denial of service against the whole pool, so the bound
    // is set at the source rather than hoped for at each call site.
    let statement_timeout_ms = config.statement_timeout.as_millis().to_string();
    options = options
        .application_name("roleblank-api")
        .options([
            ("statement_timeout", statement_timeout_ms.as_str()),
            // A transaction left open holds locks — including the audit chain
            // lock — so an abandoned one is killed rather than left to block.
            ("idle_in_transaction_session_timeout", "30000"),
        ])
        .log_statements(tracing::log::LevelFilter::Trace)
        .log_slow_statements(tracing::log::LevelFilter::Warn, Duration::from_millis(500));

    PgPoolOptions::new()
        .max_connections(config.max_connections)
        .min_connections(config.min_connections)
        .acquire_timeout(config.acquire_timeout)
        .idle_timeout(Some(config.idle_timeout))
        .max_lifetime(Some(config.max_lifetime))
        .connect_with(options)
        .await
        .map_err(|e| {
            // The driver's message can contain the connection string. Only a fixed
            // label is logged.
            tracing::error!("failed to establish the database pool");
            AppError::Internal(format!(
                "database pool initialisation failed: {}",
                kind_of(&e)
            ))
        })
}

fn kind_of(e: &sqlx::Error) -> &'static str {
    match e {
        sqlx::Error::Io(_) => "io",
        sqlx::Error::Tls(_) => "tls",
        sqlx::Error::Configuration(_) => "configuration",
        sqlx::Error::Database(_) => "database",
        sqlx::Error::PoolTimedOut => "pool_timeout",
        _ => "other",
    }
}

/// Apply pending migrations. Called only by the explicit `migrate` subcommand.
pub async fn run_migrations(pool: &PgPool) -> Result<(), AppError> {
    MIGRATOR
        .run(pool)
        .await
        .map_err(|e| AppError::Internal(format!("migration failed: {e}")))?;
    Ok(())
}

/// Whether the schema is at the version this binary expects.
///
/// Used by `/health/ready`: a process talking to a database migrated by a
/// different build is not ready, it is dangerous.
pub async fn migrations_are_current(pool: &PgPool) -> Result<bool, AppError> {
    let applied: Vec<(i64,)> = sqlx::query_as(
        "SELECT version FROM _sqlx_migrations WHERE success = true ORDER BY version",
    )
    .fetch_all(pool)
    .await
    .map_err(AppError::from)?;
    let applied: Vec<i64> = applied.into_iter().map(|(v,)| v).collect();
    Ok(MIGRATOR.iter().all(|m| applied.contains(&m.version)))
}

/// A cheap liveness probe against the database.
pub async fn ping(pool: &PgPool) -> Result<(), AppError> {
    sqlx::query("SELECT 1")
        .execute(pool)
        .await
        .map_err(AppError::from)?;
    Ok(())
}

/// Pool statistics for the metrics endpoint.
pub fn pool_stats(pool: &PgPool) -> (u32, usize) {
    (pool.size(), pool.num_idle())
}

/// Take the audit chain's serialising lock.
///
/// Every audited mutation calls this inside its transaction. It is what makes the
/// hash chain well-defined under concurrency: without it, two concurrent inserts
/// could read the same `prev_hash` and produce a fork indistinguishable from
/// tampering (ADR-006).
///
/// The cost is that audited mutations serialise on commit. At company write
/// volumes that is acceptable and measured; see PERFORMANCE_REPORT.md.
pub async fn lock_audit_chain(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(i64, Option<Vec<u8>>), AppError> {
    let row: (i64, Option<Vec<u8>>) =
        sqlx::query_as("SELECT last_seq, last_hash FROM audit_chain_head WHERE id FOR UPDATE")
            .fetch_one(&mut **tx)
            .await
            .map_err(AppError::from)?;
    Ok(row)
}

/// Take a transaction-scoped advisory lock.
///
/// Used by bootstrap so that a hundred concurrent attempts serialise rather than
/// all discovering an empty `system_ownership` at the same instant. Released
/// automatically at commit or rollback, so a crashed request cannot leave it held.
pub async fn advisory_xact_lock(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    key: i64,
) -> Result<(), AppError> {
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(key)
        .execute(&mut **tx)
        .await
        .map_err(AppError::from)?;
    Ok(())
}

/// Advisory lock keys. Constants so two call sites cannot pick the same number by
/// accident, which would deadlock unrelated operations against each other.
pub mod lock_keys {
    /// First-run bootstrap.
    pub const BOOTSTRAP: i64 = 0x726F_6C65_0000_0001;
    /// Outbox worker leadership is NOT locked — claiming uses
    /// `FOR UPDATE SKIP LOCKED` so several workers can run concurrently.
    pub const OUTBOX_MAINTENANCE: i64 = 0x726F_6C65_0000_0002;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_embedded_migration_has_a_unique_ascending_version() {
        let versions: Vec<i64> = MIGRATOR.iter().map(|m| m.version).collect();
        assert!(!versions.is_empty(), "no migrations were embedded");
        let mut sorted = versions.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            versions, sorted,
            "migration versions must be unique and ascending"
        );
    }

    #[test]
    fn migrations_are_not_reversible_by_accident() {
        // Down migrations are not used: an automatic rollback of a schema change on
        // a live database is how data gets destroyed. Destructive evolution is
        // expand -> migrate -> contract, by hand, per docs/backend/08-operations.md.
        for m in MIGRATOR.iter() {
            assert!(
                matches!(m.migration_type, sqlx::migrate::MigrationType::Simple),
                "migration {} is reversible; this project uses forward-only migrations",
                m.version
            );
        }
    }

    #[test]
    fn advisory_lock_keys_are_distinct() {
        assert_ne!(lock_keys::BOOTSTRAP, lock_keys::OUTBOX_MAINTENANCE);
    }
}
