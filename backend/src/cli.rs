//! Command-line interface: `serve`, `migrate`, `verify-audit`, `check-config`.
//!
//! Hand-parsed rather than via a CLI framework. The surface is four commands with
//! no flags; a derive-macro argument parser would add a dependency tree and a
//! layer of indirection for something a reviewer can read in one screen.

use std::sync::Arc;
use std::time::Duration;

use crate::app::AppState;
use crate::modules::audit::chain;
use crate::platform::config::Config;
use crate::platform::crypto::password;
use crate::platform::database;
use crate::platform::http::rate_limit::InProcessRateLimiter;
use crate::platform::observability::{logging, metrics::Metrics};

pub const USAGE: &str = "\
roleblank-api <command>

  serve           run the HTTP API
  migrate         apply pending database migrations (run as the migrator role)
  verify-audit    verify the audit hash chain and report the result
  check-config    validate configuration and exit without binding a port
";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Serve,
    Migrate,
    VerifyAudit,
    CheckConfig,
}

impl Command {
    pub fn from_args(mut args: impl Iterator<Item = String>) -> Result<Self, String> {
        match args.next().as_deref() {
            // Defaulting to `serve` keeps the container image's CMD simple while
            // still allowing an explicit subcommand.
            None | Some("serve") => Ok(Command::Serve),
            Some("migrate") => Ok(Command::Migrate),
            Some("verify-audit") => Ok(Command::VerifyAudit),
            Some("check-config") => Ok(Command::CheckConfig),
            Some("-h") | Some("--help") | Some("help") => Err(String::new()),
            Some(other) => Err(format!("unknown command `{other}`")),
        }
    }
}

pub async fn run(command: Command) -> Result<(), String> {
    match command {
        Command::CheckConfig => {
            logging::init_basic();
            let config = Config::from_env()?;
            println!(
                "configuration is valid for environment `{}`",
                config.environment.as_str()
            );
            Ok(())
        }
        Command::Migrate => {
            logging::init_basic();
            let config = Config::from_env()?;
            let pool = database::connect(&config.database)
                .await
                .map_err(|e| format!("{e}"))?;
            database::run_migrations(&pool)
                .await
                .map_err(|e| format!("{e}"))?;
            println!("migrations applied");
            pool.close().await;
            Ok(())
        }
        Command::VerifyAudit => {
            logging::init_basic();
            let config = Config::from_env()?;
            let pool = database::connect(&config.database)
                .await
                .map_err(|e| format!("{e}"))?;
            let outcome = verify_audit(&pool, &config).await?;
            pool.close().await;
            match outcome {
                chain::VerificationOutcome::Intact {
                    entries_checked,
                    last_seq,
                } => {
                    println!(
                        "audit chain INTACT — {entries_checked} entries verified, head at seq {last_seq}"
                    );
                    println!(
                        "note: this proves no modification was made WITHOUT the chain key. \
                         It is not a claim of tamper-proofing against an adversary holding \
                         both the database and the key (see docs/adr/ADR-006-audit-integrity.md)."
                    );
                    Ok(())
                }
                other => Err(format!("audit chain verification FAILED: {other:?}")),
            }
        }
        Command::Serve => serve().await,
    }
}

/// Read the whole chain and verify it, including that the head record agrees with
/// the last row — which is what detects a truncated tail.
async fn verify_audit(
    pool: &sqlx::PgPool,
    config: &Config,
) -> Result<chain::VerificationOutcome, String> {
    #[derive(sqlx::FromRow)]
    struct Row {
        seq: i64,
        id: uuid::Uuid,
        occurred_at: time::OffsetDateTime,
        actor_user_id: Option<uuid::Uuid>,
        actor_principal_type: Option<String>,
        actor_session_id: Option<uuid::Uuid>,
        action_code: String,
        target_type: Option<String>,
        target_id: Option<uuid::Uuid>,
        outcome: String,
        request_id: Option<String>,
        source_ip_hint: Option<String>,
        metadata: serde_json::Value,
        prev_hash: Option<Vec<u8>>,
        entry_hash: Vec<u8>,
        chain_version: i16,
    }

    let rows: Vec<Row> = sqlx::query_as(
        "SELECT seq, id, occurred_at, actor_user_id, actor_principal_type, actor_session_id,
                action_code, target_type, target_id, outcome, request_id, source_ip_hint,
                metadata, prev_hash, entry_hash, chain_version
           FROM audit_events ORDER BY seq ASC",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| format!("failed to read audit events: {e}"))?;

    let head: Option<(i64, Option<Vec<u8>>)> =
        sqlx::query_as("SELECT last_seq, last_hash FROM audit_chain_head WHERE id")
            .fetch_optional(pool)
            .await
            .map_err(|e| format!("failed to read the audit chain head: {e}"))?;

    let first_seq = rows.first().map(|r| r.seq);
    let entries: Vec<chain::StoredEntry> = rows
        .into_iter()
        .map(|r| {
            (
                chain::ChainedEntry {
                    // Read from the row, never assumed: the layout a digest was
                    // computed under is a property of the entry, not of this build.
                    chain_version: r.chain_version,
                    seq: r.seq,
                    id: r.id,
                    occurred_at: r.occurred_at,
                    actor_user_id: r.actor_user_id,
                    actor_principal_type: r.actor_principal_type,
                    actor_session_id: r.actor_session_id,
                    action_code: r.action_code,
                    target_type: r.target_type,
                    target_id: r.target_id,
                    outcome: r.outcome,
                    request_id: r.request_id,
                    source_ip_hint: r.source_ip_hint,
                    metadata: r.metadata,
                },
                r.entry_hash,
                r.prev_hash,
            )
        })
        .collect();

    let result = chain::verify_run(&config.security.audit_chain_key, &entries, None, first_seq);

    // The run can be internally consistent while the tail has been removed. The
    // head record is what makes truncation detectable.
    if let (chain::VerificationOutcome::Intact { last_seq, .. }, Some((head_seq, _))) =
        (&result, &head)
    {
        if last_seq != head_seq {
            return Ok(chain::VerificationOutcome::HeadMismatch {
                head_seq: *head_seq,
                last_row_seq: *last_seq,
            });
        }
    }

    Ok(result)
}

async fn serve() -> Result<(), String> {
    let config = Config::from_env()?;
    logging::init(&config);
    crate::platform::http::middleware::log_posture(&config);

    let pool = database::connect(&config.database)
        .await
        .map_err(|e| format!("{e}"))?;

    // Refuse to serve against a schema this binary does not expect. A process
    // talking to a database migrated by a different build is not merely unready,
    // it is dangerous — a missing column in an authorisation query would fail
    // open-shaped in ways that are hard to predict.
    if !database::migrations_are_current(&pool)
        .await
        .map_err(|e| format!("{e}"))?
    {
        return Err(
            "the database schema is behind this binary. Run `roleblank-api migrate` first."
                .to_string(),
        );
    }

    // The permission catalogue in code must match the database exactly. Either
    // direction of drift is a security problem (see modules::authorization::catalog).
    verify_permission_catalog(&pool).await?;

    let hasher = password::Hasher::new(
        config.security.argon2,
        config.security.hashing_max_concurrency,
    )
    .map_err(|e| format!("{e}"))?;
    let keyring = config.keyring().map_err(|e| format!("{e}"))?;

    let state = AppState {
        chain_key: Arc::new(config.security.audit_chain_key.clone()),
        config: Arc::new(config),
        db: pool.clone(),
        hasher: Arc::new(hasher),
        keyring: Arc::new(keyring),
        limiter: Arc::new(InProcessRateLimiter::default()),
        metrics: Arc::new(Metrics::new()),
    };

    let shutdown = tokio_util::sync::CancellationToken::new();

    // The outbox worker runs in-process. Claiming uses `FOR UPDATE SKIP LOCKED`,
    // so this is still correct if a second instance is ever deployed.
    // The worker id is recorded in `outbox_events.claimed_by`. It identifies *this
    // process*, not this deployment: with several replicas, "which one is holding
    // that row" is the question an operator actually needs answered.
    let worker_id = format!(
        "{}-{}",
        std::env::var("HOSTNAME").unwrap_or_else(|_| "roleblank-api".into()),
        std::process::id()
    );
    let worker = crate::modules::outbox::OutboxWorker::new(
        state.db.clone(),
        crate::modules::outbox::mail::build(&state.config.mail),
        state.metrics.clone(),
        state.config.outbox_poll_interval,
        state.config.outbox_batch_size,
        worker_id,
    );
    let worker_token = shutdown.clone();
    let worker_handle = tokio::spawn(async move { worker.run(worker_token).await });

    let router = crate::routes::build(state.clone());
    let listener = tokio::net::TcpListener::bind(&state.config.bind_address)
        .await
        .map_err(|e| format!("failed to bind {}: {e}", state.config.bind_address))?;

    tracing::info!(address = %state.config.bind_address, "roleblank-api listening");

    let signal_token = shutdown.clone();
    let server = axum::serve(
        listener,
        router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        wait_for_shutdown_signal().await;
        tracing::info!("shutdown signal received; draining in-flight requests");
        signal_token.cancel();
    });

    let result = server.await.map_err(|e| format!("server error: {e}"));

    // Give the worker a bounded window to finish its current batch. It must not be
    // abandoned mid-claim: a claimed row whose worker vanished is retried after its
    // backoff, but a clean stop avoids the duplicate-send window entirely.
    shutdown.cancel();
    match tokio::time::timeout(Duration::from_secs(15), worker_handle).await {
        Ok(_) => tracing::info!("outbox worker stopped cleanly"),
        Err(_) => tracing::warn!("outbox worker did not stop within 15s; continuing shutdown"),
    }

    pool.close().await;
    tracing::info!("database pool closed; shutdown complete");
    result
}

async fn verify_permission_catalog(pool: &sqlx::PgPool) -> Result<(), String> {
    let rows: Vec<(String, String, String, bool)> = sqlx::query_as(
        "SELECT code, module, max_principal_type, is_dangerous FROM permissions ORDER BY code",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| format!("failed to read the permission catalogue: {e}"))?;

    match crate::modules::authorization::catalog::diff_against(&rows) {
        None => {
            tracing::info!(permissions = rows.len(), "permission catalogue verified");
            Ok(())
        }
        Some(differences) => Err(format!(
            "the permission catalogue in code does not match the database:\n  - {differences}\n\
             Refusing to start: either direction of drift is a security problem."
        )),
    }
}

/// Wait for SIGTERM (orchestrator) or SIGINT (a developer's Ctrl-C).
async fn wait_for_shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(e) => {
                // Without SIGTERM handling a container stop becomes a hard kill.
                // Loud, because it silently degrades every future deployment.
                tracing::error!("failed to install the SIGTERM handler: {e}");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Command, String> {
        Command::from_args(args.iter().map(|s| s.to_string()))
    }

    #[test]
    fn no_argument_defaults_to_serve() {
        assert_eq!(parse(&[]).unwrap(), Command::Serve);
    }

    #[test]
    fn every_subcommand_parses() {
        assert_eq!(parse(&["serve"]).unwrap(), Command::Serve);
        assert_eq!(parse(&["migrate"]).unwrap(), Command::Migrate);
        assert_eq!(parse(&["verify-audit"]).unwrap(), Command::VerifyAudit);
        assert_eq!(parse(&["check-config"]).unwrap(), Command::CheckConfig);
    }

    #[test]
    fn an_unknown_command_is_refused_rather_than_defaulting_to_serve() {
        // Defaulting an unrecognised argument to `serve` would mean a typo in an
        // orchestrator's command line silently starts the API instead of failing.
        let err = parse(&["migrat"]).unwrap_err();
        assert!(err.contains("unknown command"));
        assert!(parse(&["--migrate"]).is_err());
        assert!(parse(&["serve --port 80"]).is_err());
    }

    #[test]
    fn help_exits_without_an_error_message() {
        assert_eq!(parse(&["--help"]).unwrap_err(), "");
        assert!(USAGE.contains("verify-audit"));
    }
}
