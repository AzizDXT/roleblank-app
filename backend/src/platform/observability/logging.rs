//! Structured logging setup.
//!
//! Production logs are JSON on stdout, one object per line, for an aggregator to
//! parse. Development logs are human-readable. The distinction is configuration,
//! and production refuses to start with the human format (see `Config`).
//!
//! What must never appear in a log is enforced at the source rather than by a
//! scrubbing pass: secrets live in `Secret<T>` (no `Display`, redacting `Debug`),
//! user-controlled strings go through `sanitize::log_value`, and SQL parameters are
//! only logged at `TRACE`.

use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

use crate::platform::config::Config;

/// Initialise the global subscriber. Called once, at startup.
pub fn init(config: &Config) {
    // `RUST_LOG` when set, otherwise a deliberate default: our own crate at INFO,
    // dependencies at WARN. Notably `sqlx` is pinned to WARN so that a change to
    // the default filter can never start emitting statements with bound
    // parameters at INFO.
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new("info,roleblank_backend=info,sqlx=warn,tower_http=warn,hyper=warn")
    });

    let registry = tracing_subscriber::registry().with(filter);

    if config.log_json {
        registry
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .flatten_event(true)
                    .with_current_span(true)
                    .with_span_list(false)
                    .with_target(true)
                    .with_file(false)
                    .with_line_number(false)
                    // File and line are omitted deliberately: they are internal
                    // path disclosure if logs are ever shipped somewhere shared,
                    // and the target plus the message identify the site well
                    // enough.
                    .with_timer(tracing_subscriber::fmt::time::UtcTime::rfc_3339()),
            )
            .init();
    } else {
        registry
            .with(
                tracing_subscriber::fmt::layer()
                    .with_target(true)
                    .with_timer(tracing_subscriber::fmt::time::UtcTime::rfc_3339()),
            )
            .init();
    }

    tracing::info!(
        environment = config.environment.as_str(),
        format = if config.log_json { "json" } else { "text" },
        "logging initialised"
    );
}

/// A minimal subscriber for tests and for the CLI subcommands, which must not
/// depend on a full configuration being loadable.
pub fn init_basic() {
    let _ = tracing_subscriber::registry()
        .with(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,sqlx=warn")),
        )
        .with(tracing_subscriber::fmt::layer().with_target(false))
        .try_init();
}
