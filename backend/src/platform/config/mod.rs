//! Typed configuration with fail-closed production validation.
//!
//! The rule this module exists to enforce: **a development convenience must never
//! silently activate in production.** Every relaxation below is gated on
//! `Environment`, and production startup aborts — loudly, before binding a port —
//! when a security-critical value is missing, weak, or obviously a placeholder.
//!
//! Startup failure is the correct behaviour. A backend that boots with a
//! wildcard CORS policy and a `changeme` encryption key is worse than one that
//! does not boot, because the first looks healthy.

pub mod net;

use std::time::Duration;

use crate::platform::crypto::aead;
use crate::platform::crypto::password::Argon2Params;
use crate::shared::secret::Secret;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Environment {
    Development,
    Test,
    Production,
}

impl Environment {
    pub fn is_production(self) -> bool {
        matches!(self, Environment::Production)
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Environment::Development => "development",
            Environment::Test => "test",
            Environment::Production => "production",
        }
    }
}

/// Values that would be catastrophic in production and are common placeholders.
/// Checked case-insensitively as substrings, because `changeme-but-longer` is the
/// same mistake as `changeme`.
const FORBIDDEN_IN_PRODUCTION: &[&str] = &[
    "changeme",
    "change-me",
    "placeholder",
    "example",
    "insecure",
    "notsecret",
    "password",
    "secret123",
    "dev_",
    "development",
    "todo",
    "xxxx",
    "test_secret",
];

#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    pub url: Secret<String>,
    pub max_connections: u32,
    pub min_connections: u32,
    pub acquire_timeout: Duration,
    pub idle_timeout: Duration,
    pub max_lifetime: Duration,
    /// Server-side statement timeout. A query that runs away is a denial of
    /// service against the pool, so every connection is capped at the source.
    pub statement_timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub access_ttl: Duration,
    pub idle_ttl: Duration,
    /// Hard ceiling. No refresh extends it, so every compromise has an end.
    pub absolute_ttl: Duration,
    pub refresh_ttl: Duration,
    pub step_up_window: Duration,
    pub max_per_user: usize,
}

#[derive(Debug, Clone)]
pub struct LimitsConfig {
    pub max_body_bytes: usize,
    pub request_timeout: Duration,
    pub max_page_size: u32,
    pub default_page_size: u32,
}

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub login_per_ip_per_minute: u32,
    pub login_per_account_per_minute: u32,
    pub mfa_per_session_per_minute: u32,
    pub refresh_per_ip_per_minute: u32,
    pub password_reset_per_ip_per_hour: u32,
    pub registration_per_ip_per_hour: u32,
    /// Deliberately separate from `registration_per_ip_per_hour`, and higher.
    ///
    /// Accepting an invitation requires a high-entropy token that an authorised
    /// internal principal issued to a specific address, so it is a far lower-risk
    /// flow than anonymous self-registration. Sharing one budget let an attacker
    /// hammering `/api/v1/registration` block invitation acceptance for everyone
    /// behind the same address — a corporate NAT — and capped onboarding at three
    /// people per hour per office.
    pub invitation_accept_per_ip_per_hour: u32,
    pub bootstrap_per_ip_per_hour: u32,
    /// The general authenticated budget, keyed on the **user id**.
    ///
    /// Keyed on the principal rather than the address for two reasons that pull in
    /// opposite directions and are both real: an office behind one NAT is many
    /// people who must not share a budget, and one compromised account spread over
    /// many sessions is one attacker who must not multiply theirs. A user id is the
    /// only key that gets both right.
    pub general_per_principal_per_minute: u32,
    /// The same budget for the system owner, deliberately higher.
    ///
    /// ROOT is not exempt from physics — an unbounded owner session is still a way
    /// to hurt the system — but the owner is also the account that recovers the
    /// company from an incident, and throttling it during one would be its own
    /// outage. See `docs/backend/RATE_LIMIT_ARCHITECTURE.md` §ROOT.
    pub general_root_per_minute: u32,
    /// A coarse per-address ceiling applied **before** authentication.
    ///
    /// Its job is narrow: bound the work an unauthenticated flood can force, since
    /// resolving a bearer token costs a database query whether or not the token is
    /// real. It is deliberately generous, because a corporate NAT is a legitimate
    /// crowd behind one address and this layer cannot tell them apart.
    pub general_per_ip_per_minute: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            login_per_ip_per_minute: 10,
            login_per_account_per_minute: 5,
            mfa_per_session_per_minute: 5,
            refresh_per_ip_per_minute: 60,
            password_reset_per_ip_per_hour: 5,
            registration_per_ip_per_hour: 3,
            invitation_accept_per_ip_per_hour: 20,
            bootstrap_per_ip_per_hour: 5,
            general_per_principal_per_minute: 600,
            general_root_per_minute: 3_000,
            general_per_ip_per_minute: 3_000,
        }
    }
}

impl RateLimitConfig {
    /// Read the limits from the environment, falling back to the defaults above.
    ///
    /// Previously this struct was built with `Default::default()` and read nothing,
    /// so an operator facing abuse could not tighten a single limit without a
    /// rebuild — a control that exists in configuration but not in configuration.
    /// Recorded as a finding in the acceptance audit; closed here.
    ///
    /// A limit of `0` is rejected rather than treated as "unlimited": a zero quota
    /// would refuse every request, and reading it as its opposite is exactly the
    /// kind of silent inversion that a security control must never do.
    fn from_env(errors: &mut ConfigErrors) -> Self {
        let d = Self::default();
        let read = |key: &str, default: u32, errors: &mut ConfigErrors| -> u32 {
            let value = env_parse(key, default, errors);
            if value == 0 {
                errors.push(format!(
                    "{key}: a rate limit of 0 would refuse every request;                      omit the variable to use the default, or set a positive quota"
                ));
                default
            } else {
                value
            }
        };
        Self {
            login_per_ip_per_minute: read(
                "RB_RATE_LOGIN_PER_IP_PER_MINUTE",
                d.login_per_ip_per_minute,
                errors,
            ),
            login_per_account_per_minute: read(
                "RB_RATE_LOGIN_PER_ACCOUNT_PER_MINUTE",
                d.login_per_account_per_minute,
                errors,
            ),
            mfa_per_session_per_minute: read(
                "RB_RATE_MFA_PER_SESSION_PER_MINUTE",
                d.mfa_per_session_per_minute,
                errors,
            ),
            refresh_per_ip_per_minute: read(
                "RB_RATE_REFRESH_PER_IP_PER_MINUTE",
                d.refresh_per_ip_per_minute,
                errors,
            ),
            password_reset_per_ip_per_hour: read(
                "RB_RATE_PASSWORD_RESET_PER_IP_PER_HOUR",
                d.password_reset_per_ip_per_hour,
                errors,
            ),
            registration_per_ip_per_hour: read(
                "RB_RATE_REGISTRATION_PER_IP_PER_HOUR",
                d.registration_per_ip_per_hour,
                errors,
            ),
            invitation_accept_per_ip_per_hour: read(
                "RB_RATE_INVITATION_ACCEPT_PER_IP_PER_HOUR",
                d.invitation_accept_per_ip_per_hour,
                errors,
            ),
            bootstrap_per_ip_per_hour: read(
                "RB_RATE_BOOTSTRAP_PER_IP_PER_HOUR",
                d.bootstrap_per_ip_per_hour,
                errors,
            ),
            general_per_principal_per_minute: read(
                "RB_RATE_GENERAL_PER_PRINCIPAL_PER_MINUTE",
                d.general_per_principal_per_minute,
                errors,
            ),
            general_root_per_minute: read(
                "RB_RATE_GENERAL_ROOT_PER_MINUTE",
                d.general_root_per_minute,
                errors,
            ),
            general_per_ip_per_minute: read(
                "RB_RATE_GENERAL_PER_IP_PER_MINUTE",
                d.general_per_ip_per_minute,
                errors,
            ),
        }
    }
}

/// How outbound mail is handled.
///
/// There is deliberately no production implementation yet. `Disabled` and
/// `DevSink` both *record* that a message was due without pretending it was
/// delivered — the brief forbids fake email success — and production refuses to
/// start with either selected once a flow that needs mail is enabled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MailProviderKind {
    /// Log the event id and type only. Never the token, never the link.
    DevSink,
    /// Write the full message to a directory so a developer can open it.
    DevFile { directory: String },
    /// Refuse to accept mail work at all.
    Disabled,
    /// The production path: SMTP over TLS, and nothing else.
    ///
    /// Deliberately narrow. A single well-understood transport that every provider
    /// speaks beats an SDK per vendor, and it keeps the credential surface to one
    /// username and one password held as a `Secret`.
    Smtp(Box<SmtpConfig>),
}

/// Connection details for the SMTP transport.
///
/// `implicit_tls` selects between the two ways SMTP is secured, because getting
/// this wrong silently sends credentials in clear text:
///
/// * `true`  — TLS from the first byte, conventionally port 465 (SMTPS).
/// * `false` — connect in clear, then **require** STARTTLS before authenticating.
///   Conventionally port 587. This is not opportunistic: if the server does not
///   offer STARTTLS the connection fails rather than continuing unencrypted.
///
/// There is no third option. Unencrypted SMTP is not configurable here at all.
#[derive(Clone)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub implicit_tls: bool,
    pub username: String,
    pub password: Secret<String>,
    /// The envelope sender, e.g. `RoleBlank <no-reply@example.com>`.
    pub from: String,
}

impl std::fmt::Debug for SmtpConfig {
    /// Never renders the password, and never the username either — an SMTP
    /// username is usually the sending address, which is not a secret but is an
    /// identifier nobody needs in a log line.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmtpConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("implicit_tls", &self.implicit_tls)
            .field("username", &"<redacted>")
            .field("password", &"<redacted>")
            .field("from", &self.from)
            .finish()
    }
}

impl PartialEq for SmtpConfig {
    fn eq(&self, other: &Self) -> bool {
        self.host == other.host
            && self.port == other.port
            && self.implicit_tls == other.implicit_tls
            && self.username == other.username
            && self.from == other.from
    }
}
impl Eq for SmtpConfig {}

#[derive(Debug, Clone)]
pub struct SecurityConfig {
    pub encryption_key: Secret<Vec<u8>>,
    pub encryption_key_version: u32,
    pub previous_encryption_key: Option<(u32, Secret<Vec<u8>>)>,
    /// HMAC key for the audit hash chain. Held separately from the database
    /// credentials on purpose: an adversary with only the database cannot forge a
    /// consistent chain (ADR-006).
    pub audit_chain_key: Secret<Vec<u8>>,
    /// Present only until the system is initialised; removed from production
    /// secrets afterwards.
    pub bootstrap_secret: Option<Secret<String>>,
    pub argon2: Argon2Params,
    pub hashing_max_concurrency: usize,
    pub totp_issuer: String,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub environment: Environment,
    pub bind_address: String,
    pub public_base_url: String,
    pub database: DatabaseConfig,
    pub sessions: SessionConfig,
    pub security: SecurityConfig,
    pub limits: LimitsConfig,
    pub rate_limits: RateLimitConfig,
    pub cors_allowed_origins: Vec<String>,
    pub trusted_proxies: net::TrustedProxies,
    pub mail: MailProviderKind,
    /// An explicit operator acknowledgement that running without mail delivery is
    /// intended. Parsed here rather than read inside `validate` so that validation
    /// stays a pure function of the configuration — a validator that consults the
    /// environment cannot be tested without mutating global state.
    pub mail_allow_disabled: bool,
    pub log_json: bool,
    /// Serving the OpenAPI document is opt-in and off by default in production.
    pub expose_openapi: bool,
    pub metrics_enabled: bool,
    pub outbox_poll_interval: Duration,
    pub outbox_batch_size: u32,
}

/// Aggregates every problem rather than failing on the first, so an operator
/// fixes one deployment instead of five.
#[derive(Debug, Default)]
pub struct ConfigErrors(Vec<String>);

impl ConfigErrors {
    fn push(&mut self, msg: impl Into<String>) {
        self.0.push(msg.into());
    }
    fn into_result(self) -> Result<(), String> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "configuration is invalid:\n{}",
                self.0
                    .iter()
                    .map(|e| format!("  - {e}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            ))
        }
    }
}

fn env_var(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.trim().is_empty())
}

fn env_parse<T: std::str::FromStr>(key: &str, default: T, errors: &mut ConfigErrors) -> T {
    match env_var(key) {
        None => default,
        Some(raw) => match raw.trim().parse() {
            Ok(v) => v,
            Err(_) => {
                errors.push(format!("{key}: `{raw}` could not be parsed"));
                default
            }
        },
    }
}

fn env_secs(key: &str, default_secs: u64, errors: &mut ConfigErrors) -> Duration {
    Duration::from_secs(env_parse(key, default_secs, errors))
}

/// Extract the username from a PostgreSQL connection URL.
///
/// `postgres://user:pass@host:5432/db?opt=1` -> `Some("user")`.
/// The password may itself contain `@`, so the *last* `@` in the authority
/// separates userinfo from host.
fn database_username(url: &str) -> Option<&str> {
    let after_scheme = url.split("://").nth(1)?;
    let authority = after_scheme.split(['/', '?']).next()?;
    let (userinfo, _host) = authority.rsplit_once('@')?;
    let user = userinfo.split(':').next()?;
    if user.is_empty() {
        None
    } else {
        Some(user)
    }
}

fn looks_like_a_placeholder(value: &str) -> Option<&'static str> {
    let lowered = value.to_lowercase();
    FORBIDDEN_IN_PRODUCTION
        .iter()
        .copied()
        .find(|needle| lowered.contains(needle))
}

impl Config {
    /// Read configuration from the environment.
    ///
    /// In development and test a `.env` file is loaded first as a convenience. It
    /// is **not** loaded in production: relying on a file on disk that may or may
    /// not be present is exactly how a production instance ends up running with a
    /// developer's key.
    pub fn from_env() -> Result<Self, String> {
        let environment = match env_var("RB_ENV").as_deref() {
            Some("production") | Some("prod") => Environment::Production,
            Some("test") => Environment::Test,
            Some("development") | Some("dev") | None => Environment::Development,
            Some(other) => {
                return Err(format!(
                    "RB_ENV must be one of development|test|production, got `{other}`"
                ))
            }
        };

        if !environment.is_production() {
            let _ = dotenvy::dotenv();
        }

        let mut errors = ConfigErrors::default();

        // --- database ---------------------------------------------------------
        let database_url = match env_var("DATABASE_URL") {
            Some(url) => url,
            None => {
                errors.push("DATABASE_URL is required");
                String::new()
            }
        };

        let cpu_count = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);

        // Pool sizing: the backend is I/O bound per request but every request holds
        // a connection only for the duration of its statements. `cpu*2 + effective
        // spindle count` is the classic starting point; PostgreSQL itself degrades
        // above roughly (cores * 2-4) active connections because of lock and buffer
        // contention, so the default is deliberately modest and measured rather
        // than set to a large round number. See PERFORMANCE_REPORT.md.
        let default_max_conns = (cpu_count * 2).clamp(5, 32) as u32;

        let database = DatabaseConfig {
            url: Secret::new(database_url.clone()),
            max_connections: env_parse("RB_DB_MAX_CONNECTIONS", default_max_conns, &mut errors),
            min_connections: env_parse("RB_DB_MIN_CONNECTIONS", 1, &mut errors),
            acquire_timeout: env_secs("RB_DB_ACQUIRE_TIMEOUT_SECONDS", 5, &mut errors),
            idle_timeout: env_secs("RB_DB_IDLE_TIMEOUT_SECONDS", 300, &mut errors),
            max_lifetime: env_secs("RB_DB_MAX_LIFETIME_SECONDS", 1800, &mut errors),
            statement_timeout: env_secs("RB_DB_STATEMENT_TIMEOUT_SECONDS", 15, &mut errors),
        };

        // --- security ---------------------------------------------------------
        let encryption_key = match env_var("RB_ENCRYPTION_KEY") {
            Some(raw) => match aead::parse_key(&raw) {
                Ok(k) => Some(k),
                Err(e) => {
                    errors.push(format!("RB_ENCRYPTION_KEY: {e}"));
                    None
                }
            },
            None => {
                errors.push(
                    "RB_ENCRYPTION_KEY is required (32 bytes, base64). \
                     Generate with: openssl rand -base64 32",
                );
                None
            }
        };

        let audit_chain_key = match env_var("RB_AUDIT_CHAIN_KEY") {
            Some(raw) => match aead::parse_key(&raw) {
                Ok(k) => Some(k),
                Err(e) => {
                    errors.push(format!("RB_AUDIT_CHAIN_KEY: {e}"));
                    None
                }
            },
            None => {
                errors.push(
                    "RB_AUDIT_CHAIN_KEY is required (32 bytes, base64). \
                     Generate with: openssl rand -base64 32",
                );
                None
            }
        };

        // Two distinct purposes must not share one key. Reusing a key across an
        // AEAD and an HMAC is a classic cross-protocol mistake, and here it would
        // also mean that an attacker who obtained one capability obtained both.
        if let (Some(a), Some(b)) = (&encryption_key, &audit_chain_key) {
            if a.expose() == b.expose() {
                errors.push("RB_ENCRYPTION_KEY and RB_AUDIT_CHAIN_KEY must be different keys");
            }
        }

        let bootstrap_secret = env_var("RB_BOOTSTRAP_SECRET");
        if let Some(s) = &bootstrap_secret {
            if s.len() < 32 {
                errors.push(format!(
                    "RB_BOOTSTRAP_SECRET must be at least 32 characters (got {})",
                    s.len()
                ));
            }
        }

        let argon2 = Argon2Params {
            memory_kib: env_parse("RB_ARGON2_MEMORY_KIB", 19_456, &mut errors),
            iterations: env_parse("RB_ARGON2_ITERATIONS", 2, &mut errors),
            parallelism: env_parse("RB_ARGON2_PARALLELISM", 1, &mut errors),
        };
        if let Err(e) = argon2.validate() {
            errors.push(e);
        }

        let previous_encryption_key = match (
            env_var("RB_ENCRYPTION_KEY_PREVIOUS"),
            env_var("RB_ENCRYPTION_KEY_PREVIOUS_VERSION"),
        ) {
            (Some(raw), Some(ver)) => match (aead::parse_key(&raw), ver.parse::<u32>()) {
                (Ok(k), Ok(v)) => Some((v, k)),
                _ => {
                    errors.push("RB_ENCRYPTION_KEY_PREVIOUS / _VERSION are malformed");
                    None
                }
            },
            (None, None) => None,
            _ => {
                errors.push(
                    "RB_ENCRYPTION_KEY_PREVIOUS and RB_ENCRYPTION_KEY_PREVIOUS_VERSION \
                     must be set together",
                );
                None
            }
        };

        let security = SecurityConfig {
            encryption_key: encryption_key.unwrap_or_else(|| Secret::new(vec![0u8; 32])),
            encryption_key_version: env_parse("RB_ENCRYPTION_KEY_VERSION", 1u32, &mut errors),
            previous_encryption_key,
            audit_chain_key: audit_chain_key.unwrap_or_else(|| Secret::new(vec![0u8; 32])),
            bootstrap_secret: bootstrap_secret.clone().map(Secret::new),
            argon2,
            hashing_max_concurrency: env_parse(
                "RB_AUTH_HASHING_MAX_CONCURRENCY",
                cpu_count.min(8),
                &mut errors,
            ),
            totp_issuer: env_var("RB_TOTP_ISSUER").unwrap_or_else(|| "RoleBlank OS".to_string()),
        };

        // --- sessions ---------------------------------------------------------
        let sessions = SessionConfig {
            access_ttl: env_secs("RB_SESSION_ACCESS_TTL_SECONDS", 900, &mut errors),
            idle_ttl: env_secs("RB_SESSION_IDLE_TTL_SECONDS", 604_800, &mut errors),
            absolute_ttl: env_secs("RB_SESSION_ABSOLUTE_TTL_SECONDS", 2_592_000, &mut errors),
            refresh_ttl: env_secs("RB_SESSION_REFRESH_TTL_SECONDS", 604_800, &mut errors),
            step_up_window: env_secs("RB_STEP_UP_WINDOW_SECONDS", 600, &mut errors),
            max_per_user: env_parse("RB_SESSION_MAX_PER_USER", 20usize, &mut errors),
        };

        // --- limits -----------------------------------------------------------
        let limits = LimitsConfig {
            // 256 KiB. Every endpoint in this API takes a small JSON document; the
            // limit exists so a 200 MB body is rejected at the transport rather
            // than buffered (TH-33).
            max_body_bytes: env_parse("RB_MAX_BODY_BYTES", 262_144usize, &mut errors),
            request_timeout: env_secs("RB_REQUEST_TIMEOUT_SECONDS", 30, &mut errors),
            max_page_size: env_parse("RB_MAX_PAGE_SIZE", 100u32, &mut errors),
            default_page_size: env_parse("RB_DEFAULT_PAGE_SIZE", 25u32, &mut errors),
        };

        // --- CORS -------------------------------------------------------------
        let cors_allowed_origins: Vec<String> = env_var("RB_CORS_ALLOWED_ORIGINS")
            .map(|v| {
                v.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        // --- trusted proxies --------------------------------------------------
        let trusted_proxies = match env_var("RB_TRUSTED_PROXIES") {
            Some(v) => match net::TrustedProxies::parse_list(&v) {
                Ok(t) => t,
                Err(e) => {
                    errors.push(format!("RB_TRUSTED_PROXIES: {e}"));
                    net::TrustedProxies::default()
                }
            },
            // Fail closed: with nothing configured we trust no proxy and use the
            // peer address. In development the loopback/RFC1918 default is applied
            // so a docker-compose setup behaves sensibly.
            None if environment.is_production() => net::TrustedProxies::default(),
            None => net::development_default(),
        };

        // --- mail -------------------------------------------------------------
        let mail = match env_var("RB_MAIL_PROVIDER").as_deref() {
            Some("dev_file") => MailProviderKind::DevFile {
                directory: env_var("RB_MAIL_DIRECTORY")
                    .unwrap_or_else(|| "/tmp/roleblank-mail".into()),
            },
            Some("dev_sink") | None => MailProviderKind::DevSink,
            Some("disabled") => MailProviderKind::Disabled,
            Some("smtp") => {
                let host = env_var("RB_SMTP_HOST").unwrap_or_default();
                let username = env_var("RB_SMTP_USERNAME").unwrap_or_default();
                let password = env_var("RB_SMTP_PASSWORD").unwrap_or_default();
                let from = env_var("RB_SMTP_FROM").unwrap_or_default();
                let implicit_tls = env_parse("RB_SMTP_IMPLICIT_TLS", true, &mut errors);
                let default_port = if implicit_tls { 465 } else { 587 };
                let port = env_parse("RB_SMTP_PORT", default_port, &mut errors);

                // Every one of the four is required. A half-configured transport
                // that starts is worse than one that refuses, because the first
                // invitation is where you find out.
                for (key, value) in [
                    ("RB_SMTP_HOST", &host),
                    ("RB_SMTP_USERNAME", &username),
                    ("RB_SMTP_PASSWORD", &password),
                    ("RB_SMTP_FROM", &from),
                ] {
                    if value.trim().is_empty() {
                        errors.push(format!(
                            "{key} is required when RB_MAIL_PROVIDER=smtp; refusing to \
                             start with a half-configured mail transport"
                        ));
                    }
                }

                // Port 25 is the server-to-server relay port, not the submission
                // port. Authenticated submission there is almost always a mistake,
                // and many networks silently drop it — which presents as
                // "invitations stopped working" with nothing to point at.
                if port == 25 {
                    errors.push(
                        "RB_SMTP_PORT=25 is the relay port, not the submission port. \
                         Use 465 (implicit TLS) or 587 (STARTTLS).",
                    );
                }

                MailProviderKind::Smtp(Box::new(SmtpConfig {
                    host,
                    port,
                    implicit_tls,
                    username,
                    password: Secret::new(password),
                    from,
                }))
            }
            Some(other) => {
                errors.push(format!(
                    "RB_MAIL_PROVIDER `{other}` is not implemented. \
                     Supported: smtp | dev_sink | dev_file | disabled."
                ));
                MailProviderKind::Disabled
            }
        };

        let config = Config {
            environment,
            bind_address: env_var("RB_BIND_ADDRESS").unwrap_or_else(|| "0.0.0.0:8080".into()),
            public_base_url: env_var("RB_PUBLIC_BASE_URL")
                .unwrap_or_else(|| "http://localhost:8090".into()),
            database,
            sessions,
            security,
            limits,
            rate_limits: RateLimitConfig::from_env(&mut errors),
            cors_allowed_origins,
            trusted_proxies,
            mail,
            mail_allow_disabled: env_parse("RB_MAIL_ALLOW_DISABLED", false, &mut errors),
            log_json: env_parse("RB_LOG_JSON", environment.is_production(), &mut errors),
            expose_openapi: env_parse(
                "RB_EXPOSE_OPENAPI",
                !environment.is_production(),
                &mut errors,
            ),
            metrics_enabled: env_parse("RB_METRICS_ENABLED", true, &mut errors),
            outbox_poll_interval: env_secs("RB_OUTBOX_POLL_INTERVAL_SECONDS", 5, &mut errors),
            outbox_batch_size: env_parse("RB_OUTBOX_BATCH_SIZE", 20u32, &mut errors),
        };

        config.validate_common(&mut errors);
        if environment.is_production() {
            config.validate_production(&mut errors, &database_url, bootstrap_secret.as_deref());
        }

        errors.into_result()?;
        Ok(config)
    }

    fn validate_common(&self, errors: &mut ConfigErrors) {
        if self.limits.max_body_bytes < 1024 || self.limits.max_body_bytes > 10 * 1024 * 1024 {
            errors.push("RB_MAX_BODY_BYTES must be between 1 KiB and 10 MiB");
        }
        if self.limits.default_page_size > self.limits.max_page_size {
            errors.push("RB_DEFAULT_PAGE_SIZE cannot exceed RB_MAX_PAGE_SIZE");
        }
        if self.limits.max_page_size == 0 || self.limits.max_page_size > 500 {
            errors.push("RB_MAX_PAGE_SIZE must be between 1 and 500");
        }
        if self.sessions.access_ttl > self.sessions.absolute_ttl {
            errors.push("session access TTL cannot exceed the absolute TTL");
        }
        if self.sessions.refresh_ttl > self.sessions.absolute_ttl {
            errors.push("session refresh TTL cannot exceed the absolute TTL");
        }
        // A step-up window wide enough to be useless is a silent downgrade of every
        // sensitive operation, so the bound is enforced rather than documented.
        let w = self.sessions.step_up_window.as_secs();
        if !(60..=1800).contains(&w) {
            errors.push("RB_STEP_UP_WINDOW_SECONDS must be between 60 and 1800");
        }
        if self.database.min_connections > self.database.max_connections {
            errors.push("RB_DB_MIN_CONNECTIONS cannot exceed RB_DB_MAX_CONNECTIONS");
        }
        if self.database.max_connections == 0 || self.database.max_connections > 200 {
            errors.push("RB_DB_MAX_CONNECTIONS must be between 1 and 200");
        }
        if self.security.hashing_max_concurrency == 0 {
            errors.push("RB_AUTH_HASHING_MAX_CONCURRENCY must be at least 1");
        }
        if self.security.encryption_key_version == 0 {
            errors.push("RB_ENCRYPTION_KEY_VERSION must be at least 1");
        }
    }

    /// Everything that must be true before this process is allowed to serve real
    /// traffic. Each check corresponds to a way a production deployment has
    /// historically gone wrong.
    fn validate_production(
        &self,
        errors: &mut ConfigErrors,
        database_url: &str,
        bootstrap_secret: Option<&str>,
    ) {
        // TH-37: a wildcard origin on an API that accepts bearer credentials.
        if self.cors_allowed_origins.iter().any(|o| o == "*") {
            errors.push(
                "RB_CORS_ALLOWED_ORIGINS contains `*`, which is never valid for an \
                 authenticated API. List the exact origins.",
            );
        }
        for origin in &self.cors_allowed_origins {
            if !origin.starts_with("https://") {
                errors.push(format!(
                    "CORS origin `{origin}` must use https:// in production"
                ));
            }
            if origin.ends_with('/') {
                errors.push(format!(
                    "CORS origin `{origin}` must not have a trailing slash (it will never match)"
                ));
            }
        }

        if !self.public_base_url.starts_with("https://") {
            errors.push("RB_PUBLIC_BASE_URL must use https:// in production");
        }
        if self.public_base_url.contains("localhost") || self.public_base_url.contains("127.0.0.1")
        {
            errors.push("RB_PUBLIC_BASE_URL must not point at localhost in production");
        }

        // TH-41: placeholder secrets.
        if let Some(hit) = looks_like_a_placeholder(database_url) {
            errors.push(format!(
                "DATABASE_URL contains the placeholder text `{hit}` — refusing to start"
            ));
        }
        if self
            .security
            .encryption_key
            .expose()
            .iter()
            .all(|b| *b == 0)
        {
            errors.push("RB_ENCRYPTION_KEY is all zero bytes — refusing to start");
        }
        if self
            .security
            .audit_chain_key
            .expose()
            .iter()
            .all(|b| *b == 0)
        {
            errors.push("RB_AUDIT_CHAIN_KEY is all zero bytes — refusing to start");
        }
        if let Some(s) = bootstrap_secret {
            if let Some(hit) = looks_like_a_placeholder(s) {
                errors.push(format!(
                    "RB_BOOTSTRAP_SECRET contains the placeholder text `{hit}` — refusing to start"
                ));
            }
        }

        // The runtime identity must not be the schema owner or a superuser.
        //
        // The username is extracted properly rather than substring-matched: a
        // naive `url.contains("postgres:")` matches the *scheme* `postgres://` and
        // would reject every valid configuration. (That bug existed here and was
        // caught by `a_correct_production_config_passes`.)
        if let Some(user) = database_username(database_url) {
            const PRIVILEGED: &[&str] = &[
                "postgres",
                "roleblank_migrator",
                "root",
                "admin",
                "superuser",
                "rdsadmin",
            ];
            if PRIVILEGED.contains(&user) {
                errors.push(format!(
                    "DATABASE_URL connects as the privileged role `{user}` — the runtime \
                     identity must be the unprivileged application role (see \
                     docs/backend/08-operations.md)"
                ));
            }
        }

        // A non-TLS database connection in production is credential exposure on the
        // wire. `sslmode=disable` is an explicit downgrade and is refused.
        if database_url.contains("sslmode=disable") {
            errors.push("DATABASE_URL disables TLS (`sslmode=disable`) — refused in production");
        }

        if self.expose_openapi {
            errors.push(
                "RB_EXPOSE_OPENAPI is on in production. The API contract is not a public \
                 document by default; set it explicitly to false or serve it behind the \
                 operator's own access control.",
            );
        }

        if !self.log_json {
            errors.push("RB_LOG_JSON must be true in production so logs are machine-parseable");
        }

        // Mail is not optional in production, because the flows that need it are the
        // flows that let people in: an invitation is the only path to an internal
        // account, and a password reset is the only path back into an existing one.
        match &self.mail {
            MailProviderKind::DevSink | MailProviderKind::DevFile { .. } => {
                errors.push(
                    "RB_MAIL_PROVIDER is a development sink, so invitation and                      password-reset delivery would go nowhere. Use RB_MAIL_PROVIDER=smtp                      in production.",
                );
            }
            MailProviderKind::Disabled => {
                // Refusing here is the change that closes the gap. Previously
                // `disabled` was accepted in production unconditionally, so a
                // deployment could boot looking healthy while every invitation and
                // every password reset failed in the outbox. It never *pretended* to
                // deliver — that part was always right — but a backend that starts
                // cleanly and cannot onboard or recover a single user is not a
                // working production system.
                //
                // An operator who genuinely wants that (an internal instance where
                // accounts are provisioned another way) can still have it, but has to
                // say so out loud.
                if !self.mail_allow_disabled {
                    errors.push(
                        "RB_MAIL_PROVIDER=disabled in production: invitations and password                          resets cannot be delivered, so nobody can be onboarded or                          recovered. Configure RB_MAIL_PROVIDER=smtp, or set                          RB_MAIL_ALLOW_DISABLED=true to accept that deliberately.",
                    );
                }
            }
            MailProviderKind::Smtp(smtp) => {
                // The transport refuses to send in clear text on its own, but a
                // configuration that only looks complete should fail here rather
                // than at the first invitation.
                if smtp.host.trim().is_empty() {
                    errors.push("RB_SMTP_HOST is empty");
                }
                // Checked here as well as in the parser, because the documentation
                // names all four and a reader should not have to know which of the
                // two layers happens to catch which one.
                if smtp.username.trim().is_empty() {
                    errors.push("RB_SMTP_USERNAME is empty");
                }
                if smtp.password.expose().trim().is_empty() {
                    errors.push("RB_SMTP_PASSWORD is empty");
                }
                if smtp.from.trim().is_empty() {
                    errors.push("RB_SMTP_FROM is empty");
                }
            }
        }

        if self.trusted_proxies.is_empty() && self.bind_address.starts_with("0.0.0.0") {
            // Not fatal — a directly exposed instance is a legitimate topology —
            // but it must be a deliberate one.
            tracing::warn!(
                "no trusted proxies configured; X-Forwarded-For will be ignored and rate \
                 limiting will key on the direct peer address"
            );
        }
    }

    pub fn keyring(&self) -> Result<aead::KeyRing, crate::platform::errors::AppError> {
        let mut ring = aead::KeyRing::new(
            self.security.encryption_key_version,
            self.security.encryption_key.clone(),
        )?;
        if let Some((v, k)) = &self.security.previous_encryption_key {
            ring = ring.with_previous(*v, k.clone())?;
        }
        Ok(ring)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_config(environment: Environment) -> Config {
        Config {
            environment,
            bind_address: "0.0.0.0:8080".into(),
            public_base_url: "https://os.example.com".into(),
            database: DatabaseConfig {
                url: Secret::new("postgres://roleblank_app:pw@db/roleblank".into()),
                max_connections: 10,
                min_connections: 1,
                acquire_timeout: Duration::from_secs(5),
                idle_timeout: Duration::from_secs(300),
                max_lifetime: Duration::from_secs(1800),
                statement_timeout: Duration::from_secs(15),
            },
            sessions: SessionConfig {
                access_ttl: Duration::from_secs(900),
                idle_ttl: Duration::from_secs(604_800),
                absolute_ttl: Duration::from_secs(2_592_000),
                refresh_ttl: Duration::from_secs(604_800),
                step_up_window: Duration::from_secs(600),
                max_per_user: 20,
            },
            security: SecurityConfig {
                encryption_key: Secret::new(vec![1u8; 32]),
                encryption_key_version: 1,
                previous_encryption_key: None,
                audit_chain_key: Secret::new(vec![2u8; 32]),
                bootstrap_secret: None,
                argon2: Argon2Params::default(),
                hashing_max_concurrency: 4,
                totp_issuer: "RoleBlank OS".into(),
            },
            limits: LimitsConfig {
                max_body_bytes: 262_144,
                request_timeout: Duration::from_secs(30),
                max_page_size: 100,
                default_page_size: 25,
            },
            rate_limits: RateLimitConfig::default(),
            cors_allowed_origins: vec!["https://app.example.com".into()],
            trusted_proxies: net::TrustedProxies::default(),
            // A *correct* production posture has a working delivery path, so the
            // reference configuration shows one rather than the acknowledged-absent
            // variant. Every value here is a placeholder that would fail validation
            // if it were empty, which is the point.
            mail: MailProviderKind::Smtp(Box::new(SmtpConfig {
                host: "smtp.example.com".into(),
                port: 465,
                implicit_tls: true,
                username: "no-reply@example.com".into(),
                password: Secret::new("smtp-password".into()),
                from: "RoleBlank <no-reply@example.com>".into(),
            })),
            mail_allow_disabled: false,
            log_json: true,
            expose_openapi: false,
            metrics_enabled: true,
            outbox_poll_interval: Duration::from_secs(5),
            outbox_batch_size: 20,
        }
    }

    fn prod_errors(mutate: impl FnOnce(&mut Config)) -> String {
        let mut c = base_config(Environment::Production);
        mutate(&mut c);
        let mut errors = ConfigErrors::default();
        c.validate_common(&mut errors);
        let url = c.database.url.expose().clone();
        let secret = c
            .security
            .bootstrap_secret
            .as_ref()
            .map(|s| s.expose().clone());
        c.validate_production(&mut errors, &url, secret.as_deref());
        errors.into_result().err().unwrap_or_default()
    }

    #[test]
    fn a_correct_production_config_passes() {
        assert_eq!(
            prod_errors(|_| {}),
            "",
            "baseline production config should be valid"
        );
    }

    #[test]
    fn production_refuses_wildcard_cors() {
        let e = prod_errors(|c| c.cors_allowed_origins = vec!["*".into()]);
        assert!(e.contains("never valid for an authenticated API"), "{e}");
    }

    #[test]
    fn production_requires_https_origins_and_base_url() {
        assert!(
            prod_errors(|c| c.cors_allowed_origins = vec!["http://app.example.com".into()])
                .contains("must use https")
        );
        assert!(
            prod_errors(|c| c.public_base_url = "http://os.example.com".into())
                .contains("must use https")
        );
        assert!(
            prod_errors(|c| c.public_base_url = "https://localhost:8090".into())
                .contains("must not point at localhost")
        );
    }

    #[test]
    fn production_refuses_zero_or_placeholder_secrets() {
        assert!(
            prod_errors(|c| c.security.encryption_key = Secret::new(vec![0u8; 32]))
                .contains("all zero bytes")
        );
        assert!(
            prod_errors(|c| c.security.audit_chain_key = Secret::new(vec![0u8; 32]))
                .contains("all zero bytes")
        );
        assert!(prod_errors(|c| {
            c.security.bootstrap_secret =
                Some(Secret::new("changeme-changeme-changeme-1234".into()))
        })
        .contains("placeholder"));
        assert!(prod_errors(|c| {
            c.database.url = Secret::new("postgres://app:changeme@db/roleblank".into())
        })
        .contains("placeholder"));
    }

    #[test]
    fn production_refuses_a_privileged_database_role() {
        let e = prod_errors(|c| {
            c.database.url = Secret::new("postgres://postgres:strongpw@db/roleblank".into())
        });
        assert!(e.contains("privileged role `postgres`"), "{e}");

        let e = prod_errors(|c| {
            c.database.url = Secret::new("postgres://roleblank_migrator:pw@db/roleblank".into())
        });
        assert!(e.contains("privileged role `roleblank_migrator`"), "{e}");
    }

    /// Regression: the earlier substring check matched the `postgres://` scheme and
    /// rejected every valid configuration.
    #[test]
    fn the_url_scheme_is_not_mistaken_for_the_username() {
        assert_eq!(
            database_username("postgres://roleblank_app:pw@db:5432/roleblank"),
            Some("roleblank_app")
        );
        assert_eq!(
            database_username("postgresql://roleblank_app:pw@db/rb?sslmode=require"),
            Some("roleblank_app")
        );
        // A password containing `@` must not confuse the split.
        assert_eq!(
            database_username("postgres://roleblank_app:p@ss@db:5432/rb"),
            Some("roleblank_app")
        );
        // No credentials at all (e.g. peer authentication).
        assert_eq!(database_username("postgres://db:5432/roleblank"), None);
        assert_eq!(database_username("not a url"), None);
        assert_eq!(
            prod_errors(|_| {}),
            "",
            "a valid app-role URL must not be rejected"
        );
    }

    #[test]
    fn production_refuses_a_plaintext_database_connection() {
        assert!(prod_errors(|c| {
            c.database.url = Secret::new("postgres://roleblank_app:pw@db/rb?sslmode=disable".into())
        })
        .contains("disables TLS"));
    }

    #[test]
    fn production_refuses_a_public_openapi_document_and_text_logs() {
        assert!(prod_errors(|c| c.expose_openapi = true).contains("RB_EXPOSE_OPENAPI"));
        assert!(prod_errors(|c| c.log_json = false).contains("machine-parseable"));
    }

    /// Silently sending nothing is worse than failing: a password reset that
    /// appears to succeed but never arrives locks a user out with no signal.
    #[test]
    fn production_refuses_a_development_mail_sink() {
        assert!(prod_errors(|c| c.mail = MailProviderKind::DevSink).contains("development sink"));
        assert!(prod_errors(|c| c.mail = MailProviderKind::DevFile {
            directory: "/tmp".into()
        })
        .contains("development sink"));
        // `disabled` is no longer silently acceptable: a production backend that
        // boots cleanly but can neither onboard nor recover a user is not working.
        assert!(prod_errors(|c| c.mail = MailProviderKind::Disabled)
            .contains("nobody can be onboarded"));
    }

    /// ...but an operator may still choose it deliberately, out loud.
    #[test]
    fn production_accepts_disabled_mail_only_when_explicitly_acknowledged() {
        assert_eq!(
            prod_errors(|c| {
                c.mail = MailProviderKind::Disabled;
                c.mail_allow_disabled = true;
            }),
            ""
        );
    }

    #[test]
    fn production_refuses_a_half_configured_smtp_transport() {
        let errors = prod_errors(|c| {
            c.mail = MailProviderKind::Smtp(Box::new(SmtpConfig {
                host: "".into(),
                port: 465,
                implicit_tls: true,
                username: "u".into(),
                password: Secret::new(String::new()),
                from: "".into(),
            }))
        });
        assert!(errors.contains("RB_SMTP_HOST is empty"), "{errors}");
        assert!(errors.contains("RB_SMTP_PASSWORD is empty"), "{errors}");
        assert!(errors.contains("RB_SMTP_FROM is empty"), "{errors}");
    }

    #[test]
    fn common_validation_catches_incoherent_limits() {
        let mut c = base_config(Environment::Development);
        c.limits.default_page_size = 500;
        c.limits.max_page_size = 100;
        c.sessions.access_ttl = Duration::from_secs(999_999_999);
        c.sessions.step_up_window = Duration::from_secs(86_400);
        c.database.min_connections = 50;
        c.database.max_connections = 10;
        let mut errors = ConfigErrors::default();
        c.validate_common(&mut errors);
        let e = errors.into_result().err().unwrap();
        assert!(e.contains("RB_DEFAULT_PAGE_SIZE cannot exceed"));
        assert!(e.contains("access TTL cannot exceed"));
        assert!(e.contains("RB_STEP_UP_WINDOW_SECONDS"));
        assert!(e.contains("RB_DB_MIN_CONNECTIONS cannot exceed"));
    }

    #[test]
    fn development_tolerates_what_production_refuses() {
        let mut c = base_config(Environment::Development);
        c.public_base_url = "http://localhost:8090".into();
        c.cors_allowed_origins = vec!["http://localhost:3000".into()];
        c.mail = MailProviderKind::DevSink;
        c.expose_openapi = true;
        c.log_json = false;
        let mut errors = ConfigErrors::default();
        c.validate_common(&mut errors);
        assert_eq!(errors.into_result().err().unwrap_or_default(), "");
    }

    #[test]
    fn placeholder_detection_is_substring_and_case_insensitive() {
        assert!(looks_like_a_placeholder("ChangeMe-2024").is_some());
        assert!(looks_like_a_placeholder("prefix_INSECURE_suffix").is_some());
        assert!(looks_like_a_placeholder("aB3x9Qw7ZmK2pL5vR8tYnE4hJ6cD1sG0").is_none());
    }
}
