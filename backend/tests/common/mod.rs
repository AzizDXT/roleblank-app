//! Integration test harness.
//!
//! Every test gets its **own PostgreSQL database**, so tests cannot see each
//! other's rows and can run concurrently. SQLite is deliberately not used as a
//! stand-in: this system depends on PostgreSQL-specific behaviour — partial unique
//! indexes, `FOR UPDATE SKIP LOCKED`, advisory locks, row-level triggers,
//! `RAISE EXCEPTION`, and per-role privileges — none of which SQLite has. Testing
//! against a fake would prove nothing about the invariants that matter.
//!
//! Databases are cloned from a template that has already been migrated, so the
//! per-test cost is a file copy rather than nine migrations.

#![allow(dead_code)] // each test binary uses a different subset of these helpers

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgConnection, PgPool};
use tokio::sync::OnceCell;
use tower::ServiceExt;
use uuid::Uuid;

use roleblank_backend::app::AppState;
use roleblank_backend::platform::config::{
    Config, DatabaseConfig, Environment, LimitsConfig, MailProviderKind, RateLimitConfig,
    SecurityConfig, SessionConfig,
};
use roleblank_backend::platform::crypto::password::{Argon2Params, Hasher};
use roleblank_backend::platform::database;
use roleblank_backend::platform::http::rate_limit::InProcessRateLimiter;
use roleblank_backend::platform::observability::metrics::Metrics;
use roleblank_backend::shared::secret::Secret;

/// Superuser connection used only to create and drop test databases.
fn admin_url() -> String {
    std::env::var("TEST_DATABASE_ADMIN_URL").unwrap_or_else(|_| {
        "postgres://postgres:dev_superuser_pw_local_only@roleblank-postgres:5432/postgres".into()
    })
}

fn base_url_for(database: &str) -> String {
    // Tests connect as the MIGRATOR role, not the runtime role, because a test
    // that needs to seed a fixture must be able to write tables the application
    // itself is deliberately not granted. Tests that verify privilege separation
    // open their own connection as `roleblank_app` — see `runtime_role_pool`.
    format!("postgres://roleblank_migrator:dev_migrator_pw@roleblank-postgres:5432/{database}")
}

fn runtime_url_for(database: &str) -> String {
    format!("postgres://roleblank_app:dev_app_pw@roleblank-postgres:5432/{database}")
}

const TEMPLATE_DB: &str = "roleblank_test_template";

static TEMPLATE: OnceCell<()> = OnceCell::const_new();

/// A one-connection pool.
///
/// Every pool a test opens counts against PostgreSQL's global `max_connections`,
/// and the suite runs one `TestApp` per test thread. A default-sized pool (ten
/// connections) multiplied by twenty-four parallel tests exhausts the server and
/// the failure surfaces as an unrelated `503` in the middle of an attack, which is
/// exactly the kind of noise that makes a security suite untrustworthy.
async fn small_pool(url: &str) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(30))
        .connect(url)
        .await
}

/// Execute a DDL statement that had to be assembled at runtime.
///
/// `CREATE DATABASE` and `DROP DATABASE` cannot take a bound parameter for the
/// database name, so the statement text is built. sqlx 0.9 requires that to be
/// acknowledged explicitly rather than accepted silently, which is the right
/// default — every use of `AssertSqlSafe` in this repository is a place a reviewer
/// must check.
///
/// **The audit for this one:** the only interpolated values are `TEMPLATE_DB` (a
/// crate constant) and a database name of the form `rb_test_<uuid-simple>`, whose
/// alphabet is `[0-9a-f]` by construction. No external input reaches it. This
/// helper is test-only and is never compiled into the application.
async fn exec_ddl(pool: &PgPool, sql: String) -> Result<(), sqlx::Error> {
    sqlx::query(sqlx::AssertSqlSafe(sql))
        .execute(pool)
        .await
        .map(|_| ())
}

/// Same, but on a caller-held connection.
///
/// `small_pool` is `max_connections(1)`. Anything that holds the pool's only
/// connection — an advisory lock, for instance — and then calls [`exec_ddl`] on the
/// same pool deadlocks against itself until the acquire timeout. Every statement
/// issued while a lock is held must therefore go through the connection that holds
/// it, not through the pool.
async fn exec_ddl_on(conn: &mut PgConnection, sql: String) -> Result<(), sqlx::Error> {
    sqlx::query(sqlx::AssertSqlSafe(sql))
        .execute(&mut *conn)
        .await
        .map(|_| ())
}

/// Guards the template database across *processes*, not just across tasks.
///
/// The template is server-global but `TEMPLATE` is a per-binary `OnceCell`, so the
/// cell alone cannot coordinate anything. While each binary unconditionally dropped
/// and recreated the template on startup, two concurrent `cargo test` processes
/// destroyed each other's template mid-clone: the victim failed with
/// `3D000: template database "roleblank_test_template" does not exist`, or worse
/// reported a whole suite as failed without executing a single assertion.
///
/// That is not a product defect, but it is a defect in the machinery that produces
/// the evidence — it can manufacture failures *and* cast doubt on green runs, which
/// makes it dangerous in exactly the place where trustworthy results matter most.
///
/// A PostgreSQL advisory lock is the right primitive because it lives in the server
/// the processes already share. Recreation takes it **exclusively**; cloning takes
/// it **shared**, so any number of clones may proceed together but never while a
/// recreation is in flight.
const TEMPLATE_LOCK_KEY: i64 = 0x524F_4C45_0000_0001_u64 as i64;

/// Is the template present and built from exactly the current migration set?
///
/// Recreating unconditionally was what made the race destructive. Recreating only
/// when the template is missing or stale means the common case — a template another
/// process already built from the same migrations — touches nothing at all.
async fn template_is_current(conn: &mut PgConnection) -> bool {
    let exists: Option<(i32,)> = sqlx::query_as("SELECT 1 FROM pg_database WHERE datname = $1")
        .bind(TEMPLATE_DB)
        .fetch_optional(&mut *conn)
        .await
        .unwrap_or(None);
    if exists.is_none() {
        return false;
    }

    let Ok(pool) = small_pool(&base_url_for(TEMPLATE_DB)).await else {
        return false;
    };
    let applied: Result<(i64, Option<i64>), _> =
        sqlx::query_as("SELECT count(*), max(version) FROM _sqlx_migrations WHERE success")
            .fetch_one(&pool)
            .await;
    pool.close().await;

    let expected_count = database::MIGRATOR.migrations.len() as i64;
    let expected_max = database::MIGRATOR
        .migrations
        .iter()
        .map(|m| m.version)
        .max();
    matches!(applied, Ok((count, max)) if count == expected_count && max == expected_max)
}

/// Build the migrated template database exactly once per test binary, and at most
/// once per migration set across every binary sharing the server.
async fn ensure_template() {
    TEMPLATE
        .get_or_init(|| async {
            let admin = small_pool(&admin_url()).await.expect("connect as superuser");
            // Everything below runs on this one connection — see `exec_ddl_on`.
            let mut conn = admin
                .acquire()
                .await
                .expect("take a connection for the template lock");
            sqlx::query("SELECT pg_advisory_lock($1)")
                .bind(TEMPLATE_LOCK_KEY)
                .execute(&mut *conn)
                .await
                .expect("take the template lock exclusively");

            if !template_is_current(&mut conn).await {
                // Recreate from scratch so a schema change never leaves a stale
                // template. Safe under the exclusive lock: no clone can be running.
                let _ = exec_ddl_on(
                    &mut conn,
                    format!(
                        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{TEMPLATE_DB}'"
                    ),
                )
                .await;
                let _ = exec_ddl_on(&mut conn, format!("DROP DATABASE IF EXISTS {TEMPLATE_DB}")).await;
                exec_ddl_on(&mut conn, format!("CREATE DATABASE {TEMPLATE_DB} OWNER roleblank_migrator"))
                    .await
                    .expect("create the template database");

                let pool = small_pool(&base_url_for(TEMPLATE_DB))
                    .await
                    .expect("connect to the template as migrator");
                database::MIGRATOR.run(&pool).await.expect("migrations must apply from empty");
                pool.close().await;
            }

            let _ = sqlx::query("SELECT pg_advisory_unlock($1)")
                .bind(TEMPLATE_LOCK_KEY)
                .execute(&mut *conn)
                .await;
            drop(conn);
            admin.close().await;
        })
        .await;
}

/// An isolated database plus everything needed to drive the real application.
pub struct TestApp {
    pub state: AppState,
    pub db: PgPool,
    database_name: String,
}

impl TestApp {
    pub async fn spawn() -> Self {
        Self::spawn_with(|_| {}).await
    }

    /// Spawn with a chance to adjust the configuration first.
    ///
    /// Exists so a suite can test a control that is deliberately set out of the way
    /// for every other suite — the general rate limiter, whose production quotas are
    /// far too large to reach in a test and whose harness quotas are far too large
    /// on purpose. Rather than lowering the limit globally (which would make every
    /// other suite assert against the limiter by accident), the suite that tests the
    /// limiter asks for a small one.
    pub async fn spawn_with(adjust: impl FnOnce(&mut Config)) -> Self {
        ensure_template().await;

        // A UUID-derived name: parallel test binaries must not collide.
        let database_name = format!("rb_test_{}", Uuid::now_v7().simple());

        let admin = small_pool(&admin_url())
            .await
            .expect("connect as superuser");
        // Shared: many clones may run at once, but none may overlap a recreation.
        // The lock and the CREATE share one connection — the pool holds only one.
        let mut conn = admin
            .acquire()
            .await
            .expect("take a connection for the template lock");
        sqlx::query("SELECT pg_advisory_lock_shared($1)")
            .bind(TEMPLATE_LOCK_KEY)
            .execute(&mut *conn)
            .await
            .expect("take the template lock for reading");
        let cloned = exec_ddl_on(
            &mut conn,
            format!(
                "CREATE DATABASE {database_name} TEMPLATE {TEMPLATE_DB} OWNER roleblank_migrator"
            ),
        )
        .await;
        let _ = sqlx::query("SELECT pg_advisory_unlock_shared($1)")
            .bind(TEMPLATE_LOCK_KEY)
            .execute(&mut *conn)
            .await;
        drop(conn);
        cloned.expect("clone the template");
        admin.close().await;

        let mut config = test_config(&database_name);
        adjust(&mut config);
        let db = database::connect(&config.database)
            .await
            .expect("connect to the test database");

        let hasher = Hasher::new(config.security.argon2, 4).expect("hasher");
        let keyring = config.keyring().expect("keyring");

        let state = AppState {
            chain_key: Arc::new(config.security.audit_chain_key.clone()),
            config: Arc::new(config),
            db: db.clone(),
            hasher: Arc::new(hasher),
            keyring: Arc::new(keyring),
            limiter: Arc::new(InProcessRateLimiter::default()),
            metrics: Arc::new(Metrics::new()),
        };

        Self {
            state,
            db,
            database_name,
        }
    }

    /// A pool connected as the **runtime** role, for tests that verify what the
    /// application identity is and is not permitted to do at the database level.
    pub async fn runtime_role_pool(&self) -> PgPool {
        small_pool(&runtime_url_for(&self.database_name))
            .await
            .expect("connect as the runtime role")
    }

    /// Send a request through the real router, with the real middleware stack.
    pub async fn request(&self, req: Request<Body>) -> TestResponse {
        let router = roleblank_backend::routes::build(self.state.clone());
        let response = router.oneshot(req).await.expect("router must not fail");
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let body: Option<Value> = serde_json::from_slice(&bytes).ok();
        TestResponse {
            status,
            headers,
            body,
            raw: bytes.to_vec(),
        }
    }

    pub async fn get(&self, path: &str, token: Option<&str>) -> TestResponse {
        self.request(build(Method::GET, path, token, None)).await
    }

    pub async fn post(&self, path: &str, token: Option<&str>, body: Value) -> TestResponse {
        self.request(build(Method::POST, path, token, Some(body)))
            .await
    }

    pub async fn patch(&self, path: &str, token: Option<&str>, body: Value) -> TestResponse {
        self.request(build(Method::PATCH, path, token, Some(body)))
            .await
    }

    pub async fn put(&self, path: &str, token: Option<&str>, body: Value) -> TestResponse {
        self.request(build(Method::PUT, path, token, Some(body)))
            .await
    }

    pub async fn delete(&self, path: &str, token: Option<&str>) -> TestResponse {
        self.request(build(Method::DELETE, path, token, None)).await
    }

    /// Simulate a process restart: drop and rebuild every in-memory component
    /// while keeping the same database. Used by the golden scenario to prove that
    /// authoritative state survives a restart.
    pub async fn restart(&mut self) {
        self.db.close().await;
        let config = test_config(&self.database_name);
        let db = database::connect(&config.database)
            .await
            .expect("reconnect");
        let hasher = Hasher::new(config.security.argon2, 4).expect("hasher");
        let keyring = config.keyring().expect("keyring");
        self.state = AppState {
            chain_key: Arc::new(config.security.audit_chain_key.clone()),
            config: Arc::new(config),
            db: db.clone(),
            hasher: Arc::new(hasher),
            keyring: Arc::new(keyring),
            // A fresh limiter and fresh metrics — exactly what a restart produces.
            limiter: Arc::new(InProcessRateLimiter::default()),
            metrics: Arc::new(Metrics::new()),
        };
        self.db = db;
    }

    pub fn database_name(&self) -> &str {
        &self.database_name
    }
}

impl Drop for TestApp {
    fn drop(&mut self) {
        // Dropping the database is best-effort: a failure here must not mask a test
        // failure. Leftovers are harmless in a disposable development container and
        // are cleaned by `rb.ps1 db-reset`.
        let name = self.database_name.clone();
        let url = admin_url();
        std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(_) => return,
            };
            rt.block_on(async {
                if let Ok(admin) = small_pool(&url).await {
                    let _ = exec_ddl(
                        &admin,
                        format!(
                            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{name}'"
                        ),
                    )
                    .await;
                    let _ = exec_ddl(&admin, format!("DROP DATABASE IF EXISTS {name}")).await;
                    admin.close().await;
                }
            });
        });
    }
}

fn build(method: Method, path: &str, token: Option<&str>, body: Option<Value>) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(t) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    match body {
        Some(value) => builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::to_vec(&value).expect("serialise body"),
            ))
            .expect("request"),
        None => builder.body(Body::empty()).expect("request"),
    }
}

pub struct TestResponse {
    pub status: StatusCode,
    pub headers: axum::http::HeaderMap,
    pub body: Option<Value>,
    pub raw: Vec<u8>,
}

impl TestResponse {
    /// The stable machine-readable error code. Tests assert on this, never on prose.
    pub fn error_code(&self) -> Option<&str> {
        self.body.as_ref()?.get("code")?.as_str()
    }

    pub fn json(&self) -> &Value {
        self.body.as_ref().unwrap_or_else(|| {
            panic!(
                "expected a JSON body, got status {} and {} bytes: {}",
                self.status,
                self.raw.len(),
                String::from_utf8_lossy(&self.raw)
            )
        })
    }

    pub fn str_at(&self, pointer: &str) -> &str {
        self.json()
            .pointer(pointer)
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("no string at `{pointer}` in {}", self.json()))
    }

    pub fn id_at(&self, pointer: &str) -> Uuid {
        Uuid::parse_str(self.str_at(pointer)).expect("a UUID")
    }

    #[track_caller]
    pub fn assert_status(&self, expected: StatusCode) -> &Self {
        assert_eq!(
            self.status,
            expected,
            "expected {expected}, got {} with body {}",
            self.status,
            String::from_utf8_lossy(&self.raw)
        );
        self
    }

    #[track_caller]
    pub fn assert_error(&self, status: StatusCode, code: &str) -> &Self {
        self.assert_status(status);
        assert_eq!(
            self.error_code(),
            Some(code),
            "expected error code `{code}`, got body {}",
            String::from_utf8_lossy(&self.raw)
        );
        // Every error must be problem+json, not plain JSON — machine clients rely
        // on the media type to know they can branch on `code`.
        assert_eq!(
            self.headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/problem+json"),
            "error responses must use application/problem+json"
        );
        self
    }

    /// Assert that no part of the response leaks something it must never contain.
    #[track_caller]
    pub fn assert_no_secrets(&self) -> &Self {
        let text = String::from_utf8_lossy(&self.raw).to_lowercase();
        for forbidden in [
            "$argon2",
            "password_hash",
            "token_hash",
            "secret_ciphertext",
            "secret_nonce",
            "chain_key",
            "entry_hash",
            "prev_hash",
            "dev_app_pw",
            "dev_migrator_pw",
            "postgres://",
            "/work/src",
            "panicked",
        ] {
            assert!(
                !text.contains(forbidden),
                "response leaked `{forbidden}`: {}",
                String::from_utf8_lossy(&self.raw)
            );
        }
        self
    }
}

/// A deterministic configuration for tests.
///
/// Argon2 is left at the real production parameters: lowering it in tests would
/// mean the timing-equalisation and bounded-concurrency behaviour is never
/// exercised against the cost that actually ships.
pub fn test_config(database: &str) -> Config {
    Config {
        environment: Environment::Test,
        bind_address: "127.0.0.1:0".into(),
        public_base_url: "http://localhost:8090".into(),
        database: DatabaseConfig {
            url: Secret::new(base_url_for(database)),
            // Four is the smallest size that still lets one request hold a
            // transaction while a second, concurrent request contends for the same
            // row — which is what the race and refresh-reuse tests exercise. Eight
            // multiplied by the test-thread count exhausted PostgreSQL's
            // `max_connections` and turned unrelated assertions into `503`s.
            max_connections: 4,
            min_connections: 1,
            acquire_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(60),
            max_lifetime: Duration::from_secs(300),
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
            encryption_key: Secret::new(vec![0x11; 32]),
            encryption_key_version: 1,
            previous_encryption_key: None,
            audit_chain_key: Secret::new(vec![0x22; 32]),
            bootstrap_secret: Some(Secret::new(TEST_BOOTSTRAP_SECRET.to_string())),
            argon2: Argon2Params::default(),
            hashing_max_concurrency: 4,
            totp_issuer: "RoleBlank OS Test".into(),
        },
        limits: LimitsConfig {
            max_body_bytes: 262_144,
            request_timeout: Duration::from_secs(30),
            max_page_size: 100,
            default_page_size: 25,
        },
        // The *general* budgets are raised far above production for the harness, and
        // only those.
        //
        // Several suites legitimately send hundreds of requests as one principal in
        // well under a minute — 630 mass-assignment probes, ~1 500 injection probes —
        // because that is what proving an input boundary takes. Under the production
        // quota those suites would start returning `429` and would then be asserting
        // against the limiter instead of against the thing they exist to test, which
        // is how a suite quietly stops testing anything.
        //
        // This is not a relaxed security posture: the operation-specific budgets
        // (login, MFA, reset, registration, invitation acceptance, bootstrap) keep
        // their real production values above, because several tests assert on them.
        // The general limiter's own behaviour is proven by `rate_limit_suite`, which
        // builds an app with deliberately tiny quotas instead of relying on these.
        rate_limits: RateLimitConfig {
            general_per_principal_per_minute: 100_000,
            general_root_per_minute: 100_000,
            general_per_ip_per_minute: 100_000,
            ..RateLimitConfig::default()
        },
        cors_allowed_origins: vec![],
        trusted_proxies: Default::default(),
        mail: MailProviderKind::DevSink,
        mail_allow_disabled: true,
        log_json: false,
        expose_openapi: true,
        metrics_enabled: true,
        outbox_poll_interval: Duration::from_millis(200),
        outbox_batch_size: 10,
    }
}

/// The bootstrap secret used by tests. Obviously fake, and only ever valid against
/// a throwaway database.
pub const TEST_BOOTSTRAP_SECRET: &str = "test-only-bootstrap-secret-0123456789abcdef";

/// A password that satisfies the real policy, for fixtures.
pub const TEST_PASSWORD: &str = "correct horse battery staple 42";
