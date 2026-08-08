//! Measurement harness for the numbers that appear in `PERFORMANCE_REPORT.md`.
//!
//! These are `#[ignore]`d so they never slow an ordinary `cargo test` run. Execute
//! deliberately, in release mode — a debug-mode Argon2 measurement is meaningless
//! and would lead to choosing far too weak a cost factor:
//!
//! ```text
//! cargo test --release --test benchmarks -- --ignored --nocapture
//! ```
//!
//! Nothing here asserts a threshold. A benchmark that fails CI on a slow runner
//! teaches people to disable benchmarks; the job of this file is to produce
//! numbers a human then reasons about.

mod common;

use std::time::{Duration, Instant};

use roleblank_backend::platform::crypto::{aead, password, tokens, totp};
use roleblank_backend::shared::secret::Secret;

/// Report percentiles rather than a mean. A mean hides the tail, and the tail is
/// what a user actually experiences.
fn report(label: &str, mut samples: Vec<Duration>) {
    samples.sort_unstable();
    let n = samples.len();
    let at = |p: f64| samples[((n as f64 * p) as usize).min(n - 1)];
    let total: Duration = samples.iter().sum();
    println!(
        "{label:<44} n={n:<5} p50={:>9.3?}  p95={:>9.3?}  p99={:>9.3?}  max={:>9.3?}  mean={:>9.3?}",
        at(0.50),
        at(0.95),
        at(0.99),
        samples[n - 1],
        total / n as u32
    );
}

fn environment() {
    println!("\n=== environment ===");
    println!(
        "cores available to this process: {}",
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(0)
    );
    println!(
        "build profile: {}",
        if cfg!(debug_assertions) {
            "debug (NUMBERS ARE MEANINGLESS)"
        } else {
            "release"
        }
    );
    println!("target: {}", std::env::consts::ARCH);
    println!();
}

/// The single most consequential performance decision in the system: Argon2id cost.
///
/// Too low and an offline attacker with the database grinds passwords cheaply. Too
/// high and a login flood turns our own KDF into an amplification weapon (TH-34).
/// The bounded-concurrency semaphore is the second half of that trade-off, and the
/// concurrent measurement below is what shows whether the bound is set sensibly.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "measurement, not a test — run with --ignored --nocapture"]
async fn argon2_cost() {
    environment();
    println!("=== Argon2id (m=19456 KiB, t=2, p=1) ===");

    let hasher = password::Hasher::new(password::Argon2Params::default(), 8).expect("hasher");
    let pw = Secret::new("correct horse battery staple 42".to_string());

    // Warm up: the first call pays allocator and page-fault costs that are not
    // representative of steady state.
    for _ in 0..3 {
        let _ = hasher.hash(&pw).await.expect("hash");
    }

    let mut hashing = Vec::new();
    let mut phc = String::new();
    for _ in 0..30 {
        let start = Instant::now();
        phc = hasher.hash(&pw).await.expect("hash");
        hashing.push(start.elapsed());
    }
    report("hash (sequential)", hashing);

    let mut verifying = Vec::new();
    for _ in 0..30 {
        let start = Instant::now();
        assert!(hasher.verify(&pw, &phc).await.expect("verify"));
        verifying.push(start.elapsed());
    }
    report("verify (sequential)", verifying);

    // Under concurrency the semaphore becomes visible: beyond the permit count,
    // requests queue. That queueing is the intended behaviour — it bounds memory
    // instead of letting a login flood exhaust it.
    for concurrency in [1usize, 4, 8, 16, 32] {
        let start = Instant::now();
        let mut handles = Vec::new();
        for _ in 0..concurrency {
            let h = &hasher;
            let pw = Secret::new("correct horse battery staple 42".to_string());
            // Cloned per task: each future needs its own owned copy, and sharing a
            // borrow across them would tie every task to one lifetime.
            let phc = phc.clone();
            handles.push(async move { h.verify(&pw, &phc).await });
        }
        let results = futures_lite_join(handles).await;
        let elapsed = start.elapsed();
        assert!(results.iter().all(|r| matches!(r, Ok(true))));
        println!(
            "verify x{concurrency:<3} concurrent            total={elapsed:>9.3?}  per-op={:>9.3?}  throughput={:>7.1}/s",
            elapsed / concurrency as u32,
            concurrency as f64 / elapsed.as_secs_f64()
        );
    }

    println!(
        "\nworst-case resident memory for hashing = permits x m_cost = 8 x 19 MiB ~= 152 MiB\n\
         Size the container accordingly; see docs/backend/08-operations.md §10."
    );
}

/// Everything on the authenticated request path that is not a database round trip.
#[test]
#[ignore = "measurement, not a test — run with --ignored --nocapture"]
fn token_and_crypto_primitives() {
    environment();
    println!("=== per-request primitives (no I/O) ===");

    let mut gen = Vec::new();
    for _ in 0..10_000 {
        let start = Instant::now();
        let _ = tokens::generate(tokens::ACCESS_TOKEN_PREFIX).expect("token");
        gen.push(start.elapsed());
    }
    report("token generation (32 CSPRNG bytes)", gen);

    let token = tokens::generate(tokens::ACCESS_TOKEN_PREFIX).expect("token");
    let plaintext = token.plaintext.expose().clone();

    let mut hashing = Vec::new();
    for _ in 0..100_000 {
        let start = Instant::now();
        let _ = tokens::hash_token(&plaintext);
        hashing.push(start.elapsed());
    }
    report("token hashing (SHA-256)", hashing);

    println!(
        "\nSHA-256 rather than a KDF is correct here: the input is already 256 bits of\n\
         uniform randomness, so a slow hash would add latency to the hottest query in\n\
         the system and buy nothing."
    );

    let ring = aead::KeyRing::new(1, Secret::new(vec![7u8; 32])).expect("keyring");
    let mut sealing = Vec::new();
    for _ in 0..10_000 {
        let start = Instant::now();
        let _ = ring
            .seal(b"JBSWY3DPEHPK3PXP1234", b"user-id")
            .expect("seal");
        sealing.push(start.elapsed());
    }
    report("AEAD seal (XChaCha20-Poly1305)", sealing);

    let sealed = ring
        .seal(b"JBSWY3DPEHPK3PXP1234", b"user-id")
        .expect("seal");
    let mut opening = Vec::new();
    for _ in 0..10_000 {
        let start = Instant::now();
        let _ = ring.open(&sealed, b"user-id").expect("open");
        opening.push(start.elapsed());
    }
    report("AEAD open", opening);

    let secret = totp::generate_secret().expect("secret");
    let now = 1_700_000_000u64;
    let code = totp::code_for_step(&secret, totp::step_at(now));
    let mut verifying = Vec::new();
    for _ in 0..10_000 {
        let start = Instant::now();
        let _ = totp::verify(&secret, &code, now, None);
        verifying.push(start.elapsed());
    }
    report("TOTP verify (3-step window)", verifying);
}

/// The authorisation evaluator runs on every authorised request. It is pure, so
/// this measures exactly the policy cost with no database noise.
#[test]
#[ignore = "measurement, not a test — run with --ignored --nocapture"]
fn authorization_evaluation() {
    use roleblank_backend::modules::authorization::domain::{
        ActorContext, Grant, PrincipalType, ResourceType, Scope, ScopeType, Target, TargetContext,
    };
    use roleblank_backend::modules::authorization::{catalog, evaluator};
    use uuid::Uuid;

    environment();
    println!("=== authorisation evaluator (pure, no I/O) ===");

    // A realistic administrator: every catalogued permission at global scope, plus
    // a handful of overrides.
    let mut actor = ActorContext::empty(Uuid::now_v7(), PrincipalType::Internal);
    for def in catalog::PERMISSIONS {
        actor.allows.push(Grant {
            permission_code: def.code.into(),
            scope: Scope::global(),
        });
    }
    for _ in 0..5 {
        actor.denies.push(Grant {
            permission_code: "tasks.delete".into(),
            scope: Scope::resource(ResourceType::Task, Uuid::now_v7()),
        });
    }
    actor.department_ids = (0..3).map(|_| Uuid::now_v7()).collect();

    let target = Target::Resource(
        TargetContext::new(ResourceType::Project, Uuid::now_v7())
            .with_department(Some(actor.department_ids[0]))
            .with_membership(true),
    );

    let mut samples = Vec::new();
    for _ in 0..100_000 {
        let start = Instant::now();
        let _ = evaluator::evaluate(&actor, "projects.read", &target);
        samples.push(start.elapsed());
    }
    report("evaluate (44 grants, 5 denials)", samples);

    let mut samples = Vec::new();
    for _ in 0..10_000 {
        let start = Instant::now();
        let _ = evaluator::capability_list(&actor);
        samples.push(start.elapsed());
    }
    report("capability_list (whole catalogue)", samples);

    // A narrow scope walks further before deciding — the pessimistic case.
    let mut narrow = ActorContext::empty(Uuid::now_v7(), PrincipalType::Internal);
    narrow.allows.push(Grant {
        permission_code: "projects.read".into(),
        scope: Scope::simple(ScopeType::Assigned),
    });
    let mut samples = Vec::new();
    for _ in 0..100_000 {
        let start = Instant::now();
        let _ = evaluator::evaluate(&narrow, "projects.read", &Target::Collection);
        samples.push(start.elapsed());
    }
    report("evaluate (deny: out of scope)", samples);

    println!(
        "\nThis is the cost that a permission cache would remove. See\n\
         docs/backend/04-authorization.md §11 — correctness before speed, and the\n\
         numbers above are why no cache exists yet."
    );
}

/// The audit hash chain is on the write path of every mutation.
#[test]
#[ignore = "measurement, not a test — run with --ignored --nocapture"]
fn audit_chain_hashing() {
    use roleblank_backend::modules::audit::chain;
    use time::OffsetDateTime;
    use uuid::Uuid;

    environment();
    println!("=== audit chain (pure, no I/O) ===");

    let key = Secret::new(vec![0x42u8; 32]);
    let entry = chain::ChainedEntry {
        chain_version: chain::CURRENT_CHAIN_VERSION,
        seq: 1,
        id: Uuid::now_v7(),
        occurred_at: OffsetDateTime::now_utc(),
        actor_user_id: Some(Uuid::now_v7()),
        actor_principal_type: Some("INTERNAL".into()),
        actor_session_id: Some(Uuid::now_v7()),
        action_code: "PROJECT.UPDATED".into(),
        target_type: Some("PROJECT".into()),
        target_id: Some(Uuid::now_v7()),
        outcome: "SUCCESS".into(),
        request_id: Some("0192f5c1-7c3a-7e1b-9f2d-3a4b5c6d7e8f".into()),
        source_ip_hint: Some("198.51.100.7".into()),
        metadata: serde_json::json!({"changed_fields": ["name", "status"], "version": 4}),
    };

    let mut samples = Vec::new();
    for _ in 0..100_000 {
        let start = Instant::now();
        let _ = chain::entry_hash(&key, &entry, Some(&[0u8; 32]));
        samples.push(start.elapsed());
    }
    report("entry_hash (HMAC-SHA256 + canonical)", samples);

    println!(
        "\nThe chain's real cost is not this hash — it is that appends serialise on\n\
         `SELECT ... FROM audit_chain_head FOR UPDATE`. That is a deliberate\n\
         correctness-over-throughput choice (ADR-006); measure it end to end with the\n\
         load-test script, not here."
    );
}

/// Minimal join helper so the benchmark does not pull in `futures`.
async fn futures_lite_join<F, T>(futures: Vec<F>) -> Vec<T>
where
    F: std::future::Future<Output = T>,
{
    let mut out = Vec::with_capacity(futures.len());
    // Sequential await would defeat the point, so the futures are polled together
    // via a simple unordered driver built from tokio's `join_all` equivalent.
    let mut pinned: Vec<std::pin::Pin<Box<F>>> = futures.into_iter().map(Box::pin).collect();
    loop {
        let mut progressed = false;
        let mut i = 0;
        while i < pinned.len() {
            let fut = &mut pinned[i];
            match futures_poll_once(fut.as_mut()).await {
                Some(value) => {
                    out.push(value);
                    pinned.remove(i);
                    progressed = true;
                }
                None => i += 1,
            }
        }
        if pinned.is_empty() {
            break;
        }
        if !progressed {
            tokio::task::yield_now().await;
        }
    }
    out
}

async fn futures_poll_once<F: std::future::Future>(
    mut fut: std::pin::Pin<&mut F>,
) -> Option<F::Output> {
    std::future::poll_fn(move |cx| {
        std::task::Poll::Ready(match fut.as_mut().poll(cx) {
            std::task::Poll::Ready(v) => Some(v),
            std::task::Poll::Pending => None,
        })
    })
    .await
}
