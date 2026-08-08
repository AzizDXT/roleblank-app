//! Layered rate limiting.
//!
//! Behind a trait from day one because the second implementation is already
//! specified: this one is per-process, which is correct for a single instance and
//! **wrong** the moment a second replica exists. That limitation is recorded as
//! RR-3 in the threat model and as a release gate, not discovered in production.
//!
//! Keys are layered rather than singular — per IP, per account, per session, per
//! operation — because each defeats a different attack. Per-IP alone is defeated
//! by a botnet; per-account alone lets one host grind every account at once.

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// The outcome of asking for permission to proceed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitDecision {
    Allowed { remaining: u32 },
    Limited { retry_after_seconds: u64 },
}

impl RateLimitDecision {
    pub fn is_allowed(self) -> bool {
        matches!(self, RateLimitDecision::Allowed { .. })
    }
}

#[async_trait]
pub trait RateLimiter: Send + Sync {
    /// Consume one unit against `key`, allowing `quota` per `window`.
    async fn check(&self, key: &str, quota: u32, window: Duration) -> RateLimitDecision;

    /// Forget a key. Called after a *successful* authentication so that a user who
    /// mistyped their password four times is not still penalised afterwards.
    async fn reset(&self, key: &str);
}

/// A token bucket per key.
///
/// A bucket rather than a fixed window: a fixed window lets an attacker send the
/// full quota at 59.9 s and again at 60.1 s — double the intended rate across the
/// boundary. A bucket refills continuously and has no boundary to exploit.
#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

pub struct InProcessRateLimiter {
    buckets: Mutex<HashMap<String, Bucket>>,
    /// Bound on distinct tracked keys. Without it, an attacker rotating source IPs
    /// turns the limiter itself into an unbounded memory leak — the limiter
    /// becoming the denial of service is a real and repeated production failure.
    max_keys: usize,
}

impl Default for InProcessRateLimiter {
    fn default() -> Self {
        Self::new(100_000)
    }
}

impl InProcessRateLimiter {
    pub fn new(max_keys: usize) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            max_keys,
        }
    }

    /// Enforce the key-table bound.
    ///
    /// This is a security control in its own right, not housekeeping. Without a
    /// hard bound, an attacker rotating source addresses makes the limiter itself
    /// the memory-exhaustion vector it exists to prevent.
    ///
    /// Eviction is staged, cheapest and least harmful first:
    ///
    ///   1. **Idle buckets.** Untouched for an hour — almost certainly gone.
    ///   2. **Fully refilled buckets.** A bucket at full quota is *behaviourally
    ///      identical* to an absent one: recreating it yields the same decision.
    ///      Evicting these costs nothing at all.
    ///   3. **Most-refilled first, in bulk.** Only if the table is still at
    ///      capacity.
    ///
    ///      Deliberately *not* least-recently-used. LRU is exploitable here: an
    ///      attacker who has exhausted their allowance against an account can touch
    ///      it, then flood `max_keys` fresh keys — every one of which is newer — so
    ///      that the account's drained bucket becomes the oldest and is evicted,
    ///      resetting the penalty. Evicting by *remaining tokens* inverts that: a
    ///      bucket at zero is the most valuable record in the table and is
    ///      discarded last, while a nearly-full bucket is nearly free to recreate.
    ///      Ties break on the oldest, which is where LRU is actually appropriate.
    ///
    ///      A tenth of the table goes at once rather than one key per call —
    ///      otherwise a saturated table would pay a full sort on every request.
    ///
    /// Returns `true` when there is room to track another key. On `false` the
    /// caller allows the request untracked: a limiter that has run out of room must
    /// degrade, never become a global outage.
    fn evict_if_needed(
        buckets: &mut HashMap<String, Bucket>,
        max_keys: usize,
        quota: u32,
        now: Instant,
    ) -> bool {
        if buckets.len() < max_keys {
            return true;
        }

        // Stage 1 — idle.
        buckets.retain(|_, b| now.duration_since(b.last_refill) < Duration::from_secs(3600));
        if buckets.len() < max_keys {
            return true;
        }

        // Stage 2 — indistinguishable from absent.
        let full = f64::from(quota);
        buckets.retain(|_, b| b.tokens < full - f64::EPSILON);
        if buckets.len() < max_keys {
            return true;
        }

        // Stage 3 — bulk-evict the most-refilled tenth, oldest first on a tie.
        let target = max_keys.saturating_sub(max_keys / 10).max(1);
        let mut ranked: Vec<(String, f64, Instant)> = buckets
            .iter()
            .map(|(k, b)| (k.clone(), b.tokens, b.last_refill))
            .collect();
        ranked.sort_unstable_by(|a, b| {
            // Descending by remaining tokens: the emptiest buckets — the accounts
            // actually being limited — sort last and survive.
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.2.cmp(&b.2))
        });
        for (key, _, _) in ranked
            .into_iter()
            .take(buckets.len().saturating_sub(target))
        {
            buckets.remove(&key);
        }

        // Loud, because reaching stage 3 means either the bound is too small for
        // real traffic or an address-rotation attack is under way. Both need a human.
        tracing::warn!(
            tracked_keys = buckets.len(),
            max_keys,
            "rate limiter key table reached capacity; evicting least-recently-used keys"
        );

        buckets.len() < max_keys
    }
}

#[async_trait]
impl RateLimiter for InProcessRateLimiter {
    async fn check(&self, key: &str, quota: u32, window: Duration) -> RateLimitDecision {
        if quota == 0 {
            return RateLimitDecision::Limited {
                retry_after_seconds: window.as_secs().max(1),
            };
        }
        let now = Instant::now();
        let refill_per_second = f64::from(quota) / window.as_secs_f64().max(0.001);

        let mut buckets = match self.buckets.lock() {
            Ok(g) => g,
            // A poisoned mutex means another thread panicked while holding it.
            // Failing open here is deliberate: a limiter that hard-fails every
            // request after one panic is a worse outcome than a lifted limit, and
            // the panic itself is already an alarm.
            Err(poisoned) => {
                tracing::error!("rate limiter mutex was poisoned; recovering");
                poisoned.into_inner()
            }
        };

        // If the table is saturated and this key is not already tracked, allow the
        // request without tracking it. Refusing instead would let an attacker turn
        // a full key table into a denial of service against every legitimate user.
        if !buckets.contains_key(key)
            && !Self::evict_if_needed(&mut buckets, self.max_keys, quota, now)
        {
            return RateLimitDecision::Allowed { remaining: 0 };
        }

        let bucket = buckets.entry(key.to_string()).or_insert(Bucket {
            tokens: f64::from(quota),
            last_refill: now,
        });

        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * refill_per_second).min(f64::from(quota));
        bucket.last_refill = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            RateLimitDecision::Allowed {
                remaining: bucket.tokens as u32,
            }
        } else {
            // Time until one whole token is available again, rounded up so a
            // client that obeys `Retry-After` is not immediately limited again.
            let deficit = 1.0 - bucket.tokens;
            let seconds = (deficit / refill_per_second).ceil() as u64;
            RateLimitDecision::Limited {
                retry_after_seconds: seconds.max(1),
            }
        }
    }

    async fn reset(&self, key: &str) {
        if let Ok(mut buckets) = self.buckets.lock() {
            buckets.remove(key);
        }
    }
}

/// Key builders.
///
/// Centralised so two call sites cannot accidentally share a namespace — if
/// `login` and `refresh` used the same key, exhausting one would lock the other.
pub mod keys {
    use std::net::IpAddr;

    pub fn login_ip(ip: IpAddr) -> String {
        format!("login:ip:{ip}")
    }
    /// Keyed on the *normalised* email so case variation cannot multiply the quota.
    pub fn login_account(email_normalized: &str) -> String {
        format!("login:acct:{email_normalized}")
    }
    pub fn mfa_session(session_id: uuid::Uuid) -> String {
        format!("mfa:sess:{session_id}")
    }
    pub fn mfa_account(user_id: uuid::Uuid) -> String {
        format!("mfa:user:{user_id}")
    }
    pub fn refresh_ip(ip: IpAddr) -> String {
        format!("refresh:ip:{ip}")
    }
    pub fn password_reset_ip(ip: IpAddr) -> String {
        format!("pwreset:ip:{ip}")
    }
    pub fn password_reset_account(email_normalized: &str) -> String {
        format!("pwreset:acct:{email_normalized}")
    }
    pub fn registration_ip(ip: IpAddr) -> String {
        format!("register:ip:{ip}")
    }
    /// Accepting an invitation is deliberately **not** keyed on
    /// `registration_ip`, even though both create an account.
    ///
    /// Sharing one budget coupled two flows with very different risk. Anonymous
    /// self-registration is unsolicited and must be tightly bounded; accepting an
    /// invitation requires a high-entropy token that an authorised internal
    /// principal issued to a specific address. Sharing the quota meant an attacker
    /// hammering `/api/v1/registration` from an address could exhaust it and block
    /// invitation acceptance for every legitimate user behind the same address —
    /// a corporate NAT, which is the normal case. It also capped onboarding at
    /// three people per hour per office.
    ///
    /// Found by the clean-room acceptance walk, which could not onboard its fourth
    /// account.
    pub fn invitation_accept_ip(ip: IpAddr) -> String {
        format!("invite-accept:ip:{ip}")
    }
    pub fn bootstrap_ip(ip: IpAddr) -> String {
        format!("bootstrap:ip:{ip}")
    }
    /// The general authenticated budget.
    ///
    /// Keyed on the **user id**, not the session and not the address. The session
    /// is wrong because an attacker holding stolen credentials can mint sessions
    /// freely and would multiply their budget by doing so; the address is wrong
    /// because an office behind one NAT is many innocent people who would share a
    /// budget with each other and with anyone who compromised one of them.
    pub fn general_principal(user_id: uuid::Uuid) -> String {
        format!("general:user:{user_id}")
    }
    /// The coarse pre-authentication ceiling.
    ///
    /// Address-keyed by necessity: before a token is resolved there is no principal
    /// to key on, and resolving it costs a database query whether or not the token
    /// is genuine. Generous, because at this point a corporate NAT and an attacker
    /// look identical.
    pub fn general_ip(ip: IpAddr) -> String {
        format!("general:ip:{ip}")
    }
}

/// Consume one unit of a bucket, or turn the refusal into the `429` contract.
///
/// Lives here rather than in a module service because both the pre-authentication
/// layer and the per-principal check in the extractors need it, and a second copy
/// is a second place for the response contract to drift.
pub async fn enforce(
    limiter: &dyn RateLimiter,
    key: &str,
    quota: u32,
    window: Duration,
) -> Result<(), crate::platform::errors::AppError> {
    match limiter.check(key, quota, window).await {
        RateLimitDecision::Allowed { .. } => Ok(()),
        RateLimitDecision::Limited {
            retry_after_seconds,
        } => Err(crate::platform::errors::AppError::TooManyRequests {
            retry_after_seconds,
        }),
    }
}

/// The window every "per minute" quota is measured over.
pub const MINUTE: Duration = Duration::from_secs(60);

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn limiter() -> InProcessRateLimiter {
        InProcessRateLimiter::new(1000)
    }

    #[tokio::test]
    async fn allows_up_to_the_quota_then_limits() {
        let l = limiter();
        let window = Duration::from_secs(60);
        for i in 0..5 {
            assert!(
                l.check("k", 5, window).await.is_allowed(),
                "request {i} should pass"
            );
        }
        let decision = l.check("k", 5, window).await;
        assert!(!decision.is_allowed());
        let RateLimitDecision::Limited {
            retry_after_seconds,
        } = decision
        else {
            panic!("expected Limited");
        };
        assert!(retry_after_seconds >= 1);
    }

    #[tokio::test]
    async fn keys_are_independent() {
        let l = limiter();
        let window = Duration::from_secs(60);
        for _ in 0..3 {
            assert!(l.check("a", 3, window).await.is_allowed());
        }
        assert!(!l.check("a", 3, window).await.is_allowed());
        // A different key is unaffected — one account being ground does not lock
        // out everyone else.
        assert!(l.check("b", 3, window).await.is_allowed());
    }

    #[tokio::test]
    async fn tokens_refill_over_time() {
        let l = limiter();
        // The limiter reads `std::time::Instant`, which tokio's test clock does not
        // control, so this must be a real sleep. The sleep overshoots the window
        // threefold on purpose: a tight margin flakes when the machine is loaded
        // (observed while a clippy build ran concurrently), and a flaky security
        // test is worse than a slow one — it teaches people to re-run rather than
        // to look.
        let window = Duration::from_millis(200);
        for _ in 0..2 {
            assert!(l.check("k", 2, window).await.is_allowed());
        }
        assert!(!l.check("k", 2, window).await.is_allowed());
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert!(
            l.check("k", 2, window).await.is_allowed(),
            "the bucket should have refilled after three times its window"
        );
    }

    /// A fixed window would allow 2× the quota across the boundary; a bucket
    /// refills continuously and has no boundary to exploit.
    #[tokio::test]
    async fn there_is_no_window_boundary_to_burst_across() {
        let l = limiter();
        // A long window keeps scheduling jitter small relative to the interval being
        // measured. With a 200 ms window a 40 ms hiccup is a 20% error; with 2 s it
        // is 2%. The bounds below are correspondingly generous — the property under
        // test is "a fraction of the quota, not all of it", and that survives a
        // loaded machine. Asserting a narrow band here would only measure the CI
        // runner's mood.
        let window = Duration::from_millis(2000);
        for _ in 0..10 {
            let _ = l.check("k", 10, window).await;
        }
        assert!(!l.check("k", 10, window).await.is_allowed());

        // A quarter of a window later, roughly a quarter of the quota is back.
        tokio::time::sleep(Duration::from_millis(500)).await;
        let mut allowed = 0;
        for _ in 0..10 {
            if l.check("k", 10, window).await.is_allowed() {
                allowed += 1;
            }
        }
        assert!(
            allowed < 10,
            "the whole quota came back after a quarter window — that is fixed-window \
             behaviour, and it is exactly what an attacker bursts across ({allowed} of 10)"
        );
        assert!(
            allowed >= 1,
            "nothing refilled after a quarter window; the bucket is not refilling at all"
        );
    }

    #[tokio::test]
    async fn reset_clears_a_key() {
        let l = limiter();
        let window = Duration::from_secs(60);
        for _ in 0..3 {
            let _ = l.check("k", 3, window).await;
        }
        assert!(!l.check("k", 3, window).await.is_allowed());
        l.reset("k").await;
        assert!(
            l.check("k", 3, window).await.is_allowed(),
            "a successful login should clear the penalty"
        );
    }

    #[tokio::test]
    async fn a_zero_quota_denies_everything() {
        let l = limiter();
        assert!(!l.check("k", 0, Duration::from_secs(60)).await.is_allowed());
    }

    /// The limiter must not become the denial of service it exists to prevent.
    ///
    /// This is the regression test for a real defect: the original eviction only
    /// dropped buckets idle for over an hour, so a burst of fresh keys — an
    /// attacker rotating source addresses — evicted nothing and the table grew
    /// without bound.
    #[tokio::test]
    async fn the_key_table_is_bounded_under_key_rotation() {
        let l = InProcessRateLimiter::new(100);
        for i in 0..10_000 {
            let _ = l
                .check(&format!("key-{i}"), 10, Duration::from_secs(60))
                .await;
        }
        let tracked = l.buckets.lock().expect("mutex").len();
        assert!(
            tracked <= 100,
            "key table grew to {tracked} entries against a cap of 100"
        );
    }

    /// Bounding must not let an attacker evict a legitimate offender's bucket and
    /// reset their penalty. A key that is actively being limited is the *last*
    /// thing evicted, because stages 1 and 2 remove idle and full buckets first.
    #[tokio::test]
    async fn an_actively_limited_key_survives_eviction_pressure() {
        let l = InProcessRateLimiter::new(50);
        let window = Duration::from_secs(3600); // effectively no refill

        // Drain the victim's bucket.
        for _ in 0..5 {
            assert!(l.check("victim", 5, window).await.is_allowed());
        }
        assert!(!l.check("victim", 5, window).await.is_allowed());

        // Flood with fresh keys to force eviction. Each is used once, so each
        // bucket is left one token short of full and cannot be dropped by stage 2 —
        // this is the hostile case, not the easy one.
        for i in 0..500 {
            let _ = l.check(&format!("flood-{i}"), 5, window).await;
        }

        assert!(
            !l.check("victim", 5, window).await.is_allowed(),
            "an attacker rotating keys reset a limited account's penalty"
        );
        assert!(l.buckets.lock().expect("mutex").len() <= 50);
    }

    /// When the table cannot make room, a brand-new key is allowed rather than
    /// refused. A limiter that has run out of space must degrade, not become a
    /// global outage.
    #[tokio::test]
    async fn a_saturated_table_degrades_instead_of_refusing_everyone() {
        let l = InProcessRateLimiter::new(4);
        let window = Duration::from_secs(3600);
        // Fill every slot with a partially drained bucket.
        for i in 0..4 {
            let _ = l.check(&format!("k{i}"), 5, window).await;
        }
        for i in 100..200 {
            assert!(
                l.check(&format!("new-{i}"), 5, window).await.is_allowed(),
                "a new key was refused because the table was full"
            );
        }
    }

    #[test]
    fn key_namespaces_do_not_collide() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let id = uuid::Uuid::now_v7();
        let all = [
            keys::login_ip(ip),
            keys::login_account("a@b.com"),
            keys::mfa_session(id),
            keys::mfa_account(id),
            keys::refresh_ip(ip),
            keys::password_reset_ip(ip),
            keys::password_reset_account("a@b.com"),
            keys::registration_ip(ip),
            keys::bootstrap_ip(ip),
            keys::general_principal(id),
            keys::general_ip(ip),
        ];
        let unique: std::collections::HashSet<&String> = all.iter().collect();
        assert_eq!(
            unique.len(),
            all.len(),
            "two key builders produced the same key"
        );
    }

    #[tokio::test]
    async fn concurrent_checks_never_exceed_the_quota() {
        use std::sync::Arc;
        let l = Arc::new(limiter());
        let window = Duration::from_secs(3600); // effectively no refill
        let mut handles = Vec::new();
        for _ in 0..50 {
            let l = l.clone();
            handles.push(tokio::spawn(async move {
                l.check("shared", 10, window).await.is_allowed()
            }));
        }
        let mut allowed = 0;
        for h in handles {
            if h.await.unwrap() {
                allowed += 1;
            }
        }
        assert_eq!(
            allowed, 10,
            "50 concurrent requests let {allowed} through a quota of 10"
        );
    }
}
