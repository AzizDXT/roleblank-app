//! Session lifetimes, the session cap, and refresh-rotation classification.
//!
//! Everything here is **pure**: it takes `now` as an argument and touches no
//! clock, no database and no configuration global. That is deliberate — these are
//! the rules that decide when a stolen token stops working, and rules that can
//! only be exercised against a live PostgreSQL instance are rules that do not get
//! exercised.

use std::time::Duration as StdDuration;
use time::{Duration, OffsetDateTime};

use crate::platform::config::SessionConfig;
use crate::platform::errors::{AppError, AppResult};

/// `sessions.auth_level` values. The database `CHECK` admits exactly these two.
pub const AUTH_LEVEL_PASSWORD: &str = "PASSWORD";
pub const AUTH_LEVEL_MFA: &str = "MFA";

/// `sessions.revocation_reason` values, matching the database `CHECK`. Named
/// constants because a typo would be a runtime constraint violation rendered as an
/// opaque 409 in the middle of a logout.
pub mod reason {
    pub const LOGOUT: &str = "LOGOUT";
    pub const LOGOUT_ALL: &str = "LOGOUT_ALL";
    pub const PASSWORD_CHANGED: &str = "PASSWORD_CHANGED";
    pub const PASSWORD_RESET: &str = "PASSWORD_RESET";
    pub const REFRESH_REUSE_DETECTED: &str = "REFRESH_REUSE_DETECTED";
    pub const SECURITY_POLICY: &str = "SECURITY_POLICY";
}

/// The three independent deadlines a session lives under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lifetimes {
    pub access_expires_at: OffsetDateTime,
    pub idle_expires_at: OffsetDateTime,
    /// The hard ceiling. No refresh ever moves this (ADR-005).
    pub absolute_expires_at: OffsetDateTime,
}

fn to_duration(value: StdDuration) -> AppResult<Duration> {
    Duration::try_from(value)
        .map_err(|_| AppError::Internal("a configured session lifetime is out of range".into()))
}

/// Adding a configured TTL to `now` can overflow for an absurd configuration.
/// Saturating rather than wrapping means the worst case is a session that expires
/// far in the future *and is still bounded by the absolute ceiling below*, never
/// one that expires in the past and is therefore unusable at birth.
fn advance(now: OffsetDateTime, by: Duration) -> OffsetDateTime {
    now.checked_add(by)
        .unwrap_or(OffsetDateTime::from_unix_timestamp(i64::from(i32::MAX)).unwrap_or(now))
}

/// Lifetimes for a brand-new session.
///
/// Access and idle are both capped at the absolute ceiling. Without the cap, a
/// misconfigured `access_ttl` longer than `absolute_ttl` would produce a session
/// whose access token outlives the ceiling the ceiling exists to impose.
pub fn new_lifetimes(config: &SessionConfig, now: OffsetDateTime) -> AppResult<Lifetimes> {
    let absolute_expires_at = advance(now, to_duration(config.absolute_ttl)?);
    Ok(Lifetimes {
        access_expires_at: advance(now, to_duration(config.access_ttl)?).min(absolute_expires_at),
        idle_expires_at: advance(now, to_duration(config.idle_ttl)?).min(absolute_expires_at),
        absolute_expires_at,
    })
}

/// Lifetimes after a successful refresh.
///
/// The absolute ceiling is carried over from the existing session unchanged. This
/// is the single most important line in the file: rotation extends access and
/// idle, and *nothing* extends the ceiling, so every compromise has an end.
pub fn refreshed_lifetimes(
    config: &SessionConfig,
    now: OffsetDateTime,
    absolute_expires_at: OffsetDateTime,
) -> AppResult<Lifetimes> {
    Ok(Lifetimes {
        access_expires_at: advance(now, to_duration(config.access_ttl)?).min(absolute_expires_at),
        idle_expires_at: advance(now, to_duration(config.idle_ttl)?).min(absolute_expires_at),
        absolute_expires_at,
    })
}

/// A refresh token never outlives the session it belongs to.
pub fn refresh_expiry(
    config: &SessionConfig,
    now: OffsetDateTime,
    absolute_expires_at: OffsetDateTime,
) -> AppResult<OffsetDateTime> {
    Ok(advance(now, to_duration(config.refresh_ttl)?).min(absolute_expires_at))
}

/// How many of a user's oldest live sessions must be revoked before one more is
/// created, so that `max_per_user` holds *after* the insert.
///
/// `max_per_user == 0` is treated as "unbounded" rather than "no sessions at all":
/// a configuration typo must not lock every user out of the product.
pub fn surplus_sessions(active: i64, max_per_user: usize) -> i64 {
    if max_per_user == 0 {
        return 0;
    }
    let max = i64::try_from(max_per_user).unwrap_or(i64::MAX);
    (active + 1 - max).max(0)
}

/// The next refresh generation, refusing to wrap.
///
/// Wrapping would collide with an earlier generation on the
/// `(session_id, generation)` unique index and, worse, would make the generation
/// number stop being a monotonic record of the family's history.
pub fn next_generation(current: i32) -> AppResult<i32> {
    current
        .checked_add(1)
        .ok_or_else(|| AppError::Internal("refresh generation overflowed".into()))
}

/// What to do with a presented refresh token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshVerdict {
    /// Consume it and mint the next generation.
    Rotate,
    /// A hit on a **consumed** row. Two parties hold the same refresh token; the
    /// only safe reading is compromise, so the whole family dies (ADR-005).
    ReuseDetected,
    /// Expired, revoked, past a ceiling, or the user is no longer ACTIVE. The
    /// client sees the same generic failure as every other rejection.
    Rejected,
}

/// Facts about a presented refresh token and its session, as loaded under
/// `FOR UPDATE`.
#[derive(Debug, Clone, Copy)]
pub struct RefreshFacts {
    pub consumed: bool,
    pub token_expires_at: OffsetDateTime,
    pub session_revoked: bool,
    pub absolute_expires_at: OffsetDateTime,
    pub idle_expires_at: OffsetDateTime,
    pub user_is_active: bool,
}

/// Classify a presented refresh token.
///
/// Reuse is checked **first and unconditionally**. An expired *and* consumed token
/// is still a compromise signal — treating it as a mere expiry would let an
/// attacker who waited out the refresh TTL probe the family silently.
pub fn classify_refresh(facts: RefreshFacts, now: OffsetDateTime) -> RefreshVerdict {
    if facts.consumed {
        return RefreshVerdict::ReuseDetected;
    }
    if facts.session_revoked
        || !facts.user_is_active
        || facts.token_expires_at <= now
        || facts.absolute_expires_at <= now
        || facts.idle_expires_at <= now
    {
        return RefreshVerdict::Rejected;
    }
    RefreshVerdict::Rotate
}

/// Whether a session created for this user must complete MFA before it can do
/// anything.
///
/// `mfa_enrolled` counts as well as `mfa_required`: a user who voluntarily enrolled
/// a second factor must be asked for it, otherwise enrolling would be decorative.
pub fn requires_mfa_completion(mfa_required: bool, mfa_enrolled: bool) -> bool {
    mfa_required || mfa_enrolled
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(access: u64, idle: u64, absolute: u64, refresh: u64) -> SessionConfig {
        SessionConfig {
            access_ttl: StdDuration::from_secs(access),
            idle_ttl: StdDuration::from_secs(idle),
            absolute_ttl: StdDuration::from_secs(absolute),
            refresh_ttl: StdDuration::from_secs(refresh),
            step_up_window: StdDuration::from_secs(600),
            max_per_user: 20,
        }
    }

    fn defaults() -> SessionConfig {
        // The documented defaults: 15 min access, 7 days idle, 30 days absolute.
        config(900, 604_800, 2_592_000, 604_800)
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("fixed timestamp")
    }

    #[test]
    fn the_documented_defaults_produce_the_documented_deadlines() {
        let l = new_lifetimes(&defaults(), now()).unwrap();
        assert_eq!(l.access_expires_at, now() + Duration::minutes(15));
        assert_eq!(l.idle_expires_at, now() + Duration::days(7));
        assert_eq!(l.absolute_expires_at, now() + Duration::days(30));
    }

    /// A misconfigured access TTL must never outlive the ceiling that exists to
    /// bound it.
    #[test]
    fn access_and_idle_are_capped_at_the_absolute_ceiling() {
        let c = config(99_999_999, 99_999_999, 3_600, 99_999_999);
        let l = new_lifetimes(&c, now()).unwrap();
        assert_eq!(l.absolute_expires_at, now() + Duration::hours(1));
        assert_eq!(l.access_expires_at, l.absolute_expires_at);
        assert_eq!(l.idle_expires_at, l.absolute_expires_at);
    }

    /// ADR-005: rotation is not a way to live forever.
    #[test]
    fn refreshing_never_extends_the_absolute_ceiling() {
        let c = defaults();
        let created = now();
        let ceiling = new_lifetimes(&c, created).unwrap().absolute_expires_at;

        let mut clock = created;
        for _ in 0..1000 {
            clock += Duration::hours(12);
            let l = refreshed_lifetimes(&c, clock, ceiling).unwrap();
            assert_eq!(l.absolute_expires_at, ceiling, "the ceiling moved");
            assert!(l.access_expires_at <= ceiling);
            assert!(l.idle_expires_at <= ceiling);
        }
    }

    #[test]
    fn a_refresh_token_never_outlives_its_session() {
        let c = defaults();
        let ceiling = now() + Duration::minutes(5);
        assert_eq!(refresh_expiry(&c, now(), ceiling).unwrap(), ceiling);

        let far = now() + Duration::days(365);
        assert_eq!(
            refresh_expiry(&c, now(), far).unwrap(),
            now() + Duration::days(7)
        );
    }

    // ---- the session cap ----------------------------------------------------

    #[test]
    fn the_session_cap_revokes_exactly_the_surplus() {
        assert_eq!(surplus_sessions(0, 20), 0);
        assert_eq!(surplus_sessions(19, 20), 0, "the 20th session fits");
        assert_eq!(surplus_sessions(20, 20), 1, "the 21st evicts one");
        assert_eq!(
            surplus_sessions(25, 20),
            6,
            "a backlog is drained in one go"
        );
        assert_eq!(surplus_sessions(0, 1), 0);
        assert_eq!(surplus_sessions(1, 1), 1);
    }

    /// A configuration typo must not lock the whole company out.
    #[test]
    fn a_zero_cap_is_treated_as_unbounded_not_as_zero_sessions() {
        assert_eq!(surplus_sessions(1000, 0), 0);
    }

    // ---- rotation -----------------------------------------------------------

    fn facts() -> RefreshFacts {
        RefreshFacts {
            consumed: false,
            token_expires_at: now() + Duration::days(7),
            session_revoked: false,
            absolute_expires_at: now() + Duration::days(30),
            idle_expires_at: now() + Duration::days(7),
            user_is_active: true,
        }
    }

    #[test]
    fn a_live_unconsumed_token_rotates() {
        assert_eq!(classify_refresh(facts(), now()), RefreshVerdict::Rotate);
    }

    /// The theft detector. A consumed row means two parties hold the same token.
    #[test]
    fn a_consumed_token_is_reuse_not_an_ordinary_rejection() {
        let f = RefreshFacts {
            consumed: true,
            ..facts()
        };
        assert_eq!(classify_refresh(f, now()), RefreshVerdict::ReuseDetected);
    }

    /// An attacker who waits out the refresh TTL before probing must not be able
    /// to convert a compromise signal into a silent expiry.
    #[test]
    fn reuse_is_detected_even_when_everything_else_has_also_expired() {
        let f = RefreshFacts {
            consumed: true,
            token_expires_at: now() - Duration::days(1),
            session_revoked: true,
            absolute_expires_at: now() - Duration::days(1),
            idle_expires_at: now() - Duration::days(1),
            user_is_active: false,
        };
        assert_eq!(classify_refresh(f, now()), RefreshVerdict::ReuseDetected);
    }

    #[test]
    fn every_other_failure_mode_is_a_plain_rejection() {
        let cases = [
            (
                "expired token",
                RefreshFacts {
                    token_expires_at: now(),
                    ..facts()
                },
            ),
            (
                "revoked session",
                RefreshFacts {
                    session_revoked: true,
                    ..facts()
                },
            ),
            (
                "suspended user",
                RefreshFacts {
                    user_is_active: false,
                    ..facts()
                },
            ),
            (
                "past the ceiling",
                RefreshFacts {
                    absolute_expires_at: now(),
                    ..facts()
                },
            ),
            (
                "idle timeout",
                RefreshFacts {
                    idle_expires_at: now(),
                    ..facts()
                },
            ),
        ];
        for (label, f) in cases {
            assert_eq!(
                classify_refresh(f, now()),
                RefreshVerdict::Rejected,
                "{label}"
            );
        }
    }

    /// Expiry is exclusive at the boundary: a token expiring exactly now is dead.
    #[test]
    fn expiry_boundaries_are_exclusive() {
        let f = RefreshFacts {
            token_expires_at: now(),
            ..facts()
        };
        assert_eq!(classify_refresh(f, now()), RefreshVerdict::Rejected);
        let f = RefreshFacts {
            token_expires_at: now() + Duration::seconds(1),
            ..facts()
        };
        assert_eq!(classify_refresh(f, now()), RefreshVerdict::Rotate);
    }

    #[test]
    fn generations_increase_and_refuse_to_wrap() {
        assert_eq!(next_generation(0).unwrap(), 1);
        assert_eq!(next_generation(41).unwrap(), 42);
        assert!(next_generation(i32::MAX).is_err());
    }

    // ---- the pending-MFA rule ----------------------------------------------

    #[test]
    fn mfa_completion_is_required_when_mandated_or_voluntarily_enrolled() {
        assert!(
            requires_mfa_completion(true, false),
            "ROOT: mandated but not yet enrolled"
        );
        assert!(requires_mfa_completion(true, true));
        assert!(
            requires_mfa_completion(false, true),
            "voluntary enrolment must still be asked for"
        );
        assert!(!requires_mfa_completion(false, false));
    }
}
