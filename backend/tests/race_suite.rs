//! Concurrency and race suites.
//!
//! Brief §72: these must be *executed*, not reasoned about. Every test here
//! creates genuine simultaneity with a barrier — spawning tasks in a loop usually
//! lets the first finish before the last starts, which passes without ever
//! exercising the race it claims to test.

mod common;

/// Preconditions only — an account exists, holds a permission, has a live session.
/// The race itself always goes through the real router. See the module docs.
#[path = "race/fixtures.rs"]
mod fixtures;

#[path = "race/bootstrap.rs"]
mod bootstrap;

#[path = "race/invitation_accept.rs"]
mod invitation_accept;

#[path = "race/password_reset.rs"]
mod password_reset;

#[path = "race/refresh_rotation.rs"]
mod refresh_rotation;

#[path = "race/optimistic_concurrency.rs"]
mod optimistic_concurrency;

#[path = "race/privilege_change_during_request.rs"]
mod privilege_change_during_request;

#[path = "race/outbox_worker.rs"]
mod outbox_worker;

#[path = "race/idempotency.rs"]
mod idempotency;
