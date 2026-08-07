//! Concurrency and race suites.
//!
//! Brief §72: these must be *executed*, not reasoned about. Every test here
//! creates genuine simultaneity with a barrier — spawning tasks in a loop usually
//! lets the first finish before the last starts, which passes without ever
//! exercising the race it claims to test.

mod common;

#[path = "race/bootstrap.rs"]
mod bootstrap;
