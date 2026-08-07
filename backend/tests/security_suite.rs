//! Adversarial security suites.
//!
//! Grouped into one test binary so `cargo test --test security_suite` runs exactly
//! the suites whose purpose is to attack the system, and so a CI job can gate on
//! them specifically.
//!
//! Each submodule is named for what it tries to break, not for what it covers.

mod common;

#[path = "security/database_invariants.rs"]
mod database_invariants;

#[path = "security/runtime_role.rs"]
mod runtime_role;
