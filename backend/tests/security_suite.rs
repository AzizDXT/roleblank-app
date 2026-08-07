//! Adversarial security suites.
//!
//! Grouped into one test binary so `cargo test --test security_suite` runs exactly
//! the suites whose purpose is to attack the system, and so a CI job can gate on
//! them specifically.
//!
//! Each submodule is named for what it tries to break, not for what it covers.
//!
//! **Every file under `tests/security/` must appear below.** A suite that is not
//! declared here is not compiled and not run — it is 500 lines of security tests
//! that pass by not existing. `attack_probes` was in exactly that state until it
//! was found by this audit.

mod common;

/// Shared adversarial fixture. Not a suite: it builds the world the suites attack.
#[path = "security/fixtures.rs"]
mod fixtures;

#[path = "security/database_invariants.rs"]
mod database_invariants;

#[path = "security/runtime_role.rs"]
mod runtime_role;

#[path = "security/attack_probes.rs"]
mod attack_probes;

#[path = "security/client_escape.rs"]
mod client_escape;

#[path = "security/root_attack.rs"]
mod root_attack;

#[path = "security/delegation_matrix.rs"]
mod delegation_matrix;

#[path = "security/bola_matrix.rs"]
mod bola_matrix;

#[path = "security/session_attacks.rs"]
mod session_attacks;
