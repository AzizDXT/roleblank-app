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

/// §5 — the same boundary as `client_escape`, judged on byte-level
/// indistinguishability rather than on the refusal alone.
#[path = "security/client_isolation.rs"]
mod client_isolation;

#[path = "security/root_attack.rs"]
mod root_attack;

/// §3 — the same objective as `root_attack`, aimed at the service, the runtime
/// database role and the triggers rather than at the route surface.
#[path = "security/root_destruction.rs"]
mod root_destruction;

#[path = "security/delegation_matrix.rs"]
mod delegation_matrix;

/// §4 — the same boundary as `delegation_matrix`, attacked from an administrator
/// built to look like one a real organisation would create.
#[path = "security/escalation_matrix.rs"]
mod escalation_matrix;

#[path = "security/bola_matrix.rs"]
mod bola_matrix;

#[path = "security/session_attacks.rs"]
mod session_attacks;

/// §6 — passwords, second factors, and the freshness of authority on a live
/// session. Complements `session_attacks`, which covers the session lifecycle.
#[path = "security/auth_attacks.rs"]
mod auth_attacks;

/// The residue of the final acceptance audit: one regression per LOW/INFO finding
/// that was closed rather than accepted. Named for the state of the report rather
/// than for a boundary, because the findings span modules and their common
/// property is that each was harmless alone.
#[path = "security/residual_hardening.rs"]
mod residual_hardening;
