//! Hardening suite — §9 mass assignment, §10 sensitive-data leakage,
//! §11 log injection, §12 resource exhaustion, §13 SQL injection.
//!
//! One binary rather than five, because every suite needs the same fixture and
//! cargo builds one process per integration-test file. `tests/hardening/world.rs`
//! is the shared world and the shared evidence helpers; each other module is one
//! section of the audit.

mod common;

#[path = "hardening/world.rs"]
mod world;

#[path = "hardening/mass_assignment.rs"]
mod mass_assignment;

#[path = "hardening/leakage.rs"]
mod leakage;

#[path = "hardening/log_injection.rs"]
mod log_injection;

#[path = "hardening/resource_limits.rs"]
mod resource_limits;

#[path = "hardening/sql_injection.rs"]
mod sql_injection;
