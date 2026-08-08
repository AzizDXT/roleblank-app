//! Per-endpoint HTTP integration suites for the business modules.
//!
//! The golden scenario walks the security story end to end exactly once. It proves
//! the spine holds; it says almost nothing about the ninety-odd endpoints that hang
//! off it. This binary is the complement: every endpoint called through the real
//! router, with its refusals asserted alongside its happy path, and the resulting
//! row read back out of PostgreSQL wherever "the API returned 200" would be a
//! weaker claim than "the row is in the state it should be".
//!
//! Grouped into one test binary so the whole business surface can be gated on with
//! `cargo test --test integration_suite`, and so the migrated-template database is
//! built once for all of it rather than once per file.

mod common;

#[path = "integration/fixtures.rs"]
mod fixtures;

#[path = "integration/departments.rs"]
mod departments;

#[path = "integration/clients.rs"]
mod clients;

#[path = "integration/projects.rs"]
mod projects;

#[path = "integration/tasks.rs"]
mod tasks;

#[path = "integration/identity.rs"]
mod identity;

#[path = "integration/roles_permissions.rs"]
mod roles_permissions;

#[path = "integration/settings_audit_system.rs"]
mod settings_audit_system;

#[path = "integration/scope_filtering.rs"]
mod scope_filtering;
