//! First-run bootstrap: the one and only path that establishes system ownership.
//!
//! Everything here exists to make a single sentence true: **a running RoleBlank
//! database has exactly one owner, and that owner was created exactly once.**
//! ADR-004 enforces that at the schema, trigger and privilege layers; this module
//! is the application layer of the same invariant, and it is deliberately the only
//! module with no authenticated caller.
//!
//! Two endpoints, both anonymous:
//!
//! * `GET  /api/v1/bootstrap/status` — one boolean, so a deployment script can tell
//!   whether it still has work to do.
//! * `POST /api/v1/bootstrap/root`   — creates the owner, once, under an operator
//!   secret, an advisory lock and a `FOR UPDATE` re-read.
//!
//! There is no repository file: the module owns four statements against three
//! singleton-ish tables and splitting them into a `repo.rs` would hide the fact
//! that they all belong to one transaction.

pub mod dto;
mod routes;
pub mod service;

pub use routes::router;
