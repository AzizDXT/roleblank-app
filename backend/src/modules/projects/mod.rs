//! Projects: the project record, its internal membership, and the links that make
//! a project visible to an external client.
//!
//! This module owns the **external trust boundary**. A project becomes visible
//! outside the company through exactly one mechanism — a live row in
//! `project_client_links` joined to an `ACTIVE` client membership — and that
//! mechanism is expressed as a SQL predicate in `visibility.rs` so that it applies
//! to the query rather than to the result.
//!
//! Read `docs/backend/MODULE_GUIDE.md` §3.5 and `docs/backend/04-authorization.md`
//! §9 before changing anything here.

pub(crate) mod dto;
pub(crate) mod repo;
pub(crate) mod routes;
pub(crate) mod service;
/// Shared with `modules::tasks`: a task's visibility is defined in terms of its
/// project's, so both live in one tested place rather than in two that can drift.
pub(crate) mod visibility;

pub use routes::router;
