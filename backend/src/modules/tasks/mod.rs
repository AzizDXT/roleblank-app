//! Tasks: the unit of work inside a project, its assignees, and its per-task
//! client visibility.
//!
//! The rule that matters most here: **sharing a project does not share its
//! tasks.** `tasks.client_visible` defaults to `false`, is not accepted on create,
//! and changing it is audited under its own action code. The external query
//! predicate requires the flag *and* a live project link, so neither alone is
//! enough (`docs/backend/04-authorization.md` §9).

pub(crate) mod dto;
pub(crate) mod repo;
pub(crate) mod routes;
pub(crate) mod service;

pub use routes::router;
