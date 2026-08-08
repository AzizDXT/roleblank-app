//! Departments — the company's internal organisational units.
//!
//! Deliberately flat: there is no parent/child hierarchy, and that omission is a
//! decision rather than an oversight (`docs/backend/05-data-model.md` §5). A
//! self-referencing tree brings cycle prevention, transitive visibility and
//! recursive authorisation queries with it; nothing in this scope needs any of
//! them, and adding a hierarchy later is an additive migration whereas removing an
//! unnecessary one is not.
//!
//! `repo` is private on purpose. The rule "a module calls another module's
//! `service`, never its `repo`" is enforced here by visibility rather than by
//! convention, so the shortcut that would bypass an authorisation decision does
//! not compile.

pub mod dto;
pub mod service;

mod repo;
mod routes;

pub use routes::router;
