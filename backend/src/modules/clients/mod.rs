//! Client accounts — the external businesses the company works for.
//!
//! **These are internal-facing endpoints for managing external customers.** They
//! are not the client portal. Every permission in this module is
//! `max_principal_type = INTERNAL`, so a `CLIENT` principal is refused by the
//! evaluator before any grant is consulted, and `state.require` turns that refusal
//! into a `404` rather than a `403` — the existence of the customer-management
//! surface is not an external user's business.
//!
//! A client account is **not** a tenant. There is one company and one database;
//! external visibility comes from explicit links, never from possession of an id.
//!
//! `repo` is private so the "call another module's `service`, never its `repo`"
//! rule is enforced by the compiler rather than by discipline.

pub mod dto;
pub mod service;

mod repo;
mod routes;

pub use routes::router;
