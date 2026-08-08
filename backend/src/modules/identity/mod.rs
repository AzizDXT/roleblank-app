//! Identity: user lifecycle, invitations, and client self-registration.
//!
//! This module owns the three ways a principal can come into existence and the
//! four states it can be in. Read `docs/backend/03-authentication.md` §10 and
//! ADR-004 before changing anything here.
//!
//! ```text
//!   invitation   ->  INTERNAL or CLIENT, roles fixed by the inviter and
//!                    re-validated against the inviter's authority on acceptance
//!   registration ->  CLIENT only, PENDING, zero memberships, `client_user` role
//!   bootstrap    ->  the owner, once, in modules::bootstrap
//! ```
//!
//! Three properties hold across every path in this module:
//!
//! * **The system owner is never a target.** `state.guard_root` is the first thing
//!   every user-targeting operation calls, before authorisation, before validation
//!   and before any write (ADR-004 layer 4).
//! * **There is no user DELETE.** Accounts are archived. The runtime database role
//!   holds no `DELETE` grant on `users`, so an attempt would fail at the database
//!   even if one were written here.
//! * **No endpoint lets a caller choose their own security envelope.**
//!   `principal_type`, `status` and role sets are constructed in code or taken from
//!   an invitation the caller could not author; every request DTO is
//!   `deny_unknown_fields`.

pub mod dto;
pub mod invitations;
pub mod registration;
mod repo;
mod routes;
pub mod service;

pub use routes::router;
