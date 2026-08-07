//! Authentication: sessions, opaque tokens, MFA, and the password lifecycle.
//!
//! Read `docs/backend/03-authentication.md`, ADR-002 and ADR-005 before changing
//! anything here. Three properties in this module are load-bearing and are easy to
//! destroy with an innocent-looking edit:
//!
//!   * **Every** authentication failure returns the same `AuthenticationFailed`.
//!     Unknown account, wrong password, suspended user, expired token, revoked
//!     session and replayed TOTP code are indistinguishable on the wire (TH-23).
//!   * The unknown-account login path performs the same Argon2id work as the
//!     known-account path, so response time is not an account-existence oracle.
//!   * A hit on a consumed refresh token is treated as *proof of compromise*, not
//!     as a racy client, and kills the whole session family (ADR-005).
//!
//! `principal` is public because the request extractors resolve a bearer token
//! through it on every authenticated request, and other modules need `load_actor`.
//! `repo` is not public: the rule "a module calls another module's `service`, never
//! its `repo`" is enforced here by visibility rather than by convention.

pub mod dto;
pub mod mfa;
pub mod principal;
pub mod service;
pub mod sessions;

mod repo;
mod routes;

pub use routes::router;
