//! Authorization: the permission catalogue, the evaluator, the delegation guard,
//! and the HTTP surface for managing roles and per-user overrides.
//!
//! Read `docs/backend/04-authorization.md` and ADR-003 before changing anything in
//! this module. The evaluation order in `evaluator::evaluate` is normative.
pub mod catalog;
pub mod delegation;
pub mod domain;
pub mod dto;
pub mod evaluator;
pub mod repo;
pub mod routes;
pub mod service;

#[cfg(test)]
mod properties;
