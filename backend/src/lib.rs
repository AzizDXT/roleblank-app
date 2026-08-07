#![forbid(unsafe_code)]
//! RoleBlank OS — internal company operating system backend.
//!
//! The crate is a library plus a thin binary so that integration and security
//! tests under `tests/` construct the real router and the real services
//! in-process, rather than testing a reimplementation of them.

pub mod app;
pub mod cli;
pub mod modules;
pub mod platform;
pub mod routes;
pub mod shared;
