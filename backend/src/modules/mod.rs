//! Business and platform modules.
//!
//! A module never calls another module''s `repo` directly, only its `service`.
//! That boundary is what keeps authorisation decisions from being bypassed by a
//! convenient shortcut.
pub mod audit;
pub mod authentication;
pub mod authorization;
pub mod bootstrap;
pub mod clients;
pub mod departments;
pub mod identity;
pub mod outbox;
pub mod projects;
pub mod settings;
pub mod system;
pub mod tasks;
