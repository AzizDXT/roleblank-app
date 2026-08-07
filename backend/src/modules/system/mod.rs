//! System module: health probes, the metrics scrape and the authenticated
//! information endpoint.
//!
//! The health probes are the only anonymous endpoints in the system that touch
//! infrastructure, so the module's whole design question is "what does an
//! unauthenticated caller learn?". The answer is: one of two fixed words.

mod dto;
mod repo;
mod routes;
mod service;

pub use dto::{HealthResponse, SystemInfoResponse};
pub use routes::router;
pub use service::{info, is_ready};
