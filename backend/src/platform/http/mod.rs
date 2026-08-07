//! HTTP transport concerns: correlation, security headers, extractors, limits.
pub mod endpoints;
pub mod extract;
pub mod middleware;
pub mod rate_limit;
pub mod request_id;
