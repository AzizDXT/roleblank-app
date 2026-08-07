//! Response shapes for the system and health endpoints.
//!
//! Every field here was chosen by asking "what does an unauthenticated attacker
//! learn from this?" first. The probes are reachable from anywhere the service is
//! reachable, so they carry a **fixed vocabulary** and nothing derived from the
//! runtime: no version string, no hostname, no schema number, no dependency name.

use serde::Serialize;

/// The only two bodies the health probes may ever produce.
///
/// A constant, not a formatted string: it is impossible for a driver message or a
/// hostname to be appended to a `&'static str`.
pub const STATUS_OK: &str = "ok";
pub const STATUS_NOT_READY: &str = "not_ready";

/// The complete body of `/health/live` and `/health/ready`.
///
/// One field, and its value is one of two constants. There is deliberately no
/// `checks`, `details`, `version` or `error` member: a readiness body that names
/// the failing dependency tells an unauthenticated caller the shape of the
/// deployment (TH-35).
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct HealthResponse {
    pub status: &'static str,
}

impl HealthResponse {
    pub fn ok() -> Self {
        Self { status: STATUS_OK }
    }
    pub fn not_ready() -> Self {
        Self {
            status: STATUS_NOT_READY,
        }
    }
}

/// `GET /api/v1/system/info` — authenticated.
///
/// Three fields, and each is justified:
///
/// * `environment` — a client legitimately renders differently against a
///   development instance, and the value is one of three fixed words.
/// * `initialized` — whether bootstrap has happened. Already observable, because
///   the bootstrap endpoint answers differently once it has.
/// * `enabled_features` — the flag keys that are on, so a client knows which
///   navigation to render. Keys only: never the description, never the sensitivity
///   marker, never a value.
///
/// What is deliberately absent: build/version identifiers, the schema version,
/// hostnames, the database, the mail provider, pool statistics, uptime and the
/// permission catalogue. Each of those turns a routine authenticated read into
/// reconnaissance for whoever phishes one low-privilege account.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct SystemInfoResponse {
    pub environment: String,
    pub initialized: bool,
    pub enabled_features: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The property the readiness probe exists to preserve: the body is a closed
    /// vocabulary, so nothing internal can ride out on it.
    #[test]
    fn health_bodies_are_exactly_two_fixed_documents() {
        let live = serde_json::to_string(&HealthResponse::ok()).expect("serialise");
        let ready = serde_json::to_string(&HealthResponse::not_ready()).expect("serialise");
        assert_eq!(live, r#"{"status":"ok"}"#);
        assert_eq!(ready, r#"{"status":"not_ready"}"#);
    }

    #[test]
    fn health_bodies_carry_no_internal_detail() {
        for body in [
            serde_json::to_string(&HealthResponse::ok()).expect("serialise"),
            serde_json::to_string(&HealthResponse::not_ready()).expect("serialise"),
        ] {
            let lowered = body.to_lowercase();
            for leak in [
                "postgres",
                "database",
                "sqlx",
                "migration",
                "schema",
                "version",
                "host",
                "localhost",
                "127.0.0.1",
                "connection",
                "pool",
                "error",
                "timeout",
                "5432",
            ] {
                assert!(
                    !lowered.contains(leak),
                    "health body leaked `{leak}`: {body}"
                );
            }
            // One member only. A future `details` map is how this leak gets
            // reintroduced, so the shape itself is asserted.
            let parsed: serde_json::Value = serde_json::from_str(&body).expect("json");
            let object = parsed.as_object().expect("object");
            assert_eq!(object.len(), 1);
            assert!(object.contains_key("status"));
        }
    }

    #[test]
    fn system_info_exposes_three_members_and_no_more() {
        let body = serde_json::to_value(SystemInfoResponse {
            environment: "production".into(),
            initialized: true,
            enabled_features: vec!["client_portal".into()],
        })
        .expect("serialise");
        let object = body.as_object().expect("object");
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, vec!["enabled_features", "environment", "initialized"]);
    }
}
