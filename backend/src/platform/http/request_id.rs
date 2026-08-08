//! Correlation identifiers.
//!
//! Every request gets an id. It appears in the response header, in every log line
//! produced while handling the request, and in any audit event the request writes,
//! so a user reporting "it failed at 14:32" can be traced end to end without
//! guessing.
//!
//! A caller-supplied `X-Request-Id` is *accepted but not trusted*: it is validated
//! for shape and length first. Echoing an arbitrary caller string into logs would
//! be a log-injection vector, and echoing an unbounded one would let a client
//! choose how large our log lines are.

use axum::extract::Request;
use axum::http::{header::HeaderName, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;
use uuid::Uuid;

pub const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");

/// Upper bound on an accepted caller-supplied id.
const MAX_LEN: usize = 64;
const MIN_LEN: usize = 8;

tokio::task_local! {
    static CURRENT_REQUEST_ID: String;
}

pub struct RequestId;

impl RequestId {
    /// The id of the request being handled on this task, if any.
    ///
    /// Returns `None` outside a request (background workers, tests), which is why
    /// the error renderer treats it as optional rather than asserting.
    pub fn current() -> Option<String> {
        CURRENT_REQUEST_ID.try_with(|id| id.clone()).ok()
    }
}

/// Accept a caller-supplied id only if it is short, printable and unambiguous.
///
/// The alphabet is deliberately narrow — alphanumerics, `-` and `_`. That excludes
/// every control character (log injection), every space (log field confusion) and
/// every quote (JSON confusion) without needing to reason about escaping later.
fn sanitize_supplied(value: &str) -> Option<String> {
    let v = value.trim();
    if v.len() < MIN_LEN || v.len() > MAX_LEN {
        return None;
    }
    if !v
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return None;
    }
    Some(v.to_string())
}

/// Middleware: establish the request id, expose it to the handler, and echo it.
pub async fn layer(mut request: Request, next: Next) -> Response {
    let supplied = request
        .headers()
        .get(&REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(sanitize_supplied);

    // UUIDv7 when generating our own: time-ordered, so ids sort chronologically in
    // a log aggregator without a separate timestamp index.
    let id = supplied.unwrap_or_else(|| Uuid::now_v7().to_string());

    // Normalise the inbound header so a downstream extractor sees the value we
    // actually adopted, not the (possibly rejected) one the caller sent.
    if let Ok(hv) = HeaderValue::from_str(&id) {
        request.headers_mut().insert(REQUEST_ID_HEADER, hv);
    }

    let echoed = id.clone();
    let mut response = CURRENT_REQUEST_ID.scope(id, next.run(request)).await;

    if let Ok(hv) = HeaderValue::from_str(&echoed) {
        response.headers_mut().insert(REQUEST_ID_HEADER, hv);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_a_reasonable_caller_supplied_id() {
        assert_eq!(sanitize_supplied("abc12345"), Some("abc12345".into()));
        assert_eq!(
            sanitize_supplied(" 0192f5c1-7c3a-7e1b-9f2d-3a4b5c6d7e8f "),
            Some("0192f5c1-7c3a-7e1b-9f2d-3a4b5c6d7e8f".into())
        );
    }

    #[test]
    fn rejects_ids_that_would_poison_a_log_line() {
        assert_eq!(sanitize_supplied("abc\r\nINFO fake line"), None);
        assert_eq!(sanitize_supplied("abc\ndef123"), None);
        assert_eq!(sanitize_supplied("abc\0def1"), None);
        assert_eq!(sanitize_supplied("\"quoted\""), None);
        assert_eq!(sanitize_supplied("has spaces here"), None);
        assert_eq!(sanitize_supplied("\x1b[31mred\x1b[0m"), None);
    }

    #[test]
    fn rejects_ids_outside_the_length_bounds() {
        assert_eq!(sanitize_supplied("short"), None);
        assert_eq!(sanitize_supplied(&"a".repeat(MAX_LEN + 1)), None);
        assert_eq!(sanitize_supplied(&"a".repeat(1_000_000)), None);
        assert!(sanitize_supplied(&"a".repeat(MAX_LEN)).is_some());
    }

    #[test]
    fn current_is_none_outside_a_request() {
        assert_eq!(RequestId::current(), None);
    }

    #[tokio::test]
    async fn current_is_visible_inside_the_scope() {
        CURRENT_REQUEST_ID
            .scope("test-request-id".to_string(), async {
                assert_eq!(RequestId::current().as_deref(), Some("test-request-id"));
            })
            .await;
    }
}
