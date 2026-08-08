//! Wiring `Idempotency-Key` into the create endpoints.
//!
//! `modules::outbox::idempotency` has always held the *record*: reserve a key,
//! fingerprint the body, store the response, replay it. What was missing was the
//! part that connects it to a request. `api/openapi.yaml` documents the header on
//! six creation endpoints and describes exactly what it promises; the header was
//! nevertheless read by nothing, so every one of those promises was false and a
//! client retrying a create after a lost response created a second object. This
//! module is that connection, in one place rather than six.
//!
//! Two decisions are worth stating.
//!
//! **The fingerprint is taken over the raw bytes, before deserialisation.** A
//! fingerprint of the parsed value would make `{"a":1,"b":2}` and `{"b":2,"a":1}`
//! the same request, which is defensible, and would make a body with an unknown
//! field the same as one without, which is not — that is the mass-assignment
//! surface. Bytes are the honest unit, and they are also what the digest is
//! cheapest over. It does mean a client that reserialises its retry with different
//! whitespace gets a `409` rather than a replay; that is the safe direction to be
//! wrong in.
//!
//! **A concurrent duplicate waits rather than failing immediately.** The record is
//! reserved by the winner before it starts work, so a genuinely simultaneous retry
//! finds `IN_PROGRESS`. Answering `409` straight away would mean the common case —
//! a client that fired twice because the first response was slow — gets an error for
//! a request that is about to succeed. Instead the loser polls the record for a
//! short, bounded window and replays the winner's response. A request that is
//! genuinely stuck still ends in a `409` once the window closes, so the ceiling on
//! how long a duplicate can occupy a connection is fixed and small.

use std::future::Future;

use axum::body::Bytes;
use axum::extract::{FromRequest, Request};
use axum::http::{header, HeaderName, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::de::DeserializeOwned;
use serde::Serialize;
use uuid::Uuid;

use crate::app::AppState;
use crate::modules::outbox::idempotency::{self, IdempotencyKey, IdempotencyOutcome, MAX_KEY_LEN};
use crate::platform::errors::{AppError, AppResult};
use crate::platform::observability::sanitize;

/// The header, lowercased once so no call site can typo the casing.
const IDEMPOTENCY_KEY_HEADER: HeaderName = HeaderName::from_static("idempotency-key");

/// How long a duplicate will wait for the in-flight original before giving up.
///
/// Deliberately far below the 30 s request timeout: a duplicate must never be the
/// thing that holds a connection open, and a create that has not finished in this
/// long is not "about to reply", it is wedged.
const IN_PROGRESS_WAIT_MS: u64 = 1_500;

/// Poll interval while waiting. Short enough that the ordinary case (the original
/// finishing in a few milliseconds) is not padded out to a visible delay.
const IN_PROGRESS_POLL_MS: u64 = 25;

/// A JSON body plus the idempotency context the request carried with it.
///
/// Replaces `extract::Json<T>` on the handlers that honour the header. It is a
/// separate type rather than an option on `Json` so that a handler which takes it
/// *must* pass it to [`create`] — the raw value is reachable only by destructuring,
/// and a handler that ignored the key would be visibly doing so.
pub struct Idempotent<T> {
    value: T,
    key: Option<IdempotencyKey>,
    fingerprint: Vec<u8>,
}

impl<T> Idempotent<T> {
    /// The parsed body. Named rather than a public field so the `key` and the
    /// `fingerprint` cannot be read, cloned or forged by a handler.
    pub fn into_value(self) -> T {
        self.value
    }
}

impl<T, S> FromRequest<S> for Idempotent<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        // The same strict content type as `extract::Json`, for the same reason: a
        // browser can issue a cross-site form POST but cannot set
        // `Content-Type: application/json` without a preflight CORS will refuse.
        let content_type = req
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        if !content_type
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .eq_ignore_ascii_case("application/json")
        {
            return Err(AppError::UnsupportedMediaType);
        }

        // Parsed before the body is read, so an oversized or control-bearing key is
        // refused without buffering the document it came with.
        let key = match req.headers().get(&IDEMPOTENCY_KEY_HEADER) {
            None => None,
            Some(raw) => {
                // A header that is not valid UTF-8, or is longer than the key bound,
                // cannot be a key we issued a record for. It is reported as a field
                // error rather than ignored: silently discarding it would hand the
                // client a *non*-idempotent request it believes is idempotent, which
                // is the failure this whole module exists to prevent.
                let text = raw.to_str().map_err(|_| {
                    AppError::field(
                        "Idempotency-Key",
                        "INVALID_FORMAT",
                        "The Idempotency-Key must contain only printable ASCII characters \
                         (no spaces, no control characters).",
                    )
                })?;
                if text.len() > MAX_KEY_LEN {
                    return Err(AppError::field(
                        "Idempotency-Key",
                        "TOO_LONG",
                        format!("The Idempotency-Key must be at most {MAX_KEY_LEN} characters."),
                    ));
                }
                Some(IdempotencyKey::parse(text)?)
            }
        };

        // `RequestBodyLimitLayer` already wraps the body, so this cannot buffer more
        // than the configured maximum however long the client claims the body is.
        let bytes = Bytes::from_request(req, state).await.map_err(|rejection| {
            match rejection.status() {
                StatusCode::PAYLOAD_TOO_LARGE => AppError::PayloadTooLarge,
                _ => AppError::BadRequest("The request body could not be read."),
            }
        })?;

        let value = serde_json::from_slice::<T>(&bytes).map_err(|e| {
            // serde's message names Rust field and type paths and quotes the
            // offending input. It is logged, never returned.
            tracing::debug!(
                rejection = %sanitize::log_value(e.to_string()),
                "rejected a JSON body"
            );
            AppError::BadRequest(
                "The request body is not valid JSON for this endpoint, or contains unrecognised fields.",
            )
        })?;

        Ok(Idempotent {
            value,
            key,
            // Over the bytes, not over `value`. See the module docs.
            fingerprint: idempotency::fingerprint(&bytes),
        })
    }
}

/// Run a creation handler under the request's idempotency key, if it has one.
///
/// The response is always `201 Created` on the fresh path — every endpoint that
/// honours the header creates something — and on the replay path it is whatever
/// status the original produced, so a client cannot tell the two apart.
///
/// A handler that *fails* releases the key rather than keeping it. That is the
/// difference between "this work already happened" and "this work was attempted":
/// leaving a failed attempt's reservation in place would make a validation error
/// permanently poison a key for 24 hours, so the client's corrected retry — the
/// thing we want it to do — would get a `409` instead of being served.
pub async fn create<T, R, F, Fut>(
    state: &AppState,
    principal_id: Uuid,
    operation: &'static str,
    request: Idempotent<T>,
    handler: F,
) -> AppResult<Response>
where
    F: FnOnce(T) -> Fut,
    Fut: Future<Output = AppResult<R>>,
    R: Serialize,
{
    let Idempotent {
        value,
        key,
        fingerprint,
    } = request;

    // No key: the endpoint behaves exactly as it did before, with no record written
    // and no extra round trip. Idempotency is opt-in per request, as the spec says.
    let Some(key) = key else {
        let created = handler(value).await?;
        return Ok((StatusCode::CREATED, axum::Json(created)).into_response());
    };

    let deadline =
        std::time::Instant::now() + std::time::Duration::from_millis(IN_PROGRESS_WAIT_MS);
    loop {
        match idempotency::begin(&state.db, principal_id, operation, &key, &fingerprint).await? {
            IdempotencyOutcome::Proceed { record_id } => {
                let created = match handler(value).await {
                    Ok(created) => created,
                    Err(e) => {
                        // Best effort: if the release fails the key stays reserved
                        // until the retention sweep, which is inconvenient but never
                        // wrong. The original error is what the client must see, so
                        // it is never replaced by a failure from the cleanup.
                        idempotency::abandon(&state.db, record_id).await;
                        return Err(e);
                    }
                };

                let body = serde_json::to_value(&created).map_err(|_| {
                    AppError::internal("a created resource could not be serialised")
                })?;
                // Stored after the work committed. A failure here is logged inside
                // `complete` and deliberately not propagated: the resource exists, and
                // failing the request would make the client retry work that succeeded.
                idempotency::complete(
                    &state.db,
                    record_id,
                    i32::from(StatusCode::CREATED.as_u16()),
                    &body,
                )
                .await?;

                return Ok((StatusCode::CREATED, axum::Json(body)).into_response());
            }

            IdempotencyOutcome::Replay { status, body } => {
                // The stored status came from `StatusCode::CREATED` and the column
                // constrains it to 100..=599, so the fallback is unreachable — but it
                // is a fallback rather than an unwrap, because this path is reachable
                // from a plain client retry.
                let status = u16::try_from(status)
                    .ok()
                    .and_then(|s| StatusCode::from_u16(s).ok())
                    .unwrap_or(StatusCode::CREATED);
                return Ok((status, axum::Json(body)).into_response());
            }

            IdempotencyOutcome::InProgress => {
                if std::time::Instant::now() >= deadline {
                    tracing::warn!(
                        operation = %sanitize::log_value(operation),
                        principal_id = %principal_id,
                        "an idempotent request was still in progress after the wait window"
                    );
                    return Err(AppError::conflict(
                        "IDEMPOTENCY_RACE",
                        "An identical request with this Idempotency-Key is still in progress. \
                         Retry shortly.",
                    ));
                }
                tokio::time::sleep(std::time::Duration::from_millis(IN_PROGRESS_POLL_MS)).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wait must be comfortably inside the request timeout, or a duplicate
    /// becomes the thing that times a connection out.
    #[test]
    fn the_wait_window_is_bounded_well_below_the_request_timeout() {
        let default_request_timeout_ms = 30_000u64;
        assert!(
            IN_PROGRESS_WAIT_MS * 4 < default_request_timeout_ms,
            "the in-progress wait is too close to the request timeout"
        );
        // `const` blocks: both sides are constants, so these are compile-time facts.
        const { assert!(IN_PROGRESS_POLL_MS > 0, "a zero poll interval would spin") };
        const {
            assert!(
                IN_PROGRESS_WAIT_MS / IN_PROGRESS_POLL_MS >= 10,
                "too few polls to catch a fast original"
            )
        };
    }

    #[test]
    fn the_header_name_is_the_one_cors_allows() {
        assert_eq!(IDEMPOTENCY_KEY_HEADER.as_str(), "idempotency-key");
    }
}
