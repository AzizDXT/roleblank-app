//! Application error type and its RFC 9457 `application/problem+json` rendering.
//!
//! Two rules govern everything in this module:
//!
//! 1. **Machine clients branch on `code`, never on prose.** `code` is a stable
//!    SCREAMING_SNAKE identifier that is part of the API contract. `title` and
//!    `detail` are human text and may be reworded at any time.
//! 2. **`detail` never carries an internal fact.** No SQL, no backtrace, no file
//!    path, no environment variable, no secret, no database hostname. Internal
//!    causes are logged against the request id and the client is told only that
//!    something failed. See `docs/backend/02-threat-model.md` TH-35.

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use std::borrow::Cow;

use crate::platform::http::request_id::RequestId;

/// Namespace for problem `type` URIs. Deliberately not a live URL: resolving it
/// must never be required to handle an error, and pointing at an external host
/// would leak error occurrence to that host.
const PROBLEM_TYPE_BASE: &str = "https://roleblank.internal/problems/";

#[derive(Debug, Clone, Serialize)]
pub struct FieldError {
    /// Dotted path to the offending field, e.g. `name` or `members.0.user_id`.
    pub field: Cow<'static, str>,
    /// Stable, machine-readable reason: `REQUIRED`, `TOO_LONG`, `INVALID_FORMAT`…
    pub code: Cow<'static, str>,
    /// Human hint. Never echoes the rejected value — echoing it back is how a
    /// validation error becomes a reflection gadget and a log-injection vector.
    pub message: Cow<'static, str>,
}

impl FieldError {
    pub fn new(
        field: impl Into<Cow<'static, str>>,
        code: impl Into<Cow<'static, str>>,
        message: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self {
            field: field.into(),
            code: code.into(),
            message: message.into(),
        }
    }
}

/// Everything a request can fail with.
///
/// Variants are grouped by the status they render as. Adding a variant forces a
/// decision about status, code and whether the detail is safe to expose.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    // ---- 400 -------------------------------------------------------------
    // NOTE ON `Display`: these messages are for logs and tests. They may contain
    // the internal detail. The client NEVER sees them — `IntoResponse` renders
    // `detail()`, which is separately audited for information leakage.
    #[error("validation failed: {}", errors.iter().map(|e| format!("{}={}", e.field, e.code)).collect::<Vec<_>>().join(", "))]
    Validation { errors: Vec<FieldError> },

    #[error("malformed request: {0}")]
    BadRequest(&'static str),

    /// A permission code arrived from a client that is not in the catalogue.
    /// Distinguished from a plain validation error because it means the caller is
    /// probing the authorisation surface, and it is audited as such.
    #[error("unknown permission code")]
    UnknownPermission,

    // ---- 401 -------------------------------------------------------------
    /// The single, deliberately undifferentiated authentication failure.
    ///
    /// Unknown account, wrong password, expired token, revoked session, malformed
    /// bearer header and suspended user all render identically. Any distinction
    /// here is an account-enumeration oracle (TH-23).
    #[error("authentication failed")]
    AuthenticationFailed,

    // ---- 403 -------------------------------------------------------------
    #[error("authorization denied")]
    AuthorizationDenied,

    /// Recent MFA verification is required. Carries the window so a client knows
    /// to re-prompt rather than to give up.
    #[error("step-up authentication required")]
    StepUpRequired { window_seconds: u64 },

    /// The session is authenticated but has not completed MFA and may only reach
    /// the MFA endpoints.
    #[error("MFA enrolment or verification required")]
    MfaRequired,

    /// Unmistakable on purpose: an operation targeted the system owner. ROOT's
    /// existence is not a secret, and the refusal should be impossible to
    /// misdiagnose as a transient failure.
    #[error("the system owner is protected from this operation")]
    RootProtected,

    /// The actor cannot grant authority it does not itself hold at that scope.
    #[error("delegation denied: {detail}")]
    DelegationDenied { detail: Cow<'static, str> },

    // ---- 404 -------------------------------------------------------------
    /// Also returned to external principals in place of 403, so that a refusal
    /// does not confirm the existence of an object they should not know about.
    #[error("resource not found")]
    NotFound,

    // ---- 409 / 412 -------------------------------------------------------
    #[error("conflict ({code}): {detail}")]
    Conflict {
        code: &'static str,
        detail: Cow<'static, str>,
    },

    /// Optimistic concurrency: the client's `version` is stale.
    #[error("version conflict")]
    VersionConflict { expected: i32, actual: i32 },

    /// Same `Idempotency-Key`, different request body.
    #[error("idempotency key reused with a different payload")]
    IdempotencyKeyReused,

    /// The system has already been initialised; bootstrap is permanently closed.
    #[error("system already initialised")]
    AlreadyInitialized,

    // ---- 413 / 415 -------------------------------------------------------
    #[error("payload too large")]
    PayloadTooLarge,

    #[error("unsupported media type")]
    UnsupportedMediaType,

    // ---- 429 -------------------------------------------------------------
    #[error("too many requests")]
    TooManyRequests { retry_after_seconds: u64 },

    // ---- 5xx -------------------------------------------------------------
    /// The catch-all. The inner message is logged, never returned.
    #[error("internal error: {0}")]
    Internal(String),

    #[error("service unavailable")]
    ServiceUnavailable,
}

impl AppError {
    pub fn internal(context: impl std::fmt::Display) -> Self {
        AppError::Internal(context.to_string())
    }

    pub fn conflict(code: &'static str, detail: impl Into<Cow<'static, str>>) -> Self {
        AppError::Conflict {
            code,
            detail: detail.into(),
        }
    }

    pub fn delegation(detail: impl Into<Cow<'static, str>>) -> Self {
        AppError::DelegationDenied {
            detail: detail.into(),
        }
    }

    pub fn field(
        field: impl Into<Cow<'static, str>>,
        code: impl Into<Cow<'static, str>>,
        message: impl Into<Cow<'static, str>>,
    ) -> Self {
        AppError::Validation {
            errors: vec![FieldError::new(field, code, message)],
        }
    }

    pub fn status(&self) -> StatusCode {
        use AppError::*;
        match self {
            Validation { .. } | BadRequest(_) | UnknownPermission => StatusCode::BAD_REQUEST,
            AuthenticationFailed => StatusCode::UNAUTHORIZED,
            AuthorizationDenied
            | StepUpRequired { .. }
            | MfaRequired
            | RootProtected
            | DelegationDenied { .. } => StatusCode::FORBIDDEN,
            NotFound => StatusCode::NOT_FOUND,
            Conflict { .. }
            | VersionConflict { .. }
            | IdempotencyKeyReused
            | AlreadyInitialized => StatusCode::CONFLICT,
            PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            UnsupportedMediaType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            TooManyRequests { .. } => StatusCode::TOO_MANY_REQUESTS,
            Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ServiceUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    /// The stable contract identifier. Clients branch on this.
    pub fn code(&self) -> &'static str {
        use AppError::*;
        match self {
            Validation { .. } => "VALIDATION_FAILED",
            BadRequest(_) => "BAD_REQUEST",
            UnknownPermission => "UNKNOWN_PERMISSION",
            AuthenticationFailed => "AUTHENTICATION_FAILED",
            AuthorizationDenied => "AUTHORIZATION_DENIED",
            StepUpRequired { .. } => "STEP_UP_REQUIRED",
            MfaRequired => "MFA_REQUIRED",
            RootProtected => "ROOT_PROTECTED",
            DelegationDenied { .. } => "DELEGATION_DENIED",
            NotFound => "RESOURCE_NOT_FOUND",
            Conflict { code, .. } => code,
            VersionConflict { .. } => "VERSION_CONFLICT",
            IdempotencyKeyReused => "IDEMPOTENCY_KEY_REUSED",
            AlreadyInitialized => "SYSTEM_ALREADY_INITIALIZED",
            PayloadTooLarge => "PAYLOAD_TOO_LARGE",
            UnsupportedMediaType => "UNSUPPORTED_MEDIA_TYPE",
            TooManyRequests { .. } => "RATE_LIMITED",
            Internal(_) => "INTERNAL_ERROR",
            ServiceUnavailable => "SERVICE_UNAVAILABLE",
        }
    }

    fn title(&self) -> &'static str {
        use AppError::*;
        match self {
            Validation { .. } => "The request payload failed validation",
            BadRequest(_) => "The request could not be understood",
            UnknownPermission => "Unknown permission code",
            AuthenticationFailed => "Authentication failed",
            AuthorizationDenied => "You are not authorized to perform this operation",
            StepUpRequired { .. } => "Recent multi-factor verification is required",
            MfaRequired => "Multi-factor authentication must be completed first",
            RootProtected => "The system owner is protected from this operation",
            DelegationDenied { .. } => "You cannot grant authority you do not hold",
            NotFound => "Resource not found",
            Conflict { .. } => "The request conflicts with the current state",
            VersionConflict { .. } => "The resource was modified by someone else",
            IdempotencyKeyReused => "Idempotency key reused with a different payload",
            AlreadyInitialized => "The system has already been initialized",
            PayloadTooLarge => "Request body too large",
            UnsupportedMediaType => "Unsupported media type",
            TooManyRequests { .. } => "Too many requests",
            Internal(_) => "Internal server error",
            ServiceUnavailable => "Service temporarily unavailable",
        }
    }

    /// Client-safe explanation. Every arm here is audited for information leakage:
    /// nothing derived from an internal string, a database message, or a secret
    /// may appear.
    fn detail(&self) -> Cow<'static, str> {
        use AppError::*;
        match self {
            Validation { .. } => Cow::Borrowed("One or more fields are invalid. See `errors`."),
            BadRequest(m) => Cow::Borrowed(*m),
            UnknownPermission => {
                Cow::Borrowed("The supplied permission code is not part of the permission catalogue.")
            }
            // Deliberately identical for every authentication failure mode.
            AuthenticationFailed => {
                Cow::Borrowed("The credentials or token supplied are not valid.")
            }
            AuthorizationDenied => {
                Cow::Borrowed("Your effective permissions do not allow this operation.")
            }
            StepUpRequired { window_seconds } => Cow::Owned(format!(
                "This operation requires multi-factor verification within the last {window_seconds} seconds."
            )),
            MfaRequired => Cow::Borrowed(
                "This session must complete multi-factor authentication before using this endpoint.",
            ),
            RootProtected => Cow::Borrowed(
                "The system owner cannot be modified, disabled or removed through the API.",
            ),
            DelegationDenied { detail } => detail.clone(),
            NotFound => Cow::Borrowed("The requested resource does not exist or is not visible to you."),
            Conflict { detail, .. } => detail.clone(),
            VersionConflict { expected, actual } => Cow::Owned(format!(
                "Expected version {expected} but the current version is {actual}. Re-read the resource and retry."
            )),
            IdempotencyKeyReused => Cow::Borrowed(
                "This Idempotency-Key was already used for a different request body.",
            ),
            AlreadyInitialized => {
                Cow::Borrowed("Bootstrap is permanently unavailable once the system is initialized.")
            }
            PayloadTooLarge => Cow::Borrowed("The request body exceeds the maximum accepted size."),
            UnsupportedMediaType => {
                Cow::Borrowed("This endpoint accepts application/json only.")
            }
            TooManyRequests { retry_after_seconds } => Cow::Owned(format!(
                "Rate limit exceeded. Retry after {retry_after_seconds} seconds."
            )),
            // The inner string is logged with the request id; it never reaches here.
            Internal(_) => Cow::Borrowed(
                "An internal error occurred. Quote the request_id when reporting this.",
            ),
            ServiceUnavailable => {
                Cow::Borrowed("A required dependency is unavailable. Retry shortly.")
            }
        }
    }

    /// Whether the failure warrants a security-relevant log line rather than an
    /// ordinary one. Used by the error-rendering middleware.
    pub fn is_security_relevant(&self) -> bool {
        use AppError::*;
        matches!(
            self,
            AuthenticationFailed
                | AuthorizationDenied
                | StepUpRequired { .. }
                | RootProtected
                | DelegationDenied { .. }
                | UnknownPermission
                | TooManyRequests { .. }
        )
    }

    /// Converts a would-be `403` into a `404` for principals that must not learn
    /// the object exists.
    ///
    /// Applied per principal type rather than blanket: inside the company,
    /// existence disclosure is acceptable and a blanket 404 would make operational
    /// support impossible. See `docs/backend/04-authorization.md` §10.
    pub fn hide_from_external(self, is_external: bool) -> Self {
        match (is_external, &self) {
            (true, AppError::AuthorizationDenied) => AppError::NotFound,
            _ => self,
        }
    }
}

/// The wire shape. Field order matches RFC 9457's examples for readability.
#[derive(Debug, Serialize)]
struct ProblemDetails<'a> {
    #[serde(rename = "type")]
    type_uri: String,
    title: &'a str,
    status: u16,
    code: &'a str,
    detail: Cow<'a, str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    errors: Option<&'a [FieldError]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    step_up: Option<StepUpHint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version_conflict: Option<VersionConflictHint>,
}

#[derive(Debug, Serialize)]
struct StepUpHint {
    window_seconds: u64,
}

/// The two versions a losing writer needs, as *data* rather than as prose.
///
/// `detail` already states both numbers, but `detail` is human text that rule 1 of
/// this module says may be reworded at any time. A client that wants to re-read and
/// retry automatically — which is the entire point of optimistic concurrency — would
/// otherwise have to parse an English sentence to find out what the current version
/// is. Emitting the pair as a field makes the retry loop machine-writable and makes
/// a test able to assert it without asserting on prose.
#[derive(Debug, Serialize)]
struct VersionConflictHint {
    /// The version the client sent.
    expected: i32,
    /// The version the row actually holds now. Re-read and retry with this.
    actual: i32,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        // The request id is placed into a task-local by the request-id middleware.
        let request_id = RequestId::current();

        if let AppError::Internal(cause) = &self {
            // The only place an internal cause is ever emitted, and it goes to the
            // log — correlated by request id — never to the client.
            tracing::error!(
                request_id = request_id.as_deref().unwrap_or("-"),
                error.kind = "internal",
                error.cause = %crate::platform::observability::sanitize::log_value(cause),
                "request failed with an internal error"
            );
        }

        let status = self.status();
        let errors = match &self {
            AppError::Validation { errors } => Some(errors.as_slice()),
            _ => None,
        };
        let step_up = match &self {
            AppError::StepUpRequired { window_seconds } => Some(StepUpHint {
                window_seconds: *window_seconds,
            }),
            _ => None,
        };
        let version_conflict = match &self {
            AppError::VersionConflict { expected, actual } => Some(VersionConflictHint {
                expected: *expected,
                actual: *actual,
            }),
            _ => None,
        };

        let code = self.code();
        let body = ProblemDetails {
            type_uri: format!("{PROBLEM_TYPE_BASE}{}", code.to_ascii_lowercase()),
            title: self.title(),
            status: status.as_u16(),
            code,
            detail: self.detail(),
            request_id,
            errors,
            step_up,
            version_conflict,
        };

        let payload = serde_json::to_vec(&body).unwrap_or_else(|_| {
            // Serialising a struct of owned strings cannot realistically fail, but
            // a panic in an error path would turn a handled 4xx into a dropped
            // connection, so there is a literal fallback instead of an unwrap.
            br#"{"type":"https://roleblank.internal/problems/internal_error","title":"Internal server error","status":500,"code":"INTERNAL_ERROR","detail":"An internal error occurred."}"#.to_vec()
        });

        let mut response = (status, payload).into_response();
        let headers = response.headers_mut();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/problem+json"),
        );
        // Error responses may embed request-specific context; they must not be
        // stored by any intermediary.
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));

        if let AppError::TooManyRequests {
            retry_after_seconds,
        } = &self
        {
            if let Ok(v) = HeaderValue::from_str(&retry_after_seconds.to_string()) {
                headers.insert(header::RETRY_AFTER, v);
            }
        }

        response
    }
}

/// Database errors are mapped centrally so that no repository has to remember to
/// avoid leaking a driver message, and so that constraint violations become
/// meaningful conflicts rather than opaque 500s.
impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        match &err {
            sqlx::Error::RowNotFound => AppError::NotFound,
            sqlx::Error::Database(db) => {
                // 23505 unique_violation, 23503 foreign_key_violation,
                // 23514 check_violation, P0001 raise_exception (our triggers).
                let code = db.code().unwrap_or_default().to_string();
                let constraint = db.constraint().unwrap_or_default().to_string();
                tracing::warn!(
                    sqlstate = %code,
                    constraint = %constraint,
                    "database constraint rejected a statement"
                );
                match code.as_str() {
                    "23505" => AppError::conflict(
                        "UNIQUE_VIOLATION",
                        "A resource with these unique attributes already exists.",
                    ),
                    "23503" => AppError::conflict(
                        "REFERENCE_VIOLATION",
                        "A referenced resource does not exist or is still in use.",
                    ),
                    // A trigger fired. These are the ROOT and client-envelope
                    // invariants; the trigger's own message is NOT forwarded,
                    // because it names internal tables and columns.
                    "P0001" => AppError::conflict(
                        "INVARIANT_VIOLATION",
                        "The operation violates a system invariant and was refused.",
                    ),
                    "42501" => {
                        // Insufficient privilege for the runtime database role. This
                        // is either an attack that got further than it should have,
                        // or a grant misconfiguration. Both are operational alarms.
                        tracing::error!("runtime database role lacks a required privilege");
                        AppError::Internal("database privilege denied".into())
                    }
                    _ => AppError::Internal(format!("database error {code}")),
                }
            }
            sqlx::Error::PoolTimedOut | sqlx::Error::PoolClosed => AppError::ServiceUnavailable,
            // A coarse, fixed classification. The driver's own message can contain
            // the connection string, the failing SQL and column names, so it is
            // never interpolated — not even into the internal variant, which is
            // logged. The full error is logged once here, structurally.
            other => {
                tracing::error!(kind = %sqlx_error_kind(other), "database driver error");
                AppError::Internal(format!("database driver error: {}", sqlx_error_kind(other)))
            }
        }
    }
}

/// A fixed label per driver error variant, safe to log and to place in an internal
/// error string. Never derived from the driver's message text.
fn sqlx_error_kind(err: &sqlx::Error) -> &'static str {
    match err {
        sqlx::Error::Configuration(_) => "configuration",
        sqlx::Error::Database(_) => "database",
        sqlx::Error::Io(_) => "io",
        sqlx::Error::Tls(_) => "tls",
        sqlx::Error::Protocol(_) => "protocol",
        sqlx::Error::RowNotFound => "row_not_found",
        sqlx::Error::TypeNotFound { .. } => "type_not_found",
        sqlx::Error::ColumnIndexOutOfBounds { .. } => "column_index_out_of_bounds",
        sqlx::Error::ColumnNotFound(_) => "column_not_found",
        sqlx::Error::ColumnDecode { .. } => "column_decode",
        sqlx::Error::Encode(_) => "encode",
        sqlx::Error::Decode(_) => "decode",
        sqlx::Error::PoolTimedOut => "pool_timed_out",
        sqlx::Error::PoolClosed => "pool_closed",
        sqlx::Error::WorkerCrashed => "worker_crashed",
        sqlx::Error::Migrate(_) => "migrate",
        _ => "other",
    }
}

pub type AppResult<T> = Result<T, AppError>;

#[cfg(test)]
mod tests {
    use super::*;

    /// Every authentication failure mode must be indistinguishable on the wire.
    #[test]
    fn authentication_failure_is_undifferentiated() {
        let e = AppError::AuthenticationFailed;
        assert_eq!(e.code(), "AUTHENTICATION_FAILED");
        assert_eq!(e.status(), StatusCode::UNAUTHORIZED);
        assert!(!e.detail().contains("password"));
        assert!(!e.detail().contains("email"));
        assert!(!e.detail().contains("exist"));
    }

    #[test]
    fn internal_detail_never_contains_the_cause() {
        let e = AppError::Internal(
            "connection to postgres://user:hunter2@10.0.0.5/roleblank refused".into(),
        );
        let detail = e.detail();
        assert!(!detail.contains("postgres"));
        assert!(!detail.contains("hunter2"));
        assert!(!detail.contains("10.0.0.5"));
    }

    #[test]
    fn external_principals_get_not_found_instead_of_forbidden() {
        assert!(matches!(
            AppError::AuthorizationDenied.hide_from_external(true),
            AppError::NotFound
        ));
        assert!(matches!(
            AppError::AuthorizationDenied.hide_from_external(false),
            AppError::AuthorizationDenied
        ));
        // Root protection is never masked: the refusal must be unmistakable.
        assert!(matches!(
            AppError::RootProtected.hide_from_external(true),
            AppError::RootProtected
        ));
    }

    #[test]
    fn every_variant_has_a_stable_screaming_snake_code() {
        let samples = [
            AppError::Validation { errors: vec![] },
            AppError::BadRequest("x"),
            AppError::UnknownPermission,
            AppError::AuthenticationFailed,
            AppError::AuthorizationDenied,
            AppError::StepUpRequired {
                window_seconds: 600,
            },
            AppError::MfaRequired,
            AppError::RootProtected,
            AppError::delegation("x"),
            AppError::NotFound,
            AppError::conflict("SOME_CONFLICT", "x"),
            AppError::VersionConflict {
                expected: 1,
                actual: 2,
            },
            AppError::IdempotencyKeyReused,
            AppError::AlreadyInitialized,
            AppError::PayloadTooLarge,
            AppError::UnsupportedMediaType,
            AppError::TooManyRequests {
                retry_after_seconds: 1,
            },
            AppError::Internal("x".into()),
            AppError::ServiceUnavailable,
        ];
        for e in samples {
            let c = e.code();
            assert!(!c.is_empty());
            assert!(
                c.chars()
                    .all(|ch| ch.is_ascii_uppercase() || ch == '_' || ch.is_ascii_digit()),
                "code `{c}` is not SCREAMING_SNAKE_CASE"
            );
        }
    }
}
