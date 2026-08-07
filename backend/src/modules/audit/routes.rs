//! Audit read routes.
//!
//! # There is no create, update, delete or side-effecting export route here
//!
//! **This absence is intentional and load-bearing** (ADR-006 §1). Audit records are
//! appended only by `modules::audit::append`, inside the transaction of the change
//! they describe. A route that could append one would let a caller manufacture
//! history; one that could remove or amend one would let an administrator erase
//! their own escalation; and an "export" that marked rows as reviewed or archived
//! would be an `UPDATE` wearing a read's costume. The database refuses `UPDATE`,
//! `DELETE` and `TRUNCATE` unconditionally and the runtime role holds only
//! `SELECT, INSERT`, so this is one of four independent controls — but it is the
//! only one that a well-meaning pull request can remove by accident. Adding a
//! mutating audit route requires a new ADR, not a new handler.

use axum::extract::rejection::QueryRejection;
use axum::extract::{FromRequestParts, Path, Query, State};
use axum::http::request::Parts;
use axum::routing::get;
use axum::Router;
use serde::de::DeserializeOwned;

use crate::app::AppState;
use crate::platform::errors::{AppError, AppResult};
use crate::platform::http::extract::Authenticated;
use crate::platform::observability::sanitize;
use crate::shared::pagination::Page;

use super::dto::{AuditEventQuery, AuditEventResponse, VerifyQuery, VerifyResponse};
use super::service;

/// Query-string extraction with our error shape.
///
/// axum's own `Query` rejection is `text/plain` containing serde's message, which
/// names Rust field and type paths and echoes the rejected value back. That is
/// internal detail and a reflection gadget, and it also breaks the promise that
/// every error from this API is `application/problem+json`.
struct ValidatedQuery<T>(T);

impl<T, S> FromRequestParts<S> for ValidatedQuery<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        match Query::<T>::try_from_uri(&parts.uri) {
            Ok(Query(value)) => Ok(ValidatedQuery(value)),
            Err(rejection) => Err(map_query_rejection(rejection)),
        }
    }
}

fn map_query_rejection(rejection: QueryRejection) -> AppError {
    // Logged against the request id, never returned: the body text repeats the
    // caller's own string and names Rust types.
    tracing::debug!(
        rejection = %sanitize::log_value(rejection.body_text()),
        "rejected a query string"
    );
    AppError::BadRequest(
        "The query string contains an unrecognised or malformed parameter for this endpoint.",
    )
}

/// Mounted under `/api/v1`. Three routes, all `GET`.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/audit/events", get(list_events))
        .route("/audit/events/{id}", get(get_event))
        .route("/audit/verify", get(verify))
}

async fn list_events(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    ValidatedQuery(query): ValidatedQuery<AuditEventQuery>,
) -> AppResult<axum::Json<Page<AuditEventResponse>>> {
    Ok(axum::Json(
        service::list_events(&state, &principal, &query).await?,
    ))
}

async fn get_event(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    Path(id): Path<String>,
) -> AppResult<axum::Json<AuditEventResponse>> {
    Ok(axum::Json(
        service::get_event(&state, &principal, &id).await?,
    ))
}

/// Requires `audit.read` **and** a recent step-up, and runs over a bounded range.
/// Both requirements are enforced in the service, so a direct service call is
/// equally protected.
async fn verify(
    State(state): State<AppState>,
    Authenticated(principal): Authenticated,
    ValidatedQuery(query): ValidatedQuery<VerifyQuery>,
) -> AppResult<axum::Json<VerifyResponse>> {
    Ok(axum::Json(
        service::verify(&state, &principal, &query).await?,
    ))
}

#[cfg(test)]
mod tests {
    /// A guard against a mutating route being added here later. The router is built
    /// by this function and by nothing else, so the method set is checkable.
    #[test]
    fn the_audit_router_exposes_reads_only() {
        let source = include_str!("routes.rs");
        // The needles are assembled at run time so that this test's own source does
        // not contain the strings it forbids.
        for verb in ["post", "put", "patch", "delete"] {
            let needle = format!("{verb}(");
            assert!(
                !source.contains(&needle),
                "a mutating audit route (`{verb}`) was added; ADR-006 requires an ADR for that"
            );
        }
        assert!(
            source.contains("get("),
            "the guard is only meaningful if it can match at all"
        );
    }
}
