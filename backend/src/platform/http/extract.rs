//! Request extractors.
//!
//! The security-relevant choices here:
//!
//! * `Authenticated` **rejects** a session that has not completed MFA. It is the
//!   default extractor, so a handler that forgets to think about MFA gets the safe
//!   behaviour. Reaching an MFA-pending session requires the explicit
//!   `MfaPendingSession` extractor, which only the MFA routes use.
//! * `Json<T>` enforces the content type and produces our problem+json errors
//!   rather than axum's plain-text rejections, which would leak the serde message.
//! * A token in a query string is refused outright rather than ignored.

use axum::extract::{FromRef, FromRequest, FromRequestParts, Request};
use axum::http::{header, request::Parts, StatusCode};
use serde::de::DeserializeOwned;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::app::AppState;
use crate::modules::authentication::principal::{self, Principal};
use crate::platform::errors::AppError;
use crate::platform::observability::sanitize;

/// The effective client address, honouring proxy headers only from a trusted peer.
#[derive(Debug, Clone, Copy)]
pub struct ClientIp(pub IpAddr);

impl ClientIp {
    pub fn hint(&self) -> Option<String> {
        Some(self.0.to_string())
    }
}

impl<S> FromRequestParts<S> for ClientIp
where
    AppState: axum::extract::FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app = <AppState as FromRef<S>>::from_ref(state);

        // `ConnectInfo` is inserted by the server when the router is served with
        // `into_make_service_with_connect_info`. Absent in unit tests that call the
        // router directly, where a loopback placeholder is correct.
        let peer = parts
            .extensions
            .get::<axum::extract::ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0.ip())
            .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));

        let forwarded = parts
            .headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok());

        Ok(ClientIp(
            app.config.trusted_proxies.client_ip(peer, forwarded),
        ))
    }
}

/// Extract and validate the bearer token, returning the raw token string.
///
/// Refusing a token supplied in the query string is deliberate and returns a
/// distinct code: query strings land in access logs, browser history, `Referer`
/// headers and analytics, so a client doing this has a real leak that a silent
/// `401` would not tell them about (TH-36).
fn bearer_from(parts: &Parts) -> Result<String, AppError> {
    if let Some(query) = parts.uri.query() {
        let lowered = query.to_ascii_lowercase();
        if lowered.contains("access_token=")
            || lowered.contains("token=")
            || lowered.contains("bearer=")
            || lowered.contains("rb_at_")
        {
            return Err(AppError::BadRequest(
                "Authentication tokens must be sent in the Authorization header, never in a URL.",
            ));
        }
    }

    let raw = parts
        .headers
        .get(header::AUTHORIZATION)
        .ok_or(AppError::AuthenticationFailed)?
        .to_str()
        .map_err(|_| AppError::AuthenticationFailed)?;

    // Bound before parsing: an unbounded header is free work for an attacker.
    if raw.len() > 512 {
        return Err(AppError::AuthenticationFailed);
    }

    // The scheme is case-insensitive per RFC 7235; the token is not.
    let (scheme, token) = raw.split_once(' ').ok_or(AppError::AuthenticationFailed)?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Err(AppError::AuthenticationFailed);
    }
    let token = token.trim();
    if token.is_empty() {
        return Err(AppError::AuthenticationFailed);
    }
    Ok(token.to_string())
}

/// An authenticated principal whose session has satisfied every requirement,
/// including MFA. **This is the extractor almost every route should use.**
#[derive(Debug, Clone)]
pub struct Authenticated(pub Principal);

impl std::ops::Deref for Authenticated {
    type Target = Principal;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S> FromRequestParts<S> for Authenticated
where
    AppState: axum::extract::FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app = <AppState as FromRef<S>>::from_ref(state);
        let token = bearer_from(parts)?;
        let principal = principal::authenticate(&app.db, &token).await?;

        // The MFA gate. A password-only session belonging to a user who must use
        // MFA can reach nothing but the MFA endpoints, so there is no window in
        // which a privileged user operates without a second factor.
        if principal.session.pending_mfa {
            return Err(AppError::MfaRequired);
        }
        Ok(Authenticated(principal))
    }
}

/// A session that has authenticated with a password but not yet completed MFA.
///
/// Only the MFA endpoints use this. Its existence is what makes `Authenticated`
/// safe by default.
#[derive(Debug, Clone)]
pub struct MfaPendingSession(pub Principal);

impl std::ops::Deref for MfaPendingSession {
    type Target = Principal;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S> FromRequestParts<S> for MfaPendingSession
where
    AppState: axum::extract::FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app = <AppState as FromRef<S>>::from_ref(state);
        let token = bearer_from(parts)?;
        // Accepts both pending and completed sessions: an already-verified user
        // may still legitimately manage their factors.
        Ok(MfaPendingSession(
            principal::authenticate(&app.db, &token).await?,
        ))
    }
}

/// A sanitised `User-Agent` for the session list. Never used for authorisation.
pub struct UserAgentHint(pub Option<String>);

impl<S: Send + Sync> FromRequestParts<S> for UserAgentHint {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(UserAgentHint(sanitize::header_hint(
            parts
                .headers
                .get(header::USER_AGENT)
                .and_then(|v| v.to_str().ok()),
            200,
        )))
    }
}

/// JSON body extraction with our error shape.
///
/// axum's built-in rejection returns `text/plain` containing serde's message,
/// which names Rust field and type paths. That is internal detail, and it also
/// breaks the promise that every error is `application/problem+json`.
pub struct Json<T>(pub T);

impl<T, S> FromRequest<S> for Json<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        // Strict content type. Refusing form and multipart encodings is also what
        // keeps this API free of CSRF surface: a browser can issue a cross-site
        // form POST, but it cannot set `Content-Type: application/json` without a
        // preflight the CORS policy will refuse.
        let content_type = req
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        let base = content_type.split(';').next().unwrap_or_default().trim();
        if !base.eq_ignore_ascii_case("application/json") {
            return Err(AppError::UnsupportedMediaType);
        }

        match axum::Json::<T>::from_request(req, state).await {
            Ok(axum::Json(value)) => Ok(Json(value)),
            Err(rejection) => {
                let status = rejection.status();
                // The rejection's own message names Rust types and unknown-field
                // details; it is logged, never returned.
                tracing::debug!(
                    rejection = %sanitize::log_value(rejection.body_text()),
                    "rejected a JSON body"
                );
                Err(match status {
                    StatusCode::PAYLOAD_TOO_LARGE => AppError::PayloadTooLarge,
                    StatusCode::UNSUPPORTED_MEDIA_TYPE => AppError::UnsupportedMediaType,
                    // Includes unknown fields, which `deny_unknown_fields` turns
                    // into a rejection — the mass-assignment defence (TH-12).
                    _ => AppError::BadRequest(
                        "The request body is not valid JSON for this endpoint, or contains unrecognised fields.",
                    ),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request as HttpRequest;

    fn parts_with(header_value: Option<&str>, uri: &str) -> Parts {
        let mut builder = HttpRequest::builder().uri(uri);
        if let Some(v) = header_value {
            builder = builder.header(header::AUTHORIZATION, v);
        }
        builder.body(()).expect("request").into_parts().0
    }

    #[test]
    fn accepts_a_well_formed_bearer_header() {
        let p = parts_with(Some("Bearer rb_at_abc"), "/api/v1/x");
        assert_eq!(bearer_from(&p).unwrap(), "rb_at_abc");
    }

    #[test]
    fn the_scheme_is_case_insensitive_but_the_token_is_not() {
        for scheme in ["Bearer", "bearer", "BEARER", "BeArEr"] {
            let p = parts_with(Some(&format!("{scheme} rb_at_AbC")), "/x");
            assert_eq!(bearer_from(&p).unwrap(), "rb_at_AbC");
        }
    }

    #[test]
    fn malformed_authorization_headers_are_refused() {
        for bad in [
            "",
            " ",
            "rb_at_abc",
            "Basic dXNlcjpwYXNz",
            "Bearer",
            "Bearer ",
            "Token rb_at_abc",
            "Bearer\trb_at_abc",
        ] {
            let p = parts_with(Some(bad), "/x");
            assert!(
                matches!(bearer_from(&p), Err(AppError::AuthenticationFailed)),
                "accepted {bad:?}"
            );
        }
    }

    #[test]
    fn a_missing_authorization_header_fails_authentication() {
        let p = parts_with(None, "/x");
        assert!(matches!(
            bearer_from(&p),
            Err(AppError::AuthenticationFailed)
        ));
    }

    #[test]
    fn an_oversized_authorization_header_is_refused_before_parsing() {
        let p = parts_with(Some(&format!("Bearer {}", "a".repeat(10_000))), "/x");
        assert!(matches!(
            bearer_from(&p),
            Err(AppError::AuthenticationFailed)
        ));
    }

    /// TH-36. The refusal is distinct from a `401` so the caller learns they have
    /// a leak rather than assuming a bad token.
    #[test]
    fn a_token_in_the_query_string_is_refused_distinctly() {
        for uri in [
            "/api/v1/projects?access_token=rb_at_abc",
            "/api/v1/projects?token=rb_at_abc",
            "/api/v1/projects?bearer=x",
            "/api/v1/projects?foo=1&ACCESS_TOKEN=x",
            "/api/v1/projects?q=rb_at_leaked",
        ] {
            let p = parts_with(Some("Bearer rb_at_abc"), uri);
            assert!(
                matches!(bearer_from(&p), Err(AppError::BadRequest(_))),
                "query-string token not refused for {uri}"
            );
        }
    }

    #[test]
    fn ordinary_query_strings_are_unaffected() {
        let p = parts_with(
            Some("Bearer rb_at_abc"),
            "/api/v1/projects?limit=25&sort=name",
        );
        assert!(bearer_from(&p).is_ok());
    }
}
