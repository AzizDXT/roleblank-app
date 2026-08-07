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
//! * `PathId`, `PathIds` and `PathKey` replace `Path<Uuid>` for the same reason
//!   `Json<T>` replaces `axum::Json<T>` — see their own documentation below.

use axum::extract::{FromRef, FromRequest, FromRequestParts, Path, Request};
use axum::http::{header, request::Parts, StatusCode};
use serde::de::DeserializeOwned;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use uuid::Uuid;

use crate::app::AppState;
use crate::modules::authentication::principal::{self, Principal};
use crate::modules::settings::validate_key;
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

// ---------------------------------------------------------------------------
// Path parameters
// ---------------------------------------------------------------------------
//
// # Why these exist instead of `Path<Uuid>`
//
// `axum::extract::Path<Uuid>` looks like the obvious choice and is the wrong one.
// Its rejection body for `GET /api/v1/departments/not-a-uuid` is:
//
// ```text
// 400 Content-Type: text/plain; charset=utf-8
// Invalid URL: Cannot parse `id` with value `not-a-uuid`: UUID parsing failed…
// ```
//
// That breaks three separate promises this codebase makes:
//
// 1. **It is not `application/problem+json`.** `docs/backend/07-api-contract.md`
//    §1 and §2 say every error carries a stable machine-readable `code`. A client
//    branching on `code` — the only thing `platform::errors` guarantees is stable —
//    receives plain text with nothing to branch on, so its error handling falls
//    through to whatever it does for an unrecognised response.
// 2. **It reflects attacker-controlled input.** The rejected segment is echoed
//    verbatim into the body. Every other refusal in this codebase deliberately
//    refuses to do that: `shared::pagination` names the *allowed* sort fields and
//    never the rejected one, and `FieldError::message` documents that echoing the
//    value is how a validation error becomes a reflection gadget and a
//    log-injection vector.
// 3. **It names the Rust field.** `` `id` `` is an internal binding, and
//    `platform::errors` is explicit that `detail` never carries an internal fact.
//
// `authorization::routes` and `audit::routes` already sidestep this by taking
// `Path<String>` and parsing by hand. These extractors are that same treatment,
// factored out so a new route gets it by default rather than by remembering to.
//
// **Do not "simplify" these back to `Path<Uuid>`.** The type would be tidier and
// the contract would silently break again.

/// The message returned for every malformed identifier, whichever position it was
/// in. It is deliberately constant: a message that varied with the input would be
/// a channel back to the caller, and the caller already knows what they sent.
const INVALID_UUID_MESSAGE: &str = "Path identifier is not a valid UUID.";

/// Parse one path segment as a UUID, or fail with a problem+json validation error
/// that says nothing about the value.
///
/// `Uuid::parse_str` is exactly what `Path<Uuid>` used to reach through serde, so
/// which inputs are *accepted* is unchanged — including the unhyphenated and
/// braced forms. Only the shape of the refusal differs. In particular the segment
/// is **not** trimmed: accepting `" <uuid> "` where axum refused it would be a new
/// acceptance, and this change is meant to alter errors, not behaviour.
fn parse_path_uuid(field: &'static str, raw: &str) -> Result<Uuid, AppError> {
    Uuid::parse_str(raw).map_err(|_| AppError::field(field, "INVALID_UUID", INVALID_UUID_MESSAGE))
}

/// A single UUID path parameter, e.g. `/departments/{id}`.
///
/// See the module section above for why this is not `Path<Uuid>`.
#[derive(Debug, Clone, Copy)]
pub struct PathId(pub Uuid);

impl<S: Send + Sync> FromRequestParts<S> for PathId {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // A `Path<String>` rejection here means the segment was not valid UTF-8
        // after percent-decoding. That is still "the caller sent something that is
        // not a UUID", so it takes the same answer rather than a distinct one that
        // would tell a prober which of the two checks they tripped.
        let Path(raw) = Path::<String>::from_request_parts(parts, state)
            .await
            .map_err(|_| AppError::field("id", "INVALID_UUID", INVALID_UUID_MESSAGE))?;
        Ok(PathId(parse_path_uuid("id", &raw)?))
    }
}

/// Two UUID path parameters, e.g. `/departments/{id}/members/{user_id}`.
///
/// See the module section above for why this is not `Path<(Uuid, Uuid)>`.
///
/// The reported fields are the positional names `id` and `sub_id` rather than the
/// route's own parameter names. One extractor serves routes whose second segment
/// is `user_id` on departments, clients and tasks but `client_account_id` on
/// projects, so a name taken from any one of them would be wrong on the others —
/// and `platform::errors` is clear that machine clients branch on `code`, which is
/// identical in both positions, never on prose or on a field label.
#[derive(Debug, Clone, Copy)]
pub struct PathIds(pub Uuid, pub Uuid);

impl<S: Send + Sync> FromRequestParts<S> for PathIds {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let Path((first, second)) = Path::<(String, String)>::from_request_parts(parts, state)
            .await
            .map_err(|_| AppError::field("id", "INVALID_UUID", INVALID_UUID_MESSAGE))?;
        Ok(PathIds(
            parse_path_uuid("id", &first)?,
            parse_path_uuid("sub_id", &second)?,
        ))
    }
}

/// A settings or feature-flag key path parameter, e.g. `/settings/{key}`.
///
/// Validation is delegated to `settings::validate_key`, which enforces the same
/// grammar as the `CHECK (key ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$')` in
/// `migrations/0006_platform.sql`, bounded in length. Sharing that one function is
/// the point: a second copy of the grammar would drift, and the looser copy is the
/// one that gets found.
///
/// A key that fails the grammar is a **validation error**, not a `404`. The
/// distinction matters — a `404` would be an answer about whether a key exists,
/// produced by a lookup that never ran, so it would be a lie in whichever
/// direction the real answer went.
#[derive(Debug, Clone)]
pub struct PathKey(pub String);

impl<S: Send + Sync> FromRequestParts<S> for PathKey {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // A non-UTF-8 segment cannot satisfy the lowercase-ASCII grammar, so it
        // takes the grammar's own refusal rather than a separate one.
        let Path(raw) = Path::<String>::from_request_parts(parts, state)
            .await
            .map_err(|_| {
                AppError::field(
                    "key",
                    "INVALID_FORMAT",
                    "A key is dot-separated lowercase segments, e.g. `registration.mode`.",
                )
            })?;
        Ok(PathKey(validate_key("key", &raw)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request as HttpRequest;
    use axum::response::IntoResponse;

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

    // -- path parameters ---------------------------------------------------

    /// Inputs that a `Path<Uuid>` route must refuse. Each is also a value that
    /// must not come back out in the response.
    fn malformed_uuids() -> Vec<String> {
        vec![
            "not-a-uuid".to_string(),
            String::new(),
            " ".to_string(),
            "1".to_string(),
            // Unbounded input: parsing must not be the thing that bounds it.
            "a".repeat(10_000),
            "../../etc/passwd".to_string(),
            "' OR 1=1--".to_string(),
            "'; DROP TABLE departments; --".to_string(),
            "<script>alert(1)</script>".to_string(),
            // A trailing character on an otherwise valid UUID: the near-miss that a
            // lenient parser would accept and then look up as something else.
            format!("{}x", Uuid::now_v7()),
        ]
    }

    #[test]
    fn a_well_formed_uuid_parses_unchanged() {
        let id = Uuid::now_v7();
        assert_eq!(parse_path_uuid("id", &id.to_string()).unwrap(), id);
        // The unhyphenated form is what `Path<Uuid>` accepted through serde, so it
        // still must: this change is about the refusal, not about acceptance.
        assert_eq!(parse_path_uuid("id", &id.simple().to_string()).unwrap(), id);
    }

    /// Surrounding whitespace was refused by `Path<Uuid>` and must still be.
    /// Trimming here would quietly widen what the API accepts.
    #[test]
    fn a_padded_uuid_is_still_refused() {
        let padded = format!(" {} ", Uuid::now_v7());
        assert!(parse_path_uuid("id", &padded).is_err());
    }

    #[test]
    fn every_malformed_identifier_is_a_validation_error_with_a_stable_code() {
        for bad in malformed_uuids() {
            let err = parse_path_uuid("id", &bad).expect_err("accepted a malformed identifier");
            assert_eq!(err.status(), StatusCode::BAD_REQUEST);
            assert_eq!(err.code(), "VALIDATION_FAILED");
            let AppError::Validation { errors } = &err else {
                panic!("not a validation error for {:.32}", bad);
            };
            assert_eq!(errors.len(), 1);
            assert_eq!(errors[0].field, "id");
            assert_eq!(errors[0].code, "INVALID_UUID");
        }
    }

    /// The second position reports the same `code`, which is the part of the
    /// contract a client branches on.
    #[test]
    fn the_second_identifier_position_uses_the_same_code() {
        let err = parse_path_uuid("sub_id", "not-a-uuid").expect_err("accepted");
        let AppError::Validation { errors } = &err else {
            panic!("not a validation error");
        };
        assert_eq!(errors[0].field, "sub_id");
        assert_eq!(errors[0].code, "INVALID_UUID");
    }

    async fn rendered_body(err: AppError) -> (String, String) {
        let response = err.into_response();
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("read body");
        (content_type, String::from_utf8_lossy(&bytes).into_owned())
    }

    /// The heart of the fix. axum's own rejection echoed the rejected segment and
    /// the Rust field name back in `text/plain`; neither may survive.
    #[tokio::test]
    async fn a_rejected_identifier_never_appears_in_the_problem_body() {
        for bad in malformed_uuids() {
            let err = parse_path_uuid("id", &bad).expect_err("accepted");
            let (content_type, body) = rendered_body(err).await;

            assert!(
                content_type.starts_with("application/problem+json"),
                "rendered as `{content_type}`, not problem+json"
            );
            assert!(
                body.contains("\"INVALID_UUID\""),
                "no stable code in {body}"
            );

            // Short inputs like "1" occur incidentally in a JSON document, so only
            // the distinctive ones are meaningful to search for.
            if bad.len() > 3 {
                assert!(
                    !body.contains(&bad),
                    "the rejected value was reflected in {body}"
                );
            }
            // axum's message quoted the Rust binding and named UUID parsing
            // internals. Neither is the client's business.
            assert!(!body.contains("Cannot parse"), "leaked axum's wording");
            assert!(!body.to_lowercase().contains("invalid url"));
        }
    }

    #[test]
    fn a_well_formed_key_passes_through_unchanged() {
        for good in ["registration", "registration.mode", "a1_b.c2_d"] {
            assert_eq!(validate_key("key", good).expect("valid key"), good);
        }
    }

    #[test]
    fn malformed_keys_are_validation_errors_rather_than_a_lookup() {
        for bad in [
            "",
            "Registration.Mode",
            "1registration",
            "registration..mode",
            "registration.mode; DROP TABLE settings",
            "../../etc/passwd",
        ] {
            let err = validate_key("key", bad).expect_err("accepted a malformed key");
            assert_eq!(err.status(), StatusCode::BAD_REQUEST);
            assert_eq!(err.code(), "VALIDATION_FAILED");
        }
        // Bounded length, so an oversized segment is refused before it becomes an
        // indexed lookup on a multi-megabyte string.
        assert!(validate_key("key", &"a".repeat(10_000)).is_err());
    }

    #[tokio::test]
    async fn a_rejected_key_never_appears_in_the_problem_body() {
        for bad in [
            "Registration.Mode",
            "../../etc/passwd",
            "registration.mode; DROP TABLE settings",
        ] {
            let err = validate_key("key", bad).expect_err("accepted");
            let (content_type, body) = rendered_body(err).await;
            assert!(content_type.starts_with("application/problem+json"));
            assert!(
                !body.contains(bad),
                "the rejected key was reflected in {body}"
            );
        }
    }
}
