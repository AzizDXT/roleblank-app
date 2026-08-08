//! §11 — log injection.
//!
//! The threat is not "a log line looks odd". It is that a user chooses what a log
//! *record* says: forging a severity, forging a whole line, breaking the JSON
//! envelope so a downstream parser mis-attributes the fields, or smuggling a bearer
//! token into a place operators paste into tickets.
//!
//! Three independent bodies of evidence, because no single one is sufficient:
//!
//!   1. **The sanitiser itself**, over the whole payload corpus. This is the
//!      function every user-controlled value passes through on its way to a log
//!      line, so a property proven here holds at every call site.
//!   2. **The persisted hints.** `sessions.user_agent_hint`,
//!      `audit_events.request_id` and `audit_events.source_ip_hint` are the parts
//!      of the log trail that survive in the database, and they are written from
//!      caller-controlled headers. They are readable, so they are assertable — a
//!      control character in any of them is a forged log record that outlived the
//!      request.
//!   3. **The echoed correlation id.** A caller-supplied `X-Request-Id` is echoed
//!      into a response header *and* into every log line for that request. If a
//!      hostile one were adopted, the response header would show it.
//!
//! The fourth body of evidence — the actual stdout of a running instance — cannot
//! be captured from inside the test process, because `tracing-subscriber` is not
//! linked into the test binary and cargo captures the harness's own stdout. It is
//! captured separately against a live container and recorded in
//! `docs/backend/audit/SECTION_9_13_FINDINGS.md` §11.

use axum::http::{header, Method, StatusCode};
use serde_json::json;

use crate::world::{self, World};
use roleblank_backend::platform::observability::sanitize;

/// Characters that let a value escape its record: the C0 and C1 control ranges,
/// plus the two Unicode separators some log viewers honour as line breaks.
fn is_line_breaking(ch: char) -> bool {
    ch.is_control() || ch == '\u{2028}' || ch == '\u{2029}'
}

#[track_caller]
fn assert_cannot_forge_a_record(context: &str, value: &str) {
    assert!(
        !value.chars().any(is_line_breaking),
        "{context} retained a control character, so a log line can be forged: {value:?}"
    );
    // A JSON formatter escapes a quote, but a text formatter does not, and the
    // sanitised value is written by both. A bare quote plus a comma is enough to
    // graft a field onto a record a human is reading.
    assert!(
        !value.contains("\u{1b}"),
        "{context} retained an ANSI escape: {value:?}"
    );
}

/// The corpus, through the function every logged value passes through.
#[test]
fn the_sanitiser_defeats_every_payload_in_the_corpus() {
    for (name, payload) in world::log_injection_payloads() {
        let out = sanitize::log_value(&payload);
        assert_cannot_forge_a_record(name, &out);

        // Bounded: a 20 KB display name must not become a 20 KB log line. The bound
        // is inclusive of the truncation marker — see finding H-2.
        assert!(
            out.chars().count() <= sanitize::MAX_LOGGED_LEN,
            "{name} produced {} characters, above the {} bound",
            out.chars().count(),
            sanitize::MAX_LOGGED_LEN
        );
        // Truncation is by character, so the result is always valid UTF-8 and a
        // multi-byte sequence is never cut in half.
        assert!(std::str::from_utf8(out.as_bytes()).is_ok());
    }
}

/// A forged severity must not survive, whichever formatter is in use.
#[test]
fn a_forged_severity_cannot_reach_a_log_record() {
    for forged in [
        "x\n2024-01-01T00:00:00Z ERROR roleblank_backend: the chain is broken",
        "x\r\n{\"level\":\"CRITICAL\",\"message\":\"owner deleted\"}",
        "x\u{2028}FATAL: shutting down",
        "x\u{85}WARN: forged",
    ] {
        let out = sanitize::log_value(forged);
        assert_cannot_forge_a_record("forged severity", &out);
        // The words survive as text — that is fine and is the point. What must not
        // survive is the *separator* that would make them their own record.
        assert_eq!(
            out.lines().count(),
            1,
            "the sanitised value spans more than one line: {out:?}"
        );
    }
}

/// A hostile `User-Agent` is stored as a session hint. It must arrive sanitised and
/// bounded, because that column is read back into operator-facing views.
#[tokio::test]
async fn a_hostile_user_agent_cannot_forge_a_session_hint() {
    let w = World::build().await;

    for (name, payload) in world::log_injection_payloads() {
        // A header value cannot itself carry a raw newline — hyper refuses to build
        // one — so the transport already blocks the crudest form. What can arrive is
        // everything else in the corpus, plus the escaped and percent-encoded
        // spellings a proxy might decode.
        let Ok(header_value) = header::HeaderValue::from_str(&payload) else {
            continue;
        };
        world::reset_auth_limits(&w.app).await;

        let request = world::raw_request(
            Method::POST,
            "/api/v1/auth/login",
            None,
            Some("application/json"),
            &[],
            serde_json::to_vec(&json!({
                "email": w.employee.email,
                "password": crate::common::TEST_PASSWORD
            }))
            .expect("serialise"),
        );
        let mut request = request;
        request
            .headers_mut()
            .insert(header::USER_AGENT, header_value);
        let response = w.app.request(request).await;
        response.assert_status(StatusCode::OK);

        let hints: Vec<(Option<String>,)> =
            sqlx::query_as("SELECT user_agent_hint FROM sessions ORDER BY created_at DESC LIMIT 1")
                .fetch_all(&w.app.db)
                .await
                .expect("read the session hint");
        for (hint,) in hints {
            let Some(hint) = hint else { continue };
            assert_cannot_forge_a_record(&format!("user_agent_hint from {name}"), &hint);
            assert!(
                hint.chars().count() <= 200,
                "{name} produced a {}-character hint, above the column's own \
                 CHECK (length(user_agent_hint) <= 200)",
                hint.chars().count()
            );
        }
    }
}

/// Regression test for finding H-2.
///
/// `sanitize_bounded` appended its truncation marker *after* taking `max_chars`
/// characters, so a `User-Agent` longer than 200 characters produced a
/// 201-character hint, violated `CHECK (length(user_agent_hint) <= 200)` in
/// `migrations/0002_sessions_and_mfa.sql`, raised SQLSTATE 23514 — which nothing
/// maps — and turned an ordinary login into a `500`. Many real browser and mobile
/// agent strings are longer than 200 characters, so this was a live outage for
/// those clients rather than only an attack.
///
/// The boundary is walked from both sides deliberately: a fix that simply widened
/// the column would pass a test that only probed one length.
#[tokio::test]
async fn a_long_user_agent_does_not_break_login() {
    let w = World::build().await;

    for length in [1usize, 199, 200, 201, 500, 8_000] {
        world::reset_auth_limits(&w.app).await;
        let mut request = world::raw_request(
            Method::POST,
            "/api/v1/auth/login",
            None,
            Some("application/json"),
            &[],
            serde_json::to_vec(&json!({
                "email": w.employee.email,
                "password": crate::common::TEST_PASSWORD
            }))
            .expect("serialise"),
        );
        request.headers_mut().insert(
            header::USER_AGENT,
            header::HeaderValue::from_str(&"u".repeat(length)).expect("an ASCII header"),
        );
        let response = w.app.request(request).await;
        assert_eq!(
            response.status,
            StatusCode::OK,
            "a {length}-character User-Agent broke login: {}",
            String::from_utf8_lossy(&response.raw)
        );
    }

    let hints: Vec<(Option<String>,)> = sqlx::query_as("SELECT user_agent_hint FROM sessions")
        .fetch_all(&w.app.db)
        .await
        .expect("read the session hints");
    for (hint,) in hints {
        let Some(hint) = hint else { continue };
        assert!(
            hint.chars().count() <= 200,
            "a {}-character hint was stored",
            hint.chars().count()
        );
    }
}

/// A caller-supplied correlation id is accepted only if it cannot poison a line.
///
/// The echoed response header is the observable: whatever id the server adopted is
/// the id every log line for that request carries.
#[tokio::test]
async fn a_hostile_request_id_is_never_adopted() {
    let w = World::build().await;

    for (name, payload) in world::log_injection_payloads() {
        let Ok(value) = header::HeaderValue::from_str(&payload) else {
            continue;
        };
        let mut request = world::raw_request(
            Method::GET,
            "/api/v1/system/info",
            w.root.bearer(),
            None,
            &[],
            Vec::new(),
        );
        request.headers_mut().insert("x-request-id", value);
        let response = w.app.request(request).await;

        let echoed = response
            .headers
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert!(
            !echoed.is_empty(),
            "{name}: no correlation id was established at all"
        );
        assert_ne!(
            echoed, payload,
            "{name}: the hostile correlation id was adopted verbatim"
        );
        assert!(
            echoed.len() >= 8
                && echoed.len() <= 64
                && echoed
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "{name}: adopted the id `{echoed}`, which is outside the accepted alphabet"
        );
    }

    // A well-formed id is still honoured — the control that proves the rejections
    // above are about the payload and not about the header being ignored.
    let mut request = world::raw_request(
        Method::GET,
        "/api/v1/system/info",
        w.root.bearer(),
        None,
        &[],
        Vec::new(),
    );
    request
        .headers_mut()
        .insert("x-request-id", header::HeaderValue::from_static("abc12345"));
    let response = w.app.request(request).await;
    assert_eq!(
        response
            .headers
            .get("x-request-id")
            .and_then(|v| v.to_str().ok()),
        Some("abc12345")
    );
}

/// Every correlation id and address hint that reached the audit trail is clean.
///
/// The audit table is the durable half of the log trail: an operator reading it
/// must not be reading a line the subject wrote.
#[tokio::test]
async fn no_persisted_audit_field_can_carry_a_forged_record() {
    let w = World::build().await;

    // Generate traffic with hostile headers and hostile bodies, so that whatever
    // the audit writer chooses to record has had a hostile value available to it.
    for (_, payload) in world::log_injection_payloads() {
        world::reset_auth_limits(&w.app).await;
        let mut request = world::raw_request(
            Method::POST,
            "/api/v1/auth/login",
            None,
            Some("application/json"),
            &[],
            serde_json::to_vec(&json!({"email": payload, "password": payload})).expect("serialise"),
        );
        if let Ok(v) = header::HeaderValue::from_str(&payload) {
            request.headers_mut().insert("x-request-id", v.clone());
            request.headers_mut().insert("x-forwarded-for", v.clone());
            request.headers_mut().insert(header::USER_AGENT, v);
        }
        let _ = w.app.request(request).await;
    }

    // A display name is user-chosen and lands in an audit metadata field on more
    // than one path.
    for (_, payload) in world::log_injection_payloads() {
        world::reset_auth_limits(&w.app).await;
        let _ = w
            .app
            .post(
                "/api/v1/invitations",
                w.root.bearer(),
                json!({
                    "email": "logprobe@hardening.test",
                    "display_name": payload,
                    "principal_type": "INTERNAL"
                }),
            )
            .await;
    }

    let rows: Vec<(Option<String>, Option<String>, String)> = sqlx::query_as(
        "SELECT request_id, source_ip_hint, metadata::text FROM audit_events ORDER BY seq",
    )
    .fetch_all(&w.app.db)
    .await
    .expect("read the audit trail");
    assert!(!rows.is_empty(), "no audit events were written at all");

    for (request_id, source_ip, metadata) in rows {
        if let Some(id) = &request_id {
            assert_cannot_forge_a_record("audit_events.request_id", id);
            assert!(
                id.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
                "audit_events.request_id holds `{id}`, outside the accepted alphabet"
            );
        }
        if let Some(ip) = &source_ip {
            assert_cannot_forge_a_record("audit_events.source_ip_hint", ip);
            assert!(
                ip.parse::<std::net::IpAddr>().is_ok(),
                "audit_events.source_ip_hint holds `{ip}`, which is not an address"
            );
        }
        // `metadata::text` is the serialised JSON. A raw control character inside it
        // would mean the builder let one through; the escaped spelling `\n` is what
        // a correctly serialised newline looks like and is not a break.
        assert_cannot_forge_a_record("audit_events.metadata", &metadata);
    }
}

/// No credential material may reach the durable log trail, however it was supplied.
///
/// The probes put a password, a bearer-shaped string and a *genuine live access
/// token* into the password field — the field an audit writer has every reason to
/// touch and no reason to record. A token pasted into the wrong box is the ordinary
/// way this goes wrong in production.
#[tokio::test]
async fn no_bearer_or_password_material_reaches_the_audit_trail() {
    let w = World::build().await;
    let smuggled_token = "rb_at_deadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    let smuggled_password = "the-actual-password-nobody-should-log";

    for secret in [
        smuggled_password,
        smuggled_token,
        w.root.token.as_str(),
        crate::common::TEST_PASSWORD,
    ] {
        world::reset_auth_limits(&w.app).await;
        let _ = w
            .app
            .post(
                "/api/v1/auth/login",
                None,
                json!({"email": w.employee.email, "password": secret}),
            )
            .await;
    }

    // And a password change, which sees both the old and the new secret.
    let _ = w
        .app
        .post(
            "/api/v1/auth/password/change",
            w.root.bearer(),
            json!({"current_password": smuggled_password, "new_password": smuggled_password}),
        )
        .await;

    // The real access token of a live session must not be anywhere either.
    let trail: Vec<(String,)> = sqlx::query_as(
        "SELECT coalesce(request_id, '') || ' ' || coalesce(source_ip_hint, '') || ' '
                || metadata::text || ' ' || action_code || ' ' || outcome
           FROM audit_events",
    )
    .fetch_all(&w.app.db)
    .await
    .expect("read the audit trail");

    for (line,) in trail {
        assert!(
            !line.contains(smuggled_password),
            "a password reached the audit trail: {line}"
        );
        assert!(
            !line.contains(smuggled_token),
            "a bearer-shaped string reached the audit trail: {line}"
        );
        assert!(
            !line.contains(&w.root.token),
            "a live access token reached the audit trail: {line}"
        );
    }

    // What the trail *does* record is the address the caller typed, under
    // `attempted_email`, and that is deliberate — "somebody tried to log in as X"
    // is the whole value of a failed-login record. It means a caller can put an
    // arbitrary string of their own choosing into the trail, so the property that
    // matters is that the string is sanitised and bounded, not that it is absent.
    // `no_persisted_audit_field_can_carry_a_forged_record` is what holds that.
    let attempted: Vec<(Option<String>,)> = sqlx::query_as(
        "SELECT metadata->>'attempted_email' FROM audit_events
          WHERE action_code = 'AUTH.LOGIN_FAILED'",
    )
    .fetch_all(&w.app.db)
    .await
    .expect("read the failed-login records");
    assert!(
        attempted.iter().any(|(v,)| v.is_some()),
        "no failed login recorded the address that was attempted"
    );
    for (value,) in attempted {
        let Some(value) = value else { continue };
        assert_cannot_forge_a_record("attempted_email", &value);
        assert!(
            value.chars().count() <= 201,
            "an attempted address of {} characters was recorded verbatim",
            value.chars().count()
        );
    }
}

/// A hostile value must not come back out in the response either — a reflection is
/// a log-injection vector against whatever the *client* logs.
#[tokio::test]
async fn hostile_input_is_never_reflected_in_a_response() {
    let w = World::build().await;

    for (name, payload) in world::log_injection_payloads() {
        world::reset_auth_limits(&w.app).await;

        // Body field, query parameter and path segment, which are the three places
        // a value can arrive and be echoed by a naive error message.
        let responses = vec![
            w.app
                .post(
                    "/api/v1/auth/login",
                    None,
                    json!({"email": payload, "password": "x"}),
                )
                .await,
            w.app
                .get(
                    &format!(
                        "/api/v1/users?search={}",
                        urlencode(&payload.chars().take(200).collect::<String>())
                    ),
                    w.root.bearer(),
                )
                .await,
            w.app
                .get(
                    &format!(
                        "/api/v1/departments/{}",
                        urlencode(&payload.chars().take(200).collect::<String>())
                    ),
                    w.root.bearer(),
                )
                .await,
        ];

        for response in responses {
            let text = String::from_utf8_lossy(&response.raw);
            // Only distinctive payloads are meaningful to search for; a single
            // control character occurs incidentally in an escaped JSON document.
            let distinctive: String = payload
                .chars()
                .filter(|c| !c.is_control())
                .take(40)
                .collect();
            if distinctive.len() > 12 {
                assert!(
                    !text.contains(&distinctive),
                    "{name}: the response reflected the payload: {text}"
                );
            }
            assert!(
                !text.contains("\r\n\r\n"),
                "{name}: the response body contains a record break: {text}"
            );
        }
    }
}

/// Percent-encode a value so it survives being placed in a URL.
fn urlencode(value: &str) -> String {
    let mut out = String::with_capacity(value.len() * 3);
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}
