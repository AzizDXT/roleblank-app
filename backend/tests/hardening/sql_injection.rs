//! §13 — SQL injection.
//!
//! "sqlx uses parameters" is not evidence. Forty-eight production queries in this
//! backend assemble their text with `format!` and pass it through
//! `sqlx::AssertSqlSafe`; the audit of what each one interpolates is in
//! `docs/backend/audit/SECTION_9_13_FINDINGS.md` §13. This file is the behavioural
//! half of that audit.
//!
//! The assertions are arranged so that a pass means something specific:
//!
//!   * a **whole-database snapshot** is taken before and after every sweep, so a
//!     statement that ran and was then rolled back into a different shape would
//!     show up as a row count that moved. The set of *tables* is part of the
//!     snapshot, so a successful `DROP TABLE` fails the comparison rather than
//!     making it vacuous;
//!   * the payloads that reach a `LIKE`-shaped surface include the wildcard
//!     metacharacters, because a bound parameter can still be a *pattern* injection
//!     even when it cannot be a syntax injection;
//!   * every refusal is checked for **reflection**, because a rejected value that
//!     comes back out is the second half of most real exploits;
//!   * the time-based payloads are timed, because a blind injection succeeds
//!     silently and the clock is the only witness.

use std::time::{Duration, Instant};

use axum::http::StatusCode;
use serde_json::json;
use uuid::Uuid;

use crate::world::{self, World};

/// A payload that reached `pg_sleep` would take at least ten seconds. Anything
/// under this is proof the argument was never executed as SQL.
const BLIND_INJECTION_CEILING: Duration = Duration::from_secs(5);

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

/// The rejected value must never come back out, and neither must anything that
/// would tell the caller what the query looked like.
#[track_caller]
fn assert_no_reflection_or_disclosure(context: &str, payload: &str, body: &[u8]) {
    let text = String::from_utf8_lossy(body);
    // Short payloads (`%`, `_`, `*`, `\`) occur incidentally inside a JSON
    // document, so only distinctive ones are meaningful to search for.
    if payload.len() > 6 {
        assert!(
            !text.contains(payload),
            "{context}: the rejected value was reflected: {text}"
        );
    }
    for disclosure in [
        "syntax error",
        "sqlstate",
        "SELECT",
        "FROM ",
        "pg_",
        "relation",
        "column ",
        "unterminated",
        "AssertSqlSafe",
    ] {
        assert!(
            !text.to_lowercase().contains(&disclosure.to_lowercase()),
            "{context}: the response disclosed `{disclosure}`: {text}"
        );
    }
}

/// Every query-string surface, on every listing endpoint, with the whole corpus.
#[tokio::test]
async fn no_query_parameter_can_alter_a_statement() {
    let w = World::build().await;
    let before = world::snapshot(&w.app).await;
    let root = w.root.bearer();

    // `(endpoint, parameter)` pairs covering each of the three query extractors and
    // each kind of parameter: free-text search, an enum filter, a UUID filter, the
    // sort column, the sort direction and the cursor.
    let surfaces: Vec<(&str, &str)> = vec![
        ("/api/v1/users", "search"),
        ("/api/v1/users", "status"),
        ("/api/v1/users", "principal_type"),
        ("/api/v1/users", "sort"),
        ("/api/v1/users", "direction"),
        ("/api/v1/users", "cursor"),
        ("/api/v1/users", "limit"),
        ("/api/v1/projects", "status"),
        ("/api/v1/projects", "department_id"),
        ("/api/v1/projects", "sort"),
        ("/api/v1/projects", "direction"),
        ("/api/v1/projects", "cursor"),
        ("/api/v1/tasks", "project_id"),
        ("/api/v1/tasks", "status"),
        ("/api/v1/tasks", "sort"),
        ("/api/v1/tasks", "direction"),
        ("/api/v1/tasks", "cursor"),
        ("/api/v1/departments", "sort"),
        ("/api/v1/departments", "direction"),
        ("/api/v1/departments", "cursor"),
        ("/api/v1/clients", "sort"),
        ("/api/v1/clients", "cursor"),
        ("/api/v1/roles", "sort"),
        ("/api/v1/roles", "direction"),
        ("/api/v1/roles", "cursor"),
        ("/api/v1/invitations", "status"),
        ("/api/v1/invitations", "sort"),
        ("/api/v1/audit/events", "actor_user_id"),
        ("/api/v1/audit/events", "action_code"),
        ("/api/v1/audit/events", "target_type"),
        ("/api/v1/audit/events", "target_id"),
        ("/api/v1/audit/events", "outcome"),
        ("/api/v1/audit/events", "occurred_from"),
        ("/api/v1/audit/events", "occurred_to"),
        ("/api/v1/audit/events", "sort"),
        ("/api/v1/audit/events", "direction"),
        ("/api/v1/audit/verify", "from_seq"),
    ];

    let payloads = world::sql_injection_payloads();
    let mut probes = 0usize;

    for (path, parameter) in &surfaces {
        for payload in &payloads {
            let started = Instant::now();
            let response = w
                .app
                .get(&format!("{path}?{parameter}={}", urlencode(payload)), root)
                .await;
            let elapsed = started.elapsed();
            probes += 1;

            // Either the value is refused, or it is treated as an ordinary literal
            // and the listing succeeds with nothing unusual in it. Both are correct;
            // a 500 is not, because it would mean the statement reached PostgreSQL
            // in a shape the driver could not handle.
            assert!(
                response.status.is_success() || response.status == StatusCode::BAD_REQUEST,
                "{path}?{parameter}={payload:?} produced {}: {}",
                response.status,
                String::from_utf8_lossy(&response.raw)
            );
            assert!(
                elapsed < BLIND_INJECTION_CEILING,
                "{path}?{parameter}={payload:?} took {elapsed:?} — a time-based \
                 injection would look exactly like this"
            );
            assert_no_reflection_or_disclosure(
                &format!("{path}?{parameter}"),
                payload,
                &response.raw,
            );
            world::assert_body_is_clean(&format!("{path}?{parameter}"), &response.raw, None);
        }
    }

    assert!(
        probes > 900,
        "the query sweep only ran {probes} probes; the surface list has shrunk"
    );
    assert_eq!(
        before,
        world::snapshot(&w.app).await,
        "the database changed shape or size during the query-parameter sweep"
    );
}

/// Every path segment, on every parameterised route.
#[tokio::test]
async fn no_path_segment_can_alter_a_statement() {
    let w = World::build().await;
    let before = world::snapshot(&w.app).await;
    let root = w.root.bearer();

    let templates = [
        "/api/v1/users/{}",
        "/api/v1/users/{}/roles",
        "/api/v1/users/{}/permissions",
        "/api/v1/users/{}/permission-overrides",
        "/api/v1/roles/{}",
        "/api/v1/departments/{}",
        "/api/v1/departments/{}/members",
        "/api/v1/clients/{}",
        "/api/v1/clients/{}/members",
        "/api/v1/projects/{}",
        "/api/v1/projects/{}/members",
        "/api/v1/projects/{}/tasks",
        "/api/v1/projects/{}/clients",
        "/api/v1/tasks/{}",
        "/api/v1/tasks/{}/assignees",
        "/api/v1/audit/events/{}",
        "/api/v1/client-portal/projects/{}",
        "/api/v1/client-portal/tasks/{}",
        "/api/v1/settings/{}",
        "/api/v1/feature-flags/{}",
        "/api/v1/auth/sessions/{}",
    ];

    for template in templates {
        for payload in world::sql_injection_payloads() {
            let path = template.replace("{}", &urlencode(payload));
            let response = w.app.get(&path, root).await;
            assert!(
                response.status.is_client_error(),
                "{template} with {payload:?} produced {}: {}",
                response.status,
                String::from_utf8_lossy(&response.raw)
            );
            assert_no_reflection_or_disclosure(template, payload, &response.raw);
        }
    }

    assert_eq!(
        before,
        world::snapshot(&w.app).await,
        "the database changed during the path-segment sweep"
    );
}

/// Every text field of every write body.
#[tokio::test]
async fn no_body_field_can_alter_a_statement() {
    let w = World::build().await;
    let before = world::snapshot(&w.app).await;
    let root = w.root.bearer();

    for payload in world::sql_injection_payloads() {
        let bodies: Vec<(&str, serde_json::Value)> = vec![
            (
                "/api/v1/auth/login",
                json!({"email": payload, "password": payload}),
            ),
            (
                "/api/v1/auth/password-reset/request",
                json!({"email": payload}),
            ),
            (
                "/api/v1/auth/password-reset/confirm",
                json!({"token": payload, "new_password": "correct horse battery 99"}),
            ),
            (
                "/api/v1/invitations/accept",
                json!({"token": payload, "password": "correct horse battery 99"}),
            ),
            (
                "/api/v1/registration",
                json!({"email": payload, "display_name": payload,
                       "password": "correct horse battery 99"}),
            ),
            (
                "/api/v1/invitations",
                json!({"email": payload, "display_name": payload,
                       "principal_type": payload}),
            ),
            (
                "/api/v1/roles",
                json!({"code": payload, "name": payload,
                       "allowed_principal_type": "INTERNAL",
                       "permissions": [{"permission_code": payload, "scope": payload}]}),
            ),
            (
                "/api/v1/departments",
                json!({"code": payload, "name": payload, "description": payload}),
            ),
            (
                "/api/v1/clients",
                json!({"code": payload, "name": payload, "description": payload}),
            ),
            (
                "/api/v1/projects",
                json!({"code": payload, "name": payload, "description": payload,
                       "manager_user_id": w.root.id, "internal_note": payload}),
            ),
            (
                "/api/v1/tasks",
                json!({"project_id": w.project, "title": payload,
                       "description": payload, "priority": payload,
                       "internal_note": payload}),
            ),
        ];

        for (path, body) in bodies {
            world::reset_auth_limits(&w.app).await;
            let started = Instant::now();
            let response = w.app.post(path, root, body).await;
            let elapsed = started.elapsed();

            assert_ne!(
                response.status,
                StatusCode::INTERNAL_SERVER_ERROR,
                "{path} with {payload:?} produced a 500: {}",
                String::from_utf8_lossy(&response.raw)
            );
            assert!(
                elapsed < BLIND_INJECTION_CEILING,
                "{path} with {payload:?} took {elapsed:?}"
            );
            assert_no_reflection_or_disclosure(path, payload, &response.raw);
        }

        // Override creation: `permission_code`, `effect` and `scope` are all
        // compared against catalogues, so each is its own surface.
        let response = w
            .app
            .post(
                &format!("/api/v1/users/{}/permission-overrides", w.victim),
                root,
                json!({"permission_code": payload, "effect": payload, "scope": payload}),
            )
            .await;
        assert!(
            response.status.is_client_error(),
            "an override was created from {payload:?}: {}",
            String::from_utf8_lossy(&response.raw)
        );
        assert_no_reflection_or_disclosure("permission-overrides", payload, &response.raw);
    }

    // Some of the bodies above legitimately create rows — a payload that is a valid
    // name is a valid name. What must not have happened is a *table* appearing or
    // disappearing, or a row count moving in a table nothing wrote to.
    let after = world::snapshot(&w.app).await;
    assert_eq!(
        before.keys().collect::<Vec<_>>(),
        after.keys().collect::<Vec<_>>(),
        "the set of tables changed during the body sweep"
    );
    for table in [
        "credentials",
        "system_ownership",
        "permissions",
        "roles",
        "role_permissions",
        "user_role_assignments",
        "user_permission_overrides",
        "mfa_factors",
        "recovery_codes",
        "system_settings",
        "feature_flags",
    ] {
        assert_eq!(
            before.get(table),
            after.get(table),
            "`{table}` changed during the body sweep"
        );
    }
}

/// The wildcard question, which parameterisation alone does not answer.
///
/// A bound parameter stops a value changing the *syntax* of a statement. It does
/// not stop the value being a pattern, if the operator is `LIKE`: `?search=%` would
/// then match every row and turn a scoped search into an enumeration. This backend
/// uses `strpos`, which has no pattern language at all — so the metacharacters must
/// behave as ordinary characters, and this test is what says so.
#[tokio::test]
async fn wildcard_metacharacters_are_literal_in_search() {
    let w = World::build().await;
    let root = w.root.bearer();
    let hash = world::password_hash(&w.app).await;

    // One account whose display name contains each metacharacter, and one that does
    // not, so a pattern interpretation and a literal one give different answers.
    let marked = world::seed_user(&w.app, "pattern%_user@hardening.test", "INTERNAL", &hash).await;
    sqlx::query("UPDATE users SET display_name = $2 WHERE id = $1")
        .bind(marked)
        .bind("wild%card_name")
        .execute(&w.app.db)
        .await
        .expect("rename the marked user");

    let total = w.app.get("/api/v1/users?limit=100", root).await;
    total.assert_status(StatusCode::OK);
    let total_count = total
        .json()
        .get("items")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .expect("an items array");
    assert!(
        total_count >= 6,
        "the fixture should hold at least six users"
    );

    for (payload, expected) in [("%", 1usize), ("_", 1), ("%_", 1), ("card_", 1), ("\\", 0)] {
        let response = w
            .app
            .get(
                &format!("/api/v1/users?search={}&limit=100", urlencode(payload)),
                root,
            )
            .await;
        response.assert_status(StatusCode::OK);
        let matched = response
            .json()
            .get("items")
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .expect("an items array");
        assert_eq!(
            matched, expected,
            "searching for {payload:?} matched {matched} rows, not {expected}; a \
             metacharacter is being interpreted as a pattern"
        );
        assert!(
            matched < total_count,
            "searching for {payload:?} returned the whole table"
        );
    }
}

/// Sorting is the one place a caller's string decides part of the statement text.
/// It must select a compile-time column, never supply one.
#[tokio::test]
async fn sorting_selects_from_an_allowlist_and_never_supplies_a_column() {
    let w = World::build().await;
    let before = world::snapshot(&w.app).await;
    let root = w.root.bearer();

    let attacks = [
        "created_at; DROP TABLE users--",
        "created_at, (SELECT password_hash FROM credentials)",
        "(SELECT password_hash FROM credentials)",
        "u.email_normalized",
        "1",
        "*",
        "",
        " created_at ; --",
        "created_at--",
        "created_at/*",
        "CREATED_AT",
        "password_hash",
    ];
    for path in [
        "/api/v1/users",
        "/api/v1/projects",
        "/api/v1/tasks",
        "/api/v1/departments",
        "/api/v1/clients",
        "/api/v1/roles",
        "/api/v1/invitations",
    ] {
        for attack in attacks {
            let response = w
                .app
                .get(&format!("{path}?sort={}", urlencode(attack)), root)
                .await;
            response.assert_error(StatusCode::BAD_REQUEST, "VALIDATION_FAILED");
            assert_eq!(
                response
                    .json()
                    .pointer("/errors/0/code")
                    .and_then(|v| v.as_str()),
                Some("NOT_ALLOWED"),
                "{path}?sort={attack:?} was refused for the wrong reason"
            );
            // The refusal names the *allowed* fields, which are public API surface.
            // It must not name the rejected one.
            assert_no_reflection_or_disclosure(path, attack, &response.raw);
        }

        // Direction is a two-value enum, and every other spelling is refused.
        for direction in ["ASC", "asc; DROP TABLE users", "ascending", "", "1"] {
            w.app
                .get(&format!("{path}?direction={}", urlencode(direction)), root)
                .await
                .assert_error(StatusCode::BAD_REQUEST, "VALIDATION_FAILED");
        }
        for direction in ["asc", "desc"] {
            let ok = w
                .app
                .get(&format!("{path}?direction={direction}"), root)
                .await;
            assert!(
                ok.status.is_success(),
                "{path}?direction={direction} was refused: {}",
                String::from_utf8_lossy(&ok.raw)
            );
        }
    }

    assert_eq!(
        before,
        world::snapshot(&w.app).await,
        "a sort probe changed the database"
    );
}

/// After every sweep in this file the database must still hold exactly the objects
/// the fixture created, with their values unaltered.
///
/// A row count alone would miss an `UPDATE` that changed a value without changing
/// a count — which is what `'; UPDATE users SET principal_type='INTERNAL'--` would
/// do if it worked.
#[tokio::test]
async fn the_database_is_intact_after_a_full_attack_sweep() {
    let w = World::build().await;
    let before = world::snapshot(&w.app).await;
    let victim_before = world::user_envelope(&w.app, w.victim).await;
    let client_before = world::user_envelope(&w.app, w.client.id).await;
    let root = w.root.bearer();

    // A concentrated sweep across every surface at once.
    for payload in world::sql_injection_payloads() {
        world::reset_auth_limits(&w.app).await;
        let encoded = urlencode(payload);
        let _ = w
            .app
            .get(&format!("/api/v1/users?search={encoded}"), root)
            .await;
        let _ = w.app.get(&format!("/api/v1/users/{encoded}"), root).await;
        let _ = w
            .app
            .get(&format!("/api/v1/settings/{encoded}"), root)
            .await;
        let _ = w
            .app
            .post(
                "/api/v1/auth/login",
                None,
                json!({"email": payload, "password": payload}),
            )
            .await;
        let _ = w
            .app
            .patch(
                &format!("/api/v1/users/{}", w.victim),
                root,
                json!({"display_name": payload, "version": 1}),
            )
            .await;
    }

    let after = world::snapshot(&w.app).await;
    assert_eq!(
        before.keys().collect::<Vec<_>>(),
        after.keys().collect::<Vec<_>>(),
        "the set of tables changed"
    );
    for (table, count) in &before {
        // `users` legitimately gains nothing here, but `audit_events` and
        // `sessions` do — failed logins are audited, which is the system working.
        if matches!(table.as_str(), "audit_events" | "sessions" | "users") {
            continue;
        }
        assert_eq!(
            after.get(table),
            Some(count),
            "`{table}` moved from {count} to {:?}",
            after.get(table)
        );
    }

    // A `PATCH` with a payload as the display name legitimately renames the user
    // once, so the name is excluded — but nothing about *what the account is* may
    // have moved.
    let victim_after = world::user_envelope(&w.app, w.victim).await;
    assert_eq!(victim_before.principal_type, victim_after.principal_type);
    assert_eq!(victim_before.status, victim_after.status);
    assert_eq!(victim_before.email, victim_after.email);
    assert_eq!(
        victim_before.security_version,
        victim_after.security_version
    );
    assert_eq!(
        client_before,
        world::user_envelope(&w.app, w.client.id).await,
        "an untouched account moved"
    );
    assert!(world::is_root_in_db(&w.app, w.root.id).await);

    // Nobody gained authority.
    let (roles, overrides) = world::authority_of(&w.app, w.victim).await;
    assert_eq!(roles.len(), 1, "the target user's role set changed");
    assert!(overrides.is_empty(), "the target user gained an override");

    // And the runtime role still cannot see what it was never granted: a successful
    // injection would most plausibly show up as the application being able to read
    // `credentials`, so the count is checked directly.
    let (credentials,): (i64,) = sqlx::query_as("SELECT count(*) FROM credentials")
        .fetch_one(&w.app.db)
        .await
        .expect("count credentials");
    assert_eq!(
        Some(&credentials),
        before.get("credentials"),
        "the credentials table changed size"
    );
}

/// Regression test for finding M-3.
///
/// A NUL byte inside a string reaches PostgreSQL as a bound parameter, and `text`
/// cannot hold one — the server answers SQLSTATE `22021`. Nothing mapped it, so it
/// fell through to `AppError::Internal`, which meant an anonymous caller could turn
/// any string field into a `500` plus an `error!` log line at will. It is a bad
/// request: the value is unrepresentable, not the system broken.
#[tokio::test]
async fn a_nul_byte_is_a_bad_request_rather_than_an_internal_error() {
    let w = World::build().await;
    let root = w.root.bearer();

    let probes: Vec<(&str, serde_json::Value)> = vec![
        (
            "/api/v1/auth/login",
            json!({"email": "a\u{0}b@c.test", "password": "x"}),
        ),
        (
            "/api/v1/auth/login",
            json!({"email": "a@c.test", "password": "pass\u{0}word"}),
        ),
        (
            "/api/v1/auth/password-reset/request",
            json!({"email": "a\u{0}b@c.test"}),
        ),
        (
            "/api/v1/registration",
            json!({"email": "a\u{0}b@c.test", "display_name": "x",
                   "password": "correct horse battery 99"}),
        ),
    ];

    for (path, body) in probes {
        world::reset_auth_limits(&w.app).await;
        let response = w.app.post(path, None, body).await;
        assert_ne!(
            response.status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "{path} answered a NUL byte with a 500: {}",
            String::from_utf8_lossy(&response.raw)
        );
        assert!(
            response.status.is_client_error(),
            "{path} answered a NUL byte with {}",
            response.status
        );
    }

    // The same byte through an authenticated write path.
    let response = w
        .app
        .post(
            "/api/v1/departments",
            root,
            json!({"code": "nulprobe", "name": "a\u{0}b"}),
        )
        .await;
    response.assert_error(StatusCode::BAD_REQUEST, "VALIDATION_FAILED");
}

/// `UUID`-shaped inputs are parsed before they are used, so a near-miss must not
/// become a lookup of something else.
#[tokio::test]
async fn identifier_inputs_are_parsed_not_interpolated() {
    let w = World::build().await;
    let root = w.root.bearer();
    let real = w.victim;

    for suffix in [
        "' OR '1'='1",
        "'--",
        " OR 1=1",
        "%20OR%201=1",
        "::text",
        ";",
        "\u{0}",
    ] {
        let path = format!("/api/v1/users/{}{}", real, urlencode(suffix));
        let response = w.app.get(&path, root).await;
        response.assert_error(StatusCode::BAD_REQUEST, "VALIDATION_FAILED");
        assert_eq!(
            response
                .json()
                .pointer("/errors/0/code")
                .and_then(|v| v.as_str()),
            Some("INVALID_UUID"),
            "a near-miss identifier was refused for the wrong reason"
        );
    }

    // The genuine identifier still resolves, so the refusals are about the suffix.
    w.app
        .get(&format!("/api/v1/users/{real}"), root)
        .await
        .assert_status(StatusCode::OK);

    // A UUID that names nothing is a 404, not a 400 — the distinction matters,
    // because collapsing them would tell a prober which of their guesses parsed.
    w.app
        .get(&format!("/api/v1/users/{}", Uuid::now_v7()), root)
        .await
        .assert_error(StatusCode::NOT_FOUND, "RESOURCE_NOT_FOUND");
}
