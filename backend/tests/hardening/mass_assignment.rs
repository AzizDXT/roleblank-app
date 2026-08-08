//! §9 — mass assignment.
//!
//! The question is not "does the endpoint answer 400". It is "can a field the
//! caller was never offered reach a column". A status code alone cannot answer
//! that: an endpoint could reject the *response* while having already written the
//! row, and an endpoint could answer `200` having silently ignored the extra field
//! — which is safe — or having honoured it — which is the vulnerability. So every
//! probe here is followed by reading the database back.
//!
//! The proof is arranged in three phases, in this order:
//!
//!   1. **Injection.** Every sensitive body-carrying endpoint receives every
//!      privileged field name, one at a time, as an actor (ROOT) who is authorised
//!      to do everything — so a refusal can only have come from the input layer,
//!      never from a missing permission.
//!   2. **State.** A whole-database row count taken before and after phase 1, plus
//!      the security envelope of the account every probe aimed at. Nothing may have
//!      moved.
//!   3. **Control.** The same bodies *without* the extra field. Each is
//!      constructed to parse cleanly and then fail on a later check — a stale
//!      `version`, a wrong password, an invalid value — so the whole test is
//!      non-mutating while still proving that the `400` in phase 1 came from the
//!      extra field rather than from the body being nonsense to begin with.
//!
//! Without phase 3 the suite would pass just as happily against an endpoint that
//! rejected every body it was ever sent.

use axum::http::{Method, StatusCode};
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::common::TestApp;
use crate::world::{self, World, ROLE_SYSTEM_ADMINISTRATOR};

/// The privileged field names §9 requires, with a value that would be an
/// escalation if it were honoured.
fn privileged_fields() -> Vec<(&'static str, Value)> {
    let some_id = "00000000-0000-7000-8000-0000000000ff";
    vec![
        ("is_root", json!(true)),
        ("root_owner", json!(true)),
        ("principal_type", json!("INTERNAL")),
        ("roles", json!(["system_administrator"])),
        ("role_ids", json!([ROLE_SYSTEM_ADMINISTRATOR])),
        ("permissions", json!(["settings.security.write"])),
        ("permission_ids", json!([some_id])),
        ("scope", json!("GLOBAL")),
        ("is_admin", json!(true)),
        ("status", json!("ACTIVE")),
        ("active", json!(true)),
        ("mfa_verified", json!(true)),
        ("mfa_enabled", json!(false)),
        ("client_id", json!(some_id)),
        ("client_visibility", json!(true)),
        ("owner_id", json!(some_id)),
        ("created_by", json!(some_id)),
        ("audit_metadata", json!({"forged": "an entry nobody wrote"})),
    ]
}

/// One endpoint under test.
struct Target {
    name: &'static str,
    method: Method,
    path: String,
    token: Option<String>,
    /// A body that parses but is designed to fail a *later* check, so the control
    /// phase changes nothing.
    base: Value,
    /// Field names from `privileged_fields` that are a genuine, documented part of
    /// this endpoint's contract. Pinned rather than skipped silently: a new name
    /// appearing in this list is a change to what a body may steer, and must be a
    /// deliberate review rather than a quiet test edit.
    declared: &'static [&'static str],
}

fn targets(w: &World) -> Vec<Target> {
    let root = w.root.token.clone();
    let unknown = Uuid::now_v7();
    let stale = json!(999_999);

    // Every base body below either carries a stale `version`, a wrong secret, or a
    // value that fails validation. None of them can succeed, which is what makes
    // the control phase safe to run against the live fixture.
    vec![
        // ---- anonymous identity surface -----------------------------------
        Target {
            name: "POST /api/v1/registration",
            method: Method::POST,
            path: "/api/v1/registration".into(),
            token: None,
            base: json!({"email": "not-an-email", "display_name": "A", "password": "short"}),
            declared: &[],
        },
        Target {
            name: "POST /api/v1/invitations/accept",
            method: Method::POST,
            path: "/api/v1/invitations/accept".into(),
            token: None,
            base: json!({"token": "rb_inv_not_a_real_token", "password": "short"}),
            declared: &[],
        },
        // ---- authentication ------------------------------------------------
        Target {
            name: "POST /api/v1/auth/login",
            method: Method::POST,
            path: "/api/v1/auth/login".into(),
            token: None,
            base: json!({"email": w.root.email, "password": "the wrong password entirely"}),
            declared: &[],
        },
        Target {
            name: "POST /api/v1/auth/refresh",
            method: Method::POST,
            path: "/api/v1/auth/refresh".into(),
            token: None,
            base: json!({"refresh_token": "rb_rt_not_a_real_token"}),
            declared: &[],
        },
        Target {
            name: "POST /api/v1/auth/password/change",
            method: Method::POST,
            path: "/api/v1/auth/password/change".into(),
            token: Some(root.clone()),
            base: json!({"current_password": "wrong", "new_password": "another correct horse 77"}),
            declared: &[],
        },
        Target {
            name: "POST /api/v1/auth/password-reset/request",
            method: Method::POST,
            path: "/api/v1/auth/password-reset/request".into(),
            token: None,
            base: json!({"email": "nobody@hardening.test"}),
            declared: &[],
        },
        Target {
            name: "POST /api/v1/auth/password-reset/confirm",
            method: Method::POST,
            path: "/api/v1/auth/password-reset/confirm".into(),
            token: None,
            base: json!({"token": "rb_pr_not_a_real_token", "new_password": "short"}),
            declared: &[],
        },
        Target {
            name: "POST /api/v1/auth/mfa/totp/activate",
            method: Method::POST,
            path: "/api/v1/auth/mfa/totp/activate".into(),
            token: Some(root.clone()),
            base: json!({"code": "000000"}),
            declared: &[],
        },
        Target {
            name: "POST /api/v1/auth/mfa/verify",
            method: Method::POST,
            path: "/api/v1/auth/mfa/verify".into(),
            token: Some(root.clone()),
            base: json!({"code": "000000"}),
            declared: &[],
        },
        Target {
            name: "POST /api/v1/auth/mfa/recovery/verify",
            method: Method::POST,
            path: "/api/v1/auth/mfa/recovery/verify".into(),
            token: Some(root.clone()),
            base: json!({"code": "not-a-recovery-code"}),
            declared: &[],
        },
        // ---- users ----------------------------------------------------------
        Target {
            name: "PATCH /api/v1/users/{id}",
            method: Method::PATCH,
            path: format!("/api/v1/users/{}", w.victim),
            token: Some(root.clone()),
            base: json!({"display_name": "Renamed", "version": stale}),
            declared: &[],
        },
        Target {
            name: "POST /api/v1/users/{id}/suspend",
            method: Method::POST,
            path: format!("/api/v1/users/{}/suspend", w.victim),
            token: Some(root.clone()),
            base: json!({"version": stale}),
            declared: &[],
        },
        Target {
            name: "POST /api/v1/users/{id}/reactivate",
            method: Method::POST,
            path: format!("/api/v1/users/{}/reactivate", w.victim),
            token: Some(root.clone()),
            base: json!({"version": stale}),
            declared: &[],
        },
        Target {
            name: "POST /api/v1/users/{id}/archive",
            method: Method::POST,
            path: format!("/api/v1/users/{}/archive", w.victim),
            token: Some(root.clone()),
            base: json!({"version": stale}),
            declared: &[],
        },
        // ---- invitations -----------------------------------------------------
        //
        // `principal_type` and `role_ids` are the operation here, not smuggled
        // extras: deciding what an invitee will be *is* creating an invitation.
        // They are checked against the inviter's delegation authority at creation
        // and again at acceptance, which `declared_fields_are_still_validated`
        // exercises below.
        Target {
            name: "POST /api/v1/invitations",
            method: Method::POST,
            path: "/api/v1/invitations".into(),
            token: Some(root.clone()),
            base: json!({
                "email": "not-an-email-at-all",
                "display_name": "Invitee",
                "principal_type": "INTERNAL"
            }),
            declared: &["principal_type", "role_ids"],
        },
        // ---- roles and delegation --------------------------------------------
        Target {
            name: "POST /api/v1/roles",
            method: Method::POST,
            path: "/api/v1/roles".into(),
            token: Some(root.clone()),
            base: json!({
                "code": "NOT A VALID CODE",
                "name": "x",
                "allowed_principal_type": "INTERNAL"
            }),
            declared: &[],
        },
        Target {
            name: "PATCH /api/v1/roles/{id}",
            method: Method::PATCH,
            path: format!("/api/v1/roles/{ROLE_SYSTEM_ADMINISTRATOR}"),
            token: Some(root.clone()),
            base: json!({"version": stale, "name": "Renamed"}),
            declared: &[],
        },
        Target {
            name: "POST /api/v1/users/{id}/roles",
            method: Method::POST,
            path: format!("/api/v1/users/{}/roles", w.victim),
            token: Some(root.clone()),
            base: json!({"role_id": unknown}),
            declared: &[],
        },
        Target {
            name: "POST /api/v1/users/{id}/permission-overrides",
            method: Method::POST,
            path: format!("/api/v1/users/{}/permission-overrides", w.victim),
            token: Some(root.clone()),
            base: json!({
                "permission_code": "not.a.real.permission",
                "effect": "ALLOW",
                "scope": "GLOBAL"
            }),
            declared: &["scope"],
        },
        // ---- departments -----------------------------------------------------
        Target {
            name: "POST /api/v1/departments",
            method: Method::POST,
            path: "/api/v1/departments".into(),
            token: Some(root.clone()),
            base: json!({"code": "NOT VALID", "name": "x"}),
            declared: &[],
        },
        Target {
            name: "PATCH /api/v1/departments/{id}",
            method: Method::PATCH,
            path: format!("/api/v1/departments/{}", w.department),
            token: Some(root.clone()),
            base: json!({"version": stale, "name": "Renamed"}),
            declared: &[],
        },
        Target {
            name: "POST /api/v1/departments/{id}/archive",
            method: Method::POST,
            path: format!("/api/v1/departments/{}/archive", w.department),
            token: Some(root.clone()),
            base: json!({"version": stale}),
            declared: &[],
        },
        Target {
            name: "POST /api/v1/departments/{id}/members",
            method: Method::POST,
            path: format!("/api/v1/departments/{}/members", w.department),
            token: Some(root.clone()),
            base: json!({"user_id": unknown}),
            declared: &[],
        },
        // ---- client accounts --------------------------------------------------
        Target {
            name: "POST /api/v1/clients",
            method: Method::POST,
            path: "/api/v1/clients".into(),
            token: Some(root.clone()),
            base: json!({"code": "NOT VALID", "name": "x"}),
            declared: &[],
        },
        Target {
            name: "PATCH /api/v1/clients/{id}",
            method: Method::PATCH,
            path: format!("/api/v1/clients/{}", w.client_account),
            token: Some(root.clone()),
            base: json!({"version": stale, "name": "Renamed"}),
            declared: &[],
        },
        Target {
            name: "POST /api/v1/clients/{id}/archive",
            method: Method::POST,
            path: format!("/api/v1/clients/{}/archive", w.client_account),
            token: Some(root.clone()),
            base: json!({"version": stale}),
            declared: &[],
        },
        Target {
            name: "POST /api/v1/clients/{id}/members",
            method: Method::POST,
            path: format!("/api/v1/clients/{}/members", w.client_account),
            token: Some(root.clone()),
            base: json!({"user_id": unknown}),
            declared: &[],
        },
        // ---- projects ----------------------------------------------------------
        Target {
            name: "POST /api/v1/projects",
            method: Method::POST,
            path: "/api/v1/projects".into(),
            token: Some(root.clone()),
            base: json!({"code": "NOT VALID", "name": "x", "manager_user_id": w.root.id}),
            declared: &[],
        },
        Target {
            name: "PATCH /api/v1/projects/{id}",
            method: Method::PATCH,
            path: format!("/api/v1/projects/{}", w.project),
            token: Some(root.clone()),
            base: json!({"version": stale, "name": "Renamed"}),
            declared: &["status"],
        },
        Target {
            name: "POST /api/v1/projects/{id}/archive",
            method: Method::POST,
            path: format!("/api/v1/projects/{}/archive", w.project),
            token: Some(root.clone()),
            base: json!({"version": stale}),
            declared: &[],
        },
        Target {
            name: "POST /api/v1/projects/{id}/members",
            method: Method::POST,
            path: format!("/api/v1/projects/{}/members", w.project),
            token: Some(root.clone()),
            base: json!({"user_id": unknown}),
            declared: &[],
        },
        Target {
            name: "POST /api/v1/projects/{id}/clients",
            method: Method::POST,
            path: format!("/api/v1/projects/{}/clients", w.project),
            token: Some(root.clone()),
            base: json!({"client_account_id": unknown}),
            declared: &[],
        },
        // ---- tasks --------------------------------------------------------------
        Target {
            name: "POST /api/v1/tasks",
            method: Method::POST,
            path: "/api/v1/tasks".into(),
            token: Some(root.clone()),
            base: json!({"project_id": unknown, "title": "x"}),
            declared: &[],
        },
        Target {
            name: "PATCH /api/v1/tasks/{id}",
            method: Method::PATCH,
            path: format!("/api/v1/tasks/{}", w.task),
            token: Some(root.clone()),
            base: json!({"version": stale, "title": "Renamed"}),
            declared: &["status"],
        },
        Target {
            name: "POST /api/v1/tasks/{id}/assignees",
            method: Method::POST,
            path: format!("/api/v1/tasks/{}/assignees", w.task),
            token: Some(root.clone()),
            base: json!({"user_id": unknown}),
            declared: &[],
        },
        // ---- settings and flags ---------------------------------------------------
        Target {
            name: "PUT /api/v1/settings/{key}",
            method: Method::PUT,
            path: "/api/v1/settings/registration.mode".into(),
            token: Some(root.clone()),
            base: json!({"value": "INVITE_ONLY", "version": stale}),
            declared: &[],
        },
        Target {
            name: "PUT /api/v1/feature-flags/{key}",
            method: Method::PUT,
            path: "/api/v1/feature-flags/chat".into(),
            token: Some(root),
            base: json!({"enabled": true, "version": stale}),
            declared: &[],
        },
    ]
}

/// Insert (or overwrite) one field in a body.
///
/// Overwriting rather than appending matters: emitting the same key twice would
/// produce a document whose meaning depends on which duplicate serde keeps, and the
/// probe would then be testing JSON parsing rather than the DTO.
fn with_field(base: &Value, name: &str, value: &Value) -> Value {
    let mut map: Map<String, Value> = base
        .as_object()
        .cloned()
        .expect("every base body is a JSON object");
    map.insert(name.to_string(), value.clone());
    Value::Object(map)
}

async fn send(app: &TestApp, t: &Target, body: &Value) -> crate::common::TestResponse {
    let request = world::raw_request(
        t.method.clone(),
        &t.path,
        t.token.as_deref(),
        Some("application/json"),
        &[],
        serde_json::to_vec(body).expect("serialise a probe body"),
    );
    app.request(request).await
}

#[tokio::test]
async fn no_privileged_field_can_be_smuggled_into_any_sensitive_endpoint() {
    let w = World::build().await;
    let fields = privileged_fields();
    let targets = targets(&w);

    // ---- phase 0: what the world looks like before anything is attacked ----
    let before = world::snapshot(&w.app).await;
    let victim_before = world::user_envelope(&w.app, w.victim).await;
    let victim_authority_before = world::authority_of(&w.app, w.victim).await;
    let admin_authority_before = world::authority_of(&w.app, w.admin.id).await;

    // ---- phase 1: injection ------------------------------------------------
    let mut probes = 0usize;
    let mut accepted_declared = Vec::new();
    for t in &targets {
        for (name, value) in &fields {
            if t.declared.contains(name) {
                accepted_declared.push((t.name, *name));
                continue;
            }
            probes += 1;
            let response = send(&w.app, t, &with_field(&t.base, name, value)).await;
            response.assert_error(StatusCode::BAD_REQUEST, "BAD_REQUEST");
            // The refusal must not repeat the caller's own field name back: a
            // reflected identifier is both an oracle for what the DTO contains and
            // a gadget for whatever renders the message.
            //
            // `status` is exempt because RFC 9457 gives every problem document a
            // member of that name — `"status":400` is the envelope, not a
            // reflection. No other injected name collides with a reserved member.
            if *name != "status" {
                let text = String::from_utf8_lossy(&response.raw);
                assert!(
                    !text.contains(name),
                    "{}: the refusal reflected the injected field name `{name}`: {text}",
                    t.name
                );
            }
        }
    }
    assert!(
        probes > 500,
        "the sweep only ran {probes} probes; the target table has shrunk"
    );

    // The exceptions are pinned. A field that becomes settable on an endpoint must
    // arrive here as a deliberate edit, not as a silently widened contract.
    accepted_declared.sort_unstable();
    assert_eq!(
        accepted_declared,
        vec![
            ("PATCH /api/v1/projects/{id}", "status"),
            ("PATCH /api/v1/tasks/{id}", "status"),
            ("POST /api/v1/invitations", "principal_type"),
            ("POST /api/v1/invitations", "role_ids"),
            ("POST /api/v1/users/{id}/permission-overrides", "scope"),
        ],
        "the set of privileged names an endpoint legitimately accepts has changed"
    );

    // ---- phase 2: the database has not moved --------------------------------
    let after = world::snapshot(&w.app).await;
    assert_eq!(
        before, after,
        "a rejected mass-assignment probe changed a row count"
    );
    assert_eq!(
        victim_before,
        world::user_envelope(&w.app, w.victim).await,
        "the target account's security envelope moved"
    );
    assert_eq!(
        victim_authority_before,
        world::authority_of(&w.app, w.victim).await,
        "the target account gained or lost authority"
    );
    assert_eq!(
        admin_authority_before,
        world::authority_of(&w.app, w.admin.id).await,
        "the administrator's authority moved"
    );
    assert!(
        world::is_root_in_db(&w.app, w.root.id).await,
        "the system owner changed identity"
    );
    for other in [w.victim, w.admin.id, w.employee.id, w.client.id] {
        assert!(
            !world::is_root_in_db(&w.app, other).await,
            "{other} became the system owner"
        );
    }

    // ---- phase 3: the control ------------------------------------------------
    // Each base body parses; each then fails a later check. If any of them came
    // back as BAD_REQUEST, phase 1's refusals would prove nothing about the
    // injected field.
    for t in &targets {
        let response = send(&w.app, t, &t.base).await;
        assert_ne!(
            response.error_code(),
            Some("BAD_REQUEST"),
            "{}: the control body was itself rejected as unparseable, so this \
             endpoint's phase-1 refusals prove nothing: {}",
            t.name,
            String::from_utf8_lossy(&response.raw)
        );
    }

    // The control phase is designed to be non-mutating too — with one exception.
    // Several of the control bodies are refused by a *handler* rather than by the
    // extractor (a wrong password, a failed second factor, a rejected bootstrap),
    // and those refusals are audited. An audit record for an attempt that was
    // denied is the system working, so `audit_events` is allowed to grow and
    // everything else is not.
    let after_control = world::snapshot(&w.app).await;
    for (table, count) in &before {
        if table == "audit_events" {
            assert!(
                after_control.get(table).copied().unwrap_or_default() >= *count,
                "audit records disappeared"
            );
            continue;
        }
        assert_eq!(
            after_control.get(table),
            Some(count),
            "the control phase changed `{table}`; it is meant to be inert"
        );
    }
}

/// Bootstrap needs its own world: the endpoint is permanently closed once an owner
/// exists, so a probe against the shared fixture would be refused by
/// `SYSTEM_ALREADY_INITIALIZED` and would prove nothing about the body.
#[tokio::test]
async fn bootstrap_cannot_be_steered_by_an_extra_field() {
    let app = TestApp::spawn().await;
    let before = world::snapshot(&app).await;

    let base = json!({
        "bootstrap_secret": crate::common::TEST_BOOTSTRAP_SECRET,
        "email": "owner@bootstrap.test",
        "display_name": "Owner",
        "password": crate::common::TEST_PASSWORD,
    });

    for (name, value) in privileged_fields() {
        let response = app
            .post(
                "/api/v1/bootstrap/root",
                None,
                with_field(&base, name, &value),
            )
            .await;
        response.assert_error(StatusCode::BAD_REQUEST, "BAD_REQUEST");
    }

    // No owner was created by any of them.
    assert_eq!(
        before,
        world::snapshot(&app).await,
        "a rejected bootstrap probe changed state"
    );
    let status = app.get("/api/v1/bootstrap/status", None).await;
    status.assert_status(StatusCode::OK);
    assert_eq!(
        status.json().get("initialized").and_then(Value::as_bool),
        Some(false),
        "the system reported itself initialised after only rejected bootstraps"
    );

    // And the clean body still works, so the refusals above were about the field.
    app.post("/api/v1/bootstrap/root", None, base)
        .await
        .assert_status(StatusCode::CREATED);
}

/// The five names an endpoint does legitimately accept are still constrained.
///
/// "Declared" is not "trusted": each of these decides something privileged, so the
/// value is checked against a closed enum, a catalogue or the actor's own
/// delegation authority. Proving they are *validated* is what stops the exception
/// list above from being a hole.
#[tokio::test]
async fn declared_privileged_fields_are_still_validated() {
    let w = World::build().await;
    let before = world::snapshot(&w.app).await;
    let root = w.root.bearer();

    // `principal_type` on an invitation is a closed enum, not free text — a value
    // outside it must not become a new kind of principal.
    for bad in ["ROOT", "SYSTEM", "internal", "INTERNAL; DROP TABLE users"] {
        w.app
            .post(
                "/api/v1/invitations",
                root,
                json!({
                    "email": "probe@hardening.test",
                    "display_name": "Probe",
                    "principal_type": bad
                }),
            )
            .await
            .assert_error(StatusCode::BAD_REQUEST, "VALIDATION_FAILED");
    }

    // `role_ids` names roles from the catalogue; an unknown id is refused rather
    // than created, and the refusal is a field error on `role_ids` — so the field
    // is genuinely consulted rather than accepted and dropped.
    let unknown_role = w
        .app
        .post(
            "/api/v1/invitations",
            root,
            json!({
                "email": "probe@hardening.test",
                "display_name": "Probe",
                "principal_type": "INTERNAL",
                "role_ids": [Uuid::now_v7()]
            }),
        )
        .await;
    unknown_role.assert_error(StatusCode::BAD_REQUEST, "VALIDATION_FAILED");
    assert_eq!(
        unknown_role
            .json()
            .pointer("/errors/0/field")
            .and_then(Value::as_str),
        Some("role_ids")
    );

    // `scope` on an override is a closed enum.
    for bad in ["SUPERGLOBAL", "global", "GLOBAL'--", ""] {
        w.app
            .post(
                &format!("/api/v1/users/{}/permission-overrides", w.victim),
                root,
                json!({"permission_code": "audit.read", "effect": "ALLOW", "scope": bad}),
            )
            .await
            .assert_error(StatusCode::BAD_REQUEST, "VALIDATION_FAILED");
    }

    // `status` on a project patch may not reach `ARCHIVED`: archiving is a separate
    // endpoint behind a separate permission, and letting a patch do it would route
    // around that permission.
    let project_version: (i32,) = sqlx::query_as("SELECT version FROM projects WHERE id = $1")
        .bind(w.project)
        .fetch_one(&w.app.db)
        .await
        .expect("read the project version");
    let archived = w
        .app
        .patch(
            &format!("/api/v1/projects/{}", w.project),
            root,
            json!({"version": project_version.0, "status": "ARCHIVED"}),
        )
        .await;
    assert_ne!(
        archived.status,
        StatusCode::OK,
        "a project was archived through PATCH, bypassing projects.archive"
    );
    let (status,): (String,) = sqlx::query_as("SELECT status FROM projects WHERE id = $1")
        .bind(w.project)
        .fetch_one(&w.app.db)
        .await
        .expect("read the project status");
    assert_eq!(status, "ACTIVE", "the project's status moved");

    // `status` on a task patch is a closed enum too.
    for bad in ["ARCHIVED", "todo", "DONE'; --"] {
        let task_version: (i32,) = sqlx::query_as("SELECT version FROM tasks WHERE id = $1")
            .bind(w.task)
            .fetch_one(&w.app.db)
            .await
            .expect("read the task version");
        w.app
            .patch(
                &format!("/api/v1/tasks/{}", w.task),
                root,
                json!({"version": task_version.0, "status": bad}),
            )
            .await
            .assert_error(StatusCode::BAD_REQUEST, "VALIDATION_FAILED");
    }

    assert_eq!(
        before,
        world::snapshot(&w.app).await,
        "a refused declared-field probe changed state"
    );
}

/// A body may not carry the same privileged field twice, nor bury it in a nested
/// object, nor reach the DTO as an array element.
///
/// `deny_unknown_fields` is a per-struct property; a nested DTO that lacked it
/// would be a hole underneath an endpoint whose top level looks closed.
#[tokio::test]
async fn nested_and_repeated_privileged_fields_are_refused_too() {
    let w = World::build().await;
    let before = world::snapshot(&w.app).await;
    let root = w.root.bearer();

    // `permissions[]` on a role is the one place this API accepts a nested request
    // object. It must be closed as well.
    for injected in [
        json!({"permission_code": "audit.read", "scope": "GLOBAL", "is_root": true}),
        json!({"permission_code": "audit.read", "scope": "GLOBAL", "resource_id": "x"}),
        json!({"permission_code": "audit.read", "scope": "GLOBAL", "effect": "ALLOW"}),
    ] {
        w.app
            .post(
                "/api/v1/roles",
                root,
                json!({
                    "code": "probe_role",
                    "name": "Probe",
                    "allowed_principal_type": "INTERNAL",
                    "permissions": [injected]
                }),
            )
            .await
            .assert_error(StatusCode::BAD_REQUEST, "BAD_REQUEST");
    }

    // A duplicate key: serde keeps the last, so a body that repeats a legitimate
    // field with a privileged value must not be able to win by ordering.
    let raw = r#"{"display_name":"Legit","version":1,"display_name":"Overwritten",
                  "principal_type":"INTERNAL"}"#
        .to_string();
    let response = w
        .app
        .request(world::raw_request(
            Method::PATCH,
            &format!("/api/v1/users/{}", w.victim),
            root,
            Some("application/json"),
            &[],
            raw.into_bytes(),
        ))
        .await;
    response.assert_error(StatusCode::BAD_REQUEST, "BAD_REQUEST");

    assert_eq!(
        before,
        world::snapshot(&w.app).await,
        "a nested or repeated-field probe changed state"
    );
}
