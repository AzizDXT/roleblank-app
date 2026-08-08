//! Settings, feature flags, the audit reader, and the platform endpoints.
//!
//! Grouped because they share one property: each is a *global singleton* surface.
//! Configuration has no department and no owner, and neither does audit history,
//! so every decision here is `Target::Collection` — which only a `GLOBAL` grant
//! covers. A department-bounded administrator reaches none of it, and that is the
//! fail-closed reading rather than an oversight.

use axum::http::{header, StatusCode};
use serde_json::{json, Value};
use std::sync::Arc;
use uuid::Uuid;

use crate::common::TestApp;
use crate::fixtures::*;

fn setting_named<'a>(body: &'a Value, key: &str) -> Option<&'a Value> {
    body.as_array()
        .expect("a plain array")
        .iter()
        .find(|item| item["key"] == json!(key))
}

// ===========================================================================
// Settings
// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_settings_listing_carries_the_seeded_configuration() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;

    let listed = app.get("/api/v1/settings", Some(&root.token)).await;
    listed.assert_status(StatusCode::OK).assert_no_secrets();
    let mode = setting_named(listed.json(), "registration.mode").expect("the seeded setting");
    assert_eq!(mode["value"], json!("INVITE_ONLY"));
    assert_eq!(mode["value_type"], json!("ENUM"));
    assert_eq!(mode["is_security_sensitive"], json!(true));
    assert_eq!(mode["version"], json!(1));

    let ttl = setting_named(listed.json(), "invitations.ttl_hours").expect("the seeded setting");
    assert_eq!(ttl["value"], json!(72));
    assert_eq!(ttl["is_security_sensitive"], json!(false));
}

/// The security-sensitive rows are excluded by the **query**, not filtered out of
/// the response: a caller without `settings.security.write` never has
/// `registration.mode` in this process's memory, let alone in their body.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ordinary_settings_reader_never_sees_a_security_sensitive_row() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let operator = create_employee(&app, &root.token, "ops@roleblank.test", None).await;
    let role = create_role(
        &app,
        &root.token,
        "product_operator",
        "INTERNAL",
        &[
            ("settings.read", "GLOBAL"),
            ("settings.features.write", "GLOBAL"),
        ],
    )
    .await;
    app.post(
        &format!("/api/v1/users/{}/roles", operator.user_id),
        Some(&root.token),
        json!({"role_id": role}),
    )
    .await
    .assert_status(StatusCode::CREATED);

    let settings = app.get("/api/v1/settings", Some(&operator.token)).await;
    settings.assert_status(StatusCode::OK);
    assert!(
        setting_named(settings.json(), "registration.mode").is_none(),
        "a sensitive setting reached an ordinary reader"
    );
    assert!(setting_named(settings.json(), "invitations.ttl_hours").is_some());

    let flags = app
        .get("/api/v1/feature-flags", Some(&operator.token))
        .await;
    flags.assert_status(StatusCode::OK);
    assert!(
        setting_named(flags.json(), "client_portal").is_none(),
        "a sensitive flag reached an ordinary reader"
    );
    assert!(setting_named(flags.json(), "chat").is_some());

    // Holding the ordinary write permission does not widen the read either.
    app.put(
        "/api/v1/settings/registration.mode",
        Some(&operator.token),
        json!({"value": "CLIENT_SELF_REGISTRATION", "version": 1}),
    )
    .await
    .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");

    // The refused attempt on a security-sensitive setting is recorded: it is
    // exactly the signal an intrusion-detection reader is looking for.
    let (denied,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM audit_events
          WHERE action_code = 'SETTING.CHANGED' AND outcome = 'DENIED'",
    )
    .fetch_one(&app.db)
    .await
    .expect("count");
    assert_eq!(denied, 1);

    let value: Value =
        sqlx::query_scalar("SELECT value FROM system_settings WHERE key = 'registration.mode'")
            .fetch_one(&app.db)
            .await
            .expect("the setting row");
    assert_eq!(value, json!("INVITE_ONLY"), "the refusal must have held");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ordinary_setting_is_written_and_both_values_are_recorded() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;

    let updated = app
        .put(
            "/api/v1/settings/invitations.ttl_hours",
            Some(&root.token),
            json!({"value": 24, "version": 1}),
        )
        .await;
    updated.assert_status(StatusCode::OK).assert_no_secrets();
    assert_eq!(updated.json()["value"], json!(24));
    assert_eq!(updated.json()["version"], json!(2));
    assert_eq!(updated.id_at("/updated_by"), root.user_id);

    let meta: Value = sqlx::query_scalar(
        "SELECT metadata FROM audit_events
          WHERE action_code = 'SETTING.CHANGED' AND outcome = 'SUCCESS'",
    )
    .fetch_one(&app.db)
    .await
    .expect("the audit row");
    assert_eq!(meta["setting_key"], json!("invitations.ttl_hours"));
    assert_eq!(meta["security_sensitive"], json!(false));
    assert_eq!(meta["old_value"], json!("72"));
    assert_eq!(meta["new_value"], json!("24"));

    app.put(
        "/api/v1/settings/invitations.ttl_hours",
        Some(&root.token),
        json!({"value": 12, "version": 1}),
    )
    .await
    .assert_error(StatusCode::CONFLICT, "VERSION_CONFLICT");
}

/// `audit_events` is append-only with no delete path anywhere, so a value written
/// there is written permanently — and the values of security-sensitive settings
/// are exactly the ones an attacker would most like a permanent, widely-readable
/// copy of. The key and the actor are what accountability needs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sensitive_setting_records_the_key_but_never_the_values() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;

    app.put(
        "/api/v1/settings/registration.mode",
        Some(&root.token),
        json!({"value": "CLIENT_SELF_REGISTRATION", "version": 1}),
    )
    .await
    .assert_status(StatusCode::OK);

    let meta: Value = sqlx::query_scalar(
        "SELECT metadata FROM audit_events
          WHERE action_code = 'SETTING.CHANGED' AND outcome = 'SUCCESS'",
    )
    .fetch_one(&app.db)
    .await
    .expect("the audit row");
    let rendered = meta.to_string();
    assert!(rendered.contains("registration.mode"));
    assert_eq!(meta["security_sensitive"], json!(true));
    assert_eq!(meta["values_recorded"], json!(false));
    assert!(
        !rendered.contains("INVITE_ONLY") && !rendered.contains("CLIENT_SELF_REGISTRATION"),
        "a security-sensitive value leaked into the permanent record: {rendered}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_setting_value_is_validated_against_the_type_the_row_declares() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;

    // An ENUM is a closed set held in code, not whatever string is in the row.
    for bad in [json!("OPEN"), json!("invite_only"), json!(1), json!(true)] {
        app.put(
            "/api/v1/settings/registration.mode",
            Some(&root.token),
            json!({"value": bad, "version": 1}),
        )
        .await
        .assert_error(StatusCode::BAD_REQUEST, "VALIDATION_FAILED");
    }

    // An INTEGER setting that accepted `"24"` would be a control disabled by a typo.
    for bad in [
        json!("24"),
        json!(1.5),
        json!(true),
        json!(2_000_000_000i64),
    ] {
        app.put(
            "/api/v1/settings/invitations.ttl_hours",
            Some(&root.token),
            json!({"value": bad, "version": 1}),
        )
        .await
        .assert_error(StatusCode::BAD_REQUEST, "VALIDATION_FAILED");
    }

    // The key describes the setting; a caller who could change it could downgrade a
    // sensitive setting and then write it with the weaker permission.
    for body in [
        json!({"value": 24, "version": 1, "is_security_sensitive": false}),
        json!({"value": 24, "version": 1, "value_type": "STRING"}),
        json!({"value": 24, "version": 1, "key": "other.setting"}),
        json!({"value": 24}),
    ] {
        app.put(
            "/api/v1/settings/invitations.ttl_hours",
            Some(&root.token),
            body,
        )
        .await
        .assert_error(StatusCode::BAD_REQUEST, "BAD_REQUEST");
    }
}

/// Settings and flags are created by migrations, never by the API: a key that
/// appears at runtime is a key nothing reads.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unknown_key_is_not_found_and_a_malformed_one_is_a_field_error() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;

    app.put(
        "/api/v1/settings/no.such.setting",
        Some(&root.token),
        json!({"value": "x", "version": 1}),
    )
    .await
    .assert_error(StatusCode::NOT_FOUND, "RESOURCE_NOT_FOUND");

    for key in ["Registration.Mode", "registration-mode", "1registration"] {
        app.put(
            &format!("/api/v1/settings/{key}"),
            Some(&root.token),
            json!({"value": "x", "version": 1}),
        )
        .await
        .assert_error(StatusCode::BAD_REQUEST, "VALIDATION_FAILED");
    }

    // There is no POST and no DELETE: a security control that can be removed is
    // worse than one that can only be changed.
    let created = app
        .post(
            "/api/v1/settings",
            Some(&root.token),
            json!({"key": "new.setting", "value": 1}),
        )
        .await;
    assert_eq!(created.status, StatusCode::METHOD_NOT_ALLOWED);
    let deleted = app
        .delete("/api/v1/settings/invitations.ttl_hours", Some(&root.token))
        .await;
    assert_eq!(deleted.status, StatusCode::METHOD_NOT_ALLOWED);
}

// ===========================================================================
// Feature flags
// ===========================================================================

/// Switching a flag changes what is *offered*, never who is *authorised*. The
/// client-portal routes stay independently authorised with the flag off.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_feature_flag_is_toggled_and_the_change_is_audited() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;

    let listed = app.get("/api/v1/feature-flags", Some(&root.token)).await;
    listed.assert_status(StatusCode::OK).assert_no_secrets();
    assert_eq!(
        setting_named(listed.json(), "client_portal").expect("seeded")["enabled"],
        json!(true)
    );
    assert_eq!(
        setting_named(listed.json(), "chat").expect("seeded")["enabled"],
        json!(false)
    );

    let toggled = app
        .put(
            "/api/v1/feature-flags/chat",
            Some(&root.token),
            json!({"enabled": true, "version": 1}),
        )
        .await;
    toggled.assert_status(StatusCode::OK);
    assert_eq!(toggled.json()["enabled"], json!(true));
    assert_eq!(toggled.json()["version"], json!(2));
    assert_eq!(audit_count(&app, "FEATURE_FLAG.CHANGED").await, 1);

    app.put(
        "/api/v1/feature-flags/chat",
        Some(&root.token),
        json!({"enabled": false, "version": 1}),
    )
    .await
    .assert_error(StatusCode::CONFLICT, "VERSION_CONFLICT");

    for body in [
        json!({"enabled": "true", "version": 1}),
        json!({"enabled": true}),
        json!({"enabled": true, "version": 2, "is_security_sensitive": false}),
    ] {
        app.put("/api/v1/feature-flags/chat", Some(&root.token), body)
            .await
            .assert_error(StatusCode::BAD_REQUEST, "BAD_REQUEST");
    }

    app.put(
        "/api/v1/feature-flags/no_such_flag",
        Some(&root.token),
        json!({"enabled": true, "version": 1}),
    )
    .await
    .assert_error(StatusCode::NOT_FOUND, "RESOURCE_NOT_FOUND");
}

/// A sensitive flag records neither boolean, for the same reason a sensitive
/// setting records neither value.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sensitive_flag_change_records_neither_boolean() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;

    app.put(
        "/api/v1/feature-flags/client_portal",
        Some(&root.token),
        json!({"enabled": false, "version": 1}),
    )
    .await
    .assert_status(StatusCode::OK);

    let meta: Value = sqlx::query_scalar(
        "SELECT metadata FROM audit_events WHERE action_code = 'FEATURE_FLAG.CHANGED'",
    )
    .fetch_one(&app.db)
    .await
    .expect("the audit row");
    assert_eq!(meta["flag_key"], json!("client_portal"));
    assert_eq!(meta["values_recorded"], json!(false));
    let object = meta.as_object().expect("object");
    assert!(!object.contains_key("old_value") && !object.contains_key("new_value"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn configuration_is_out_of_reach_for_an_employee_and_for_a_client() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let employee = create_employee(&app, &root.token, "dev@roleblank.test", None).await;
    let contact = create_client_user(&app, &root.token, "contact@acme.test", None).await;

    for path in ["/api/v1/settings", "/api/v1/feature-flags"] {
        app.get(path, Some(&employee.token))
            .await
            .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");
        // `settings.*` is INTERNAL-only, so an external principal is refused at the
        // envelope and the refusal is shaped as a 404.
        app.get(path, Some(&contact.token))
            .await
            .assert_error(StatusCode::NOT_FOUND, "RESOURCE_NOT_FOUND");
    }

    app.put(
        "/api/v1/feature-flags/chat",
        Some(&employee.token),
        json!({"enabled": true, "version": 1}),
    )
    .await
    .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");
}

// ===========================================================================
// System and health
// ===========================================================================

/// Liveness answers "should the supervisor restart this process?" and performs no
/// database call at all — a database outage must not turn into a crash loop.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_health_probes_are_anonymous_uncacheable_and_disclose_one_word() {
    let app = TestApp::spawn().await;

    for path in ["/health/live", "/health/ready"] {
        let probe = app.get(path, None).await;
        probe.assert_status(StatusCode::OK).assert_no_secrets();
        assert_eq!(probe.json(), &json!({"status": "ok"}));
        // A cached `ok` from a proxy would keep routing traffic to a process that
        // has since lost its database.
        assert!(
            probe
                .headers
                .get(header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .contains("no-store"),
            "a probe response must never be cached"
        );
        // A readiness body that names its dependencies is free reconnaissance.
        let object = probe.json().as_object().expect("object");
        assert_eq!(object.len(), 1);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn readiness_reports_not_ready_once_the_database_is_gone() {
    let app = TestApp::spawn().await;
    app.get("/health/ready", None)
        .await
        .assert_status(StatusCode::OK);

    // Closing the pool is the closest a test can get to "the database went away"
    // without racing the container. The body must still be one of the two fixed
    // documents — no driver message, no hostname, no schema version.
    app.db.close().await;

    let probe = app.get("/health/ready", None).await;
    probe
        .assert_status(StatusCode::SERVICE_UNAVAILABLE)
        .assert_no_secrets();
    assert_eq!(probe.json(), &json!({"status": "not_ready"}));

    // Liveness is unaffected: the process itself is fine.
    app.get("/health/live", None)
        .await
        .assert_status(StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_metrics_scrape_is_prometheus_text_and_carries_no_identifying_label() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    // Generate at least one labelled series through the real router.
    app.get("/api/v1/settings", Some(&root.token))
        .await
        .assert_status(StatusCode::OK);

    let scrape = app.get("/metrics", None).await;
    scrape.assert_status(StatusCode::OK).assert_no_secrets();
    assert_eq!(
        scrape
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("text/plain; version=0.0.4; charset=utf-8")
    );
    let body = String::from_utf8_lossy(&scrape.raw).to_string();
    assert!(body.contains("roleblank_http_requests_total"));

    // Metric labels are unbounded cardinality *and* they end up in a monitoring
    // system with a weaker access-control model than this one, so no principal
    // identifier may appear in them.
    assert!(!body.contains(&root.user_id.to_string()));
    assert!(!body.contains(&root.email));
    assert!(!body.contains(&root.token));
}

/// Disabled means `404`, not `403`: an operator who turned the scrape off should
/// not have its existence confirmed to a prober.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_disabled_metrics_endpoint_does_not_exist() {
    let mut app = TestApp::spawn().await;
    let mut config = (*app.state.config).clone();
    config.metrics_enabled = false;
    app.state.config = Arc::new(config);

    app.get("/metrics", None)
        .await
        .assert_error(StatusCode::NOT_FOUND, "RESOURCE_NOT_FOUND");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn system_info_needs_authentication_and_exposes_three_members() {
    let app = TestApp::spawn().await;

    app.get("/api/v1/system/info", None)
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "AUTHENTICATION_FAILED");

    let root = bootstrap_root(&app).await;
    let info = app.get("/api/v1/system/info", Some(&root.token)).await;
    info.assert_status(StatusCode::OK).assert_no_secrets();
    let object = info.json().as_object().expect("object");
    let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, vec!["enabled_features", "environment", "initialized"]);
    assert_eq!(info.json()["initialized"], json!(true));
    // Keys only — never the description, never the sensitivity marker, and never a
    // key that *carries* the marker. `client_portal` is the one enabled flag in the
    // seeded set and it is security-sensitive, so this endpoint reports nothing:
    // the filter is applied in the query, which is why an unauthorised caller never
    // has the key in memory. `GET /api/v1/feature-flags` is where a principal
    // holding `settings.security.write` reads the sensitive rows.
    assert_eq!(info.json()["enabled_features"], json!([]));

    // Now enable a flag that is *not* security-sensitive, so the two audiences can
    // actually be told apart. Without this the endpoint returns an empty list to
    // everybody and the envelope below would pass for the wrong reason.
    sqlx::query(
        "INSERT INTO feature_flags (key, description, enabled, is_security_sensitive)
         VALUES ('new_onboarding', 'rollout switch', true, false)",
    )
    .execute(&app.db)
    .await
    .expect("seed a non-sensitive flag");

    let internal = app.get("/api/v1/system/info", Some(&root.token)).await;
    internal.assert_status(StatusCode::OK);
    assert_eq!(
        internal.json()["enabled_features"],
        json!(["new_onboarding"]),
        "an internal principal should see ordinary rollout flags"
    );

    // The client envelope stops there. A flag does not have to be marked
    // security-sensitive to be a company-internal fact — a rollout switch names
    // work in progress — so an external principal gets the deployment identity and
    // nothing else.
    let contact = create_client_user(&app, &root.token, "contact@acme.test", None).await;
    let as_client = app.get("/api/v1/system/info", Some(&contact.token)).await;
    as_client.assert_status(StatusCode::OK);
    assert_eq!(
        as_client.json()["enabled_features"],
        json!([]),
        "an external principal was handed the internal capability list"
    );
    // The other two fields are deliberately identical for both audiences.
    assert_eq!(
        as_client.json()["environment"],
        internal.json()["environment"]
    );
    assert_eq!(
        as_client.json()["initialized"],
        internal.json()["initialized"]
    );
}

// ===========================================================================
// Audit
// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_audit_listing_supports_every_documented_filter() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let department = create_department(&app, &root.token, "ops", "Operations").await;
    let project = create_project(&app, &root.token, "rollout", root.user_id, None).await;

    let all = app.get("/api/v1/audit/events", Some(&root.token)).await;
    all.assert_status(StatusCode::OK).assert_no_secrets();
    assert!(!all.json()["items"].as_array().expect("items").is_empty());

    // Chain material is integrity data, not business data: a reader cannot check it
    // without the chain key, and publishing it hands a would-be tamperer the exact
    // digests to reproduce.
    for item in all.json()["items"].as_array().expect("items") {
        for forbidden in ["entry_hash", "prev_hash", "hash"] {
            assert!(
                item.get(forbidden).is_none(),
                "`{forbidden}` reached an ordinary audit reader"
            );
        }
    }

    let by_action = app
        .get(
            "/api/v1/audit/events?action_code=DEPARTMENT.CREATED",
            Some(&root.token),
        )
        .await;
    by_action.assert_status(StatusCode::OK);
    let items = by_action.json()["items"].as_array().expect("items").clone();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["target_id"], json!(department.to_string()));
    let event_id = Uuid::parse_str(items[0]["id"].as_str().expect("an id")).expect("a UUID");

    for query in [
        format!("actor_user_id={}", root.user_id),
        "target_type=PROJECT".to_string(),
        format!("target_id={project}"),
        "outcome=SUCCESS".to_string(),
        "occurred_from=2020-01-01T00:00:00Z".to_string(),
        "occurred_to=2099-01-01T00:00:00Z".to_string(),
        "limit=2&sort=occurred_at&direction=asc".to_string(),
    ] {
        let filtered = app
            .get(&format!("/api/v1/audit/events?{query}"), Some(&root.token))
            .await;
        filtered.assert_status(StatusCode::OK);
        assert!(
            !filtered.json()["items"]
                .as_array()
                .expect("items")
                .is_empty(),
            "the filter `{query}` matched nothing"
        );
    }

    // A filter that matches nothing is an empty page, not an error.
    let none = app
        .get(
            "/api/v1/audit/events?action_code=MFA.DISABLED",
            Some(&root.token),
        )
        .await;
    none.assert_status(StatusCode::OK);
    assert!(none.json()["items"].as_array().expect("items").is_empty());

    let one = app
        .get(
            &format!("/api/v1/audit/events/{event_id}"),
            Some(&root.token),
        )
        .await;
    one.assert_status(StatusCode::OK).assert_no_secrets();
    assert_eq!(one.str_at("/action_code"), "DEPARTMENT.CREATED");
    assert!(one.json()["seq"].as_i64().expect("a sequence") > 0);
}

/// Every one of these would be dangerous if it were interpolated, and each must be
/// refused by the allowlist before it becomes a bind parameter — and the rejected
/// value must not be echoed back into a response a client renders and a log stores.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_audit_filters_refuse_malformed_and_hostile_values_without_echoing_them() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;

    for query in [
        "action_code=user.created",
        // Percent-encoded because the harness builds a real `Uri`, which refuses
        // raw quotes and spaces before the request is even dispatched.
        "action_code=USER.CREATED%27%3B%20DROP%20TABLE%20audit_events--",
        "action_code=%25",
        "target_type=PROJECT.TASK",
        "actor_user_id=not-a-uuid",
        "target_id=1",
        "outcome=ok",
        "occurred_from=yesterday",
        "occurred_from=2026-06-01T00:00:00Z&occurred_to=2026-01-01T00:00:00Z",
        "limit=0",
        "sort=seq",
    ] {
        let refused = app
            .get(&format!("/api/v1/audit/events?{query}"), Some(&root.token))
            .await;
        refused.assert_error(StatusCode::BAD_REQUEST, "VALIDATION_FAILED");
        let body = String::from_utf8_lossy(&refused.raw);
        assert!(
            !body.contains("DROP"),
            "the rejected input was echoed: {body}"
        );
    }

    // An unrecognised parameter is refused rather than ignored.
    app.get(
        "/api/v1/audit/events?action_code_like=USER.%25",
        Some(&root.token),
    )
    .await
    .assert_error(StatusCode::BAD_REQUEST, "BAD_REQUEST");

    // A malformed id cannot name a record, so it is indistinguishable from one that
    // does not exist rather than reflecting the caller's input back.
    app.get("/api/v1/audit/events/not-a-uuid", Some(&root.token))
        .await
        .assert_error(StatusCode::NOT_FOUND, "RESOURCE_NOT_FOUND");
    app.get(
        &format!("/api/v1/audit/events/{}", Uuid::now_v7()),
        Some(&root.token),
    )
    .await
    .assert_error(StatusCode::NOT_FOUND, "RESOURCE_NOT_FOUND");
}

/// Verification is a bulk cryptographic scan of the integrity record, and running
/// it is how one would learn whether tampering has already been noticed — so it
/// costs an auditor one prompt and a stolen session the whole capability.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chain_verification_requires_a_second_factor_and_reports_the_window_it_covered() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    create_department(&app, &root.token, "ops", "Operations").await;

    let verified = app.get("/api/v1/audit/verify", Some(&root.token)).await;
    verified.assert_status(StatusCode::OK).assert_no_secrets();
    assert_eq!(verified.str_at("/outcome"), "INTACT");
    assert_eq!(verified.json()["reached_chain_head"], json!(true));
    assert!(
        verified.json()["entries_checked"]
            .as_u64()
            .expect("a count")
            > 0
    );
    // `INTACT` over a window is not `INTACT` over history, so the window is stated.
    assert!(verified.json()["checked_from_seq"].as_i64().expect("seq") >= 1);
    // Absent diagnostics are omitted entirely rather than serialised as null.
    assert!(verified.json().get("diagnostics").is_none());
    assert!(verified.json().get("first_divergent_seq").is_none());

    for query in [
        "limit=0",
        "limit=100001",
        "limit=abc",
        "from_seq=0",
        "from_seq=x",
    ] {
        app.get(&format!("/api/v1/audit/verify?{query}"), Some(&root.token))
            .await
            .assert_error(StatusCode::BAD_REQUEST, "VALIDATION_FAILED");
    }
    app.get("/api/v1/audit/verify?everything=true", Some(&root.token))
        .await
        .assert_error(StatusCode::BAD_REQUEST, "BAD_REQUEST");

    // An auditor who holds `audit.read` but has not just proved a second factor may
    // read history and may not scan it.
    let auditor = create_employee(&app, &root.token, "auditor@roleblank.test", None).await;
    let role = create_role(
        &app,
        &root.token,
        "auditor",
        "INTERNAL",
        &[("audit.read", "GLOBAL")],
    )
    .await;
    app.post(
        &format!("/api/v1/users/{}/roles", auditor.user_id),
        Some(&root.token),
        json!({"role_id": role}),
    )
    .await
    .assert_status(StatusCode::CREATED);

    app.get("/api/v1/audit/events", Some(&auditor.token))
        .await
        .assert_status(StatusCode::OK);
    app.get("/api/v1/audit/verify", Some(&auditor.token))
        .await
        .assert_error(StatusCode::FORBIDDEN, "STEP_UP_REQUIRED");

    enrol_mfa(&app, &auditor.token).await;
    app.get("/api/v1/audit/verify", Some(&auditor.token))
        .await
        .assert_status(StatusCode::OK);
}

/// Audit history has no department and no owner, so reading it is all-or-nothing
/// and only a GLOBAL grant reaches it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audit_history_is_out_of_reach_without_a_global_grant() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let employee = create_employee(&app, &root.token, "dev@roleblank.test", None).await;
    let contact = create_client_user(&app, &root.token, "contact@acme.test", None).await;

    app.get("/api/v1/audit/events", Some(&employee.token))
        .await
        .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");
    app.get("/api/v1/audit/verify", Some(&employee.token))
        .await
        .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");
    app.get("/api/v1/audit/events", Some(&contact.token))
        .await
        .assert_error(StatusCode::NOT_FOUND, "RESOURCE_NOT_FOUND");

    // There is no mutating audit route at all: history is appended only by the
    // transaction of the change it describes.
    for (method, body) in [("post", json!({})), ("patch", json!({}))] {
        let response = if method == "post" {
            app.post("/api/v1/audit/events", Some(&root.token), body)
                .await
        } else {
            app.patch("/api/v1/audit/events", Some(&root.token), body)
                .await
        };
        assert_eq!(response.status, StatusCode::METHOD_NOT_ALLOWED);
    }
}
