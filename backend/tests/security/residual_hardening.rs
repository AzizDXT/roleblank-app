//! The attacks the LOW and INFO findings said were still available.
//!
//! Every other suite in this directory is named for a boundary. This one is named
//! for a *state of the report*: it holds the regressions for the residue the final
//! acceptance audit left open — the findings that were individually harmless and
//! collectively a description of where the second layer was missing.
//!
//! They are grouped rather than distributed because each one is a single assertion
//! about a single fix, and because their common property is the thing worth
//! preserving: **none of these was exploitable, and every one of them fails without
//! its fix.** A test that passes both before and after would be documentation, not
//! a regression.
//!
//! The disposition of each finding — fixed, accepted, or reclassified — is recorded
//! in `docs/backend/audit/LOW_INFO_DISPOSITION.md`, and each test below names the
//! finding it closes.

use axum::http::StatusCode;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::common::TestApp;
use crate::fixtures::{login, password_hash, seed_user, unknown_id, World};

// ===========================================================================
// L1 — dangerous authority granted to an existing account must mandate MFA
//
// `catalog::PermissionDef::is_dangerous` promises that holding such a permission
// "mandates that the holder has MFA enrolled". That was implemented only at
// invitation acceptance. Granting the same authority to an account that already
// existed imposed nothing: the grant was audited as a success, the grantee could
// not use it, and neither party was told why.
// ===========================================================================

/// Create a role whose contents are dangerous, so the grant paths have something
/// real to react to. `iam.roles.assign` is flagged dangerous in the catalogue.
async fn dangerous_role(w: &World) -> Uuid {
    let created = w
        .app
        .post(
            "/api/v1/roles",
            w.root.bearer(),
            json!({
                "code": "danger_role",
                "name": "Dangerous Role",
                "allowed_principal_type": "INTERNAL",
                "permissions": [{"permission_code": "iam.roles.assign", "scope": "GLOBAL"}],
            }),
        )
        .await;
    created.assert_status(StatusCode::CREATED);
    created.id_at("/id")
}

async fn mfa_required_for(app: &TestApp, user_id: Uuid) -> bool {
    let row: (bool,) = sqlx::query_as("SELECT mfa_required FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&app.db)
        .await
        .expect("read mfa_required");
    row.0
}

/// L1. Assigning a role that carries a dangerous permission puts the subject into
/// the enrolment-required state, and their next login proves it.
#[tokio::test]
async fn assigning_a_dangerous_role_mandates_a_second_factor() {
    let w = World::build().await;
    let hash = password_hash(&w.app).await;
    let subject = seed_user(&w.app, "grantee@fixture.test", "INTERNAL", &hash).await;

    assert!(
        !mfa_required_for(&w.app, subject).await,
        "the fixture account already required MFA, which would make this vacuous"
    );

    let role_id = dangerous_role(&w).await;
    w.app
        .post(
            &format!("/api/v1/users/{subject}/roles"),
            w.root.bearer(),
            json!({ "role_id": role_id }),
        )
        .await
        .assert_status(StatusCode::CREATED);

    assert!(
        mfa_required_for(&w.app, subject).await,
        "a dangerous permission was granted without mandating a second factor"
    );

    // The flag is not decorative: the next session it produces is MFA-pending, so
    // the account cannot operate at all until a factor is enrolled.
    let token = login(&w.app, "grantee@fixture.test").await;
    let me = w.app.get("/api/v1/auth/me", Some(&token)).await;
    me.assert_status(StatusCode::OK);
    assert_eq!(
        me.json().get("mfa_required").and_then(Value::as_bool),
        Some(true),
        "the mandate did not reach the session"
    );

    // And the granter can see in the log that this grant is what imposed it.
    let mandated: (bool,) = sqlx::query_as(
        "SELECT (metadata->>'mfa_mandated')::boolean
           FROM audit_events
          WHERE action_code = 'ROLE.ASSIGNED' AND target_id = $1",
    )
    .bind(subject)
    .fetch_one(&w.app.db)
    .await
    .expect("read the assignment audit event");
    assert!(mandated.0, "the audit record did not report the mandate");
}

/// L1, the override half. An ALLOW override for a dangerous permission mandates
/// enrolment; a DENY of the same permission must not, because a DENY confers
/// nothing and imposing an authentication requirement for it would punish the
/// subject for authority being taken away.
#[tokio::test]
async fn a_dangerous_allow_override_mandates_a_second_factor_and_a_deny_does_not() {
    let w = World::build().await;
    let hash = password_hash(&w.app).await;
    let allowed = seed_user(&w.app, "allowed@fixture.test", "INTERNAL", &hash).await;
    let denied = seed_user(&w.app, "denied@fixture.test", "INTERNAL", &hash).await;

    w.app
        .post(
            &format!("/api/v1/users/{allowed}/permission-overrides"),
            w.root.bearer(),
            json!({"permission_code": "iam.roles.assign", "effect": "ALLOW", "scope": "GLOBAL"}),
        )
        .await
        .assert_status(StatusCode::CREATED);
    assert!(
        mfa_required_for(&w.app, allowed).await,
        "an ALLOW override for a dangerous permission did not mandate a second factor"
    );

    w.app
        .post(
            &format!("/api/v1/users/{denied}/permission-overrides"),
            w.root.bearer(),
            json!({"permission_code": "iam.roles.assign", "effect": "DENY", "scope": "GLOBAL"}),
        )
        .await
        .assert_status(StatusCode::CREATED);
    assert!(
        !mfa_required_for(&w.app, denied).await,
        "a DENY override imposed an enrolment requirement it does not justify"
    );
}

// ===========================================================================
// F-05 — the extractor, not the service, excludes a pending session
// ===========================================================================

/// `/mfa/disable` and `/mfa/recovery/regenerate` weaken the second factor, so a
/// password-only session must not reach the handler at all. The services still
/// call `require_step_up`; this asserts the *extractor* refuses first, which is
/// what makes the exclusion a property of the type rather than of one line in a
/// service that a future edit could move.
#[tokio::test]
async fn a_pending_session_is_refused_by_the_extractor_on_the_mfa_weakening_routes() {
    let w = World::build().await;
    let hash = password_hash(&w.app).await;
    let subject = seed_user(&w.app, "pending@fixture.test", "INTERNAL", &hash).await;

    // Mandate MFA without enrolling one: every session this account opens is
    // pending, which is exactly the state these two routes must not serve.
    sqlx::query("UPDATE users SET mfa_required = true WHERE id = $1")
        .bind(subject)
        .execute(&w.app.db)
        .await
        .expect("mandate MFA");

    let token = login(&w.app, "pending@fixture.test").await;
    let bearer = Some(token.as_str());

    // The pending state is real: an MFA route that *should* be reachable is.
    w.app
        .post("/api/v1/auth/mfa/totp/setup", bearer, json!({}))
        .await
        .assert_status(StatusCode::CREATED);

    for path in [
        "/api/v1/auth/mfa/disable",
        "/api/v1/auth/mfa/recovery/regenerate",
    ] {
        // `MFA_REQUIRED` is the extractor's refusal. `STEP_UP_REQUIRED` would mean
        // the request reached the service — safe today, but by a different
        // mechanism than the route table declares.
        w.app
            .post(path, bearer, json!({}))
            .await
            .assert_error(StatusCode::FORBIDDEN, "MFA_REQUIRED");
    }
}

// ===========================================================================
// F-08 — a refused listing must be metered and logged like any other denial
// ===========================================================================

/// Counts the `authz_denials_total` series in the rendered exposition.
fn denial_total(app: &TestApp) -> u64 {
    app.state
        .metrics
        .render()
        .lines()
        .filter(|line| line.starts_with("roleblank_authz_denials_total{"))
        .filter_map(|line| line.rsplit(' ').next()?.parse::<u64>().ok())
        .sum()
}

/// F-08. Four listing paths raised `AuthorizationDenied` directly instead of going
/// through `state.require`, which is the only place the denial metric is
/// incremented and the `"authorization denied"` log line is emitted. A refused
/// listing is what an enumeration sweep looks like, and it was invisible.
#[tokio::test]
async fn a_refused_listing_is_counted_like_every_other_denial() {
    let w = World::build().await;

    for (who, path) in [
        // An external client holds no internal read permission at all.
        (w.client_a.bearer(), "/api/v1/projects"),
        (w.client_a.bearer(), "/api/v1/tasks"),
        // An internal employee holds no portal permission and never can.
        (w.employee.bearer(), "/api/v1/client-portal/projects"),
    ] {
        let before = denial_total(&w.app);
        let refused = w.app.get(path, who).await;
        assert!(
            refused.status.is_client_error(),
            "`{path}` was not refused, so the metric assertion below proves nothing"
        );
        assert!(
            denial_total(&w.app) > before,
            "the refusal of `{path}` was not counted as an authorisation denial"
        );
    }
}

// ===========================================================================
// F-09 — `GET /system/info` must not name the security-sensitive flags
// ===========================================================================

/// F-09. The endpoint authenticates and nothing else, and its body is served whole
/// to an external CLIENT. The sensitivity marker exists to say "this toggle is
/// worth attacking"; returning the key it marks handed out the target list.
#[tokio::test]
async fn system_info_names_ordinary_feature_flags_and_never_the_sensitive_ones() {
    let w = World::build().await;

    // The seeded set has exactly one enabled flag and it is sensitive, so a filter
    // and a blanket refusal would be indistinguishable. Enable a non-sensitive one
    // to tell them apart: the fix must be a filter, not an empty list.
    sqlx::query("UPDATE feature_flags SET enabled = true WHERE key = 'chat'")
        .execute(&w.app.db)
        .await
        .expect("enable a non-sensitive flag");

    // Asserted against an *internal* principal on purpose. An external one is
    // separately given an empty list, so testing the filter through a CLIENT would
    // pass whether the filter existed or not.
    let info = w.app.get("/api/v1/system/info", w.employee.bearer()).await;
    info.assert_status(StatusCode::OK);
    let features = info.json()["enabled_features"]
        .as_array()
        .expect("enabled_features is a list")
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();

    assert!(
        features.contains(&"chat"),
        "the endpoint stopped reporting enabled flags entirely: {features:?}"
    );
    assert!(
        !features.contains(&"client_portal"),
        "a security-sensitive flag key was published to a principal who may not \
         read the feature-flag surface: {features:?}"
    );

    // And nothing at all crosses the client envelope.
    let as_client = w.app.get("/api/v1/system/info", w.client_a.bearer()).await;
    as_client.assert_status(StatusCode::OK);
    let client_features = as_client.json()["enabled_features"]
        .as_array()
        .expect("enabled_features is a list");
    assert!(
        !client_features
            .iter()
            .filter_map(Value::as_str)
            .any(|key| key == "client_portal"),
        "a security-sensitive flag key crossed the client envelope: {client_features:?}"
    );
}

// ===========================================================================
// F-10 — a collection-level decision must not be taken after an existence check
// ===========================================================================

/// F-10. `GET/PATCH/DELETE /roles/{id}` and `DELETE /invitations/{id}` loaded the
/// row before authorising against `Target::Collection`, so an unauthorised
/// *internal* principal could tell a real identifier (`403`) from an invented one
/// (`404`). External principals were never affected; this is the internal half.
#[tokio::test]
async fn an_unauthorised_principal_cannot_tell_a_real_role_from_an_invented_one() {
    let w = World::build().await;
    let invented = unknown_id();

    // The baseline employee holds no `iam.roles.*` authority whatsoever.
    let bearer = w.employee.bearer();

    let real_get = w
        .app
        .get(
            &format!("/api/v1/roles/{}", crate::fixtures::ROLE_EMPLOYEE),
            bearer,
        )
        .await;
    let fake_get = w
        .app
        .get(&format!("/api/v1/roles/{invented}"), bearer)
        .await;
    assert_eq!(
        (real_get.status, real_get.error_code()),
        (fake_get.status, fake_get.error_code()),
        "a real role id answered differently from an invented one"
    );

    let real_delete = w
        .app
        .delete(
            &format!("/api/v1/roles/{}", crate::fixtures::ROLE_EMPLOYEE),
            bearer,
        )
        .await;
    let fake_delete = w
        .app
        .delete(&format!("/api/v1/roles/{invented}"), bearer)
        .await;
    assert_eq!(
        (real_delete.status, real_delete.error_code()),
        (fake_delete.status, fake_delete.error_code()),
        "a real role id answered differently from an invented one on delete"
    );

    // Invitations: the same shape, on a row the employee may not even know exists.
    let invitation = w
        .app
        .post(
            "/api/v1/invitations",
            w.root.bearer(),
            json!({
                "email": "invitee@fixture.test",
                "display_name": "Invitee",
                "principal_type": "INTERNAL",
                "role_ids": [crate::fixtures::ROLE_EMPLOYEE],
            }),
        )
        .await;
    invitation.assert_status(StatusCode::CREATED);
    let invitation_id = invitation.id_at("/id");

    let real = w
        .app
        .delete(&format!("/api/v1/invitations/{invitation_id}"), bearer)
        .await;
    let fake = w
        .app
        .delete(&format!("/api/v1/invitations/{invented}"), bearer)
        .await;
    assert_eq!(
        (real.status, real.error_code()),
        (fake.status, fake.error_code()),
        "a real invitation id answered differently from an invented one"
    );
}

// ===========================================================================
// F-13 — one path-identifier grammar, not three
// ===========================================================================

/// F-13. `authorization::routes` trimmed its path segments and
/// `platform::http::extract` deliberately did not, so `/roles/%20{uuid}%20` was a
/// `200` while `/departments/%20{uuid}%20` was a `400` — with a test on each side
/// pinning its own behaviour, so neither module would ever notice the other.
#[tokio::test]
async fn every_module_parses_a_path_identifier_with_the_same_grammar() {
    let w = World::build().await;
    let bearer = w.root.bearer();
    let padded = format!("%20{}%20", crate::fixtures::ROLE_EMPLOYEE);

    // The unpadded form is genuinely reachable for this actor, so a refusal below
    // is about the padding and not about authority.
    w.app
        .get(
            &format!("/api/v1/roles/{}", crate::fixtures::ROLE_EMPLOYEE),
            bearer,
        )
        .await
        .assert_status(StatusCode::OK);

    for path in [
        format!("/api/v1/roles/{padded}"),
        format!("/api/v1/departments/{padded}"),
        format!("/api/v1/users/{padded}/roles"),
    ] {
        w.app
            .get(&path, bearer)
            .await
            .assert_error(StatusCode::BAD_REQUEST, "VALIDATION_FAILED");
    }

    // The audit route keeps its own "a malformed id is a 404" contract, but the
    // *acceptance set* is now the same: a padded id names no record.
    let event: (Uuid,) = sqlx::query_as("SELECT id FROM audit_events ORDER BY seq DESC LIMIT 1")
        .fetch_one(&w.app.db)
        .await
        .expect("at least one audit event exists");
    w.app
        .get(&format!("/api/v1/audit/events/{}", event.0), bearer)
        .await
        .assert_status(StatusCode::OK);
    w.app
        .get(&format!("/api/v1/audit/events/%20{}%20", event.0), bearer)
        .await
        .assert_status(StatusCode::NOT_FOUND);
}

// ===========================================================================
// F-2 (§3–6) — the ROOT guard must be the first check in `delete_override`
// ===========================================================================

/// The owner can hold no override, so this route always refused — but as a `404`
/// produced by a lookup, not as a guard. The refusal was therefore recorded as an
/// ordinary `AUTHORIZATION.DENIED` and never reached the ROOT alerting feed, and
/// the invariant rested on an argument about bootstrap ordering rather than on a
/// check.
#[tokio::test]
async fn deleting_an_override_from_the_owner_is_refused_as_root_protection() {
    let w = World::build().await;
    let invented = unknown_id();

    // The administrator genuinely holds `iam.permissions.delegate@GLOBAL` and a
    // recent second factor, so the only thing that can refuse this is the ROOT
    // guard itself.
    w.app
        .delete(
            &format!(
                "/api/v1/users/{}/permission-overrides/{invented}",
                w.root.id
            ),
            w.admin.bearer(),
        )
        .await
        .assert_error(StatusCode::FORBIDDEN, "ROOT_PROTECTED");

    let recorded: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM audit_events
          WHERE action_code = 'ROOT.PROTECTION_TRIGGERED'
            AND target_id = $1
            AND metadata->>'operation' = 'override.delete'",
    )
    .bind(w.root.id)
    .fetch_one(&w.app.db)
    .await
    .expect("count root protection events");
    assert_eq!(
        recorded.0, 1,
        "the attempt on the owner did not reach the ROOT alerting feed"
    );
}

// ===========================================================================
// F-12 — cancellation has its own action code
// ===========================================================================

/// An auditor filtering `action_code = TASK.CANCELLED` used to get an empty page
/// and the reasonable conclusion that nothing had been cancelled.
#[tokio::test]
async fn cancelling_a_task_is_recorded_under_its_own_action_code() {
    let w = World::build().await;

    w.app
        .delete(
            &format!("/api/v1/tasks/{}", w.internal_task),
            w.root.bearer(),
        )
        .await
        .assert_status(StatusCode::NO_CONTENT);

    let counts: (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM audit_events
                  WHERE action_code = 'TASK.CANCELLED' AND target_id = $1),
                (SELECT count(*) FROM audit_events
                  WHERE action_code = 'TASK.UPDATED' AND target_id = $1)",
    )
    .bind(w.internal_task)
    .fetch_one(&w.app.db)
    .await
    .expect("count the task audit events");

    assert_eq!(counts.0, 1, "the cancellation has no TASK.CANCELLED record");
    assert_eq!(
        counts.1, 0,
        "the cancellation is still also recorded as an ordinary update"
    );
}

// ===========================================================================
// F-11 — `/mfa/disable` is metered like every other MFA endpoint
// ===========================================================================

/// It was the only endpoint in the sensitive set with no limiter, and it is the one
/// that turns the second factor off.
#[tokio::test]
async fn disabling_the_second_factor_is_rate_limited() {
    let w = World::build().await;
    let quota = w.app.state.config.rate_limits.mfa_per_session_per_minute;

    // ROOT has an enrolled factor and a recent step-up, so every attempt reaches
    // the limiter. `mfa_required` is set for the owner, so each attempt that gets
    // past it is refused with `MFA_MANDATORY` rather than actually disabling
    // anything — which is what makes this safe to repeat.
    let mut limited = false;
    for _ in 0..=quota {
        let response = w
            .app
            .post("/api/v1/auth/mfa/disable", w.root.bearer(), json!({}))
            .await;
        if response.status == StatusCode::TOO_MANY_REQUESTS {
            limited = true;
            break;
        }
    }
    assert!(
        limited,
        "`/auth/mfa/disable` accepted more than its per-minute quota"
    );
}

/// `expires_at` was written on every idempotency record and read by nothing, while
/// three documents asserted that a scheduled sweep deleted on it. The table grew
/// one row per mutating request forever. This pins the sweep that now exists.
#[tokio::test]
async fn expired_idempotency_records_are_swept() {
    use roleblank_backend::modules::outbox::idempotency;

    let app = TestApp::spawn().await;

    // One already expired, one still live.
    for (key, expires) in [("expired-key", "-1 hour"), ("live-key", "1 hour")] {
        sqlx::query(
            "INSERT INTO idempotency_records
                 (id, principal_id, operation, idempotency_key, request_fingerprint,
                  status, expires_at)
             VALUES ($1, $2, 'test.op', $3, decode(repeat('ab', 32), 'hex'),
                     'IN_PROGRESS', now() + $4::interval)",
        )
        .bind(Uuid::now_v7())
        .bind(Uuid::now_v7())
        .bind(key)
        .bind(expires)
        .execute(&app.db)
        .await
        .expect("seed an idempotency record");
    }

    let removed = idempotency::sweep_expired(&app.db, 500)
        .await
        .expect("sweep must succeed");
    assert_eq!(removed, 1, "the sweep removed the wrong number of rows");

    let remaining: Vec<String> =
        sqlx::query_scalar("SELECT idempotency_key FROM idempotency_records ORDER BY 1")
            .fetch_all(&app.db)
            .await
            .expect("read remaining");
    assert_eq!(
        remaining,
        vec!["live-key".to_string()],
        "the sweep deleted a record that had not expired"
    );
}
