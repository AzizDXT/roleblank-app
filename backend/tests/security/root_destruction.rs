//! §3 — destroying the system owner, attempted at **every layer**.
//!
//! `root_attack.rs` drives the HTTP surface. This suite exists because a refusal
//! at one layer proves nothing about the others, and the ownership invariant
//! (ADR-004) is claimed to hold at four of them independently:
//!
//!   1. the **route** — no request shape reaches a destructive handler;
//!   2. the **service** — the guard lives in the service function, so a future
//!      route, a CLI command or a background job that calls it is guarded too;
//!   3. the **runtime database role** — even code execution inside the API process
//!      cannot write the rows, because `roleblank_app` holds no such privilege;
//!   4. the **trigger** — even a connection that *does* hold the privilege is
//!      refused by the database itself.
//!
//! A test that only ever speaks HTTP cannot tell layer 1 from layers 2–4. Each
//! section below therefore attacks one specific layer and says which.
//!
//! Every test finishes at `assert_owner_survives`: exactly one ownership row, and
//! the owner still `ACTIVE` / `INTERNAL` / `mfa_required`. A `403` that still wrote
//! the row would be worse than no check at all.

use axum::http::{Method, StatusCode};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

use crate::common::{TestApp, TEST_PASSWORD};
use crate::fixtures::{login, World, ROLE_CLIENT_USER, ROLE_EMPLOYEE};

use roleblank_backend::modules::authentication::principal::{authenticate, Principal};
use roleblank_backend::modules::authorization::dto as authz_dto;
use roleblank_backend::modules::authorization::service as authz_service;
use roleblank_backend::modules::identity::dto as identity_dto;
use roleblank_backend::modules::identity::service as identity_service;
use roleblank_backend::platform::errors::AppError;
use roleblank_backend::platform::http::extract::Authenticated;

// ===========================================================================
// The invariant, stated once
// ===========================================================================

/// The complete final state every test in this file must leave behind.
///
/// Asserted as one function rather than as scattered `assert!`s so that adding a
/// component of the invariant automatically strengthens every test at once.
async fn assert_owner_survives(app: &TestApp, root_id: Uuid) {
    let owners: (i64,) = sqlx::query_as("SELECT count(*) FROM system_ownership")
        .fetch_one(&app.db)
        .await
        .expect("count ownership rows");
    assert_eq!(
        owners.0, 1,
        "there must be exactly one ownership row, found {}",
        owners.0
    );

    let owner: (Uuid,) = sqlx::query_as("SELECT root_user_id FROM system_ownership")
        .fetch_one(&app.db)
        .await
        .expect("read ownership");
    assert_eq!(owner.0, root_id, "ownership moved to another account");

    let row: (String, String, bool) =
        sqlx::query_as("SELECT status, principal_type, mfa_required FROM users WHERE id = $1")
            .bind(root_id)
            .fetch_one(&app.db)
            .await
            .expect("the owner's row must still exist");
    assert_eq!(row.0, "ACTIVE", "the owner is no longer ACTIVE");
    assert_eq!(row.1, "INTERNAL", "the owner crossed the client envelope");
    assert!(row.2, "MFA was made optional for the owner");
}

/// Did this statement fail? A destructive statement that *succeeds* is the finding.
#[track_caller]
fn assert_refused<T>(outcome: Result<T, sqlx::Error>, what: &str) {
    assert!(
        outcome.is_err(),
        "the database ACCEPTED `{what}` — the ownership invariant is not enforced at this layer"
    );
}

/// Resolve a bearer token into the same `Principal` the extractors build.
///
/// This is what lets the service-layer section call the guarded functions with a
/// genuine actor rather than a hand-assembled one: a fabricated `ActorContext`
/// would be testing the test's idea of an administrator, not the system's.
async fn principal_for(db: &PgPool, token: &str) -> Principal {
    authenticate(db, token)
        .await
        .expect("the fixture token must authenticate")
}

// ===========================================================================
// Layer 1 — the route surface
// ===========================================================================

/// Bulk and mass-mutation shapes. None of these routes exists, and the point of
/// the test is that none of them *appears* later without a reviewer noticing.
///
/// A bulk endpoint is the classic way a per-object guard is lost: the guard is
/// written into the single-object handler and the batch handler loops over ids
/// without it.
#[tokio::test]
async fn no_bulk_or_mass_mutation_route_can_reach_the_owner() {
    let w = World::build().await;

    let bulk: Vec<(Method, String, serde_json::Value)> = vec![
        (
            Method::POST,
            "/api/v1/users/bulk".into(),
            json!({"ids": [w.root.id, w.employee.id], "action": "SUSPEND"}),
        ),
        (
            Method::POST,
            "/api/v1/users/bulk-suspend".into(),
            json!({"user_ids": [w.root.id]}),
        ),
        (
            Method::POST,
            "/api/v1/users/bulk-archive".into(),
            json!({"user_ids": [w.root.id]}),
        ),
        (
            Method::POST,
            "/api/v1/users/batch".into(),
            json!({"operations": [{"id": w.root.id, "op": "archive"}]}),
        ),
        (
            Method::DELETE,
            "/api/v1/users".into(),
            json!({"ids": [w.root.id]}),
        ),
        (
            Method::PATCH,
            "/api/v1/users".into(),
            json!({"status": "SUSPENDED"}),
        ),
        (
            Method::POST,
            format!("/api/v1/users/{}/delete", w.root.id),
            json!({}),
        ),
        (
            Method::POST,
            format!("/api/v1/users/{}/demote", w.root.id),
            json!({"principal_type": "CLIENT"}),
        ),
        (
            Method::POST,
            format!("/api/v1/users/{}/principal-type", w.root.id),
            json!({"principal_type": "CLIENT"}),
        ),
        (
            Method::POST,
            format!("/api/v1/users/{}/sessions/revoke", w.root.id),
            json!({}),
        ),
        (
            Method::DELETE,
            format!("/api/v1/users/{}/sessions", w.root.id),
            json!({}),
        ),
        (
            Method::POST,
            "/api/v1/system/ownership".into(),
            json!({"root_user_id": w.admin.id}),
        ),
        (
            Method::PUT,
            "/api/v1/system/ownership".into(),
            json!({"root_user_id": w.admin.id}),
        ),
        (
            Method::POST,
            "/api/v1/system/transfer-ownership".into(),
            json!({"to": w.admin.id}),
        ),
    ];

    for (method, path, body) in bulk {
        let response = match method {
            Method::POST => w.app.post(&path, w.admin.bearer(), body).await,
            Method::PUT => w.app.put(&path, w.admin.bearer(), body).await,
            Method::PATCH => w.app.patch(&path, w.admin.bearer(), body).await,
            _ => w.app.delete(&path, w.admin.bearer()).await,
        };
        assert!(
            response.status == StatusCode::NOT_FOUND
                || response.status == StatusCode::METHOD_NOT_ALLOWED,
            "{method} {path} answered {} — a mass-mutation route exists and was not reviewed",
            response.status
        );
        response.assert_no_secrets();
    }

    assert_owner_survives(&w.app, w.root.id).await;
}

/// Every documented HTTP method aimed at the owner's own resource paths.
///
/// The `PATCH`/`POST` cases are covered by `root_attack`; this one sweeps the
/// *whole* method space so that a handler added under an unexpected verb is
/// caught rather than discovered.
#[tokio::test]
async fn every_http_method_on_the_owners_resources_is_refused() {
    let w = World::build().await;

    let paths = [
        format!("/api/v1/users/{}", w.root.id),
        format!("/api/v1/users/{}/roles", w.root.id),
        format!("/api/v1/users/{}/permission-overrides", w.root.id),
        format!("/api/v1/users/{}/suspend", w.root.id),
        format!("/api/v1/users/{}/archive", w.root.id),
    ];

    for path in &paths {
        for method in [Method::PUT, Method::DELETE] {
            let response = match method {
                Method::PUT => w.app.put(path, w.admin.bearer(), json!({})).await,
                _ => w.app.delete(path, w.admin.bearer()).await,
            };
            assert_ne!(
                response.status,
                StatusCode::OK,
                "{method} {path} succeeded against the owner"
            );
            assert_ne!(
                response.status,
                StatusCode::NO_CONTENT,
                "{method} {path} succeeded against the owner"
            );
            response.assert_no_secrets();
        }
    }

    assert_owner_survives(&w.app, w.root.id).await;
}

/// The owner's principal type is the client envelope's anchor. Nothing may move it.
///
/// Three shapes are tried: a smuggled field on the profile update, a client role
/// assignment, and an invitation naming the owner's address.
#[tokio::test]
async fn the_owners_principal_type_cannot_be_changed_by_any_request_shape() {
    let w = World::build().await;

    // A smuggled field is a parse failure, not a silently ignored key.
    w.app
        .patch(
            &format!("/api/v1/users/{}", w.root.id),
            w.admin.bearer(),
            json!({"version": 1, "principal_type": "CLIENT"}),
        )
        .await
        .assert_error(StatusCode::BAD_REQUEST, "BAD_REQUEST");

    // Assigning a CLIENT-only role would move the owner across the envelope by the
    // back door. The ROOT guard fires before the principal-type mismatch is even
    // considered, which is the correct order: the owner is not a target at all.
    w.app
        .post(
            &format!("/api/v1/users/{}/roles", w.root.id),
            w.admin.bearer(),
            json!({"role_id": ROLE_CLIENT_USER}),
        )
        .await
        .assert_error(StatusCode::FORBIDDEN, "ROOT_PROTECTED");

    // An invitation to the owner's own address must not be able to re-type the
    // existing account. Either it is refused, or it creates an invitation that can
    // never be accepted — never a mutation of the owner.
    let invited = w
        .app
        .post(
            "/api/v1/invitations",
            w.admin.bearer(),
            json!({
                "email": w.root.email,
                "display_name": "Owner, but external",
                "principal_type": "CLIENT",
                "role_ids": [],
            }),
        )
        .await;
    assert!(
        invited.status.is_client_error(),
        "an invitation re-typed the owner's account: {}",
        String::from_utf8_lossy(&invited.raw)
    );

    assert_owner_survives(&w.app, w.root.id).await;
}

// ===========================================================================
// Layer 2 — the service functions, called directly
// ===========================================================================

/// The guard must live in the **service**, not in the route.
///
/// This test bypasses the router entirely and calls the same functions the
/// handlers call, with a genuine administrator principal. If the ROOT check had
/// been implemented as route middleware, every assertion below would fail — and a
/// future caller (a CLI command, an outbox job, a new endpoint) would have shipped
/// an unguarded path.
#[tokio::test]
async fn the_identity_service_refuses_the_owner_when_called_directly() {
    let w = World::build().await;
    let admin = Authenticated(principal_for(&w.app.db, &w.admin.token).await);

    let update = identity_service::update_user(
        &w.app.state,
        &admin,
        w.root.id,
        identity_dto::UpdateUserRequest {
            display_name: Some("Renamed by a direct call".into()),
            email: None,
            version: 1,
        },
    )
    .await;
    assert!(
        matches!(update, Err(AppError::RootProtected)),
        "identity_service::update_user did not refuse the owner: {:?}",
        update.map(|_| "Ok")
    );

    let suspend = identity_service::suspend_user(
        &w.app.state,
        &admin,
        w.root.id,
        identity_dto::SuspendUserRequest {
            version: 1,
            reason: None,
        },
    )
    .await;
    assert!(
        matches!(suspend, Err(AppError::RootProtected)),
        "identity_service::suspend_user did not refuse the owner"
    );

    let archive = identity_service::archive_user(
        &w.app.state,
        &admin,
        w.root.id,
        identity_dto::ArchiveUserRequest {
            version: 1,
            reason: None,
        },
    )
    .await;
    assert!(
        matches!(archive, Err(AppError::RootProtected)),
        "identity_service::archive_user did not refuse the owner"
    );

    let reactivate = identity_service::reactivate_user(
        &w.app.state,
        &admin,
        w.root.id,
        identity_dto::ReactivateUserRequest { version: 1 },
    )
    .await;
    assert!(
        matches!(reactivate, Err(AppError::RootProtected)),
        "identity_service::reactivate_user did not refuse the owner"
    );

    assert_owner_survives(&w.app, w.root.id).await;
}

/// The same, for the authorisation services — the ones that hand out authority.
///
/// The owner itself is used as the actor for the last two cases: ROOT bypasses
/// permission *evaluation*, so if the guard were expressed as "the actor needs a
/// permission the owner lacks" it would not hold against the owner. It must be a
/// property of the **subject**, and these assertions are what proves that.
#[tokio::test]
async fn the_authorisation_service_refuses_the_owner_when_called_directly() {
    let w = World::build().await;
    let admin = principal_for(&w.app.db, &w.admin.token).await;
    let root = principal_for(&w.app.db, &w.root.token).await;

    let role_id = Uuid::parse_str(ROLE_EMPLOYEE).expect("a fixture role id");

    for (label, actor) in [("an administrator", &admin), ("the owner itself", &root)] {
        let assigned = authz_service::assign_role(
            &w.app.state,
            actor,
            None,
            w.root.id,
            authz_dto::AssignRoleRequest { role_id },
        )
        .await;
        assert!(
            matches!(assigned, Err(AppError::RootProtected)),
            "assign_role called by {label} did not refuse the owner"
        );

        let unassigned =
            authz_service::unassign_role(&w.app.state, actor, None, w.root.id, role_id).await;
        assert!(
            matches!(unassigned, Err(AppError::RootProtected)),
            "unassign_role called by {label} did not refuse the owner"
        );

        for effect in ["ALLOW", "DENY"] {
            let created = authz_service::create_override(
                &w.app.state,
                actor,
                None,
                w.root.id,
                authz_dto::CreateOverrideRequest {
                    permission_code: "audit.read".into(),
                    effect: effect.into(),
                    scope: "GLOBAL".into(),
                    resource_type: None,
                    resource_id: None,
                    expires_at: None,
                    reason: None,
                },
            )
            .await;
            assert!(
                matches!(created, Err(AppError::RootProtected)),
                "create_override({effect}) called by {label} did not refuse the owner"
            );
        }

        // `delete_override` looks the override up *before* it reaches the ROOT
        // guard, so the owner — who can never hold one — is refused with
        // `NotFound` rather than `RootProtected`. The refusal is total either way,
        // which is what is asserted; the ordering is recorded as an observation in
        // the findings document rather than asserted as `RootProtected`, because
        // asserting the weaker code would freeze the weaker ordering in place.
        let deleted =
            authz_service::delete_override(&w.app.state, actor, None, w.root.id, Uuid::now_v7())
                .await;
        assert!(
            matches!(
                deleted,
                Err(AppError::RootProtected) | Err(AppError::NotFound)
            ),
            "delete_override called by {label} did not refuse the owner"
        );
    }

    let overrides: (i64,) =
        sqlx::query_as("SELECT count(*) FROM user_permission_overrides WHERE user_id = $1")
            .bind(w.root.id)
            .fetch_one(&w.app.db)
            .await
            .expect("count");
    assert_eq!(overrides.0, 0, "a direct service call wrote on the owner");

    assert_owner_survives(&w.app, w.root.id).await;
}

// ===========================================================================
// Layer 3 — the runtime database role
// ===========================================================================

/// The privilege boundary that survives arbitrary code execution in the API.
///
/// This is the layer that matters if an attacker reaches SQL execution inside the
/// running process: the connection the application holds is `roleblank_app`, and
/// these statements must fail on **privilege**, before any trigger is consulted.
/// It is run against a live, fully populated world rather than a bare schema so
/// that a `WHERE` clause matching zero rows cannot masquerade as a refusal.
#[tokio::test]
async fn the_runtime_role_cannot_destroy_the_owner_of_a_live_system() {
    let w = World::build().await;
    let runtime = w.app.runtime_role_pool().await;

    // --- the owner's row -------------------------------------------------
    for (label, sql) in [
        ("delete the owner", "DELETE FROM users WHERE id = $1"),
        (
            "delete every user",
            "DELETE FROM users WHERE id IS NOT NULL",
        ),
        (
            "suspend the owner",
            "UPDATE users SET status = 'SUSPENDED' WHERE id = $1",
        ),
        (
            "archive the owner",
            "UPDATE users SET status = 'ARCHIVED' WHERE id = $1",
        ),
        (
            "un-activate the owner",
            "UPDATE users SET status = 'PENDING' WHERE id = $1",
        ),
        (
            "demote the owner across the envelope",
            "UPDATE users SET principal_type = 'CLIENT' WHERE id = $1",
        ),
        (
            "make MFA optional for the owner",
            "UPDATE users SET mfa_required = false WHERE id = $1",
        ),
        (
            "re-point the owner's row at a different account id",
            "UPDATE users SET id = gen_random_uuid() WHERE id = $1",
        ),
    ] {
        assert_refused(
            sqlx::query(sql).bind(w.root.id).execute(&runtime).await,
            label,
        );
    }

    // --- the ownership record --------------------------------------------
    for (label, sql) in [
        (
            "move ownership to the administrator",
            "UPDATE system_ownership SET root_user_id = $1",
        ),
        (
            "insert a second owner",
            "INSERT INTO system_ownership (root_user_id) VALUES ($1)",
        ),
    ] {
        assert_refused(
            sqlx::query(sql).bind(w.admin.id).execute(&runtime).await,
            label,
        );
    }
    assert_refused(
        sqlx::query("DELETE FROM system_ownership")
            .execute(&runtime)
            .await,
        "delete the ownership record",
    );
    assert_refused(
        sqlx::query("TRUNCATE system_ownership")
            .execute(&runtime)
            .await,
        "truncate the ownership record",
    );
    assert_refused(
        sqlx::query("TRUNCATE users CASCADE")
            .execute(&runtime)
            .await,
        "truncate every user",
    );

    // --- the protective machinery ----------------------------------------
    //
    // Dropping or disabling a trigger requires ownership of the table. The runtime
    // role owns nothing, so these fail on privilege — which is exactly why the
    // trigger cannot be turned off by whoever controls the application.
    for (label, sql) in [
        (
            "drop the ROOT protection trigger",
            "DROP TRIGGER trg_users_protect_root ON users",
        ),
        (
            "disable the ROOT protection trigger",
            "ALTER TABLE users DISABLE TRIGGER trg_users_protect_root",
        ),
        (
            "disable every trigger on users",
            "ALTER TABLE users DISABLE TRIGGER ALL",
        ),
        (
            "drop the ownership immutability trigger",
            "DROP TRIGGER trg_system_ownership_immutable ON system_ownership",
        ),
        (
            "drop the ownership table",
            "DROP TABLE system_ownership CASCADE",
        ),
        (
            "replace the protection function itself with a no-op",
            "CREATE OR REPLACE FUNCTION public.rb_users_protect_root() RETURNS trigger \
             AS $$ BEGIN RETURN NEW; END $$ LANGUAGE plpgsql",
        ),
        (
            "add a nullable escape-hatch column",
            "ALTER TABLE users ADD COLUMN owner_override boolean",
        ),
        (
            "become the table owner",
            "ALTER TABLE users OWNER TO roleblank_app",
        ),
    ] {
        assert_refused(sqlx::query(sql).execute(&runtime).await, label);
    }

    // Self-granting is asserted on its **effect**, not on the statement's outcome.
    //
    // PostgreSQL does not raise an error when a `GRANT` confers nothing: it emits a
    // warning and reports success, so `assert_refused` here would fail against a
    // perfectly secure database. Asserting the statement rather than the privilege
    // is the mistake this comment exists to prevent being reintroduced.
    let _ = sqlx::query("GRANT ALL ON users TO roleblank_app")
        .execute(&runtime)
        .await;
    let _ = sqlx::query("GRANT ALL ON system_ownership TO roleblank_app")
        .execute(&runtime)
        .await;
    assert_refused(
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(w.employee.id)
            .execute(&runtime)
            .await,
        "delete a user after attempting to self-grant ALL on users",
    );
    assert_refused(
        sqlx::query("DELETE FROM system_ownership")
            .execute(&runtime)
            .await,
        "delete ownership after attempting to self-grant ALL on system_ownership",
    );

    // --- escaping the role itself ----------------------------------------
    for (label, sql) in [
        ("become the superuser", "SET ROLE postgres"),
        ("become the migrator", "SET ROLE roleblank_migrator"),
        (
            "reset session authorisation",
            "SET SESSION AUTHORIZATION postgres",
        ),
        (
            "grant itself superuser",
            "ALTER ROLE roleblank_app SUPERUSER",
        ),
        (
            "grant itself the migrator role",
            "GRANT roleblank_migrator TO roleblank_app",
        ),
    ] {
        assert_refused(sqlx::query(sql).execute(&runtime).await, label);
    }

    runtime.close().await;
    assert_owner_survives(&w.app, w.root.id).await;
}

// ===========================================================================
// Layer 4 — the trigger, against a connection that *does* hold the privilege
// ===========================================================================

/// The migrator role owns the schema and holds `UPDATE` and `DELETE` on `users`.
/// It is the strongest identity the application's own credentials can reach, and
/// the trigger must still refuse it. This is the layer that would catch a
/// compromised migration or an operator with the wrong connection string.
#[tokio::test]
async fn the_trigger_refuses_even_a_privileged_connection() {
    let w = World::build().await;

    for (label, sql) in [
        ("delete the owner", "DELETE FROM users WHERE id = $1"),
        (
            "suspend the owner",
            "UPDATE users SET status = 'SUSPENDED' WHERE id = $1",
        ),
        (
            "archive the owner",
            "UPDATE users SET status = 'ARCHIVED' WHERE id = $1",
        ),
        (
            "demote the owner",
            "UPDATE users SET principal_type = 'CLIENT' WHERE id = $1",
        ),
        (
            "make MFA optional for the owner",
            "UPDATE users SET mfa_required = false WHERE id = $1",
        ),
    ] {
        assert_refused(
            sqlx::query(sql).bind(w.root.id).execute(&w.app.db).await,
            label,
        );
    }

    // Ownership is immutable even to the schema owner.
    assert_refused(
        sqlx::query("UPDATE system_ownership SET root_user_id = $1")
            .bind(w.admin.id)
            .execute(&w.app.db)
            .await,
        "move ownership as the schema owner",
    );
    assert_refused(
        sqlx::query("DELETE FROM system_ownership")
            .execute(&w.app.db)
            .await,
        "delete ownership as the schema owner",
    );
    assert_refused(
        sqlx::query("INSERT INTO system_ownership (root_user_id) VALUES ($1)")
            .bind(w.admin.id)
            .execute(&w.app.db)
            .await,
        "add a second owner as the schema owner",
    );

    assert_owner_survives(&w.app, w.root.id).await;
}

// ===========================================================================
// The whole sequence, end to end
// ===========================================================================

/// Run the full campaign in one process and then prove the owner is not merely
/// *present* but still **working**.
///
/// A per-attack assertion can be satisfied by a system that is left subtly broken —
/// a row that survives but a session that no longer authenticates, or an owner who
/// can read but no longer act. The last three requests here are the ones that show
/// the account is genuinely intact.
#[tokio::test]
async fn the_owner_is_still_fully_operational_after_the_whole_campaign() {
    let w = World::build().await;

    // A representative slice of every layer, in one run.
    for (path, body) in [
        (
            format!("/api/v1/users/{}/suspend", w.root.id),
            json!({"version": 1}),
        ),
        (
            format!("/api/v1/users/{}/archive", w.root.id),
            json!({"version": 1}),
        ),
        (
            format!("/api/v1/users/{}/roles", w.root.id),
            json!({"role_id": ROLE_EMPLOYEE}),
        ),
        (
            format!("/api/v1/users/{}/permission-overrides", w.root.id),
            json!({"permission_code": "audit.read", "effect": "DENY", "scope": "GLOBAL"}),
        ),
    ] {
        w.app
            .post(&path, w.admin.bearer(), body)
            .await
            .assert_error(StatusCode::FORBIDDEN, "ROOT_PROTECTED");
    }

    let runtime = w.app.runtime_role_pool().await;
    for sql in [
        "DELETE FROM users WHERE id = $1",
        "UPDATE users SET status = 'ARCHIVED' WHERE id = $1",
    ] {
        assert_refused(
            sqlx::query(sql).bind(w.root.id).execute(&runtime).await,
            sql,
        );
    }
    runtime.close().await;

    assert_owner_survives(&w.app, w.root.id).await;

    // Still authenticates on the token it already held...
    w.app
        .get("/api/v1/auth/me", w.root.bearer())
        .await
        .assert_status(StatusCode::OK);

    // ...still holds unrestricted authority, which is what a successful DENY
    // override would have taken away...
    w.app
        .get("/api/v1/audit/events", w.root.bearer())
        .await
        .assert_status(StatusCode::OK);

    // ...and can still start a brand new session, which is what a successful
    // suspension or archive would have prevented.
    let fresh = w
        .app
        .post(
            "/api/v1/auth/login",
            None,
            json!({"email": w.root.email, "password": TEST_PASSWORD}),
        )
        .await;
    fresh.assert_status(StatusCode::OK);
    // The owner's `mfa_required` survived, so the new session is MFA-pending —
    // itself an assertion that the flag was not cleared by any of the above.
    assert_eq!(
        fresh.json().get("mfa_required").and_then(|v| v.as_bool()),
        Some(true),
        "the owner's new session did not demand MFA — the flag was cleared somewhere"
    );

    // And the account is reachable by its own credentials from scratch.
    let _ = login(&w.app, &w.root.email).await;
    assert_owner_survives(&w.app, w.root.id).await;
}
