//! `/api/v1/users`, `/api/v1/invitations`, `/api/v1/registration`.
//!
//! Three separate stories share this file because they are the three ways an
//! account can come into existence or change what it is:
//!
//! * the lifecycle an administrator drives (suspend, reactivate, archive), where
//!   the interesting assertion is that suspension takes effect *now* — the session
//!   is revoked in the same transaction, not by a later job;
//! * invitations, the only path to an INTERNAL account, where the token is never
//!   returned by any endpoint and the invitation is single-use;
//! * self-registration, which is anonymous and must therefore answer identically
//!   whatever address it is given.

use axum::http::StatusCode;
use serde_json::json;
use uuid::Uuid;

use crate::common::{TestApp, TEST_PASSWORD};
use crate::fixtures::*;

// ---------------------------------------------------------------------------
// Row readers
// ---------------------------------------------------------------------------

async fn user_status(app: &TestApp, id: Uuid) -> String {
    sqlx::query_scalar("SELECT status FROM users WHERE id = $1")
        .bind(id)
        .fetch_one(&app.db)
        .await
        .expect("the user row")
}

async fn live_session_count(app: &TestApp, user: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM sessions WHERE user_id = $1 AND revoked_at IS NULL")
        .bind(user)
        .fetch_one(&app.db)
        .await
        .expect("count live sessions")
}

async fn invitation_status(app: &TestApp, id: Uuid) -> String {
    sqlx::query_scalar("SELECT status FROM invitations WHERE id = $1")
        .bind(id)
        .fetch_one(&app.db)
        .await
        .expect("the invitation row")
}

/// Write a setting directly.
///
/// Used only where a test needs a *precondition*, not where it is asserting on the
/// settings endpoint itself — `settings_audit_system.rs` drives `PUT /settings`
/// through HTTP and asserts the permission split around it.
async fn set_registration_mode(app: &TestApp, mode: &str) {
    sqlx::query(
        "UPDATE system_settings SET value = to_jsonb($1::text) WHERE key = 'registration.mode'",
    )
    .bind(mode)
    .execute(&app.db)
    .await
    .expect("set the registration mode");
}

// ===========================================================================
// Users
// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_and_read_expose_the_user_projection_and_nothing_else() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let employee = create_employee(&app, &root.token, "dev@roleblank.test", None).await;

    let listed = app.get("/api/v1/users", Some(&root.token)).await;
    listed.assert_status(StatusCode::OK).assert_no_secrets();
    let mut ids = ids_in(&listed);
    ids.sort();
    let mut expected = vec![root.user_id, employee.user_id];
    expected.sort();
    assert_eq!(ids, expected);

    let one = app
        .get(
            &format!("/api/v1/users/{}", employee.user_id),
            Some(&root.token),
        )
        .await;
    one.assert_status(StatusCode::OK).assert_no_secrets();
    let object = one.json().as_object().expect("an object");
    // The field set is pinned: a password hash cannot reach here because there is
    // no field it could occupy, and `email_normalized` is an identity key rather
    // than a fact about the person.
    let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec![
            "activated_at",
            "archived_at",
            "created_at",
            "display_name",
            "email",
            "id",
            "mfa_enrolled",
            "mfa_required",
            "principal_type",
            "security_version",
            "status",
            "suspended_at",
            "updated_at",
            "version",
        ]
    );

    app.get(
        &format!("/api/v1/users/{}", Uuid::now_v7()),
        Some(&root.token),
    )
    .await
    .assert_error(StatusCode::NOT_FOUND, "RESOURCE_NOT_FOUND");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_user_listing_filters_are_validated_against_closed_sets() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let employee = create_employee(&app, &root.token, "dev@roleblank.test", None).await;
    let contact = create_client_user(&app, &root.token, "contact@acme.test", None).await;

    let internal = app
        .get("/api/v1/users?principal_type=INTERNAL", Some(&root.token))
        .await;
    internal.assert_status(StatusCode::OK);
    assert!(ids_in(&internal).contains(&employee.user_id));
    assert!(!ids_in(&internal).contains(&contact.user_id));

    let clients = app
        .get("/api/v1/users?principal_type=CLIENT", Some(&root.token))
        .await;
    assert_eq!(ids_in(&clients), vec![contact.user_id]);

    // The search runs as a bound parameter against the normalised email and the
    // display name; it is never interpolated.
    let searched = app
        .get("/api/v1/users?search=CONTACT@acme", Some(&root.token))
        .await;
    searched.assert_status(StatusCode::OK);
    assert_eq!(ids_in(&searched), vec![contact.user_id]);

    for bad in [
        "principal_type=ADMIN",
        "status=DELETED",
        "sort=display_name",
        "limit=0",
    ] {
        app.get(&format!("/api/v1/users?{bad}"), Some(&root.token))
            .await
            .assert_error(StatusCode::BAD_REQUEST, "VALIDATION_FAILED");
    }
    app.get("/api/v1/users?is_root=true", Some(&root.token))
        .await
        .assert_status(StatusCode::BAD_REQUEST);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn patch_changes_profile_fields_and_refuses_a_stale_version() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let employee = create_employee(&app, &root.token, "dev@roleblank.test", None).await;
    let path = format!("/api/v1/users/{}", employee.user_id);

    let patched = app
        .patch(
            &path,
            Some(&root.token),
            json!({"version": 1, "display_name": "Devon", "email": "Devon@RoleBlank.test"}),
        )
        .await;
    patched.assert_status(StatusCode::OK).assert_no_secrets();
    assert_eq!(patched.str_at("/display_name"), "Devon");
    assert_eq!(patched.str_at("/email"), "Devon@RoleBlank.test");
    assert_eq!(patched.json()["version"], json!(2));

    // The stored identity key is the normalised form, which is what the unique
    // index enforces — so the raw address may keep its capitals.
    let normalized: String = sqlx::query_scalar("SELECT email_normalized FROM users WHERE id = $1")
        .bind(employee.user_id)
        .fetch_one(&app.db)
        .await
        .expect("the user row");
    assert_eq!(normalized, "devon@roleblank.test");

    app.patch(
        &path,
        Some(&root.token),
        json!({"version": 1, "display_name": "Stale"}),
    )
    .await
    .assert_error(StatusCode::CONFLICT, "VERSION_CONFLICT");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn patch_refuses_a_duplicate_address_and_anything_that_changes_what_an_account_is() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let first = create_employee(&app, &root.token, "first@roleblank.test", None).await;
    let second = create_employee(&app, &root.token, "second@roleblank.test", None).await;

    app.patch(
        &format!("/api/v1/users/{}", second.user_id),
        Some(&root.token),
        json!({"version": 1, "email": "FIRST@roleblank.test"}),
    )
    .await
    .assert_error(StatusCode::CONFLICT, "EMAIL_IN_USE");

    for body in [
        json!({"version": 1, "principal_type": "CLIENT"}),
        json!({"version": 1, "status": "ARCHIVED"}),
        json!({"version": 1, "is_root": true}),
        json!({"version": 1, "security_version": 99}),
        json!({"display_name": "no version"}),
    ] {
        app.patch(
            &format!("/api/v1/users/{}", first.user_id),
            Some(&root.token),
            body,
        )
        .await
        .assert_error(StatusCode::BAD_REQUEST, "BAD_REQUEST");
    }
}

/// Suspension that leaves existing sessions alive is not suspension, so the
/// revocation happens in the same transaction as the status change: there is no
/// window and no background job that could fail on its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn suspension_revokes_every_live_session_in_the_same_breath() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let employee = create_employee(&app, &root.token, "dev@roleblank.test", None).await;
    assert_eq!(live_session_count(&app, employee.user_id).await, 1);

    let suspended = app
        .post(
            &format!("/api/v1/users/{}/suspend", employee.user_id),
            Some(&root.token),
            json!({"version": 1, "reason": "under investigation"}),
        )
        .await;
    suspended.assert_status(StatusCode::OK);
    assert_eq!(suspended.str_at("/status"), "SUSPENDED");
    assert_eq!(user_status(&app, employee.user_id).await, "SUSPENDED");
    assert_eq!(live_session_count(&app, employee.user_id).await, 0);

    // The token stops working immediately, and the failure is undifferentiated.
    app.get("/api/v1/auth/me", Some(&employee.token))
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "AUTHENTICATION_FAILED");

    // ...and so does logging in again, which is indistinguishable from a wrong
    // password.
    relax_ip_quotas(&app).await;
    login(&app, &employee.email)
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "AUTHENTICATION_FAILED");

    assert_eq!(
        audit_count_for(&app, "USER.SUSPENDED", employee.user_id).await,
        1
    );
    assert_eq!(
        audit_count_for(&app, "SESSION.REVOKED_ALL", employee.user_id).await,
        1
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reactivation_restores_the_account_and_archiving_ends_it() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let employee = create_employee(&app, &root.token, "dev@roleblank.test", None).await;

    app.post(
        &format!("/api/v1/users/{}/suspend", employee.user_id),
        Some(&root.token),
        json!({"version": 1}),
    )
    .await
    .assert_status(StatusCode::OK);

    let reactivated = app
        .post(
            &format!("/api/v1/users/{}/reactivate", employee.user_id),
            Some(&root.token),
            json!({"version": 2}),
        )
        .await;
    reactivated.assert_status(StatusCode::OK);
    assert_eq!(reactivated.str_at("/status"), "ACTIVE");
    assert_eq!(user_status(&app, employee.user_id).await, "ACTIVE");

    // A reactivated account can log in again: suspension is temporary by design.
    relax_ip_quotas(&app).await;
    login(&app, &employee.email)
        .await
        .assert_status(StatusCode::OK);

    let archived = app
        .post(
            &format!("/api/v1/users/{}/archive", employee.user_id),
            Some(&root.token),
            json!({"version": 3, "reason": "left the company"}),
        )
        .await;
    archived.assert_status(StatusCode::OK);
    assert_eq!(archived.str_at("/status"), "ARCHIVED");
    assert_eq!(live_session_count(&app, employee.user_id).await, 0);

    // ARCHIVED is terminal: an account that returns gets a new one and a new trail.
    app.post(
        &format!("/api/v1/users/{}/reactivate", employee.user_id),
        Some(&root.token),
        json!({"version": 4}),
    )
    .await
    .assert_error(StatusCode::CONFLICT, "INVALID_STATUS_TRANSITION");

    // There is no `DELETE /users/{id}` at all — accounts are archived, never erased.
    let response = app
        .delete(
            &format!("/api/v1/users/{}", employee.user_id),
            Some(&root.token),
        )
        .await;
    assert_eq!(response.status, StatusCode::METHOD_NOT_ALLOWED);
    let (still_there,): (i64,) = sqlx::query_as("SELECT count(*) FROM users WHERE id = $1")
        .bind(employee.user_id)
        .fetch_one(&app.db)
        .await
        .expect("count");
    assert_eq!(still_there, 1);
}

/// An actor removing their own access is at best a support ticket and at worst an
/// attacker covering their tracks, so it is refused rather than analysed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nobody_may_change_their_own_account_status() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let admin = create_employee(&app, &root.token, "admin@roleblank.test", None).await;
    let role = create_role(
        &app,
        &root.token,
        "user_admin",
        "INTERNAL",
        &[
            ("iam.users.read", "GLOBAL"),
            ("iam.users.suspend", "GLOBAL"),
        ],
    )
    .await;
    app.post(
        &format!("/api/v1/users/{}/roles", admin.user_id),
        Some(&root.token),
        json!({"role_id": role}),
    )
    .await
    .assert_status(StatusCode::CREATED);

    app.post(
        &format!("/api/v1/users/{}/suspend", admin.user_id),
        Some(&admin.token),
        json!({"version": 1}),
    )
    .await
    .assert_error(StatusCode::CONFLICT, "SELF_TARGET_REFUSED");
    assert_eq!(user_status(&app, admin.user_id).await, "ACTIVE");
}

/// The owner is refused identically whoever asks — including the owner — and the
/// attempt is recorded under its own action code so it is trivially alertable.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_system_owner_cannot_be_edited_suspended_or_archived_by_anyone() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;

    for (method, path, body) in [
        (
            "patch",
            format!("/api/v1/users/{}", root.user_id),
            json!({"version": 1, "display_name": "Impostor"}),
        ),
        (
            "post",
            format!("/api/v1/users/{}/suspend", root.user_id),
            json!({"version": 1}),
        ),
        (
            "post",
            format!("/api/v1/users/{}/archive", root.user_id),
            json!({"version": 1}),
        ),
    ] {
        let response = if method == "patch" {
            app.patch(&path, Some(&root.token), body).await
        } else {
            app.post(&path, Some(&root.token), body).await
        };
        response.assert_error(StatusCode::FORBIDDEN, "ROOT_PROTECTED");
    }

    assert_eq!(user_status(&app, root.user_id).await, "ACTIVE");
    assert_eq!(
        audit_count_for(&app, "ROOT.PROTECTION_TRIGGERED", root.user_id).await,
        3,
        "every refused attempt on the owner must survive the failed transaction"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_employee_can_read_only_their_own_record_and_may_change_nothing() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let employee = create_employee(&app, &root.token, "dev@roleblank.test", None).await;
    let other = create_employee(&app, &root.token, "other@roleblank.test", None).await;

    // `iam.users.read@SELF` reaches exactly one record.
    app.get(
        &format!("/api/v1/users/{}", employee.user_id),
        Some(&employee.token),
    )
    .await
    .assert_status(StatusCode::OK);
    app.get(
        &format!("/api/v1/users/{}", other.user_id),
        Some(&employee.token),
    )
    .await
    .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");

    let listed = app.get("/api/v1/users", Some(&employee.token)).await;
    listed.assert_status(StatusCode::OK);
    assert_eq!(ids_in(&listed), vec![employee.user_id]);

    // Reading yourself is not the authority to change yourself.
    app.patch(
        &format!("/api/v1/users/{}", employee.user_id),
        Some(&employee.token),
        json!({"version": 1, "display_name": "Renamed"}),
    )
    .await
    .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");
}

// ===========================================================================
// Invitations
// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_invitation_is_created_listed_and_accepted_exactly_once() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;

    let created = invite(
        &app,
        &root.token,
        "newcomer@roleblank.test",
        "Newcomer",
        "INTERNAL",
        &[Uuid::parse_str(ROLE_EMPLOYEE).expect("seeded role")],
        None,
        None,
    )
    .await;
    created
        .assert_status(StatusCode::CREATED)
        .assert_no_secrets();
    let invitation = created.id_at("/id");
    assert_eq!(created.str_at("/status"), "PENDING");
    // The plaintext token has no field it could occupy in any response.
    for key in created.json().as_object().expect("object").keys() {
        let lowered = key.to_lowercase();
        assert!(!lowered.contains("token"), "`{key}` could carry the token");
        assert!(!lowered.contains("hash"));
    }

    let listed = app.get("/api/v1/invitations", Some(&root.token)).await;
    listed.assert_status(StatusCode::OK);
    assert_eq!(ids_in(&listed), vec![invitation]);

    let by_status = app
        .get("/api/v1/invitations?status=PENDING", Some(&root.token))
        .await;
    assert_eq!(ids_in(&by_status), vec![invitation]);
    app.get("/api/v1/invitations?status=NONSENSE", Some(&root.token))
        .await
        .assert_error(StatusCode::BAD_REQUEST, "VALIDATION_FAILED");

    let token = invitation_token_for(&app, "newcomer@roleblank.test").await;
    let accepted = app
        .post(
            "/api/v1/invitations/accept",
            None,
            json!({"token": token, "password": TEST_PASSWORD, "display_name": "New Comer"}),
        )
        .await;
    accepted
        .assert_status(StatusCode::CREATED)
        .assert_no_secrets();
    assert_eq!(accepted.str_at("/display_name"), "New Comer");
    assert_eq!(accepted.str_at("/principal_type"), "INTERNAL");
    assert_eq!(accepted.str_at("/status"), "ACTIVE");
    // No session and no token: the invitee authenticates through the ordinary
    // login path, which is where MFA enrolment is enforced.
    assert!(accepted.json().get("access_token").is_none());

    assert_eq!(invitation_status(&app, invitation).await, "ACCEPTED");

    // Single use. A second presentation of the same token is indistinguishable
    // from an unknown one.
    relax_ip_quotas(&app).await;
    app.post(
        "/api/v1/invitations/accept",
        None,
        json!({"token": token, "password": TEST_PASSWORD}),
    )
    .await
    .assert_error(StatusCode::UNAUTHORIZED, "AUTHENTICATION_FAILED");
}

/// Every rejection reason returns the same failure: unknown, revoked, expired and
/// already-accepted are indistinguishable to whoever is holding the token.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_revoked_invitation_cannot_be_accepted_and_the_row_survives() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let created = invite(
        &app,
        &root.token,
        "newcomer@roleblank.test",
        "Newcomer",
        "INTERNAL",
        &[],
        None,
        None,
    )
    .await;
    created.assert_status(StatusCode::CREATED);
    let invitation = created.id_at("/id");
    let token = invitation_token_for(&app, "newcomer@roleblank.test").await;

    let revoked = app
        .delete(
            &format!("/api/v1/invitations/{invitation}"),
            Some(&root.token),
        )
        .await;
    revoked.assert_status(StatusCode::OK);
    assert_eq!(revoked.str_at("/status"), "REVOKED");
    // Revoke, never erase: "who invited whom, and who changed their mind" stays
    // answerable.
    assert_eq!(invitation_status(&app, invitation).await, "REVOKED");
    assert_eq!(
        audit_count_for(&app, "INVITATION.REVOKED", invitation).await,
        1
    );

    app.delete(
        &format!("/api/v1/invitations/{invitation}"),
        Some(&root.token),
    )
    .await
    .assert_error(StatusCode::CONFLICT, "INVITATION_NOT_PENDING");

    relax_ip_quotas(&app).await;
    app.post(
        "/api/v1/invitations/accept",
        None,
        json!({"token": token, "password": TEST_PASSWORD}),
    )
    .await
    .assert_error(StatusCode::UNAUTHORIZED, "AUTHENTICATION_FAILED");

    let (users,): (i64,) = sqlx::query_as("SELECT count(*) FROM users WHERE email_normalized = $1")
        .bind("newcomer@roleblank.test")
        .fetch_one(&app.db)
        .await
        .expect("count");
    assert_eq!(users, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_malformed_or_unknown_token_is_the_same_undifferentiated_failure() {
    let app = TestApp::spawn().await;
    let _root = bootstrap_root(&app).await;

    for token in [
        "rb_iv_thisisnotarealtokenatallbutlooksright",
        "rb_at_wrongprefixentirely",
        "not-a-token",
        "",
    ] {
        relax_ip_quotas(&app).await;
        app.post(
            "/api/v1/invitations/accept",
            None,
            json!({"token": token, "password": TEST_PASSWORD}),
        )
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "AUTHENTICATION_FAILED");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_two_envelope_constraints_are_field_errors_rather_than_constraint_violations() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let department = create_department(&app, &root.token, "ops", "Operations").await;
    let account = create_client_account(&app, &root.token, "acme", "Acme").await;

    invite(
        &app,
        &root.token,
        "a@roleblank.test",
        "A",
        "INTERNAL",
        &[],
        None,
        Some(account),
    )
    .await
    .assert_error(StatusCode::BAD_REQUEST, "VALIDATION_FAILED");

    invite(
        &app,
        &root.token,
        "b@acme.test",
        "B",
        "CLIENT",
        &[],
        Some(department),
        None,
    )
    .await
    .assert_error(StatusCode::BAD_REQUEST, "VALIDATION_FAILED");

    invite(
        &app,
        &root.token,
        "c@roleblank.test",
        "C",
        "SUPERUSER",
        &[],
        None,
        None,
    )
    .await
    .assert_error(StatusCode::BAD_REQUEST, "VALIDATION_FAILED");

    invite(
        &app,
        &root.token,
        "d@roleblank.test",
        "D",
        "INTERNAL",
        &[Uuid::now_v7()],
        None,
        None,
    )
    .await
    .assert_error(StatusCode::BAD_REQUEST, "VALIDATION_FAILED");
}

/// An authenticated inviter with `iam.users.invite` may already list users, so
/// reporting a duplicate address here is not an enumeration oracle — unlike the
/// anonymous registration endpoint, which deliberately answers identically.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inviting_an_address_that_already_has_an_account_is_a_conflict() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let employee = create_employee(&app, &root.token, "dev@roleblank.test", None).await;

    invite(
        &app,
        &root.token,
        &employee.email,
        "Duplicate",
        "INTERNAL",
        &[],
        None,
        None,
    )
    .await
    .assert_error(StatusCode::CONFLICT, "EMAIL_IN_USE");

    // One live invitation per address, too: inviting the same person twice is a
    // deterministic conflict rather than two simultaneously valid tokens.
    invite(
        &app,
        &root.token,
        "newcomer@roleblank.test",
        "Newcomer",
        "INTERNAL",
        &[],
        None,
        None,
    )
    .await
    .assert_status(StatusCode::CREATED);
    invite(
        &app,
        &root.token,
        "newcomer@roleblank.test",
        "Newcomer",
        "INTERNAL",
        &[],
        None,
        None,
    )
    .await
    .assert_error(StatusCode::CONFLICT, "UNIQUE_VIOLATION");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_employee_cannot_issue_or_read_invitations() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let employee = create_employee(&app, &root.token, "dev@roleblank.test", None).await;

    app.get("/api/v1/invitations", Some(&employee.token))
        .await
        .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");
    invite(
        &app,
        &employee.token,
        "newcomer@roleblank.test",
        "Newcomer",
        "INTERNAL",
        &[],
        None,
        None,
    )
    .await
    .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");
}

// ===========================================================================
// Registration
// ===========================================================================

/// The config endpoint answers to the open internet, so it discloses two fields
/// and nothing else — no user count, no invitation policy, no build id.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_registration_config_discloses_two_fields_and_follows_the_mode() {
    let app = TestApp::spawn().await;

    // A freshly migrated database is INVITE_ONLY: self-registration must be off
    // until an operator deliberately turns it on.
    let closed = app.get("/api/v1/registration/config", None).await;
    closed.assert_status(StatusCode::OK).assert_no_secrets();
    assert_eq!(
        closed.json(),
        &json!({"registration_available": false, "registration_type": null})
    );

    set_registration_mode(&app, "CLIENT_SELF_REGISTRATION").await;
    let open = app.get("/api/v1/registration/config", None).await;
    assert_eq!(
        open.json(),
        &json!({"registration_available": true, "registration_type": "client"})
    );

    // Anything unrecognised fails closed rather than defaulting to "open".
    set_registration_mode(&app, "OPEN").await;
    let broken = app.get("/api/v1/registration/config", None).await;
    assert_eq!(broken.json()["registration_available"], json!(false));
}

/// When self-registration is off the endpoint does not exist. Advertising a
/// disabled capability tells an attacker which setting to go after.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn registration_is_absent_under_every_mode_but_one() {
    let app = TestApp::spawn().await;

    for mode in ["INVITE_ONLY", "DISABLED", "SOMETHING_ELSE"] {
        set_registration_mode(&app, mode).await;
        relax_ip_quotas(&app).await;
        app.post(
            "/api/v1/registration",
            None,
            json!({
                "email": "stranger@example.test",
                "display_name": "Stranger",
                "password": TEST_PASSWORD,
            }),
        )
        .await
        .assert_error(StatusCode::NOT_FOUND, "RESOURCE_NOT_FOUND");
    }

    let (users,): (i64,) = sqlx::query_as("SELECT count(*) FROM users")
        .fetch_one(&app.db)
        .await
        .expect("count");
    assert_eq!(users, 0);
}

/// Self-registration produces a CLIENT principal in `PENDING` with the baseline
/// role, **no client membership**, and no way in until a human inside the company
/// links it. None of that is reachable from the request body.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn self_registration_creates_an_inert_pending_client_account() {
    let app = TestApp::spawn().await;
    set_registration_mode(&app, "CLIENT_SELF_REGISTRATION").await;

    let accepted = app
        .post(
            "/api/v1/registration",
            None,
            json!({
                "email": "Stranger@Example.test",
                "display_name": "Stranger",
                "password": TEST_PASSWORD,
            }),
        )
        .await;
    accepted
        .assert_status(StatusCode::ACCEPTED)
        .assert_no_secrets();
    let first_body = accepted.raw.clone();
    assert_eq!(accepted.str_at("/registration_status"), "SUBMITTED");
    assert!(
        !String::from_utf8_lossy(&accepted.raw).contains('@'),
        "the response must not echo the submitted address"
    );

    let (id, principal_type, status, activated_at): (
        Uuid,
        String,
        String,
        Option<time::OffsetDateTime>,
    ) = sqlx::query_as(
        "SELECT id, principal_type, status, activated_at FROM users WHERE email_normalized = $1",
    )
    .bind("stranger@example.test")
    .fetch_one(&app.db)
    .await
    .expect("the registered user");
    assert_eq!(principal_type, "CLIENT");
    assert_eq!(status, "PENDING");
    assert!(
        activated_at.is_none(),
        "`was this ever approved` must have an unambiguous answer"
    );

    let (memberships,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM client_memberships WHERE user_id = $1")
            .bind(id)
            .fetch_one(&app.db)
            .await
            .expect("count");
    assert_eq!(
        memberships, 0,
        "registering must not join the stranger to any client account"
    );

    let roles: Vec<String> = sqlx::query_scalar(
        "SELECT r.code FROM user_role_assignments ura
           JOIN roles r ON r.id = ura.role_id WHERE ura.user_id = $1",
    )
    .bind(id)
    .fetch_all(&app.db)
    .await
    .expect("the assigned roles");
    assert_eq!(roles, vec!["client_user".to_string()]);

    // A PENDING account cannot obtain a session, so the role confers nothing.
    relax_ip_quotas(&app).await;
    login(&app, "Stranger@Example.test")
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "AUTHENTICATION_FAILED");

    // The second submission of the same address is byte-for-byte the first
    // response: an anonymous endpoint that answered differently would be an
    // account-enumeration oracle.
    relax_ip_quotas(&app).await;
    let repeat = app
        .post(
            "/api/v1/registration",
            None,
            json!({
                "email": "stranger@example.test",
                "display_name": "Someone Else",
                "password": TEST_PASSWORD,
            }),
        )
        .await;
    repeat.assert_status(StatusCode::ACCEPTED);
    assert_eq!(repeat.raw, first_body);

    let (count,): (i64,) = sqlx::query_as("SELECT count(*) FROM users WHERE email_normalized = $1")
        .bind("stranger@example.test")
        .fetch_one(&app.db)
        .await
        .expect("count");
    assert_eq!(count, 1, "the duplicate must not have created a second row");
}

/// Each of these, if honoured, would let an anonymous caller choose their own
/// security envelope. `deny_unknown_fields` makes every one a parse failure before
/// the service is entered — and before the registration mode is even consulted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn registration_refuses_every_privileged_field() {
    let app = TestApp::spawn().await;
    set_registration_mode(&app, "CLIENT_SELF_REGISTRATION").await;

    for injected in [
        json!({"principal_type": "INTERNAL"}),
        json!({"role_ids": [ROLE_SYSTEM_ADMINISTRATOR]}),
        json!({"status": "ACTIVE"}),
        json!({"is_root": true}),
        json!({"permissions": ["settings.security.write"]}),
        json!({"client_account_id": Uuid::now_v7()}),
        json!({"mfa_required": false}),
    ] {
        let mut body = json!({
            "email": "stranger@example.test",
            "display_name": "Stranger",
            "password": TEST_PASSWORD,
        });
        for (key, value) in injected.as_object().expect("object") {
            body[key] = value.clone();
        }
        relax_ip_quotas(&app).await;
        app.post("/api/v1/registration", None, body)
            .await
            .assert_error(StatusCode::BAD_REQUEST, "BAD_REQUEST");
    }

    let (users,): (i64,) = sqlx::query_as("SELECT count(*) FROM users")
        .fetch_one(&app.db)
        .await
        .expect("count");
    assert_eq!(users, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn registration_validates_the_address_and_the_password() {
    let app = TestApp::spawn().await;
    set_registration_mode(&app, "CLIENT_SELF_REGISTRATION").await;

    for (email, password) in [
        ("not-an-address", TEST_PASSWORD),
        ("a@b.com\nBcc: attacker@evil.test", TEST_PASSWORD),
        ("stranger@example.test", "short"),
    ] {
        relax_ip_quotas(&app).await;
        app.post(
            "/api/v1/registration",
            None,
            json!({"email": email, "display_name": "Stranger", "password": password}),
        )
        .await
        .assert_error(StatusCode::BAD_REQUEST, "VALIDATION_FAILED");
    }
}
