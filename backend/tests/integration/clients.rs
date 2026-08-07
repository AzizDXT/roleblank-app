//! `/api/v1/clients` — client accounts and the membership lifecycle.
//!
//! The membership tests are the ones that matter. A client membership is the root
//! of *all* external visibility: `PENDING` grants nothing, `ACTIVE` grants
//! everything the links allow, and the transition between them is a separate
//! endpoint with its own permission and its own audit event precisely because it
//! is the moment company data becomes visible to someone outside the company.
//!
//! Two states in the vocabulary — `SUSPENDED` on a membership and `SUSPENDED` on
//! an account — have no endpoint that produces them. Where a test needs one it is
//! written directly, and said so at the call site: pretending the API can reach it
//! would be a fiction, and skipping it would leave the reinstatement path untested.

use axum::http::StatusCode;
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::common::TestApp;
use crate::fixtures::*;

// ---------------------------------------------------------------------------
// Row readers and direct writes
// ---------------------------------------------------------------------------

async fn account_status(app: &TestApp, id: Uuid) -> String {
    sqlx::query_scalar("SELECT status FROM client_accounts WHERE id = $1")
        .bind(id)
        .fetch_one(&app.db)
        .await
        .expect("the client account row")
}

async fn membership_status(app: &TestApp, account: Uuid, user: Uuid) -> String {
    sqlx::query_scalar(
        "SELECT status FROM client_memberships WHERE client_account_id = $1 AND user_id = $2",
    )
    .bind(account)
    .bind(user)
    .fetch_one(&app.db)
    .await
    .expect("the membership row")
}

async fn membership_activated_at(
    app: &TestApp,
    account: Uuid,
    user: Uuid,
) -> Option<OffsetDateTime> {
    sqlx::query_scalar(
        "SELECT activated_at FROM client_memberships
          WHERE client_account_id = $1 AND user_id = $2",
    )
    .bind(account)
    .bind(user)
    .fetch_one(&app.db)
    .await
    .expect("the membership row")
}

/// Put a membership into `SUSPENDED`.
///
/// There is no endpoint that does this: `add_member` produces `PENDING`,
/// `activate` produces `ACTIVE` and `remove` produces `REMOVED`. `SUSPENDED` is
/// nevertheless a real state the transition matrix handles, and the reinstatement
/// path out of it would otherwise never be exercised, so the row is written
/// directly and the *API's* behaviour from that state is what is asserted.
async fn suspend_membership_directly(app: &TestApp, account: Uuid, user: Uuid) {
    sqlx::query(
        "UPDATE client_memberships SET status = 'SUSPENDED'
          WHERE client_account_id = $1 AND user_id = $2",
    )
    .bind(account)
    .bind(user)
    .execute(&app.db)
    .await
    .expect("suspend the membership");
}

/// Likewise for an account: `SUSPENDED` is a live commercial state the service
/// reasons about, and no endpoint sets it.
async fn suspend_account_directly(app: &TestApp, account: Uuid) {
    sqlx::query("UPDATE client_accounts SET status = 'SUSPENDED' WHERE id = $1")
        .bind(account)
        .execute(&app.db)
        .await
        .expect("suspend the account");
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_stores_an_active_account_at_version_one() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;

    let created = app
        .post(
            "/api/v1/clients",
            Some(&root.token),
            json!({"code": "ACME", "name": "Acme Ltd", "description": "A customer"}),
        )
        .await;
    created
        .assert_status(StatusCode::CREATED)
        .assert_no_secrets();
    assert_eq!(created.str_at("/code"), "acme");
    assert_eq!(created.str_at("/status"), "ACTIVE");
    assert_eq!(created.json()["version"], json!(1));
    assert_eq!(created.json()["account_manager_user_id"], json!(null));

    let id = created.id_at("/id");
    assert_eq!(account_status(&app, id).await, "ACTIVE");
    assert_eq!(audit_count_for(&app, "CLIENT.CREATED", id).await, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn read_and_list_return_the_stored_rows() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let first = create_client_account(&app, &root.token, "acme", "Acme").await;
    let second = create_client_account(&app, &root.token, "globex", "Globex").await;

    let found = app
        .get(&format!("/api/v1/clients/{first}"), Some(&root.token))
        .await;
    found.assert_status(StatusCode::OK).assert_no_secrets();
    assert_eq!(found.str_at("/name"), "Acme");

    let page = app
        .get(
            "/api/v1/clients?sort=created_at&direction=asc",
            Some(&root.token),
        )
        .await;
    page.assert_status(StatusCode::OK);
    assert_eq!(ids_in(&page), vec![first, second]);

    app.get(
        &format!("/api/v1/clients/{}", Uuid::now_v7()),
        Some(&root.token),
    )
    .await
    .assert_error(StatusCode::NOT_FOUND, "RESOURCE_NOT_FOUND");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn patch_applies_with_the_current_version_and_is_refused_with_a_stale_one() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let id = create_client_account(&app, &root.token, "acme", "Acme").await;

    let patched = app
        .patch(
            &format!("/api/v1/clients/{id}"),
            Some(&root.token),
            json!({"version": 1, "name": "Acme International"}),
        )
        .await;
    patched.assert_status(StatusCode::OK);
    assert_eq!(patched.json()["version"], json!(2));

    app.patch(
        &format!("/api/v1/clients/{id}"),
        Some(&root.token),
        json!({"version": 1, "name": "Stale"}),
    )
    .await
    .assert_error(StatusCode::CONFLICT, "VERSION_CONFLICT");

    let name: String = sqlx::query_scalar("SELECT name FROM client_accounts WHERE id = $1")
        .bind(id)
        .fetch_one(&app.db)
        .await
        .expect("the client account row");
    assert_eq!(name, "Acme International");
}

/// Absent means "leave the manager alone"; an explicit `null` means "clear it".
/// Collapsing the two would make detaching an account manager impossible.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_account_manager_can_be_set_and_explicitly_cleared() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let id = create_client_account(&app, &root.token, "acme", "Acme").await;

    let set = app
        .patch(
            &format!("/api/v1/clients/{id}"),
            Some(&root.token),
            json!({"version": 1, "account_manager_user_id": root.user_id}),
        )
        .await;
    set.assert_status(StatusCode::OK);
    assert_eq!(set.id_at("/account_manager_user_id"), root.user_id);

    let untouched = app
        .patch(
            &format!("/api/v1/clients/{id}"),
            Some(&root.token),
            json!({"version": 2, "name": "Acme"}),
        )
        .await;
    untouched.assert_status(StatusCode::OK);
    assert_eq!(untouched.id_at("/account_manager_user_id"), root.user_id);

    let cleared = app
        .patch(
            &format!("/api/v1/clients/{id}"),
            Some(&root.token),
            json!({"version": 3, "account_manager_user_id": null}),
        )
        .await;
    cleared.assert_status(StatusCode::OK);
    assert_eq!(cleared.json()["account_manager_user_id"], json!(null));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_account_manager_must_be_internal_and_must_exist() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let id = create_client_account(&app, &root.token, "acme", "Acme").await;
    let outsider = create_client_user(&app, &root.token, "contact@acme.test", None).await;

    app.patch(
        &format!("/api/v1/clients/{id}"),
        Some(&root.token),
        json!({"version": 1, "account_manager_user_id": outsider.user_id}),
    )
    .await
    .assert_error(StatusCode::CONFLICT, "PRINCIPAL_TYPE_MISMATCH");

    app.patch(
        &format!("/api/v1/clients/{id}"),
        Some(&root.token),
        json!({"version": 1, "account_manager_user_id": Uuid::now_v7()}),
    )
    .await
    .assert_error(StatusCode::CONFLICT, "UNKNOWN_USER");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn archive_is_terminal_and_makes_the_account_read_only() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let id = create_client_account(&app, &root.token, "acme", "Acme").await;

    let archived = app
        .post(
            &format!("/api/v1/clients/{id}/archive"),
            Some(&root.token),
            json!({"version": 1}),
        )
        .await;
    archived.assert_status(StatusCode::OK);
    assert_eq!(archived.str_at("/status"), "ARCHIVED");
    assert_eq!(account_status(&app, id).await, "ARCHIVED");
    assert_eq!(audit_count_for(&app, "CLIENT.ARCHIVED", id).await, 1);

    app.post(
        &format!("/api/v1/clients/{id}/archive"),
        Some(&root.token),
        json!({"version": 2}),
    )
    .await
    .assert_error(StatusCode::CONFLICT, "CLIENT_ALREADY_ARCHIVED");

    app.patch(
        &format!("/api/v1/clients/{id}"),
        Some(&root.token),
        json!({"version": 2, "name": "Reopened"}),
    )
    .await
    .assert_error(StatusCode::CONFLICT, "CLIENT_ARCHIVED");
}

/// A suspended customer is still a live commercial relationship, so editing and
/// archiving it must both remain possible — unlike an archived one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_suspended_account_is_still_editable_and_archivable() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let id = create_client_account(&app, &root.token, "acme", "Acme").await;
    suspend_account_directly(&app, id).await;

    app.patch(
        &format!("/api/v1/clients/{id}"),
        Some(&root.token),
        json!({"version": 1, "name": "Acme (in arrears)"}),
    )
    .await
    .assert_status(StatusCode::OK);

    app.post(
        &format!("/api/v1/clients/{id}/archive"),
        Some(&root.token),
        json!({"version": 2}),
    )
    .await
    .assert_status(StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_duplicate_code_is_refused() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    create_client_account(&app, &root.token, "acme", "Acme").await;

    app.post(
        "/api/v1/clients",
        Some(&root.token),
        json!({"code": "acme", "name": "Acme Again"}),
    )
    .await
    .assert_error(StatusCode::CONFLICT, "UNIQUE_VIOLATION");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_and_patch_refuse_unknown_and_privileged_fields() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;

    for body in [
        json!({"code": "acme", "name": "Acme", "status": "ACTIVE"}),
        json!({"code": "acme", "name": "Acme", "version": 5}),
        json!({"code": "acme", "name": "Acme", "created_by": Uuid::now_v7()}),
    ] {
        app.post("/api/v1/clients", Some(&root.token), body)
            .await
            .assert_error(StatusCode::BAD_REQUEST, "BAD_REQUEST");
    }

    let id = create_client_account(&app, &root.token, "acme", "Acme").await;
    app.patch(
        &format!("/api/v1/clients/{id}"),
        Some(&root.token),
        json!({"version": 1, "code": "renamed"}),
    )
    .await
    .assert_error(StatusCode::BAD_REQUEST, "BAD_REQUEST");
}

// ---------------------------------------------------------------------------
// Membership lifecycle
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_membership_walks_pending_to_active_to_removed() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let account = create_client_account(&app, &root.token, "acme", "Acme").await;
    let contact = create_client_user(&app, &root.token, "contact@acme.test", None).await;

    // --- PENDING -----------------------------------------------------------
    let added = app
        .post(
            &format!("/api/v1/clients/{account}/members"),
            Some(&root.token),
            json!({"user_id": contact.user_id}),
        )
        .await;
    added.assert_status(StatusCode::CREATED).assert_no_secrets();
    assert_eq!(added.str_at("/status"), "PENDING");
    assert_eq!(
        added.json()["grants_visibility"],
        json!(false),
        "a PENDING membership must report that it confers nothing"
    );
    assert_eq!(
        membership_status(&app, account, contact.user_id).await,
        "PENDING"
    );
    assert!(membership_activated_at(&app, account, contact.user_id)
        .await
        .is_none());

    let members = app
        .get(
            &format!("/api/v1/clients/{account}/members"),
            Some(&root.token),
        )
        .await;
    members.assert_status(StatusCode::OK);
    assert_eq!(member_ids_in(&members), vec![contact.user_id]);

    // --- ACTIVE ------------------------------------------------------------
    let activated = app
        .post(
            &format!(
                "/api/v1/clients/{account}/members/{}/activate",
                contact.user_id
            ),
            Some(&root.token),
            json!({}),
        )
        .await;
    activated.assert_status(StatusCode::OK);
    assert_eq!(activated.str_at("/status"), "ACTIVE");
    assert_eq!(activated.json()["grants_visibility"], json!(true));
    assert_eq!(
        membership_status(&app, account, contact.user_id).await,
        "ACTIVE"
    );
    assert!(
        membership_activated_at(&app, account, contact.user_id)
            .await
            .is_some(),
        "activation must record when it happened"
    );
    assert_eq!(
        audit_count_for(&app, "CLIENT.MEMBER_ACTIVATED", account).await,
        1,
        "the moment data becomes externally visible gets its own audit event"
    );

    // Activating an already-active membership is a conflict, not a no-op.
    app.post(
        &format!(
            "/api/v1/clients/{account}/members/{}/activate",
            contact.user_id
        ),
        Some(&root.token),
        json!({}),
    )
    .await
    .assert_error(StatusCode::CONFLICT, "MEMBERSHIP_ALREADY_ACTIVE");

    // --- REMOVED -----------------------------------------------------------
    app.delete(
        &format!("/api/v1/clients/{account}/members/{}", contact.user_id),
        Some(&root.token),
    )
    .await
    .assert_status(StatusCode::NO_CONTENT);
    assert_eq!(
        membership_status(&app, account, contact.user_id).await,
        "REMOVED"
    );

    app.delete(
        &format!("/api/v1/clients/{account}/members/{}", contact.user_id),
        Some(&root.token),
    )
    .await
    .assert_error(StatusCode::CONFLICT, "MEMBERSHIP_ALREADY_REMOVED");

    // Reinstating must go back through PENDING: restoring external access is never
    // a single keystroke on a membership that was explicitly ended.
    app.post(
        &format!(
            "/api/v1/clients/{account}/members/{}/activate",
            contact.user_id
        ),
        Some(&root.token),
        json!({}),
    )
    .await
    .assert_error(StatusCode::CONFLICT, "MEMBERSHIP_REMOVED");

    let revived = app
        .post(
            &format!("/api/v1/clients/{account}/members"),
            Some(&root.token),
            json!({"user_id": contact.user_id}),
        )
        .await;
    revived.assert_status(StatusCode::CREATED);
    assert_eq!(revived.str_at("/status"), "PENDING");
    assert_eq!(
        membership_status(&app, account, contact.user_id).await,
        "PENDING"
    );
}

/// The one transition the API cannot itself produce, exercised from a row written
/// directly: a suspended membership may be reinstated in one step, unlike a
/// removed one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_suspended_membership_is_reinstated_by_activation() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let account = create_client_account(&app, &root.token, "acme", "Acme").await;
    let contact = create_client_user(&app, &root.token, "contact@acme.test", Some(account)).await;

    suspend_membership_directly(&app, account, contact.user_id).await;

    let listed = app
        .get(
            &format!("/api/v1/clients/{account}/members"),
            Some(&root.token),
        )
        .await;
    assert_eq!(listed.json()["items"][0]["status"], json!("SUSPENDED"));
    assert_eq!(listed.json()["items"][0]["grants_visibility"], json!(false));

    let reinstated = app
        .post(
            &format!(
                "/api/v1/clients/{account}/members/{}/activate",
                contact.user_id
            ),
            Some(&root.token),
            json!({}),
        )
        .await;
    reinstated.assert_status(StatusCode::OK);
    assert_eq!(reinstated.str_at("/status"), "ACTIVE");
    assert_eq!(reinstated.json()["grants_visibility"], json!(true));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_an_external_principal_may_be_a_client_member() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let account = create_client_account(&app, &root.token, "acme", "Acme").await;
    let employee = create_employee(&app, &root.token, "staff@roleblank.test", None).await;

    app.post(
        &format!("/api/v1/clients/{account}/members"),
        Some(&root.token),
        json!({"user_id": employee.user_id}),
    )
    .await
    .assert_error(StatusCode::CONFLICT, "PRINCIPAL_TYPE_MISMATCH");

    app.post(
        &format!("/api/v1/clients/{account}/members"),
        Some(&root.token),
        json!({"user_id": Uuid::now_v7()}),
    )
    .await
    .assert_error(StatusCode::CONFLICT, "UNKNOWN_USER");

    // A membership status can never arrive in a request body: activation is a
    // separate, separately audited decision.
    app.post(
        &format!("/api/v1/clients/{account}/members"),
        Some(&root.token),
        json!({"user_id": employee.user_id, "status": "ACTIVE"}),
    )
    .await
    .assert_error(StatusCode::BAD_REQUEST, "BAD_REQUEST");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_membership_that_does_not_exist_cannot_be_activated_or_removed() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let account = create_client_account(&app, &root.token, "acme", "Acme").await;
    let contact = create_client_user(&app, &root.token, "contact@acme.test", None).await;

    app.post(
        &format!(
            "/api/v1/clients/{account}/members/{}/activate",
            contact.user_id
        ),
        Some(&root.token),
        json!({}),
    )
    .await
    .assert_error(StatusCode::NOT_FOUND, "RESOURCE_NOT_FOUND");

    app.delete(
        &format!("/api/v1/clients/{account}/members/{}", contact.user_id),
        Some(&root.token),
    )
    .await
    .assert_error(StatusCode::NOT_FOUND, "RESOURCE_NOT_FOUND");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_member_cannot_be_added_to_an_archived_account() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let account = create_client_account(&app, &root.token, "acme", "Acme").await;
    let contact = create_client_user(&app, &root.token, "contact@acme.test", None).await;

    app.post(
        &format!("/api/v1/clients/{account}/archive"),
        Some(&root.token),
        json!({"version": 1}),
    )
    .await
    .assert_status(StatusCode::OK);

    app.post(
        &format!("/api/v1/clients/{account}/members"),
        Some(&root.token),
        json!({"user_id": contact.user_id}),
    )
    .await
    .assert_error(StatusCode::CONFLICT, "CLIENT_ARCHIVED");
}

// ---------------------------------------------------------------------------
// What a membership actually confers
// ---------------------------------------------------------------------------

/// **The property this module exists to protect.** A `PENDING` membership on an
/// account holding a live project link grants no visibility whatsoever — not a
/// filtered view, not an empty-but-existing project, nothing. Activation is what
/// changes that, and only activation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pending_membership_grants_no_visibility_and_activation_grants_it() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let account = create_client_account(&app, &root.token, "acme", "Acme").await;
    let project = create_project(&app, &root.token, "rollout", root.user_id, None).await;

    app.post(
        &format!("/api/v1/projects/{project}/clients"),
        Some(&root.token),
        json!({"client_account_id": account}),
    )
    .await
    .assert_status(StatusCode::NO_CONTENT);

    let contact = create_client_user(&app, &root.token, "contact@acme.test", None).await;
    app.post(
        &format!("/api/v1/clients/{account}/members"),
        Some(&root.token),
        json!({"user_id": contact.user_id}),
    )
    .await
    .assert_status(StatusCode::CREATED);

    // PENDING: the shared project is not merely hidden from the listing, it does
    // not exist as far as this principal is concerned.
    let empty = app
        .get("/api/v1/client-portal/projects", Some(&contact.token))
        .await;
    empty.assert_status(StatusCode::OK);
    assert!(
        ids_in(&empty).is_empty(),
        "a PENDING membership returned a project"
    );
    app.get(
        &format!("/api/v1/client-portal/projects/{project}"),
        Some(&contact.token),
    )
    .await
    .assert_error(StatusCode::NOT_FOUND, "RESOURCE_NOT_FOUND");

    // ACTIVE: the same principal, the same link, a different answer.
    app.post(
        &format!(
            "/api/v1/clients/{account}/members/{}/activate",
            contact.user_id
        ),
        Some(&root.token),
        json!({}),
    )
    .await
    .assert_status(StatusCode::OK);

    let visible = app
        .get("/api/v1/client-portal/projects", Some(&contact.token))
        .await;
    visible.assert_status(StatusCode::OK).assert_no_secrets();
    assert_eq!(ids_in(&visible), vec![project]);

    let detail = app
        .get(
            &format!("/api/v1/client-portal/projects/{project}"),
            Some(&contact.token),
        )
        .await;
    detail.assert_status(StatusCode::OK);
    // The external projection is a different Rust type, not a filtered one: these
    // keys have no field to occupy.
    for forbidden in [
        "internal_note",
        "manager_user_id",
        "department_id",
        "created_by",
        "version",
    ] {
        assert!(
            detail.json().get(forbidden).is_none(),
            "the client projection leaked `{forbidden}`"
        );
    }
}

/// Removing the membership takes the visibility away again on the very next query
/// — there is no cache to invalidate, which is the whole point of deriving it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn removing_a_membership_removes_visibility_immediately() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let account = create_client_account(&app, &root.token, "acme", "Acme").await;
    let project = create_project(&app, &root.token, "rollout", root.user_id, None).await;
    app.post(
        &format!("/api/v1/projects/{project}/clients"),
        Some(&root.token),
        json!({"client_account_id": account}),
    )
    .await
    .assert_status(StatusCode::NO_CONTENT);

    let contact = create_client_user(&app, &root.token, "contact@acme.test", Some(account)).await;
    assert_eq!(
        ids_in(
            &app.get("/api/v1/client-portal/projects", Some(&contact.token))
                .await
        ),
        vec![project]
    );

    app.delete(
        &format!("/api/v1/clients/{account}/members/{}", contact.user_id),
        Some(&root.token),
    )
    .await
    .assert_status(StatusCode::NO_CONTENT);

    let after = app
        .get("/api/v1/client-portal/projects", Some(&contact.token))
        .await;
    after.assert_status(StatusCode::OK);
    assert!(ids_in(&after).is_empty());
}

/// Archiving the account touches no membership row and cuts no link. It does not
/// need to: the visibility predicate requires `client_accounts.status = 'ACTIVE'`,
/// so every membership of the account stops granting visibility at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn archiving_the_account_ends_visibility_without_touching_a_membership() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let account = create_client_account(&app, &root.token, "acme", "Acme").await;
    let project = create_project(&app, &root.token, "rollout", root.user_id, None).await;
    app.post(
        &format!("/api/v1/projects/{project}/clients"),
        Some(&root.token),
        json!({"client_account_id": account}),
    )
    .await
    .assert_status(StatusCode::NO_CONTENT);
    let contact = create_client_user(&app, &root.token, "contact@acme.test", Some(account)).await;

    app.post(
        &format!("/api/v1/clients/{account}/archive"),
        Some(&root.token),
        json!({"version": 1}),
    )
    .await
    .assert_status(StatusCode::OK);

    let after = app
        .get("/api/v1/client-portal/projects", Some(&contact.token))
        .await;
    after.assert_status(StatusCode::OK);
    assert!(ids_in(&after).is_empty());
    assert_eq!(
        membership_status(&app, account, contact.user_id).await,
        "ACTIVE",
        "archiving must not have rewritten the membership; the predicate does the work"
    );
}

// ---------------------------------------------------------------------------
// Authorisation
// ---------------------------------------------------------------------------

/// `clients.*` is INTERNAL-only in the catalogue, so an external principal is
/// refused at the envelope — before any grant is consulted — and the refusal is
/// shaped as a `404`: the customer-management surface does not acknowledge itself
/// to a client.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_customer_surface_does_not_acknowledge_itself_to_a_client() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let account = create_client_account(&app, &root.token, "acme", "Acme").await;
    let contact = create_client_user(&app, &root.token, "contact@acme.test", Some(account)).await;

    app.get("/api/v1/clients", Some(&contact.token))
        .await
        .assert_error(StatusCode::NOT_FOUND, "RESOURCE_NOT_FOUND");
    app.get(&format!("/api/v1/clients/{account}"), Some(&contact.token))
        .await
        .assert_error(StatusCode::NOT_FOUND, "RESOURCE_NOT_FOUND");
    app.get(
        &format!("/api/v1/clients/{account}/members"),
        Some(&contact.token),
    )
    .await
    .assert_error(StatusCode::NOT_FOUND, "RESOURCE_NOT_FOUND");
    app.post(
        "/api/v1/clients",
        Some(&contact.token),
        json!({"code": "mine", "name": "Mine"}),
    )
    .await
    .assert_error(StatusCode::NOT_FOUND, "RESOURCE_NOT_FOUND");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_employee_holds_no_authority_over_client_accounts() {
    let app = TestApp::spawn().await;
    let root = bootstrap_root(&app).await;
    let account = create_client_account(&app, &root.token, "acme", "Acme").await;
    let employee = create_employee(&app, &root.token, "staff@roleblank.test", None).await;

    // An internal principal gets a 403: existence disclosure inside the company is
    // acceptable, and the distinction is what makes the client 404 meaningful.
    app.get("/api/v1/clients", Some(&employee.token))
        .await
        .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");
    app.get(&format!("/api/v1/clients/{account}"), Some(&employee.token))
        .await
        .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");
    app.post(
        "/api/v1/clients",
        Some(&employee.token),
        json!({"code": "mine", "name": "Mine"}),
    )
    .await
    .assert_error(StatusCode::FORBIDDEN, "AUTHORIZATION_DENIED");
}
