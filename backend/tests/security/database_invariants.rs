//! Database-level security invariants, tested directly against PostgreSQL.
//!
//! These do not go through HTTP. The whole point is to prove that the invariants
//! hold **even when the application is bypassed entirely** — an application bug, a
//! stray migration, or an operator with a `psql` session must not be sufficient to
//! remove the system owner or rewrite audit history.
//!
//! Brief §68 requires exactly this: "Do not test only through HTTP."

use axum::http::StatusCode;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

use crate::common::{TestApp, TEST_BOOTSTRAP_SECRET, TEST_PASSWORD};
use crate::fixtures;

/// Seed a minimal identity fixture directly, bypassing the application.
async fn seed(pool: &PgPool) -> (Uuid, Uuid, Uuid) {
    let root = Uuid::now_v7();
    let employee = Uuid::now_v7();
    let client = Uuid::now_v7();

    for (id, email, principal) in [
        (root, "root@invariant.test", "INTERNAL"),
        (employee, "emp@invariant.test", "INTERNAL"),
        (client, "cli@invariant.test", "CLIENT"),
    ] {
        sqlx::query(
            "INSERT INTO users (id, email, email_normalized, display_name, principal_type,
                                status, mfa_required, activated_at)
             VALUES ($1,$2,$2,$3,$4,'ACTIVE',$5, now())",
        )
        .bind(id)
        .bind(email)
        .bind("Fixture")
        .bind(principal)
        .bind(principal == "INTERNAL" && id == root)
        .execute(pool)
        .await
        .expect("seed user");
    }

    sqlx::query("INSERT INTO system_ownership (root_user_id) VALUES ($1)")
        .bind(root)
        .execute(pool)
        .await
        .expect("establish ownership");

    (root, employee, client)
}

fn assert_refused(result: Result<sqlx::postgres::PgQueryResult, sqlx::Error>, what: &str) {
    match result {
        Err(_) => {}
        Ok(r) => panic!(
            "{what} was NOT refused (rows affected: {})",
            r.rows_affected()
        ),
    }
}

// ===========================================================================
// The ROOT ownership invariant (ADR-004)
// ===========================================================================

#[tokio::test]
async fn a_second_owner_is_impossible() {
    let app = TestApp::spawn().await;
    let (_, employee, _) = seed(&app.db).await;

    assert_refused(
        sqlx::query("INSERT INTO system_ownership (root_user_id) VALUES ($1)")
            .bind(employee)
            .execute(&app.db)
            .await,
        "establishing a second owner",
    );

    let count: (i64,) = sqlx::query_as("SELECT count(*) FROM system_ownership")
        .fetch_one(&app.db)
        .await
        .expect("count");
    assert_eq!(count.0, 1);
}

#[tokio::test]
async fn ownership_cannot_be_moved_or_removed() {
    let app = TestApp::spawn().await;
    let (root, employee, _) = seed(&app.db).await;

    assert_refused(
        sqlx::query("UPDATE system_ownership SET root_user_id = $1")
            .bind(employee)
            .execute(&app.db)
            .await,
        "moving ownership by UPDATE",
    );
    assert_refused(
        sqlx::query("DELETE FROM system_ownership")
            .execute(&app.db)
            .await,
        "deleting the ownership row",
    );

    let current: (Uuid,) = sqlx::query_as("SELECT root_user_id FROM system_ownership")
        .fetch_one(&app.db)
        .await
        .expect("read ownership");
    assert_eq!(current.0, root, "ownership moved");
}

#[tokio::test]
async fn the_owner_cannot_be_deleted_suspended_archived_or_demoted() {
    let app = TestApp::spawn().await;
    let (root, _, _) = seed(&app.db).await;

    let attacks: Vec<(&str, &str)> = vec![
        ("delete", "DELETE FROM users WHERE id = $1"),
        (
            "suspend",
            "UPDATE users SET status = 'SUSPENDED' WHERE id = $1",
        ),
        (
            "archive",
            "UPDATE users SET status = 'ARCHIVED' WHERE id = $1",
        ),
        (
            "set pending",
            "UPDATE users SET status = 'PENDING' WHERE id = $1",
        ),
        (
            "convert to CLIENT",
            "UPDATE users SET principal_type = 'CLIENT' WHERE id = $1",
        ),
        (
            "disable MFA",
            "UPDATE users SET mfa_required = false WHERE id = $1",
        ),
    ];

    for (label, sql) in attacks {
        assert_refused(sqlx::query(sql).bind(root).execute(&app.db).await, label);
    }

    let row: (String, String, bool) =
        sqlx::query_as("SELECT status, principal_type, mfa_required FROM users WHERE id = $1")
            .bind(root)
            .fetch_one(&app.db)
            .await
            .expect("owner still exists");
    assert_eq!(row.0, "ACTIVE");
    assert_eq!(row.1, "INTERNAL");
    assert!(row.2, "owner MFA requirement was removed");
}

/// A bulk administrative action must not sweep up the owner. The statement is
/// refused as a whole, so nobody is suspended — including the innocent bystanders.
#[tokio::test]
async fn a_bulk_suspend_cannot_catch_the_owner() {
    let app = TestApp::spawn().await;
    let (_, _, _) = seed(&app.db).await;

    assert_refused(
        sqlx::query("UPDATE users SET status = 'SUSPENDED'")
            .execute(&app.db)
            .await,
        "bulk suspension of all users",
    );

    let suspended: (i64,) = sqlx::query_as("SELECT count(*) FROM users WHERE status = 'SUSPENDED'")
        .fetch_one(&app.db)
        .await
        .expect("count");
    assert_eq!(suspended.0, 0, "a bulk update partially applied");
}

#[tokio::test]
async fn an_external_principal_can_never_become_the_owner() {
    let app = TestApp::spawn().await;

    let client = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO users (id, email, email_normalized, display_name, principal_type, status)
         VALUES ($1,'ext@invariant.test','ext@invariant.test','Ext','CLIENT','ACTIVE')",
    )
    .bind(client)
    .execute(&app.db)
    .await
    .expect("seed client");

    assert_refused(
        sqlx::query("INSERT INTO system_ownership (root_user_id) VALUES ($1)")
            .bind(client)
            .execute(&app.db)
            .await,
        "making a CLIENT principal the owner",
    );
}

// ===========================================================================
// The client security envelope
// ===========================================================================

#[tokio::test]
async fn a_client_principal_cannot_receive_an_internal_role() {
    let app = TestApp::spawn().await;
    let (_, _, client) = seed(&app.db).await;

    // `system_administrator` is seeded by migration 0008 with a fixed id.
    assert_refused(
        sqlx::query(
            "INSERT INTO user_role_assignments (id, user_id, role_id)
             VALUES ($1, $2, '00000000-0000-7000-8000-000000000001')",
        )
        .bind(Uuid::now_v7())
        .bind(client)
        .execute(&app.db)
        .await,
        "assigning an INTERNAL role to a CLIENT principal",
    );
}

#[tokio::test]
async fn an_internal_permission_cannot_be_attached_to_a_client_role() {
    let app = TestApp::spawn().await;

    for permission in ["audit.read", "iam.users.read", "settings.security.write"] {
        assert_refused(
            sqlx::query(
                "INSERT INTO role_permissions (role_id, permission_code, scope_type)
                 VALUES ('00000000-0000-7000-8000-000000000003', $1, 'GLOBAL')",
            )
            .bind(permission)
            .execute(&app.db)
            .await,
            &format!("attaching `{permission}` to the client role"),
        );
    }
}

#[tokio::test]
async fn an_internal_permission_cannot_be_allowed_for_a_client_principal() {
    let app = TestApp::spawn().await;
    let (root, _, client) = seed(&app.db).await;

    assert_refused(
        sqlx::query(
            "INSERT INTO user_permission_overrides
                 (id, user_id, permission_code, effect, scope_type, granted_by)
             VALUES ($1, $2, 'audit.read', 'ALLOW', 'GLOBAL', $3)",
        )
        .bind(Uuid::now_v7())
        .bind(client)
        .bind(root)
        .execute(&app.db)
        .await,
        "allowing an INTERNAL permission for a CLIENT principal",
    );

    // A DENY override is always permitted: it only ever removes authority.
    sqlx::query(
        "INSERT INTO user_permission_overrides
             (id, user_id, permission_code, effect, scope_type, granted_by)
         VALUES ($1, $2, 'client.portal.projects.read', 'DENY', 'GLOBAL', $3)",
    )
    .bind(Uuid::now_v7())
    .bind(client)
    .bind(root)
    .execute(&app.db)
    .await
    .expect("a DENY override must always be permitted");
}

#[tokio::test]
async fn membership_tables_enforce_the_principal_boundary() {
    let app = TestApp::spawn().await;
    let (_, employee, client) = seed(&app.db).await;

    let dept = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO departments (id, code, name, status) VALUES ($1,'eng','Engineering','ACTIVE')",
    )
    .bind(dept)
    .execute(&app.db)
    .await
    .expect("seed department");

    // A CLIENT must not be able to enter an internal structure.
    assert_refused(
        sqlx::query(
            "INSERT INTO department_memberships (id, department_id, user_id, role_in_department)
             VALUES ($1,$2,$3,'MEMBER')",
        )
        .bind(Uuid::now_v7())
        .bind(dept)
        .bind(client)
        .execute(&app.db)
        .await,
        "adding a CLIENT to a department",
    );

    let account = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO client_accounts (id, code, name, status) VALUES ($1,'acme','Acme','ACTIVE')",
    )
    .bind(account)
    .execute(&app.db)
    .await
    .expect("seed client account");

    // ...and an INTERNAL user must not be a member of a customer's account.
    assert_refused(
        sqlx::query(
            "INSERT INTO client_memberships (id, client_account_id, user_id, status)
             VALUES ($1,$2,$3,'ACTIVE')",
        )
        .bind(Uuid::now_v7())
        .bind(account)
        .bind(employee)
        .execute(&app.db)
        .await,
        "adding an INTERNAL user to a client account",
    );
}

// ===========================================================================
// Audit immutability (ADR-006)
// ===========================================================================

async fn insert_audit_row(pool: &PgPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO audit_events (id, action_code, outcome, entry_hash)
         VALUES ($1,'USER.CREATED','SUCCESS', decode(repeat('61',32),'hex'))",
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("audit insert must succeed — the log is append-only, not read-only");
    id
}

#[tokio::test]
async fn audit_events_cannot_be_updated_deleted_or_truncated_even_by_the_schema_owner() {
    let app = TestApp::spawn().await;
    let id = insert_audit_row(&app.db).await;

    assert_refused(
        sqlx::query("UPDATE audit_events SET outcome = 'FAILURE' WHERE id = $1")
            .bind(id)
            .execute(&app.db)
            .await,
        "updating an audit event",
    );
    assert_refused(
        sqlx::query("DELETE FROM audit_events WHERE id = $1")
            .bind(id)
            .execute(&app.db)
            .await,
        "deleting an audit event",
    );
    // TRUNCATE bypasses row-level triggers, which is why it has its own guard.
    assert_refused(
        sqlx::query("TRUNCATE audit_events").execute(&app.db).await,
        "truncating the audit log",
    );

    let remaining: (i64,) = sqlx::query_as("SELECT count(*) FROM audit_events")
        .fetch_one(&app.db)
        .await
        .expect("count");
    assert_eq!(remaining.0, 1);
}

#[tokio::test]
async fn the_audit_chain_head_cannot_move_backwards() {
    let app = TestApp::spawn().await;

    sqlx::query("UPDATE audit_chain_head SET last_seq = 10 WHERE id")
        .execute(&app.db)
        .await
        .expect("moving the head forwards is legitimate");

    assert_refused(
        sqlx::query("UPDATE audit_chain_head SET last_seq = 3 WHERE id")
            .execute(&app.db)
            .await,
        "rewinding the audit chain head",
    );
    assert_refused(
        sqlx::query("DELETE FROM audit_chain_head")
            .execute(&app.db)
            .await,
        "deleting the audit chain head",
    );
}

#[tokio::test]
async fn system_initialisation_cannot_be_reverted() {
    let app = TestApp::spawn().await;

    sqlx::query("UPDATE system_state SET initialized_at = now() WHERE id")
        .execute(&app.db)
        .await
        .expect("initialising is legitimate");

    assert_refused(
        sqlx::query("UPDATE system_state SET initialized_at = NULL WHERE id")
            .execute(&app.db)
            .await,
        "reverting initialisation",
    );
    assert_refused(
        sqlx::query("UPDATE system_state SET initialized_at = now() - interval '1 day' WHERE id")
            .execute(&app.db)
            .await,
        "rewriting the initialisation timestamp",
    );
    assert_refused(
        sqlx::query("DELETE FROM system_state")
            .execute(&app.db)
            .await,
        "deleting the system state row",
    );
}

// ===========================================================================
// Uniqueness and single-use invariants
// ===========================================================================

#[tokio::test]
async fn duplicate_emails_differing_only_in_case_are_impossible() {
    let app = TestApp::spawn().await;

    sqlx::query(
        "INSERT INTO users (id, email, email_normalized, display_name, principal_type, status)
         VALUES ($1,'Alice@Example.com','alice@example.com','Alice','INTERNAL','ACTIVE')",
    )
    .bind(Uuid::now_v7())
    .execute(&app.db)
    .await
    .expect("first insert");

    assert_refused(
        sqlx::query(
            "INSERT INTO users (id, email, email_normalized, display_name, principal_type, status)
             VALUES ($1,'ALICE@EXAMPLE.COM','alice@example.com','Alice 2','INTERNAL','ACTIVE')",
        )
        .bind(Uuid::now_v7())
        .execute(&app.db)
        .await,
        "a duplicate email differing only in case",
    );
}

#[tokio::test]
async fn only_one_pending_invitation_per_address_can_exist() {
    let app = TestApp::spawn().await;
    let (root, _, _) = seed(&app.db).await;

    let insert = |token: u8| {
        let db = app.db.clone();
        async move {
            sqlx::query(
                "INSERT INTO invitations (id, email, email_normalized, principal_type, display_name,
                                          token_hash, status, invited_by, expires_at)
                 VALUES ($1,'new@x.test','new@x.test','INTERNAL','New',
                         decode(repeat($2,32),'hex'),'PENDING',$3, now() + interval '1 day')",
            )
            .bind(Uuid::now_v7())
            .bind(format!("{token:02x}"))
            .bind(root)
            .execute(&db)
            .await
        }
    };

    insert(0x61).await.expect("first invitation");
    assert_refused(
        insert(0x62).await,
        "a second pending invitation for the same address",
    );
}

#[tokio::test]
async fn a_duplicate_permission_code_is_impossible() {
    let app = TestApp::spawn().await;
    assert_refused(
        sqlx::query(
            "INSERT INTO permissions (code, module, description, max_principal_type)
             VALUES ('audit.read','audit','duplicate','INTERNAL')",
        )
        .execute(&app.db)
        .await,
        "a duplicate permission code",
    );
}

#[tokio::test]
async fn invalid_enum_values_are_refused_by_check_constraints() {
    let app = TestApp::spawn().await;
    // Seeded so the last case has a real user to reference. Without a row, its
    // `INSERT ... SELECT ... LIMIT 1` would insert nothing and report success —
    // the test would pass while proving nothing.
    let _ = seed(&app.db).await;

    let cases: Vec<(&str, &str)> = vec![
        (
            "an unknown user status",
            "INSERT INTO users (id,email,email_normalized,display_name,principal_type,status)
             VALUES (gen_random_uuid(),'a@b.test','a@b.test','X','INTERNAL','DELETED')",
        ),
        (
            "an unknown principal type",
            "INSERT INTO users (id,email,email_normalized,display_name,principal_type,status)
             VALUES (gen_random_uuid(),'c@d.test','c@d.test','X','SUPERUSER','ACTIVE')",
        ),
        (
            "a non-normalised email",
            "INSERT INTO users (id,email,email_normalized,display_name,principal_type,status)
             VALUES (gen_random_uuid(),'E@F.test','E@F.test','X','INTERNAL','ACTIVE')",
        ),
        (
            "an unknown scope type on a role permission",
            "INSERT INTO role_permissions (role_id, permission_code, scope_type)
             VALUES ('00000000-0000-7000-8000-000000000002','tasks.create','EVERYTHING')",
        ),
        (
            "a RESOURCE scope with no object",
            "INSERT INTO user_permission_overrides (id,user_id,permission_code,effect,scope_type,granted_by)
             SELECT gen_random_uuid(), id, 'tasks.read','ALLOW','RESOURCE', id FROM users LIMIT 1",
        ),
    ];

    for (label, sql) in cases {
        assert_refused(sqlx::query(sql).execute(&app.db).await, label);
    }
}

// ===========================================================================
// Referential integrity (§8)
//
// Every one of these is reachable only by bypassing the application entirely.
// That is the point: a foreign key is the guarantee that survives a bug in the
// service layer, a bad migration, or an operator with a `psql` session.
// ===========================================================================

/// An orphan is refused at insert time, not merely avoided by the service layer.
///
/// Each of these tables hangs authority or credentials off a principal. A row whose
/// owner does not exist is not a tidiness problem: `credentials` without a user is a
/// password that authenticates nobody-in-particular, and a `user_role_assignments`
/// row pointing at a missing role is a grant whose meaning cannot be evaluated.
#[tokio::test]
async fn foreign_keys_refuse_orphaned_rows() {
    let app = TestApp::spawn().await;
    let ghost = Uuid::now_v7();

    let cases: Vec<(&str, &str)> = vec![
        (
            "credentials for a user that does not exist",
            "INSERT INTO credentials (user_id, password_hash) VALUES ($1, 'x')",
        ),
        (
            "a password-reset token for a user that does not exist",
            "INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at)
             VALUES (gen_random_uuid(), $1, decode(repeat('62',32),'hex'),
                     now() + interval '1 hour')",
        ),
        (
            "an MFA factor for a user that does not exist",
            "INSERT INTO mfa_factors (id, user_id, factor_type, secret_ciphertext, secret_nonce,
                                      key_version)
             VALUES (gen_random_uuid(), $1, 'TOTP', decode('61','hex'), decode('62','hex'), 1)",
        ),
        (
            "a role assignment for a user that does not exist",
            "INSERT INTO user_role_assignments (id, user_id, role_id)
             VALUES (gen_random_uuid(), $1, '00000000-0000-7000-8000-000000000002')",
        ),
    ];

    for (label, sql) in cases {
        assert_refused(sqlx::query(sql).bind(ghost).execute(&app.db).await, label);
    }

    // ...and the inverse direction: a grant naming a role that does not exist.
    let (_, employee, _) = seed(&app.db).await;
    assert_refused(
        sqlx::query("INSERT INTO user_role_assignments (id, user_id, role_id) VALUES ($1,$2,$3)")
            .bind(Uuid::now_v7())
            .bind(employee)
            .bind(Uuid::now_v7())
            .execute(&app.db)
            .await,
        "a role assignment naming a role that does not exist",
    );

    // A permission code is a foreign key into the seeded catalogue, so a typo in a
    // grant is a failed INSERT rather than a grant that silently authorises nothing.
    assert_refused(
        sqlx::query(
            "INSERT INTO role_permissions (role_id, permission_code, scope_type)
             VALUES ('00000000-0000-7000-8000-000000000002', 'audit.raed', 'GLOBAL')",
        )
        .execute(&app.db)
        .await,
        "a role permission naming a permission that does not exist",
    );
}

/// `ON DELETE RESTRICT` everywhere: a principal that anything still references
/// cannot be erased, so history never loses the subject it refers to.
#[tokio::test]
async fn a_referenced_user_cannot_be_erased() {
    let app = TestApp::spawn().await;
    let (_, employee, _) = seed(&app.db).await;

    // A real Argon2id PHC string: `credentials.password_hash` carries
    // `CHECK (password_hash LIKE '$argon2id$%')`, so a placeholder would be refused
    // here and this test would "pass" without ever creating the reference whose
    // protection is the point.
    let hash = fixtures::password_hash(&app).await;
    sqlx::query("INSERT INTO credentials (user_id, password_hash) VALUES ($1, $2)")
        .bind(employee)
        .bind(&hash)
        .execute(&app.db)
        .await
        .expect("seed credentials");

    assert_refused(
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(employee)
            .execute(&app.db)
            .await,
        "deleting a user that credentials still reference",
    );

    let still_there: (i64,) = sqlx::query_as("SELECT count(*) FROM users WHERE id = $1")
        .bind(employee)
        .fetch_one(&app.db)
        .await
        .expect("count");
    assert_eq!(still_there.0, 1);
}

/// Single-use tokens: what the *database* does and does not guarantee.
///
/// **This test documents a deliberate boundary rather than only a defence.** The
/// schema makes it impossible for two rows to share a token digest, so a stolen
/// link can never be duplicated into a second live credential. It does **not**
/// constrain `consumed_at`: nothing at the database level stops a second UPDATE
/// re-clearing it, because single use is enforced by the consuming statement's
/// `WHERE consumed_at IS NULL` gate inside a `FOR UPDATE` transaction.
///
/// That split is worth pinning explicitly. A reader who assumes the database
/// enforces single use would be wrong, and the race suite — not this file — is what
/// proves the application-level gate actually holds under contention.
#[tokio::test]
async fn a_token_digest_is_unique_but_consumption_is_an_application_invariant() {
    let app = TestApp::spawn().await;
    let (_, employee, _) = seed(&app.db).await;

    let insert = |suffix: &'static str| {
        let db = app.db.clone();
        async move {
            sqlx::query(
                "INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at)
                 VALUES ($1, $2, decode(repeat($3,32),'hex'), now() + interval '1 hour')",
            )
            .bind(Uuid::now_v7())
            .bind(employee)
            .bind(suffix)
            .execute(&db)
            .await
        }
    };

    insert("61").await.expect("the first token");
    assert_refused(
        insert("61").await,
        "a second token row carrying the same digest",
    );
    // A *different* digest is fine — the constraint is on the secret, not the user.
    insert("62").await.expect("a second, distinct token");

    // And the honest half: the database does not itself prevent un-consuming.
    sqlx::query("UPDATE password_reset_tokens SET consumed_at = now()")
        .execute(&app.db)
        .await
        .expect("consume");
    let reopened = sqlx::query("UPDATE password_reset_tokens SET consumed_at = NULL")
        .execute(&app.db)
        .await
        .expect("the database does not constrain consumed_at");
    assert_eq!(
        reopened.rows_affected(),
        2,
        "if this ever starts failing, the schema gained a guard and the invariant \
         table in the audit report needs updating"
    );
}

/// Converting a principal between types is guarded **only for the owner**.
///
/// Recorded as a measured boundary, not as a pass. The `CHECK` restricts the value
/// set and `rb_users_protect_root` pins the owner, but an ordinary employee's
/// `principal_type` can be rewritten by anyone holding the migration role — and the
/// client-envelope triggers fire on membership and grant writes, not on this
/// column, so the conversion leaves the user's existing INTERNAL role assignments
/// in place. The application is the only thing that prevents this transition.
#[tokio::test]
async fn a_non_owner_principal_transition_is_constrained_only_by_the_value_set() {
    let app = TestApp::spawn().await;
    let (_, employee, _) = seed(&app.db).await;

    // The value set is enforced.
    assert_refused(
        sqlx::query("UPDATE users SET principal_type = 'ROOT' WHERE id = $1")
            .bind(employee)
            .execute(&app.db)
            .await,
        "an unknown principal type",
    );

    sqlx::query(
        "INSERT INTO user_role_assignments (id, user_id, role_id)
         VALUES ($1, $2, '00000000-0000-7000-8000-000000000002')",
    )
    .bind(Uuid::now_v7())
    .bind(employee)
    .execute(&app.db)
    .await
    .expect("assign the built-in employee role");

    // ...but the transition itself is not, and it does not cascade to the grants
    // the envelope would have refused on insert. This is the gap the report records.
    let converted = sqlx::query("UPDATE users SET principal_type = 'CLIENT' WHERE id = $1")
        .bind(employee)
        .execute(&app.db)
        .await
        .expect("the database permits a non-owner conversion");
    assert_eq!(converted.rows_affected(), 1);

    let stranded: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM user_role_assignments ura
           JOIN roles r ON r.id = ura.role_id
          WHERE ura.user_id = $1 AND r.allowed_principal_type = 'INTERNAL'",
    )
    .bind(employee)
    .fetch_one(&app.db)
    .await
    .expect("count");
    assert_eq!(
        stranded.0, 1,
        "if this reaches zero the schema gained a cascade and the report needs updating"
    );
}

// ===========================================================================
// Audit integrity end to end (§16)
//
// `chain.rs` has unit tests over synthetic entries. Those prove the algorithm.
// They do not prove that the rows this application actually writes verify, nor
// that a real edit to a real table is caught — which is the whole claim of
// ADR-006. These drive genuine events through the router, then tamper with the
// stored rows and re-run the shipped verifier.
//
// Every one of these runs against the per-test throwaway database created by
// `TestApp::spawn`, which is dropped when the test ends. Nothing here touches any
// database that outlives the test.
// ===========================================================================

/// A bootstrapped system with several genuinely sensitive events behind it, plus a
/// ROOT token that has just proved a second factor (the verifier demands step-up).
async fn chain_with_real_events() -> (TestApp, String) {
    let app = TestApp::spawn().await;

    app.post(
        "/api/v1/bootstrap/root",
        None,
        json!({
            "bootstrap_secret": TEST_BOOTSTRAP_SECRET,
            "email": fixtures::ROOT_EMAIL,
            "display_name": "System Owner",
            "password": TEST_PASSWORD,
        }),
    )
    .await
    .assert_status(StatusCode::CREATED);

    let token = fixtures::login(&app, fixtures::ROOT_EMAIL).await;
    // Enrolment both completes MFA and stamps `mfa_verified_at`, which is what the
    // verifier's step-up requirement reads.
    fixtures::enrol_totp(&app, &token).await;

    // A few more audited, consequential mutations so the chain has real links.
    for (code, name) in [("ops", "Operations"), ("eng", "Engineering")] {
        app.post(
            "/api/v1/departments",
            Some(&token),
            json!({ "code": code, "name": name }),
        )
        .await
        .assert_status(StatusCode::CREATED);
    }

    (app, token)
}

/// The lowest and highest `seq` currently in the chain.
async fn chain_bounds(app: &TestApp) -> (i64, i64) {
    let row: (i64, i64) =
        sqlx::query_as("SELECT coalesce(min(seq), 0), coalesce(max(seq), 0) FROM audit_events")
            .fetch_one(&app.db)
            .await
            .expect("read the chain bounds");
    row
}

/// Rewrite an audit row the only way it can be rewritten: as the table's owner,
/// with the append-only trigger switched off around the statement.
///
/// This is exactly the threat ADR-006 names — a malicious administrator, a stolen
/// dump, a compromised backup — and it is why the chain key lives outside the
/// database. The trigger is switched back on afterwards so that the verifier is
/// examining a table in its normal state, and the *data* is the only thing that
/// changed.
async fn tamper(app: &TestApp, sql: &'static str, seq: i64) {
    sqlx::query("ALTER TABLE audit_events DISABLE TRIGGER trg_audit_events_append_only")
        .execute(&app.db)
        .await
        .expect("the migration role owns the table and may disable its trigger");

    let affected = sqlx::query(sql)
        .bind(seq)
        .execute(&app.db)
        .await
        .expect("tamper")
        .rows_affected();
    assert_eq!(
        affected, 1,
        "the tampering statement changed {affected} rows"
    );

    sqlx::query("ALTER TABLE audit_events ENABLE TRIGGER trg_audit_events_append_only")
        .execute(&app.db)
        .await
        .expect("restore the trigger");
}

async fn run_verifier(app: &TestApp, token: &str) -> serde_json::Value {
    let response = app.get("/api/v1/audit/verify", Some(token)).await;
    response.assert_status(StatusCode::OK);

    // Deliberately *not* `assert_no_secrets`, which bans the substring `entry_hash`
    // outright. On divergence this endpoint returns a `diagnostics` object naming
    // the stored digests of the offending row, and that is by design: it is what
    // tells an auditor where the damage is. Publishing a digest costs nothing —
    // forging the chain needs the HMAC key, not the hashes it produced.
    //
    // The listing endpoint is the one that must never expose chain material, and
    // `tests/integration/settings_audit_system.rs` holds that line. What matters
    // here is that the *key* never appears, so that is what is checked.
    let text = String::from_utf8_lossy(&response.raw);
    for forbidden in ["chain_key", "$argon2", "postgres://", "dev_migrator_pw"] {
        assert!(
            !text.contains(forbidden),
            "the verifier response leaked `{forbidden}`: {text}"
        );
    }
    response.json().clone()
}

/// The baseline: what the application itself writes must verify.
///
/// Without this, every tamper-detection result below would be worthless — a
/// verifier that reports damage on an untouched chain detects nothing, it simply
/// always complains.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_genuine_chain_verifies_intact() {
    let (app, token) = chain_with_real_events().await;

    let (_, head) = chain_bounds(&app).await;
    assert!(
        head >= 4,
        "expected several sensitive events, found {head} — the tamper tests below \
         would be checking an almost-empty chain"
    );

    let result = run_verifier(&app, &token).await;
    println!("AUDIT-EVIDENCE untampered: {result}");
    assert_eq!(result["outcome"], json!("INTACT"), "{result}");
    assert_eq!(result["reached_chain_head"], json!(true));
    assert_eq!(
        result["entries_checked"].as_i64().expect("a count"),
        head,
        "the verifier did not cover the whole chain"
    );
}

/// Editing a field that is covered by the chain is detected, and located.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rewriting_an_audit_row_is_detected() {
    let (app, token) = chain_with_real_events().await;
    let (first, head) = chain_bounds(&app).await;
    let victim = (first + head) / 2;

    // The classic cover-up: a refusal reported as a success, or the reverse.
    tamper(
        &app,
        "UPDATE audit_events SET outcome = 'FAILURE' WHERE seq = $1",
        victim,
    )
    .await;

    let result = run_verifier(&app, &token).await;
    println!("AUDIT-EVIDENCE rewritten seq={victim}: {result}");
    assert_eq!(
        result["outcome"],
        json!("HASH_MISMATCH"),
        "a rewritten audit row was not detected: {result}"
    );
    assert_eq!(
        result["first_divergent_seq"],
        json!(victim),
        "the verifier did not point at the row that was altered: {result}"
    );
}

/// Rewriting `metadata` — the part an attacker would most want to edit, because it
/// carries the *detail* of what was done — is covered by the chain too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rewriting_audit_metadata_is_detected() {
    let (app, token) = chain_with_real_events().await;
    let (first, head) = chain_bounds(&app).await;
    let victim = (first + head) / 2;

    tamper(
        &app,
        "UPDATE audit_events SET metadata = jsonb_build_object('source', 'innocent') WHERE seq = $1",
        victim,
    )
    .await;

    let result = run_verifier(&app, &token).await;
    println!("AUDIT-EVIDENCE metadata seq={victim}: {result}");
    assert_eq!(
        result["outcome"],
        json!("HASH_MISMATCH"),
        "rewritten metadata was not detected: {result}"
    );
    assert_eq!(result["first_divergent_seq"], json!(victim));
}

/// Excising an entry from the middle leaves a gap the verifier reports, rather than
/// a shorter chain that still looks self-consistent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deleting_an_audit_row_is_detected() {
    let (app, token) = chain_with_real_events().await;
    let (first, head) = chain_bounds(&app).await;
    let victim = (first + head) / 2;

    tamper(&app, "DELETE FROM audit_events WHERE seq = $1", victim).await;

    let result = run_verifier(&app, &token).await;
    println!("AUDIT-EVIDENCE deleted seq={victim}: {result}");
    assert_eq!(
        result["outcome"],
        json!("MISSING_SEQUENCE"),
        "a deleted audit row was not detected: {result}"
    );
    assert_eq!(result["first_divergent_seq"], json!(victim));
}

/// Deleting the *most recent* entries — the shape of a cover-up performed right
/// after the act — is caught by the separate head record, not by the links.
///
/// A truncated tail is internally consistent: every surviving link still checks
/// out. Only the independently maintained `audit_chain_head` knows how far the
/// chain is supposed to reach, which is precisely why it exists.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn truncating_the_audit_tail_is_detected() {
    let (app, token) = chain_with_real_events().await;
    let (_, head) = chain_bounds(&app).await;

    tamper(&app, "DELETE FROM audit_events WHERE seq = $1", head).await;

    let result = run_verifier(&app, &token).await;
    println!("AUDIT-EVIDENCE truncated head={head}: {result}");
    assert_eq!(
        result["outcome"],
        json!("HEAD_MISMATCH"),
        "a truncated audit tail was not detected: {result}"
    );
}

/// The other half of the claim: the identity the application runs as could not have
/// performed any of the tampering above.
///
/// The tests above had to hold the **migration** role to do their damage. If the
/// runtime role could do the same, a compromised application process would be able
/// to rewrite its own history and every result above would be moot.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_runtime_role_could_not_have_tampered_at_all() {
    let (app, _token) = chain_with_real_events().await;
    let runtime = app.runtime_role_pool().await;
    let (_, head) = chain_bounds(&app).await;

    // 1. It cannot switch the guard off — it does not own the table.
    assert_refused(
        sqlx::query("ALTER TABLE audit_events DISABLE TRIGGER trg_audit_events_append_only")
            .execute(&runtime)
            .await,
        "the runtime role disabling the append-only trigger",
    );
    // Nor by disabling all of them, which is a separate privilege check.
    assert_refused(
        sqlx::query("ALTER TABLE audit_events DISABLE TRIGGER ALL")
            .execute(&runtime)
            .await,
        "the runtime role disabling every trigger on the audit log",
    );

    // 2. It cannot perform the writes themselves, trigger or no trigger.
    assert_refused(
        sqlx::query("UPDATE audit_events SET outcome = 'FAILURE' WHERE seq = $1")
            .bind(head)
            .execute(&runtime)
            .await,
        "the runtime role updating an audit row",
    );
    assert_refused(
        sqlx::query("DELETE FROM audit_events WHERE seq = $1")
            .bind(head)
            .execute(&runtime)
            .await,
        "the runtime role deleting an audit row",
    );
    assert_refused(
        sqlx::query("TRUNCATE audit_events").execute(&runtime).await,
        "the runtime role truncating the audit log",
    );
    // 3. Nor drop the evidence wholesale.
    assert_refused(
        sqlx::query("DROP TABLE audit_events")
            .execute(&runtime)
            .await,
        "the runtime role dropping the audit log",
    );

    // The chain is exactly as long as it was, so nothing above partially applied.
    let (_, head_after) = chain_bounds(&app).await;
    assert_eq!(head_after, head, "the runtime role changed the audit log");
}
