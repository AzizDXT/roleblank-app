//! Database-level security invariants, tested directly against PostgreSQL.
//!
//! These do not go through HTTP. The whole point is to prove that the invariants
//! hold **even when the application is bypassed entirely** — an application bug, a
//! stray migration, or an operator with a `psql` session must not be sufficient to
//! remove the system owner or rewrite audit history.
//!
//! Brief §68 requires exactly this: "Do not test only through HTTP."

use sqlx::PgPool;
use uuid::Uuid;

use crate::common::TestApp;

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
