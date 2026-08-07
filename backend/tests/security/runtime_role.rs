//! Privilege separation, verified by executing attacks **as the runtime database
//! role** — the identity the running application actually connects with.
//!
//! Brief §98 requires the ROOT destruction suite to include "database operations
//! using runtime DB role". This is that: even with a completely compromised
//! application process able to execute arbitrary SQL, the invariants must hold.

use sqlx::PgPool;
use uuid::Uuid;

use crate::common::TestApp;

async fn seed_owner(pool: &PgPool) -> Uuid {
    let root = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO users (id, email, email_normalized, display_name, principal_type,
                            status, mfa_required, activated_at)
         VALUES ($1,'root@rt.test','root@rt.test','Root','INTERNAL','ACTIVE',true, now())",
    )
    .bind(root)
    .execute(pool)
    .await
    .expect("seed owner");
    sqlx::query("INSERT INTO system_ownership (root_user_id) VALUES ($1)")
        .bind(root)
        .execute(pool)
        .await
        .expect("establish ownership");
    root
}

#[track_caller]
fn assert_refused(result: Result<sqlx::postgres::PgQueryResult, sqlx::Error>, what: &str) {
    match result {
        Err(_) => {}
        Ok(r) => panic!(
            "the RUNTIME database role was permitted to {what} (rows affected: {})",
            r.rows_affected()
        ),
    }
}

#[tokio::test]
async fn the_runtime_role_is_not_a_superuser_and_owns_nothing() {
    let app = TestApp::spawn().await;
    let runtime = app.runtime_role_pool().await;

    let row: (String, bool, bool, bool) = sqlx::query_as(
        "SELECT current_user, rolsuper, rolcreatedb, rolcreaterole
           FROM pg_roles WHERE rolname = current_user",
    )
    .fetch_one(&runtime)
    .await
    .expect("read role attributes");

    assert_eq!(row.0, "roleblank_app");
    assert!(!row.1, "the runtime role must not be a superuser");
    assert!(!row.2, "the runtime role must not have CREATEDB");
    assert!(!row.3, "the runtime role must not have CREATEROLE");

    let owned: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM pg_tables WHERE schemaname = 'public' AND tableowner = current_user",
    )
    .fetch_one(&runtime)
    .await
    .expect("count owned tables");
    assert_eq!(
        owned.0, 0,
        "the runtime role owns tables and could therefore disable triggers"
    );
}

#[tokio::test]
async fn the_runtime_role_cannot_alter_the_schema() {
    let app = TestApp::spawn().await;
    let runtime = app.runtime_role_pool().await;

    let attacks: Vec<(&str, &str)> = vec![
        ("drop the audit table", "DROP TABLE audit_events"),
        ("drop the users table", "DROP TABLE users"),
        (
            "disable the ROOT protection trigger",
            "ALTER TABLE users DISABLE TRIGGER trg_users_protect_root",
        ),
        (
            "disable the audit append-only trigger",
            "ALTER TABLE audit_events DISABLE TRIGGER trg_audit_events_append_only",
        ),
        (
            "disable the ownership immutability trigger",
            "ALTER TABLE system_ownership DISABLE TRIGGER trg_system_ownership_immutable",
        ),
        (
            "drop a constraint",
            "ALTER TABLE users DROP CONSTRAINT users_status_check",
        ),
        (
            "add a column",
            "ALTER TABLE users ADD COLUMN backdoor boolean",
        ),
        (
            "create a shadowing table",
            "CREATE TABLE public.users_shadow (id uuid)",
        ),
        (
            "create a function",
            "CREATE FUNCTION public.rb_backdoor() RETURNS void AS $$ BEGIN END $$ LANGUAGE plpgsql",
        ),
    ];

    for (label, sql) in attacks {
        assert_refused(sqlx::query(sql).execute(&runtime).await, label);
    }
}

#[tokio::test]
async fn the_runtime_role_cannot_touch_the_owner() {
    let app = TestApp::spawn().await;
    let root = seed_owner(&app.db).await;
    let runtime = app.runtime_role_pool().await;

    // No DELETE grant on `users` at all — not only for the owner. Users are
    // archived, never erased, so historical references and audit meaning survive.
    assert_refused(
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(root)
            .execute(&runtime)
            .await,
        "delete the owner",
    );
    assert_refused(
        sqlx::query("DELETE FROM users").execute(&runtime).await,
        "delete every user",
    );
    assert_refused(
        sqlx::query("UPDATE users SET status='SUSPENDED' WHERE id=$1")
            .bind(root)
            .execute(&runtime)
            .await,
        "suspend the owner",
    );
    assert_refused(
        sqlx::query("UPDATE users SET principal_type='CLIENT' WHERE id=$1")
            .bind(root)
            .execute(&runtime)
            .await,
        "demote the owner to an external principal",
    );

    // Ownership itself is read-only to the application.
    assert_refused(
        sqlx::query("UPDATE system_ownership SET root_user_id = gen_random_uuid()")
            .execute(&runtime)
            .await,
        "move ownership",
    );
    assert_refused(
        sqlx::query("DELETE FROM system_ownership")
            .execute(&runtime)
            .await,
        "remove ownership",
    );

    // INSERT *is* granted — bootstrap is an HTTP endpoint — but the singleton
    // primary key means it can succeed at most once in the database's lifetime.
    assert_refused(
        sqlx::query("INSERT INTO system_ownership (root_user_id) VALUES ($1)")
            .bind(root)
            .execute(&runtime)
            .await,
        "establish a second ownership row",
    );

    let still: (String, Uuid) = sqlx::query_as(
        "SELECT u.status, o.root_user_id
           FROM system_ownership o JOIN users u ON u.id = o.root_user_id",
    )
    .fetch_one(&app.db)
    .await
    .expect("owner intact");
    assert_eq!(still.0, "ACTIVE");
    assert_eq!(still.1, root);
}

#[tokio::test]
async fn the_runtime_role_can_append_audit_but_never_rewrite_it() {
    let app = TestApp::spawn().await;
    let runtime = app.runtime_role_pool().await;

    // Appending must work — the application writes audit events on every mutation.
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO audit_events (id, action_code, outcome, entry_hash)
         VALUES ($1,'USER.CREATED','SUCCESS', decode(repeat('61',32),'hex'))",
    )
    .bind(id)
    .execute(&runtime)
    .await
    .expect("the application must be able to append audit events");

    // Rewriting must not.
    assert_refused(
        sqlx::query("UPDATE audit_events SET outcome='FAILURE' WHERE id=$1")
            .bind(id)
            .execute(&runtime)
            .await,
        "update an audit event",
    );
    assert_refused(
        sqlx::query("DELETE FROM audit_events WHERE id=$1")
            .bind(id)
            .execute(&runtime)
            .await,
        "delete an audit event",
    );
    assert_refused(
        sqlx::query("DELETE FROM audit_events")
            .execute(&runtime)
            .await,
        "delete all audit events",
    );
    assert_refused(
        sqlx::query("TRUNCATE audit_events").execute(&runtime).await,
        "truncate the audit log",
    );

    let remaining: (i64,) = sqlx::query_as("SELECT count(*) FROM audit_events")
        .fetch_one(&app.db)
        .await
        .expect("count");
    assert_eq!(remaining.0, 1);
}

#[tokio::test]
async fn the_runtime_role_cannot_rewrite_migration_history() {
    let app = TestApp::spawn().await;
    let runtime = app.runtime_role_pool().await;

    for (label, sql) in [
        ("delete migration history", "DELETE FROM _sqlx_migrations"),
        (
            "rewrite a migration checksum",
            "UPDATE _sqlx_migrations SET checksum = ''",
        ),
        (
            "mark a migration failed",
            "UPDATE _sqlx_migrations SET success = false",
        ),
    ] {
        assert_refused(sqlx::query(sql).execute(&runtime).await, label);
    }
}

/// The `DELETE` grant is deliberately narrow: exactly two tables, both bounded
/// caches of completed work with a documented retention policy. If this test
/// starts failing because a new table appears in the list, that is a schema
/// change that needs review, not a test to update.
#[tokio::test]
async fn delete_is_granted_on_exactly_the_expected_tables() {
    let app = TestApp::spawn().await;
    let runtime = app.runtime_role_pool().await;

    let mut deletable: Vec<String> = sqlx::query_scalar(
        "SELECT table_name FROM information_schema.role_table_grants
          WHERE grantee = 'roleblank_app' AND privilege_type = 'DELETE'
          ORDER BY table_name",
    )
    .fetch_all(&runtime)
    .await
    .expect("read grants");
    deletable.sort();

    assert_eq!(
        deletable,
        vec![
            "idempotency_records".to_string(),
            "outbox_events".to_string(),
            "role_permissions".to_string(),
            "user_permission_overrides".to_string(),
            "user_role_assignments".to_string(),
        ],
        "the set of tables the application may DELETE from changed — review it deliberately"
    );
}

/// Nothing in the schema may be reachable by `PUBLIC`, or every role in the
/// cluster would inherit access.
#[tokio::test]
async fn public_has_no_privileges_on_the_schema() {
    let app = TestApp::spawn().await;

    let public_grants: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM information_schema.role_table_grants
          WHERE grantee = 'PUBLIC' AND table_schema = 'public'",
    )
    .fetch_one(&app.db)
    .await
    .expect("read grants");
    assert_eq!(
        public_grants.0, 0,
        "PUBLIC holds table privileges in the public schema"
    );
}
