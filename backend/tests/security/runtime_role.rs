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
            // Added by 0012. `DELETE /api/v1/roles/{id}` is fully authorised and
            // then could not execute its final statement, so it returned `500` for
            // every caller. The statement itself still carries
            // `AND is_system = false`, so the grant does not widen what an
            // authorised caller can reach.
            "roles".to_string(),
            "user_permission_overrides".to_string(),
            "user_role_assignments".to_string(),
        ],
        "the set of tables the application may DELETE from changed — review it deliberately"
    );
}

/// The inverse invariant to everything above: what the runtime role **must be able
/// to do**.
///
/// Every other test in this file asserts a refusal. That asymmetry hid a
/// deployment-blocking defect for the whole of the build: `0009_runtime_grants.sql`
/// enumerated the tables the application touches and omitted `permissions`, so
/// `serve` could not read the catalogue it verifies at startup and **the
/// application could not boot at all** as its intended identity. 903 tests passed
/// throughout, because the integration harness connects as the migrator role and
/// no test ever ran the startup path.
///
/// A table the runtime role cannot read is a startup failure or a runtime 500
/// waiting for the code path that reads it. There is no table in this schema the
/// application legitimately must be blind to — the restrictions that matter are all
/// on *writing*, and those are asserted above.
#[tokio::test]
async fn the_runtime_role_can_read_every_table_in_the_schema() {
    let app = TestApp::spawn().await;
    let runtime = app.runtime_role_pool().await;

    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename",
    )
    .fetch_all(&app.db)
    .await
    .expect("list tables");

    assert!(
        tables.len() > 25,
        "expected the full schema, found {}",
        tables.len()
    );

    let mut unreadable = Vec::new();
    for table in &tables {
        // Identifier interpolated from `pg_tables`, not from input; bounded by the
        // schema itself.
        let sql = format!("SELECT 1 FROM {table} LIMIT 1");
        if sqlx::query(sqlx::AssertSqlSafe(sql))
            .fetch_optional(&runtime)
            .await
            .is_err()
        {
            unreadable.push(table.clone());
        }
    }

    assert!(
        unreadable.is_empty(),
        "the runtime role cannot SELECT from: {unreadable:?}\n\
         Add a GRANT in a new migration. Every table the application cannot read is a \
         startup failure or a runtime 500 waiting to happen — `permissions` was exactly \
         this, and it prevented the application from booting."
    );
}

/// The startup path itself, executed as the identity that actually runs it.
///
/// `serve` performs these two reads before it binds a port. Neither had ever been
/// executed as `roleblank_app` by any test.
#[tokio::test]
async fn the_runtime_role_can_execute_the_startup_queries() {
    let app = TestApp::spawn().await;
    let runtime = app.runtime_role_pool().await;

    // 1. Schema-currency check — `database::migrations_are_current`.
    let applied: Vec<(i64,)> = sqlx::query_as(
        "SELECT version FROM _sqlx_migrations WHERE success = true ORDER BY version",
    )
    .fetch_all(&runtime)
    .await
    .expect("the runtime role must be able to read migration history");
    assert!(!applied.is_empty(), "no migrations recorded");

    // 2. Permission-catalogue verification — `cli::verify_permission_catalog`.
    //    This is the exact statement, and it is the one that failed.
    let catalogue: Vec<(String, String, String, bool)> = sqlx::query_as(
        "SELECT code, module, max_principal_type, is_dangerous FROM permissions ORDER BY code",
    )
    .fetch_all(&runtime)
    .await
    .expect(
        "the runtime role must be able to read the permission catalogue — without this \
         the application refuses to start",
    );

    assert_eq!(
        catalogue.len(),
        roleblank_backend::modules::authorization::catalog::PERMISSIONS.len(),
        "the seeded catalogue and the compiled catalogue disagree in size"
    );

    // And the check the startup path then performs must pass.
    assert!(
        roleblank_backend::modules::authorization::catalog::diff_against(&catalogue).is_none(),
        "the catalogue read as the runtime role does not match the compiled one"
    );
}

/// The audit append path, executed statement-for-statement as the runtime role.
///
/// Reading a table is not the same as being able to write the way the application
/// writes. `0009` granted `USAGE, SELECT` on the audit sequence, which covers
/// `nextval` and `currval` — but **`setval()` requires `UPDATE`**. `audit::append`
/// calls `setval` on every write, and `append` runs inside *every audited
/// mutation*, so bootstrap, login and every create returned `500` with
/// `SQLSTATE 42501` while the application otherwise looked healthy.
///
/// A grant test that only asserts `SELECT` would not have caught it. This one
/// performs the same four statements `append` performs, in the same order, as
/// `roleblank_app`.
#[tokio::test]
async fn the_runtime_role_can_perform_the_whole_audit_append() {
    let app = TestApp::spawn().await;
    let runtime = app.runtime_role_pool().await;

    let mut tx = runtime.begin().await.expect("begin as the runtime role");

    // 1. Lock the chain head.
    let (last_seq, _last_hash): (i64, Option<Vec<u8>>) =
        sqlx::query_as("SELECT last_seq, last_hash FROM audit_chain_head WHERE id FOR UPDATE")
            .fetch_one(&mut *tx)
            .await
            .expect("the runtime role must be able to lock the audit chain head");

    let next = last_seq + 1;
    let id = Uuid::now_v7();

    // 2. Insert the event with an explicit seq.
    sqlx::query(
        "INSERT INTO audit_events (seq, id, action_code, outcome, entry_hash)
         VALUES ($1, $2, 'USER.CREATED', 'SUCCESS', decode(repeat('61',32),'hex'))",
    )
    .bind(next)
    .bind(id)
    .execute(&mut *tx)
    .await
    .expect("the runtime role must be able to append an audit event");

    // 3. Advance the sequence — the statement that was actually failing.
    sqlx::query("SELECT setval('audit_events_seq_seq', $1, true)")
        .bind(next)
        .execute(&mut *tx)
        .await
        .expect(
            "the runtime role must be able to setval the audit sequence — this requires \
             UPDATE on the sequence, which USAGE does not imply, and without it every \
             audited mutation in the system fails with SQLSTATE 42501",
        );

    // 4. Move the chain head forward.
    sqlx::query("UPDATE audit_chain_head SET last_seq = $1, last_hash = $2 WHERE id")
        .bind(next)
        .bind(vec![0x61u8; 32])
        .execute(&mut *tx)
        .await
        .expect("the runtime role must be able to advance the audit chain head");

    tx.commit().await.expect("commit the audit append");

    let stored: (i64,) = sqlx::query_as("SELECT seq FROM audit_events WHERE id = $1")
        .bind(id)
        .fetch_one(&app.db)
        .await
        .expect("the event must be readable afterwards");
    assert_eq!(stored.0, next);
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

/// Replay the statements `authorization::service::delete_role` issues, as the role
/// the application actually runs as.
///
/// This is the test that would have caught the defect 0012 fixes, and the reason
/// the grant-list test above did not: that one asserts the deletable set equals a
/// list it already knew, so it can detect a grant *disappearing* and can never
/// detect one that was never there. Pinning the current answer cannot discover that
/// the answer is wrong.
///
/// The integration tests drive this route and pass, because the harness connects as
/// `roleblank_migrator`, which owns the tables. Three defects of exactly this shape
/// have now been found — the missing `SELECT` on `permissions`, the missing
/// `UPDATE` on the audit sequence, and this one — so the rule is: any statement the
/// application issues must be exercised at least once by the role that will issue
/// it in production.
#[tokio::test]
async fn the_runtime_role_can_delete_a_custom_role() {
    let app = TestApp::spawn().await;
    let runtime = app.runtime_role_pool().await;

    let role_id = Uuid::now_v7();
    // Seeded as the migrator, because creating the row is not what is under test.
    sqlx::query(
        "INSERT INTO roles (id, code, name, description, allowed_principal_type, is_system)
         VALUES ($1, $2, 'Doomed', '', 'INTERNAL', false)",
    )
    .bind(role_id)
    .bind(format!("doomed_{}", role_id.simple()))
    .execute(&app.db)
    .await
    .expect("seed a custom role");

    // The two statements the service issues, in order, as the runtime role.
    sqlx::query("DELETE FROM role_permissions WHERE role_id = $1")
        .bind(role_id)
        .execute(&runtime)
        .await
        .expect("the runtime role must be able to clear a role's permissions");

    let deleted = sqlx::query("DELETE FROM roles WHERE id = $1 AND is_system = false")
        .bind(role_id)
        .execute(&runtime)
        .await
        .expect("the runtime role must be able to delete a custom role");
    assert_eq!(deleted.rows_affected(), 1, "the role was not deleted");

    // The grant must not have opened a way to remove a built-in role. That is held
    // by the statement's own predicate, not by the privilege, so it is asserted
    // rather than assumed.
    let system_removed = sqlx::query("DELETE FROM roles WHERE id = $1 AND is_system = false")
        .bind(Uuid::parse_str("00000000-0000-7000-8000-000000000001").expect("seeded role id"))
        .execute(&runtime)
        .await
        .expect("statement should run");
    assert_eq!(
        system_removed.rows_affected(),
        0,
        "a built-in role was deleted; the is_system predicate is the only thing stopping it"
    );
}
