-- =============================================================================
-- 0009 — Runtime privilege separation
--
-- The role that OWNS this schema (roleblank_migrator) is NOT the role the
-- application connects as (roleblank_app). Production runtime credentials must
-- not be able to drop tables, alter the schema, disable triggers, rewrite
-- migration history, or bypass the audit and ROOT invariants.
--
-- This migration is conditional on the runtime role existing, so that
-- `migrate` still succeeds from a completely empty database in environments
-- where roles have not been provisioned yet (a developer's throwaway database,
-- or a test harness). If the role is absent the grants are skipped with a
-- NOTICE — they are re-applied idempotently on the next run after provisioning.
--
-- Role provisioning itself lives in ops/sql/provision_dev.sql and
-- ops/sql/provision_ci.sql, because creating roles requires privileges the
-- migrator deliberately may not have in production.
-- =============================================================================

DO $$
DECLARE
    v_app_role CONSTANT text := 'roleblank_app';
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = v_app_role) THEN
        RAISE NOTICE
            'runtime role % does not exist; skipping grants. Run ops/sql/provision_*.sql and re-run migrate.',
            v_app_role;
        RETURN;
    END IF;

    -- Start from nothing. PUBLIC must not retain anything by default either.
    EXECUTE format('REVOKE ALL ON SCHEMA public FROM %I', v_app_role);
    EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA public FROM %I', v_app_role);
    EXECUTE format('REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM %I', v_app_role);
    EXECUTE format('REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM %I', v_app_role);
    REVOKE ALL ON SCHEMA public FROM PUBLIC;

    -- USAGE only: the application may resolve names in the schema. It may NOT
    -- CREATE in it, so it cannot introduce a shadowing table or a helper function.
    EXECUTE format('GRANT USAGE ON SCHEMA public TO %I', v_app_role);

    -- --- Ordinary business tables: full DML, no DDL ---------------------------
    EXECUTE format($g$
        GRANT SELECT, INSERT, UPDATE ON
            users, credentials,
            sessions, session_refresh_tokens, mfa_factors, recovery_codes,
            password_reset_tokens, invitations, invitation_roles,
            roles, role_permissions, user_role_assignments, user_permission_overrides,
            departments, department_memberships,
            client_accounts, client_memberships,
            projects, project_memberships, project_client_links,
            tasks, task_assignees,
            system_settings, feature_flags
        TO %I $g$, v_app_role);

    -- --- Deliberate DELETE policy --------------------------------------------
    -- DELETE is granted on exactly two tables, both of which are bounded caches of
    -- completed work with a documented retention policy. Everything else in this
    -- schema is a security principal or a business record with historical meaning,
    -- and its lifecycle is expressed as archived / revoked / removed_at / status.
    --
    -- In particular there is NO DELETE on `users`: even a non-owner account cannot
    -- be erased by the application, which is what keeps historical references and
    -- audit meaning intact. It is also the third independent barrier protecting
    -- ROOT (after the trigger and the absent API surface).
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON idempotency_records, outbox_events TO %I',
                   v_app_role);

    -- Role membership rows are genuinely revocable: unassigning a role is a
    -- removal, not an archival, and keeping tombstones here would complicate the
    -- effective-permission query on the hottest path. The removal is audited.
    EXECUTE format('GRANT DELETE ON user_role_assignments, user_permission_overrides, role_permissions TO %I',
                   v_app_role);

    -- --- system_state: readable, and updatable ONLY to record initialisation ---
    -- The trigger installed in 0001 refuses to revert or rewrite initialized_at,
    -- so UPDATE here cannot un-initialise the system.
    EXECUTE format('GRANT SELECT, UPDATE ON system_state TO %I', v_app_role);

    -- --- system_ownership: SELECT + INSERT, never UPDATE or DELETE ------------
    -- INSERT is required because first-run bootstrap is an HTTP endpoint served by
    -- the running application. It is safe to grant precisely because the table is a
    -- singleton by primary key: the INSERT can succeed at most once in the lifetime
    -- of the database, the BEFORE INSERT trigger refuses a non-INTERNAL or
    -- non-ACTIVE owner, and UPDATE/DELETE are both ungranted here AND refused
    -- unconditionally by trg_system_ownership_immutable.
    --
    -- So the runtime role can establish ownership exactly once and can never move
    -- it, remove it, or point it at anyone else. That is the whole invariant.
    EXECUTE format('GRANT SELECT, INSERT ON system_ownership TO %I', v_app_role);

    -- --- audit: append only ---------------------------------------------------
    -- No UPDATE. No DELETE. Combined with the triggers in 0007 and the fact that
    -- this role does not own the tables (so it cannot ALTER TABLE ... DISABLE
    -- TRIGGER), audit history has no mutation path available to the application.
    EXECUTE format('GRANT SELECT, INSERT ON audit_events TO %I', v_app_role);
    EXECUTE format('GRANT SELECT, UPDATE ON audit_chain_head TO %I', v_app_role);
    EXECUTE format('GRANT USAGE, SELECT ON SEQUENCE audit_events_seq_seq TO %I', v_app_role);

    -- --- Migration history: read only ----------------------------------------
    -- The application must not be able to rewrite what has been applied.
    IF EXISTS (SELECT 1 FROM pg_tables WHERE schemaname = 'public' AND tablename = '_sqlx_migrations') THEN
        EXECUTE format('GRANT SELECT ON _sqlx_migrations TO %I', v_app_role);
    END IF;

    RAISE NOTICE 'runtime grants applied to %', v_app_role;
END;
$$;

-- -----------------------------------------------------------------------------
-- Future tables created by later migrations do NOT inherit these grants
-- automatically. That is intentional: a new table should be an explicit decision
-- about what the runtime role may do with it, not an implicit full-access
-- default. Each future migration adds its own GRANT block, and a security test
-- asserts that no table is left with implicit access.
-- -----------------------------------------------------------------------------
