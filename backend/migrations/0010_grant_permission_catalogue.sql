-- =============================================================================
-- 0010 — Grant the runtime role read access to the permission catalogue
--
-- FIXES A DEPLOYMENT-BLOCKING DEFECT.
--
-- `0009_runtime_grants.sql` enumerated every table the application touches and
-- omitted exactly one: `permissions`. The consequence is total — `serve` reads the
-- catalogue at startup to compare it against `modules::authorization::catalog`, and
-- refuses to boot on divergence. With no SELECT grant that read fails, so the
-- application **cannot start at all** as its intended runtime identity:
--
--     ERROR: failed to read the permission catalogue:
--            error returned from database: permission denied for table permissions
--
-- ## Why 903 tests did not catch it
--
-- Three gaps lined up, and each was individually defensible:
--
--   1. The integration harness connects as `roleblank_migrator`, deliberately, so
--      that fixtures can write tables the application is not granted. No test ever
--      issued the application's own queries as the application's own role.
--   2. `tests/security/runtime_role.rs` does use `roleblank_app`, but every
--      assertion in it is of the form "this must be REFUSED". Nothing asserted that
--      anything must be PERMITTED.
--   3. `serve` was never executed against a database in any test — the suites build
--      the router in-process and never run the startup path that reads this table.
--
-- Found by a clean-room test: a brand-new PostgreSQL, provisioned and migrated from
-- the committed SQL, with the production image started as `roleblank_app`. It
-- failed on the first request because it had never reached the first request.
--
-- The regression test added alongside this migration asserts the inverse invariant
-- to the one 0009 already covers: the runtime role must be able to SELECT from
-- every table in the schema. A table it cannot read is a startup failure or a
-- runtime 500 waiting for the code path that reads it.
-- =============================================================================

DO $$
DECLARE
    v_app_role CONSTANT text := 'roleblank_app';
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = v_app_role) THEN
        RAISE NOTICE 'runtime role % does not exist; skipping grant', v_app_role;
        RETURN;
    END IF;

    -- SELECT only. The catalogue is seeded by migration and is never written at
    -- runtime: it is the compiled-in `catalog::PERMISSIONS` that is authoritative,
    -- and the startup check exists to prove the two agree. Granting INSERT or
    -- UPDATE here would make the table the application could edit the very thing
    -- that governs what the application may do.
    EXECUTE format('GRANT SELECT ON permissions TO %I', v_app_role);

    -- ------------------------------------------------------------------------
    -- SECOND DEFECT, found by the same clean-room run once the first was fixed.
    --
    -- `0009` granted `USAGE, SELECT` on the audit sequence. That covers `nextval`
    -- and `currval` — but **`setval()` requires `UPDATE`**, and `audit::append`
    -- calls it on every write to keep the sequence ahead of the explicitly
    -- supplied `seq`.
    --
    -- `append` runs inside *every audited mutation*, so the effect was total: the
    -- first bootstrap, every login, and every create or update returned
    --
    --     500  error.cause = "database privilege denied"   (SQLSTATE 42501)
    --
    -- The application started, served `/health/*`, and then failed every single
    -- state-changing request. Fail-closed and loud — no data was corrupted and no
    -- authorisation was bypassed — but the system was entirely non-functional as
    -- its intended identity.
    --
    -- Granting UPDATE on this one sequence weakens no invariant. `audit_events.seq`
    -- is always supplied explicitly by the writer, derived from `audit_chain_head`
    -- under a row lock; the sequence's DEFAULT is never used, and the chain head is
    -- the authority for ordering. Moving the sequence would therefore change
    -- nothing an attacker could exploit, while keeping the defensive `setval` that
    -- stops a future insert relying on the default from colliding.
    EXECUTE format('GRANT UPDATE ON SEQUENCE audit_events_seq_seq TO %I', v_app_role);

    RAISE NOTICE 'granted SELECT on permissions and UPDATE on audit_events_seq_seq to %',
                 v_app_role;
END;
$$;
