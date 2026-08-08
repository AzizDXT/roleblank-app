-- 0012 — the runtime role could not delete a role.
--
-- `DELETE /api/v1/roles/{id}` returned `500` for every caller, every time.
--
-- The path is fully authorised — `iam.roles.delete`, step-up, the delegation guard,
-- and a check that no live assignment remains — and then executes
-- `DELETE FROM role_permissions` (granted, 0009) followed by
-- `DELETE FROM roles` (**not** granted). PostgreSQL raises SQLSTATE 42501, the
-- transaction rolls back whole, and the caller receives an internal error.
--
-- Nothing is left half-deleted, so this is a correctness and availability defect
-- rather than a data-integrity one. It is not an edge case: the failure rate is
-- 100% for exactly the principal the endpoint exists for, which makes
-- `iam.roles.delete` an ungrantable capability in practice. It also manufactures
-- false security alarms, because `errors/mod.rs` logs a privilege denial at
-- `error!` level with a comment saying it means either an attack or a grant
-- misconfiguration — and here it means routine housekeeping.
--
-- **Why the tests did not catch it, again.** `tests/common/mod.rs` connects as
-- `roleblank_migrator`, which *owns* the tables, so the integration tests that
-- drive this exact route pass. This is the third defect of this shape: the missing
-- `SELECT` on `permissions` and the missing `UPDATE` on the audit sequence (both
-- HIGH, both closed by 0010) were the first two. The suite has since grown a
-- runtime-role test that walks `information_schema.role_table_grants` — and that
-- test *passed*, because it asserted the deletable set was exactly the five tables
-- it already knew about. A test that pins the current answer cannot discover that
-- the answer is wrong; the regression added alongside this migration drives the
-- route as `roleblank_app` instead.
--
-- Forward-only, idempotent, and safe on a populated database: a GRANT adds a
-- privilege and touches no row.

DO $$
DECLARE
    v_app_role CONSTANT text := 'roleblank_app';
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = v_app_role) THEN
        RAISE NOTICE 'runtime role % does not exist; skipping grant', v_app_role;
        RETURN;
    END IF;

    -- Deletion is already gated by four application checks and by
    -- `roles.is_system = false` in the statement itself, so the grant does not
    -- widen what an authorised caller can reach — it only lets the authorised
    -- caller finish.
    EXECUTE format('GRANT DELETE ON roles TO %I', v_app_role);

    RAISE NOTICE 'granted DELETE on roles to %', v_app_role;
END;
$$;
