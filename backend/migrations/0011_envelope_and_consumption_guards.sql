-- =============================================================================
-- 0011 — Close four database-layer gaps found by the final acceptance audit
--
-- All four are the same shape: an invariant this system states plainly, enforced
-- in one layer where the surrounding code enforces it in two. None of them was
-- exploitable through the API — the application never performs any of the writes
-- guarded below — and that is exactly the point. Every one of them required
-- database access to reach, and "the database is held by an adversary" is the
-- threat these tables are designed against everywhere else.
--
--   1. `users.principal_type` could be rewritten for any non-owner, and the
--      conversion did not cascade. (SECTION_7_16 F-2, LOW)
--   2. Single-use token consumption had no database guard: `consumed_at` could be
--      set back to NULL, re-opening a spent token. (SECTION_7_16 F-3, LOW)
--   3. The ROOT protection trigger pinned the owner's lifecycle and envelope but
--      not their email address, so the owner's account could be steered through
--      the password-reset flow. (SECTION_3_6 F-3, INFO)
--   4. `audit_events.source_ip_hint` was stored but not covered by the hash chain,
--      so an adversary holding the database could rewrite every source IP in the
--      log without breaking verification. (SECTION_23_26 F-14, INFO)
--
-- Forward-only, like every migration here. Each guard refuses a transition; none
-- rewrites existing data, so there is nothing to backfill and nothing to undo.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1. The client envelope, applied to the column the envelope hangs off
--
-- Three triggers already enforce the envelope at the point rows are written:
-- `rb_role_assignment_principal_match` (a CLIENT cannot hold an INTERNAL role),
-- `rb_require_internal_user` (department, project and task membership is staff
-- only) and `rb_require_client_user` (client membership is external only). Every
-- one of them reads `users.principal_type` and none of them fires when that column
-- is the thing that changes.
--
-- So the envelope held for every path that adds a row, and had a hole in the path
-- that changes what the rows mean: `UPDATE users SET principal_type = 'CLIENT'`
-- left the subject's INTERNAL role assignments and department memberships exactly
-- where they were, in a combination that would have been refused had it been
-- written in the other order. The result is a principal the evaluator treats as
-- external while the membership tables still treat them as staff.
--
-- The guard is a re-check, not a ban. A conversion that leaves nothing stranded is
-- still permitted, so an operator repairing a mis-created account can do it by
-- clearing the dependent rows first — which is the order the application would
-- have had to use anyway. A blanket pin would have been one line shorter and would
-- have made a legitimate correction impossible.
--
-- Only *live* rows are consulted. A removed membership is history: it was
-- legitimate when it was written, and refusing a conversion because of it would
-- make the guard progressively harder to satisfy over an account's lifetime for no
-- security gain.
-- -----------------------------------------------------------------------------
CREATE FUNCTION rb_users_principal_type_envelope() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    v_count bigint;
BEGIN
    IF NEW.principal_type IS NOT DISTINCT FROM OLD.principal_type THEN
        RETURN NEW;
    END IF;

    -- Role assignments must match the new principal type exactly, which is the
    -- same comparison rb_role_assignment_principal_match makes on insert.
    SELECT count(*) INTO v_count
      FROM user_role_assignments ura
      JOIN roles r ON r.id = ura.role_id
     WHERE ura.user_id = NEW.id
       AND r.allowed_principal_type IS DISTINCT FROM NEW.principal_type;
    IF v_count > 0 THEN
        RAISE EXCEPTION
            'cannot convert user % to %: % role assignment(s) are restricted to the other principal type',
            NEW.id, NEW.principal_type, v_count
            USING ERRCODE = 'raise_exception',
                  HINT = 'remove the incompatible role assignments first';
    END IF;

    -- An ALLOW override for an INTERNAL-only permission cannot survive a
    -- conversion to CLIENT; rb_override_envelope refuses to create one.
    IF NEW.principal_type = 'CLIENT' THEN
        SELECT count(*) INTO v_count
          FROM user_permission_overrides o
          JOIN permissions p ON p.code = o.permission_code
         WHERE o.user_id = NEW.id
           AND o.effect = 'ALLOW'
           AND p.max_principal_type = 'INTERNAL';
        IF v_count > 0 THEN
            RAISE EXCEPTION
                'cannot convert user % to CLIENT: % ALLOW override(s) name INTERNAL-only permissions',
                NEW.id, v_count
                USING ERRCODE = 'raise_exception',
                      HINT = 'remove the incompatible permission overrides first';
        END IF;

        SELECT (SELECT count(*) FROM department_memberships
                 WHERE user_id = NEW.id AND removed_at IS NULL)
             + (SELECT count(*) FROM project_memberships
                 WHERE user_id = NEW.id AND removed_at IS NULL)
             + (SELECT count(*) FROM task_assignees
                 WHERE user_id = NEW.id AND removed_at IS NULL)
          INTO v_count;
        IF v_count > 0 THEN
            RAISE EXCEPTION
                'cannot convert user % to CLIENT: % live internal membership(s) or assignment(s) remain',
                NEW.id, v_count
                USING ERRCODE = 'raise_exception',
                      HINT = 'remove the department, project and task memberships first';
        END IF;

        SELECT count(*) INTO v_count
          FROM client_accounts
         WHERE account_manager_user_id = NEW.id;
        IF v_count > 0 THEN
            RAISE EXCEPTION
                'cannot convert user % to CLIENT: they manage % client account(s)',
                NEW.id, v_count
                USING ERRCODE = 'raise_exception',
                      HINT = 'reassign the account manager first';
        END IF;
    END IF;

    -- The mirror image: client membership requires a CLIENT principal.
    IF NEW.principal_type = 'INTERNAL' THEN
        SELECT count(*) INTO v_count
          FROM client_memberships
         WHERE user_id = NEW.id AND removed_at IS NULL;
        IF v_count > 0 THEN
            RAISE EXCEPTION
                'cannot convert user % to INTERNAL: % live client membership(s) remain',
                NEW.id, v_count
                USING ERRCODE = 'raise_exception',
                      HINT = 'remove the client account memberships first';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_users_principal_type_envelope
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION rb_users_principal_type_envelope();

-- -----------------------------------------------------------------------------
-- 2. Consumption is final
--
-- `password_reset_tokens`, `session_refresh_tokens` and `recovery_codes` are all
-- single-use by the same mechanism: the consuming statement is
-- `UPDATE ... SET consumed_at = now() WHERE ... AND consumed_at IS NULL`, taken
-- inside a transaction holding the row. That gate was verified under contention
-- (one success in fifty, for both password reset and refresh rotation), so the
-- invariant holds — in one layer.
--
-- The tables placed no constraint on the column, so `UPDATE ... SET consumed_at =
-- NULL` re-opened a spent token: a stolen-and-used reset link becomes usable
-- again, a rotated refresh token becomes live again alongside its successor, and a
-- burnt recovery code becomes a working MFA bypass again. `recovery_codes` is
-- included even though the audit named only the first two — it is the same column,
-- the same statement shape and the same single-use claim, and it is the one whose
-- re-opening bypasses a second factor.
--
-- The rule is immutability rather than "not back to NULL": once a timestamp says
-- when a credential was spent, rewriting it to a different time falsifies the same
-- record without ever making the column NULL.
-- -----------------------------------------------------------------------------
CREATE FUNCTION rb_consumption_is_final() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.consumed_at IS NOT NULL
       AND NEW.consumed_at IS DISTINCT FROM OLD.consumed_at THEN
        RAISE EXCEPTION
            'consumed_at is immutable once set on % (attempted % -> %)',
            TG_TABLE_NAME, OLD.consumed_at, NEW.consumed_at
            USING ERRCODE = 'raise_exception',
                  HINT = 'single-use credentials cannot be re-opened';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_password_reset_tokens_consumption_final
    BEFORE UPDATE ON password_reset_tokens
    FOR EACH ROW EXECUTE FUNCTION rb_consumption_is_final();

CREATE TRIGGER trg_session_refresh_tokens_consumption_final
    BEFORE UPDATE ON session_refresh_tokens
    FOR EACH ROW EXECUTE FUNCTION rb_consumption_is_final();

CREATE TRIGGER trg_recovery_codes_consumption_final
    BEFORE UPDATE ON recovery_codes
    FOR EACH ROW EXECUTE FUNCTION rb_consumption_is_final();

-- -----------------------------------------------------------------------------
-- 3. The owner's email address is part of the owner's identity
--
-- `rb_users_protect_root` guarded four things on the owner's row — status,
-- principal_type, mfa_required and id — plus an unconditional DELETE refusal. It
-- did not guard the address the account authenticates and recovers with, so the
-- runtime role (which holds UPDATE on `users`) could take the owner's email and
-- drive the password-reset flow to a mailbox it controls.
--
-- That conferred nothing an attacker at that level did not already have — the same
-- role holds INSERT on `sessions` — which is why the audit rated it INFO. It is
-- closed anyway because it is nearly free and because the documented invariant
-- should be the implemented one: nothing in this application updates the owner's
-- email. `identity::service::update_user` is the only path that writes the column
-- and it refuses the owner as its first substantive act, so this trigger can never
-- fire on a legitimate request.
--
-- CREATE OR REPLACE rather than an edit to 0001: applied migrations are immutable,
-- and their checksums are verified.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION rb_users_protect_root() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    v_root uuid;
BEGIN
    SELECT root_user_id INTO v_root FROM system_ownership WHERE id;

    IF v_root IS NULL THEN
        -- Not yet bootstrapped; nothing to protect.
        IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
        RETURN NEW;
    END IF;

    IF TG_OP = 'DELETE' THEN
        IF OLD.id = v_root THEN
            RAISE EXCEPTION 'the system owner cannot be deleted'
                USING ERRCODE = 'raise_exception';
        END IF;
        RETURN OLD;
    END IF;

    IF OLD.id = v_root THEN
        IF NEW.status <> 'ACTIVE' THEN
            RAISE EXCEPTION 'the system owner must remain ACTIVE (attempted %)', NEW.status
                USING ERRCODE = 'raise_exception';
        END IF;
        IF NEW.principal_type <> 'INTERNAL' THEN
            RAISE EXCEPTION 'the system owner must remain an INTERNAL principal'
                USING ERRCODE = 'raise_exception';
        END IF;
        IF NEW.mfa_required = false THEN
            RAISE EXCEPTION 'MFA cannot be made optional for the system owner'
                USING ERRCODE = 'raise_exception';
        END IF;
        IF NEW.id <> OLD.id THEN
            RAISE EXCEPTION 'the system owner id is immutable'
                USING ERRCODE = 'raise_exception';
        END IF;
        -- Added in 0011. Both columns, not just the normalised one: the address
        -- shown to a human and the address the lookup matches on must not be able
        -- to disagree, and password reset resolves through email_normalized.
        IF NEW.email IS DISTINCT FROM OLD.email
           OR NEW.email_normalized IS DISTINCT FROM OLD.email_normalized THEN
            RAISE EXCEPTION 'the system owner email address is immutable'
                USING ERRCODE = 'raise_exception';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

-- -----------------------------------------------------------------------------
-- 4. Bring `source_ip_hint` inside the hash chain
--
-- `chain::ChainedEntry` states the rule plainly: a field not in that struct is not
-- protected. `source_ip_hint` was the only substantive column outside it. The chain
-- claims that "any modification, deletion or reordering performed without the chain
-- key is detected", and against the adversary that claim is written for — someone
-- holding a database dump, a restored backup, or superuser access — rewriting where
-- every action came from was undetectable. Origin is precisely what an intruder
-- wants to change in a log they cannot delete.
--
-- Adding a field changes the bytes that are hashed, so every entry already written
-- would fail verification. This column is the version marker that stops that:
-- existing rows stay at 1 and verify under the layout they were written with, and
-- everything from this build forward is written as 2. `chain::canonical_bytes`
-- includes the marker itself in the v2 digest, so a row cannot be downgraded to the
-- weaker layout without the key.
--
-- The `DEFAULT` is what backfills; there is no data migration. The column is
-- covered by the table's existing `GRANT SELECT, INSERT` — table privileges extend
-- to columns added later — so the runtime role needs no new grant, and it still
-- holds no UPDATE here.
-- -----------------------------------------------------------------------------
ALTER TABLE audit_events
    ADD COLUMN chain_version smallint NOT NULL DEFAULT 1
        CHECK (chain_version >= 1);

-- Makes "which entries predate the source-IP coverage" a query rather than an
-- assumption, so an auditor can bound the exposure exactly.
CREATE INDEX audit_events_chain_version_idx ON audit_events (chain_version)
    WHERE chain_version < 2;
