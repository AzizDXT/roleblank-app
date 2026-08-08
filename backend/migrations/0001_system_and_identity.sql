-- =============================================================================
-- 0001 — System state, ownership, and identity
--
-- This migration establishes the two invariants the whole system rests on:
--   * exactly one initialisation event  (system_state)
--   * exactly one, immutable, owner     (system_ownership)
-- Both are enforced by the schema itself, not by application discipline.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- Shared helper: keeps updated_at honest without every writer remembering to.
-- -----------------------------------------------------------------------------
CREATE FUNCTION rb_touch_updated_at() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END;
$$;

-- =============================================================================
-- system_state — singleton
--
-- `id boolean PRIMARY KEY CHECK (id)` admits exactly one row and no more. A
-- second bootstrap is therefore a primary-key violation at the storage layer,
-- which is a stronger guarantee than any application check can offer.
-- =============================================================================
CREATE TABLE system_state (
    id             boolean     PRIMARY KEY DEFAULT true CHECK (id),
    initialized_at timestamptz,                       -- NULL  =>  bootstrap still available
    schema_note    text        NOT NULL DEFAULT '',
    created_at     timestamptz NOT NULL DEFAULT now()
);

-- The single row exists from migration time so that bootstrap is an UPDATE of a
-- known row (lockable with FOR UPDATE) rather than an INSERT racing itself.
INSERT INTO system_state (id, initialized_at) VALUES (true, NULL);

-- system_state must never be deleted, and initialisation must never be undone.
CREATE FUNCTION rb_system_state_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'system_state row cannot be deleted'
            USING ERRCODE = 'raise_exception';
    END IF;
    IF OLD.initialized_at IS NOT NULL AND NEW.initialized_at IS NULL THEN
        RAISE EXCEPTION 'system initialisation cannot be reverted'
            USING ERRCODE = 'raise_exception';
    END IF;
    IF OLD.initialized_at IS NOT NULL AND NEW.initialized_at <> OLD.initialized_at THEN
        RAISE EXCEPTION 'system initialisation timestamp is immutable'
            USING ERRCODE = 'raise_exception';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_system_state_guard
    BEFORE UPDATE OR DELETE ON system_state
    FOR EACH ROW EXECUTE FUNCTION rb_system_state_guard();

-- =============================================================================
-- users
-- =============================================================================
CREATE TABLE users (
    id               uuid        PRIMARY KEY,
    email            text        NOT NULL CHECK (length(email) BETWEEN 3 AND 254),
    -- Identity is the normalised form. lower(trim(...)) and nothing further:
    -- dot-stripping or plus-folding would silently merge distinct real mailboxes.
    email_normalized text        NOT NULL CHECK (email_normalized = lower(btrim(email_normalized))),
    display_name     text        NOT NULL CHECK (length(display_name) BETWEEN 1 AND 200),
    principal_type   text        NOT NULL CHECK (principal_type IN ('INTERNAL', 'CLIENT')),
    status           text        NOT NULL CHECK (status IN ('PENDING', 'ACTIVE', 'SUSPENDED', 'ARCHIVED')),
    mfa_required     boolean     NOT NULL DEFAULT false,
    mfa_enrolled     boolean     NOT NULL DEFAULT false,
    -- Bumped on every privilege change. Surfaced in /auth/me so a client can see
    -- that its capability set moved; reserved as the invalidation key for any
    -- future permission cache. No cache exists today.
    security_version integer     NOT NULL DEFAULT 1 CHECK (security_version > 0),
    version          integer     NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    activated_at     timestamptz,
    suspended_at     timestamptz,
    archived_at      timestamptz
);

CREATE UNIQUE INDEX users_email_normalized_key ON users (email_normalized);
CREATE INDEX users_principal_status_idx        ON users (principal_type, status);
CREATE INDEX users_created_at_idx              ON users (created_at DESC, id DESC);

CREATE TRIGGER trg_users_touch
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION rb_touch_updated_at();

-- =============================================================================
-- system_ownership — the ROOT_OWNER invariant (ADR-004)
--
-- Ownership is NOT a role and NOT a column on users. It is a singleton row that
-- no runtime code path may alter. The application is not granted INSERT/UPDATE/
-- DELETE on this table at all (see 0008_grants.sql); bootstrap runs as the
-- migrator role. Even so, the triggers below refuse mutation unconditionally, so
-- that a future grant mistake is still not sufficient.
-- =============================================================================
CREATE TABLE system_ownership (
    id             boolean     PRIMARY KEY DEFAULT true CHECK (id),
    root_user_id   uuid        NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    established_at timestamptz NOT NULL DEFAULT now()
);

-- An external principal must never be able to become the owner, even via SQL.
CREATE FUNCTION rb_system_ownership_insert_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    v_type   text;
    v_status text;
BEGIN
    SELECT principal_type, status INTO v_type, v_status
      FROM users WHERE id = NEW.root_user_id;

    IF v_type IS DISTINCT FROM 'INTERNAL' THEN
        RAISE EXCEPTION 'system owner must be an INTERNAL principal (got %)', coalesce(v_type, '<missing user>')
            USING ERRCODE = 'raise_exception';
    END IF;
    IF v_status IS DISTINCT FROM 'ACTIVE' THEN
        RAISE EXCEPTION 'system owner must be ACTIVE at establishment (got %)', coalesce(v_status, '<missing user>')
            USING ERRCODE = 'raise_exception';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_system_ownership_insert_guard
    BEFORE INSERT ON system_ownership
    FOR EACH ROW EXECUTE FUNCTION rb_system_ownership_insert_guard();

-- Unconditional. There is deliberately no actor-dependent branch here: any code
-- path that could legitimately move ownership is a code path that could be abused
-- to steal it. Ownership recovery is an offline procedure performed by the schema
-- owner (docs/backend/08-operations.md).
CREATE FUNCTION rb_system_ownership_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'system_ownership is immutable: % is not permitted', TG_OP
        USING ERRCODE = 'raise_exception',
              HINT    = 'ownership replacement is an offline recovery procedure, not an API';
END;
$$;

CREATE TRIGGER trg_system_ownership_immutable
    BEFORE UPDATE OR DELETE ON system_ownership
    FOR EACH ROW EXECUTE FUNCTION rb_system_ownership_immutable();

-- =============================================================================
-- ROOT protection on users
--
-- Consults system_ownership directly rather than a denormalised flag, so there is
-- no second copy of the truth to drift. Note the runtime role additionally holds
-- NO DELETE grant on users at all — users are archived, never erased, so that
-- historical references and audit meaning survive.
-- =============================================================================
CREATE FUNCTION rb_users_protect_root() RETURNS trigger
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
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_users_protect_root
    BEFORE UPDATE OR DELETE ON users
    FOR EACH ROW EXECUTE FUNCTION rb_users_protect_root();

-- =============================================================================
-- credentials
--
-- Split from users on purpose: the query that runs on every authenticated request
-- physically cannot return a password hash, because the hash is not in that table.
-- =============================================================================
CREATE TABLE credentials (
    user_id             uuid        PRIMARY KEY REFERENCES users (id) ON DELETE RESTRICT,
    password_hash       text        NOT NULL CHECK (password_hash LIKE '$argon2id$%'),
    password_updated_at timestamptz NOT NULL DEFAULT now(),
    must_change         boolean     NOT NULL DEFAULT false,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now()
);

CREATE TRIGGER trg_credentials_touch
    BEFORE UPDATE ON credentials
    FOR EACH ROW EXECUTE FUNCTION rb_touch_updated_at();
