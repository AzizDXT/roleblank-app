-- =============================================================================
-- 0007 — Append-only audit log with an HMAC hash chain (ADR-006)
--
-- Four independent controls protect this table:
--   1. no mutating API surface exists
--   2. the triggers below refuse UPDATE and DELETE unconditionally
--   3. the runtime role holds only SELECT, INSERT (see 0009_grants.sql) and does
--      not own the table, so it cannot ALTER TABLE ... DISABLE TRIGGER
--   4. an HMAC-SHA256 chain keyed OUTSIDE the database
--
-- The claim is precisely: modification, deletion or reordering performed WITHOUT
-- the chain key is detectable. It is NOT a claim of tamper-proofing against an
-- adversary who holds both the database and the key.
-- =============================================================================

CREATE TABLE audit_events (
    -- bigserial, not uuid: the chain is defined by a total order, and a gapless
    -- monotonic sequence makes "a row was removed" detectable on its own.
    seq                  bigserial   PRIMARY KEY,
    id                   uuid        NOT NULL,
    occurred_at          timestamptz NOT NULL DEFAULT now(),

    actor_user_id        uuid        REFERENCES users (id) ON DELETE RESTRICT,
    actor_principal_type text        CHECK (actor_principal_type IN ('INTERNAL', 'CLIENT', 'SYSTEM')),
    actor_session_id     uuid,

    action_code          text        NOT NULL CHECK (action_code ~ '^[A-Z][A-Z0-9_]*(\.[A-Z][A-Z0-9_]*)*$'),
    target_type          text        CHECK (target_type IS NULL OR length(target_type) <= 50),
    target_id            uuid,
    outcome              text        NOT NULL CHECK (outcome IN ('SUCCESS', 'DENIED', 'FAILURE')),

    request_id           text        CHECK (request_id IS NULL OR length(request_id) <= 64),
    source_ip_hint       text        CHECK (source_ip_hint IS NULL OR length(source_ip_hint) <= 45),

    -- A closed, sanitised structure written by modules::audit — never a raw request
    -- body. Passwords, tokens of any kind, TOTP secrets, recovery codes and keys
    -- must never appear here; a test asserts this.
    metadata             jsonb       NOT NULL DEFAULT '{}'::jsonb,

    prev_hash            bytea       CHECK (prev_hash IS NULL OR octet_length(prev_hash) = 32),
    entry_hash           bytea       NOT NULL CHECK (octet_length(entry_hash) = 32)
);

CREATE UNIQUE INDEX audit_events_id_key      ON audit_events (id);
CREATE INDEX audit_events_time_idx           ON audit_events (occurred_at DESC, seq DESC);
CREATE INDEX audit_events_actor_idx          ON audit_events (actor_user_id, occurred_at DESC)
                                             WHERE actor_user_id IS NOT NULL;
CREATE INDEX audit_events_action_idx         ON audit_events (action_code, occurred_at DESC);
CREATE INDEX audit_events_target_idx         ON audit_events (target_type, target_id, occurred_at DESC)
                                             WHERE target_id IS NOT NULL;

-- -----------------------------------------------------------------------------
-- audit_chain_head
--
-- Appends serialise on `SELECT ... FOR UPDATE` against this single row, taken
-- inside the writing transaction. That is what makes the chain well-defined under
-- concurrency: without it two concurrent inserts could both read the same
-- prev_hash and produce a fork that verification could not distinguish from
-- tampering.
-- -----------------------------------------------------------------------------
CREATE TABLE audit_chain_head (
    id        boolean     PRIMARY KEY DEFAULT true CHECK (id),
    last_seq  bigint      NOT NULL DEFAULT 0,
    last_hash bytea       CHECK (last_hash IS NULL OR octet_length(last_hash) = 32),
    updated_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO audit_chain_head (id, last_seq, last_hash) VALUES (true, 0, NULL);

-- -----------------------------------------------------------------------------
-- Append-only enforcement.
--
-- No actor-dependent branch, no exception for administrators, no "unless a flag is
-- set". An administrator who can rewrite history can erase their own escalation,
-- so there is deliberately nothing to negotiate with here.
-- -----------------------------------------------------------------------------
CREATE FUNCTION rb_audit_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only: % is not permitted', TG_OP
        USING ERRCODE = 'raise_exception',
              HINT    = 'audit history has no update or delete path in this system';
END;
$$;

CREATE TRIGGER trg_audit_events_append_only
    BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION rb_audit_append_only();

-- TRUNCATE bypasses row-level triggers entirely, so it needs its own statement
-- -level trigger. Without this, `TRUNCATE audit_events` would erase everything
-- while the append-only trigger above sat silently unfired.
CREATE FUNCTION rb_audit_no_truncate() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_events cannot be truncated'
        USING ERRCODE = 'raise_exception';
END;
$$;

CREATE TRIGGER trg_audit_events_no_truncate
    BEFORE TRUNCATE ON audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION rb_audit_no_truncate();

-- The chain head must only ever move forward, and only by one row at a time.
CREATE FUNCTION rb_audit_chain_head_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'audit_chain_head cannot be deleted' USING ERRCODE = 'raise_exception';
    END IF;
    IF NEW.last_seq < OLD.last_seq THEN
        RAISE EXCEPTION 'audit chain head cannot move backwards (% -> %)', OLD.last_seq, NEW.last_seq
            USING ERRCODE = 'raise_exception';
    END IF;
    NEW.updated_at := now();
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_audit_chain_head_guard
    BEFORE UPDATE OR DELETE ON audit_chain_head
    FOR EACH ROW EXECUTE FUNCTION rb_audit_chain_head_guard();
