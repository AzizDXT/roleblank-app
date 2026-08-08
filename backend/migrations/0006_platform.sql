-- =============================================================================
-- 0006 — System settings, feature flags, idempotency, transactional outbox
-- =============================================================================

CREATE TABLE system_settings (
    key                   text        PRIMARY KEY CHECK (key ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$'),
    value                 jsonb       NOT NULL,
    value_type            text        NOT NULL CHECK (value_type IN ('STRING', 'BOOLEAN', 'INTEGER', 'ENUM')),
    -- Writing a security-sensitive setting requires settings.security.write AND a
    -- recent step-up. Writing an ordinary one requires only settings.features.write.
    is_security_sensitive boolean     NOT NULL DEFAULT false,
    description           text        NOT NULL DEFAULT '',
    version               integer     NOT NULL DEFAULT 1 CHECK (version > 0),
    updated_by            uuid        REFERENCES users (id) ON DELETE RESTRICT,
    updated_at            timestamptz NOT NULL DEFAULT now(),
    created_at            timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE feature_flags (
    key                   text        PRIMARY KEY CHECK (key ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$'),
    enabled               boolean     NOT NULL DEFAULT false,
    is_security_sensitive boolean     NOT NULL DEFAULT false,
    description           text        NOT NULL DEFAULT '',
    version               integer     NOT NULL DEFAULT 1 CHECK (version > 0),
    updated_by            uuid        REFERENCES users (id) ON DELETE RESTRICT,
    updated_at            timestamptz NOT NULL DEFAULT now(),
    created_at            timestamptz NOT NULL DEFAULT now()
);

-- =============================================================================
-- idempotency_records
--
-- Scoped by (principal, operation, key) so one principal's key can never replay
-- another principal's response — an unscoped key namespace is a cross-tenant
-- information leak waiting to happen. The body fingerprint turns "same key,
-- different body" into a deterministic 409 rather than a silently wrong replay.
-- =============================================================================
CREATE TABLE idempotency_records (
    id                  uuid        PRIMARY KEY,
    principal_id        uuid        NOT NULL,
    operation           text        NOT NULL CHECK (length(operation) BETWEEN 1 AND 100),
    idempotency_key     text        NOT NULL CHECK (length(idempotency_key) BETWEEN 8 AND 200),
    request_fingerprint bytea       NOT NULL CHECK (octet_length(request_fingerprint) = 32),
    status              text        NOT NULL CHECK (status IN ('IN_PROGRESS', 'COMPLETED')),
    response_status     integer     CHECK (response_status IS NULL OR response_status BETWEEN 100 AND 599),
    response_body       jsonb,
    created_at          timestamptz NOT NULL DEFAULT now(),
    completed_at        timestamptz,
    expires_at          timestamptz NOT NULL,

    CONSTRAINT idempotency_completion_consistent
        CHECK ((status = 'COMPLETED') = (completed_at IS NOT NULL AND response_status IS NOT NULL))
);

CREATE UNIQUE INDEX idempotency_records_key
    ON idempotency_records (principal_id, operation, idempotency_key);
CREATE INDEX idempotency_records_expiry_idx ON idempotency_records (expires_at);

-- =============================================================================
-- outbox_events
--
-- The event and the state change it describes commit in the SAME transaction.
-- This is the whole point: a `tokio::spawn` after commit can lose the side effect
-- on a crash, and a send before commit can produce a side effect for a change
-- that rolled back.
-- =============================================================================
CREATE TABLE outbox_events (
    id           uuid        PRIMARY KEY,
    event_type   text        NOT NULL CHECK (length(event_type) BETWEEN 1 AND 100),
    payload      jsonb       NOT NULL,
    status       text        NOT NULL DEFAULT 'PENDING'
                             CHECK (status IN ('PENDING', 'SENT', 'FAILED', 'DEAD')),
    attempts     integer     NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    max_attempts integer     NOT NULL DEFAULT 8 CHECK (max_attempts > 0),
    available_at timestamptz NOT NULL DEFAULT now(),
    claimed_at   timestamptz,
    claimed_by   text        CHECK (claimed_by IS NULL OR length(claimed_by) <= 100),
    last_error   text        CHECK (last_error IS NULL OR length(last_error) <= 2000),
    created_at   timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz
);

-- Serves the worker's claim scan. Partial, because SENT and DEAD rows are the
-- overwhelming majority over time and must not be walked on every poll.
CREATE INDEX outbox_events_claimable_idx
    ON outbox_events (available_at, id) WHERE status IN ('PENDING', 'FAILED');
CREATE INDEX outbox_events_status_idx ON outbox_events (status, created_at DESC);
