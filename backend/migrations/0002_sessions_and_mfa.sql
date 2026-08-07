-- =============================================================================
-- 0002 — Sessions, refresh rotation, MFA, recovery codes, reset tokens
--
-- Every credential-like value in this file is stored ONLY as a SHA-256 digest.
-- No plaintext token exists in the database, in a log, or in any response beyond
-- the single moment it is issued.
-- =============================================================================

CREATE TABLE sessions (
    id                  uuid        PRIMARY KEY,
    user_id             uuid        NOT NULL REFERENCES users (id) ON DELETE RESTRICT,

    -- SHA-256 of the opaque access token. The token itself is 32 CSPRNG bytes;
    -- a slow KDF would add latency to the hottest query in the system and buy
    -- nothing against a 256-bit uniformly random preimage.
    access_token_hash   bytea       NOT NULL CHECK (octet_length(access_token_hash) = 32),

    access_expires_at   timestamptz NOT NULL,
    idle_expires_at     timestamptz NOT NULL,
    -- Hard ceiling. No amount of refreshing extends it, so every compromise ends.
    absolute_expires_at timestamptz NOT NULL,

    auth_level          text        NOT NULL CHECK (auth_level IN ('PASSWORD', 'MFA')),
    -- While true the session may reach ONLY the MFA endpoints. This is what makes
    -- MFA non-bypassable: there is no window in which a password-only session of
    -- an MFA-required user can touch a business endpoint.
    pending_mfa         boolean     NOT NULL DEFAULT false,
    mfa_verified_at     timestamptz,

    last_activity_at    timestamptz NOT NULL DEFAULT now(),
    revoked_at          timestamptz,
    revocation_reason   text        CHECK (revocation_reason IN (
                            'LOGOUT', 'LOGOUT_ALL', 'PASSWORD_CHANGED', 'PASSWORD_RESET',
                            'USER_SUSPENDED', 'USER_ARCHIVED', 'ADMIN_REVOKED',
                            'REFRESH_REUSE_DETECTED', 'MFA_RESET', 'SECURITY_POLICY')),

    -- Recognition aids for the user's own session list. Sanitised and truncated.
    -- NEVER used for authorisation: IP binding breaks mobile clients on every
    -- network change and hands an attacker a spoofable input.
    client_ip_hint      text        CHECK (client_ip_hint IS NULL OR length(client_ip_hint) <= 45),
    user_agent_hint     text        CHECK (user_agent_hint IS NULL OR length(user_agent_hint) <= 200),

    created_at          timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT sessions_revocation_consistent
        CHECK ((revoked_at IS NULL) = (revocation_reason IS NULL)),
    CONSTRAINT sessions_mfa_consistent
        CHECK (NOT (pending_mfa AND auth_level = 'MFA'))
);

CREATE UNIQUE INDEX sessions_access_token_hash_key ON sessions (access_token_hash);
CREATE INDEX sessions_active_by_user_idx ON sessions (user_id) WHERE revoked_at IS NULL;
CREATE INDEX sessions_user_created_idx   ON sessions (user_id, created_at DESC);

-- -----------------------------------------------------------------------------
-- session_refresh_tokens
--
-- Consumed rows are RETAINED on purpose: they are the theft detector. A hit on a
-- consumed row means two parties hold the same refresh token, and the only safe
-- interpretation is compromise -> the whole family is revoked. Deleting consumed
-- rows would delete the signal.
-- -----------------------------------------------------------------------------
CREATE TABLE session_refresh_tokens (
    id          uuid        PRIMARY KEY,
    session_id  uuid        NOT NULL REFERENCES sessions (id) ON DELETE RESTRICT,
    token_hash  bytea       NOT NULL CHECK (octet_length(token_hash) = 32),
    generation  integer     NOT NULL CHECK (generation >= 0),
    expires_at  timestamptz NOT NULL,
    consumed_at timestamptz,
    replaced_by uuid        REFERENCES session_refresh_tokens (id) ON DELETE RESTRICT,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX session_refresh_tokens_hash_key ON session_refresh_tokens (token_hash);
CREATE UNIQUE INDEX session_refresh_tokens_gen_key  ON session_refresh_tokens (session_id, generation);
CREATE INDEX session_refresh_tokens_live_idx
    ON session_refresh_tokens (session_id) WHERE consumed_at IS NULL;

-- =============================================================================
-- mfa_factors
-- =============================================================================
CREATE TABLE mfa_factors (
    id                uuid        PRIMARY KEY,
    user_id           uuid        NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    factor_type       text        NOT NULL CHECK (factor_type IN ('TOTP')),
    status            text        NOT NULL CHECK (status IN ('PENDING', 'ACTIVE', 'DISABLED')),

    -- XChaCha20-Poly1305. key_version is stored alongside so the master key can be
    -- rotated later without an eager re-encryption of every row (ADR-002).
    secret_ciphertext bytea       NOT NULL CHECK (octet_length(secret_ciphertext) BETWEEN 17 AND 256),
    secret_nonce      bytea       NOT NULL CHECK (octet_length(secret_nonce) = 24),
    key_version       integer     NOT NULL CHECK (key_version > 0),

    -- Replay defence: the highest TOTP counter already accepted. A code at or
    -- below this value is refused even if it is still inside its time window,
    -- which kills replay of a code captured in transit.
    last_used_step    bigint,

    label             text        CHECK (label IS NULL OR length(label) <= 100),
    created_at        timestamptz NOT NULL DEFAULT now(),
    activated_at      timestamptz,
    disabled_at       timestamptz,

    CONSTRAINT mfa_factors_status_consistent CHECK (
        (status = 'ACTIVE'   AND activated_at IS NOT NULL AND disabled_at IS NULL) OR
        (status = 'PENDING'  AND activated_at IS NULL     AND disabled_at IS NULL) OR
        (status = 'DISABLED' AND disabled_at IS NOT NULL)
    )
);

-- At most one live TOTP factor per user.
CREATE UNIQUE INDEX mfa_factors_one_live_per_user
    ON mfa_factors (user_id, factor_type) WHERE status IN ('PENDING', 'ACTIVE');
CREATE INDEX mfa_factors_user_idx ON mfa_factors (user_id);

-- =============================================================================
-- recovery_codes
-- =============================================================================
CREATE TABLE recovery_codes (
    id          uuid        PRIMARY KEY,
    user_id     uuid        NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    batch_id    uuid        NOT NULL,
    code_hash   bytea       NOT NULL CHECK (octet_length(code_hash) = 32),
    created_at  timestamptz NOT NULL DEFAULT now(),
    consumed_at timestamptz
);

CREATE UNIQUE INDEX recovery_codes_hash_key ON recovery_codes (code_hash);
CREATE INDEX recovery_codes_live_idx ON recovery_codes (user_id) WHERE consumed_at IS NULL;

-- =============================================================================
-- password_reset_tokens
-- =============================================================================
CREATE TABLE password_reset_tokens (
    id                uuid        PRIMARY KEY,
    user_id           uuid        NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    token_hash        bytea       NOT NULL CHECK (octet_length(token_hash) = 32),
    expires_at        timestamptz NOT NULL,
    consumed_at       timestamptz,
    requested_ip_hint text        CHECK (requested_ip_hint IS NULL OR length(requested_ip_hint) <= 45),
    created_at        timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX password_reset_tokens_hash_key ON password_reset_tokens (token_hash);
CREATE INDEX password_reset_tokens_live_idx
    ON password_reset_tokens (user_id) WHERE consumed_at IS NULL;
