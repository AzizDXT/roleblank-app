-- =============================================================================
-- 0004 — Departments, client accounts, memberships, invitations
--
-- Client accounts model external businesses. They are NOT tenants: there is one
-- company and one database. A CLIENT principal is an external, untrusted human
-- whose visibility is derived entirely from explicit links.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- departments
--
-- Deliberately flat. A self-referencing hierarchy brings cycle prevention,
-- transitive visibility and recursive authorisation queries; nothing in the
-- current scope needs it, and adding it later is an additive migration whereas
-- removing an unnecessary one is not.
-- -----------------------------------------------------------------------------
CREATE TABLE departments (
    id           uuid        PRIMARY KEY,
    code         text        NOT NULL CHECK (code ~ '^[a-z0-9][a-z0-9_-]{0,49}$'),
    name         text        NOT NULL CHECK (length(name) BETWEEN 1 AND 150),
    description  text        NOT NULL DEFAULT '' CHECK (length(description) <= 1000),
    status       text        NOT NULL CHECK (status IN ('ACTIVE', 'ARCHIVED')),
    lead_user_id uuid        REFERENCES users (id) ON DELETE RESTRICT,
    version      integer     NOT NULL DEFAULT 1 CHECK (version > 0),
    created_by   uuid        REFERENCES users (id) ON DELETE RESTRICT,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    archived_at  timestamptz,
    CONSTRAINT departments_archive_consistent CHECK ((status = 'ARCHIVED') = (archived_at IS NOT NULL))
);

CREATE UNIQUE INDEX departments_code_key ON departments (code);
CREATE INDEX departments_status_idx      ON departments (status, name);

CREATE TRIGGER trg_departments_touch
    BEFORE UPDATE ON departments
    FOR EACH ROW EXECUTE FUNCTION rb_touch_updated_at();

CREATE TABLE department_memberships (
    id                 uuid        PRIMARY KEY,
    department_id      uuid        NOT NULL REFERENCES departments (id) ON DELETE RESTRICT,
    user_id            uuid        NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    role_in_department text        NOT NULL CHECK (role_in_department IN ('MEMBER', 'LEAD')),
    added_by           uuid        REFERENCES users (id) ON DELETE RESTRICT,
    joined_at          timestamptz NOT NULL DEFAULT now(),
    removed_at         timestamptz
);

-- Partial unique index: one live membership per (department, user), while history
-- of previous memberships is preserved rather than deleted.
CREATE UNIQUE INDEX department_memberships_live_key
    ON department_memberships (department_id, user_id) WHERE removed_at IS NULL;
CREATE INDEX department_memberships_user_live_idx
    ON department_memberships (user_id) WHERE removed_at IS NULL;

-- -----------------------------------------------------------------------------
-- Reusable guard: a membership table that must only ever contain INTERNAL users.
-- Applied to department, project and task membership. An external principal must
-- not be able to enter internal structures even by direct SQL.
-- -----------------------------------------------------------------------------
CREATE FUNCTION rb_require_internal_user() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    v_type text;
BEGIN
    SELECT principal_type INTO v_type FROM users WHERE id = NEW.user_id;
    IF v_type IS DISTINCT FROM 'INTERNAL' THEN
        RAISE EXCEPTION '% requires an INTERNAL principal (user % is %)',
                        TG_TABLE_NAME, NEW.user_id, coalesce(v_type, '<missing>')
            USING ERRCODE = 'raise_exception';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_department_memberships_internal_only
    BEFORE INSERT OR UPDATE ON department_memberships
    FOR EACH ROW EXECUTE FUNCTION rb_require_internal_user();

-- =============================================================================
-- client_accounts
-- =============================================================================
CREATE TABLE client_accounts (
    id                      uuid        PRIMARY KEY,
    code                    text        NOT NULL CHECK (code ~ '^[a-z0-9][a-z0-9_-]{0,49}$'),
    name                    text        NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    description             text        NOT NULL DEFAULT '' CHECK (length(description) <= 1000),
    status                  text        NOT NULL CHECK (status IN ('ACTIVE', 'SUSPENDED', 'ARCHIVED')),
    account_manager_user_id uuid        REFERENCES users (id) ON DELETE RESTRICT,
    version                 integer     NOT NULL DEFAULT 1 CHECK (version > 0),
    created_by              uuid        REFERENCES users (id) ON DELETE RESTRICT,
    created_at              timestamptz NOT NULL DEFAULT now(),
    updated_at              timestamptz NOT NULL DEFAULT now(),
    archived_at             timestamptz
);

CREATE UNIQUE INDEX client_accounts_code_key ON client_accounts (code);
CREATE INDEX client_accounts_status_idx      ON client_accounts (status, name);

CREATE TRIGGER trg_client_accounts_touch
    BEFORE UPDATE ON client_accounts
    FOR EACH ROW EXECUTE FUNCTION rb_touch_updated_at();

-- The account manager is company staff.
CREATE FUNCTION rb_client_account_manager_internal() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    v_type text;
BEGIN
    IF NEW.account_manager_user_id IS NULL THEN
        RETURN NEW;
    END IF;
    SELECT principal_type INTO v_type FROM users WHERE id = NEW.account_manager_user_id;
    IF v_type IS DISTINCT FROM 'INTERNAL' THEN
        RAISE EXCEPTION 'client account manager must be an INTERNAL principal'
            USING ERRCODE = 'raise_exception';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_client_accounts_manager_internal
    BEFORE INSERT OR UPDATE ON client_accounts
    FOR EACH ROW EXECUTE FUNCTION rb_client_account_manager_internal();

-- -----------------------------------------------------------------------------
-- client_memberships
--
-- A relationship table, never a users.client_id column, so that "a user belongs to
-- more than one client account" never requires unwinding an assumption.
-- A membership is inert until status = 'ACTIVE'.
-- -----------------------------------------------------------------------------
CREATE TABLE client_memberships (
    id                uuid        PRIMARY KEY,
    client_account_id uuid        NOT NULL REFERENCES client_accounts (id) ON DELETE RESTRICT,
    user_id           uuid        NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    status            text        NOT NULL CHECK (status IN ('PENDING', 'ACTIVE', 'SUSPENDED', 'REMOVED')),
    invited_by        uuid        REFERENCES users (id) ON DELETE RESTRICT,
    activated_at      timestamptz,
    removed_at        timestamptz,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX client_memberships_key ON client_memberships (client_account_id, user_id);
CREATE INDEX client_memberships_user_active_idx
    ON client_memberships (user_id) WHERE status = 'ACTIVE';

CREATE TRIGGER trg_client_memberships_touch
    BEFORE UPDATE ON client_memberships
    FOR EACH ROW EXECUTE FUNCTION rb_touch_updated_at();

-- Only external principals may be members of a client account.
CREATE FUNCTION rb_require_client_user() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    v_type text;
BEGIN
    SELECT principal_type INTO v_type FROM users WHERE id = NEW.user_id;
    IF v_type IS DISTINCT FROM 'CLIENT' THEN
        RAISE EXCEPTION 'client_memberships requires a CLIENT principal (user % is %)',
                        NEW.user_id, coalesce(v_type, '<missing>')
            USING ERRCODE = 'raise_exception';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_client_memberships_client_only
    BEFORE INSERT OR UPDATE ON client_memberships
    FOR EACH ROW EXECUTE FUNCTION rb_require_client_user();

-- =============================================================================
-- invitations
--
-- The only path to an INTERNAL account. The intended principal type and role set
-- are fixed by the inviter at creation and re-validated against the INVITER's own
-- delegation authority at acceptance time, so a stale invitation cannot outlive
-- the authority that created it.
-- =============================================================================
CREATE TABLE invitations (
    id                uuid        PRIMARY KEY,
    email             text        NOT NULL CHECK (length(email) BETWEEN 3 AND 254),
    email_normalized  text        NOT NULL CHECK (email_normalized = lower(btrim(email_normalized))),
    principal_type    text        NOT NULL CHECK (principal_type IN ('INTERNAL', 'CLIENT')),
    display_name      text        NOT NULL CHECK (length(display_name) BETWEEN 1 AND 200),
    client_account_id uuid        REFERENCES client_accounts (id) ON DELETE RESTRICT,
    department_id     uuid        REFERENCES departments (id) ON DELETE RESTRICT,
    token_hash        bytea       NOT NULL CHECK (octet_length(token_hash) = 32),
    status            text        NOT NULL CHECK (status IN ('PENDING', 'ACCEPTED', 'REVOKED', 'EXPIRED')),
    invited_by        uuid        NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    accepted_user_id  uuid        REFERENCES users (id) ON DELETE RESTRICT,
    expires_at        timestamptz NOT NULL,
    accepted_at       timestamptz,
    revoked_at        timestamptz,
    created_at        timestamptz NOT NULL DEFAULT now(),

    -- An internal invitation can never carry a client account, and a client
    -- invitation can never carry a department.
    CONSTRAINT invitations_internal_no_client CHECK (principal_type = 'CLIENT' OR client_account_id IS NULL),
    CONSTRAINT invitations_client_no_department CHECK (principal_type = 'INTERNAL' OR department_id IS NULL),
    CONSTRAINT invitations_accepted_consistent CHECK ((status = 'ACCEPTED') = (accepted_user_id IS NOT NULL))
);

CREATE UNIQUE INDEX invitations_token_hash_key ON invitations (token_hash);
-- One live invitation per address: inviting the same person twice is a
-- deterministic conflict rather than two simultaneously valid tokens.
CREATE UNIQUE INDEX invitations_one_pending_per_email
    ON invitations (email_normalized) WHERE status = 'PENDING';
CREATE INDEX invitations_status_idx ON invitations (status, created_at DESC);

CREATE TABLE invitation_roles (
    invitation_id uuid NOT NULL REFERENCES invitations (id) ON DELETE RESTRICT,
    role_id       uuid NOT NULL REFERENCES roles (id) ON DELETE RESTRICT,
    scope_type    text NOT NULL DEFAULT 'GLOBAL'
                       CHECK (scope_type IN ('GLOBAL', 'DEPARTMENT', 'ASSIGNED', 'SELF')),
    PRIMARY KEY (invitation_id, role_id)
);
