-- =============================================================================
-- 0003 — Permissions, roles, assignments, per-user overrides
--
-- The triggers in this file are deliberately redundant with the application's
-- authorisation checks. TH-08 (a CLIENT receiving an internal role) and TH-09
-- (a CLIENT holding an internal permission) must not be defeatable by a single
-- application defect, so each is refused independently by the database.
-- =============================================================================

CREATE TABLE permissions (
    code               text        PRIMARY KEY
                                   CHECK (code ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$'),
    module             text        NOT NULL CHECK (length(module) BETWEEN 1 AND 50),
    description        text        NOT NULL CHECK (length(description) BETWEEN 1 AND 300),
    -- 'INTERNAL' => only INTERNAL principals may ever hold it. This column IS the
    -- client security envelope; the evaluator consults it before it looks at a
    -- single grant.
    max_principal_type text        NOT NULL CHECK (max_principal_type IN ('INTERNAL', 'ANY')),
    -- Granting or exercising a dangerous permission requires recent step-up MFA.
    is_dangerous       boolean     NOT NULL DEFAULT false,
    created_at         timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX permissions_module_idx ON permissions (module, code);

CREATE TABLE roles (
    id                     uuid        PRIMARY KEY,
    code                   text        NOT NULL CHECK (code ~ '^[a-z][a-z0-9_]*$'),
    name                   text        NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    description            text        NOT NULL DEFAULT '' CHECK (length(description) <= 500),
    -- System roles cannot be edited or deleted through the API by anyone.
    is_system              boolean     NOT NULL DEFAULT false,
    allowed_principal_type text        NOT NULL CHECK (allowed_principal_type IN ('INTERNAL', 'CLIENT')),
    version                integer     NOT NULL DEFAULT 1 CHECK (version > 0),
    created_by             uuid        REFERENCES users (id) ON DELETE RESTRICT,
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX roles_code_key ON roles (code);

CREATE TRIGGER trg_roles_touch
    BEFORE UPDATE ON roles
    FOR EACH ROW EXECUTE FUNCTION rb_touch_updated_at();

-- -----------------------------------------------------------------------------
-- role_permissions
--
-- RESOURCE scope is intentionally absent here: a role is a reusable template and
-- cannot name a specific object. Only per-user overrides may be RESOURCE-scoped.
-- -----------------------------------------------------------------------------
CREATE TABLE role_permissions (
    role_id         uuid        NOT NULL REFERENCES roles (id) ON DELETE RESTRICT,
    permission_code text        NOT NULL REFERENCES permissions (code) ON DELETE RESTRICT,
    scope_type      text        NOT NULL CHECK (scope_type IN ('GLOBAL', 'DEPARTMENT', 'ASSIGNED', 'SELF')),
    granted_by      uuid        REFERENCES users (id) ON DELETE RESTRICT,
    granted_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (role_id, permission_code)
);

CREATE INDEX role_permissions_role_idx ON role_permissions (role_id);

-- A CLIENT-facing role must not be able to carry an INTERNAL-only permission.
CREATE FUNCTION rb_role_permission_envelope() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    v_role_principal text;
    v_perm_max       text;
BEGIN
    SELECT allowed_principal_type INTO v_role_principal FROM roles       WHERE id   = NEW.role_id;
    SELECT max_principal_type     INTO v_perm_max       FROM permissions WHERE code = NEW.permission_code;

    IF v_role_principal = 'CLIENT' AND v_perm_max = 'INTERNAL' THEN
        RAISE EXCEPTION 'permission % is INTERNAL-only and cannot be attached to a CLIENT role', NEW.permission_code
            USING ERRCODE = 'raise_exception';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_role_permission_envelope
    BEFORE INSERT OR UPDATE ON role_permissions
    FOR EACH ROW EXECUTE FUNCTION rb_role_permission_envelope();

-- -----------------------------------------------------------------------------
-- user_role_assignments
-- -----------------------------------------------------------------------------
CREATE TABLE user_role_assignments (
    id         uuid        PRIMARY KEY,
    user_id    uuid        NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    role_id    uuid        NOT NULL REFERENCES roles (id) ON DELETE RESTRICT,
    granted_by uuid        REFERENCES users (id) ON DELETE RESTRICT,
    granted_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX user_role_assignments_key ON user_role_assignments (user_id, role_id);
CREATE INDEX user_role_assignments_user_idx   ON user_role_assignments (user_id);
CREATE INDEX user_role_assignments_role_idx   ON user_role_assignments (role_id);

-- The role's principal type must match the subject's. This is the database half of
-- the client envelope: a CLIENT cannot receive an INTERNAL role even by direct SQL.
CREATE FUNCTION rb_role_assignment_principal_match() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    v_user_principal text;
    v_role_principal text;
    v_role_code      text;
BEGIN
    SELECT principal_type INTO v_user_principal FROM users WHERE id = NEW.user_id;
    SELECT allowed_principal_type, code INTO v_role_principal, v_role_code FROM roles WHERE id = NEW.role_id;

    IF v_user_principal IS DISTINCT FROM v_role_principal THEN
        RAISE EXCEPTION 'role % is restricted to % principals and cannot be assigned to a % principal',
                        v_role_code, v_role_principal, v_user_principal
            USING ERRCODE = 'raise_exception';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_role_assignment_principal_match
    BEFORE INSERT OR UPDATE ON user_role_assignments
    FOR EACH ROW EXECUTE FUNCTION rb_role_assignment_principal_match();

-- -----------------------------------------------------------------------------
-- user_permission_overrides
--
-- Explicit exceptions for one person. A matching DENY always beats any role ALLOW
-- (see docs/backend/04-authorization.md §5), and a DENY also blocks delegation of
-- that permission by the denied actor.
-- -----------------------------------------------------------------------------
CREATE TABLE user_permission_overrides (
    id              uuid        PRIMARY KEY,
    user_id         uuid        NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    permission_code text        NOT NULL REFERENCES permissions (code) ON DELETE RESTRICT,
    effect          text        NOT NULL CHECK (effect IN ('ALLOW', 'DENY')),
    scope_type      text        NOT NULL CHECK (scope_type IN ('GLOBAL', 'DEPARTMENT', 'ASSIGNED', 'SELF', 'RESOURCE')),
    resource_type   text        CHECK (resource_type IS NULL OR resource_type IN ('PROJECT', 'TASK', 'DEPARTMENT', 'CLIENT_ACCOUNT', 'USER')),
    resource_id     uuid,
    expires_at      timestamptz,
    reason          text        NOT NULL DEFAULT '' CHECK (length(reason) <= 500),
    granted_by      uuid        NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    granted_at      timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT overrides_resource_consistent CHECK (
        (scope_type = 'RESOURCE') = (resource_id IS NOT NULL AND resource_type IS NOT NULL)
    )
);

CREATE UNIQUE INDEX user_permission_overrides_key
    ON user_permission_overrides (
        user_id, permission_code, effect, scope_type,
        coalesce(resource_id, '00000000-0000-0000-0000-000000000000'::uuid)
    );
CREATE INDEX user_permission_overrides_lookup_idx
    ON user_permission_overrides (user_id, permission_code);

-- A CLIENT must never receive an ALLOW override for an INTERNAL-only permission.
-- DENY overrides are always permitted: they only ever remove authority.
CREATE FUNCTION rb_override_envelope() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    v_user_principal text;
    v_perm_max       text;
BEGIN
    IF NEW.effect <> 'ALLOW' THEN
        RETURN NEW;
    END IF;

    SELECT principal_type     INTO v_user_principal FROM users       WHERE id   = NEW.user_id;
    SELECT max_principal_type INTO v_perm_max       FROM permissions WHERE code = NEW.permission_code;

    IF v_user_principal = 'CLIENT' AND v_perm_max = 'INTERNAL' THEN
        RAISE EXCEPTION 'permission % is INTERNAL-only and cannot be allowed for a CLIENT principal', NEW.permission_code
            USING ERRCODE = 'raise_exception';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_override_envelope
    BEFORE INSERT OR UPDATE ON user_permission_overrides
    FOR EACH ROW EXECUTE FUNCTION rb_override_envelope();
