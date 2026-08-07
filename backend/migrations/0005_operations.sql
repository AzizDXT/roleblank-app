-- =============================================================================
-- 0005 — Projects, project membership, client sharing, tasks
--
-- The rule that shapes this file: a resource identifier is NOT an authorisation.
-- Client visibility is derived exclusively from project_client_links joined to an
-- ACTIVE client_membership, never from possession of a UUID.
-- =============================================================================

CREATE TABLE projects (
    id              uuid        PRIMARY KEY,
    code            text        NOT NULL CHECK (code ~ '^[a-z0-9][a-z0-9_-]{0,49}$'),
    name            text        NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    description     text        NOT NULL DEFAULT '' CHECK (length(description) <= 5000),
    status          text        NOT NULL CHECK (status IN ('ACTIVE', 'PAUSED', 'COMPLETED', 'ARCHIVED')),
    manager_user_id uuid        NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    department_id   uuid        REFERENCES departments (id) ON DELETE RESTRICT,
    start_date      date,
    target_date     date,
    -- Internal-only field. It is physically absent from ClientProjectResponse; the
    -- client projection is a separate struct, not a filtered serialisation.
    internal_note   text        NOT NULL DEFAULT '' CHECK (length(internal_note) <= 5000),
    version         integer     NOT NULL DEFAULT 1 CHECK (version > 0),
    created_by      uuid        REFERENCES users (id) ON DELETE RESTRICT,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    archived_at     timestamptz,
    completed_at    timestamptz,

    CONSTRAINT projects_dates_ordered
        CHECK (target_date IS NULL OR start_date IS NULL OR target_date >= start_date),
    CONSTRAINT projects_archive_consistent
        CHECK ((status = 'ARCHIVED') = (archived_at IS NOT NULL))
);

CREATE UNIQUE INDEX projects_code_key      ON projects (code);
CREATE INDEX projects_status_idx           ON projects (status, created_at DESC, id DESC);
CREATE INDEX projects_department_idx       ON projects (department_id) WHERE department_id IS NOT NULL;
CREATE INDEX projects_manager_idx          ON projects (manager_user_id);

CREATE TRIGGER trg_projects_touch
    BEFORE UPDATE ON projects
    FOR EACH ROW EXECUTE FUNCTION rb_touch_updated_at();

-- The manager of an internal project is company staff.
CREATE FUNCTION rb_project_manager_internal() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    v_type text;
BEGIN
    SELECT principal_type INTO v_type FROM users WHERE id = NEW.manager_user_id;
    IF v_type IS DISTINCT FROM 'INTERNAL' THEN
        RAISE EXCEPTION 'project manager must be an INTERNAL principal'
            USING ERRCODE = 'raise_exception';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_projects_manager_internal
    BEFORE INSERT OR UPDATE ON projects
    FOR EACH ROW EXECUTE FUNCTION rb_project_manager_internal();

CREATE TABLE project_memberships (
    id              uuid        PRIMARY KEY,
    project_id      uuid        NOT NULL REFERENCES projects (id) ON DELETE RESTRICT,
    user_id         uuid        NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    role_in_project text        NOT NULL CHECK (role_in_project IN ('MEMBER', 'LEAD')),
    added_by        uuid        REFERENCES users (id) ON DELETE RESTRICT,
    added_at        timestamptz NOT NULL DEFAULT now(),
    removed_at      timestamptz
);

CREATE UNIQUE INDEX project_memberships_live_key
    ON project_memberships (project_id, user_id) WHERE removed_at IS NULL;
-- Serves ASSIGNED scope resolution on every authorised project request.
CREATE INDEX project_memberships_user_live_idx
    ON project_memberships (user_id) WHERE removed_at IS NULL;

CREATE TRIGGER trg_project_memberships_internal_only
    BEFORE INSERT OR UPDATE ON project_memberships
    FOR EACH ROW EXECUTE FUNCTION rb_require_internal_user();

-- -----------------------------------------------------------------------------
-- project_client_links — the ONLY thing that makes a project visible externally
-- -----------------------------------------------------------------------------
CREATE TABLE project_client_links (
    id                uuid        PRIMARY KEY,
    project_id        uuid        NOT NULL REFERENCES projects (id) ON DELETE RESTRICT,
    client_account_id uuid        NOT NULL REFERENCES client_accounts (id) ON DELETE RESTRICT,
    note              text        NOT NULL DEFAULT '' CHECK (length(note) <= 500),
    shared_by         uuid        NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    shared_at         timestamptz NOT NULL DEFAULT now(),
    revoked_by        uuid        REFERENCES users (id) ON DELETE RESTRICT,
    revoked_at        timestamptz,

    CONSTRAINT project_client_links_revoke_consistent
        CHECK ((revoked_at IS NULL) = (revoked_by IS NULL))
);

-- Revocation is an UPDATE, never a DELETE: the history of what was once shared
-- with whom is exactly the kind of record a client dispute later depends on.
CREATE UNIQUE INDEX project_client_links_live_key
    ON project_client_links (project_id, client_account_id) WHERE revoked_at IS NULL;
CREATE INDEX project_client_links_account_live_idx
    ON project_client_links (client_account_id) WHERE revoked_at IS NULL;

-- =============================================================================
-- tasks
-- =============================================================================
CREATE TABLE tasks (
    id             uuid        PRIMARY KEY,
    project_id     uuid        NOT NULL REFERENCES projects (id) ON DELETE RESTRICT,
    title          text        NOT NULL CHECK (length(title) BETWEEN 1 AND 300),
    description    text        NOT NULL DEFAULT '' CHECK (length(description) <= 10000),
    status         text        NOT NULL CHECK (status IN ('TODO', 'IN_PROGRESS', 'BLOCKED', 'DONE', 'CANCELLED')),
    priority       text        NOT NULL DEFAULT 'NORMAL' CHECK (priority IN ('LOW', 'NORMAL', 'HIGH', 'URGENT')),
    due_date       date,
    -- Per task, defaults to false, and NOT inherited from the project. Sharing a
    -- project with a client must never silently expose its task list.
    client_visible boolean     NOT NULL DEFAULT false,
    internal_note  text        NOT NULL DEFAULT '' CHECK (length(internal_note) <= 5000),
    version        integer     NOT NULL DEFAULT 1 CHECK (version > 0),
    created_by     uuid        REFERENCES users (id) ON DELETE RESTRICT,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    completed_at   timestamptz,

    CONSTRAINT tasks_completion_consistent
        CHECK ((status = 'DONE') = (completed_at IS NOT NULL))
);

CREATE INDEX tasks_project_status_idx  ON tasks (project_id, status, created_at DESC, id DESC);
CREATE INDEX tasks_client_visible_idx  ON tasks (project_id) WHERE client_visible;
CREATE INDEX tasks_due_idx             ON tasks (due_date) WHERE due_date IS NOT NULL AND status <> 'DONE';

CREATE TRIGGER trg_tasks_touch
    BEFORE UPDATE ON tasks
    FOR EACH ROW EXECUTE FUNCTION rb_touch_updated_at();

CREATE TABLE task_assignees (
    id          uuid        PRIMARY KEY,
    task_id     uuid        NOT NULL REFERENCES tasks (id) ON DELETE RESTRICT,
    user_id     uuid        NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    assigned_by uuid        REFERENCES users (id) ON DELETE RESTRICT,
    assigned_at timestamptz NOT NULL DEFAULT now(),
    removed_at  timestamptz
);

CREATE UNIQUE INDEX task_assignees_live_key
    ON task_assignees (task_id, user_id) WHERE removed_at IS NULL;
CREATE INDEX task_assignees_user_live_idx
    ON task_assignees (user_id) WHERE removed_at IS NULL;

CREATE TRIGGER trg_task_assignees_internal_only
    BEFORE INSERT OR UPDATE ON task_assignees
    FOR EACH ROW EXECUTE FUNCTION rb_require_internal_user();
