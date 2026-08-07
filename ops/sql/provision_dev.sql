-- =============================================================================
-- Development role provisioning for RoleBlank OS
--
-- Run as a PostgreSQL superuser, once, before the first `migrate`:
--     .\scripts\rb.ps1 db-provision
--
-- Creates TWO separate identities, which is the point of this file:
--
--   roleblank_migrator  owns the schema. Runs migrations. Never used by the API.
--   roleblank_app       the runtime identity. Owns nothing. Cannot DDL.
--                       Cannot disable a trigger. Cannot rewrite audit history.
--
-- Idempotent: safe to run repeatedly.
--
-- !!! THE PASSWORDS BELOW ARE DEVELOPMENT-ONLY PLACEHOLDERS. !!!
-- They exist so a developer can start in one command on a loopback-only
-- container. Production credentials come from the secret manager and are never
-- written in a file in this repository. See docs/backend/08-operations.md.
-- =============================================================================

\set ON_ERROR_STOP on

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'roleblank_migrator') THEN
        -- LOGIN so migrations can be run as this role from the CLI.
        -- No SUPERUSER, no CREATEROLE, no BYPASSRLS: owning the schema is enough
        -- authority for migrations and nothing more should be handed out.
        CREATE ROLE roleblank_migrator LOGIN PASSWORD 'dev_migrator_pw'
            NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION;
        RAISE NOTICE 'created role roleblank_migrator';
    ELSE
        RAISE NOTICE 'role roleblank_migrator already exists';
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'roleblank_app') THEN
        CREATE ROLE roleblank_app LOGIN PASSWORD 'dev_app_pw'
            NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION;
        RAISE NOTICE 'created role roleblank_app';
    ELSE
        RAISE NOTICE 'role roleblank_app already exists';
    END IF;
END;
$$;

-- CREATE DATABASE cannot run inside a DO block or a transaction, so it is guarded
-- by \gexec instead.
SELECT 'CREATE DATABASE roleblank OWNER roleblank_migrator'
 WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'roleblank')
\gexec

-- A second database used only by the integration test harness, which creates and
-- drops throwaway databases inside it.
SELECT 'CREATE DATABASE roleblank_test OWNER roleblank_migrator'
 WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'roleblank_test')
\gexec

\connect roleblank

-- The migrator owns the schema; the app role connects but owns nothing.
ALTER SCHEMA public OWNER TO roleblank_migrator;

-- Revoke the historical PUBLIC grant. Without this, every role in the cluster —
-- including roleblank_app — can CREATE objects in `public`, which would let the
-- runtime identity introduce a shadowing table or a helper function.
REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON DATABASE roleblank FROM PUBLIC;

GRANT CONNECT ON DATABASE roleblank TO roleblank_app;
GRANT CONNECT ON DATABASE roleblank TO roleblank_migrator;
GRANT ALL    ON SCHEMA   public     TO roleblank_migrator;
GRANT USAGE  ON SCHEMA   public     TO roleblank_app;

-- Deliberately NOT set: ALTER DEFAULT PRIVILEGES granting the app role access to
-- future tables. Each migration grants explicitly on the tables it creates
-- (see 0009_runtime_grants.sql), so a new table is a decision rather than an
-- implicit full-access default.

\connect roleblank_test
ALTER SCHEMA public OWNER TO roleblank_migrator;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT CONNECT ON DATABASE roleblank_test TO roleblank_app;
GRANT CONNECT ON DATABASE roleblank_test TO roleblank_migrator;
GRANT ALL   ON SCHEMA public TO roleblank_migrator;
GRANT USAGE ON SCHEMA public TO roleblank_app;

-- The test harness creates and drops throwaway databases, so it needs CREATEDB.
-- Development only; the production migrator role must NOT have this.
ALTER ROLE roleblank_migrator CREATEDB;

\echo 'RoleBlank development roles provisioned.'
\echo '  migrator : postgres://roleblank_migrator:dev_migrator_pw@localhost:5440/roleblank'
\echo '  runtime  : postgres://roleblank_app:dev_app_pw@localhost:5440/roleblank'
