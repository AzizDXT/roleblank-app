-- =============================================================================
-- RoleBlank OS — CI database provisioning
-- =============================================================================
-- Creates the two separate PostgreSQL identities the privilege-separation design
-- requires, plus the `roleblank` database:
--
--   roleblank_migrator  — owns the database and the schema. Runs migrations.
--                         This is the ONLY identity permitted to alter the shape
--                         of the schema.
--   roleblank_app       — the runtime identity the API connects as. Owns
--                         nothing, cannot create or drop anything, is not a
--                         superuser and cannot create databases or roles.
--
-- WHY the split: if the serving process is compromised, the attacker inherits
-- its database identity. An identity that cannot DROP TABLE, cannot disable a
-- trigger, cannot alter the audit chain's constraints and does not own the
-- objects it reads is a materially smaller prize than a single all-powerful
-- role. The audit-chain and ROOT_OWNER invariants enforced by database triggers
-- are only meaningful if the runtime role cannot remove those triggers.
--
-- Idempotent: safe to run repeatedly against the same cluster.
-- Must be run as a superuser (CI runs it as `postgres`).
--
-- Usage (passwords passed in, never stored in this file):
--   psql -v ON_ERROR_STOP=1 -U postgres -d postgres \
--        -v migrator_password='...' -v app_password='...' \
--        -f ops/sql/provision_ci.sql
--
-- This file is psql-specific (it uses \if, \gexec and \connect). It is not
-- plain SQL and will not run through a generic SQL client.
-- =============================================================================

\set ON_ERROR_STOP on

-- -----------------------------------------------------------------------------
-- Password defaults
-- -----------------------------------------------------------------------------
-- !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
-- !! THE FALLBACK PASSWORDS BELOW ARE FAKE AND EXIST ONLY SO THIS FILE CAN   !!
-- !! RUN UNATTENDED IN CI AGAINST A THROWAWAY, LOOPBACK-ONLY CONTAINER.      !!
-- !! THEY ARE NOT SECRETS. IF EITHER OF THEM EVER APPEARS IN A NON-CI        !!
-- !! ENVIRONMENT, THAT ENVIRONMENT IS MISCONFIGURED — TREAT IT AS AN         !!
-- !! INCIDENT. Production roles are created by a human operator with         !!
-- !! generated passwords held in a secret manager (docs/backend/08-operations.md).
-- !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
\if :{?migrator_password}
\else
  \set migrator_password 'ci_only_fake_migrator_pw'
\endif

\if :{?app_password}
\else
  \set app_password 'ci_only_fake_app_pw'
\endif

-- -----------------------------------------------------------------------------
-- 1. Roles
-- -----------------------------------------------------------------------------
-- CREATE ROLE cannot be wrapped in IF NOT EXISTS, hence the DO block. The role
-- is created here with no password; attributes and password are applied
-- immediately afterwards so that a re-run also *converges* an existing role to
-- the intended state instead of leaving whatever it happened to have.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'roleblank_migrator') THEN
        CREATE ROLE roleblank_migrator LOGIN;
        RAISE NOTICE 'created role roleblank_migrator';
    ELSE
        RAISE NOTICE 'role roleblank_migrator already exists';
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'roleblank_app') THEN
        CREATE ROLE roleblank_app LOGIN;
        RAISE NOTICE 'created role roleblank_app';
    ELSE
        RAISE NOTICE 'role roleblank_app already exists';
    END IF;
END
$$;

-- Passwords are applied outside the DO block on purpose: psql does NOT
-- interpolate its variables inside dollar-quoted strings, so a password
-- referenced within `DO $$ ... $$` would be taken literally. `format(%L)` also
-- quotes/escapes the value correctly, which naive string concatenation does not.
SELECT format(
    'ALTER ROLE roleblank_migrator WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE '
    'NOREPLICATION NOBYPASSRLS INHERIT PASSWORD %L',
    :'migrator_password'
)\gexec

-- The runtime role is stripped of every attribute that would let it escalate:
-- not a superuser, cannot create databases, cannot create or grant roles, cannot
-- replicate (which would let it stream the entire cluster), and cannot bypass
-- row-level security.
SELECT format(
    'ALTER ROLE roleblank_app WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE '
    'NOREPLICATION NOBYPASSRLS INHERIT PASSWORD %L',
    :'app_password'
)\gexec

-- -----------------------------------------------------------------------------
-- 2. Database
-- -----------------------------------------------------------------------------
-- CREATE DATABASE cannot run inside a transaction or a DO block, so the
-- idempotency guard is a \gexec that produces zero rows when the database
-- already exists.
SELECT 'CREATE DATABASE roleblank OWNER roleblank_migrator'
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'roleblank')\gexec

-- Converge ownership even if the database pre-existed with a different owner.
ALTER DATABASE roleblank OWNER TO roleblank_migrator;

-- PUBLIC gets CONNECT on every new database by default. Revoking it and granting
-- explicitly means a future role cannot reach this database by accident.
REVOKE CONNECT ON DATABASE roleblank FROM PUBLIC;
GRANT  CONNECT ON DATABASE roleblank TO roleblank_migrator;
GRANT  CONNECT ON DATABASE roleblank TO roleblank_app;

-- -----------------------------------------------------------------------------
-- 3. Inside the roleblank database
-- -----------------------------------------------------------------------------
-- Object-level privileges are per-database, so we must connect to it.
\connect roleblank

-- The schema is owned by the migrator: it is the identity that creates tables.
ALTER SCHEMA public OWNER TO roleblank_migrator;

-- PostgreSQL 15+ already removes PUBLIC's CREATE on `public`, but older clusters
-- and restored dumps may not have. Revoking unconditionally is idempotent and
-- guarantees the runtime role cannot create objects of its own — an attacker who
-- can CREATE TABLE can stage data and shadow functions on the search_path.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL    ON SCHEMA public FROM roleblank_app;

-- USAGE lets the runtime role *see* objects in the schema; it does not let it
-- create any.
GRANT USAGE ON SCHEMA public TO roleblank_app;

-- Existing objects (this file may run after migrations on a re-provision).
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES    IN SCHEMA public TO roleblank_app;
GRANT USAGE, SELECT                  ON ALL SEQUENCES IN SCHEMA public TO roleblank_app;

-- Objects that migrations will create later. Without this, every new migration
-- would require a matching manual GRANT and the app would fail at run time on a
-- table CI never exercised.
--
-- Note the deliberate absence of TRUNCATE and REFERENCES: the runtime role must
-- not be able to empty a table in one statement (audit_events above all), and
-- must not be able to attach foreign keys that change delete semantics.
ALTER DEFAULT PRIVILEGES FOR ROLE roleblank_migrator IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO roleblank_app;

ALTER DEFAULT PRIVILEGES FOR ROLE roleblank_migrator IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO roleblank_app;

-- Functions default to EXECUTE for PUBLIC. Explicitly not granting anything
-- extra here; migrations grant EXECUTE per function where the runtime needs it.

-- -----------------------------------------------------------------------------
-- 4. Verification — makes a silent partial failure impossible
-- -----------------------------------------------------------------------------
DO $$
DECLARE
    bad_attr text;
BEGIN
    SELECT string_agg(rolname, ', ')
      INTO bad_attr
      FROM pg_roles
     WHERE rolname = 'roleblank_app'
       AND (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls);

    IF bad_attr IS NOT NULL THEN
        RAISE EXCEPTION
            'runtime role % still holds a privileged attribute — provisioning must not be considered successful',
            bad_attr;
    END IF;

    IF (SELECT nspowner FROM pg_namespace WHERE nspname = 'public')
       <> (SELECT oid FROM pg_roles WHERE rolname = 'roleblank_migrator') THEN
        RAISE EXCEPTION 'schema public is not owned by roleblank_migrator';
    END IF;

    RAISE NOTICE 'provisioning verified: migrator owns the schema, runtime role is unprivileged';
END
$$;
