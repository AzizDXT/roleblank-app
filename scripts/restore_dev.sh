#!/usr/bin/env bash
# =============================================================================
# RoleBlank OS — restore the DEVELOPMENT database from a dump
# =============================================================================
# DESTRUCTIVE. This drops the `roleblank` database and recreates it from a dump
# produced by scripts/backup_dev.sh.
#
# Usage:
#   RB_CONFIRM_RESTORE=yes ./scripts/restore_dev.sh [path/to/file.dump]
#
# With no argument it picks the newest file in backups/.
#
# The RB_CONFIRM_RESTORE guard exists because this script is one tab-completion
# away from `backup_dev.sh` and a mistyped command must not be able to destroy a
# database. There is no --force flag on purpose: the guard has to be typed out.
#
# Interpreter note: POSIX body, bash interpreter — `set -o pipefail` is not in
# POSIX sh but losing a piped pg_restore's exit status is unacceptable here.
# =============================================================================
set -euo pipefail

# --- Configuration (matches scripts/rb.ps1 and docker-compose.dev.yml) --------
CONTAINER="${RB_PG_CONTAINER:-roleblank-postgres}"
DB_NAME="${RB_DB_NAME:-roleblank}"
DB_OWNER="${RB_DB_OWNER:-roleblank_migrator}"
DB_SUPERUSER="${RB_PG_SUPERUSER:-postgres}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BACKUP_DIR="${REPO_ROOT}/backups"

say()  { printf '==> %s\n' "$*"; }
fail() { printf '!!! %s\n' "$*" >&2; exit 1; }

# --- Guard rails -------------------------------------------------------------
if [ "${RB_CONFIRM_RESTORE:-}" != "yes" ]; then
    fail "refusing to run: this DROPS the '${DB_NAME}' database and every row in it.
    Re-run with the confirmation set explicitly:
        RB_CONFIRM_RESTORE=yes $0 ${1:-<dump file>}"
fi

command -v docker >/dev/null 2>&1 || fail "docker is not on PATH."

if [ -z "$(docker ps --filter "name=^/${CONTAINER}$" --format '{{.Names}}' || true)" ]; then
    fail "container '${CONTAINER}' is not running. Start it first:  ./scripts/rb.ps1 db-up"
fi

# --- Resolve the dump --------------------------------------------------------
if [ "$#" -ge 1 ] && [ -n "$1" ]; then
    DUMP_FILE="$1"
else
    [ -d "${BACKUP_DIR}" ] || fail "no backups/ directory and no dump path given."
    # Newest first. `ls -t` is adequate here because backup_dev.sh writes UTC
    # timestamped names, so lexical and chronological order agree anyway.
    DUMP_FILE="$(ls -t "${BACKUP_DIR}"/*.dump 2>/dev/null | head -n 1 || true)"
    [ -n "${DUMP_FILE}" ] || fail "no *.dump files found in ${BACKUP_DIR} and no path given."
    say "No dump specified — selected the newest one in backups/."
fi

[ -f "${DUMP_FILE}" ] || fail "dump file not found: ${DUMP_FILE}"
DUMP_SIZE="$(ls -lh "${DUMP_FILE}" | awk '{print $5}')"

# --- Announce exactly what is about to happen --------------------------------
say "About to perform a DESTRUCTIVE restore:"
printf '      container    : %s\n' "${CONTAINER}"
printf '      dump file    : %s (%s)\n' "${DUMP_FILE}" "${DUMP_SIZE}"
printf '      step 1       : terminate all connections to "%s"\n' "${DB_NAME}"
printf '      step 2       : DROP DATABASE IF EXISTS %s        <-- irreversible\n' "${DB_NAME}"
printf '      step 3       : CREATE DATABASE %s OWNER %s\n' "${DB_NAME}" "${DB_OWNER}"
printf '      step 4       : pg_restore the dump into it\n'
printf '      step 5       : print row counts for users and audit_events\n'

# --- Step 1+2+3: drop and recreate ------------------------------------------
# Connections must be terminated first: DROP DATABASE fails while any session is
# attached, and a stray psql or a running API is the normal case in development.
# pg_backend_pid() exclusion keeps this session alive.
say "Terminating connections and recreating the database..."
docker exec -i "${CONTAINER}" \
    psql --username="${DB_SUPERUSER}" --dbname=postgres --no-password \
         --set=ON_ERROR_STOP=1 <<SQL
SELECT pg_terminate_backend(pid)
  FROM pg_stat_activity
 WHERE datname = '${DB_NAME}' AND pid <> pg_backend_pid();
DROP DATABASE IF EXISTS ${DB_NAME};
CREATE DATABASE ${DB_NAME} OWNER ${DB_OWNER};
SQL

# --- Step 4: restore ---------------------------------------------------------
# --exit-on-error: by default pg_restore reports errors and carries on, which
# produces a partially restored database that looks like a success.
# Ownership and privileges are taken from the dump (no --no-owner), which is
# correct here because the migrator/app roles exist in this cluster; restoring
# into a cluster without them would need --no-owner --no-privileges plus a
# re-run of ops/sql/provision_*.sql.
say "Restoring (pg_restore --exit-on-error)..."
docker exec -i "${CONTAINER}" \
    pg_restore --username="${DB_SUPERUSER}" --dbname="${DB_NAME}" \
               --no-password --exit-on-error --verbose \
    < "${DUMP_FILE}"

# --- Step 5: verify ----------------------------------------------------------
# A restore is not "done" because pg_restore exited 0 — it is done when the data
# is demonstrably there. users and audit_events are the two tables whose loss
# would matter most: identities, and the tamper-evident audit chain.
say "Verifying restored contents..."
count_of() {
    docker exec -i "${CONTAINER}" \
        psql --username="${DB_SUPERUSER}" --dbname="${DB_NAME}" \
             --no-password --tuples-only --no-align \
             --command="SELECT count(*) FROM $1;" 2>/dev/null || echo "ERROR"
}

USERS_COUNT="$(count_of users)"
AUDIT_COUNT="$(count_of audit_events)"

printf '      users        : %s row(s)\n' "${USERS_COUNT}"
printf '      audit_events : %s row(s)\n' "${AUDIT_COUNT}"

if [ "${USERS_COUNT}" = "ERROR" ] || [ "${AUDIT_COUNT}" = "ERROR" ]; then
    fail "could not read row counts — the restore did not produce the expected schema."
fi

say "Restore complete."
say "Next: verify the audit hash chain end to end —  ./scripts/rb.ps1 verify-audit"
