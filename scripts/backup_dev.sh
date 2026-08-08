#!/usr/bin/env bash
# =============================================================================
# RoleBlank OS — logical backup of the DEVELOPMENT database
# =============================================================================
# Dumps the `roleblank` database out of the local development PostgreSQL
# container into backups/roleblank_dev_<UTC timestamp>.dump.
#
# This is a DEVELOPMENT convenience, not a backup strategy. A production backup
# strategy needs off-host storage, encryption at rest, retention policy, PITR via
# WAL archiving, and — most importantly — regularly rehearsed restores. A dump
# that has never been restored is a hypothesis, not a backup.
#
# Interpreter note: the body of this script is POSIX sh, but `set -o pipefail` is
# a bash/ksh extension (dash does not implement it) and silently losing the exit
# status of a piped pg_dump is exactly the failure mode this guards against. Bash
# is therefore the interpreter; nothing else here is bash-specific.
# =============================================================================
set -euo pipefail

# --- Configuration (matches scripts/rb.ps1 and docker-compose.dev.yml) --------
CONTAINER="${RB_PG_CONTAINER:-roleblank-postgres}"
DB_NAME="${RB_DB_NAME:-roleblank}"
DB_SUPERUSER="${RB_PG_SUPERUSER:-postgres}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BACKUP_DIR="${REPO_ROOT}/backups"

TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_FILE="${BACKUP_DIR}/roleblank_dev_${TIMESTAMP}.dump"

say()  { printf '==> %s\n' "$*"; }
fail() { printf '!!! %s\n' "$*" >&2; exit 1; }

# --- Preconditions -----------------------------------------------------------
command -v docker >/dev/null 2>&1 || fail "docker is not on PATH."

# Refuse rather than produce a zero-byte "backup". An empty or missing dump that
# looks like a success is worse than a loud failure.
if [ -z "$(docker ps --filter "name=^/${CONTAINER}$" --format '{{.Names}}' || true)" ]; then
    fail "container '${CONTAINER}' is not running. Start it first:  ./scripts/rb.ps1 db-up
    (or: docker compose -f docker-compose.dev.yml up -d postgres)"
fi

mkdir -p "${BACKUP_DIR}"

# --- Announce exactly what is about to happen --------------------------------
say "About to run a logical backup:"
printf '      container : %s\n' "${CONTAINER}"
printf '      database  : %s\n' "${DB_NAME}"
printf '      role      : %s\n' "${DB_SUPERUSER}"
printf '      format    : custom (-Fc, compressed, restorable selectively)\n'
printf '      output    : %s\n' "${OUT_FILE}"
printf '      command   : docker exec %s pg_dump -U %s -d %s -Fc\n' \
       "${CONTAINER}" "${DB_SUPERUSER}" "${DB_NAME}"

# --- Dump --------------------------------------------------------------------
# -Fc (custom format) rather than plain SQL because it is compressed, allows
# selective restore of individual tables via pg_restore -t, and does not depend
# on psql to replay.
# --no-password: never hang waiting on an interactive prompt in a script. The
# official image authenticates local socket connections with `trust`, which is
# why no password is supplied here; if that changes, export PGPASSWORD.
# Writing to a temp file first means an interrupted dump never leaves a
# plausible-looking but truncated .dump behind.
TMP_FILE="${OUT_FILE}.partial"
trap 'rm -f "${TMP_FILE}"' EXIT

docker exec "${CONTAINER}" \
    pg_dump --username="${DB_SUPERUSER}" --dbname="${DB_NAME}" \
            --format=custom --compress=9 --no-password \
    > "${TMP_FILE}"

mv "${TMP_FILE}" "${OUT_FILE}"
trap - EXIT

# --- Report ------------------------------------------------------------------
# Size is printed as a sanity signal: a dump that suddenly shrank by an order of
# magnitude is the cheapest possible early warning of data loss.
SIZE_BYTES="$(wc -c < "${OUT_FILE}" | tr -d ' ')"
SIZE_HUMAN="$(ls -lh "${OUT_FILE}" | awk '{print $5}')"

say "Backup complete."
printf '      file  : %s\n' "${OUT_FILE}"
printf '      size  : %s (%s bytes)\n' "${SIZE_HUMAN}" "${SIZE_BYTES}"

if [ "${SIZE_BYTES}" -lt 1024 ]; then
    fail "dump is under 1 KiB — that is almost certainly not a real backup. Investigate before trusting it."
fi

say "Restore with:  RB_CONFIRM_RESTORE=yes ./scripts/restore_dev.sh '${OUT_FILE}'"
