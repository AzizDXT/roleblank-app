#!/usr/bin/env bash
# =============================================================================
# RoleBlank OS — load test
# =============================================================================
# Drives the API with `oha` from inside a container (the Windows host enforces an
# Application Control policy that blocks freshly-built, unsigned binaries, so no
# Rust tool is installed on the host — see docs/backend/00-reconnaissance.md §3).
#
# Scenarios are run and reported SEPARATELY, never blended, because they have
# structurally different cost profiles and one aggregate number across them would
# be meaningless.
#
# Usage:
#   export RB_LOAD_TEST_TOKEN='<a session bearer token from a real login>'
#   ./scripts/load_test.sh
#
# Optional:
#   RB_LOAD_TEST_URL       base URL             (default http://host.docker.internal:8090)
#   RB_LOAD_TEST_DURATION  per-scenario runtime (default 30s)
#   RB_LOAD_TEST_CONN      concurrent conns     (default 50)
#   RB_LOAD_TEST_LOGIN_EMAIL / RB_LOAD_TEST_LOGIN_PASSWORD  enable the login scenario
#
# These numbers describe THIS machine under THIS configuration. They are not a
# capacity model and must never be quoted as production throughput.
#
# Interpreter note: POSIX body, bash interpreter — `set -o pipefail` is not POSIX
# but the oha output is piped, and a silently-swallowed failure would be reported
# as a passing load test.
# =============================================================================
set -euo pipefail

OHA_IMAGE="${RB_OHA_IMAGE:-ghcr.io/hatoo/oha:latest}"
NETWORK="${RB_NETWORK:-roleblank_net}"
BASE_URL="${RB_LOAD_TEST_URL:-http://host.docker.internal:8090}"
DURATION="${RB_LOAD_TEST_DURATION:-30s}"
CONNECTIONS="${RB_LOAD_TEST_CONN:-50}"

say()  { printf '\n==> %s\n' "$*"; }
fail() { printf '\n!!! %s\n' "$*" >&2; exit 1; }

# --- Preconditions -----------------------------------------------------------
command -v docker >/dev/null 2>&1 || fail "docker is not on PATH."

# Fail loudly and immediately. Running the authenticated scenarios without a
# token would measure the 401 path at full speed and report it as excellent
# performance — the most misleading possible result.
if [ -z "${RB_LOAD_TEST_TOKEN:-}" ]; then
    fail "RB_LOAD_TEST_TOKEN is not set.

    The authenticated scenarios need a real session bearer token, otherwise this
    script would be benchmarking the 401 rejection path and reporting it as if it
    were the API's real performance.

    Obtain one by logging in against the running dev API, then:
        export RB_LOAD_TEST_TOKEN='eyJ...'
        $0"
fi

# --- Scenario runner ---------------------------------------------------------
# --network roleblank_net attaches the load generator to the project network so
# it can also target the API by container name if you point RB_LOAD_TEST_URL at
# one. --add-host maps host.docker.internal on every platform (Docker Desktop
# provides it natively; host-gateway makes it work on plain Linux too), which is
# how the container reaches the API published on the host's loopback at 8090.
#
# --no-tui is required: oha's default interactive TUI produces no parseable
# output when stdout is not a terminal.
run_scenario() {
    label="$1"; shift

    say "SCENARIO: ${label}"
    printf '    target      : %s\n' "${SCENARIO_URL}"
    printf '    duration    : %s   connections: %s   rate: %s\n' \
           "${DURATION}" "${SCENARIO_CONN}" "${SCENARIO_RATE:-unthrottled}"

    output="$(
        docker run --rm \
            --network "${NETWORK}" \
            --add-host host.docker.internal:host-gateway \
            "${OHA_IMAGE}" \
            --no-tui \
            -z "${DURATION}" \
            -c "${SCENARIO_CONN}" \
            "$@" \
            "${SCENARIO_URL}"
    )" || fail "scenario '${label}' failed to execute (is the API up at ${BASE_URL}?)"

    # Throughput and error shape matter as much as latency: a fast p99 with a 50%
    # error rate is a broken service, not a fast one.
    printf '%s\n' "${output}" | grep -E '^  (Success rate|Requests/sec):' || true

    printf '    latency:\n'
    # oha prints a "Latency distribution" block with one line per percentile.
    printf '%s\n' "${output}" \
        | grep -E '^[[:space:]]+(50|95|99)\.00% in ' \
        | sed 's/^[[:space:]]*/      p/' \
        || printf '      (no latency distribution reported — check the output above)\n'

    # Any non-2xx is worth surfacing explicitly; oha lists status codes it saw.
    printf '%s\n' "${output}" | grep -A 10 '^Status code distribution:' || true
}

say "RoleBlank load test"
printf '    base URL   : %s\n' "${BASE_URL}"
printf '    generator  : %s (container, network %s)\n' "${OHA_IMAGE}" "${NETWORK}"
printf '    per-scenario duration: %s\n' "${DURATION}"

# -----------------------------------------------------------------------------
# 1. Liveness — no database, no auth. This is the floor: it measures the HTTP
#    stack and the runtime, nothing else. If this is slow, nothing else can be
#    fast, and the problem is not in the application logic.
# -----------------------------------------------------------------------------
SCENARIO_URL="${BASE_URL}/health/live"
SCENARIO_CONN="${CONNECTIONS}"
SCENARIO_RATE=""
run_scenario "health/live — liveness, no DB, no auth"

# -----------------------------------------------------------------------------
# 2. Readiness — touches the database connection pool. The delta between this and
#    /health/live is the cost of a pool checkout plus a trivial round trip, i.e.
#    the baseline database tax paid by every other endpoint.
# -----------------------------------------------------------------------------
SCENARIO_URL="${BASE_URL}/health/ready"
SCENARIO_CONN="${CONNECTIONS}"
SCENARIO_RATE=""
run_scenario "health/ready — readiness, DB pool round trip"

# -----------------------------------------------------------------------------
# 3. Authenticated identity read — session lookup + token hashing + permission
#    resolution on the hot path, with a minimal response body. This isolates the
#    per-request authentication/authorisation overhead.
# -----------------------------------------------------------------------------
SCENARIO_URL="${BASE_URL}/api/v1/auth/me"
SCENARIO_CONN="${CONNECTIONS}"
SCENARIO_RATE=""
run_scenario "GET /api/v1/auth/me — authenticated, session + authz overhead" \
    -H "Authorization: Bearer ${RB_LOAD_TEST_TOKEN}" \
    -H "Accept: application/json"

# -----------------------------------------------------------------------------
# 4. Project list — a realistic authorised collection read: authentication, then
#    the authorisation engine filtering rows, then serialisation.
# -----------------------------------------------------------------------------
SCENARIO_URL="${BASE_URL}/api/v1/projects"
SCENARIO_CONN="${CONNECTIONS}"
SCENARIO_RATE=""
run_scenario "GET /api/v1/projects — authorised collection read" \
    -H "Authorization: Bearer ${RB_LOAD_TEST_TOKEN}" \
    -H "Accept: application/json"

# -----------------------------------------------------------------------------
# 5. Task list — typically the largest and most-scoped collection in the system,
#    so it is the one most likely to expose a missing index or an N+1.
# -----------------------------------------------------------------------------
SCENARIO_URL="${BASE_URL}/api/v1/tasks"
SCENARIO_CONN="${CONNECTIONS}"
SCENARIO_RATE=""
run_scenario "GET /api/v1/tasks — authorised collection read (largest scope)" \
    -H "Authorization: Bearer ${RB_LOAD_TEST_TOKEN}" \
    -H "Accept: application/json"

# -----------------------------------------------------------------------------
# 6. Login — MEASURED SEPARATELY AND AT A DELIBERATELY LOW RATE.
#
#    WHY SEPARATE: login is dominated by Argon2id, which is memory-hard *by
#    design* — it is intentionally three to four orders of magnitude more
#    expensive than any other endpoint here. Mixing even a small share of logins
#    into the general run would drag the aggregate p95/p99 towards the Argon2id
#    cost and tell you nothing true about either population: the read endpoints
#    would look broken and the login cost would look diluted.
#
#    WHY LOW RATE: the server bounds password-hashing concurrency with a
#    semaphore precisely so a login flood cannot exhaust memory (recon R5).
#    Hammering it at full concurrency measures the queue in front of the hasher,
#    not the hasher — and trips the per-IP rate limiter, after which you are
#    benchmarking 429 responses.
# -----------------------------------------------------------------------------
if [ -n "${RB_LOAD_TEST_LOGIN_EMAIL:-}" ] && [ -n "${RB_LOAD_TEST_LOGIN_PASSWORD:-}" ]; then
    LOGIN_BODY="$(printf '{"email":"%s","password":"%s"}' \
                  "${RB_LOAD_TEST_LOGIN_EMAIL}" "${RB_LOAD_TEST_LOGIN_PASSWORD}")"
    SCENARIO_URL="${BASE_URL}/api/v1/auth/login"
    SCENARIO_CONN="${RB_LOAD_TEST_LOGIN_CONN:-4}"
    SCENARIO_RATE="${RB_LOAD_TEST_LOGIN_RATE:-5}/s"
    run_scenario "POST /api/v1/auth/login — Argon2id-bound, low rate, ISOLATED" \
        -m POST \
        -q "${RB_LOAD_TEST_LOGIN_RATE:-5}" \
        -T "application/json" \
        -d "${LOGIN_BODY}" \
        -H "Accept: application/json"
else
    say "SCENARIO: login — SKIPPED"
    printf '    RB_LOAD_TEST_LOGIN_EMAIL / RB_LOAD_TEST_LOGIN_PASSWORD are not set.\n'
    printf '    Set both to include the isolated Argon2id login scenario. Credentials are\n'
    printf '    never hard-coded in this script.\n'
fi

say "Load test finished."
printf '    Reminder: these percentiles characterise this host and this configuration\n'
printf '    only. Compare runs against each other, not against a target SLO taken from\n'
printf '    a different machine.\n'
