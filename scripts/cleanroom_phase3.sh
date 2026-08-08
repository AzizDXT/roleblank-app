#!/usr/bin/env bash
# Clean-room acceptance, phase 3 — database outage and recovery (closure §15 steps
# 29–30).
#
# Phase 2 proves the backend survives its own restart. This proves the harder case:
# the database goes away underneath a running backend, and comes back.
#
# What is being checked is the *distinction* the system draws. A backend that
# cannot reach its database is not broken and its requests are not malformed —
# it is temporarily unable to serve. Answering `500` there tells a client to give
# up and an operator to go looking for an application bug; `503` tells both the
# truth. Liveness must stay up throughout, because killing and rescheduling the
# API would not fix a database outage.
#
# The host stops and starts PostgreSQL around this script; here we only observe.
set -uo pipefail

API="${API:-http://rb-cleanroom-api:8080}"
PHASE="${PHASE:-during}"
FAILURES=0

pass() { printf '  PASS  %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; FAILURES=$((FAILURES+1)); }

code() { curl -s -o /tmp/b -w '%{http_code}' "$@"; }
body() { cat /tmp/b 2>/dev/null || printf ''; }

case "$PHASE" in
during)
  printf '\n\033[1m== PHASE 3a  PostgreSQL is DOWN ==\033[0m\n'

  c=$(code "$API/health/live")
  [ "$c" = 200 ] && pass "liveness still 200 — the process is healthy, its dependency is not" \
                 || fail "liveness returned $c; a restart would not fix a database outage"

  c=$(code "$API/health/ready")
  [ "$c" = 503 ] && pass "readiness 503 — correctly withdrawn from the load balancer" \
                 || fail "readiness returned $c, expected 503"

  # A request that genuinely needs the database must be 503 (retry me), never 500
  # (I am broken). `bootstrap/status` reads a row and cannot answer without one.
  c=$(code "$API/api/v1/bootstrap/status")
  case "$c" in
    503) pass "a database-backed request returns 503, not 500" ;;
    500) fail "a database-backed request returned 500 — a client is told to give up on a transient outage" ;;
    *)   fail "a database-backed request returned an unexpected $c: $(body | head -c 160)" ;;
  esac

  headers=$(curl -s -D - -o /dev/null "$API/api/v1/bootstrap/status")
  if grep -qi 'application/problem+json' <<<"$headers"; then
    pass "the outage response still honours the problem+json contract"
  else
    fail "the outage response broke the error contract"
  fi

  # Not everything should fail. `registration/config` deliberately fails *closed*:
  # it cannot read the mode, so it reports signup unavailable rather than erroring.
  # An outage must not become an accidental way to open registration.
  c=$(code "$API/api/v1/registration/config")
  if [ "$c" = 200 ] && grep -q '"registration_available":false' <<<"$(body)"; then
    pass "registration config fails closed (200, signup reported unavailable)"
  else
    fail "registration config did not fail closed: $c $(body | head -c 120)"
  fi
  ;;

after)
  printf '\n\033[1m== PHASE 3b  PostgreSQL is BACK ==\033[0m\n'

  # The pool must reconnect on its own. Needing a restart to recover from a blip is
  # an availability defect, not a database one.
  ready=0
  for _ in $(seq 1 60); do
    [ "$(code "$API/health/ready")" = 200 ] && { ready=1; break; }
    sleep 1
  done
  [ "$ready" = 1 ] && pass "readiness recovered without restarting the backend" \
                   || fail "readiness never recovered; the pool did not reconnect"

  c=$(code "$API/api/v1/registration/config")
  [ "$c" = 200 ] && pass "data requests serve again ($c)" || fail "data requests still failing ($c)"
  ;;
esac

printf '\n\033[1m==== clean-room phase 3 (%s): %s failure(s) ====\033[0m\n' "$PHASE" "$FAILURES"
exit $((FAILURES > 0))
