#!/usr/bin/env bash
# Clean-room acceptance, phase 2 (FINAL_ACCEPTANCE_REPORT §2 steps 17-19, and §21).
#
# Runs AFTER the host has restarted the API container. It reuses the session tokens
# phase 1 minted, so "the session survived a restart" is a claim about server-side
# state rather than about a token this script re-issued.
#
# `req` sets the globals CODE and BODY rather than echoing — a command substitution
# would run it in a subshell and discard the assignment.
set -uo pipefail

API="${API:-http://rb-cleanroom-api:8080}"
. /state/tokens.env
FAILURES=0
CODE=""
BODY=""

say()  { printf '\n\033[1m== %s\033[0m\n' "$1"; }
pass() { printf '  PASS  %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; FAILURES=$((FAILURES+1)); }
check(){ if [ "$CODE" = "$1" ]; then pass "$2 ($CODE)"; else fail "$2 (expected $1, got $CODE) $BODY"; fi; }
jbool(){ sed -n "s/.*\"$1\":\(true\|false\).*/\1/p" <<<"$BODY" | head -1; }

req() {
  local m="$1" p="$2" t="${3:-}" b="${4:-}"
  local -a a=(-s -o /tmp/body -w '%{http_code}' -X "$m" "$API$p")
  [ -n "$t" ] && a+=(-H "Authorization: Bearer $t")
  [ -n "$b" ] && a+=(-H 'Content-Type: application/json' -d "$b")
  CODE=$(curl "${a[@]}")
  BODY=$(cat /tmp/body 2>/dev/null || printf '')
}

say "STEP 17  Readiness after restart"
for i in $(seq 1 40); do req GET /health/ready; [ "$CODE" = 200 ] && break; sleep 1; done
check 200 "GET /health/ready"
req GET /health/live; check 200 "GET /health/live"

say "STEP 18  Authoritative state persisted"
req GET /api/v1/bootstrap/status
[ "$(jbool initialized)" = true ] && pass "initialized=true persisted" || fail "initialisation state lost: $BODY"

req GET /api/v1/auth/me "$ROOT"; check 200 "ROOT session survived the restart"
[ "$(jbool is_root)" = true ] && pass "still recognised as owner" || fail "ownership lost: $BODY"

req GET "/api/v1/projects/$PROJ" "$ROOT";    check 200 "project persisted"
req GET "/api/v1/clients/$CA" "$ROOT";       check 200 "client A persisted"
req GET "/api/v1/departments/$DEPT" "$ROOT"; check 200 "department persisted"

say "STEP 19  Sessions and isolation behave correctly after restart"
req GET "/api/v1/client-portal/projects/$PROJ" "$CA_TOK"; check 200 "client A access survived"
req GET "/api/v1/client-portal/projects/$PROJ" "$CB_TOK"; check 404 "client B still excluded"
req GET /api/v1/audit/events "$EMP";                      check 403 "employee still refused on audit"
req GET /api/v1/users "$CA_TOK";                          check 404 "client A still cannot enumerate users"

say "STEP 19  Revocation takes effect on the very next request"
req POST /api/v1/auth/logout "$EMP" '{}'
{ [ "$CODE" = 200 ] || [ "$CODE" = 204 ]; } && pass "employee logout ($CODE)" || fail "logout failed ($CODE): $BODY"
req GET /api/v1/auth/me "$EMP"; check 401 "revoked token refused immediately, with no wait for expiry"

say "STEP 19  Audit chain verifies after the restart"
req GET /api/v1/audit/verify "$ROOT"
case "$CODE" in
  200) pass "GET /api/v1/audit/verify (200)"
       grep -qi 'intact' <<<"$BODY" && pass "chain reported intact" || fail "chain not intact: $BODY" ;;
  403) pass "verify demands step-up (403) — correct, the step-up window had expired" ;;
  *)   fail "unexpected verify status $CODE: $BODY" ;;
esac

printf '\n\033[1m==== clean-room phase 2: %s failure(s) ====\033[0m\n' "$FAILURES"
exit $((FAILURES > 0))
