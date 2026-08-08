#!/usr/bin/env bash
# Reproducer for the general-rate-limit finding (CLOSURE §3, §8).
#
# The claim under test: no general limiter is applied to authenticated API
# requests, so any authenticated principal — regardless of how little authority it
# holds — can drive unbounded growth of an append-only table by repeatedly calling
# an endpoint it is not allowed to use. Each refusal is correctly denied *and*
# deliberately committed as an audit row, and every audit append takes the global
# chain lock that every legitimate mutation also needs.
#
# Run before and after the fix. Before: no 429 anywhere, audit grows 1:1 with
# requests. After: requests bounded, audit growth bounded, authorisation unchanged.
#
# `req` sets globals rather than echoing — a command substitution would run it in a
# subshell and discard the assignment.
set -uo pipefail

API="${API:-http://rb-cleanroom-api:8080}"
N="${N:-60}"
. /state/tokens.env
ROOT_PW='correct horse battery staple 42'
PW='correct horse battery staple 42'

login() {
  curl -s -X POST "$API/api/v1/auth/login" -H 'Content-Type: application/json' \
    -d "{\"email\":\"$1\",\"password\":\"$PW\"}" |
    sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p'
}

totp() { oathtool --totp -b "$1"; }

# ROOT needs a full MFA session; the step-up window from phase 1 has long closed.
fresh_root() {
  local pending full
  pending=$(curl -s -X POST "$API/api/v1/auth/login" -H 'Content-Type: application/json' \
    -d "{\"email\":\"owner@audit.test\",\"password\":\"$ROOT_PW\"}" |
    sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
  sleep 31
  full=$(curl -s -X POST "$API/api/v1/auth/mfa/verify" -H 'Content-Type: application/json' \
    -H "Authorization: Bearer $pending" -d "{\"code\":\"$(totp "$SECRET")\"}" |
    sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
  [ -n "$full" ] && printf '%s' "$full" || printf '%s' "$pending"
}

audit_count() {
  PGPASSWORD=cleanroom_super_pw psql -h rb-cleanroom-pg -U postgres -d roleblank -tAc \
    'SELECT count(*) FROM audit_events' | tr -d '[:space:]'
}

# Hammer one endpoint the principal is not allowed to use, and report the shape of
# the answer plus what it cost the system.
hammer() {
  local label="$1" token="$2" method="$3" path="$4" body="${5:-}"
  local before after codes=""
  before=$(audit_count)
  local start=$SECONDS
  for _ in $(seq 1 "$N"); do
    local -a a=(-s -o /dev/null -w '%{http_code}' -X "$method" "$API$path"
                -H "Authorization: Bearer $token")
    [ -n "$body" ] && a+=(-H 'Content-Type: application/json' -d "$body")
    codes="$codes $(curl "${a[@]}")"
  done
  local elapsed=$((SECONDS - start))
  after=$(audit_count)
  local n429 distinct
  n429=$(printf '%s' "$codes" | tr ' ' '\n' | grep -c '^429$')
  distinct=$(printf '%s' "$codes" | tr ' ' '\n' | grep -v '^$' | sort -u | tr '\n' ',' | sed 's/,$//')
  printf '  %-26s reqs=%-4s codes=%-16s 429=%-4s audit_delta=%-5s %ss\n' \
    "$label" "$N" "$distinct" "$n429" "$((after - before))" "$elapsed"
}

printf '\n\033[1m== Reproducer: general authenticated rate limiting ==\033[0m\n'
printf 'N=%s requests per principal, each to an endpoint that principal may not use.\n\n' "$N"

EMP_T=$(login emp@audit.test)
CA_T=$(login clienta@audit.test)
ADMIN_T=$(login admin@audit.test)
ROOT_T=$(fresh_root)

for name in EMP_T CA_T ADMIN_T ROOT_T; do
  [ -n "${!name}" ] || { printf '  SETUP FAIL: no token for %s\n' "$name"; exit 1; }
done
printf 'tokens acquired: employee, client A, administrator, ROOT\n\n'

# The employee case is the original finding: a committed AUTHORIZATION.DENIED row
# per request, on a table with no delete path.
hammer "employee -> share client" "$EMP_T" POST "/api/v1/projects/$PROJ/clients" \
  "{\"client_account_id\":\"$CA\"}"
hammer "client A -> users list"   "$CA_T"  GET  "/api/v1/users"
hammer "client A -> audit events" "$CA_T"  GET  "/api/v1/audit/events"
hammer "admin -> read-only load"  "$ADMIN_T" GET "/api/v1/projects"
hammer "ROOT  -> read-only load"  "$ROOT_T"  GET "/api/v1/projects"

printf '\nInterpretation:\n'
printf '  429=0 across the board            -> no general limiter is applied.\n'
printf '  audit_delta ~= reqs on a denial   -> attacker-controlled append-only growth.\n'
printf '  audit_delta ~= 0 on a read        -> reads are not the amplifier; denials are.\n'
