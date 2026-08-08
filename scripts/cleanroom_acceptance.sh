#!/usr/bin/env bash
# Clean-room acceptance walk (FINAL_ACCEPTANCE_REPORT §2, steps 1-16).
#
# Drives the running API over HTTP only — no test harness, no in-process router, no
# database fixtures. Everything it needs it creates through the public surface, in
# the order a real operator would. Run against a brand-new database provisioned and
# migrated from the committed SQL, with the production image.
#
# `req` sets the globals CODE and BODY rather than echoing, because a command
# substitution runs it in a subshell and any assignment inside would be discarded —
# which silently turned every body assertion into a no-op on the first attempt.
set -uo pipefail

API="${API:-http://rb-cleanroom-api:8080}"
BOOT="${BOOT:?bootstrap secret required}"
PW='correct horse battery staple 42'
FAILURES=0
CODE=""
BODY=""

say()  { printf '\n\033[1m== %s\033[0m\n' "$1"; }
pass() { printf '  PASS  %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; FAILURES=$((FAILURES+1)); }
check(){ if [ "$CODE" = "$1" ]; then pass "$2 ($CODE)"; else fail "$2 (expected $1, got $CODE) $BODY"; fi; }

# Flat string/boolean extraction. jq is not in the runner image and the audit path
# should not grow a dependency to read six fields.
jget() { sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p" <<<"$BODY" | head -1; }
jbool(){ sed -n "s/.*\"$1\":\(true\|false\).*/\1/p" <<<"$BODY" | head -1; }

req() {
  local m="$1" p="$2" t="${3:-}" b="${4:-}"
  local -a a=(-s -o /tmp/body -w '%{http_code}' -X "$m" "$API$p")
  [ -n "$t" ] && a+=(-H "Authorization: Bearer $t")
  [ -n "$b" ] && a+=(-H 'Content-Type: application/json' -d "$b")
  CODE=$(curl "${a[@]}")
  BODY=$(cat /tmp/body 2>/dev/null || printf '')
}

totp() { oathtool --totp -b "$1"; }

# Read the invitation token the way the mail provider would.
#
# `InvitationResponse` deliberately does NOT carry the token — handing the inviter
# their invitee's credential would be a design flaw, and it is correctly absent. The
# token exists only in the outbox payload destined for the mail provider. This audit
# therefore reads it from the outbox, standing in for the delivery that a production
# mail provider would perform.
#
# **This is itself an audit finding.** With no production mail provider implemented,
# there is no path by which a real invitee ever receives this token, so nobody can
# be onboarded in production today. Recorded in the acceptance report.
invite_token() {
  PGPASSWORD=cleanroom_super_pw psql -h rb-cleanroom-pg -U postgres -d roleblank -tAc \
    "SELECT substring(payload->>'invite_url' from 'token=([A-Za-z0-9_-]+)')
       FROM outbox_events
      WHERE event_type='mail.invitation' AND payload->>'to' = '$1'
      ORDER BY created_at DESC LIMIT 1" | tr -d '[:space:]'
}

say "STEP 4  Readiness before any data exists"
req GET /health/live;  check 200 "GET /health/live"
req GET /health/ready; check 200 "GET /health/ready"
for leak in postgres 5432 password migrator sqlx /work; do
  grep -qi "$leak" <<<"$BODY" && fail "readiness leaked '$leak'" || pass "readiness hides '$leak'"
done

say "STEP 5  Bootstrap reports uninitialised"
req GET /api/v1/bootstrap/status; check 200 "GET /api/v1/bootstrap/status"
[ "$(jbool initialized)" = false ] && pass "initialized=false" || fail "expected false: $BODY"
[ "${#BODY}" -lt 40 ] && pass "status body reveals only a boolean (${#BODY} bytes)" || fail "body too large: $BODY"

say "STEP 5  Create ROOT_OWNER"
req POST /api/v1/bootstrap/root '' "{\"bootstrap_secret\":\"$BOOT\",\"email\":\"owner@audit.test\",\"display_name\":\"System Owner\",\"password\":\"$PW\"}"
check 201 "POST /api/v1/bootstrap/root"
ROOT_ID=$(jget user_id); [ -n "$ROOT_ID" ] && pass "owner id $ROOT_ID" || fail "no user_id: $BODY"
grep -qi 'argon2\|"password"\|token_hash' <<<"$BODY" && fail "response leaked credential material" || pass "no credential material in response"

say "STEP 6  Second bootstrap must fail, permanently"
req POST /api/v1/bootstrap/root '' "{\"bootstrap_secret\":\"$BOOT\",\"email\":\"impostor@audit.test\",\"display_name\":\"Impostor\",\"password\":\"$PW\"}"
check 409 "second bootstrap refused"
grep -q SYSTEM_ALREADY_INITIALIZED <<<"$BODY" && pass "code SYSTEM_ALREADY_INITIALIZED" || fail "wrong code: $BODY"

say "STEP 7  ROOT MFA enrolment is mandatory and non-bypassable"
req POST /api/v1/auth/login '' "{\"email\":\"owner@audit.test\",\"password\":\"$PW\"}"
check 200 "login"
PENDING=$(jget access_token)
[ "$(jbool mfa_required)" = true ] && pass "mfa_required=true" || fail "owner not forced through MFA: $BODY"

req GET /api/v1/users "$PENDING";    check 403 "pending-MFA session refused on /users"
grep -q MFA_REQUIRED <<<"$BODY" && pass "code MFA_REQUIRED" || fail "wrong code: $BODY"
req GET /api/v1/projects "$PENDING"; check 403 "pending-MFA session refused on /projects"
req GET /api/v1/audit/events "$PENDING"; check 403 "pending-MFA session refused on /audit/events"

req POST /api/v1/auth/mfa/totp/setup "$PENDING" '{}'
{ [ "$CODE" = 200 ] || [ "$CODE" = 201 ]; } && pass "TOTP enrolment ($CODE)" || fail "enrolment failed ($CODE): $BODY"
SECRET=$(jget secret); [ -n "$SECRET" ] && pass "secret issued once" || fail "no secret: $BODY"

req POST /api/v1/auth/mfa/totp/activate "$PENDING" "{\"code\":\"$(totp "$SECRET")\"}"
{ [ "$CODE" = 200 ] || [ "$CODE" = 201 ]; } && pass "TOTP activated ($CODE)" || fail "activation failed ($CODE): $BODY"
grep -q recovery_codes <<<"$BODY" && pass "recovery codes issued" || fail "no recovery codes: $BODY"

say "STEP 8  ROOT full login"
req POST /api/v1/auth/login '' "{\"email\":\"owner@audit.test\",\"password\":\"$PW\"}"
P2=$(jget access_token)
# Replay protection is real: activation consumed the current TOTP counter, so the
# next verification must use a later step — exactly what a human does when they wait
# for the code to roll over.
sleep 31
req POST /api/v1/auth/mfa/verify "$P2" "{\"code\":\"$(totp "$SECRET")\"}"
check 200 "MFA verify with the next code"
ROOT=$(jget access_token); [ -z "$ROOT" ] && ROOT="$P2"
req GET /api/v1/auth/me "$ROOT"; check 200 "GET /auth/me"
[ "$(jbool is_root)" = true ]      && pass "is_root=true"       || fail "not root: $BODY"
[ "$(jbool mfa_pending)" = false ] && pass "mfa_pending=false"  || fail "still pending: $BODY"

say "STEP 9  Department + administrator"
req POST /api/v1/departments "$ROOT" '{"code":"eng","name":"Engineering"}'; check 201 "create department"
DEPT=$(jget id)

ADMIN_ROLE='00000000-0000-7000-8000-000000000001'
req POST /api/v1/invitations "$ROOT" "{\"email\":\"admin@audit.test\",\"display_name\":\"Admin\",\"principal_type\":\"INTERNAL\",\"role_ids\":[\"$ADMIN_ROLE\"],\"department_id\":null,\"client_account_id\":null}"
check 201 "invite administrator"
T=$(invite_token admin@audit.test)
req POST /api/v1/invitations/accept '' "{\"token\":\"$T\",\"password\":\"$PW\"}"; check 201 "accept administrator invitation"
req POST /api/v1/auth/login '' "{\"email\":\"admin@audit.test\",\"password\":\"$PW\"}"; check 200 "administrator login"
ADMIN=$(jget access_token)

say "STEP 10  Restricted employee"
req POST /api/v1/invitations "$ROOT" "{\"email\":\"emp@audit.test\",\"display_name\":\"Employee\",\"principal_type\":\"INTERNAL\",\"role_ids\":[],\"department_id\":\"$DEPT\",\"client_account_id\":null}"
check 201 "invite employee"
T=$(invite_token emp@audit.test)
req POST /api/v1/invitations/accept '' "{\"token\":\"$T\",\"password\":\"$PW\"}"; check 201 "accept employee invitation"
req POST /api/v1/auth/login '' "{\"email\":\"emp@audit.test\",\"password\":\"$PW\"}"; check 200 "employee login"
EMP=$(jget access_token)
req GET /api/v1/audit/events "$EMP"; check 403 "employee refused on audit"
req POST /api/v1/departments "$EMP" '{"code":"rogue","name":"Rogue"}'; check 403 "employee refused creating a department"

say "STEP 11-12  Client accounts A and B, each with an activated user"
req POST /api/v1/clients "$ROOT" '{"code":"client-a","name":"Client A"}'; check 201 "create client A"; CA=$(jget id)
req POST /api/v1/clients "$ROOT" '{"code":"client-b","name":"Client B"}'; check 201 "create client B"; CB=$(jget id)

CLIENT_USER_ROLE='00000000-0000-7000-8000-000000000003'
CLIENT_TOKEN=""
mkclient() {
  local acct="$1" mail="$2" uid t
  # The `client_user` role must be granted explicitly. An earlier version of this
  # walk sent `role_ids: []` and then reported the portal as broken — it was not:
  # an account with no roles holds no permissions, and the portal correctly refused
  # it. Least privilege by default, working as designed.
  req POST /api/v1/invitations "$ROOT" "{\"email\":\"$mail\",\"display_name\":\"Client User\",\"principal_type\":\"CLIENT\",\"role_ids\":[\"$CLIENT_USER_ROLE\"],\"department_id\":null,\"client_account_id\":\"$acct\"}"
  [ "$CODE" = 201 ] || { fail "invite $mail ($CODE): $BODY"; return 1; }
  t=$(invite_token "$mail")
  [ -n "$t" ] || { fail "no invitation token reached the outbox for $mail"; return 1; }
  req POST /api/v1/invitations/accept '' "{\"token\":\"$t\",\"password\":\"$PW\"}"
  [ "$CODE" = 201 ] || { fail "accept $mail ($CODE): $BODY"; return 1; }
  uid=$(jget user_id)
  # Accepting a CLIENT invitation that names a client account creates the
  # membership ACTIVE already — the internal principal made the linkage decision
  # when they issued the invitation. Adding it again is therefore a 409, and that
  # is correct. Self-registration is the path that lands in PENDING.
  req POST "/api/v1/clients/$acct/members" "$ROOT" "{\"user_id\":\"$uid\"}"
  case "$CODE" in
    200|201) pass "membership created for $mail" ;;
    409)     pass "membership already ACTIVE from the invitation ($mail)" ;;
    *)       fail "add member $mail ($CODE): $BODY" ;;
  esac
  req POST /api/v1/auth/login '' "{\"email\":\"$mail\",\"password\":\"$PW\"}"
  [ "$CODE" = 200 ] || { fail "login $mail ($CODE): $BODY"; return 1; }
  CLIENT_TOKEN=$(jget access_token)
}
mkclient "$CA" clienta@audit.test && CA_TOK="$CLIENT_TOKEN" && pass "client A user authenticated"
mkclient "$CB" clientb@audit.test && CB_TOK="$CLIENT_TOKEN" && pass "client B user authenticated"
CA_TOK="${CA_TOK:-}"; CB_TOK="${CB_TOK:-}"

say "STEP 13  Internal project, shared with nobody"
req POST /api/v1/projects "$ROOT" "{\"code\":\"apollo\",\"name\":\"Apollo\",\"manager_user_id\":\"$ROOT_ID\"}"
check 201 "create project"; PROJ=$(jget id)

say "STEP 14  Neither client may discover it before sharing"
req GET "/api/v1/client-portal/projects/$PROJ" "$CA_TOK"; check 404 "client A cannot see unshared project"
req GET "/api/v1/client-portal/projects/$PROJ" "$CB_TOK"; check 404 "client B cannot see unshared project"
req GET "/api/v1/projects/$PROJ" "$CA_TOK";               check 404 "client A gets 404 (not 403) on the internal route"

say "STEP 14  Share with client A only"
req POST "/api/v1/projects/$PROJ/clients" "$ROOT" "{\"client_account_id\":\"$CA\"}"
# 204 is the documented success for this route — it creates a link and returns no
# representation.
case "$CODE" in
  200|201|204) pass "shared with A ($CODE)" ;;
  *)           fail "share failed ($CODE): $BODY" ;;
esac

say "STEP 15  Client A reads the client projection"
req GET "/api/v1/client-portal/projects/$PROJ" "$CA_TOK"; check 200 "client A reads shared project"
for f in internal_note created_by manager_user_id department_id; do
  grep -q "\"$f\"" <<<"$BODY" && fail "client projection leaked $f" || pass "client projection omits $f"
done

say "STEP 16  Client B cannot discover or access it"
req GET "/api/v1/client-portal/projects/$PROJ" "$CB_TOK"; check 404 "client B refused the shared project"
req GET /api/v1/client-portal/projects "$CB_TOK"
grep -q "$PROJ" <<<"$BODY" && fail "client B's list contains A's project" || pass "client B's list excludes it"
req GET /api/v1/client-portal/projects "$CA_TOK"
grep -q "$PROJ" <<<"$BODY" && pass "client A's list contains it" || fail "client A's list is missing it: $BODY"

say "STEP 16  Client A cannot reach any internal surface"
for p in /api/v1/users /api/v1/audit/events /api/v1/roles /api/v1/permissions /api/v1/clients /api/v1/departments /api/v1/tasks /api/v1/projects /api/v1/settings /api/v1/invitations; do
  req GET "$p" "$CA_TOK"; check 404 "client A refused $p"
done

# Hand live session tokens to phase 2. The restart is performed by the host, so it
# is a genuine process restart rather than something this script could fake.
if [ -d /state ]; then
  cat > /state/tokens.env <<EOF
export ROOT='$ROOT'
export ROOT_ID='$ROOT_ID'
export ADMIN='$ADMIN'
export EMP='$EMP'
export CA_TOK='$CA_TOK'
export CB_TOK='$CB_TOK'
export PROJ='$PROJ'
export CA='$CA'
export CB='$CB'
export DEPT='$DEPT'
export SECRET='$SECRET'
EOF
  pass "session state handed to phase 2"
fi

printf '\n\033[1m==== clean-room phase 1: %s failure(s) ====\033[0m\n' "$FAILURES"
exit $((FAILURES > 0))
