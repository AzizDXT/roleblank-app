# Backend closure report

The final engineering gate before frontend implementation. Every result below was
produced by a command run against this tree during closure. Nothing is carried
forward from the previous acceptance report; where that report disagreed with the
code, the code won and the disagreement is recorded.

---

## 1. Starting state

Branch `audit/final-acceptance`, commit `2363a9e`, working tree clean, 10
migrations. The previous phase reported 1 009 tests passing, 93.66% line coverage,
all gates green, and **one open MEDIUM**: the general rate limiter.

Those numbers were treated as claims and re-derived. Full baseline:
`CLOSURE_BASELINE.md`.

## 2. Open findings found

### The MEDIUM, reproduced before anything was changed

Confirmed at source — `middleware::apply` installed seven layers and no rate
limiter; `keys::general_principal` and `keys::general_ip` existed and were called
from exactly one place in the crate, a unit test.

Confirmed by execution, 60 requests per principal against a live instance:

| Principal | Endpoint | Status | `429`s | Audit rows |
|---|---|---|---|---|
| employee | `POST /projects/{id}/clients` | `403` | **0** | **60** |
| client | `GET /users` | `404` | **0** | 0 |
| administrator | `GET /projects` | `403` | **0** | 0 |
| ROOT | `GET /projects` | `200` | **0** | 0 |

The baseline sharpened the finding in two ways the earlier report had not. First,
**no** authenticated principal was bounded, including ROOT. Second, the audit
amplification is specific to the paths that deliberately *commit* a denial record:
refusals masked to `404` write nothing, so an attacker preferring stealth was
equally unlimited **and** left no evidence. The rate-limit gap was therefore
strictly broader than the audit-growth gap, and the two needed separate fixes.

### Everything else

Six LOW and thirteen INFO items inherited, plus four issues found during closure by
regenerating the route matrix against current code.

## 3. Changes made

| Area | Change |
|---|---|
| Rate limiting | Three-class layered limiter (below), 17 tests, `RATE_LIMIT_ARCHITECTURE.md` |
| Rate-limit config | All eleven limits now read from the environment; a quota of `0` is refused rather than read as "unlimited" |
| Observability | Metrics layer installed — `/metrics` promised request volumes and error rates and recorded neither; two series were being written in the entire process |
| Mail | `SmtpProvider` (SMTP over TLS, `lettre`), production refuses `disabled` without an explicit acknowledgement, and refuses a half-configured transport |
| `GET /system/info` | Feature-flag list no longer crosses the client envelope |
| `POST /auth/logout` | Route table corrected to `MfaPending`, matching the handler |
| OpenAPI | New test holds the JSON artifact and the YAML source in agreement |
| 14 LOW/INFO fixes | See `audit/LOW_INFO_DISPOSITION.md` |
| Schema | `0011_envelope_and_consumption_guards.sql` — principal-type envelope re-check, single-use token consumption guards |

## 4. Rate limiting architecture

Full document: `RATE_LIMIT_ARCHITECTURE.md`. In brief:

1. **Anonymous operation budgets** — unchanged, per-operation, deliberately
   separate. Merging them has already caused one real bug (invitation acceptance
   sharing the registration bucket, capping onboarding at three people per hour per
   office).
2. **General authenticated budget** — the main control, charged in the principal
   extractors, **keyed on the user id**. Keyed on the address, an office behind one
   NAT would share a budget; keyed on the session, a stolen credential would
   multiply its budget by logging in again. Both directions are pinned by tests.
3. **Pre-authentication address ceiling** — coarse and generous, bounding the
   database round trip that resolving *any* bearer token costs, genuine or not.

ROOT is not exempt, only larger, and no lockout is possible: buckets refill
continuously and the authenticated budget is keyed on the user, so an external
attacker cannot spend the owner's budget without the owner's token.

**One ordering bug was found by the live reproduction and not by the tests.** The
budget was originally charged *after* the MFA gate, so a session that had proved a
password but not a second factor was refused before reaching the limiter and could
repeat the request for free. The administrator row showed `429=0` where every other
principal was bounded. The charge now precedes the gate; pinned by
`a_session_pending_mfa_is_charged_the_general_budget`.

### Result, same reproduction, after the fix

| Principal | Before | After |
|---|---|---|
| employee | `403`×60, 0 × `429`, **60 audit rows** | `403`×20, `429`×40, **20 audit rows** |
| client (`/users`) | `404`×60, 0 × `429` | `404`×20, `429`×40 |
| administrator | `403`×60, 0 × `429` | `403`×20, `429`×40 |
| ROOT | `200`×60, 0 × `429` | `200`×40, `429`×20 (its larger budget) |

Audit growth is bounded exactly at the quota. Authorisation is unchanged: every
request that was refused before is still refused, for the same reason.

## 5. Security findings closed

| Severity | Open at freeze |
|---|---|
| CRITICAL | **0** |
| HIGH | **0** |
| MEDIUM | **0** |
| LOW | **0 actionable** |

The MEDIUM is closed. The 14 LOW/INFO fixes each carry a regression test that was
**observed failing without the fix** — verified in two batches, ten of ten.

One item was **reclassified upward**: `audit_events.source_ip_hint` was rated INFO,
but the audit chain's claim is written against an adversary holding the database,
and against exactly that adversary every source IP could be rewritten while
verification still reported the chain intact. Origin is what an intruder most wants
to change in a log they cannot delete. A gap inside the stated claim of the
flagship integrity control is not INFO. Fixed with a versioned chain layout: legacy
rows verify under the layout they were written with, new rows are v2, and the
version marker is itself inside the v2 digest so a row cannot be relabelled to
escape to the weaker layout.

## 6. LOW / INFO disposition

14 fixed, 7 accepted, 1 reclassified then fixed. Full table with reasoning:
`audit/LOW_INFO_DISPOSITION.md`.

The accepted items are all INFO and all documentation or unused-code observations,
with two worth naming because they carry real cost: `AppState::not_found_or_denied`
is a second implementation of a security rule already expressed by
`AppError::hide_from_external`, and `evaluator::holds_any`'s docstring misdescribes
how `/auth/me` works.

## 7. Test inventory and coverage

| Suite | Tests |
|---|---|
| unit (`src/lib.rs`) | 601 |
| `security_suite` | 159 |
| `integration_suite` | 155 |
| `race_suite` | 58 |
| `hardening_suite` | 34 |
| `rate_limit_suite` | **17 (new)** |
| `failure_injection` | 10 |
| `openapi_contract` | 6 |
| `router_registry` | 5 |
| `golden_scenario` | 1 |
| `benchmarks` | 4 (ignored by default; run separately, 4/4) |

**Total: 1 046 passed, 0 failed.**

Coverage: **91.16% region, 92.95% function, 93.34% line** (32 280 regions). Very
slightly below the pre-closure figure, which is expected and honest rather than a
regression: closure added production code — an SMTP transport whose delivery path
cannot be exercised without a real mail server, and error branches in the new
configuration parsing — faster than it added tests for lines that are only reachable
against live infrastructure.

## 8. Clean-room result

Fresh PostgreSQL database, fresh secrets, fresh runtime role, no seed data,
migrations applied as the **migrator** role and the API run as the **runtime** role.

* Phase 1 — 16-step walk over HTTP only: **0 failures**
* Phase 2 — after a full backend restart, driven with phase 1's tokens: **0 failures**
* Phase 3 — PostgreSQL stopped underneath the running backend, then restarted:
  **0 failures**

Phase 3 is new at closure and checks the distinction the system draws under
dependency failure: liveness stayed `200` (killing the API would not fix a database
outage), readiness went `503`, a database-backed request returned `503` rather than
`500`, the problem+json contract held, and `registration/config` **failed closed** —
`200` reporting signup unavailable, so an outage cannot become an accidental way to
open registration. On recovery, readiness returned without restarting the backend.

## 9. ROOT result

Re-verified on the restored database at closure: a second ownership row, an
`UPDATE`, and a `DELETE` are each refused by trigger; exactly one row remains; the
runtime role cannot delete audit history. Both invitation-placement exploit
reproducers remain blocked (`403` at the placement).

## 10. Client isolation result

Covered by `security_suite` (159) and the clean-room walk: client A cannot reach
client B's project, membership, or any internal surface; the feature-flag list no
longer crosses the envelope; a throttled response reveals nothing a normal refusal
would not.

## 11. Privilege escalation result

`escalation_matrix` and the two exploit scripts. Delegation, DENY escape,
self-promotion, role composition, principal-type conversion, and proxy escalation
through department and client placement all remain refused.

## 12. Authentication result

`auth_attacks` plus the race suite: wrong password, unknown identity, MFA failure,
TOTP replay, recovery-code reuse, refresh rotation and reuse, concurrent refresh,
session revocation. The keystone property — **a permission change takes effect on
the very next request, without waiting for token expiry** — is pinned by a test
that drives six privilege transitions through one token.

## 13. Runtime database privilege result

Verified directly against the live instance as `roleblank_app`.

**Can:** read every table it needs, insert audit rows, `setval` the audit sequence.

**Cannot:** `ALTER`, `DROP`, disable triggers, change ownership, edit
`_sqlx_migrations`, `UPDATE`/`DELETE`/`TRUNCATE` audit history, touch
`system_ownership`, or create a role. `rolsuper` is `false`.

This is the check that caught the two HIGH defects in the previous phase, and it is
run as a matter of routine now rather than as an afterthought.

## 14. Audit result

`verify-audit` on the restored database: **chain INTACT, 29 entries, head at seq
29**. The chain now covers `source_ip_hint` under a versioned layout. Tamper
detection is proven positively elsewhere (`HASH_MISMATCH`, `MISSING_SEQUENCE`,
`HEAD_MISMATCH` for four distinct mutations).

## 15. Backup / restore result

Using verified steps with an explicit size assertion **before** the destructive
step — the previous phase lost a clean-room to an ad-hoc command whose `pg_dump`
silently wrote nothing.

Dump 147 798 bytes → `DROP DATABASE` (existence confirmed `0`) → restore from the
**host** copy → `pg_restore` exit 0, **0 warnings** → state **byte-identical**
including the audit chain head hash → 28 triggers, 115 checks, 52 foreign keys
restored → backend booted against the restored database and reached readiness →
chain verified.

## 16. Test-harness result

Two suites run **simultaneously** against one PostgreSQL: **314 tests, 0 failures**,
no template destruction. The same experiment before the harness fix produced 65
fabricated failures, and once produced a suite reporting an entire file as failed
having executed zero assertions.

Remaining harness limitation: test databases leak (detached cleanup thread dies with
the process). Bounded per run; 82 present after several full runs, against 493
accumulated before.

## 17. Performance regression result

Release build, container, shared 24-core host. Nothing was tuned to produce a
better number.

| Endpoint | p50 | p95 | p99 | 5xx |
|---|---|---|---|---|
| `GET /health/ready` | 1.0 ms | 1.4 ms | 1.6 ms | 0 |
| `GET /api/v1/auth/me` | 3.8 ms | 4.5 ms | 5.4 ms | 0 |
| `GET /api/v1/projects` | 3.9 ms | 4.5 ms | 4.9 ms | 0 |
| `GET /api/v1/tasks` | 4.0 ms | 4.6 ms | 5.6 ms | 0 |
| denied endpoint (`403` + committed audit row) | 7.2 ms | 10.7 ms | 12.2 ms | 0 |

Against the pre-closure baseline (`auth/me` 2.6 ms p50, `projects` 3.2 ms,
`tasks` 5.3 ms), the limiter and metrics layers cost on the order of **one
millisecond or less**, and p95 on the list endpoints improved — the earlier
measurement was noisier. No unacceptable regression.

CPU-bound primitives are unchanged: authorisation `evaluate` 28 ns, audit
`entry_hash` 518 ns, AEAD seal 1.36 µs, TOTP verify 479 ns.

## 18. OpenAPI state

95 operations in both artifacts, matching the 95 routes in `ROUTE_TABLE`. Held in
agreement by six contract tests, one of them new at closure and specifically
comparing the JSON artifact against the YAML source, because only the YAML was
previously validated and the JSON is what a frontend generates from.

Hashes are recorded in `BACKEND_FREEZE_MANIFEST.md`.

## 19. Frontend contract state

Eight documents, all generated by reading current code:

`ROUTE_SECURITY_MATRIX.md` (95 routes, 14 columns) · `FRONTEND_ERROR_CONTRACT.md` ·
`FRONTEND_CAPABILITY_CONTRACT.md` · `PERMISSION_CATALOG.md` (42) ·
`REGISTRATION_CONTRACT.md` · `CONCURRENCY_CONTRACT.md` · `IDEMPOTENCY_CONTRACT.md` ·
`FRONTEND_ACTION_CATALOG.md` (92 actions).

Three routes were flagged as having an unclear posture; two are now fixed
(`/auth/logout`, `/system/info`) and the third is a documented divergence between
where step-up is declared and where it is enforced — the enforcement is correct, the
two sources of truth simply explain it differently.

## 20. Remaining limitations

Listed in full in `BACKEND_FREEZE_MANIFEST.md`. The three that matter most:

1. **Rate limiting is single-instance.** More than one API process requires a
   distributed `RateLimiter` first.
2. **SMTP has never been exercised against a real mail server.** Configuration,
   TLS mode selection and refusal behaviour are tested; delivery is not.
3. **A PostgreSQL superuser is outside the model** and always was.

## 21. Freeze commit

Recorded at commit time; see the terminal summary and `git log`.

## 22. Verdict

Applied against §37: 0 CRITICAL, 0 HIGH, 0 MEDIUM, 0 unresolved actionable LOW;
1 046 tests passing; clean-room green across three phases; rate limiting fixed and
proven by before/after measurement; runtime database role proven; ROOT proven
immutable through restore; client isolation proven; OpenAPI current and
cross-checked; frontend contracts generated; reports updated; tree clean after the
final commit.

**BACKEND FOUNDATION CLOSED — FRONTEND CONTRACT FROZEN**
