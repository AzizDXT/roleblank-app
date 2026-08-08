# RoleBlank OS — Final Backend Acceptance & Adversarial Audit

**Scope:** the backend foundation as it stands in the working tree at audit time.
No new features were added. No frontend work was started. Nothing was pushed.

**Standard of proof used throughout:** a result is recorded as **PASS** only if it
was produced by a command that actually ran during this audit. Claims carried over
from earlier development were re-derived from scratch or marked **BLOCKED**.
`PASS` / `FAIL` / `BLOCKED` / `NOT_APPLICABLE` are used literally.

**What this report does not claim.** Not "production secure", not "unhackable", not
"fully OWASP compliant", not "zero vulnerabilities". It reports what was executed,
what was observed, and what remains open.

---

## 1. The single most important result

Three independent rounds of adversarial testing during this audit each found real
defects that a **green test suite had not**. At the start of the audit the suite
reported 622 passing tests and zero failures. That suite could not boot the
application against a correctly provisioned database, because every test connected
as the schema owner rather than as the runtime role the product actually uses.

> A green suite describes the tests, not the system.

Seven HIGH-severity defects were found. Every one of them was invisible to a suite
that reported success.

---

## 2. Severity summary

| Severity | Found | Fixed | Open |
|---|---|---|---|
| CRITICAL | 0 | 0 | **0** |
| HIGH | 7 | 7 | **0** |
| MEDIUM | 5 | 4 | 1 |
| LOW | 8 | 2 | 6 |
| INFO | 13 | 0 | 13 |

The severity gate for this audit is: *any remaining CRITICAL or HIGH forces
NOT READY.* Open CRITICAL/HIGH count is **0**.

### The seven HIGH findings

| # | Finding | Why it mattered | State |
|---|---|---|---|
| H1 | Runtime role had no `SELECT` on `permissions` | The application **could not start** against a correctly provisioned database | Fixed |
| H2 | `setval()` requires `UPDATE` on the sequence, which `USAGE` does not imply | **Every audited mutation** — i.e. every write — returned `500` | Fixed |
| H3 | Invitation placement was never authorised | Privilege **escalation by proxy**, proven end to end | Fixed |
| H4 | `accept_invitation` self-deadlocked the connection pool | Invitation acceptance failed entirely under concurrency | Fixed |
| H5 | Six listing endpoints reflected the caller's query string in `text/plain` | Reflection gadget + DTO field-list disclosure + contract break | Fixed |
| H6 | `User-Agent` longer than 200 chars returned `500` | Ordinary browsers and mobile clients **could not log in** | Fixed |
| H7 | Test harness destroyed its own shared template database across processes | Could silently void the security gate in either direction | Fixed |

H1 and H2 together meant the system, as committed, **did not run at all** under its
own documented deployment model. Both were invisible because the tests used the
wrong database role — the exact failure mode the privilege separation exists to
create, never exercised.

---

## 3. The escalation chain (H3), in full

This is the finding the audit was designed to look for: not an isolated bug, but a
path where a legal action reaches an illegal outcome.

`POST /api/v1/invitations` authorised only `iam.users.invite@Collection`. The
`department_id` and `client_account_id` fields in the request body were validated
for *coherence* — INTERNAL cannot carry a client account, CLIENT cannot carry a
department — and never authorised against the thing they named. On acceptance both
became real memberships, and the client membership was written **ACTIVE**.

Measured against a live server, all four steps in one run:

| Step | Observed |
|---|---|
| Attacker reads the classified project | `403` — correctly denied |
| Attacker adds a member to that department directly | `403` — correctly denied |
| Attacker invites a proxy **into that same department** | `201` — **accepted** |
| Proxy (attacker-controlled address) reads the classified project | `200` — **escalation confirmed** |

The two `403`s are the important part: they are the system's own judgement that
this principal must not reach that department. The invitation body walked around
it. The attacker never gains a permission — they mint a *second account* that holds
one, at an address they control.

**Why the CLIENT variant did not fire.** It is blocked today, but only
*incidentally*: `client.portal.*` is `max_principal_type = CLIENT`, so an INTERNAL
actor can never hold it and therefore can never delegate it. Nothing was checking
the placement. The protection was an accident of an unrelated rule — which is
precisely the kind of defence that disappears the moment someone adds a legitimate
reason for an internal role to carry a portal permission.

**Fix.** `departments::service::authorize_placement` and
`clients::service::authorize_placement`, called from `create_invitation` inside the
transaction against the locked row. Each module authorises its own placement, so
the scope semantics stay owned by the module that defines them. The demand is
deliberately identical to the direct route's: same permission, same target
construction, same step-up.

**Verification after fix:** exploit re-run → `403`; the legitimate ROOT onboarding
flow → unchanged. Three regression tests, including a **positive** case proving the
guard is an authorisation check and not a blanket refusal.

**Reproducers:** `scripts/exploit_department_placement.sh`,
`scripts/exploit_invitation_placement.sh`.

---

## 4. Clean-room verification (§2)

A brand-new PostgreSQL 18.4 instance, a brand-new database, a brand-new set of
secrets. No seed data, no manual state, nothing carried over from development.

* **Phase 1** — 16-step walk over HTTP only: bootstrap → mandatory ROOT MFA →
  department → administrator → restricted employee → client accounts → project →
  sharing → client portal isolation → audit. **0 failures.**
* **Phase 2** — after a full container restart, driven with the tokens phase 1
  minted, so "the session survived" is a claim about server-side state rather than
  about a token the script re-issued. **0 failures.**

Both phases were re-run after the fixes landed. Result: **PASS**.

H1 and H2 were both discovered here, by the simple act of running the application
as the role it is supposed to run as.

---

## 5. Backup and restore drill (§22)

Performed on the disposable clean-room database, all ten checkpoints.

| # | Checkpoint | Result |
|---|---|---|
| 1 | Populate realistic sample data | PASS |
| 2 | Take backup (`pg_dump -Fc`, 140 314 bytes, size asserted) | PASS |
| 3 | Destroy the database (`DROP DATABASE`, existence confirmed 0) | PASS |
| 4 | Restore from the **host** copy | PASS — 0 warnings |
| 5 | Start the backend against the restored database | PASS — booted, `/health/ready` 200 |
| 6 | Verify ROOT ownership | PASS — singleton intact; second insert, `UPDATE` and `DELETE` all refused by trigger; runtime role still denied `DELETE` |
| 7 | Verify users | PASS — 5/5 |
| 8 | Verify roles and permissions | PASS — 3 roles, 42 permissions, 45 role-permissions; 24 triggers, 114 checks, 52 FKs, 88 indexes all restored |
| 9 | Verify projects and clients | PASS — 1 project, 2 client accounts, 2 memberships, 1 link |
| 10 | Verify audit integrity | PASS — `verify-audit`: chain INTACT, 28 entries, head at seq 28 |

The restored snapshot was **byte-identical** to the pre-backup snapshot, including
the audit chain head hash. A full HTTP re-verification against the restored
database also passed with 0 failures, including that pre-backup session tokens
still authenticated — the restore preserved live server-side session state, not
merely table rows.

**One honest note on method.** A first attempt at this drill destroyed the
clean-room data. Git Bash rewrote the container path `/tmp/rb_audit.dump` into a
Windows path, `pg_dump` wrote nothing, and the ad-hoc command sequence proceeded to
`DROP DATABASE` anyway. The data was disposable and was rebuilt, but the lesson is
recorded because it is the sharpest one available: **the committed scripts were
safer than the ad-hoc command.** `scripts/backup_dev.sh` runs under
`set -euo pipefail` and measures the artefact; `scripts/restore_dev.sh` requires
`RB_CONFIRM_RESTORE`, asserts the dump file exists, and verifies row counts
afterwards. The failure was in improvising around them. The drill above was redone
with `MSYS_NO_PATHCONV=1` and an explicit size assertion before the destructive step.

---

## 6. ROOT ownership invariant

Re-verified from scratch on the clean-room database, at both layers.

| Attack | Result |
|---|---|
| Insert a second ownership row | Refused — trigger |
| `UPDATE` the owner | Refused — "system_ownership is immutable" |
| `DELETE` the owner | Refused — "system_ownership is immutable" |
| Runtime role `DELETE` on `system_ownership` | Refused — no grant |
| ROOT_OWNER representable as a row in `roles` | Not present — it is not a role |
| Second bootstrap | `409 SYSTEM_ALREADY_INITIALIZED` |
| Owner targeted by role assignment, override, department membership | Refused |

Ownership survived backup, `DROP DATABASE`, restore and restart, with the
invariant-enforcing triggers restored intact rather than merely the data.

**One correction found here (M2):** the department membership routes ran the root
guard *before* authorisation. `guard_root` answers `403 ROOT_PROTECTED` while every
other subject id answers `404` to an external principal — a usable oracle that
confirmed the owner's user id, and the existence of internal users at all, to a
CLIENT. Measured before and after on the live instance:

| Subject id | Before | After |
|---|---|---|
| the owner | `403 ROOT_PROTECTED` | `404 RESOURCE_NOT_FOUND` |
| an unknown user | `404 RESOURCE_NOT_FOUND` | `404 RESOURCE_NOT_FOUND` |

`identity/service.rs` had already identified and solved exactly this; departments
never got the treatment. Ordering does not weaken the protection — `require` judges
the *actor*, `guard_root` the *subject*, and the subject is still refused. It only
stops the system answering a question the caller was never allowed to ask.

---

## 7. Open findings

Nothing open is CRITICAL or HIGH. The two MEDIUMs are stated in full because they
are the most useful things in this report for deciding what to do next.

### M-A — A denial-of-service chain: unbounded audit growth with no rate limiter

**Severity: MEDIUM**, conditional on deployment (see below).

Two separately-rated findings compose. The general per-principal rate limiter is
configured (`general_per_principal_per_minute`, default 600), has both key builders
written, and is **never installed** — `middleware::apply` adds panic capture,
request id, timeout, body limit, method guard, CORS and security headers, and no
rate-limit layer. Only eight endpoints are limited at all, all in authentication,
bootstrap and identity. Separately, several routes deliberately **commit** an
`AUTHORIZATION.DENIED` audit row when they refuse — a good design — into a table
that is append-only by construction, where the runtime role holds only
`SELECT, INSERT`, and where every write takes the global audit chain advisory lock
that serialises every other mutation in the system.

Measured on the live instance, from an ordinary employee account holding **no**
project permissions:

| Observation | Value |
|---|---|
| Requests sent to `POST /projects/{id}/clients` | 100 |
| Distinct status codes returned | `403` only — authorisation held throughout |
| Requests rate-limited (`429`) | **0** |
| Audit rows written | **101** |
| Elapsed | 2 s (≈50 req/s from one unoptimised loop) |

So the authorisation decision is correct every time, and the cost of being wrong is
paid by the system rather than the attacker.

**Why MEDIUM and not HIGH.** It requires an account the company issued. Public
self-registration is **disabled by default** — verified: `registration_available:
false`, and `POST /api/v1/registration` returns `404`. The attack is also
self-evidencing (every row names the actor), operator-detectable, and recoverable:
an administrator can suspend the account, and a DBA can prune, even though the
runtime role cannot.

**It becomes HIGH if public registration is enabled**, because that makes accounts
cheap and turns this into a near-anonymous denial of service. That condition should
be treated as a gate on enabling the feature.

**Recommended fix, and why it was not applied during the freeze.** Wire the
already-configured limiter, and/or suppress repeated identical denial records
while keeping a count. This was deliberately *not* done here: installing a global
rate-limit layer at the end of an audit would change the behaviour of every route
in the system, including suites that legitimately issue 600+ probes in under a
minute, and it would have to be certified by exactly the evidence this report is
producing. Rushing it would trade a documented MEDIUM for an undocumented risk. It
is the top recommended action after the freeze.

Also worth recording: `RateLimitConfig` is built with `::default()` and reads no
environment variables, so an operator cannot tune even the eight limits that *are*
enforced.

### M-B — Object decision and listing predicate disagreed — **FIXED**

**Severity: MEDIUM.** Confirmed by execution, then fixed and re-verified.

A narrow `DENY` override is resolved per object by the evaluator, but the listings
for `users`, `departments` and `clients` build their SQL predicate from
`effective_scopes`, which by construction strips only *GLOBAL* denials — its own
comment says a narrower denial "is handled per-object at `evaluate` time". A
listing has no per-object `evaluate`. `departments::repo::visibility_for` takes the
ALLOW scopes and the actor's department ids and never reads `actor.denies` at all.

Consequently a `RESOURCE`-scoped DENY that correctly blocks
`GET /departments/{id}` does not remove that department from `GET /departments`,
which returns the row and its fields.

`projects/visibility.rs` already did this correctly — it carries
`denied_resource_ids` into the predicate. Three independent scope-to-SQL
translations existed and only one of them handled narrow denials.

Confirmed by three tests written to fail, one per listing. All three did:

| Listing | Object route honours the DENY | Listing honoured it (before) | (after) |
|---|---|---|---|
| `GET /departments` | yes | **no** | yes |
| `GET /clients` | yes | **no** | yes |
| `GET /users` | yes | **no** | yes |

**Fix.** Each listing now subtracts the actor's explicit denials from its SQL
predicate, including on the branch where the caller holds the permission at
`Collection` — the branch that previously skipped the check entirely, since a
narrow DENY never appears in a `Collection` evaluation.

For `clients` the exclusion is bound at a **fixed** `$4` in every variant rather
than appended only when non-empty: an exclusion that is added "when there is
something to exclude" is one somebody eventually forgets, and an empty array makes
the predicate trivially true, so uniformity costs nothing. A unit test asserts that
no variant can lose it. For `users`, both resource-scoped and department-scoped
denials are excluded, mirroring the allow side.

### Open LOW / INFO

| ID | Severity | Summary |
|---|---|---|
| L1 | LOW | `mfa_required` is set at invitation acceptance but not by `assign_role`/`create_override`, so a dangerous permission granted later does not force enrolment. Verified to **fail closed** (no factor ⇒ permanent `STEP_UP_REQUIRED`), but fragile against any future trusted-device step-up. |
| L2 | LOW | Non-owner `principal_type` transitions are unguarded at the database level (application-protected only). |
| L3 | LOW | Single-use token consumption has no database-level guard (by design; documented). |
| L4 | LOW | Leaked test databases: the `Drop` handler spawns a detached thread that dies with the process. **493** `rb_test_*` databases had accumulated and measurably slowed the environment. |
| L5 | LOW | Two endpoints in the sensitive set have no rate limiter. |
| L6 | LOW | Three independent UUID path parsers, one accepting inputs the others reject. |
| I1–I13 | INFO | Includes: vestigial `state.guard_root(false)` no-ops in `identity/service.rs`; the metrics module is 1 072 lines and records two series with no metrics layer installed; `endpoints.rs` is a fourth unused copy of the route list; cancelling a task is recorded as `TASK.UPDATED`; `source_ip_hint` is stored but not covered by the hash chain; the runtime role can change ROOT's display name and credentials row (docs-accuracy issue, no new capability). |

---

## 7a. Gates, inventory, coverage and performance (§17–§20)

All measurements below were taken on the final tree, after every fix, with no
other test run sharing the database.

### Quality gates — all PASS

| Gate | Result | Detail |
|---|---|---|
| `cargo fmt --all -- --check` | **PASS** | clean (24 files needed reformatting mid-audit and were formatted) |
| `cargo clippy --all-targets -- -D warnings` | **PASS** | zero warnings; one `type_complexity` error was fixed by naming the type rather than by an `allow` |
| `cargo audit` | **PASS** | 1 190 advisories loaded, 256 crate dependencies scanned, **0 vulnerabilities** |
| `cargo deny check` | **PASS** | advisories ok, bans ok, licenses ok, sources ok |

An honest note on the last one: `cargo deny` first reported a licence failure
against `zmij v1.0.23` ("MIT is not explicitly allowed") — which was nonsense,
because MIT is the first entry in the allowlist. The cause was my own container
mount: `deny.toml` lives at the repository root and only `backend/` was mounted, so
cargo-deny silently fell back to its built-in defaults. **A tool running with a
configuration it could not find still exits and still prints a verdict.** Re-run
with `--config`, the result is clean. The same class of mistake — a wrong mount
producing a confident wrong answer — also caused a spurious `openapi_contract`
failure earlier in the audit.

### Test inventory (§18) — 1 009 executed, 0 failed

| Suite | Tests | What it covers |
|---|---|---|
| unit (`src/lib.rs`) | 596 | pure rules: evaluator, delegation lattice, scopes, validation, crypto, pagination |
| `integration_suite` | 155 | end-to-end HTTP across every module |
| `security_suite` | 145 | ROOT, escalation, client isolation, auth attacks, DB invariants, runtime role |
| `race_suite` | 58 | barrier-synchronised concurrency on every single-winner path |
| `hardening_suite` | 34 | mass assignment, leakage, log injection, resource limits, SQL injection |
| `failure_injection` | 10 | behaviour when the database and dependencies fail |
| `openapi_contract` | 5 | every served route is documented, with matching permission and step-up |
| `router_registry` | 5 | the route table and the router cannot drift apart |
| `golden_scenario` | 1 | one full business walkthrough |
| `benchmarks` | 4 (ignored by default; **run, 4/4 passed**) | CPU-bound primitives |

**Total: 1 009 passed, 0 failed, 4 ignored-by-default (executed separately).**

### Coverage (§19) — 91.31% region, 93.18% function, 93.66% line

Not chased for the number. The gaps that actually matter:

| File | Line coverage | Judgement |
|---|---|---|
| `platform/observability/logging.rs` | **0.00%** | Subscriber initialisation, run once at startup and never under test. Low risk (a failure is immediate and total), but it means log *formatting* is proven only by the log-injection suite driving a live server, not by unit tests. |
| `platform/config/mod.rs` | 64.44% | The largest real gap. Startup validation is the control that refuses to boot on weak secrets and wildcard CORS; `config_fail_closed` covers the headline refusals, but two thirds of the branches — individual field parses and defaults — are unexercised. A misparse here fails at startup rather than silently, which is why this is a gap and not a finding. |
| `platform/database/mod.rs` | 74.34% | Pool construction and TLS options. |
| `platform/http/idempotency.rs` | 82.40% | Replay/conflict paths are covered; some storage error branches are not. |
| `platform/errors/mod.rs` | 87.37% | Two of this audit's findings (H6, M-3) were *unmapped error arms*, so the uncovered remainder here is the highest-value place to add tests next. |

### Performance (§20) — measured, not tuned

Nothing was reconfigured to produce a nicer number. Release profile, inside a
container, on a shared 24-core development host — treat as indicative, not as a
capacity plan.

CPU-bound primitives (p50 / p95):

| Operation | p50 | p95 |
|---|---|---|
| authorisation `evaluate` (44 grants, 5 denials) | **28 ns** | 30 ns |
| `evaluate` (deny, out of scope) | 21 ns | 23 ns |
| `capability_list` (whole catalogue) | 1.94 µs | 2.15 µs |
| audit `entry_hash` (HMAC-SHA256 + canonical encoding) | 518 ns | 587 ns |
| token generation (32 CSPRNG bytes) | 329 ns | 354 ns |
| token hashing (SHA-256) | 53 ns | 56 ns |
| AEAD seal / open (XChaCha20-Poly1305) | 1.36 µs / 1.17 µs | 1.47 µs / 1.21 µs |
| TOTP verify (3-step window) | 479 ns | 490 ns |

The 28 ns evaluator result is the number that matters most: it is the cost a
permission cache would remove, and it is the reason no cache exists. Re-deriving
authorisation on every request is not the expensive part of a request.

End-to-end HTTP (50 samples each, through the real router and database):

| Endpoint | p50 | p95 | max |
|---|---|---|---|
| `GET /health/ready` | 1.3 ms | 1.8 ms | 6.7 ms |
| `GET /api/v1/auth/me` | 2.6 ms | 3.1 ms | 6.3 ms |
| `GET /api/v1/projects` | 3.2 ms | 12.3 ms | 19.8 ms |
| `GET /api/v1/tasks` | 5.3 ms | 12.1 ms | 14.4 ms |

**`POST /auth/login` is reported separately and deliberately.** A naive
50-sample run gave a p50 of 1.2 ms, which is *false*: only the first three requests
were real logins, and the other 17 were `429`s rejected before any hashing. The
honest figures are **14.9 / 15.6 / 18.1 ms for the three logins that actually ran**,
which is the Argon2id cost (m=19456 KiB, t=2, p=1) behaving exactly as intended. The
contaminated average is itself evidence that the login limiter works — and a good
example of how a benchmark flatters a system if you do not look at the status codes.

The audit chain's real cost is not the 518 ns hash: appends serialise on
`SELECT … FROM audit_chain_head FOR UPDATE`. That is a deliberate
correctness-over-throughput choice (ADR-006, RR-6), and it is the mechanism that
finding M-A abuses.

---

## 8. What was actively hunted and not found

Recording these matters as much as the findings: they are the attacks that did
**not** work, and each was executed rather than reasoned about.

* Permission caching in the token — a live session reflects grant/revoke on the
  **very next request**, proven across six privilege transitions with one token.
* 403-vs-404 existence oracles (outside the departments case above).
* DENY escape by adding a role; role-composition escalation; self-promotion via a
  self-authored role.
* TOTP replay; refresh-token reuse; MFA bypass on a pending session.
* Mass assignment — 630 probes with database read-back: no finding.
* SQL injection — ~1 500 probes with whole-schema snapshots: no finding. All 49
  dynamic-SQL sites interpolate only `&'static str` constants, allowlist-resolved
  sort columns, and `ASC`/`DESC`. `LIMIT` is always bound, `OFFSET` does not exist,
  and there is no `LIKE`/regex — the one free-text search uses `strpos`, so
  wildcard-pattern injection is impossible. Proven behaviourally.
* Log injection — CRLF, ANSI, NUL and U+2028 folded to `·`; no forged record,
  severity or token, in both JSON and text formatters, verified against a live
  server under raw-socket attack.
* Client envelope escape; cross-client data access; audit chain tampering without
  the key.

---

## 9. Limits of this audit — what was NOT proven

Stated plainly, because a report that hides these is worth less than one that does.

1. **Real clock passage.** Expiry is simulated by writing past timestamps. A bug in
   how "now" is obtained would not be caught.
2. **Transport layer.** Most tests drive the router in-process, so TLS, HTTP/2
   framing and proxy header smuggling are unreachable by them. (The clean-room and
   log-injection work did use real sockets.)
3. **Timing oracles beyond login.** In-process timings are too noisy to assert on;
   a flaky timing assertion in a security suite is worse than none.
4. **`projects` parity was not re-proven.** M-B was found and fixed in the three
   listings that lacked the control. `projects` already carried denials into its
   predicate and was left untouched, on the strength of reading it rather than a
   new test of its own.
5. **Superuser-level database attacks** are outside every layer of the ROOT
   invariant by construction, and are not claimed to be defended.
6. **No claim of completeness.** Absence of a finding in a category above means the
   probes run did not find one — not that none exists.

---

## 10. Final re-verification (everything below ran on the final tree)

Every fix in this report was re-verified together, from scratch, after the last
change landed. Nothing here is carried over from an earlier run.

| Check | Result |
|---|---|
| `cargo test --all-targets` | **1 009 passed, 0 failed**, exit 0 |
| `cargo fmt --check` / `clippy -D warnings` / `cargo audit` / `cargo deny` | **all PASS** |
| Clean-room phase 1 (fresh database, fresh secrets, HTTP only) | **0 failures** |
| Clean-room phase 2 (after container restart) | **0 failures** |
| `exploit_department_placement.sh` | **exploit blocked** — `403` at the placement |
| `exploit_invitation_placement.sh` | **exploit blocked** — `403` at the placement |
| `verify-audit` | chain **INTACT**, 45 entries, head at seq 45 |
| ROOT singleton: second insert / `UPDATE` / `DELETE` | all **refused by trigger**; exactly 1 row |
| Owner-identity oracle from an external CLIENT | `404` for the owner **and** `404` for an unknown id — indistinguishable |

## 11. Severity gate (§29)

The gate: *any remaining CRITICAL or HIGH forces NOT READY.*

* CRITICAL open: **0**
* HIGH open: **0** (7 found, 7 fixed and re-verified)

The gate passes. One MEDIUM remains open (**M-A**, the denial-of-service chain),
deliberately and with its reasoning stated in §7: wiring a global rate limiter at
the end of a freeze would change the behaviour of every route in the system and
would itself need certifying by exactly the evidence this report provides. It is
the first thing to do next, and **enabling public registration should be gated on
it**, because cheap accounts would raise M-A to HIGH.

## 12. Verdict

**BACKEND FOUNDATION READY FOR FRONTEND**

Stated with its limits attached, because the standard of this audit was evidence
rather than adjectives:

* It means: no CRITICAL or HIGH finding remains open; the application boots and
  runs as its own runtime role; the ownership invariant, the client trust boundary
  and the audit chain each survived direct attack, a restart and a full
  backup/restore cycle; and 1 009 tests plus four gates pass on the final tree.
* It does not mean "secure", "unhackable" or "fully compliant". §9 lists what was
  not proven, and §7 lists what is still open.

The most useful sentence in this report is not the verdict. It is that a suite of
622 green tests could not boot the system it was testing — and that the seven HIGH
findings were all found by running the thing, as the role it actually runs as,
against a database nobody had prepared for it.
