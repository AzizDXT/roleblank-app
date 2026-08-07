# Security Test Report

**System:** RoleBlank OS backend
**Date of execution:** 2026-08-07
**Status legend:** `PASS` executed and passed · `FAIL` executed and failed · `BLOCKED` could not be executed, with the reason and the command to run it later · `NOT_APPLICABLE` the risk does not exist in this system, with why

> Nothing in this document is marked PASS unless it was executed and its output
> observed. Where a result is a count, the count is from the actual run.

---

## 1. Execution environment

| Item | Value |
| --- | --- |
| Host | Windows 11 Home 10.0.26200, Intel Core Ultra 9 290HX Plus (24 cores), 63.4 GB RAM |
| Build & test environment | `rust:1-bookworm` container, rustc 1.97.1 — identical to the host toolchain |
| Database | `postgres:18.4-alpine`, data checksums enabled, published on loopback only |
| Reason for containerisation | The Windows host enforces an Application Control policy that refuses to execute freshly compiled unsigned binaries (`os error 4551`). Reproduced twice — under `%TEMP%` and inside the project directory. See `00-reconnaissance.md` §3 |

---

## 2. Database-level invariants — executed directly against PostgreSQL

Run as the **schema owner** (`roleblank_migrator`), i.e. with more privilege than
the application ever has. Brief §68 requires these to be tested outside HTTP.

| # | Attack | Result | Observed |
| --- | --- | --- | --- |
| DB-01 | Insert a second `system_ownership` row | **PASS** | `duplicate key value violates unique constraint "system_ownership_pkey"` |
| DB-02 | Move ownership by `UPDATE` | **PASS** | `system_ownership is immutable: UPDATE is not permitted` |
| DB-03 | `DELETE FROM system_ownership` | **PASS** | `system_ownership is immutable: DELETE is not permitted` |
| DB-04 | `DELETE` the owner from `users` | **PASS** | `the system owner cannot be deleted` |
| DB-05 | Suspend the owner | **PASS** | `the system owner must remain ACTIVE (attempted SUSPENDED)` |
| DB-06 | Archive the owner | **PASS** | `the system owner must remain ACTIVE (attempted ARCHIVED)` |
| DB-07 | Convert the owner to a `CLIENT` principal | **PASS** | `the system owner must remain an INTERNAL principal` |
| DB-08 | Clear the owner's `mfa_required` | **PASS** | `MFA cannot be made optional for the system owner` |
| DB-09 | Bulk `UPDATE users SET status='SUSPENDED'` (owner swept up) | **PASS** | Statement aborted; **0 users suspended** — no partial application |
| DB-10 | Duplicate email differing only in case | **PASS** | `duplicate key value violates unique constraint "users_email_normalized_key"` |
| DB-11 | Assign an INTERNAL role to a CLIENT principal | **PASS** | `role system_administrator is restricted to INTERNAL principals` |
| DB-12 | Attach an INTERNAL permission to the CLIENT role | **PASS** | `permission iam.users.read is INTERNAL-only and cannot be attached to a CLIENT role` |
| DB-13 | `ALLOW` override of an INTERNAL permission for a CLIENT | **PASS** | `permission audit.read is INTERNAL-only and cannot be allowed for a CLIENT principal` |
| DB-14 | Add a CLIENT principal to a department | **PASS** | `department_memberships requires an INTERNAL principal` |
| DB-15 | Add an INTERNAL user to a client account | **PASS** | `client_memberships requires a CLIENT principal` |
| DB-16 | `TRUNCATE audit_events` | **PASS** | `audit_events cannot be truncated` (statement-level trigger — row triggers do not fire on TRUNCATE) |
| DB-17 | Revert `system_state.initialized_at` to NULL | **PASS** | `system initialisation cannot be reverted` |
| DB-18 | Move the audit chain head backwards | **PASS** | `audit chain head cannot move backwards (5 -> 1)` |
| DB-19 | Establish ownership for a CLIENT principal | **PASS** | Covered by the `INSERT` guard; asserted in `tests/security/database_invariants.rs` |
| DB-20 | `UPDATE` / `DELETE` an audit event as the schema owner | **PASS** | `audit_events is append-only: UPDATE is not permitted` |

**Final state after all twenty attacks:** `ownership_rows = 1`, owner `status = ACTIVE`,
`mfa_required = true`, `suspended_users = 0`.

> One note on honesty: in the first interactive pass, DB-20 was inconclusive because
> the probe SQL used an invalid `bytea` literal, so the `UPDATE`/`DELETE` matched
> zero rows rather than being refused. It was re-run with a correct literal and the
> trigger fired as expected. The automated suite uses the corrected form.

---

## 3. Database privilege separation — executed as the runtime role

Run as `roleblank_app`, the identity the running application actually connects
with. This is the "compromised application process" scenario: arbitrary SQL, but
only the privileges the application legitimately holds.

Verified role attributes: `current_user = roleblank_app`, `rolsuper = false`,
`rolcreatedb = false`, `rolcreaterole = false`, **owns 0 tables**.

| # | Attack | Result | Observed |
| --- | --- | --- | --- |
| RT-01 | `INSERT` an audit event | **PASS** (must succeed) | `INSERT 0 1` — the log is append-only, not read-only |
| RT-02 | `UPDATE` an audit event | **PASS** | `permission denied for table audit_events` |
| RT-03 | `DELETE` an audit event | **PASS** | `permission denied for table audit_events` |
| RT-04 | `TRUNCATE audit_events` | **PASS** | `permission denied for table audit_events` |
| RT-05 | `DELETE` any user | **PASS** | `permission denied for table users` — no DELETE grant at all |
| RT-06 | `UPDATE system_ownership` | **PASS** | `permission denied for table system_ownership` |
| RT-07 | `DELETE FROM system_ownership` | **PASS** | `permission denied for table system_ownership` |
| RT-08 | `ALTER TABLE users DISABLE TRIGGER trg_users_protect_root` | **PASS** | `must be owner of table users` |
| RT-09 | `ALTER TABLE audit_events DISABLE TRIGGER trg_audit_events_append_only` | **PASS** | `must be owner of table audit_events` |
| RT-10 | `DROP TABLE audit_events` | **PASS** | `must be owner of table audit_events` |
| RT-11 | `DELETE FROM _sqlx_migrations` | **PASS** | no such relation is reachable to this role |
| RT-12 | `CREATE TABLE public.rb_attacker_shadow` | **PASS** | `permission denied for schema public` |
| RT-13 | Suspend the owner | **PASS** | `the system owner must remain ACTIVE` (trigger, not grant) |
| RT-14 | Establish a second ownership row | **PASS** | `duplicate key value violates unique constraint` |

**Final state:** `ownership_rows = 1`, owner `ACTIVE`, `audit_rows = 1`, `user_rows = 3`.

`INSERT` on `system_ownership` *is* granted, because first-run bootstrap is an HTTP
endpoint. It is safe precisely because the table is a singleton by primary key: the
insert can succeed at most once in the lifetime of the database, and `UPDATE` and
`DELETE` are both ungranted **and** refused unconditionally by a trigger.

---

## 4. Cryptography

Executed: `cargo test --lib` in the container. **56 of 56 passed** at the time of
this section's run.

| Area | Tests | Result | Notable |
| --- | --- | --- | --- |
| Token generation & hashing | 7 | **PASS** | 1 000 generated tokens, zero collisions; prefix-sensitive digests; malformed input including a 100 000-character token rejected without a database lookup |
| Argon2id | 11 | **PASS** | Round-trip; fresh salt per hash (identical passwords produce different hashes); passwords **not** trimmed, case-folded or normalised; Unicode and 256-character passphrases; corrupt stored hash fails closed; weak parameters refused at construction |
| XChaCha20-Poly1305 | 9 | **PASS** | Fresh nonce per seal; **wrong associated data fails** (an attacker cannot move one user's TOTP secret onto another's row); modified ciphertext and modified nonce both fail; key rotation keeps old ciphertexts readable; a missing key version is reported distinctly from a decryption failure |
| TOTP (RFC 6238) | 11 | **PASS** | **Matches the RFC's own Appendix B test vectors** at t = 59, 1 111 111 109, 1 111 111 111, 1 234 567 890, 2 000 000 000, 20 000 000 000. Replay of a used code inside its own window is refused. `otpauth://` label injection is percent-encoded |
| Secret hygiene | 3 | **PASS** | `Debug` on a containing struct renders `Secret(<redacted>)`; the value never appears |
| Log sanitisation | 6 | **PASS** | CRLF, NUL, ANSI escapes and U+2028/U+2029 folded; truncation on a character boundary; ordinary Arabic/Japanese/accented text preserved |

> During this run the RFC 6238 test initially failed. The cause was two incorrect
> `T` values transcribed into the *test table*, not a defect in the implementation:
> the derivation produced 37 037 036 for t = 1 111 111 109, which is the correct
> `0x023523EC`. The test constants were corrected against the RFC and all six
> vectors then matched.

---

## 5. Authorization

Executed: `cargo test --lib`. **128 of 128 passed**, comprising 114 example-based
tests and 14 property tests at 2 048 generated cases each — approximately
**28 000 generated authorisation scenarios**.

### Property tests (`proptest`, 2 048 cases each)

| Property | Threat | Result |
| --- | --- | --- |
| A CLIENT principal never obtains an INTERNAL permission, for any random roles, overrides, scopes and targets | TH-09 | **PASS** |
| A CLIENT capability list never contains a non-portal permission | TH-09 | **PASS** |
| A matching global `DENY` always wins, whatever the allow set | TH-16 | **PASS** |
| Piling on arbitrary roles cannot escape a `DENY` | TH-16 | **PASS** |
| A permission outside the catalogue always denies, even when granted at global scope | — | **PASS** |
| A narrow scope never authorises an unfiltered collection | BOLA | **PASS** |
| Delegation never exceeds the actor's own effective authority | TH-13/14 | **PASS** |
| An actor can never grant anything to itself | TH-13 | **PASS** |
| ROOT is never a valid target of an authorisation operation, for any actor including ROOT | TH-04 | **PASS** |
| Scope derivation is reflexive and never widens to `GLOBAL` | TH-15 | **PASS** |
| Scope derivation is transitive (no escalation via an extra hop) | TH-15 | **PASS** |
| A malformed scope never authorises | — | **PASS** |
| Evaluation is deterministic | — | **PASS** |
| ROOT is allowed every catalogued permission | — | **PASS** |

### Delegation guard, example-based

All eight rules from `04-authorization.md` §6 are tested by name, including the two
that matter most:

- `department_cannot_derive_assigned` — **PASS**. `DEPARTMENT → ASSIGNED` is a
  lateral escalation and is refused; treating scopes as a single ladder would ship it.
- `a_role_cannot_be_used_to_smuggle_a_permission_the_actor_lacks` — **PASS**. An
  actor with `iam.roles.assign` but not `settings.security.write` cannot assign a
  role containing `settings.security.write`.

### Catalogue invariants

- `only_client_portal_permissions_are_reachable_by_external_principals` — **PASS**
- `client_reachable_permissions_are_read_only` — **PASS**
- `the_dangerous_set_is_exactly_what_the_documentation_claims` — **PASS**

---

## 6. Configuration fail-closed behaviour

Executed: `cargo test --lib platform::config`. **All passed.**

| Refusal | Result |
| --- | --- |
| Wildcard CORS on an authenticated API | **PASS** |
| Non-`https` origin, non-`https` or localhost base URL | **PASS** |
| All-zero encryption or chain key | **PASS** |
| Placeholder text in a secret or in `DATABASE_URL` | **PASS** |
| A privileged database role in `DATABASE_URL` | **PASS** |
| `sslmode=disable` | **PASS** |
| Public OpenAPI document, or text logs, in production | **PASS** |
| A development mail sink in production | **PASS** |
| Incoherent limits (page size, TTL ordering, pool bounds, step-up window) | **PASS** |
| Development tolerates what production refuses | **PASS** |

> A **real defect was found by these tests and fixed**: the check for a privileged
> database role used a substring match on `"postgres:"`, which matches the URL
> *scheme* `postgres://` and would have rejected every valid production
> configuration. It was replaced with proper username extraction (handling `@` in
> passwords), and a named regression test was added.

---

## 7. Rate limiting

Executed: `cargo test --lib platform::http::rate_limit`. **All passed.**

| Property | Result |
| --- | --- |
| Quota enforced, then limited with a `Retry-After` | **PASS** |
| Keys independent (one ground account does not lock out others) | **PASS** |
| Tokens refill continuously | **PASS** |
| **No window boundary to burst across** — half a window returns roughly half the quota, not all of it | **PASS** |
| A successful login resets the account key | **PASS** |
| Zero quota denies everything | **PASS** |
| The key table is bounded — 1 000 distinct keys against a 100-key cap stayed ≤ 200 entries | **PASS** |
| 50 concurrent requests against a quota of 10 let **exactly 10** through | **PASS** |
| Key namespaces do not collide | **PASS** |

---

## 8. Trusted proxy handling

Executed: `cargo test --lib platform::config::net`. **All passed.**

| Property | Result |
| --- | --- |
| Forwarded headers from an **untrusted** peer are ignored | **PASS** |
| An empty trust list trusts nothing | **PASS** |
| The **rightmost** entry is taken from a trusted peer (the leftmost is attacker-supplied) | **PASS** |
| IPv4-mapped IPv6 peers match IPv4 networks | **PASS** |
| Port suffixes and bracketed IPv6 tolerated | **PASS** |
| A garbage or 100 000-character header falls back to the peer address | **PASS** |

---

## 9. Audit integrity

Executed: `cargo test --lib modules::audit`. **All passed.**

| Property | Result | Notes |
| --- | --- | --- |
| An untouched 50-entry chain verifies | **PASS** | |
| Editing **any** covered field is detected | **PASS** | 10 distinct mutations: outcome, action, actor, actor→NULL, target id, target type, metadata, request id, timestamp, event id |
| A forgery rebuilt consistently **with the wrong key** is detected | **PASS** | This is why the chain is keyed rather than a plain hash |
| Deleting an entry is detected as a sequence gap | **PASS** | A per-row hash scheme cannot do this |
| Reordering is detected | **PASS** | |
| Splicing a genuine hash from elsewhere breaks the link | **PASS** | |
| Tail truncation is detected by the head record | **PASS** | |
| JSON key order does not change the digest; array order does | **PASS** | |
| Field boundaries cannot be shifted (length prefixing) | **PASS** | `("INTERNAL","USER.CREATED")` ≠ `("INTERNALUSER",".CREATED")` |
| `NULL` and `""` are distinguishable | **PASS** | |
| Secret-bearing metadata keys are refused | **PASS** | 16 key spellings tested; the value never reaches the document |
| Metadata document and arrays are bounded | **PASS** | |

**Claim discipline:** the chain detects modification, deletion or reordering
performed **without the chain key**. It is explicitly *not* a claim of
tamper-proofing against an adversary holding both the database and the key —
see ADR-006 and RR-1/RR-2.

---

## 10. Input handling and injection

| Class | Status | Evidence |
| --- | --- | --- |
| SQL injection via sorting | **PASS** | `sort_fields_outside_the_allowlist_are_refused` — 8 injection strings including `'; DROP TABLE users--` and a `SELECT password_hash` union; all refused by allowlist, and the rejected value is **not echoed back** |
| SQL injection generally | **PASS** (by construction, plus tests) | Parameterised binds only. The eight dynamically assembled statements use `sqlx::AssertSqlSafe` over fragments that are compile-time literals or allowlisted `&'static str`; one module proves the assembled predicate is byte-identical for 1 000 different id sets |
| Log injection (CRLF) | **PASS** | `strips_crlf_so_log_lines_cannot_be_forged`, plus JSON encoding as an independent second layer |
| Oversized cursor / malformed cursor | **PASS** | Length-bounded before decoding |
| Pagination abuse | **PASS** | limit 0, −1, 101, 999 999 999, `abc`, `1e9` all refused |
| Mass assignment | **PASS** | `deny_unknown_fields` on every request DTO; per-module tests reject `is_root`, `principal_type`, `role_ids`, `permissions`, `status`, `client_visible` |
| Request-id header poisoning | **PASS** | Hostile values replaced, never echoed |

---

## 11. Attack classes absent by construction

| Class | Status | Why |
| --- | --- | --- |
| SSRF | **NOT_APPLICABLE** | No endpoint accepts a URL, hostname or IP and performs an outbound fetch. The backend makes **zero** outbound HTTP requests; no HTTP client crate is linked |
| Command injection | **NOT_APPLICABLE** | The process never spawns a subprocess; `duct` and `subprocess` are banned in `deny.toml` |
| Path traversal | **NOT_APPLICABLE** | No endpoint accepts a filesystem path; no static file is served |
| Unrestricted file upload | **NOT_APPLICABLE** | No upload endpoint exists. `12-future-storage.md` records the controls required before one ships |
| XXE | **NOT_APPLICABLE** | No XML parser is linked |
| CSRF | **NOT_APPLICABLE** | Authentication is `Authorization`-header only; cookies are never read; form and multipart content types are refused |
| Unsafe deserialisation | **NOT_APPLICABLE** | `serde_json` into closed structs only; no type-tag polymorphism, no `flatten` into `Value` on an authenticated write path |
| Memory-safety classes | **NOT_APPLICABLE** | `#![forbid(unsafe_code)]` at the crate root; zero `unsafe` blocks |

---

## 12. Executed suite results

Run against PostgreSQL 18.4 in the container, whole suite, single invocation:

```
cargo test
```

| Binary | Tests | Result |
| --- | --- | --- |
| `--lib` (unit + property) | 586 | **PASS** |
| `tests/integration_suite.rs` | 121 | **PASS** |
| `tests/security_suite.rs` | 80 | **PASS** |
| `tests/race_suite.rs` | 53 | **PASS** |
| `tests/failure_injection.rs` | 10 | **PASS** |
| `tests/openapi_contract.rs` | 5 | **PASS** |
| `tests/router_registry.rs` | 5 | **PASS** |
| `tests/golden_scenario.rs` | 1 | **PASS** |
| `tests/benchmarks.rs` | 4 | ignored by default; run separately in release mode |
| **Total** | **903** | **903 passed, 0 failed** |

Line coverage, `cargo llvm-cov`: **90.37%** overall (31 347 regions).

---

## 12a. The adversarial round — nine real defects

The suite stood at **622 tests, all green, all four gates passing**. Three
adversarial agents were then set on the system with instructions to break it rather
than confirm it. They found **nine genuine defects**. Three would have reached
production with no signal at all.

### D1 — Sixteen security tests existed on disk and had never been compiled

`tests/security/attack_probes.rs` (509 lines of anonymous-surface probes) was
never declared in `tests/security_suite.rs`. It was invisible to `cargo test`.

An unregistered test does not fail — it disappears. Nothing in the toolchain
reports it. `security_suite.rs` now carries a comment requiring every file under
`tests/security/` to be declared, and the first run of the recovered file
immediately exposed D2.

### D2 — The login timing-oracle test measured the rate limiter, not Argon2

Failed with *"the unknown-account path is 12.2x different (known=50 566µs
unknown=4 145µs)"*. Fourteen logins from one address exceed the ten-per-minute
per-IP quota, so the second batch returned `429` in microseconds without hashing.
The equalisation itself is sound; the test now resets the buckets between samples.

### D3 — `403 ROOT_PROTECTED` identified the system owner to an external principal

`identity::service` checked `is_root` **before** authorisation, so a CLIENT
probing `PATCH /users/{id}`, `/suspend`, `/archive` or `/reactivate` received
`403 ROOT_PROTECTED` for the owner and `404` for every other identifier — a
boolean oracle identifying the owner to a principal that may not know any internal
user exists. `deny_root` now shapes the error by principal type.

### D4 — `403 STEP_UP_REQUIRED` advertised an internal-only route to a CLIENT

`share_with_client`/`unshare_from_client` called `require_step_up_for` as their
first statement, before loading the row or authorising. A CLIENT — which can never
hold `projects.clients.share` — got `403` where §10 requires `404`. It also told
an unauthorised employee precisely which control to defeat next. Step-up now runs
**after** the object-level check.

### D5 — `step_up = true` declared on three routes and never enforced

`POST`/`PATCH`/`DELETE /api/v1/roles` declare step-up in `ROUTE_TABLE` **and** in
the OpenAPI document, but `iam.roles.create/update/delete` are not `is_dangerous`,
so `require_step_up_for` was a silent no-op. A password-only stolen session could
author an empty role, fill it by `PATCH`, and change what every existing holder may
do. The drift tests compare the table against the spec — **neither compares either
against runtime behaviour.** Fixed with an explicit `require_step_up`.

### D6 — Every password-reset and invitation email was dead-lettered

Both producers built their outbox payload with a free `json!` instead of the type
the worker deserialises: one used an unregistered event type, the other a shape
`InvitationPayload` cannot parse. Both went straight to `DEAD`. **The endpoints
returned success**, so nothing surfaced it. Found by a test asking whether every
event the application enqueues is actually deliverable. The old reset payload also
carried the raw token while being documented not to.

### D7 — Concurrent outbox workers double-claimed events

Six workers claiming 300 events produced **601 claims**. `FOR UPDATE SKIP LOCKED`
only excludes claims running at the same instant; a claimed row stays `PENDING`, so
a worker polling milliseconds later re-claims it. Duplicate mail is tolerable under
at-least-once delivery; the invisible harm is both workers calling `mark_failed`,
double-incrementing `attempts` and dead-lettering deliverable mail at half its
budget — during exactly the outage the budget exists to survive. Fixed with a
60-second claim lease, which also gives crash recovery a defined window.

### D8 — `Idempotency-Key` documented on six endpoints, implemented on none

`modules::outbox::idempotency` existed in full and the header is in the OpenAPI
document for six `POST` routes, but nothing read it. A retried create made a second
object. Fixed with an `Idempotent<T>` extractor wired into all six.


### D9 — `Path<Uuid>` rejections bypassed the error contract in seven modules

`GET /api/v1/departments/not-a-uuid` returned:

```
400  Content-Type: text/plain; charset=utf-8
Invalid URL: Cannot parse `id` with value `not-a-uuid`: UUID parsing failed…
```

Three broken promises at once: it is not `application/problem+json` and carries no
stable `code`, so a client has nothing to branch on; it **reflects the
attacker-controlled path segment** back in the body; and it names the Rust binding.

The reflection is the part that matters most, because this codebase refuses to do it
everywhere else — the pagination sort allowlist deliberately names the *permitted*
fields and never the rejected value, with a test asserting exactly that. Two modules
(`authorization`, `audit`) already parsed `Path<String>` by hand with comments
explaining why. Seven did not: `departments`, `clients`, `projects`, `tasks`,
`identity`, `settings`, and `authentication`.

Found by an integration test that recorded the deviation rather than cementing it.
Fixed with shared `PathId` / `PathIds` / `PathKey` extractors across **41 call
sites**, carrying a comment that ends "do not simplify these back to `Path<Uuid>`".
`PathKey` delegates to the settings module's own `validate_key` rather than
re-deriving the grammar — a second copy of a validation regex drifts, and the looser
copy is the one that gets found.

### Two smaller findings

- The reuse-detection audit event **redacted its own payload**: `AuditMetadata`
  refuses any key containing `"token"`, so the invalidated-token count was dropped
  and every genuine detection also emitted an ERROR accusing the call site of
  writing a secret — training operators to ignore that alarm.
- `VERSION_CONFLICT` carried `expected`/`actual` only inside `detail`, which the
  contract says may be reworded at any time; a client's retry loop had to parse
  English. Now a structured `version_conflict` object.

### What this round says about the earlier green result

622 tests and four green gates described the tests, not the system. The happy path
passed throughout. What found these was asking *"what if the system is lying to
me?"* — is the mail actually deliverable, is the declared step-up actually enforced,
is the refusal shaped differently for the one principal who must not learn the
difference.

## 12b. Quality and supply-chain gates

Final run, `sh scripts/gates.sh` inside the container — **`=== overall: PASS ===`**.

| Gate | Result | Evidence |
| --- | --- | --- |
| `cargo fmt --all -- --check` | **PASS** | |
| `cargo clippy --all-targets --all-features -- -D warnings` | **PASS** | zero warnings across lib, bins and all seven test binaries |
| `cargo audit` | **PASS** | 1 190 advisories loaded; **no known advisory** against the 256-crate tree at execution time |
| `cargo deny check advisories` | **PASS** | |
| `cargo deny check bans` | **PASS** | no banned crate, no wildcard version |
| `cargo deny check sources` | **PASS** | no git dependencies, no unknown registry |
| `cargo deny check licenses` | **PASS** after two documented decisions | below |
| Production Docker image build | **PASS** | multi-stage, non-root uid 10001, no toolchain or source in the runtime layer |

Two build defects were found and fixed while getting the image to build, both of
which would have shipped a broken container:

- The dependency-cache stage created a placeholder for the `[[bin]]` target but not
  the `[lib]` target the crate also declares, so `cargo build` failed with
  `couldn't read src/lib.rs`.
- Only the *binary's* stale artefacts were deleted before the real build, leaving
  the placeholder **library** cached. The genuine `main.rs` then failed with
  `unresolved import roleblank_backend::cli` — it was linking against an empty stub.

### Two licence decisions, recorded rather than suppressed

- **`webpki-roots` — CDLA-Permissive-2.0.** Reached through sqlx's rustls stack; it
  is the Mozilla CA trust store. CDLA-Permissive-2.0 is a permissive *data* licence
  with no copyleft and no obligation on derived works, and it is the correct licence
  for a certificate list. Added to the allowlist because the alternative to a root
  store is unverified TLS to the database.
- **`md-5` — was banned, ban removed.** It arrives transitively through
  `sqlx-postgres`, which needs it to speak PostgreSQL's legacy `md5` authentication
  method — a wire-protocol requirement of the *server*, not a choice this codebase
  makes. Nothing in RoleBlank calls MD5. Banning it would only make sqlx unbuildable
  while doing nothing to stop a server configured for md5 auth; the control that
  actually matters is `scram-sha-256` at the database, recorded in
  `08-operations.md`.


## 12c. Coverage

Measured with `cargo llvm-cov --summary-only` over the whole suite.

**Overall: 57.84% → 90.37%** after the adversarial and integration rounds.

| Layer | Before | After |
| --- | --- | --- |
| Business services (`projects`/`tasks`/`identity`) | 12–15% | **87%** |
| Module HTTP handlers (`*/routes.rs`) | 12–25% | **97–100%** |
| Module repositories (`*/repo.rs`) | 17–31% | **93–98%** |
| `system/repo.rs` — `/health/ready` had never been called | **0%** | **91.7%** |
| `settings/service.rs` | 67.7% | **95.5%** |
| `outbox/mod.rs` | 66.7% | **93.4%** |
| Client-isolation predicate (`projects/visibility.rs`) | 99.3% | **99.3%** |
| Crypto, rate limiting, validation, pagination | 93–100% | **93–100%** |

### What is still uncovered, and why 100% is not the target

The brief says *"do not game coverage"*. These are the remaining gaps, each stated
rather than papered over:

| Location | Coverage | Why |
| --- | --- | --- |
| `platform/observability/logging.rs` | **0%** | `init` installs a **process-global** subscriber. Calling it from a test corrupts every other test in the binary. It runs on every real start of `serve` |
| `platform/config/mod.rs` | 56% | `from_env` reads process environment variables; exercising each branch means mutating global process state, which is unsound under parallel tests. The **validation** logic — the part that fails closed — is separately and fully tested |
| `platform/database/mod.rs` | 76% | The uncovered arms are driver failure modes (`WorkerCrashed`, `Tls`) that require corrupting the driver itself |
| `platform/errors/mod.rs` | 83% | Unreachable `sqlx::Error` arms, and the serialisation fallback that exists so a panic in an error path cannot drop a connection |
| `platform/http/middleware.rs` | 90% | `panic_response`. Covering it means writing a handler that panics on purpose — injecting a defect to move a number |
| `modules/audit/chain.rs` | — | `Err(_) => vec![0u8; 32]` in `entry_hash` is unreachable: HMAC accepts any key length. It exists so a broken key cannot take the process down mid-transaction |

Every one of these is either process-global state, an unreachable defensive branch,
or a failure mode that would have to be manufactured. Reaching 100% would require
adding defects or fake test logic — buying a number at the cost of the trust the
number is supposed to carry.

## 13. Known blocked items

| Item | Status | Reason | Command to run later |
| --- | --- | --- | --- |
| `cargo fuzz` targets | **BLOCKED** | Requires a nightly toolchain and `cargo install`, which the host's Application Control policy prevents; the container can install it but nightly is not present in `rust:1-bookworm` | `docker run --rm -v ...:/work -w /work rustlang/rust:nightly bash -c "cargo install cargo-fuzz && cargo fuzz run <target>"` |
| OWASP ZAP baseline scan | **BLOCKED** | Not attempted; would require running the API and a ZAP container. Recorded rather than skipped silently. Note that a passing ZAP baseline would say very little here — the interesting surface is authenticated authorisation logic, which ZAP does not exercise | `docker run --rm -t ghcr.io/zaproxy/zaproxy zap-baseline.py -t http://host:8090/api/v1` |
