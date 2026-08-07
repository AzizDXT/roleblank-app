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

| Binary | Tests | Result | Wall clock |
| --- | --- | --- | --- |
| `--lib` (unit + property) | 581 | **PASS** | 0.90 s |
| `tests/golden_scenario.rs` | 1 | **PASS** | 0.50 s |
| `tests/openapi_contract.rs` | 5 | **PASS** | 0.01 s |
| `tests/router_registry.rs` | 5 | **PASS** | 0.00 s |
| `tests/race_suite.rs` | 7 | **PASS** | 0.53 s |
| `tests/security_suite.rs` | 23 | **PASS** | 0.70 s |
| `tests/benchmarks.rs` | 4 | ignored by default; executed separately in release mode | — |
| **Total** | **622** | **622 passed, 0 failed** | ~2.7 s |

### The golden end-to-end scenario — PASS

Executed from an empty database through the real router and the real middleware
stack: bootstrap status reports uninitialised → ROOT created → **second bootstrap
refused with `SYSTEM_ALREADY_INITIALIZED`** → login returns `mfa_required` →
**the MFA-pending session is refused on `/users` and `/projects` with
`MFA_REQUIRED`** → TOTP enrolment and activation → recovery codes issued → full
authentication → `/auth/me` confirms `is_root` and `mfa_pending = false` →
**simulated process restart** → the session still resolves, proving authoritative
state is in the database → **audit chain verifies intact** → exactly one ownership
row remains.

The scenario additionally asserts that the stored password is an Argon2id PHC
string containing no plaintext, and that neither the bootstrap secret nor the
password appears anywhere in the audit log.

### Bootstrap race — PASS

**100 simultaneous bootstrap attempts**, released together from a barrier so the
race is genuine rather than a spawn loop that serialises itself. Result: **exactly
one `201`**, 99 refused (`409` where another attempt won, `429` where the per-IP
bootstrap limit refused it first — a hundred simultaneous attempts from one address
*is* an attack). The database holds one ownership row and **one user**, confirming
that every losing transaction rolled back cleanly rather than leaving an orphan.

### Two defects found by these runs and fixed

Both were real, both were found by the tests rather than by reading:

1. **The audit chain never verified.** `entry_hash` covered a nanosecond-precision
   timestamp while PostgreSQL `timestamptz` stores microseconds, so every entry
   reported as tampered the moment it was read back. Fixed by truncating to
   microsecond precision *before* hashing, so the value hashed is exactly the value
   stored. Regression test:
   `audit::tests::timestamps_are_truncated_to_what_postgresql_stores`.

2. **The rate limiter's key table grew without bound.** Eviction only dropped
   buckets idle for over an hour, so a burst of fresh keys — an attacker rotating
   source addresses — evicted nothing. The limiter became exactly the
   memory-exhaustion vector its own comment warned about. Its own test caught it.
   The first fix used least-recently-used eviction, and a second test then showed
   **that was exploitable**: an attacker who exhausted their allowance against an
   account could touch it and then flood `max_keys` newer keys, making the victim's
   drained bucket the oldest and evicting it — resetting the penalty. Final policy
   evicts by *remaining tokens*, so a bucket at zero is the last thing discarded.
   Tests: `the_key_table_is_bounded_under_key_rotation`,
   `an_actively_limited_key_survives_eviction_pressure`,
   `a_saturated_table_degrades_instead_of_refusing_everyone`.

### One contract gap found by review, not by test — and the control added for it

`GET /api/v1/users/{id}/permission-overrides` was implemented and mounted but
declared in neither `ROUTE_TABLE` nor the OpenAPI document. The drift test compares
those two artefacts, so a route absent from **both** was invisible to it.

Fixed by declaring the route, and a new control was added so the class of problem is
caught in future: `routes::tests::every_catalogued_permission_is_either_routed_or_knowingly_reserved`
fails if any catalogued permission has no route, unless it is explicitly listed as
knowingly reserved or as dynamically enforced. It immediately surfaced four cases —
three genuinely reserved (`iam.users.create`, `iam.sessions.read`,
`iam.sessions.revoke`) and one, `settings.security.write`, that is enforced *after*
the target row is loaded because the requirement depends on that row's
`is_security_sensitive`. Both categories are now named in the test with reasons.

**Residual risk, stated plainly:** the drift test still cannot see a route that
exists in the axum router but in neither the table nor the spec. Enumerating axum's
live route table is not supported by the framework. The mitigation is the review that
found this one; a source-scanning test over each module's `routes.rs` would close it
properly and is recorded as deferred work.

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

## 13. Known blocked items

| Item | Status | Reason | Command to run later |
| --- | --- | --- | --- |
| `cargo fuzz` targets | **BLOCKED** | Requires a nightly toolchain and `cargo install`, which the host's Application Control policy prevents; the container can install it but nightly is not present in `rust:1-bookworm` | `docker run --rm -v ...:/work -w /work rustlang/rust:nightly bash -c "cargo install cargo-fuzz && cargo fuzz run <target>"` |
| OWASP ZAP baseline scan | **BLOCKED** | Not attempted; would require running the API and a ZAP container. Recorded rather than skipped silently. Note that a passing ZAP baseline would say very little here — the interesting surface is authenticated authorisation logic, which ZAP does not exercise | `docker run --rm -t ghcr.io/zaproxy/zaproxy zap-baseline.py -t http://host:8090/api/v1` |
