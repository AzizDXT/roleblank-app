# RoleBlank OS — Backend Implementation Report

**Date:** 2026-08-07 · **Scope:** `backend/`, `api/`, `ops/`, `scripts/`, `.github/`
**Companion documents:** `00-reconnaissance.md` … `12-future-storage.md`, `MODULE_GUIDE.md`, `ADR-001` … `ADR-006`, `SECURITY_TEST_REPORT.md`

Every count below was obtained by reading or grepping the repository, not estimated. Every test result is either quoted from `SECURITY_TEST_REPORT.md` — which records only executed runs — or explicitly marked as written but not yet executed end to end.

---

## 1. Executive summary

RoleBlank OS is an internal company operating system. What exists today is its backend: one Rust binary over one PostgreSQL 18 database, implementing identity, authentication, authorisation, company structure, projects and tasks, a read-only client portal, settings, and an append-only audit log with a keyed hash chain.

| Measure | Value | Source |
| --- | --- | --- |
| Rust source files in `backend/src` | 98 (35 437 lines) | `find` + `wc -l` |
| Integration test files in `backend/tests` | 10 (2 898 lines) | same |
| Migrations | 9 (1 414 lines) | `backend/migrations/*.sql` |
| Tables created | 31 | `CREATE TABLE` across all migrations |
| Database triggers | 24 | `CREATE TRIGGER` across all migrations |
| Endpoints in `ROUTE_TABLE` | 93 | `backend/src/routes.rs` lines 58–182 |
| OpenAPI path items / operations | 74 / 93 | `api/openapi.yaml` (5 139 lines) |
| Permissions in `catalog::PERMISSIONS` | 42 | `modules/authorization/catalog.rs` |
| Permissions seeded in SQL | 42 | `migrations/0008_seed_catalog.sql` |
| Test attributes in `backend/src` | 576 | `#[test]` / `#[tokio::test]` |
| Test attributes in `backend/tests` | 55, of which 4 are `#[ignore]`d benchmarks | same |
| Resolved crates | 256 | `Cargo.lock` |

**Executed and observed:** 20 database-level invariant attacks run as the schema owner, 14 privilege-escalation attempts run as the runtime database role, and scoped `cargo test --lib` runs covering cryptography, the authorisation evaluator, configuration fail-closed behaviour, rate limiting, trusted-proxy handling and audit-chain integrity. All are recorded with their observed output in `SECURITY_TEST_REPORT.md`.

**Not yet executed end to end:** the golden scenario, the three automated security suites, the bootstrap race suite, the OpenAPI drift test, the supply-chain and lint gates, coverage, and every benchmark. Sections 11 and 13 state this plainly and give the commands.

No claim is made that this system is "production secure", "fully OWASP compliant" or free of vulnerabilities. The claims made are narrow and each names its evidence.

---

## 2. Architecture implemented

A **modular monolith** (ADR-001): one binary `roleblank-api`, one database, module boundaries enforced by Rust visibility. No microservices, no broker, no Redis, no secondary store.

Requests flow strictly downward; no layer reaches around the one below it.

| Layer | Location | Responsibility |
| --- | --- | --- |
| HTTP transport | `platform/http`, `modules/*/routes.rs` | parse, bound, delegate — never a business rule |
| Application service | `modules/*/service.rs` | transaction boundary, authorisation call, audit emission |
| Domain / policy | `modules/authorization` | pure, synchronous, testable without a database |
| Repository | `modules/*/repo.rs` | explicit SQLx, explicit columns, parameterised binds |
| PostgreSQL | `migrations/` | constraints, triggers, privilege separation |

The transaction boundary sits in the service layer deliberately: an authorisation decision depending on database state must be made *inside* the transaction that mutates that state, or the check and the write straddle a window in which the world changed (TH-43).

Twelve business modules are declared in `src/modules/mod.rs` — `audit`, `authentication`, `authorization`, `bootstrap`, `clients`, `departments`, `identity`, `outbox`, `projects`, `settings`, `system`, `tasks` — and six platform modules in `src/platform/mod.rs`: `config`, `crypto`, `database`, `errors`, `http`, `observability`. `shared/` carries pagination, cursors, validation and `Secret<T>`. Two directories exist but are empty and undeclared: `src/modules/users/` and `src/platform/security/` (see section 14).

Deliberately not abstracted: no generic `Repository<T>`, no ORM, no policy DSL, no DI container. `AppState` is a plain struct of `Arc`s. The two traits that do exist — `RateLimiter` and `MailProvider` — exist because both have a known second implementation (Redis; SMTP) and the call sites must not change when it arrives.

Concurrency: Tokio multi-threaded runtime; the outbox worker is a supervised in-process task claiming rows with `FOR UPDATE SKIP LOCKED`; password hashing is semaphore-bounded so Argon2id's memory cost cannot become a self-inflicted denial of service; shutdown drains in-flight requests, cancels the worker, then closes the pool. Identifiers are UUIDv7 throughout — time-ordered for index density, 74 bits of randomness so they are not enumerable, and never treated as authorisation.

---

## 3. Database schema

Nine forward-only migrations create 31 tables.

| Migration | Tables |
| --- | --- |
| `0001_system_and_identity` | `system_state`, `system_ownership`, `users`, `credentials` |
| `0002_sessions_and_mfa` | `sessions`, `session_refresh_tokens`, `mfa_factors`, `recovery_codes`, `password_reset_tokens` |
| `0003_authorization` | `permissions`, `roles`, `role_permissions`, `user_role_assignments`, `user_permission_overrides` |
| `0004_company_and_clients` | `departments`, `department_memberships`, `client_accounts`, `client_memberships`, `invitations`, `invitation_roles` |
| `0005_operations` | `projects`, `project_memberships`, `project_client_links`, `tasks`, `task_assignees` |
| `0006_platform` | `system_settings`, `feature_flags`, `idempotency_records`, `outbox_events` |
| `0007_audit` | `audit_events`, `audit_chain_head` |
| `0008_seed_catalog` | seeds 42 permissions, 3 roles, 3 settings, 7 feature flags |
| `0009_runtime_grants` | table-level grants for the runtime role |

Conventions: `uuid` identifiers generated in the application, `timestamptz` in UTC for every instant, `CHECK` constraints on every enumerated column, `version integer` for optimistic concurrency on editable business rows.

**Singletons are enforced by the primary key, not a trigger.** `system_state` and `system_ownership` both use `id boolean PRIMARY KEY DEFAULT true CHECK (id)`, which admits exactly one row forever; a second insert is a primary-key violation.

**No `ON DELETE CASCADE` appears anywhere** — verified by grep over all nine migrations. Every foreign key is `ON DELETE RESTRICT`; lifecycle is `archived` / `revoked` / `removed_at` / `status`, never `DELETE`.

Of the 24 triggers, eleven maintain `updated_at`. The thirteen carrying security meaning:

| Trigger | Invariant |
| --- | --- |
| `trg_system_ownership_immutable` | `UPDATE`/`DELETE` on ownership raise unconditionally |
| `trg_system_ownership_insert_guard` | the owner must be an `INTERNAL` principal |
| `trg_system_state_guard` | initialisation cannot be reverted to `NULL` |
| `trg_users_protect_root` | the owner cannot be deleted, made non-`ACTIVE`, converted to `CLIENT`, or have `mfa_required` cleared |
| `trg_role_assignment_principal_match` | a role's `allowed_principal_type` must match the subject |
| `trg_role_permission_envelope` | an `INTERNAL`-only permission cannot be attached to a `CLIENT` role |
| `trg_override_envelope` | an `ALLOW` override of an `INTERNAL`-only permission cannot target a `CLIENT` |
| `trg_department_memberships_internal_only`, `trg_project_memberships_internal_only`, `trg_task_assignees_internal_only` | these tables admit `INTERNAL` principals only |
| `trg_client_memberships_client_only` | client accounts admit `CLIENT` principals only |
| `trg_projects_manager_internal`, `trg_client_accounts_manager_internal` | managers must be `INTERNAL` |
| `trg_audit_events_append_only`, `trg_audit_events_no_truncate` | `UPDATE`, `DELETE` and `TRUNCATE` on audit rows all raise |
| `trg_audit_chain_head_guard` | the chain head cannot move backwards |

---

## 4. Authentication model

`Authorization: Bearer <opaque-token>` and nothing else — no cookies, no query parameters, no basic auth (ADR-002).

| Element | Implementation |
| --- | --- |
| Token material | 32 bytes from `OsRng`, base64url unpadded, prefixed `rb_at_` / `rb_rt_` |
| Token at rest | SHA-256 digest only; plaintext never reaches the database, a log, a metric label or a URL |
| Lifetimes | access 15 min; idle 7 days rolling; absolute 30 days, **unextendable by refresh** |
| Refresh | rotated unconditionally; consumed generations retained in `session_refresh_tokens` |
| Reuse detection | a hit on a consumed refresh row revokes the whole session family and audits it |
| Password hashing | Argon2id, m = 19 456 KiB, t = 2, p = 1, 16-byte salt, PHC-encoded |
| Hashing concurrency | semaphore-bounded, default `min(cpu, 8)` |
| Second factor | TOTP (RFC 6238), HMAC-SHA1, 6 digits, 30-second step, ±1 step window |
| TOTP secret at rest | XChaCha20-Poly1305, 24-byte random nonce, stored `key_version`, user id as associated data |
| Replay defence | `mfa_factors.last_used_step` rejects any code at or below the highest already accepted |
| Recovery codes | 10 × 20 random bytes, shown once, stored as SHA-256, single use |

Login is enumeration-resistant by construction: an unknown account still performs a full Argon2id verification against a fixed dummy hash, and every failure mode — unknown account, wrong password, suspended user, expired token, revoked session, malformed header — returns the single `AUTHENTICATION_FAILED` error.

**`pending_mfa` is what makes MFA non-bypassable.** Such a session is real, but `ROUTE_TABLE` marks exactly six paths `MfaPending`-reachable (`/auth/me` plus five `/auth/mfa/*`), and a unit test in `routes.rs` asserts the pending surface never grows beyond those and never contains a non-MFA path. Everything else returns `403 MFA_REQUIRED`.

**Step-up** is `sessions.mfa_verified_at` recency. Twelve routes carry `step_up = true` (counted by grepping `ROUTE_TABLE` for a trailing `true`): role create/update/delete, role assign/unassign, permission-override create/delete, project–client link/unlink, MFA disable, recovery-code regeneration, and audit verification. A `routes.rs` test asserts that every route exercising an `is_dangerous` permission also carries step-up.

---

## 5. ROOT ownership protection

System ownership is asset A1. It is a singleton row in `system_ownership` — **not a role, not a flag, not a permission** (ADR-004) — established once at bootstrap and immutable through every runtime path, defended at four independent points.

| Point | Control |
| --- | --- |
| Schema | `id boolean PRIMARY KEY CHECK (id)` admits one row forever; a second insert is a PK violation |
| Triggers | `trg_system_ownership_immutable` raises on `UPDATE`/`DELETE` with no actor-dependent branch; `trg_users_protect_root` refuses to delete the owner, to set their status to anything but `ACTIVE`, to change their `principal_type`, or to clear `mfa_required` |
| Grants | the runtime role holds no `DELETE` on `users` at all, and no `UPDATE`/`DELETE` on `system_ownership` |
| Application | `state.guard_root(...)` refuses any authorisation operation targeting the owner; no ownership-transfer endpoint exists |

The evaluator returns `Allow(RootOwnership)` for the owner — the single bypass in the system, and it bypasses **policy only**. It is reached only after a valid, unrevoked, unexpired session belonging to an `ACTIVE` user, with `pending_mfa = false` (ROOT has `mfa_required = true`), with step-up recency where required, after input validation and after rate limiting. ROOT actions are audited exactly like everyone else's. ROOT is never locked out by failed authentication: throttling with backoff, never a lockout state, because an attacker able to disable the owner by submitting bad passwords would have disabled the company.

Ownership recovery is an offline, change-controlled procedure (`08-operations.md` §6) requiring a superuser, a stopped service and two recorded people. It deliberately leaves a permanent break in the audit chain at the recovery entry, so a later auditor can distinguish a documented recovery from an attack.

**Executed evidence.** Twenty attacks were run directly against PostgreSQL as the *schema owner* — more privilege than the application ever holds — and all twenty were refused (`SECURITY_TEST_REPORT.md` §2, DB-01 … DB-20). Final state: `ownership_rows = 1`, owner `ACTIVE`, `mfa_required = true`, `suspended_users = 0`. DB-09, a bulk `UPDATE users SET status='SUSPENDED'` that swept up the owner, was aborted at statement level with **zero** users suspended — no partial application.

---

## 6. Authorization model

**Deny unless explicitly allowed** (ADR-003). Every authenticated route declares a required permission; every route touching an identified resource performs a second, object-level decision after the row is loaded. There is no route that is merely "authenticated".

Four layers: **envelope** (principal type against `permission.max_principal_type`, checked before any grant is looked up) → **policy** (deny-by-default evaluation of roles plus per-user overrides) → **object** (does a granted scope cover *this* row?) → **visibility** (for `CLIENT` principals the repository query itself carries the predicate, so an invisible row is never selected).

### Catalogue

42 permissions across 8 modules, counted in both `catalog.rs` and `0008_seed_catalog.sql`. A startup check refuses to boot on divergence in either direction: a code-only permission silently breaks a feature, a database-only permission is an ungoverned grant.

| Attribute | Count | Members |
| --- | --- | --- |
| `is_dangerous = true` | 5 | `iam.permissions.delegate`, `iam.roles.assign`, `iam.sessions.revoke`, `projects.clients.share`, `settings.security.write` |
| `max_principal_type = ANY` | 2 | `client.portal.projects.read`, `client.portal.tasks.read` |
| `max_principal_type = INTERNAL` | 40 | everything else |

### Scopes and delegation

Five closed scopes, no scripting language: `GLOBAL`, `DEPARTMENT`, `ASSIGNED`, `SELF`, `RESOURCE(type, id)`. Roles may carry the first four; user overrides may additionally carry `RESOURCE`. `Target::Collection` is covered **only** by `GLOBAL` — any narrower scope turns listing into a filtered query rather than a permitted one, which is why listing is "permission gate plus scope-derived SQL predicate" and never "fetch all, filter in Rust".

Scopes are **not** totally ordered. `DEPARTMENT` and `ASSIGNED` are incomparable: an actor bounded by their department must not be able to mint `ASSIGNED` authority, because the grantee could be assigned to a project in another department. The lattice is `GLOBAL → {GLOBAL, DEPARTMENT, ASSIGNED, SELF, RESOURCE}`, `DEPARTMENT → {DEPARTMENT, SELF}`, `ASSIGNED → {ASSIGNED, SELF}`, `SELF → {SELF}`, `RESOURCE(t,id) → RESOURCE(t,id)`. Every other pair is denied.

Six further hard rules, each tested by name: no modification of a system role; no assignment of a role containing any permission the actor cannot itself delegate at that permission's scope (checked per permission, not per role); no self-targeted override at all; no authorisation operation targeting ROOT; no role whose `allowed_principal_type` conflicts with the subject; symmetric authority for adding and removing a `DENY`.

### No administrative bypass, and no cache

There is deliberately no `if user.is_admin { allow }`. The built-in `system_administrator` role withholds `iam.permissions.delegate` and `settings.security.write` — ROOT grants those deliberately. `employee` is `SELF` / `DEPARTMENT` / `ASSIGNED` only; `client_user` holds the two portal permissions at `ASSIGNED` and nothing else.

Effective permissions are recomputed from two indexed queries on every request that needs them. `users.security_version` is bumped on every privilege change so a future cache would have a correct invalidation key — but stale authority is a security bug, and no cache is introduced before a measurement demands one.

`404` versus `403`: a `CLIENT` requesting an invisible object or an internal-only route receives `404` (a `403` would confirm existence across the trust boundary); an `INTERNAL` principal lacking a permission inside the company receives `403`; anything targeting ROOT receives `403 ROOT_PROTECTED`. The rule is implemented once, in `AppError::for_principal`.

---

## 7. Client isolation model

The internal/external boundary is asset A4 — a leak breaches a third party's confidentiality and other clients' as well. It is enforced three times, independently.

**Envelope (code).** `catalog::envelope_permits` denies before any grant is collected. Only the two `client.portal.*` permissions carry `max_principal_type = ANY`; a `CLIENT` principal cannot hold any of the other 40 regardless of what roles or overrides are attached.

**Predicate (SQL).** Every query serving a `CLIENT` principal carries the visibility join directly:

```sql
EXISTS (SELECT 1
          FROM project_client_links pcl
          JOIN client_memberships cm ON cm.client_account_id = pcl.client_account_id
          JOIN client_accounts    ca ON ca.id = pcl.client_account_id
         WHERE pcl.project_id = p.id
           AND pcl.revoked_at IS NULL
           AND cm.user_id = $uid
           AND cm.status  = 'ACTIVE'
           AND ca.status  = 'ACTIVE')
```

A task additionally requires `t.client_visible = true`. Two consequences that are easy to get wrong: **sharing a project does not share its tasks** (`client_visible` defaults to `false`, is per-task, and must be set by an internal principal), and **revoking a link removes visibility on the very next query**, with no cache to invalidate.

**Triggers (database).** `trg_role_assignment_principal_match`, `trg_role_permission_envelope`, `trg_override_envelope`, and the four membership triggers that refuse a `CLIENT` in a department, project or task-assignee table and refuse an `INTERNAL` user in a client account. DB-11 … DB-15 in `SECURITY_TEST_REPORT.md` §2 record these as executed and refused.

The portal surface is four routes, all `GET`, all declaring a `client.portal.*` permission; a `routes.rs` test asserts both properties, so a mutating portal endpoint cannot be added by accident. Response shape is separated at the type level: `ClientProjectResponse` is a distinct struct whose internal fields are *physically absent*, not skipped during serialisation.

---

## 8. Implemented API modules

93 endpoints, counted from `ROUTE_TABLE`. Twelve are anonymous, six are reachable by an MFA-pending session, and the remaining 75 require a fully authenticated session.

| Group | Endpoints | Notes |
| --- | --- | --- |
| Health and platform | 3 | `/health/live`, `/health/ready`, `/metrics` — anonymous by necessity |
| Bootstrap | 2 | anonymous, rate limited; `status` reveals only a boolean |
| Authentication | 10 | login, refresh, logout, logout-all, me, session list/revoke, password change, reset request/confirm |
| MFA | 6 | TOTP setup/activate/verify, recovery verify/regenerate, disable |
| Registration and invitation acceptance (anonymous) | 3 | registration config, registration, invitation accept |
| Users | 6 | list, read, update, suspend, reactivate, archive |
| Invitations (authenticated) | 3 | list, create, revoke |
| Roles and permissions | 12 | catalogue, role CRUD, role assignment, user permissions, overrides |
| Departments | 8 | CRUD, archive, membership management |
| Client accounts | 9 | CRUD, archive, membership management with explicit activation |
| Projects | 12 | CRUD, archive, membership, client links, project task listing |
| Tasks | 7 | CRUD, assignees |
| Client portal | 4 | read-only projections of projects and tasks |
| Settings and flags | 5 | settings, feature flags, system info |
| Audit | 3 | list, read, verify |

The anonymous surface is **pinned by an equality assertion** in `routes.rs`: adding to it fails the build unless the list is edited deliberately. Further `routes.rs` tests assert that no anonymous route declares a permission or step-up, that no `GET` declares a write permission, that every declared permission exists in the catalogue, that no route is registered twice, and that path patterns use `{name}` placeholders rather than concrete ids (unbounded metric label cardinality otherwise).

The contract is a hand-authored OpenAPI 3.1 document with a drift test (`tests/openapi_contract.rs`) asserting it describes exactly the `(method, path)` pairs the router serves. Nine `.http` collections live in `api/requests/`, including `99-attack-probes.http`.

---

## 9. Security controls

| Area | Control | Where |
| --- | --- | --- |
| Password hashing | Argon2id 19 MiB / t=2 / p=1, PHC, per-password salt | `platform/crypto/password.rs` |
| Tokens | 32 bytes `OsRng`, SHA-256 at rest, constant-time digest compare | `platform/crypto/tokens.rs` |
| Encryption at rest | XChaCha20-Poly1305, 192-bit random nonce, `key_version`, AAD binds ciphertext to its row | `platform/crypto/aead.rs` |
| TOTP | RFC 6238 over RustCrypto `hmac` + `sha1` | `platform/crypto/totp.rs` |
| Audit chain | HMAC-SHA256 over a length-prefixed canonical encoding | `modules/audit/chain.rs` |
| Secret hygiene | `Secret<T>`: no `Display`, no `Serialize`, redacting `Debug`, zeroised on drop | `shared/secret.rs` |
| Body limit / timeouts | 256 KiB body; 30 s request; 15 s statement; 30 s idle-in-transaction | `platform/http`, `platform/database` |
| Pagination | keyset, never `OFFSET`; default 25, max 100 | `shared/pagination.rs` |
| Sorting | compile-time allowlist returning `&'static str` | `PageRequest::resolve` |
| Mass assignment | `#[serde(deny_unknown_fields)]` on every request DTO | all `dto.rs` |
| Content type | `application/json` only; form and multipart refused | `platform/http/extract.rs` |
| Rate limiting | token bucket, layered per IP / account / session, bounded key table | `platform/http/rate_limit.rs` |
| Trusted proxies | `X-Forwarded-For` honoured only from configured CIDRs; **rightmost** entry taken | `platform/config/net.rs` |
| Idempotency | `Idempotency-Key` scoped by principal + operation + body fingerprint | `modules/outbox/idempotency.rs` |
| Log sanitisation | control characters and U+2028/U+2029 folded; length-bounded on a character boundary | `platform/observability/sanitize.rs` |
| Errors | RFC 9457 `application/problem+json`, stable `code`, fixed driver-error classification | `platform/errors` |
| Memory safety | `#![forbid(unsafe_code)]` at the crate root | `src/lib.rs` line 1 |

Two key-management rules are worth restating: the AEAD key and the audit-chain key **must differ**, and identical values are refused at startup; and every ciphertext stores its `key_version`, so the master key rotates without eager re-encryption.

Production startup refuses to bind a port on any of eleven conditions — wildcard or non-`https` CORS origin, non-`https` or localhost base URL, all-zero or placeholder key, identical keys, short bootstrap secret, a privileged database role in `DATABASE_URL`, `sslmode=disable`, sub-OWASP Argon2 parameters, exposed OpenAPI, text logs, or a development mail sink. All problems are reported together, not one per restart. `roleblank-api check-config` runs the same validation as a deploy gate.

Supply chain: 256 crates, `Cargo.lock` committed, no git or wildcard dependencies. `deny.toml` treats advisories and unknown sources as hard failures, allowlists licences, and bans `openssl`, `openssl-sys`, `native-tls`, `chrono`, `md-5`, `sha-1`, `duct` and `subprocess`, each with a stated reason.

Attack classes absent by construction, each recorded as a decision rather than an oversight: SSRF (zero outbound HTTP requests; no HTTP client crate linked), command injection (no subprocess spawn), path traversal (no filesystem path accepted, no static file served), file upload (no upload endpoint), XXE (no XML parser linked), CSRF (header-only authentication, cookies never read, form and multipart refused), unsafe deserialisation (closed structs only).

---

## 10. Audit design

The audit log is asset A5. The claim made is **tamper-evidence**, not tamper-proofing (ADR-006), and the boundary of that claim is stated below.

1. **No mutating surface.** Three audit endpoints exist, all `GET`. No update, no delete, no bulk operation, no administrative escape hatch.
2. **Triggers.** `trg_audit_events_append_only` raises on `UPDATE` and `DELETE`; `trg_audit_events_no_truncate` is statement-level, because row triggers do not fire on `TRUNCATE`.
3. **Privilege separation.** The runtime role holds `SELECT, INSERT` on `audit_events` and nothing else, and does not own the table, so it cannot `ALTER TABLE … DISABLE TRIGGER`.
4. **Keyed hash chain.** `entry_hash = HMAC-SHA256(chain_key, canonical(prev_hash ‖ seq ‖ id ‖ occurred_at ‖ actor ‖ action ‖ target ‖ outcome ‖ metadata))`, length-prefixed so field boundaries cannot be shifted. Appends serialise on `SELECT … FROM audit_chain_head FOR UPDATE` inside the writing transaction, which is what makes the chain well-defined under concurrency. The chain key lives **outside** the database.

Every state change writes its audit event **inside the same transaction** as the mutation, via `state.audit(&mut tx, event)`. Denied attempts at sensitive operations are audited with `Outcome::Denied`. Metadata is a closed builder that refuses secret-bearing keys. `modules/audit/mod.rs` defines 63 action-code constants.

**The claim, stated narrowly.** The chain detects modification, deletion or reordering performed *without* the chain key. It is explicitly **not** a claim of tamper-proofing against an adversary holding both the database and the key (RR-1, RR-2). If one person holds both, the tamper-evidence claim is void — not weakened, void. That is why `08-operations.md` §5 requires the key to be stored where the database administrator cannot reach it, and §9 requires the verified head `seq` and hash to be exported daily to a location they cannot write.

---

## 11. Tests executed

Everything here is quoted from `SECURITY_TEST_REPORT.md`, which records only runs whose output was observed. Nothing has been upgraded from "written" to "passed".

### Executed and observed

| Suite | Method | Result as recorded |
| --- | --- | --- |
| Database invariants, as **schema owner** | direct SQL | 20 of 20 attacks refused (DB-01 … DB-20); final state 1 ownership row, owner `ACTIVE`, `mfa_required = true`, 0 suspended users |
| Privilege separation, as **runtime role** | direct SQL as `roleblank_app` | 14 of 14 attempts refused (RT-01 … RT-14); role verified `rolsuper = false`, `rolcreatedb = false`, `rolcreaterole = false`, owns 0 tables |
| Cryptography | `cargo test --lib` | 56 of 56 passed, including the RFC 6238 Appendix B vectors at six values of *t* |
| Authorisation | `cargo test --lib` | 128 of 128 passed — 114 example-based plus 14 property tests at 2 048 cases each, ≈ 28 000 generated scenarios |
| Configuration fail-closed | `cargo test --lib platform::config` | all passed |
| Rate limiting | `cargo test --lib platform::http::rate_limit` | all passed, including 50 concurrent requests against a quota of 10 letting exactly 10 through |
| Trusted proxy handling | `cargo test --lib platform::config::net` | all passed |
| Audit integrity | `cargo test --lib modules::audit` | all passed, including 10 distinct single-field mutations, deletion, reordering, splicing, tail truncation, and a forgery rebuilt with the wrong key |
| Input handling and injection | `cargo test --lib` | PASS recorded for SQL-injection-via-sorting, log injection, oversized and malformed cursors, pagination abuse, mass assignment, request-id poisoning |

Two real defects were found *by* these runs and fixed, both recorded rather than quietly corrected: the privileged-database-role check used a substring match on `"postgres:"` that also matched the URL scheme `postgres://` and would have rejected every valid production configuration; and DB-20 was initially inconclusive because the probe SQL used an invalid `bytea` literal, so the statement matched zero rows rather than being refused — re-run correctly, the trigger fired. Two RFC 6238 constants were also found mis-transcribed in the *test table*, not in the implementation.

### Written but **not yet executed** end to end against PostgreSQL

These compile as part of the crate but their full run against a live database had not completed when this report was written. **They are not PASS.**

| Suite | File | Test functions | Command |
| --- | --- | --- | --- |
| Golden end-to-end scenario | `tests/golden_scenario.rs` | 1 | `cargo test --test golden_scenario` |
| Database invariants (automated) | `tests/security/database_invariants.rs` | 16 | `cargo test --test security_suite database_invariants` |
| Runtime-role privilege separation (automated) | `tests/security/runtime_role.rs` | 7 | `cargo test --test security_suite runtime_role` |
| Attack probes | `tests/security/attack_probes.rs` | 16 | `cargo test --test security_suite attack_probes` |
| Bootstrap race (100 concurrent) | `tests/race/bootstrap.rs` | 6 | `cargo test --test race_suite` |
| OpenAPI contract drift | `tests/openapi_contract.rs` | 5 | `cargo test --test openapi_contract` |

The automated `database_invariants` and `runtime_role` suites cover the same ground as the interactive SQL runs above: the interactive runs are the executed evidence, these are its regression form.

The golden scenario as written covers steps 1–6 and 30–33 of the brief's scenario: an empty database, uninitialised bootstrap status, ROOT creation, a refused second bootstrap, mandatory MFA enrolment with recovery codes, full ROOT authentication, audit accumulation, survival of a **server restart**, and a whole-chain verification at the end. Steps 7–29 are not present in that file; the behaviour they describe is covered by module-level tests rather than by this single scenario.

Also not yet executed: `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo audit`, `cargo deny check`, `cargo llvm-cov --summary-only`.

### Blocked, with the reason recorded

| Item | Reason | Command for later |
| --- | --- | --- |
| `cargo fuzz` | Needs a nightly toolchain and `cargo install`; the host's Application Control policy blocks freshly compiled binaries and `rust:1-bookworm` carries no nightly | `docker run --rm -v ...:/work -w /work rustlang/rust:nightly bash -c "cargo install cargo-fuzz && cargo fuzz run <target>"` |
| OWASP ZAP baseline | Not attempted; recorded rather than skipped silently. A passing baseline would say little here — the interesting surface is authenticated authorisation logic, which ZAP does not exercise | `docker run --rm -t ghcr.io/zaproxy/zaproxy zap-baseline.py -t http://host:8090/api/v1` |

### Inventory

576 test attributes exist in `backend/src` and 55 in `backend/tests`. The largest concentrations are `modules/authorization` (96), `modules/projects` (46), `modules/authentication` (44), `modules/audit` (43), `modules/outbox` (42), `modules/identity` (40) and `platform/crypto` (38). These are counts of test functions present, **not** a claim that all of them have been run.

---

## 12. Security tooling results

| Tool | Configured where | Status |
| --- | --- | --- |
| `cargo fmt --check` | `Makefile: lint`, CI `quality` job | configured, **not yet run** |
| `cargo clippy --all-targets --all-features -- -D warnings` | same | configured, **not yet run** |
| `cargo audit` | `Makefile: audit`, CI `supply-chain` job | configured, **not yet run** |
| `cargo deny check` | `Makefile: deny`, `deny.toml` (107 lines) | configured, **not yet run** |
| `cargo llvm-cov --summary-only` | `Makefile: coverage` | configured, **not yet run** |
| `cargo fuzz` | — | **BLOCKED** (section 11) |
| OWASP ZAP baseline | — | **BLOCKED**, not attempted |

`.github/workflows/backend-ci.yml` (244 lines) defines three jobs: `quality` (fmt, clippy, build); `test`, which provisions the two database roles from `ops/sql/provision_ci.sql`, runs `migrate` as the migrator role, then `cargo test --locked --all-features` against `postgres:18.4-alpine`; and `supply-chain` (`cargo audit`, `cargo deny check`). The supply-chain job is deliberately not `continue-on-error`: a known-vulnerable dependency is a build failure, and an advisory judged inapplicable must be recorded in `deny.toml` where it is reviewable rather than by weakening the gate. A fourth manual-only job (fuzz / mutation testing / load test) is present but commented out.

The CI database is published on `127.0.0.1` via `--publish` rather than the `ports:` key, because `ports:` binds `0.0.0.0` on the runner — this project never publishes PostgreSQL on `0.0.0.0` anywhere, not even on a machine destroyed ten minutes later. Every credential in the workflow is a labelled CI-only placeholder, and the two 32-byte keys decode to human-readable warnings so anyone finding one in a real environment knows instantly that it is wrong.

Two static properties were verified by reading source rather than by a tool: `#![forbid(unsafe_code)]` at `src/lib.rs` line 1, and the absence of `ON DELETE CASCADE` in every migration.

---

## 13. Performance results

**No benchmark run has been completed. This section contains no numbers, because none have been measured.**

Five documents (`03-authentication.md` §6, `04-authorization.md` §11, `05-data-model.md` §10, `08-operations.md` §10, and residual risk RR-6) refer to a `PERFORMANCE_REPORT.md`. **That file does not exist in the repository.** The Argon2 parameters currently defaulted (m = 19 456 KiB, t = 2, p = 1) meet the OWASP floor, but the claim in `03-authentication.md` §6 that they were "benchmarked on this machine" is not supported by any recorded run.

### The measurement harness that exists

`backend/tests/benchmarks.rs`, 335 lines, four `#[ignore]`d measurement functions run deliberately and only in release mode:

```
cargo test --release --test benchmarks -- --ignored --nocapture
```

They are `#[ignore]`d so an ordinary `cargo test` is not slowed, and nothing in the file asserts a threshold — a benchmark that fails CI on a slow runner teaches people to disable benchmarks. Each reports p50, p95, p99, max and mean rather than a mean alone, because a mean hides the tail and the tail is what a user experiences. Each also prints the core count, target architecture, and whether the build is debug, in which case it states that the numbers are meaningless.

| Function | Measures |
| --- | --- |
| `argon2_cost` | Argon2id hash and verify, 30 samples each after a 3-iteration warm-up, then verify at concurrency 1, 4, 8, 16 and 32 to make the bounding semaphore's queueing visible. Also states worst-case resident hashing memory: permits × `m_cost` = 8 × 19 MiB ≈ 152 MiB |
| `token_and_crypto_primitives` | Token generation (10 000 samples), SHA-256 token hashing (100 000), AEAD seal and open (10 000 each), TOTP verify over a 3-step window (10 000) |
| `authorization_evaluation` | The pure evaluator: `evaluate` with all 42 catalogued permissions granted at `GLOBAL` plus 5 resource-scoped denials (100 000 samples), `capability_list` over the whole catalogue (10 000), and the pessimistic out-of-scope denial path (100 000) |
| `audit_chain_hashing` | `chain::entry_hash` — HMAC-SHA256 over the canonical encoding — 100 000 samples |

The file states plainly what it does not measure: the audit chain's real cost is not the hash but the serialisation of appends on `SELECT … FROM audit_chain_head FOR UPDATE`, which must be measured end to end with `scripts/load_test.sh`.

### The environment a measurement would run in

| Item | Value |
| --- | --- |
| Host | Windows 11 Home 10.0.26200 |
| CPU | Intel Core Ultra 9 290HX Plus, 24 cores |
| RAM | 63.4 GB |
| Build and test environment | `rust:1-bookworm` container, rustc 1.97.1 — identical to the host toolchain |
| Database | PostgreSQL 18.4 (`postgres:18.4-alpine`), data checksums enabled, loopback only |

The containerisation is not a preference: the Windows host enforces an Application Control policy that refuses to execute freshly compiled unsigned binaries (`os error 4551`), reproduced twice — under `%TEMP%` and inside the project directory — and documented in `00-reconnaissance.md` §3. Every compile, test and benchmark therefore runs in the container.

---

## 14. Known risks

### Residual risks carried from `02-threat-model.md` §6

| # | Risk | Why it remains | Mitigation in place |
| --- | --- | --- | --- |
| RR-1 | Full host compromise reveals the audit chain key and the AEAD key | Both must be readable by the running process | Keys come from the environment or secret manager, are `Secret<T>`-wrapped and zeroised; the chain is verifiable by an offline holder of the key, which detects tampering performed without it |
| RR-2 | PostgreSQL `SUPERUSER` can disable triggers and rewrite audit rows | Inherent to owning the database | The runtime role is neither owner nor superuser; superuser credentials are not used by the application; chain verification detects the edit afterwards |
| RR-3 | In-process rate limiting is per-instance | Single instance today | `trait RateLimiter` exists; horizontal scaling requires the Redis implementation *before* deployment — recorded as a release gate |
| RR-4 | ROOT is a single point of failure | Deliberate, per the ownership invariant | Ownership replacement is an offline, documented, audited procedure (ADR-004); ROOT cannot be locked out by attacker-driven failures |
| RR-5 | No production email provider | Deferred scope | Reset and invite flows create outbox events and are testable; production refuses to start if a real provider is required but absent — no silent fake success |
| RR-6 | Audit-chain appends are globally serialised | Correctness chosen over throughput | **Not yet measured** — the report it points to does not exist (section 13) |

### Gaps from `09-asvs-review.md`

| # | Gap | Severity | Disposition |
| --- | --- | --- | --- |
| G1 | Inbound TLS is an infrastructure obligation, not application-enforced | Medium | Documented deployment requirement (`08-operations.md` §11) |
| G2 | No phishing-resistant second factor (WebAuthn) | Medium | `mfa_factors.factor_type` already admits a second value; additive change |
| G3 | No anti-automation challenge on registration | Low | Mitigated by the `INVITE_ONLY` default and inert `PENDING` accounts |
| G4 | Keys are environment-supplied, not KMS-backed | Low | Deployment concern; no code change required to adopt one |
| G5 | No regulated erasure workflow | Low–Medium | Deliberate conflict with audit integrity; needs a documented pseudonymisation procedure before any such obligation applies |
| G6 | Rate limiting is per-process | Medium **at scale** | Release gate: the distributed implementation must ship before a second replica does (RR-3) |
| G7 | No production mail provider | Medium | Production fails closed rather than silently dropping mail; onboarding is administrator-driven until it ships |

### RR-7 — cross-module integration paths are under-evidenced

Several modules were written **concurrently, by separate agents**. Each carries its own unit tests and each is internally coherent, but the paths that cross module boundaries — identity → authorisation → audit, projects → clients → portal projection, invitation acceptance → role assignment → delegation guard, mutation → outbox → mail — have unit-test coverage of their ends and **not** end-to-end evidence of their middle. The golden scenario, which is the test that would exercise those paths in one run, has not been executed end to end. This is the largest evidence gap in the current state, and it is why section 21 leads with running that suite.

### Documentation drifts found while writing this report

None is a security defect on its own, but each would mislead a reader who trusted the document.

| Drift | Detail |
| --- | --- |
| `PERFORMANCE_REPORT.md` | Referenced by five documents and by `benchmarks.rs`; the file does not exist |
| `platform::security::step_up::STEP_UP_OPERATIONS` | Named by `03-authentication.md` §8. `src/platform/security/` is an empty directory, `platform/mod.rs` declares no `security` module, and no `STEP_UP_OPERATIONS` symbol exists. Step-up *is* implemented — through `AppState::require_step_up` / `require_step_up_for` and the `step_up` flag on `ROUTE_TABLE` |
| Empty `src/modules/users/` | Present on disk, not declared in `modules/mod.rs`; user management lives in `modules/identity` |
| Endpoint count | `01-architecture.md` §7 says "~70 endpoints"; `ROUTE_TABLE` holds 93 |
| Step-up window | `03-authentication.md` §8 says 600 s default, configurable 300–900; `06-security-controls.md` §3 says a 60–1800 s configurable window |
| Threat-model test names | `02-threat-model.md` §4 names tests such as `root_attack_suite`, `client_escape_suite`, `bola_suite`, `delegation_suite`. The actual functions are named differently (for example `the_owner_cannot_be_deleted_suspended_archived_or_demoted`). The coverage largely exists; the names in the matrix are not resolvable by grep |

---

## 15. Deferred work

Stated as absences, not as a roadmap. Nothing below is partially built, and nothing below should be assumed to work.

| Deferred | What is absent | Consequence today |
| --- | --- | --- |
| **Production mail provider** | No SMTP or transactional-mail integration; `trait MailProvider` and the outbox exist, a real implementation does not | Password reset and invitation emails are **not delivered**. Production refuses to start with a development sink; `RB_MAIL_PROVIDER=disabled` acknowledges this and makes those flows fail loudly. Onboarding must be administrator-driven |
| **Distributed rate limiting** | No Redis implementation of `trait RateLimiter` | Single replica only; a second replica silently multiplies every quota by the replica count (RR-3, G6) |
| **File storage** | No upload, download or presign endpoint; no object-store client | The entire ASVS V5 chapter is unreachable. `12-future-storage.md` records the controls required before any of it ships |
| **Realtime / chat** | No WebSocket or SSE surface | Design recorded in `11-future-realtime.md` |
| **AI / MCP** | No agent surface; the `ai.assistant` flag is off and **is not an access control** | `10-future-ai-mcp-security.md` records the constraint that an agent gets a principal with permissions, never database credentials and never ROOT |
| **WebAuthn** | Not implemented; `mfa_factors.factor_type` admits only `'TOTP'` today | TOTP is the only second factor (G2) |
| **CRM, finance, approvals** | Not built at all — no tables, no modules, no endpoints | Out of scope for this phase |
| **Department hierarchy** | No parent/child relation on `departments` | Deliberate: a self-referencing tree brings cycle prevention, transitive visibility and recursive authorisation with it. Adding it later is an additive migration |
| **Permission caching** | None | Every request recomputes effective permissions from two indexed queries |
| **SSO / OAuth / OIDC** | No such surface | ASVS V10 not applicable today |

---

## 16. Operational commands

Windows developers use `scripts/rb.ps1`, which wraps the same commands in the `rust:1-bookworm` container and echoes every `docker run` it performs. Linux, macOS and CI use the `Makefile`.

| Task | `scripts/rb.ps1` | Make |
| --- | --- | --- |
| Start / stop the development database | `db-up` / `db-down` | `make db-up` / `make db-down` |
| Destroy the volume and start clean | `db-reset` | `make db-reset` |
| Create the migrator and runtime roles | `db-provision` | `make db-provision` |
| Open `psql` | `psql` | — |
| Apply migrations | `migrate` | `make migrate` |
| Debug / release build | `build` / `release` | `make build` / `make release` |
| Run the API | `run` | `make run` |
| All tests | `test` | `make test` |
| Security suites only | `test-security` | `make test-security` |
| Race suites only | — | `make test-race` |
| Lint (fmt + clippy, warnings are errors) | `lint`, `fmt` | `make lint`, `make fmt` |
| Advisories / licence and ban policy | `audit`, `deny` | `make audit`, `make deny` |
| Coverage summary | `coverage` | `make coverage` |
| OpenAPI drift check | — | `make openapi-check` |
| Verify the audit chain | `verify-audit` | `make verify-audit` |
| Shell in the build container | `sh` | — |
| Backup / restore development data | — | `make backup-dev` / `make restore-dev` |
| Load test / everything CI runs | — | `make load-test` / `make ci` |

The binary has four subcommands, parsed in `src/cli.rs`: `serve` (the default), `migrate`, `verify-audit`, `check-config`. Migration is **never** folded into `serve` — implicit migration on startup races every replica of a rolling deploy against the same schema change. `serve` refuses to start when the schema is behind the binary, so the ordering is enforced rather than documented.

Development ports are claimed deliberately, to avoid the containers already running on this machine: **`127.0.0.1:5440`** for PostgreSQL, **`127.0.0.1:8090`** for the API.

---

## 17. How to bootstrap a clean installation

1. **Provision two database roles.** `roleblank_migrator` owns the schema; `roleblank_app` is the runtime identity and owns nothing. Development: `.\scripts\rb.ps1 db-provision` (runs `ops/sql/provision_dev.sql`). Production: adapt that file with real credentials from the secret manager and **without** the `CREATEDB` grant the development migrator has — that exists only so the test harness can create throwaway databases.
2. **Set the secrets.** `RB_ENCRYPTION_KEY` and `RB_AUDIT_CHAIN_KEY`, each 32 bytes base64-encoded and **different from each other**; `RB_BOOTSTRAP_SECRET` of at least 32 characters (`openssl rand -base64 48`); `DATABASE_URL` connecting as `roleblank_app` with TLS, never `sslmode=disable`.
3. **Validate before deploying.** `roleblank-api check-config` runs the same fail-closed validation as startup without binding a port. Use it as a deploy gate.
4. **Apply migrations as the migrator role.** `roleblank-api migrate`. Runtime grants come from `0009_runtime_grants.sql`; default privileges for *future* tables are deliberately not granted, so a new table must be an explicit decision.
5. **Start the API.** `roleblank-api serve`.
6. **Confirm the system is uninitialised.** `GET /api/v1/bootstrap/status` returns `{"initialized": false}` — a boolean and nothing else.
7. **Create the owner.** `POST /api/v1/bootstrap/root` with the bootstrap secret, an email, a display name and a long passphrase. This can succeed at most once in the lifetime of the database.
8. **Complete MFA enrolment immediately.** The owner lands in `MFA_ENROLMENT_REQUIRED`: they can log in, but the session reaches only `/api/v1/auth/mfa/*` until a TOTP factor is activated. **Store the recovery codes offline** — they are displayed once.
9. **Remove `RB_BOOTSTRAP_SECRET` from production configuration.** The endpoint refuses to run again regardless, but a secret with no remaining purpose is pure risk.
10. **Back up the audit chain key separately**, somewhere the database administrator cannot reach. Without it, restored audit history is unverifiable — and if one person holds both, the tamper-evidence claim is void.

---

## 18. How to run locally

```powershell
.\scripts\rb.ps1 db-up            # postgres:18.4-alpine on 127.0.0.1:5440, data checksums on
.\scripts\rb.ps1 db-provision     # create roleblank_migrator and roleblank_app
.\scripts\rb.ps1 migrate          # apply all nine migrations as the migrator
.\scripts\rb.ps1 run              # serve on 127.0.0.1:8090
```

On Linux, macOS or CI: `make db-up && make db-provision && make migrate && make run`.

`docker-compose.dev.yml` (128 lines) brings up the same stack, building the API from `backend/Dockerfile` (136 lines, two stages: a `rust:1-bookworm` builder and a `debian-slim` runtime carrying exactly one binary, the migrations and the CA bundle — a compiler in a runtime image is an attacker's toolbox). The image runs as uid 10001.

In development `.env` is loaded, loopback and RFC1918 proxies are trusted, the OpenAPI document is served and logs are text. In production `.env` is **not read at all**.

**The development compose file is not production orchestration.** Production additionally requires TLS at the edge; `RB_TRUSTED_PROXIES` set to the edge's CIDRs (otherwise every client shares one rate-limit bucket keyed on the proxy address); the database not published on any external interface; secrets injected at runtime rather than baked into an image; a read-only root filesystem with all Linux capabilities dropped; network segmentation; and `/metrics` reachable only from the scraper.

---

## 19. How to run tests

```bash
make test              # cargo test --all-features
make test-security     # cargo test --test security_suite -- --nocapture
make test-race         # cargo test --test race_suite -- --test-threads=1
make openapi-check     # cargo test --test openapi_contract
make lint              # cargo fmt --check && cargo clippy -- -D warnings
make audit && make deny
make coverage          # cargo llvm-cov --summary-only
make ci                # lint build test audit deny openapi-check
```

On Windows: `.\scripts\rb.ps1 test`, `.\scripts\rb.ps1 test-security`, `.\scripts\rb.ps1 lint`, and so on.

Individual suites, for the ones section 11 lists as not yet executed:

```bash
cargo test --test golden_scenario
cargo test --test security_suite database_invariants
cargo test --test security_suite runtime_role
cargo test --test security_suite attack_probes
cargo test --test race_suite
cargo test --test openapi_contract
```

Benchmarks are separate and must be run in release mode:

```bash
cargo test --release --test benchmarks -- --ignored --nocapture
```

All of these require the development database to be up and provisioned. The race suite runs with `--test-threads=1` because it measures concurrency inside the test, not across tests. Debug mode is fine for correctness; Argon2 measurements taken in debug mode are meaningless, and the harness says so on every run.

---

## 20. How to inspect the API

- **`backend/src/routes.rs`** — the authoritative route table, 93 entries, each carrying method, path pattern, access class (`Anonymous` / `Authenticated` / `MfaPending`), required permission and step-up flag. This is the source of truth and the single place a reviewer can see the whole authenticated surface.
- **`api/openapi.yaml`** — hand-authored OpenAPI 3.1, 74 path items, 93 operations, checked against the route table by `cargo test --test openapi_contract`, so adding an endpoint without documenting it fails the build. `RB_EXPOSE_OPENAPI` serves it in development; production **refuses to start** with it enabled.
- **`api/requests/`** — nine `.http` collections covering bootstrap, auth and MFA, users and invitations, roles and permissions, departments and clients, projects and tasks, the client portal, settings and audit, plus `99-attack-probes.http`.
- **`backend/src/modules/authorization/catalog.rs`** — the 42 permissions with module, principal-type ceiling and dangerous flag. Read it alongside the route table to see what each endpoint actually requires.
- **Errors** — every failure is RFC 9457 `application/problem+json` with a stable machine `code`. Branch on `code`; `title` and `detail` are human text and may be reworded.

---

## 21. What must be reviewed before frontend work begins

Ordered: each item assumes the ones above it are done. Items 1–4 are blocking, because a frontend built against unverified behaviour encodes that behaviour's bugs into its own assumptions.

**Blocking**

1. **Run the full test binary set against PostgreSQL and record the results.** `make db-up && make db-provision && make migrate && make test`, then the six individual commands in section 19. Update `SECURITY_TEST_REPORT.md` §12 with actual outcomes. Until this is done, the golden scenario, all three security suites, the race suite and the OpenAPI drift test are **unverified**.
2. **Exercise the cross-module integration paths (RR-7).** The modules were written concurrently by separate agents. Walk at least these four paths end to end and confirm the audit event, the permission check and the transaction boundary all fire in the right order: (a) invitation created → accepted → roles assigned, with the delegation guard applied *at acceptance*; (b) project created → shared with a client account → the client user sees the project but not its tasks until `client_visible` is set; (c) a role change is reflected on the very next request by that user, with no cached authority; (d) a mutation that enqueues an outbox event — both commit together, or neither does.
3. **Run `make lint`, `make audit` and `make deny`, and fix what they report.** None has been executed. A clippy or advisory finding discovered after the frontend has integrated costs more than one found now.
4. **Verify the OpenAPI document has not drifted** (`make openapi-check`). The frontend will be generated or hand-written against `api/openapi.yaml`; if that disagrees with `routes.rs`, the frontend is being built against a document rather than against the API.

**Before the first authenticated screen is designed**

5. **Decide and record the token-handling contract.** The API is `Authorization`-header only and reads no cookies, so it has no CSRF surface of its own. The moment a BFF introduces a cookie, CSRF becomes the BFF's obligation (`03-authentication.md` §11). Decide now whether the web client is a BFF holding tokens server-side or a direct SPA.
6. **Design for the `pending_mfa` state explicitly.** A successful login can return a session that may call only six endpoints. A frontend assuming "login means authenticated" will render a broken shell. Confirm the six-path list in `ROUTE_TABLE` against what the client will attempt.
7. **Design for step-up, and resolve the window contradiction first.** Twelve routes return `403 STEP_UP_REQUIRED` with a `step_up.window_seconds` hint, and the client must re-prompt rather than give up. `03-authentication.md` §8 says 600 s default, configurable 300–900; `06-security-controls.md` §3 says 60–1800 s. Read the configuration code and correct whichever document is wrong before a client hard-codes either.
8. **Design for `409 VERSION_CONFLICT`.** Every editable resource carries `version`; every update is `WHERE id = $1 AND version = $2`. The client must send the version it read and handle the conflict by re-reading, never by retrying blindly.
9. **Decide the `404` versus `403` behaviour in the UI.** A client principal receives `404` for anything it cannot see, including internal-only routes; an internal principal receives `403`. The same UI code path will see both and must not render "not found" for a permissions problem an administrator could fix.

**Before anything is deployed beyond a single developer machine**

10. **Close the mail gap or accept it in writing.** Password reset and invitation emails are **not delivered** (RR-5, G7). Either ship a provider or agree that onboarding is administrator-driven — and make the frontend say so, rather than showing "check your email".
11. **Honour the horizontal-scaling gate.** Rate limiting is per-process (RR-3, G6). The Redis implementation of `trait RateLimiter` must ship *before* a second replica does.
12. **Confirm TLS termination and `RB_TRUSTED_PROXIES` (G1).** The application does not enforce inbound TLS. If the proxy CIDRs are unset, rate limiting keys on the proxy's address and every client shares one bucket — worse than no rate limiting, because it looks like it is working.
13. **Establish audit-chain key custody.** Store the chain key where the database administrator cannot reach it, schedule `verify-audit` daily, and export the verified head `seq` and hash to a location they cannot write. Without that split, the ADR-006 claim is void.
14. **Test a restore.** A backup that has never been restored is not a backup. Restore to a scratch database, check row counts on `users` and `audit_events`, then run `verify-audit` against the restored copy.

**Housekeeping that will otherwise mislead the next reader**

15. **Resolve the documentation drifts in section 14** — the missing `PERFORMANCE_REPORT.md`, the non-existent `platform::security::step_up` path, the two empty directories, the "~70 endpoints" figure, and the threat-model test names no grep resolves. Either write the code the documents describe or correct the documents.
16. **Run the benchmarks once and write the numbers down** (section 13). The Argon2 cost factor is the single most consequential performance decision in the system, and it is currently defaulted rather than measured: `cargo test --release --test benchmarks -- --ignored --nocapture`.

---

## 22. Final acceptance audit — outcome

Full record: `FINAL_ACCEPTANCE_REPORT.md`. Summary for anyone picking this up.

### Verdict

**BACKEND FOUNDATION READY FOR FRONTEND** — 0 CRITICAL and 0 HIGH open, after
7 HIGH findings were fixed and re-verified.

### State of the tree

| | Value |
|---|---|
| Tests | **1 009 passed, 0 failed** (10 suites) + 4 benchmarks run separately |
| Coverage | 91.31% region / 93.18% function / **93.66% line** |
| Gates | `fmt`, `clippy -D warnings`, `cargo audit`, `cargo deny` — **all PASS** |
| Clean-room | phase 1 and phase 2 (post-restart), **0 failures**, fresh database and secrets |
| Backup/restore drill | all 10 checkpoints PASS; restored state byte-identical including the audit chain head hash |
| Migrations | 10 (0010 added during the audit: the runtime-role grants that made the system bootable) |

### What changed in `src/` during the audit

| Area | Change |
|---|---|
| `migrations/0010` | `GRANT SELECT ON permissions` and `GRANT UPDATE ON audit_events_seq_seq` to the runtime role — **without these the application could not start, and no write could be audited** |
| `identity/invitations.rs` | placement now authorised; inviter's actor loaded before `begin()` to end a pool self-deadlock |
| `departments/service.rs`, `clients/service.rs` | `authorize_placement`; ROOT guard moved after authorisation |
| `departments/repo.rs`, `clients/repo.rs`, `identity/repo.rs` | listings subtract explicit denials from the SQL predicate |
| `platform/http/extract.rs` | shared validated-query extractor (stops six endpoints reflecting caller input) |
| `platform/errors/mod.rs` | `Io`/`Tls`/pool errors → `503`; NUL/invalid-text SQLSTATEs → `400` |
| `platform/observability/sanitize.rs` | truncation marker no longer pushes a value past its length bound |
| `platform/http/rate_limit.rs`, `platform/config/mod.rs` | invitation acceptance no longer shares the registration limiter bucket |
| `tests/common/mod.rs` | template database guarded by a PostgreSQL advisory lock and recreated only when stale |

### The one thing to do first

Wire the general per-principal rate limiter. It is already configured
(`general_per_principal_per_minute`, default 600) and both key builders exist; no
middleware installs it. Until then, any authenticated account can drive unbounded
growth of an append-only table while holding the global audit-chain lock — measured
at 101 rows in 2 seconds with zero `429`s.

**Enabling public self-registration should be gated on that fix.** It is disabled
by default today, and that default is the only thing keeping the issue at MEDIUM
rather than HIGH.

### The lesson worth carrying into the frontend work

622 tests passed against a system that could not boot. The tests connected as the
schema owner; the application runs as a restricted role. Every layer of this
backend was designed correctly and the tests exercised a configuration the product
never uses. When the frontend gets its own test suite, make the first test the one
that runs the real thing, in the real configuration, as the real principal.
