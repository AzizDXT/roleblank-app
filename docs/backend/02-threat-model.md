# 02 — Threat Model

## 1. Assets, ranked

| # | Asset | Why it matters |
| --- | --- | --- |
| A1 | **System ownership (ROOT_OWNER)** | Whoever holds it holds the company OS. Loss is unrecoverable through the application |
| A2 | Authentication credentials & sessions | Gateway to everything else |
| A3 | Authorisation state (roles, permissions, overrides) | Silent escalation is worse than a loud breach |
| A4 | The internal/external (CLIENT) boundary | A leak here is a breach of a third party's confidentiality, and of other clients' |
| A5 | Audit history | The only record of what happened; an attacker who can edit it erases themselves |
| A6 | Business data (projects, tasks, departments, client accounts) | |
| A7 | Secrets at rest (TOTP secrets, encryption key, DB credentials) | |
| A8 | Availability | A company OS that is down stops the company |

## 2. Trust boundaries

```
  ╔═════════════ UNTRUSTED ═════════════╗
  ║ anonymous internet                  ║
  ║ CLIENT principals (external firms)  ║──┐
  ╚═════════════════════════════════════╝  │
                                           │ HTTPS (terminated at the edge proxy)
  ╔═══════ SEMI-TRUSTED ════════════════╗  │
  ║ INTERNAL employees                  ║──┤
  ║ INTERNAL administrators             ║──┤
  ╚═════════════════════════════════════╝  │
                                           ▼
  ╔═══════════════════════════ APPLICATION ════════════════════════════╗
  ║ roleblank-api   — connects as the unprivileged runtime DB role     ║
  ╚════════════════════════════════════════════════════════════════════╝
                                           │
  ╔═══════════════════════════ DATA ═══════════════════════════════════╗
  ║ PostgreSQL — schema owned by a *different* role the app cannot use  ║
  ╚════════════════════════════════════════════════════════════════════╝
```

The three boundaries that must not be crossed by a bug alone:

1. **anonymous → authenticated**
2. **CLIENT → INTERNAL** (the "client envelope")
3. **any principal → ROOT ownership**

Each is defended at two independent layers (application *and* database), so that a single
application defect is insufficient.

## 3. Adversaries

| ID | Adversary | Capability assumed |
| --- | --- | --- |
| T1 | Anonymous internet attacker | Unlimited malformed requests, credential stuffing lists, race harnesses |
| T2 | Malicious CLIENT user | Valid credentials, valid session, full knowledge of the API contract, will guess UUIDs and tamper with every JSON field |
| T3 | Compromised employee account | Valid low-privilege INTERNAL session |
| T4 | Malicious administrator | Broad but *not* unlimited permissions; wants ROOT, or wants to erase audit history |
| T5 | Attacker with a stolen **access** token | Read of a token from a log, a proxy, or a device |
| T6 | Attacker with an old **refresh** token | Exfiltrated backup or an intercepted rotation |
| T7 | Database-read adversary | Stolen dump / read replica access |
| T8 | Operator making a configuration mistake | Wildcard CORS, weak key, debug endpoint left on |
| T9 | Future AI/MCP agent | Runs inside the system; may be prompt-injected |

Explicitly **out of scope** (stated, not hand-waved): full compromise of the production
host with root and the application's own encryption key, malicious infrastructure operator
with `SUPERUSER` on PostgreSQL, and physical attack. Against those, the audit chain is
*tamper-evident to an external verifier holding the chain key offline*, and nothing more.
See `docs/backend/06-security-controls.md` §Audit for the exact, non-inflated claim.

## 4. Threat → control matrix

| ID | Threat | Adversary | Control | Test |
| --- | --- | --- | --- | --- |
| TH-01 | Second ROOT created by racing bootstrap | T1 | Singleton PK on `system_state`/`system_ownership`, `INSERT … ON CONFLICT DO NOTHING` inside a transaction holding a transaction-level advisory lock | `race_bootstrap` (100 concurrent) |
| TH-02 | Bootstrap replayed after initialisation | T1 | `initialized_at IS NULL` guard *inside* the same transaction; endpoint returns 409 forever after | `bootstrap_second_attempt_fails` |
| TH-03 | Bootstrap secret guessed | T1 | ≥32-byte required secret, constant-time compare, rate limited, never logged | `bootstrap_wrong_secret` |
| TH-04 | ROOT deleted / suspended / archived via API | T4 | No delete endpoint; service-layer ROOT guard; **DB trigger** rejects DELETE and any non-`ACTIVE` status on the ROOT row; runtime DB role has **no DELETE grant on `users`** | `root_attack_suite` (12 vectors) |
| TH-05 | ROOT demoted by rewriting `system_ownership` | T4 | Table has no API surface; **DB trigger rejects UPDATE and DELETE unconditionally** | `root_attack_suite` |
| TH-06 | ROOT sessions revoked to lock the owner out | T4 | Session-revocation service refuses any target that is ROOT unless the actor *is* ROOT | `root_attack_suite` |
| TH-07 | ROOT locked out by attacker-driven failed logins | T1 | Throttling with backoff, **never** permanent lockout; ROOT is exempt from account lock, only slowed | `root_not_lockable` |
| TH-08 | CLIENT receives an internal role | T2/T4 | `roles.allowed_principal_type` + **DB trigger** on `user_role_assignments`; service-layer envelope check | `client_escape_suite` |
| TH-09 | CLIENT holds an internal-only permission | T2/T4 | `permissions.max_principal_type`; evaluator denies before any grant lookup | property test `client_envelope_holds` |
| TH-10 | CLIENT enumerates users/projects by UUID | T2 | Repository-level visibility predicate; `404` (not `403`) for invisible objects | `client_escape_suite`, `bola_suite` |
| TH-11 | CLIENT A reads CLIENT B's shared project | T2 | Join through `project_client_links` × `client_memberships(status='ACTIVE')` in the query itself | `client_escape_suite` |
| TH-12 | Mass assignment (`is_root`, `principal_type`, `role_ids`, `status`) | T2/T3 | Every request DTO is explicit and `#[serde(deny_unknown_fields)]` | `mass_assignment_suite` |
| TH-13 | Self-promotion by an employee | T3 | Delegation guard: actor cannot grant what it does not effectively hold; cannot widen its own scope | `delegation_suite` |
| TH-14 | Administrator grants a permission it lacks | T4 | Delegation guard evaluates the *actor's* effective grant for each permission being granted, at the requested scope | `delegation_suite` |
| TH-15 | Administrator widens scope (`DEPARTMENT` → `GLOBAL`) | T4 | Scope-derivation lattice; incomparable scopes are denied | `delegation_suite`, property test |
| TH-16 | Explicit DENY bypassed by adding another role | T3/T4 | DENY overrides are evaluated *after* union of role allows and always win | unit + property `deny_beats_allow` |
| TH-17 | Stolen access token used after revocation | T5 | Opaque token, hashed at rest, looked up per request; revocation is a single `UPDATE` and takes effect on the next request | `session_revocation_immediate` |
| TH-18 | Permission change not effective until token expiry | T3 | No authority is encoded in the token; permissions are read per request | golden scenario step 25 |
| TH-19 | Refresh token reuse after rotation | T6 | Consumed refresh rows are retained; a hit on a consumed row **revokes the whole session family** | `race_refresh_reuse` |
| TH-20 | Session fixation | T1 | Sessions are only ever created by the server after successful authentication; no client-supplied session identifier is accepted anywhere |  `no_client_session_id` |
| TH-21 | Password reset token reused / raced | T1 | Hashed, single-use, `UPDATE … WHERE consumed_at IS NULL` returning row count inside a transaction | `race_password_reset` |
| TH-22 | Invitation accepted twice | T1 | Same pattern; exactly one winner | `race_invitation_accept` |
| TH-23 | Account enumeration via login | T1 | Generic `AUTHENTICATION_FAILED` for unknown-user *and* wrong-password; dummy Argon2id verification on the unknown-user path | `enumeration_timing` |
| TH-24 | Account enumeration via password-reset / registration | T1 | Identical generic response regardless of existence | `enumeration_reset` |
| TH-25 | Brute force / credential stuffing | T1 | Layered limiter: per-IP, per-account, per-operation; exponential backoff | `rate_limit_suite` |
| TH-26 | TOTP brute force / replay | T1/T5 | 6-digit ±1 step window, per-session attempt limiter, **`last_used_step` rejects replay of an already-used code** | `mfa_suite` |
| TH-27 | Recovery-code brute force | T1 | High-entropy codes, hashed, single-use, rate limited | `mfa_suite` |
| TH-28 | Sensitive change without recent MFA | T4/T5 | `STEP_UP_REQUIRED` enforced server-side on a fixed operation list | `step_up_suite` |
| TH-29 | Audit history edited or deleted | T4 | No mutating endpoint exists; **DB trigger** rejects UPDATE/DELETE on `audit_events`; runtime role holds only `SELECT, INSERT` | `audit_immutability_suite` |
| TH-30 | Audit rows silently removed from a dump | T7 | HMAC-SHA256 hash chain with a key held **outside** the database; `verify-audit` command | `audit_chain_detects_tamper` |
| TH-31 | SQL injection | T1..T4 | Parameterised SQL only; sorting/filtering resolved through a compile-time allowlist, never string interpolation | `sqli_suite` + code rule |
| TH-32 | Log injection (CRLF) forging audit/log lines | T2/T3 | JSON-encoded structured logs + control-character stripping on every user-controlled logged value | `log_injection_suite` |
| TH-33 | Resource exhaustion (huge body / arrays / pagination) | T1 | 256 KB global body limit, per-field length caps, array caps, `page_size ≤ 100`, request timeout | `input_limits_suite` |
| TH-34 | Argon2id used as an amplification DoS | T1 | Bounded hashing concurrency + rate limiting *before* hashing | benchmark + `argon2_bound` |
| TH-35 | Secrets leaked in errors or logs | T1..T8 | `Secret<T>` wrapper with redacting `Debug`; production error redaction; no SQL/backtrace/path in responses | `error_redaction_suite` |
| TH-36 | Token placed in a URL/query string | T8 | Bearer header only; a token-looking query parameter is rejected with `TOKEN_IN_QUERY_STRING` | `token_in_query_rejected` |
| TH-37 | Wildcard CORS on an authenticated API | T8 | Production startup **fails** on `*` with credentials; default deny | `config_fail_closed` |
| TH-38 | Spoofed client IP defeating rate limits | T1 | `X-Forwarded-For` honoured **only** from configured trusted proxy CIDRs; otherwise the peer address | `trusted_proxy_suite` |
| TH-39 | Duplicate side effects on retry | T1/T8 | `Idempotency-Key` with principal+operation scoping and a body fingerprint | `idempotency_suite` |
| TH-40 | Email sent but transaction rolled back (or vice-versa) | — | Transactional outbox; the event and the state change commit together | `outbox_suite` |
| TH-41 | Weak/absent secrets in production | T8 | Startup validation refuses to boot: key length, no known-weak values, no dev defaults | `config_fail_closed` |
| TH-42 | Public registration creating an employee | T1 | Registration path can *only* construct `principal_type = CLIENT`; the field is not accepted from input at all | `registration_suite` |
| TH-43 | Privilege changed mid-request (TOCTOU) | T3/T4 | Authorise inside the mutating transaction, with `FOR UPDATE` on the subject for privilege operations | `race_concurrent_role_change` |
| TH-44 | Lost update on concurrent edits | T3 | `version` column; stale version → `409 VERSION_CONFLICT` | `race_project_update`, `race_task_update` |
| TH-45 | Prompt-injected AI agent acting as ROOT | T9 | Architectural rule: agents get a principal with permissions, never DB credentials, never ROOT. Documented in `10-future-ai-mcp-security.md`; no AI surface is built now |

## 5. Attack classes from the OWASP API Top 10 that are *absent by construction*

Stated explicitly so their absence is a decision, not an oversight.

| Class | Status | Why |
| --- | --- | --- |
| **SSRF** | **Not applicable** | No endpoint accepts a URL, hostname, or IP and performs an outbound fetch. The backend makes **zero** outbound HTTP requests. Adding one later requires the hardened egress layer specified in `06-security-controls.md` §Egress |
| **Unrestricted file upload** | **Not applicable** | No upload endpoint exists. `12-future-storage.md` records the required controls before one is added |
| **Command injection** | **Not applicable** | The process never spawns a subprocess. No `std::process::Command` appears in the crate (enforced by a grep test in CI) |
| **Path traversal** | **Not applicable** | No endpoint accepts a filesystem path and no static file is served |
| **Unsafe deserialization** | **Mitigated by construction** | Only `serde_json` into explicit, closed structs. No type-tag polymorphism, no `#[serde(flatten)]` into `Value` on any authenticated write path |
| **XSS / CSRF** | **Not applicable at this layer** | The API accepts only `application/json` (rejects `application/x-www-form-urlencoded` and `multipart/form-data`), authenticates only via the `Authorization` header, never via cookies, and returns only `application/json` / `application/problem+json` with `X-Content-Type-Options: nosniff`. CSRF becomes relevant when the future BFF introduces cookies — recorded in `docs/backend/06-security-controls.md` §Future web boundary |
| **XXE** | **Not applicable** | No XML parser is linked |
| **Mass assignment via ORM** | **Not applicable** | No ORM; no struct is both a database row and a request body |

## 6. Residual risks (carried, not solved)

| # | Residual risk | Why it remains | Mitigation in place |
| --- | --- | --- | --- |
| RR-1 | Full host compromise reveals the audit chain key and the AEAD key | Both must be readable by the running process | Keys come from the environment/secret manager, are `Secret<T>`-wrapped and zeroised; the chain is verifiable by an **offline** holder of the key, which detects tampering performed without that key |
| RR-2 | PostgreSQL `SUPERUSER` can disable triggers and rewrite audit rows | Inherent to owning the database | Runtime role is neither owner nor superuser; superuser credentials are not used by the application; hash-chain verification detects the edit afterwards |
| RR-3 | In-process rate limiting is per-instance | Single instance today | `trait RateLimiter`; horizontal scaling requires the Redis implementation *before* it is deployed — recorded as a release gate |
| RR-4 | ROOT is a single point of failure | Deliberate, per the ownership invariant | Ownership replacement is an offline, documented, audited procedure (ADR-004); ROOT cannot be locked out by attacker-driven failures |
| RR-5 | No production email provider | Deferred scope | Reset/invite flows create outbox events and are fully testable; production refuses to start if a real provider is required but absent — no silent fake success |
| RR-6 | Audit-chain appends are globally serialised | Correctness chosen over throughput | Measured; see `PERFORMANCE_REPORT.md` |
