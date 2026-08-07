# 09 — OWASP ASVS 5.0.0 Review

A self-assessment mapping implemented controls to ASVS chapters, targeting
**Level 2** rigour across ordinary backend functionality with **stronger controls**
applied to system ownership, authentication, MFA, sessions, permission management
and secret handling.

> **This is not a certification.** No formal ASVS assessment has been performed and
> none is claimed. This is the engineering team's own mapping, written so that a
> reviewer can see what was considered, what was implemented, what was deliberately
> not implemented, and where the gaps are. Verification evidence is in
> `SECURITY_TEST_REPORT.md`; where a row says "verified", that report names the test.

**Legend:** ✅ implemented and verified · 🟡 partially implemented, gap stated ·
⬜ deliberately out of scope, with why · ➖ not applicable to this system, with why

---

## V1 — Encoding and Sanitisation

| Requirement area | Status | Implementation |
| --- | --- | --- |
| Input validation at a trust boundary | ✅ | `shared::validation`; validation lives in the **service**, not the handler, so a direct service call is equally protected |
| Injection prevention — SQL | ✅ | Parameterised binds only. Dynamic `ORDER BY` comes from a compile-time allowlist returning `&'static str`; the user's string is only ever compared. Verified: `sort_fields_outside_the_allowlist_are_refused` |
| Injection prevention — OS command | ➖ | The process never spawns a subprocess. `duct`/`subprocess` banned in `deny.toml` |
| Injection prevention — LDAP / XPath / XML | ➖ | No such parser or directory is linked |
| Output encoding for the consuming context | ✅ | JSON only; `serde_json` performs the encoding. `X-Content-Type-Options: nosniff` on every response |
| Log injection | ✅ | `sanitize::log_value` strips control characters and U+2028/U+2029 and bounds length; JSON encoding is an independent second layer. Verified |
| Deserialisation safety | ✅ | Closed structs with `deny_unknown_fields`; no type-tag polymorphism; no `flatten` into `Value` on an authenticated write path |
| Memory-safety classes | ➖ | `#![forbid(unsafe_code)]`; zero `unsafe` blocks in the crate |

## V2 — Validation and Business Logic

| Requirement area | Status | Implementation |
| --- | --- | --- |
| Bounded input | ✅ | 256 KiB body, per-field character limits matching the database `CHECK` constraints, 100-item arrays, page size ≤ 100, 512-byte bearer header |
| Business-logic limits | ✅ | Session cap per user; rate limits per operation, IP and account |
| Sequential/state-machine integrity | ✅ | Lifecycle transitions are explicit and tested as a matrix; `CHECK` constraints enforce state coherence (`tasks.completed_at` ⇔ `status='DONE'`, archive consistency) |
| Anti-automation | 🟡 | Layered rate limiting with exponential backoff. **Gap:** no CAPTCHA or proof-of-work on registration. Accepted: registration is `INVITE_ONLY` by default and self-registration produces an inert `PENDING` account with zero visibility |
| Idempotency of consequential creates | ✅ | `Idempotency-Key` scoped by principal + operation + body fingerprint |
| Race conditions | ✅ | Advisory lock + in-transaction re-check + singleton PK for bootstrap; `FOR UPDATE` on refresh tokens, invitations and reset tokens; optimistic `version` on business resources |

## V3 — Web Frontend Security

➖ **Not applicable at this layer.** This is a backend API with no HTML surface. It
authenticates only via the `Authorization` header, never a cookie; refuses form and
multipart content types; and returns only JSON. CSRF, XSS, clickjacking and
`SameSite` cookie policy become the future BFF's obligations, recorded in
`03-authentication.md` §11. The one V3 control that does apply — `nosniff` — is set.

## V4 — API and Web Service

| Requirement area | Status | Implementation |
| --- | --- | --- |
| Documented, enforced schema | ✅ | Hand-authored OpenAPI 3.1 with an automated drift test against the router's route table |
| Correct HTTP semantics and status codes | ✅ | RFC 9457 Problem Details with stable machine-readable `code`; no state-changing `GET` (asserted by test) |
| Content-type enforcement | ✅ | `application/json` only; everything else `415` |
| Method restriction | ✅ | `TRACE` and `CONNECT` refused |
| CORS | ✅ | Default deny; production refuses wildcard, non-https and trailing-slash origins; credentials not allowed |
| Mass assignment | ✅ | `deny_unknown_fields` on every request DTO. Verified per module |
| Excessive data exposure | ✅ | Hand-written response DTOs; separate client projections with internal fields **physically absent**; `credentials` split from `users` at the storage layer |

## V5 — File Handling

⬜ **Deliberately out of scope.** No upload, download or filesystem path endpoint
exists, so the entire chapter is unreachable. `12-future-storage.md` records the
controls that must be in place before any of it ships: server-generated object
keys, extension allowlist *plus* magic-byte verification, size limits at the edge
and in the signed policy, authorisation on presign issuance, and a quarantine state
before a file becomes downloadable.

## V6 — Authentication

| Requirement area | Status | Implementation |
| --- | --- | --- |
| Password storage | ✅ | Argon2id, unique 16-byte salt, m=19 456 KiB / t=2 / p=1, PHC-encoded. Weaker parameters refused at startup |
| Password policy | ✅ | 12–256 characters, no composition rules, no trimming or case folding, known-bad list, identity check |
| Credential recovery | ✅ | Hashed single-use token, 30-minute expiry, generic response either way, all sessions revoked on success |
| Generic authentication failure | ✅ | One error for every failure mode, plus a dummy Argon2id verification on the unknown-account path. Verified by both a body-equality test and a timing-ratio test |
| Brute-force resistance | ✅ | Per-IP and per-account token buckets; successful login resets the account key |
| **No permanent lockout of the owner** | ✅ | Throttling with backoff, never a lockout state — an attacker must not be able to disable the company by submitting bad passwords (ADR-004) |
| MFA — TOTP | ✅ | RFC 6238, verified against the standard's own test vectors; secrets sealed with XChaCha20-Poly1305 under the owning user's id as associated data |
| MFA — mandatory for privileged principals | ✅ | ROOT and holders of dangerous permissions; `pending_mfa` sessions reach only the MFA endpoints, so there is no bypass window |
| MFA replay resistance | ✅ | `last_used_step` refuses an already-accepted code inside its own window |
| Recovery codes | ✅ | High-entropy, shown once, stored hashed, single-use, rate limited |
| WebAuthn / phishing-resistant factor | ⬜ | Not implemented. The correct long-term direction, but it would exclude users without a compatible authenticator today. `mfa_factors.factor_type` already admits a second value, so adding it is additive |

## V7 — Session Management

| Requirement area | Status | Implementation |
| --- | --- | --- |
| Server-side session state | ✅ | Opaque 256-bit tokens; **no** authority encoded in the token |
| Token entropy | ✅ | 32 bytes from `OsRng` |
| Token storage | ✅ | SHA-256 digests only; plaintext appears in exactly one response |
| Session binding to a verified identity | ✅ | Sessions are created only by the server after successful authentication; no client-supplied session identifier is accepted anywhere |
| Absolute and idle timeouts | ✅ | 15 min access / 7 days idle / **30 days absolute, unextendable by refresh** |
| Immediate revocation | ✅ | Validity is one query joining `users.status`; suspension is effective on the next request with no background job |
| Rotation and reuse detection | ✅ | Unconditional rotation; a hit on a consumed refresh token revokes the whole family and audits it |
| Session termination on credential change | ✅ | Password change revokes all other sessions; reset and suspension revoke all |
| Concurrent session limit | ✅ | Configurable; the oldest is revoked beyond the cap |
| Session fixation | ➖ | No client-supplied identifier is ever adopted |

## V8 — Authorization

| Requirement area | Status | Implementation |
| --- | --- | --- |
| Deny by default | ✅ | Every authenticated route declares a permission; unknown codes deny |
| Object-level authorisation (BOLA) | ✅ | Decisions are made against the **loaded row**, not the path parameter; plus an independent SQL visibility predicate for external principals |
| Function-level authorisation | ✅ | Route table declares the required permission; asserted against the catalogue by test |
| Field-level / property authorisation | ✅ | Separate client projections; request DTOs cannot carry privileged properties |
| Least privilege by default | ✅ | The `employee` role is `SELF`/`DEPARTMENT`/`ASSIGNED` only |
| No implicit administrative bypass | ✅ | There is deliberately no `if user.is_admin { allow }`. The built-in administrator role withholds `iam.permissions.delegate` and `settings.security.write` |
| Privilege escalation prevention | ✅ | Delegation guard with a partial scope lattice; self-modification refused outright; role assignment validated permission-by-permission |
| Enforcement at a trusted layer | ✅ | Service layer, inside the mutating transaction, with the subject `FOR UPDATE` |
| Multi-tenancy / cross-account isolation | ✅ | Client isolation implemented as an envelope check *and* a query predicate, and verified by property test over random grants |

## V9 — Self-contained Tokens

➖ **Not applicable.** No JWT, no signed self-contained token, no client-side
authority. This chapter's entire risk class — algorithm confusion, `alg: none`, key
confusion, unrevocable claims — is absent by construction (ADR-002).

## V10 — OAuth and OIDC

➖ **Not applicable.** No OAuth or OIDC surface today. When SSO is introduced it
will be a distinct, separately reviewed subsystem; nothing in the current design
presumes it.

## V11 — Cryptography

| Requirement area | Status | Implementation |
| --- | --- | --- |
| Approved algorithms | ✅ | Argon2id, XChaCha20-Poly1305, SHA-256, HMAC-SHA256; HMAC-SHA1 only where RFC 6238 mandates it |
| No home-grown primitives | ✅ | All primitives from audited RustCrypto crates. The single local *construction* is RFC 6238 TOTP, validated against the RFC's published vectors (ADR-002) |
| Random number generation | ✅ | OS CSPRNG for every secret; a CSPRNG failure fails the request rather than falling back |
| Authenticated encryption | ✅ | AEAD with associated data binding a ciphertext to its owning row |
| Nonce management | ✅ | 192-bit random nonces make counter management unnecessary — the reuse failure mode is removed from the design rather than managed |
| Key management and rotation | ✅ | `key_version` stored with every ciphertext; a key ring keeps retired versions readable; rotation procedure documented |
| Key separation | ✅ | Encryption and audit-chain keys must differ; identical values refused at startup |
| Constant-time comparison | ✅ | `subtle::ConstantTimeEq` wherever a secret is compared in application code |
| HSM / KMS-backed keys | ⬜ | Keys come from the environment/secret manager. A KMS integration is a deployment concern, not a code change, and is not claimed |

## V12 — Secure Communication

| Requirement area | Status | Implementation |
| --- | --- | --- |
| TLS for the database connection | ✅ | rustls; production refuses `sslmode=disable` |
| TLS for inbound traffic | 🟡 | Terminated at the edge proxy; the API speaks plain HTTP inside the network. **This is an infrastructure obligation**, documented in `08-operations.md` §11, and is not enforced by the application |
| Certificate validation on outbound calls | ➖ | The backend makes no outbound calls |

## V13 — Configuration

| Requirement area | Status | Implementation |
| --- | --- | --- |
| Secure defaults | ✅ | Registration `INVITE_ONLY`; CORS empty; trusted proxies empty; unbuilt feature flags off |
| Secrets not in source control | ✅ | `.env` git-ignored; `.env.example` carries obvious placeholders; production does not read `.env` |
| Fail-closed startup validation | ✅ | Eleven distinct production refusals, all reported together. Verified |
| Debug surface disabled in production | ✅ | OpenAPI off by default; no debug endpoint exists |
| Dependency management | ✅ | `Cargo.lock` committed; no git or wildcard dependencies; `deny.toml` with a licence allowlist and named crate bans |
| Unnecessary features disabled | ✅ | `default-features = false` on sqlx; feature sets chosen explicitly |

## V14 — Data Protection

| Requirement area | Status | Implementation |
| --- | --- | --- |
| Sensitive data at rest | ✅ | Passwords hashed, tokens digested, TOTP secrets AEAD-encrypted |
| Sensitive data in transit | 🟡 | TLS is an edge obligation (see V12) |
| Secrets in memory | ✅ | `Secret<T>` — no `Display`, no `Serialize`, redacting `Debug`, zeroised on drop |
| Caching controls | ✅ | `no-store` on every response |
| Data minimisation in responses | ✅ | Explicit DTOs; separate client projections |
| Right-to-erasure support | 🟡 | Users are archived, never deleted, deliberately (audit meaning and historical references). A regulated erasure workflow would need a documented pseudonymisation procedure. **Recorded as a gap, not solved** |

## V15 — Secure Coding and Architecture

| Requirement area | Status | Implementation |
| --- | --- | --- |
| Documented architecture and threat model | ✅ | `01`–`08` plus six ADRs; 45 threats mapped to controls and named tests |
| Trust boundaries identified | ✅ | Three, each defended at two independent layers |
| Least-privilege runtime | ✅ | Separate database roles; verified by executing 14 attacks as the runtime identity |
| Defence in depth | ✅ | Application checks plus database triggers plus privilege separation for ROOT, audit and the client envelope |
| No dangerous language features | ✅ | `forbid(unsafe_code)`; no `unwrap`/`expect`/`panic!`/`todo!` in non-test code |
| Third-party component review | ✅ | Security-critical crates justified individually in `00-reconnaissance.md` §5 |

## V16 — Security Logging and Error Handling

| Requirement area | Status | Implementation |
| --- | --- | --- |
| Security events logged | ✅ | Authentication, authorisation denials, MFA, sessions, privilege changes, client sharing, settings, ROOT-protection triggers |
| Log integrity | ✅ | Audit is append-only at three layers, with an HMAC hash chain keyed outside the database |
| No sensitive data in logs | ✅ | `Secret<T>`, a closed audit-metadata builder that refuses secret-bearing keys, and `sqlx` pinned to `warn` so parameters cannot surface |
| Time source | ✅ | `timestamptz`, UTC, RFC 3339 in logs |
| Error handling reveals nothing | ✅ | Fixed classification for driver errors; no SQL, backtrace, path or hostname in any response |
| Log injection prevention | ✅ | Verified |
| Logging cannot be disabled to hide activity | 🟡 | Audit writes are unconditional and in-transaction. `RUST_LOG` can suppress *operational* logs — that is a deliberate separation, and it does not touch audit history |

## V17 — WebRTC

➖ Not applicable.

---

## Summary of stated gaps

| # | Gap | Severity | Disposition |
| --- | --- | --- | --- |
| G1 | Inbound TLS is an infrastructure obligation, not application-enforced | Medium | Documented deployment requirement (`08-operations.md` §11) |
| G2 | No phishing-resistant second factor (WebAuthn) | Medium | Schema already admits it; additive change |
| G3 | No anti-automation challenge on registration | Low | Mitigated by `INVITE_ONLY` default and inert `PENDING` accounts |
| G4 | Keys are environment-supplied, not KMS-backed | Low | Deployment concern; no code change required to adopt one |
| G5 | No regulated erasure workflow | Low–Medium | Deliberate conflict with audit integrity; needs a documented pseudonymisation procedure before any such obligation applies |
| G6 | Rate limiting is per-process | Medium **at scale** | Release gate: the distributed implementation must ship before a second replica does (RR-3) |
| G7 | No production mail provider | Medium | Production fails closed rather than silently dropping mail; onboarding is administrator-driven until it ships |

None of these are claimed to be solved. Each is either a deployment obligation with
a named owner, or an explicitly deferred piece of work with a recorded consequence.
