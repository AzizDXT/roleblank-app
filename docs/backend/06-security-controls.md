# 06 — Security Controls

What is actually implemented, where it lives, and what each control does *not* do.
Claims here are deliberately narrow; evidence is in
`docs/backend/SECURITY_TEST_REPORT.md`.

## 1. Cryptography

Every primitive comes from the audited RustCrypto stack. Exactly one *construction*
is written locally, and it is validated against the standard's own test vectors.

| Purpose | Primitive | Crate | Where |
| --- | --- | --- | --- |
| Password hashing | Argon2id, 19 MiB / t=2 / p=1, 16-byte salt, PHC encoding | `argon2` 0.5.3 | `platform/crypto/password.rs` |
| Session / reset / invite tokens | 32 bytes `OsRng`, SHA-256 at rest | `rand` 0.9.5, `sha2` 0.10.9 | `platform/crypto/tokens.rs` |
| TOTP secrets at rest | XChaCha20-Poly1305, 24-byte random nonce, key-versioned | `chacha20poly1305` 0.10.1 | `platform/crypto/aead.rs` |
| TOTP codes | RFC 6238 over HMAC-SHA1 | `hmac` 0.12.1, `sha1` 0.10.7 | `platform/crypto/totp.rs` |
| Audit chain | HMAC-SHA256, length-prefixed canonical encoding | `hmac`, `sha2` | `modules/audit/chain.rs` |
| Constant-time comparison | `subtle::ConstantTimeEq` | `subtle` 2.6.1 | `tokens::digests_equal` |
| Secret hygiene | redacting `Debug`, zeroise on drop | `zeroize` 1.9.0 | `shared/secret.rs` |

**Why SHA-256 and not Argon2 for tokens.** The input is already 256 bits of uniform
randomness. A password KDF exists to compensate for low-entropy human input; against
a uniformly random preimage it adds latency to the hottest query in the system and
buys nothing.

**Why XChaCha20-Poly1305 and not AES-GCM.** The 192-bit nonce makes random nonce
generation safe without a counter. With a 96-bit GCM nonce, birthday-bound
collisions become a real concern at scale, and nonce reuse in a counter-mode cipher
is catastrophic — it leaks the XOR of two plaintexts and breaks the authenticator.
The larger nonce removes that failure mode from the design rather than managing it.

**Associated data binds a ciphertext to its row.** A TOTP secret is sealed with the
owning user's id as AAD, so an attacker with `UPDATE` on `mfa_factors` cannot move
one user's factor onto another's record and have it decrypt.

**The one local construction.** RFC 6238 TOTP — roughly thirty lines of counter
derivation and dynamic truncation, fully specified by the RFC and verified against
its **Appendix B test vectors** for `t = 59, 1111111109, 1111111111, 1234567890,
2000000000, 20000000000`. No cryptographic primitive is implemented here. Rationale
in ADR-002.

## 2. Key management

| Key | Source | Purpose |
| --- | --- | --- |
| `RB_ENCRYPTION_KEY` | environment / secret manager, 32 bytes base64 | AEAD for TOTP secrets |
| `RB_AUDIT_CHAIN_KEY` | environment / secret manager, 32 bytes base64 | audit HMAC chain |
| `RB_BOOTSTRAP_SECRET` | environment, ≥32 chars, **removed after initialisation** | first-run gate |

- The two 32-byte keys must be **different**; identical values are refused at
  startup. Reusing one key across an AEAD and an HMAC is a cross-protocol mistake,
  and here it would also mean that obtaining one capability obtained both.
- Every ciphertext stores `key_version`, so the master key can be rotated without
  eagerly re-encrypting. `KeyRing::with_previous` keeps retired versions readable
  during the transition; removing a version too early is reported distinctly from a
  decryption failure, because it is an operational error and not a tampering signal.
- Production startup **refuses** an all-zero key, a key containing placeholder text,
  or a key of the wrong length.
- Keys live in `Secret<T>`: no `Display`, no `Serialize`, redacting `Debug`,
  zeroised on drop. `rg 'expose\(\)'` enumerates every place a secret is unwrapped.

## 3. Authentication controls

| Control | Implementation |
| --- | --- |
| Undifferentiated failure | One `AppError::AuthenticationFailed` for unknown account, wrong password, suspended user, expired token, revoked session, malformed header |
| Timing equalisation | Unknown account still performs a full Argon2id verification against a fixed dummy hash |
| Bounded hashing | Semaphore, default `min(cpu, 8)` — Argon2id's memory cost is otherwise a self-inflicted amplification vector |
| Token shape check | Prefix + length + alphabet validated before any database lookup |
| Immediate revocation | Session validity is a single query joining `users.status`; suspension takes effect on the next request with no background job |
| Absolute lifetime | 30 days, unextendable by refresh — every compromise has a bounded end |
| Refresh rotation | Unconditional; consumed generations retained |
| Reuse detection | A hit on a consumed refresh row revokes the whole family and audits `AUTH.REFRESH_REUSE_DETECTED` |
| MFA non-bypass | `pending_mfa` sessions reach only the MFA endpoints; `Authenticated` rejects them by default |
| TOTP replay | `last_used_step` refuses a code at or below the highest already accepted, even inside its window |
| Step-up | `mfa_verified_at` recency, computed per request, 60–1800 s configurable window |
| No token in URL | A token-shaped query parameter is refused with a distinct code, so the caller learns they have a leak |

## 4. Authorization controls

Deny by default; four independent layers (`04-authorization.md` §2). The evaluator
is pure and synchronous, so it is exhaustively testable without a database:
**14 property tests × 2048 generated cases** assert the invariants that matter —
the client envelope, DENY precedence, no self-delegation, ROOT untargetability, and
that derivation is reflexive, transitive and never widening.

Database-level redundancy for the two invariants a single application bug must not
be able to break:

| Invariant | Application | Database |
| --- | --- | --- |
| A CLIENT never receives an internal role | `delegation::check_role_assignment` | `trg_role_assignment_principal_match` |
| A CLIENT never holds an internal permission | evaluator step 3 | `trg_role_permission_envelope`, `trg_override_envelope` |
| ROOT cannot be deleted / suspended / demoted | `RootGuard`, no delete endpoint | `trg_users_protect_root`, no `DELETE` grant |
| Ownership cannot move | no code path exists | `trg_system_ownership_immutable`, singleton PK |

## 5. Input handling

| Control | Value | Where |
| --- | --- | --- |
| Request body limit | 256 KiB | `RequestBodyLimitLayer` |
| Request timeout | 30 s | `TimeoutLayer` |
| Database statement timeout | 15 s, set in the startup packet | `platform/database` |
| Idle-in-transaction timeout | 30 s — an abandoned transaction holds the audit chain lock | startup packet |
| Page size | default 25, max 100 | `shared/pagination.rs` |
| Array length | max 100 items | `validation::validate_array_len` |
| String lengths | per-field, matching the database `CHECK` constraints exactly | `shared/validation.rs` |
| Unknown JSON fields | rejected | `#[serde(deny_unknown_fields)]` on every request DTO |
| Content type | `application/json` only | `http::extract::Json` |
| Sorting / filtering | compile-time allowlist returning `&'static str` | `PageRequest::resolve` |
| Cursor | opaque, length-bounded, structurally validated | `Cursor::decode` |

Pagination is **keyset**, never `OFFSET`: `OFFSET 100000` makes PostgreSQL walk and
discard a hundred thousand rows, letting a client turn a cheap endpoint into an
expensive one by incrementing a number.

## 6. Output handling

- Every error is `application/problem+json` with a stable `code`. Machine clients
  branch on `code`; `title` and `detail` are human text and may be reworded.
- `detail` is audited per variant for information leakage. No SQL, no backtrace, no
  file path, no environment variable, no database hostname, no driver message.
- Database driver errors are mapped through a fixed classification table; the
  driver's own message — which can contain the connection string and the failing
  SQL — is never interpolated, not even into the internal variant that gets logged.
- Response DTOs are hand-written and never a database row struct. `credentials` is a
  separate table from `users` specifically so the query that runs on every
  authenticated request *cannot* return a password hash.
- Client projections are separate types, not filtered serialisations: internal
  fields are physically absent from `ClientProjectResponse`.

## 7. Logging

- JSON to stdout in production (enforced — production refuses to start with the
  text format). File and line are omitted deliberately: they are internal path
  disclosure if logs are shipped somewhere shared.
- `sqlx` is pinned to `warn` in the default filter, and statements log only at
  `TRACE`, so a change to the default level can never start emitting bound
  parameters.
- Every user-controlled value passes `sanitize::log_value`: control characters
  become `·`, U+2028/U+2029 are folded, and length is bounded to 200 characters on
  a character boundary. Combined with JSON encoding this closes CRLF log forgery
  (TH-32).
- Never logged: passwords, any token or token digest beyond what a lookup requires,
  TOTP secrets, recovery codes, encryption keys, database credentials, reset and
  invitation tokens, or full request bodies.

## 8. Rate limiting

Layered, because each layer defeats a different attack: per-IP alone is defeated by
a botnet, per-account alone lets one host grind every account at once.

| Operation | Per IP | Per account / session |
| --- | --- | --- |
| login | 10 / min | 5 / min per normalised email |
| MFA verification | — | 5 / min per session and per account |
| refresh | 60 / min | — |
| password reset | 5 / hour | 5 / hour per account |
| registration | 3 / hour | — |
| bootstrap | 5 / hour | — |
| general authenticated | — | 600 / min per principal |

Token bucket rather than fixed window: a fixed window lets an attacker send the full
quota at 59.9 s and again at 60.1 s. The key table is **bounded** — a limiter that
grows without limit under IP rotation becomes the denial of service it was meant to
prevent. A successful login resets the account key so a user who mistyped is not
still penalised.

**ROOT is never locked out.** Failed authentication is throttled with backoff but
never converts to a lockout state, because an attacker who could lock the owner out
by submitting bad passwords would have disabled the company (ADR-004).

**Limitation, stated plainly:** this implementation is per-process. It is correct
for a single instance and wrong the moment a second replica exists. Recorded as RR-3
and as a release gate; `trait RateLimiter` exists so the Redis implementation
changes no call site.

## 9. Trusted proxies

`X-Forwarded-For` is honoured **only** when the immediate peer is inside a
configured CIDR; otherwise the peer address is used and the header is ignored
entirely. The **rightmost** entry is taken, not the leftmost — entries to the left
are attacker-supplied, and taking the first is the spoofable choice. Empty
configuration means trust nothing, which is the correct fail-closed default.

## 10. Configuration

Production startup **fails** — before binding a port — on: wildcard CORS, a non-https
origin, a trailing-slash origin, a non-https or localhost public base URL, an
all-zero or placeholder key, identical encryption and chain keys, a bootstrap secret
under 32 characters, a database URL connecting as a privileged role, `sslmode=disable`,
Argon2 parameters below the OWASP floor, an exposed OpenAPI document, text logs, or
a development mail sink. All problems are reported together rather than one at a
time. `roleblank-api check-config` runs the same validation as a deployment gate.

## 11. Database privilege separation

`roleblank_migrator` owns the schema. `roleblank_app` is the runtime identity and
owns nothing. Verified by direct SQL as that role — 14 of 14 attacks refused:

- `UPDATE` / `DELETE` / `TRUNCATE` on `audit_events` → `permission denied`
- `DELETE` on `users` → `permission denied`
- `UPDATE` / `DELETE` on `system_ownership` → `permission denied`
- `ALTER TABLE … DISABLE TRIGGER` → `must be owner of table`
- `DROP TABLE audit_events` → `must be owner of table`
- `CREATE TABLE` in `public` → `permission denied for schema`
- suspending ROOT → refused by trigger
- establishing a second owner → `duplicate key`

`INSERT` on `system_ownership` **is** granted, because bootstrap is an HTTP endpoint.
It is safe precisely because the table is a singleton by primary key: the insert can
succeed at most once in the lifetime of the database, and `UPDATE`/`DELETE` are both
ungranted *and* refused by an unconditional trigger.

## 12. Attack surface deliberately absent

| Class | Why it does not apply |
| --- | --- |
| SSRF | No endpoint accepts a URL, hostname or IP and performs an outbound fetch. The backend makes **zero** outbound HTTP requests |
| Command injection | The process never spawns a subprocess; `duct` and `subprocess` are banned in `deny.toml` |
| Path traversal | No endpoint accepts a filesystem path; no static file is served |
| File upload | No upload endpoint exists (`12-future-storage.md` records the controls required before one ships) |
| XXE | No XML parser is linked |
| CSRF | Authentication is `Authorization`-header only; cookies are never read. Form and multipart content types are refused, so a cross-site form POST cannot reach a handler |
| Unsafe deserialisation | `serde_json` into closed structs only; no type-tag polymorphism, no `flatten` into `Value` on an authenticated write path |
| `unsafe` Rust | `#![forbid(unsafe_code)]` at the crate root |

Adding any of these later requires the hardened design recorded in the relevant
future-architecture document — not an ad-hoc endpoint.

## 13. Supply chain

- 256 crates resolved; `Cargo.lock` committed.
- No git dependencies, no wildcard versions, no alpha/beta/nightly.
- `deny.toml`: advisories and unknown sources are hard failures; licences are an
  allowlist; `openssl`, `native-tls`, `md-5`, `chrono`, `duct` and `subprocess` are
  banned with stated reasons.
- Security-critical crate rationale is in `00-reconnaissance.md` §5.

## 14. Future egress requirements

The backend has no outbound network surface today. Before one is added — webhooks,
link previews, an import feature, a mail provider — it must go through a dedicated
hardened egress layer with: TLS verification, connect and total timeouts, a bounded
response size, schema validation of the response, no automatic redirect following
for sensitive requests, a DNS-resolution allowlist that rejects private and
link-local ranges *after* resolution (to defeat DNS rebinding), and its own rate
limit. This is stated here so that "just add a `reqwest` call" is visibly a
larger decision than it looks.
