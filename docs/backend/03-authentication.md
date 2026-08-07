# 03 — Authentication

## 1. Token model

`Authorization: Bearer <opaque-token>`. Nothing else authenticates. No cookies, no query
parameters, no custom headers, no basic auth.

Both token kinds are **32 bytes from the OS CSPRNG** (`rand::rngs::OsRng`), encoded
base64url without padding (43 characters), and prefixed for unambiguous classification:

```
  rb_at_<43 chars>    access token
  rb_rt_<43 chars>    refresh token
```

The prefix exists so that a leaked token is identifiable by secret-scanning tooling and so
that presenting a refresh token to the access path fails loudly rather than ambiguously.

**Only SHA-256 digests are stored.** The plaintext token never touches the database, a log,
a metric label, an error body, or a URL. Lookup is by digest, which is indexed — an
attacker with a database dump obtains 256-bit preimages, not usable tokens.

> SHA-256 (not Argon2) is correct here precisely because the input is 256 bits of uniform
> randomness. There is no low-entropy secret to slow-hash; a password KDF would only add
> per-request cost with no security gain.

## 2. Why opaque server-side sessions and not JWTs

Permissions must be revocable *now*. A self-contained bearer JWT is valid until it expires
by definition; revoking it requires a server-side denylist, at which point the server is
already doing a lookup per request and the JWT has bought nothing but a larger token and a
signature-verification bug surface.

Consequence, stated plainly: **the server is authoritative on every request.** Nothing about
a principal's authority is cached in the token. Changing a role takes effect on the very
next request. This is validated by step 25 of the golden scenario.

## 3. Session record

One row per session (`sessions`), holding the *current* access-token digest. Refresh tokens
live in a child table (`session_refresh_tokens`) so that consumed generations are retained
for reuse detection.

| Field | Purpose |
| --- | --- |
| `id` | session identifier (never sent to the client as a credential) |
| `user_id` | subject |
| `access_token_hash` | SHA-256 of the current access token, unique |
| `access_expires_at` | short — default **15 minutes** |
| `absolute_expires_at` | hard ceiling — default **30 days**; no amount of refreshing extends it |
| `idle_expires_at` | rolling — default **7 days** of inactivity |
| `auth_level` | `PASSWORD` or `MFA` — the assurance actually achieved |
| `mfa_verified_at` | drives step-up; `NULL` until a second factor is verified |
| `pending_mfa` | `true` while the session may *only* call the MFA endpoints |
| `revoked_at`, `revocation_reason` | revocation is an update, never a delete |
| `client_ip_hint`, `user_agent_hint` | truncated, sanitised, for the user's own session list |

A session is usable only when `revoked_at IS NULL` **and** `now() < access_expires_at`
**and** `now() < absolute_expires_at` **and** `now() < idle_expires_at` **and** the owning
user's status is `ACTIVE`. The user-status check is a join in the same query, so suspending
a user kills their sessions on their next request without a background job.

## 4. Login flow

```
POST /api/v1/auth/login  { email, password }

 1. rate limit  (per-IP, and per-normalised-email once known)
 2. look up user by email_normalized
 3. if absent          -> verify the password against a fixed dummy Argon2id hash, then
                          return the SAME generic AUTHENTICATION_FAILED as a wrong password
 4. if status != ACTIVE-> generic AUTHENTICATION_FAILED (no distinction leaked)
 5. verify Argon2id    -> under the hashing semaphore
 6. if MFA is required or enrolled:
        create session with pending_mfa = true, auth_level = PASSWORD
        respond 200 { mfa_required: true, access_token, ... }   ← usable ONLY for /auth/mfa/*
    else:
        create session with auth_level = PASSWORD, mfa_verified_at = NULL
 7. audit AUTH_LOGIN_SUCCEEDED / AUTH_LOGIN_FAILED (failures record the attempted
    normalised email but never the password or any part of it)
```

Steps 3 and 4 are why login cannot be used to enumerate accounts: the unknown-user path
performs the same Argon2id work as the known-user path.

### The `pending_mfa` state

A session created for a user who must complete MFA is a *real* session with a real access
token, but a middleware gate rejects every route except:

```
GET  /api/v1/auth/me                (reduced projection)
POST /api/v1/auth/mfa/totp/setup
POST /api/v1/auth/mfa/totp/activate
POST /api/v1/auth/mfa/verify
POST /api/v1/auth/mfa/recovery/verify
POST /api/v1/auth/logout
```

Everything else returns `403 MFA_REQUIRED`. This is what makes MFA non-bypassable for
privileged users: there is no window in which a password-only session can do anything.

ROOT is bootstrapped straight into `mfa_enrolled = false, mfa_required = true`, i.e. the
`MFA_ENROLLMENT_REQUIRED` state.

## 5. Refresh and rotation

```
POST /api/v1/auth/refresh  { refresh_token }

  BEGIN
    SELECT ... FROM session_refresh_tokens WHERE token_hash = $1 FOR UPDATE
      not found              -> 401 AUTHENTICATION_FAILED   (generic)
      consumed_at IS NOT NULL-> ***REUSE DETECTED***
                                revoke the entire session (family) + audit
                                + revoke every unconsumed token in the family
                                -> 401 AUTHENTICATION_FAILED
      expired / session revoked / user not ACTIVE -> 401
    mark consumed, mint a new refresh row (generation + 1) linked via replaced_by
    mint a new access token; UPDATE sessions.access_token_hash
  COMMIT
```

Rotation is unconditional: every successful refresh invalidates both the presented refresh
token and the previous access token. `FOR UPDATE` on the token row is what makes two
concurrent refreshes deterministic — exactly one wins, the loser is treated as reuse and
the family dies. That is the correct, conservative outcome and it is tested.

## 6. Password storage

Argon2id via the RustCrypto `argon2` crate, PHC-encoded, unique 16-byte salt per password.

Parameters are configuration, defaulted to values that meet current OWASP guidance and were
**benchmarked on this machine** rather than copied (see `PERFORMANCE_REPORT.md`):

| Parameter | Default |
| --- | --- |
| `m_cost` | 19 456 KiB (19 MiB) |
| `t_cost` | 2 |
| `p_cost` | 1 |
| output | 32 bytes |

Concurrency is bounded by `AUTH_HASHING_MAX_CONCURRENCY` (default = CPU count, capped at 8).
Requests beyond the bound wait; the rate limiter rejects long before the queue grows. This
is the mitigation for using an intentionally memory-hard KDF on a public endpoint.

### Password policy

- minimum **12** characters, maximum **256** (measured in Unicode scalar values)
- **no** composition rules — no forced symbol/uppercase/digit classes
- input is **not** trimmed, **not** case-folded, **not** Unicode-normalised — the bytes the
  user typed are the bytes that are hashed
- rejected: exact matches against a small embedded list of catastrophically common
  passwords, and passwords equal to the user's own email
- changing a password revokes **all other** sessions of that user and bumps
  `credentials.password_updated_at`

## 7. MFA (TOTP, RFC 6238)

- SHA-1 HMAC, 6 digits, 30-second step — the interoperable profile every authenticator app
  implements. The primitives come from the vetted `hmac` + `sha1` crates; only the RFC 6238
  construction is ours, and it is verified against the **official RFC 6238 Appendix B test
  vectors** in `crypto::totp::tests`. See ADR-002 for why a third-party TOTP crate was not
  used.
- Secret: 20 bytes from the CSPRNG, presented **once** at setup as base32 + `otpauth://` URI.
- At rest the secret is **XChaCha20-Poly1305** ciphertext with a 24-byte random nonce and a
  stored `key_version`, under a master key from the environment. Never plaintext, never
  logged, never returned after setup.
- Validation window ±1 step (±30 s). `mfa_factors.last_used_step` records the highest
  accepted counter; any code at or below it is rejected, which kills replay of a code
  captured in transit.
- Setup → `PENDING`; the factor only becomes `ACTIVE` after the user proves a correct code.
- **Mandatory** for ROOT and for any user holding a permission flagged `is_dangerous`.

### Recovery codes

10 codes × 20 random bytes, rendered as `XXXXX-XXXXX-XXXXX-XXXXX` base32. Shown **once**.
Stored as SHA-256 digests. Single use (`UPDATE … WHERE consumed_at IS NULL` gated on rows
affected). Regenerating invalidates the whole previous batch. Verification is rate limited
per account and audited.

## 8. Step-up authentication

`sessions.mfa_verified_at` must be within `AUTH_STEP_UP_WINDOW_SECONDS` (default **600 s**,
configurable 60–1800, matching the bound `platform::config` enforces) for any operation on the step-up list:

```
role create / update / delete            permission grant / revoke / override
role assignment to a user                user promotion into a protected role
MFA disable, recovery-code regeneration  security settings write
feature flags flagged security-sensitive session revocation for another user
client account link / unlink to project  registration mode change
```

Failure is `403` with `code = "STEP_UP_REQUIRED"` and a machine-readable
`step_up.window_seconds` hint, so a client knows to re-prompt rather than to give up.
The list lives in one place (`platform::security::step_up::STEP_UP_OPERATIONS`) and is
asserted by test to cover every route the route table marks sensitive.

## 9. Password reset

```
POST /api/v1/auth/password-reset/request { email }
  -> ALWAYS 202 with the same body, whether or not the account exists
  -> if it exists: 32-byte token, SHA-256 stored, 30-minute expiry, single use,
     outbox event enqueued in the same transaction

POST /api/v1/auth/password-reset/confirm { token, new_password }
  -> single-use consumption inside a transaction (rows-affected gated)
  -> sets the new hash, revokes ALL sessions of that user, audits
  -> generic failure for expired / consumed / unknown
```

The plaintext token exists only in the response of nothing and in the outbox payload
destined for the mail provider. It is **never** logged — the outbox logger logs the event
id and type only.

## 10. Registration and invitations

`registration.mode` ∈ `DISABLED` | `INVITE_ONLY` | `CLIENT_SELF_REGISTRATION`.

- Self-registration constructs `principal_type = CLIENT` in code. The request DTO has no
  field for it, no field for roles, no field for status. A payload carrying one is rejected
  by `deny_unknown_fields` before it reaches the service.
- A self-registered client lands in `PENDING` with **zero** client memberships. It can see
  nothing until an authorised internal principal links it to a client account and activates
  the membership.
- Employees are created only through invitations. The invitation carries the intended
  principal type and role set, both fixed at creation by the inviter and re-validated
  against the **inviter's own delegation authority** at acceptance time. Accepting an
  invitation cannot produce ROOT.

## 11. What the future web layer must do (not built here)

```
Browser ──HTTP-only, Secure, SameSite=Strict cookie──▶ Node/Next BFF ──Bearer──▶ Rust API
```

The BFF holds the RoleBlank tokens server-side and never exposes them to JavaScript.
Flutter keeps them in Keychain / EncryptedSharedPreferences. Neither exists yet; this
document is the contract they must satisfy. CSRF protection becomes the BFF's obligation
the moment a cookie is introduced — the Rust API never reads cookies and therefore has no
CSRF surface of its own.
