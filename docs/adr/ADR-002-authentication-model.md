# ADR-002 — Authentication model

**Status:** Accepted · **Date:** 2026-08-07

## Context

Three future clients — a web BFF, Flutter iOS and Flutter Android — must authenticate
against one API. Permission changes and account suspension must take effect immediately.
Privileged principals must not be able to bypass MFA.

## Decision

1. **Opaque, high-entropy, server-side session tokens** carried in `Authorization: Bearer`.
   No JWT. No authority encoded in any token.
2. **Access + refresh pair**, refresh rotated on every use, reuse of a consumed refresh
   token revokes the entire session family.
3. **Argon2id** for passwords, with bounded hashing concurrency.
4. **TOTP (RFC 6238)** implemented over the RustCrypto `hmac` + `sha1` primitives, verified
   against the RFC's own test vectors, rather than pulling a third-party TOTP crate.
5. **Step-up authentication** gated on `sessions.mfa_verified_at` recency for a fixed list
   of sensitive operations.
6. A password-only session for an MFA-required user exists in a **`pending_mfa`** state that
   can reach only the MFA endpoints.

## Rationale

**Opaque over JWT.** The requirement "role/permission changes must take effect immediately"
and "authorization-bearing JWT" are mutually exclusive. A JWT is valid until it expires;
making it revocable requires a per-request server-side denylist lookup — the same lookup an
opaque token needs, plus signature verification, plus key rotation, plus a family of
algorithm-confusion and `alg: none` bugs the system now simply does not have. The token is
a lookup key and nothing more.

**Hashed at rest with SHA-256, not Argon2.** The token is 256 bits of CSPRNG output. There
is no low-entropy secret for a KDF to protect; a slow hash on the hottest query in the
system would cost latency and buy nothing. A stolen dump yields digests of uniformly random
256-bit values.

**Refresh rotation with family revocation.** Rotation alone does not detect theft — it just
narrows the window. Retaining consumed refresh rows and treating a hit on one as a
*positive signal of compromise* is what converts theft into detection. The conservative
consequence — a concurrent double-refresh from a legitimate client also kills the family —
is accepted deliberately: a spurious re-login is a smaller harm than an undetected
persistent session, and it is explicitly tested (`race_refresh_reuse`).

**Own TOTP construction.** Deliberate and narrow. The *primitives* (HMAC, SHA-1) come from
audited RustCrypto crates; only the RFC 6238 counter/truncation construction — roughly
thirty lines, fully specified by the RFC — is ours, and it is validated against the RFC's
published Appendix B test vectors for SHA-1, SHA-256 and SHA-512. The alternative,
`totp-rs`, pulls a materially larger tree (including QR-code and image handling by default)
for a construction that is smaller than its own README. **No cryptographic primitive is
implemented here**; the brief's prohibition is respected.

**`pending_mfa` rather than "no session until MFA".** A separate short-lived pre-auth token
type would be a second credential kind with its own storage, expiry and revocation
semantics — more surface for the same result. Reusing the session record with a
capability gate keeps one revocation path and one storage format.

## Consequences

- Every authenticated request costs one indexed lookup on `sessions(access_token_hash)`.
  Measured in `PERFORMANCE_REPORT.md`.
- Suspension, password change and privilege change are effective on the next request with
  no background job and no cache invalidation.
- Legitimate clients must serialise their refresh calls; the API contract states this.
- Losing both the authenticator and all recovery codes requires an operator-side reset.
  Documented in `08-operations.md`.
- MFA cannot be skipped by a privileged user: there is no state in which a password-only
  session can call a business endpoint.

## Alternatives rejected

| Alternative | Why not |
| --- | --- |
| JWT access + opaque refresh | Access token remains valid after revocation for its lifetime — directly violates the immediate-revocation requirement |
| Long-lived single token | No rotation, no theft detection |
| bcrypt / PBKDF2 / scrypt | Argon2id is current OWASP guidance; bcrypt additionally truncates at 72 bytes, which breaks the passphrase support required here |
| WebAuthn as the only second factor | Correct long-term direction, but excludes users without a compatible authenticator today. Recorded as future work; the `mfa_factors.factor_type` column already admits a second value |
