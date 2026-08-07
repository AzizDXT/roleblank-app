# ADR-005 — Session model

**Status:** Accepted · **Date:** 2026-08-07 · **Refines:** ADR-002

## Context

Sessions must be revocable instantly, must survive across three future client platforms,
must not be replayable after theft for long, and must not become a persistence mechanism
for an attacker who obtained a token once.

## Decision

One `sessions` row per session holding the **current** access-token digest, plus a child
table `session_refresh_tokens` retaining **every** refresh generation including consumed
ones.

| Lifetime | Default | Purpose |
| --- | --- | --- |
| access | 15 min | bounds replay of a stolen access token |
| idle | 7 days | closes abandoned sessions |
| absolute | 30 days | a session can never be refreshed indefinitely |

Validity is a single query with a join to `users`, requiring simultaneously:
`revoked_at IS NULL`, `now() < access_expires_at`, `now() < idle_expires_at`,
`now() < absolute_expires_at`, `users.status = 'ACTIVE'`.

## Rationale

**Why the user-status join rather than a revocation job.** Suspending a user must kill their
sessions. Doing it with a background sweep leaves a window; doing it with a `UPDATE
sessions` fan-out is a second write that can fail independently. Joining `users.status` into
the session-validation query makes suspension effective on the very next request, for every
session, atomically, with no job to fail. Explicit revocation rows are still written for
audit and for the user's session list, but correctness does not depend on them.

**Why an absolute lifetime.** Rotation alone lets a session live forever as long as it keeps
refreshing. An attacker who successfully rotates a stolen family retains access
indefinitely. `absolute_expires_at` is a hard ceiling that no refresh extends, so every
compromise has a bounded end.

**Why consumed refresh rows are retained.** They *are* the theft detector. A hit on a
consumed row means two parties hold the same refresh token; the only safe interpretation is
compromise, so the whole family is revoked with reason `REFRESH_REUSE_DETECTED` and an audit
event is written. Deleting consumed rows would delete the signal.

**Why `FOR UPDATE` on the refresh row.** Two concurrent refreshes must have a deterministic
outcome. Row-level locking makes exactly one the winner; the loser observes a consumed row
and triggers family revocation. This is stricter than necessary for a merely racy client,
and that strictness is the intended posture — it is exercised by `race_refresh_reuse`.

**Why session IDs are never credentials.** `sessions.id` appears in audit events and in the
user's own session list. It cannot be used to authenticate; only the token digest can, and
the digest is not derivable from the id.

**Why device metadata is a "hint".** `client_ip_hint` and `user_agent_hint` are stored
truncated and control-character-stripped, purely so a user can recognise their own sessions.
They are never used for authorisation — IP-based session binding breaks mobile clients on
every network change and provides an attacker with a spoofable input.

## Consequences

- Refresh must be serialised by the client. Documented in the API contract.
- `session_refresh_tokens` grows at one row per refresh; bounded by a documented retention
  sweep that only removes rows from sessions ended more than N days ago.
- Password change revokes all *other* sessions; password reset and suspension revoke *all*.
- A user on a poor network that retries a refresh will occasionally be logged out. Accepted;
  the alternative is a grace window in which reuse is indistinguishable from theft.

## Alternatives rejected

| Alternative | Why not |
| --- | --- |
| Reuse window (accept the previous token for N seconds) | Makes theft detection probabilistic and gives a real attacker a usable window |
| Sliding expiry with no absolute cap | A compromised family never ends |
| Session data in a signed cookie | Not revocable; also introduces CSRF surface the API currently does not have |
| Redis session store | Second source of truth for the most security-critical state in the system |
| IP-bound sessions | Breaks legitimate mobile use; spoofable behind proxies |
