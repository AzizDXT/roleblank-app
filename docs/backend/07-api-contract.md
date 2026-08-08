# 07 — API Contract

Base path `/api/v1`. The machine-readable contract is `api/openapi.yaml`, and a
test (`tests/openapi_contract.rs`) fails the build if that document and the router
disagree. This page is the human-readable companion: the conventions, and the
reasoning behind the ones that are not obvious.

## 1. Transport

- JSON only. `Content-Type: application/json` is required on every request with a
  body; `application/x-www-form-urlencoded` and `multipart/form-data` are refused.

  That refusal is also this API's CSRF answer: a browser can issue a cross-site
  form POST, but it cannot set `Content-Type: application/json` without a preflight
  the CORS policy refuses. Combined with never reading cookies, the API has no CSRF
  surface of its own.
- Responses are `application/json`, or `application/problem+json` on error.
- `Authorization: Bearer <token>` is the only authentication mechanism. No cookies,
  no query parameters, no custom headers.
- Every response carries `X-Request-Id`, `X-Content-Type-Options: nosniff`, and
  `Cache-Control: no-store, no-cache, must-revalidate, private`.
- No state-changing `GET`. Asserted by a test over the route table.

## 2. Errors — RFC 9457 Problem Details

```jsonc
{
  "type":       "https://roleblank.internal/problems/authorization_denied",
  "title":      "You are not authorized to perform this operation",
  "status":     403,
  "code":       "AUTHORIZATION_DENIED",
  "detail":     "Your effective permissions do not allow this operation.",
  "request_id": "0192f5c1-7c3a-7e1b-9f2d-3a4b5c6d7e8f",
  "errors":     [ { "field": "name", "code": "TOO_LONG", "message": "..." } ]
}
```

**Branch on `code`.** It is part of the contract and is stable. `title` and
`detail` are human text and may be reworded in any release. `type` is a stable
identifier, not a resolvable URL — resolving it must never be required to handle an
error, and pointing at an external host would leak error occurrence to that host.

`detail` never contains SQL, a stack trace, a file path, an environment variable, a
database hostname, or a driver message. Internal causes are logged against
`request_id` instead.

### The full code set

| Status | `code` | Meaning |
| --- | --- | --- |
| 400 | `VALIDATION_FAILED` | one or more fields invalid; see `errors` |
| 400 | `BAD_REQUEST` | malformed body, unknown JSON field, or a token in the URL |
| 400 | `UNKNOWN_PERMISSION` | a permission code outside the catalogue was supplied |
| 401 | `AUTHENTICATION_FAILED` | **every** authentication failure mode |
| 403 | `AUTHORIZATION_DENIED` | permission denied (internal principals) |
| 403 | `STEP_UP_REQUIRED` | recent MFA verification required; carries `step_up.window_seconds` |
| 403 | `MFA_REQUIRED` | this session must complete MFA first |
| 403 | `ROOT_PROTECTED` | the operation targeted the system owner |
| 403 | `DELEGATION_DENIED` | the actor cannot grant authority it does not hold |
| 404 | `RESOURCE_NOT_FOUND` | absent — **or invisible to an external principal** |
| 409 | `UNIQUE_VIOLATION`, `REFERENCE_VIOLATION`, `INVARIANT_VIOLATION` | constraint conflicts |
| 409 | `VERSION_CONFLICT` | stale `version`; carries `expected` and `actual` |
| 409 | `IDEMPOTENCY_KEY_REUSED` | same key, different body |
| 409 | `SYSTEM_ALREADY_INITIALIZED` | bootstrap is permanently closed |
| 413 | `PAYLOAD_TOO_LARGE` | body exceeds 256 KiB |
| 415 | `UNSUPPORTED_MEDIA_TYPE` | not `application/json` |
| 429 | `RATE_LIMITED` | carries `Retry-After` |
| 500 | `INTERNAL_ERROR` | quote `request_id` when reporting |
| 503 | `SERVICE_UNAVAILABLE` | a required dependency is down |

### `AUTHENTICATION_FAILED` is deliberately undifferentiated

Unknown account, wrong password, suspended user, expired token, revoked session and
malformed bearer header all return the same status, code and detail. Any
distinction is an account-enumeration oracle. The unknown-account path additionally
performs a full Argon2id verification against a dummy hash so the timing matches.

### `404` versus `403`

| Situation | Response |
| --- | --- |
| An external (`CLIENT`) principal requests something it cannot see | `404` — a `403` would confirm the object exists |
| An external principal calls an internal-only route | `404` |
| An internal principal lacks a permission on an object that exists | `403` |
| Any principal targets the system owner with a forbidden operation | `403 ROOT_PROTECTED` — ROOT's existence is not a secret and the refusal must be unmistakable |

Applied per principal type in one place, not blanket. A blanket `404` inside the
company would make operational support impossible.

## 3. Pagination

Cursor-based (keyset), never offset. `OFFSET 100000` makes PostgreSQL walk and
discard a hundred thousand rows, letting a client turn a cheap endpoint into an
expensive one by incrementing a number.

```
GET /api/v1/projects?limit=25&sort=created_at&direction=desc&cursor=<opaque>
```

```json
{ "items": [ ... ], "next_cursor": "AAABi...", "has_more": true }
```

| Parameter | Rules |
| --- | --- |
| `limit` | 1–100, default 25. Out of range is `400`, not silently clamped |
| `sort` | **allowlisted per endpoint.** Most collections allow only `created_at` and `updated_at`; see `docs/product/01-application-structure.md` §9 for the exact list per endpoint. Anything else is `400 NOT_ALLOWED`, and the rejected value is not echoed back |
| `direction` | `asc` \| `desc` |
| `cursor` | opaque, length-bounded, structurally validated. Not signed — it is not a security boundary, and a forged cursor can only reposition a query the caller was already authorised to run |

`sort` is an allowlist because `ORDER BY` cannot be parameterised: it is either an
allowlist or it is SQL injection. Each public field name maps to a compile-time
`&'static str`; the user's string is only ever compared.

A narrow permission scope turns a list endpoint into a *filtered query*, not a
refused one. `Target::Collection` is covered only by `GLOBAL` scope, which is what
prevents "authorise, then fetch everything and filter in Rust".

## 4. Optimistic concurrency

Editable resources carry `version`. Updates must send the version they read:

```jsonc
PATCH /api/v1/projects/{id}
{ "version": 3, "name": "New name" }
```

A stale version is `409 VERSION_CONFLICT` with `expected` and `actual` in `detail`.
Nothing is ever silently overwritten.

## 5. Idempotency

`Idempotency-Key: <8–200 printable ASCII characters>` on create operations where a
retry could duplicate something consequential: invitations, user creation, project
creation, client creation.

- Scoped by `(principal, operation, key)`. An unscoped key namespace would let one
  principal replay another's response.
- The body is fingerprinted. Same key + same body replays the stored response; same
  key + **different** body is `409 IDEMPOTENCY_KEY_REUSED` rather than a silently
  wrong replay.
- Records expire; the key is not permanent.
- **Not** applied to authentication endpoints — replaying a login is not a safe
  operation to make idempotent.

## 6. Request bodies

Every request DTO is closed (`deny_unknown_fields`). An unrecognised field is a
`400`, not an ignored extra. This is the mass-assignment defence: a payload
carrying `is_root`, `principal_type`, `role_ids`, `permissions`, `status` or
`client_visible` on an endpoint that does not authorise changing it does not
silently drop the field — it fails.

Fields a request DTO never contains unless the endpoint explicitly authorises the
change: `id`, `created_by`, `created_at`, `version` (except as the concurrency
token), `security_version`, `principal_type`, `is_root`, `role_ids`, `permissions`,
`status` on create.

## 7. Response shaping

Response DTOs are hand-written and are never a database row struct. For anything an
external principal can see there are two distinct types:

```
ProjectResponse   ≠   ClientProjectResponse
TaskResponse      ≠   ClientTaskResponse
```

`internal_note`, `created_by`, `manager_user_id`, `department_id` and `version` are
**physically absent** from the client types — not skipped during serialisation. A
skipped field is one attribute away from being included; an absent field cannot be.
Serialisation tests assert the JSON keys.

`credentials` is a separate table from `users` for the same reason at the storage
layer: the query that runs on every authenticated request *cannot* return a
password hash.

## 8. Authentication flow

```
POST /api/v1/auth/login          { email, password }
  → 200 { access_token, refresh_token, expires_in, mfa_required, token_type }

  mfa_required = true  ⇒  the session is PENDING and may call ONLY:
                          GET  /api/v1/auth/me            (reduced projection)
                          POST /api/v1/auth/mfa/*
                          POST /api/v1/auth/logout
                          everything else ⇒ 403 MFA_REQUIRED

POST /api/v1/auth/mfa/verify     { code }        → the session becomes MFA-level
POST /api/v1/auth/refresh        { refresh_token } → rotates BOTH tokens
POST /api/v1/auth/logout                          → revokes this session
```

Tokens are **opaque server-side session handles, not JWTs**. Nothing about a
principal's authority is encoded in them; the server is authoritative on every
request, so a permission change takes effect on the very next call.

| Lifetime | Default |
| --- | --- |
| access | 15 minutes |
| idle | 7 days |
| absolute | 30 days — no amount of refreshing extends it |

### Refresh must be serialised by the client

Rotation is unconditional and reuse is treated as compromise: presenting a refresh
token that has already been consumed revokes the **entire session family** and
audits `AUTH.REFRESH_REUSE_DETECTED`. Two concurrent refreshes therefore end the
session. This is stricter than necessary for a merely racy client, and the
strictness is intended — a spurious re-login is a smaller harm than an undetected
persistent session.

## 9. Step-up authentication

Sensitive operations require `mfa_verified_at` within the configured window
(default 600 s, bounded 60–1800). Failure is:

```jsonc
{ "status": 403, "code": "STEP_UP_REQUIRED", "step_up": { "window_seconds": 600 } }
```

Re-prompt for a TOTP code, call `POST /api/v1/auth/mfa/verify`, retry. The list of
step-up operations lives in one place and is asserted against the route table by
test — a client cannot be relied on to know it, and the backend does not rely on a
client knowing it.

## 10. Capability discovery

`GET /api/v1/auth/me` returns the principal plus its effective capabilities:

```jsonc
{
  "user_id": "…", "principal_type": "INTERNAL", "is_root": false,
  "security_version": 7, "mfa_enrolled": true, "step_up_active": false,
  "capabilities": [ { "permission": "projects.read", "scopes": ["ASSIGNED"] } ]
}
```

**This is a hint for hiding buttons, not a security boundary.** The backend
re-derives every decision per request regardless of what the client believes.
`security_version` increments on any privilege change, so a client can detect that
its capability set moved and re-fetch.

An external principal's capability list can only ever contain the two
`client.portal.*` permissions — asserted by a property test over random grants.

## 11. Anonymous surface

Exactly twelve routes, pinned by a test so that growing this set is a deliberate,
reviewed change:

```
GET  /health/live                        GET  /health/ready
GET  /metrics
GET  /api/v1/bootstrap/status            POST /api/v1/bootstrap/root
POST /api/v1/auth/login                  POST /api/v1/auth/refresh
POST /api/v1/auth/password-reset/request POST /api/v1/auth/password-reset/confirm
GET  /api/v1/registration/config         POST /api/v1/registration
POST /api/v1/invitations/accept
```

Each is rate limited. `bootstrap/status` returns a single boolean and nothing else.
`registration/config` returns only whether registration is open and, if so, that it
is of type `client` — never a security setting.

## 12. Endpoints that deliberately do not exist

Their absence is a design decision, and adding any of them needs an ADR rather than
a pull request:

| Absent | Why |
| --- | --- |
| `DELETE /api/v1/users/{id}` | users are archived, never erased — historical references and audit meaning must survive. The runtime database role has no `DELETE` grant on `users` at all |
| Any audit write, update, delete or purge | audit history has no mutation path (ADR-006) |
| Ownership transfer | any code path that can move ownership can be abused to steal it (ADR-004). Recovery is offline and documented |
| File upload | no storage layer exists; `12-future-storage.md` records what must be true first |
| Any URL-fetching endpoint | this is why the SSRF class is absent by construction |
| A debug or "run SQL" endpoint | — |

## 13. Limits

| Limit | Value |
| --- | --- |
| request body | 256 KiB |
| request timeout | 30 s |
| page size | 100 |
| array length in a request | 100 items |
| `Idempotency-Key` | 8–200 characters |
| `X-Request-Id` (if supplied) | 8–64 characters, `[A-Za-z0-9_-]` only |
| bearer header | 512 bytes |

A caller-supplied `X-Request-Id` outside that alphabet is silently replaced with a
generated one rather than rejected — echoing an arbitrary string into logs is a
log-injection vector, and failing the request over a cosmetic header would be worse
than ignoring it.

## 14. Versioning

`/api/v1` is a stability promise. Within it: fields may be **added** to responses,
new optional request fields may be added, and new endpoints may appear. Removing a
field, tightening a constraint, changing a `code`, or changing an authorisation
requirement is a `v2` change.

Because request DTOs reject unknown fields, clients must not send fields they do
not understand — forward compatibility runs in one direction only, and that is the
direction that keeps mass assignment impossible.
