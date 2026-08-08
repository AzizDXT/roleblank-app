# Route security matrix

Regenerated from the current source. Every one of the **95** entries in
`backend/src/routes.rs` `ROUTE_TABLE` has a row below.

Each column was filled by reading the mounted handler and the service it
delegates to, not by copying `ROUTE_TABLE`. Where the declared table and the code
disagree, the code is reported and the disagreement is listed in
§14 "Routes with unclear security posture".

## Status of the general rate limiter

A **general rate limiter is newly enforced**, in two layers. Both were verified
present in the source at the time this document was regenerated.

| Layer | Where it runs | Key | Default quota | Applies to |
|---|---|---|---|---|
| **general-authenticated** | inside the `Authenticated` and `MfaPendingSession` extractors, after the principal is resolved and **before** any authorisation or resource work | `general:user:{user_id}` | 600/min, and **3000/min for the system owner** — a larger budget, not an exemption | every route that requires a session |
| **coarse pre-auth ceiling** | the innermost middleware layer, before authentication | `general:ip:{ip}` | 3000/min | *every* request, including anonymous ones and requests bearing invalid tokens |

The per-principal budget is keyed on the **user id**, not the session and not the
address: a session key would let one compromised account multiply its budget by
minting sessions, and an address key would make one office behind a NAT share a
single budget.

The coarse per-IP ceiling exists because resolving a bearer token costs a database
query whether or not the token is real. It is deliberately generous and is not the
control that governs normal traffic.

Because both layers exist, **no route is completely unlimited**. Rows that say
"coarse per-IP ceiling only" carry no dedicated limiter of their own; rows that say
`anonymous-operation` carry a tight, purpose-built one on top of the ceiling.

A frontend must handle `429 RATE_LIMITED` with `Retry-After` on every route.

## How to read the columns

| Column | Meaning |
| --- | --- |
| **Access** | `anon` — no session, no `Authorization` header needed. `mfa-pending` — the `MfaPendingSession` extractor: accepts a password-only session *and* a fully verified one. `auth` — the `Authenticated` extractor, which rejects a session with `pending_mfa = true` with `403 MFA_REQUIRED` (`platform/http/extract.rs`). |
| **Principals** | Which principal types can actually succeed. Derived from `max_principal_type` in `modules/authorization/catalog.rs`: every code except `client.portal.*` is `INTERNAL`, so a `CLIENT` principal is refused at the envelope before any grant is consulted. |
| **Permission** | The code the service passes to `state.require`. `—` when the handler takes no permission decision. |
| **Object-level authz** | `row` — the service loads the row (usually `FOR UPDATE`) and builds a `TargetContext` from the **loaded** row before calling `state.require`. `collection` — authorised against `Target::Collection`, which `evaluator::scope_covers` admits only for `GLOBAL`. `filter` — the actor's scopes become a SQL `WHERE` clause; no per-row `require` runs. `self` — the subject is the calling session, resolved from the bearer token. `—` — no authorisation decision. |
| **Scope** | Which scope types can reach this operation. `GLOBAL only` for collection targets; `object` means `GLOBAL / DEPARTMENT / ASSIGNED / RESOURCE` are all evaluated against the loaded row (`SELF` for user targets). |
| **Step-up** | Whether a recent second factor is enforced *in code*, and where. `route` means `ROUTE_TABLE` declares `step_up = true`; the enforcing call is named. |
| **Rate-limit class** | `anonymous-operation` — the endpoint carries its own dedicated limiter for an unauthenticated flow. `general-authenticated` — covered by the newly enforced per-principal limiter charged in the extractor. `coarse per-IP ceiling only` — no dedicated limiter; only the pre-auth address ceiling applies. Dedicated limiters that additionally apply are named. |
| **Audit** | The `action::*` constants the service writes. `—` for reads that write nothing. |
| **Client-safe** | Whether an external `CLIENT` principal is answered `404` rather than `403` (`AppError::hide_from_external`), and whether the response body is a reduced client projection. |
| **Idem.** | `key` — the handler takes `Idempotent<T>` and honours `Idempotency-Key`. `—` — the header is not read. |
| **Success** | The status the handler returns on success. |
| **Distinctive errors** | Codes beyond the universal set below. |

### Universal error codes

Every route can also produce these, so they are not repeated per row:

* `INTERNAL_ERROR` (500), `SERVICE_UNAVAILABLE` (503 — database unreachable, or the
  request timeout fired).
* `RATE_LIMITED` (429), with a `Retry-After` header — every route is now covered by
  at least the coarse per-IP ceiling, and every authenticated route by the
  per-principal budget as well.
* Every **authenticated** route: `AUTHENTICATION_FAILED` (401),
  `MFA_REQUIRED` (403 — only from the `auth` extractor), `AUTHORIZATION_DENIED`
  (403, or `RESOURCE_NOT_FOUND` 404 for a CLIENT principal).
* Every route taking a `{id}` path segment: `VALIDATION_FAILED` (400) with field
  code `INVALID_UUID`.
* Every route with a JSON body: `UNSUPPORTED_MEDIA_TYPE` (415),
  `PAYLOAD_TOO_LARGE` (413), `BAD_REQUEST` (400 — malformed JSON or an
  unrecognised field, because every request DTO is `deny_unknown_fields`).
* Every route with a query string: `BAD_REQUEST` (400) for an unrecognised
  parameter.

---

## 1. Health and platform (3)

| METHOD | PATH | Access | Principals | Permission | Object-level authz | Scope | Step-up | Rate-limit class | Audit | Client-safe | Idem. | Success | Distinctive errors |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| GET | `/health/live` | anon | anyone | — | — | n/a | no | coarse per-IP ceiling only | — | n/a — fixed `{"status":"ok"}`, no database call | — | 200 | none |
| GET | `/health/ready` | anon | anyone | — | — | n/a | no | coarse per-IP ceiling only | — | n/a — closed two-value document; the service collapses every failure to a `bool` | — | 200 | 503 with the plain body `{"status":"not_ready"}` — **not** problem+json |
| GET | `/metrics` | anon | anyone | — | — | n/a | no | coarse per-IP ceiling only | — | n/a — Prometheus text; carries no principal-identifying label | — | 200 | `RESOURCE_NOT_FOUND` (404) when `RB_METRICS_ENABLED=false` |

## 2. Bootstrap (2)

| METHOD | PATH | Access | Principals | Permission | Object-level authz | Scope | Step-up | Rate-limit class | Audit | Client-safe | Idem. | Success | Distinctive errors |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| GET | `/api/v1/bootstrap/status` | anon | anyone | — | — | n/a | no | coarse per-IP ceiling only (no dedicated limiter) | — | n/a — one boolean | — | 200 | none |
| POST | `/api/v1/bootstrap/root` | anon | anyone | — | advisory lock + `system_state FOR UPDATE` | n/a | no | anonymous-operation (`bootstrap:ip:{ip}`) | `SYSTEM.BOOTSTRAPPED`, `SYSTEM.BOOTSTRAP_REJECTED` | n/a — `404` when no operator secret is configured; wrong secret and already-initialised are the same `401` | — | 201 | `RESOURCE_NOT_FOUND` (404, secret not configured), `AUTHENTICATION_FAILED` (401), `SYSTEM_ALREADY_INITIALIZED` (409), `VALIDATION_FAILED` (400), `RATE_LIMITED` (429) |

## 3. Authentication (16)

Object-level authorisation does not apply to any of these: the subject is always
the calling session. `DELETE /auth/sessions/{id}` is the only one taking an id,
and ownership is a predicate inside the `UPDATE`.

| METHOD | PATH | Access | Principals | Permission | Object-level authz | Scope | Step-up | Rate-limit class | Audit | Client-safe | Idem. | Success | Distinctive errors |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| POST | `/api/v1/auth/login` | anon | INTERNAL + CLIENT | — | — | n/a | no | anonymous-operation (`login:ip:{ip}` **and** `login:acct:{email}`) | `AUTH.LOGIN_SUCCEEDED`, `AUTH.LOGIN_FAILED`, `SESSION.REVOKED` (session-cap eviction) | n/a — one undifferentiated `401` for every failure mode; dummy Argon2 on the unknown-account path | — | 200 | `AUTHENTICATION_FAILED` (401), `RATE_LIMITED` (429) |
| POST | `/api/v1/auth/refresh` | anon | INTERNAL + CLIENT | — | refresh-token row `FOR UPDATE` | n/a | no | anonymous-operation (`refresh:ip:{ip}`) | `AUTH.REFRESHED`, `AUTH.REFRESH_REUSE_DETECTED` | n/a — reuse kills the token family and still returns the generic `401` | — | 200 | `AUTHENTICATION_FAILED` (401), `RATE_LIMITED` (429) |
| POST | `/api/v1/auth/logout` | **mfa-pending** (the table declares `Authenticated`; see §14) | INTERNAL + CLIENT | — | self | self | no | general-authenticated | `AUTH.LOGOUT` | n/a | — | 200 | — |
| POST | `/api/v1/auth/logout-all` | auth | INTERNAL + CLIENT | — | self | self | no | general-authenticated | `SESSION.REVOKED_ALL` | n/a | — | 200 | — |
| GET | `/api/v1/auth/me` | mfa-pending | INTERNAL + CLIENT | — | self | self | no | general-authenticated | — | n/a — a pending session receives the structurally smaller `PendingMfaMeResponse`, with no capability list, no `is_root` and no `auth_level` | — | 200 | — |
| GET | `/api/v1/auth/sessions` | auth | INTERNAL + CLIENT | — | self (SQL-scoped to `principal.user_id()`) | self | no | general-authenticated | — | n/a — no path parameter exists, so no other list is addressable | — | 200 | — |
| DELETE | `/api/v1/auth/sessions/{id}` | auth | INTERNAL + CLIENT | — | SQL predicate `WHERE id = $1 AND user_id = $2` | self | no | general-authenticated | `SESSION.REVOKED` | n/a — zero rows affected renders `404`, identical to "somebody else's session" | — | 200 | `RESOURCE_NOT_FOUND` (404) |
| POST | `/api/v1/auth/password/change` | auth | INTERNAL + CLIENT | — | self | self | no | general-authenticated **plus** `login:acct:{own email}` | `PASSWORD.CHANGED` | n/a — the current password is required even with a valid session | — | 200 | `AUTHENTICATION_FAILED` (401 — wrong current password), `VALIDATION_FAILED` (400 — password policy), `RATE_LIMITED` (429) |
| POST | `/api/v1/auth/password-reset/request` | anon | INTERNAL + CLIENT | — | — | n/a | no | anonymous-operation (`pwreset:ip:{ip}` **and** `pwreset:acct:{email}`) | `PASSWORD.RESET_REQUESTED` | n/a — always `202` with a fixed body type that has no variable field | — | 202 | `RATE_LIMITED` (429) |
| POST | `/api/v1/auth/password-reset/confirm` | anon | INTERNAL + CLIENT | — | reset-token row `FOR UPDATE` | n/a | no | anonymous-operation (`pwreset:ip:{ip}`) | `PASSWORD.RESET_COMPLETED`, `SESSION.REVOKED_ALL` | n/a — every rejection is the same `401` | — | 200 | `AUTHENTICATION_FAILED` (401), `VALIDATION_FAILED` (400), `RATE_LIMITED` (429) |
| POST | `/api/v1/auth/mfa/totp/setup` | mfa-pending | INTERNAL + CLIENT | — | self | self | no | general-authenticated **plus** `mfa:sess:{sid}` and `mfa:user:{uid}` | `MFA.ENROLMENT_STARTED` | n/a | — | 201 | `MFA_ALREADY_ENROLLED` (409), `RATE_LIMITED` (429) |
| POST | `/api/v1/auth/mfa/totp/activate` | mfa-pending | INTERNAL + CLIENT | — | self (factor `FOR UPDATE`) | self | no | general-authenticated **plus** `mfa:sess` + `mfa:user` | `MFA.ACTIVATED`, `MFA.RECOVERY_CODES_GENERATED`, `MFA.REPLAY_DETECTED`, `MFA.VERIFICATION_FAILED` | n/a | — | 200 | `MFA_NOT_PENDING` (409), `AUTHENTICATION_FAILED` (401 — bad code), `RATE_LIMITED` (429) |
| POST | `/api/v1/auth/mfa/verify` | mfa-pending | INTERNAL + CLIENT | — | self (factor `FOR UPDATE`) | self | no | general-authenticated **plus** `mfa:sess` + `mfa:user` | `AUTH.STEP_UP_COMPLETED`, `MFA.REPLAY_DETECTED`, `MFA.VERIFICATION_FAILED` | n/a | — | 200 | `AUTHENTICATION_FAILED` (401), `RATE_LIMITED` (429) |
| POST | `/api/v1/auth/mfa/recovery/verify` | mfa-pending | INTERNAL + CLIENT | — | self | self | no | general-authenticated **plus** `mfa:sess` + `mfa:user` | `MFA.RECOVERY_CODE_CONSUMED`, `MFA.VERIFICATION_FAILED` | n/a | — | 200 | `AUTHENTICATION_FAILED` (401), `RATE_LIMITED` (429) |
| POST | `/api/v1/auth/mfa/recovery/regenerate` | auth | INTERNAL + CLIENT | — | self | self | **yes** — route flag + `state.require_step_up` in the service | general-authenticated **plus** `mfa:sess` + `mfa:user` | `MFA.RECOVERY_CODES_GENERATED` | n/a | — | 200 | `STEP_UP_REQUIRED` (403), `MFA_NOT_ENROLLED` (409), `RATE_LIMITED` (429) |
| POST | `/api/v1/auth/mfa/disable` | auth | INTERNAL + CLIENT | — | self | self | **yes** — route flag + `state.require_step_up` | general-authenticated **plus** `mfa:sess` + `mfa:user` | `MFA.DISABLED` | n/a | — | 200 | `STEP_UP_REQUIRED` (403), `MFA_MANDATORY` (409 — refused outright when the account has `mfa_required`) |

## 4. Registration and invitation acceptance (3)

| METHOD | PATH | Access | Principals | Permission | Object-level authz | Scope | Step-up | Rate-limit class | Audit | Client-safe | Idem. | Success | Distinctive errors |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| GET | `/api/v1/registration/config` | anon | anyone | — | — | n/a | no | coarse per-IP ceiling only (no dedicated limiter) | — | n/a — two fields; an unreadable setting fails closed to "disabled" | — | 200 | none (a database failure is reported as "closed", not as an error) |
| POST | `/api/v1/registration` | anon | anyone (produces a CLIENT) | — | — | n/a | no | anonymous-operation (`register:ip:{ip}`) | `USER.REGISTERED` (Success **and** Denied) | n/a — always `202` with a byte-identical body; `principal_type = CLIENT` and `status = PENDING` are literals in code with no DTO field | — | 202 | `RESOURCE_NOT_FOUND` (404 — self-registration disabled, which is the default), `VALIDATION_FAILED` (400), `RATE_LIMITED` (429) |
| POST | `/api/v1/invitations/accept` | anon | anyone (produces the invited principal type) | — | invitation row `FOR UPDATE`; the inviter's authority is re-derived at acceptance | n/a | the inviter's step-up recency is asserted `true` at acceptance, deliberately | anonymous-operation (`invite-accept:ip:{ip}` — a **separate** budget from registration) | `USER.CREATED`, `INVITATION.ACCEPTED` | n/a — every rejection reason is the same `401` | — | 201 | `AUTHENTICATION_FAILED` (401), `VALIDATION_FAILED` (400), `RATE_LIMITED` (429) |

## 5. Users (6)

`iam.users.*` is `INTERNAL` in the catalogue, so a CLIENT principal is refused at
the envelope and receives `404`.

| METHOD | PATH | Access | Principals | Permission | Object-level authz | Scope | Step-up | Rate-limit class | Audit | Client-safe | Idem. | Success | Distinctive errors |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| GET | `/api/v1/users` | auth | INTERNAL only | `iam.users.read` | filter (scopes become a SQL `WHERE`; DENY overrides become exclusions) | scope-filtered; `GLOBAL` short-circuits the filter | no | general-authenticated | — | yes — 404 for CLIENT | — | 200 | — |
| GET | `/api/v1/users/{id}` | auth | INTERNAL only | `iam.users.read` | row (`TargetContext::other_user`) | object (`GLOBAL` / `SELF` / `RESOURCE`) | no | general-authenticated | — | yes | — | 200 | `RESOURCE_NOT_FOUND` (404) |
| PATCH | `/api/v1/users/{id}` | auth | INTERNAL only | `iam.users.update` | row (`FOR UPDATE`) | object | conditional — `require_step_up_for`; `iam.users.update` is **not** dangerous, so no step-up in practice | general-authenticated | `USER.UPDATED`, `ROOT.PROTECTION_TRIGGERED` on a ROOT target | yes | — | 200 | `VERSION_CONFLICT` (409), `ROOT_PROTECTED` (403), `EMAIL_IN_USE` (409), `VALIDATION_FAILED` (400) |
| POST | `/api/v1/users/{id}/suspend` | auth | INTERNAL only | `iam.users.suspend` | row (`FOR UPDATE`) | object | conditional (not dangerous → none) | general-authenticated | `USER.SUSPENDED`, `SESSION.REVOKED_ALL`, `ROOT.PROTECTION_TRIGGERED` | yes | — | 200 | `VERSION_CONFLICT` (409), `ROOT_PROTECTED` (403), `SELF_TARGET_REFUSED` (409), `INVALID_STATUS_TRANSITION` (409) |
| POST | `/api/v1/users/{id}/reactivate` | auth | INTERNAL only | `iam.users.suspend` | row (`FOR UPDATE`) | object | conditional (not dangerous → none) | general-authenticated | `USER.REACTIVATED`, `ROOT.PROTECTION_TRIGGERED` | yes | — | 200 | `VERSION_CONFLICT` (409), `ROOT_PROTECTED` (403), `SELF_TARGET_REFUSED` (409), `INVALID_STATUS_TRANSITION` (409) |
| POST | `/api/v1/users/{id}/archive` | auth | INTERNAL only | `iam.users.archive` | row (`FOR UPDATE`) | object | conditional (not dangerous → none) | general-authenticated | `USER.ARCHIVED`, `SESSION.REVOKED_ALL`, `ROOT.PROTECTION_TRIGGERED` | yes | — | 200 | `VERSION_CONFLICT` (409), `ROOT_PROTECTED` (403), `SELF_TARGET_REFUSED` (409), `INVALID_STATUS_TRANSITION` (409) |

## 6. Invitations (3)

| METHOD | PATH | Access | Principals | Permission | Object-level authz | Scope | Step-up | Rate-limit class | Audit | Client-safe | Idem. | Success | Distinctive errors |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| GET | `/api/v1/invitations` | auth | INTERNAL only | `iam.users.invite` | collection | GLOBAL only | no | general-authenticated | — | yes | — | 200 | — |
| POST | `/api/v1/invitations` | auth | INTERNAL only | `iam.users.invite` | collection, **plus** a placement decision against the named department (`departments.members.manage`) and/or client account (`clients.members.manage`), **plus** the delegation guard on every role | GLOBAL only for the invite itself; object for each placement | **conditional** — `state.require_step_up` fires when any named role carries a dangerous permission | general-authenticated | `INVITATION.CREATED` | yes | **key** | 201 | `EMAIL_IN_USE` (409), `DELEGATION_DENIED` (403), `STEP_UP_REQUIRED` (403), `VALIDATION_FAILED` (400), `IDEMPOTENCY_KEY_REUSED` (409), `IDEMPOTENCY_RACE` (409) |
| DELETE | `/api/v1/invitations/{id}` | auth | INTERNAL only | `iam.users.invite` | collection, then the invitation row | GLOBAL only | no | general-authenticated | `INVITATION.REVOKED` | yes | — | 200 (returns the revoked invitation) | `INVITATION_NOT_PENDING` (409), `RESOURCE_NOT_FOUND` (404) |

## 7. Roles and permissions (13)

Roles are authorised against `Target::Collection` on purpose: `ResourceType` has
no `ROLE` variant, so a role cannot be named by a `RESOURCE`-scoped grant and has
no department to resolve `DEPARTMENT` against. Only a `GLOBAL` grant reaches them.

| METHOD | PATH | Access | Principals | Permission | Object-level authz | Scope | Step-up | Rate-limit class | Audit | Client-safe | Idem. | Success | Distinctive errors |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| GET | `/api/v1/permissions` | auth | INTERNAL only | `iam.permissions.read` | collection | GLOBAL only | no | general-authenticated | — | yes | — | 200 | — |
| GET | `/api/v1/roles` | auth | INTERNAL only | `iam.roles.read` | collection | GLOBAL only | no | general-authenticated | — | yes | — | 200 | — |
| POST | `/api/v1/roles` | auth | INTERNAL only | `iam.roles.create` | collection + `check_role_authoring` (the actor cannot author a role containing authority it does not itself hold) | GLOBAL only | **yes** — route flag; the service calls `state.require_step_up` explicitly because `iam.roles.create` is *not* flagged dangerous in the catalogue | general-authenticated | `ROLE.CREATED`, `AUTHORIZATION.DENIED` on refusal | yes | **key** | 201 | `STEP_UP_REQUIRED` (403), `DELEGATION_DENIED` (403), `UNKNOWN_PERMISSION` (400), `UNIQUE_VIOLATION` (409), `IDEMPOTENCY_KEY_REUSED` (409), `IDEMPOTENCY_RACE` (409) |
| GET | `/api/v1/roles/{id}` | auth | INTERNAL only | `iam.roles.read` | collection (after loading the row for existence) | GLOBAL only | no | general-authenticated | — | yes | — | 200 | `RESOURCE_NOT_FOUND` (404) |
| PATCH | `/api/v1/roles/{id}` | auth | INTERNAL only | `iam.roles.update` | collection + `check_role_authoring` | GLOBAL only | **yes** — route flag + explicit `state.require_step_up` | general-authenticated | `ROLE.UPDATED`, `AUTHORIZATION.DENIED` | yes | — | 200 | `VERSION_CONFLICT` (409), `STEP_UP_REQUIRED` (403), `DELEGATION_DENIED` (403), `UNKNOWN_PERMISSION` (400) |
| DELETE | `/api/v1/roles/{id}` | auth | INTERNAL only | `iam.roles.delete` | collection | GLOBAL only | **yes** — route flag + explicit `state.require_step_up` | general-authenticated | `ROLE.DELETED`, `AUTHORIZATION.DENIED` | yes | — | 204 | `ROLE_IN_USE` (409), `STEP_UP_REQUIRED` (403), `RESOURCE_NOT_FOUND` (404) |
| GET | `/api/v1/users/{id}/roles` | auth | INTERNAL only | `iam.roles.read` | row (user target) | object (`GLOBAL` / `SELF` / `RESOURCE`) | no | general-authenticated | — | yes | — | 200 | `RESOURCE_NOT_FOUND` (404) |
| POST | `/api/v1/users/{id}/roles` | auth | INTERNAL only | `iam.roles.assign` | row (subject `FOR UPDATE`) + `check_role_assignment` | object | **yes** — route flag; `iam.roles.assign` is dangerous, so `require_step_up_for` fires | general-authenticated | `ROLE.ASSIGNED`, `AUTHORIZATION.DENIED`, `ROOT.PROTECTION_TRIGGERED` | yes | — | 201 | `STEP_UP_REQUIRED` (403), `DELEGATION_DENIED` (403), `ROOT_PROTECTED` (403), `SUBJECT_ARCHIVED` (409), `ROLE_ALREADY_ASSIGNED` (409) |
| DELETE | `/api/v1/users/{id}/roles/{role_id}` | auth | INTERNAL only | `iam.roles.assign` | row (subject `FOR UPDATE`) | object | **yes** — route flag + dangerous permission | general-authenticated | `ROLE.UNASSIGNED`, `AUTHORIZATION.DENIED`, `ROOT.PROTECTION_TRIGGERED` | yes | — | 204 | `STEP_UP_REQUIRED` (403), `DELEGATION_DENIED` (403), `ROOT_PROTECTED` (403), `RESOURCE_NOT_FOUND` (404) |
| GET | `/api/v1/users/{id}/permissions` | auth | INTERNAL only | `iam.permissions.read` | row (user target) | object | no | general-authenticated | — | yes | — | 200 | `RESOURCE_NOT_FOUND` (404) |
| GET | `/api/v1/users/{id}/permission-overrides` | auth | INTERNAL only | `iam.permissions.read` | row (user target) | object | no | general-authenticated | — | yes | — | 200 | `RESOURCE_NOT_FOUND` (404) |
| POST | `/api/v1/users/{id}/permission-overrides` | auth | INTERNAL only | `iam.permissions.delegate` | row (subject `FOR UPDATE`) + `check_permission_grant` | object | **yes** — route flag + dangerous permission | general-authenticated | `PERMISSION.OVERRIDE_CREATED`, `AUTHORIZATION.DENIED`, `ROOT.PROTECTION_TRIGGERED` | yes | — | 201 | `STEP_UP_REQUIRED` (403), `DELEGATION_DENIED` (403), `ROOT_PROTECTED` (403), `UNKNOWN_PERMISSION` (400), `SUBJECT_ARCHIVED` (409) |
| DELETE | `/api/v1/users/{id}/permission-overrides/{override_id}` | auth | INTERNAL only | `iam.permissions.delegate` | row (subject `FOR UPDATE`) | object | **yes** — route flag + dangerous permission | general-authenticated | `PERMISSION.OVERRIDE_REMOVED`, `AUTHORIZATION.DENIED` | yes | — | 204 | `STEP_UP_REQUIRED` (403), `DELEGATION_DENIED` (403), `RESOURCE_NOT_FOUND` (404) |

## 8. Departments (7)

`target_for` sets `department_id = row.id`, so a `DEPARTMENT`-scoped grant reaches
a department the actor is a member of.

| METHOD | PATH | Access | Principals | Permission | Object-level authz | Scope | Step-up | Rate-limit class | Audit | Client-safe | Idem. | Success | Distinctive errors |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| GET | `/api/v1/departments` | auth | INTERNAL only | `departments.read` | filter (a non-GLOBAL actor gets its own departments; no usable scope routes through `require` for the correctly shaped refusal) | scope-filtered | no | general-authenticated | — | yes | — | 200 | — |
| POST | `/api/v1/departments` | auth | INTERNAL only | `departments.create` | collection | GLOBAL only | conditional (not dangerous → none) | general-authenticated | `DEPARTMENT.CREATED` | yes | **key** | 201 | `UNIQUE_VIOLATION` (409), `VALIDATION_FAILED` (400), `UNKNOWN_USER` (409 — unknown lead), `IDEMPOTENCY_KEY_REUSED` (409), `IDEMPOTENCY_RACE` (409) |
| GET | `/api/v1/departments/{id}` | auth | INTERNAL only | `departments.read` | row (membership resolved from the database) | object | no | general-authenticated | — | yes | — | 200 | `RESOURCE_NOT_FOUND` (404) |
| PATCH | `/api/v1/departments/{id}` | auth | INTERNAL only | `departments.update` | row (`FOR UPDATE`) | object | conditional (not dangerous → none) | general-authenticated | `DEPARTMENT.UPDATED` | yes | — | 200 | `VERSION_CONFLICT` (409), `DEPARTMENT_ARCHIVED` (409), `UNKNOWN_USER` (409) |
| POST | `/api/v1/departments/{id}/archive` | auth | INTERNAL only | `departments.archive` | row (`FOR UPDATE`) | object | conditional (not dangerous → none) | general-authenticated | `DEPARTMENT.ARCHIVED` | yes | — | 200 | `VERSION_CONFLICT` (409), `DEPARTMENT_ALREADY_ARCHIVED` (409), `DEPARTMENT_HAS_LIVE_PROJECTS` (409) |
| GET | `/api/v1/departments/{id}/members` | auth | INTERNAL only | `departments.read` | row | object | no | general-authenticated | — | yes | — | 200 | `RESOURCE_NOT_FOUND` (404) |
| POST | `/api/v1/departments/{id}/members` | auth | INTERNAL only | `departments.members.manage` | row (`FOR UPDATE`) | object | conditional (not dangerous → none) | general-authenticated | `DEPARTMENT.MEMBER_ADDED`, `ROOT.PROTECTION_TRIGGERED` | yes | — | 201 | `UNKNOWN_USER` (409), `ALREADY_A_MEMBER` (409), `PRINCIPAL_TYPE_MISMATCH` (409), `USER_ARCHIVED` (409), `DEPARTMENT_ARCHIVED` (409), `ROOT_PROTECTED` (403) |
| DELETE | `/api/v1/departments/{id}/members/{user_id}` | auth | INTERNAL only | `departments.members.manage` | row (`FOR UPDATE`) | object | conditional (not dangerous → none) | general-authenticated | `DEPARTMENT.MEMBER_REMOVED`, `ROOT.PROTECTION_TRIGGERED` | yes | — | 204 | `ROOT_PROTECTED` (403), `RESOURCE_NOT_FOUND` (404) |

## 9. Client accounts (9)

`target_for` sets `department_id = None` deliberately, so a `DEPARTMENT`-scoped
grant can never reach a client account. `actor_is_member` is true only for the
account manager, which is what `ASSIGNED` resolves against.

| METHOD | PATH | Access | Principals | Permission | Object-level authz | Scope | Step-up | Rate-limit class | Audit | Client-safe | Idem. | Success | Distinctive errors |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| GET | `/api/v1/clients` | auth | INTERNAL only | `clients.read` | filter; an external principal is routed through `require` and gets `404` | scope-filtered | no | general-authenticated | — | yes | — | 200 | — |
| POST | `/api/v1/clients` | auth | INTERNAL only | `clients.create` | collection | GLOBAL only | conditional (not dangerous → none) | general-authenticated | `CLIENT.CREATED` | yes | **key** | 201 | `UNIQUE_VIOLATION` (409), `UNKNOWN_USER` (409), `VALIDATION_FAILED` (400), `IDEMPOTENCY_KEY_REUSED` (409), `IDEMPOTENCY_RACE` (409) |
| GET | `/api/v1/clients/{id}` | auth | INTERNAL only | `clients.read` | row | object (`GLOBAL` / `ASSIGNED` / `RESOURCE`) | no | general-authenticated | — | yes | — | 200 | `RESOURCE_NOT_FOUND` (404) |
| PATCH | `/api/v1/clients/{id}` | auth | INTERNAL only | `clients.update` | row (`FOR UPDATE`) | object | conditional (not dangerous → none) | general-authenticated | `CLIENT.UPDATED` | yes | — | 200 | `VERSION_CONFLICT` (409), `CLIENT_ARCHIVED` (409), `UNKNOWN_USER` (409) |
| POST | `/api/v1/clients/{id}/archive` | auth | INTERNAL only | `clients.archive` | row (`FOR UPDATE`) | object | conditional (not dangerous → none) | general-authenticated | `CLIENT.ARCHIVED` | yes | — | 200 | `VERSION_CONFLICT` (409), `CLIENT_ALREADY_ARCHIVED` (409) |
| GET | `/api/v1/clients/{id}/members` | auth | INTERNAL only | `clients.read` | row | object | no | general-authenticated | — | yes | — | 200 | `RESOURCE_NOT_FOUND` (404) |
| POST | `/api/v1/clients/{id}/members` | auth | INTERNAL only | `clients.members.manage` | row (`FOR UPDATE`) | object | conditional (not dangerous → none) | general-authenticated | `CLIENT.MEMBER_ADDED` | yes | — | 201 | `UNKNOWN_USER` (409), `ALREADY_A_MEMBER` (409), `PRINCIPAL_TYPE_MISMATCH` (409), `USER_ARCHIVED` (409), `CLIENT_ARCHIVED` (409) |
| POST | `/api/v1/clients/{id}/members/{user_id}/activate` | auth | INTERNAL only | `clients.members.manage` | row (`FOR UPDATE`) | object | conditional (not dangerous → none) | general-authenticated | `CLIENT.MEMBER_ACTIVATED` | yes | — | 200 | `MEMBERSHIP_ALREADY_ACTIVE` (409), `MEMBERSHIP_REMOVED` (409), `MEMBERSHIP_CHANGED` (409), `CLIENT_ARCHIVED` (409) |
| DELETE | `/api/v1/clients/{id}/members/{user_id}` | auth | INTERNAL only | `clients.members.manage` | row (`FOR UPDATE`) | object | conditional (not dangerous → none) | general-authenticated | `CLIENT.MEMBER_REMOVED` | yes | — | 204 | `MEMBERSHIP_ALREADY_REMOVED` (409), `MEMBERSHIP_CHANGED` (409), `RESOURCE_NOT_FOUND` (404) |

## 10. Projects (11)

| METHOD | PATH | Access | Principals | Permission | Object-level authz | Scope | Step-up | Rate-limit class | Audit | Client-safe | Idem. | Success | Distinctive errors |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| GET | `/api/v1/projects` | auth | INTERNAL only | `projects.read` | filter | scope-filtered | no | general-authenticated | — | yes — an external principal is refused with `404` | — | 200 | — |
| POST | `/api/v1/projects` | auth | INTERNAL only | `projects.create` | row-shaped target built from the **requested** `department_id`, so a department-scoped creator cannot create outside its department | object | no | general-authenticated | `PROJECT.CREATED` | yes | **key** | 201 | `UNIQUE_VIOLATION` (409), `EXTERNAL_PRINCIPAL` (409), `VALIDATION_FAILED` (400), `IDEMPOTENCY_KEY_REUSED` (409), `IDEMPOTENCY_RACE` (409) |
| GET | `/api/v1/projects/{id}` | auth | INTERNAL only | `projects.read` | row (department + membership from the loaded row) | object | no | general-authenticated | — | yes | — | 200 | `RESOURCE_NOT_FOUND` (404) |
| PATCH | `/api/v1/projects/{id}` | auth | INTERNAL only | `projects.update` | row (`FOR UPDATE`); a department move is authorised **twice**, once against the source and once against the destination | object | no | general-authenticated | `PROJECT.UPDATED` | yes | — | 200 | `VERSION_CONFLICT` (409), `INVALID_STATE_TRANSITION` (409), `EXTERNAL_PRINCIPAL` (409) |
| POST | `/api/v1/projects/{id}/archive` | auth | INTERNAL only | `projects.archive` | row (`FOR UPDATE`) | object | no | general-authenticated | `PROJECT.ARCHIVED` | yes | — | 200 | `VERSION_CONFLICT` (409), `ALREADY_ARCHIVED` (409) |
| GET | `/api/v1/projects/{id}/members` | auth | INTERNAL only | `projects.read` | row | object | no | general-authenticated | — | yes | — | 200 | `RESOURCE_NOT_FOUND` (404) |
| POST | `/api/v1/projects/{id}/members` | auth | INTERNAL only | `projects.members.manage` | row (`FOR UPDATE`) | object | no | general-authenticated | `PROJECT.MEMBER_ADDED` | yes | — | 204 | `PROJECT_ARCHIVED` (409), `ALREADY_A_MEMBER` (409), `EXTERNAL_PRINCIPAL` (409) |
| DELETE | `/api/v1/projects/{id}/members/{user_id}` | auth | INTERNAL only | `projects.members.manage` | row (`FOR UPDATE`) | object | no | general-authenticated | `PROJECT.MEMBER_REMOVED` | yes | — | 204 | `RESOURCE_NOT_FOUND` (404) |
| GET | `/api/v1/projects/{id}/clients` | auth | INTERNAL only | `projects.read` | row | object | no | general-authenticated | — | yes | — | 200 | `RESOURCE_NOT_FOUND` (404) |
| POST | `/api/v1/projects/{id}/clients` | auth | INTERNAL only | `projects.clients.share` | row (`FOR UPDATE`) | object | **yes** — route flag; `projects.clients.share` is dangerous | general-authenticated | `PROJECT.SHARED_WITH_CLIENT`, `AUTHORIZATION.DENIED` on refusal | yes | — | 204 | `STEP_UP_REQUIRED` (403), `PROJECT_ARCHIVED` (409), `CLIENT_ACCOUNT_NOT_ACTIVE` (409) |
| DELETE | `/api/v1/projects/{id}/clients/{client_account_id}` | auth | INTERNAL only | `projects.clients.share` | row (`FOR UPDATE`) | object | **yes** — route flag + dangerous permission | general-authenticated | `PROJECT.UNSHARED_FROM_CLIENT`, `AUTHORIZATION.DENIED` | yes | — | 204 | `STEP_UP_REQUIRED` (403), `RESOURCE_NOT_FOUND` (404) |

## 11. Tasks (8, plus the project-nested listing)

`task_target` takes its department from the task's **project**, so a
`DEPARTMENT`-scoped grant follows the project. `ASSIGNED` resolves against an
active assignee row.

| METHOD | PATH | Access | Principals | Permission | Object-level authz | Scope | Step-up | Rate-limit class | Audit | Client-safe | Idem. | Success | Distinctive errors |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| GET | `/api/v1/projects/{project_id}/tasks` | auth | INTERNAL only | `tasks.read` | filter, bounded to the project in the path | scope-filtered | no | general-authenticated | — | yes | — | 200 | — |
| GET | `/api/v1/tasks` | auth | INTERNAL only | `tasks.read` | filter | scope-filtered | no | general-authenticated | — | yes | — | 200 | — |
| POST | `/api/v1/tasks` | auth | INTERNAL only | `tasks.create` | target built from the **loaded project** named in the body (project `404` first) | object | no | general-authenticated | `TASK.CREATED` | yes | **key** | 201 | `PROJECT_ARCHIVED` (409), `EXTERNAL_PRINCIPAL` (409), `RESOURCE_NOT_FOUND` (404), `IDEMPOTENCY_KEY_REUSED` (409), `IDEMPOTENCY_RACE` (409) |
| GET | `/api/v1/tasks/{id}` | auth | INTERNAL only | `tasks.read` | row (project department + assignee) | object | no | general-authenticated | — | yes | — | 200 | `RESOURCE_NOT_FOUND` (404) |
| PATCH | `/api/v1/tasks/{id}` | auth | INTERNAL only | `tasks.update` | row (`FOR UPDATE`) | object | no | general-authenticated | `TASK.UPDATED`, and additionally `TASK.CLIENT_VISIBILITY_CHANGED` when `client_visible` moves | yes | — | 200 | `VERSION_CONFLICT` (409), `INVALID_STATE_TRANSITION` (409) |
| DELETE | `/api/v1/tasks/{id}` | auth | INTERNAL only | `tasks.delete` | row (`FOR UPDATE`) | object | no | general-authenticated | `TASK.CANCELLED` (cancellation is a status change, not a row removal) | yes | — | 204 | `VERSION_CONFLICT` (409 — only when `?version=` is supplied), `ALREADY_CANCELLED` (409), `INVALID_STATE_TRANSITION` (409) |
| GET | `/api/v1/tasks/{id}/assignees` | auth | INTERNAL only | `tasks.read` | row | object | no | general-authenticated | — | yes | — | 200 | `RESOURCE_NOT_FOUND` (404) |
| POST | `/api/v1/tasks/{id}/assignees` | auth | INTERNAL only | `tasks.assign` | row (`FOR UPDATE`) | object | no | general-authenticated | `TASK.ASSIGNED` | yes | — | 204 | `TASK_CANCELLED` (409), `ALREADY_ASSIGNED` (409), `EXTERNAL_PRINCIPAL` (409) |
| DELETE | `/api/v1/tasks/{id}/assignees/{user_id}` | auth | INTERNAL only | `tasks.assign` | row (`FOR UPDATE`) | object | no | general-authenticated | `TASK.UNASSIGNED` | yes | — | 204 | `RESOURCE_NOT_FOUND` (404) |

## 12. Client portal (4)

The only business surface an external principal may reach, and read-only
throughout. Each handler builds a target with `department_id = None` and
`actor_is_member = true`, and every portal permission is `ASSIGNED`-scoped in
practice — visibility resolves through an **ACTIVE** client membership joined to a
live project link. An INTERNAL principal holding the portal permission may also
call these.

| METHOD | PATH | Access | Principals | Permission | Object-level authz | Scope | Step-up | Rate-limit class | Audit | Client-safe | Idem. | Success | Distinctive errors |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| GET | `/api/v1/client-portal/projects` | auth | INTERNAL **and** CLIENT | `client.portal.projects.read` | filter, bounded to the actor's ACTIVE client memberships | `ASSIGNED` in practice | no | general-authenticated | — | **yes** — reduced `ClientProjectResponse` projection chosen by the route, not by a flag | — | 200 | — |
| GET | `/api/v1/client-portal/projects/{id}` | auth | INTERNAL **and** CLIENT | `client.portal.projects.read` | row, loaded through the client-visibility predicate | `ASSIGNED` | no | general-authenticated | — | yes | — | 200 | `RESOURCE_NOT_FOUND` (404) |
| GET | `/api/v1/client-portal/projects/{id}/tasks` | auth | INTERNAL **and** CLIENT | `client.portal.tasks.read` | filter, bounded to the visible project and `client_visible = true` tasks | `ASSIGNED` | no | general-authenticated | — | yes — `ClientTaskResponse` carries no `internal_note`, `created_by`, `version` or `client_visible` | — | 200 | `RESOURCE_NOT_FOUND` (404) |
| GET | `/api/v1/client-portal/tasks/{id}` | auth | INTERNAL **and** CLIENT | `client.portal.tasks.read` | row, loaded through the client-visibility predicate | `ASSIGNED` | no | general-authenticated | — | yes | — | 200 | `RESOURCE_NOT_FOUND` (404) |

## 13. Settings, feature flags, system and audit (8)

| METHOD | PATH | Access | Principals | Permission | Object-level authz | Scope | Step-up | Rate-limit class | Audit | Client-safe | Idem. | Success | Distinctive errors |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| GET | `/api/v1/settings` | auth | INTERNAL only | `settings.read` | collection | GLOBAL only | no | general-authenticated | — | yes | — | 200 | — |
| PUT | `/api/v1/settings/{key}` | auth | INTERNAL only | `settings.features.write` **or** `settings.security.write` — decided **after** the row is loaded, from its `is_security_sensitive` column | row (`FOR UPDATE`) | GLOBAL only (`Target::Collection`) | **conditional** — a security-sensitive key requires `settings.security.write`, which is dangerous, so `require_step_up_for` fires | general-authenticated | `SETTING.CHANGED` (Success and Denied; values are **not** recorded for security-sensitive keys) | yes | — | 200 | `VERSION_CONFLICT` (409), `STEP_UP_REQUIRED` (403), `VALIDATION_FAILED` (400 — bad key grammar or value type), `RESOURCE_NOT_FOUND` (404 — unknown key) |
| GET | `/api/v1/feature-flags` | auth | INTERNAL only | `settings.read` | collection | GLOBAL only | no | general-authenticated | — | yes | — | 200 | — |
| PUT | `/api/v1/feature-flags/{key}` | auth | INTERNAL only | `settings.features.write` **or** `settings.security.write` (same dynamic split) | row (`FOR UPDATE`) | GLOBAL only | conditional, as above | general-authenticated | `FEATURE_FLAG.CHANGED` (Success and Denied) | yes | — | 200 | `VERSION_CONFLICT` (409), `STEP_UP_REQUIRED` (403), `VALIDATION_FAILED` (400), `RESOURCE_NOT_FOUND` (404) |
| GET | `/api/v1/system/info` | auth | INTERNAL **and** CLIENT — the handler takes no permission decision and ignores the principal | **—** | — | n/a | no | general-authenticated | — | **no reduction** — any authenticated principal, including a CLIENT, receives `environment`, `initialized` and the list of enabled feature-flag keys. See §14. | — | 200 | — |
| GET | `/api/v1/audit/events` | auth | INTERNAL only | `audit.read` | collection | GLOBAL only | no | general-authenticated | — | yes | — | 200 | `BAD_REQUEST` (400 — bad filter) |
| GET | `/api/v1/audit/events/{id}` | auth | INTERNAL only | `audit.read` | collection | GLOBAL only | no | general-authenticated | — | yes | — | 200 | `RESOURCE_NOT_FOUND` (404 — a malformed id is also `404`, not a validation error, so it does not reflect the caller's input) |
| GET | `/api/v1/audit/verify` | auth | INTERNAL only | `audit.read` | collection | GLOBAL only | **yes** — route flag + explicit `state.require_step_up` in the service; the permission is not flagged dangerous, so the demand is stated in code | general-authenticated | — | yes | — | 200 | `STEP_UP_REQUIRED` (403), `VALIDATION_FAILED` / `BAD_REQUEST` (400 — window out of range) |

---

## 14. Routes with unclear security posture

Four items. Nothing else in the 95 was ambiguous.

### 14.1 `POST /api/v1/auth/logout` — declared `Authenticated`, implemented `MfaPendingSession`

`ROUTE_TABLE` declares `Access::Authenticated`, but `modules/authentication/routes.rs`
extracts `MfaPendingSession`, with a comment saying a session stuck in
`MFA_ENROLLMENT_REQUIRED` must be able to dispose of its token. The **implementation
is the wider of the two**, and it is the behaviour a frontend must code against: a
pending-MFA session can log out. The declared table is what the OpenAPI drift test
compares, so this deviation is invisible to that test. Reported below as a bug.

### 14.2 `POST /api/v1/auth/mfa/recovery/regenerate` and `POST /api/v1/auth/mfa/disable` — **resolved**

These two previously had the same mismatch as `logout` (declared `Authenticated`,
implemented with `MfaPendingSession`). As of the source read for this
regeneration, both handlers use the `Authenticated` extractor, so the declaration
and the implementation now agree, and both remain behind `state.require_step_up`
in the service. `POST /api/v1/auth/mfa/disable` has also gained the dedicated
`mfa:sess` / `mfa:user` limiter it previously lacked. **No action needed** — the
item is retained here only so a reader comparing against an earlier revision of
this document is not misled.

### 14.3 `GET /api/v1/system/info` — authenticated, but no permission and no principal-type reduction

The handler ignores its `Principal` (`_principal`), and the service returns the
environment name, whether the system is initialised, and the enabled feature-flag
keys. There is no permission check and no client projection, so an external
`CLIENT` principal receives the same document an administrator does.

The source now argues this is deliberate and safe: the environment is visible from
the URL, `initialized` is already observable from the bootstrap endpoint's
behaviour, and `enabled_feature_flag_keys` **excludes `is_security_sensitive` rows
in the query itself** — a filter the comment records as previously missing. The
residual disclosure is therefore the set of enabled *non-sensitive* flag keys.

It is left in this section because the posture is still a judgement rather than an
enforced rule: nothing in the route table, the catalogue or a test prevents a
future non-sensitive flag from being an internal fact, and there is no permission
gate to fall back on. A frontend must not treat this endpoint as internal-only,
and should not surface `enabled_features` in a client-portal experience.

### 14.4 Step-up on `iam.roles.create` / `iam.roles.update` / `iam.roles.delete` and `audit.read`

These four routes declare `step_up = true` in `ROUTE_TABLE`, but their permissions
are **not** flagged `is_dangerous` in the catalogue, so `require_step_up_for` would
not fire. The services therefore call `state.require_step_up` explicitly, and the
source comments say so. The behaviour is correct and verified; the posture is
"unclear" only in the sense that the catalogue and the route table disagree about
why, so a reader consulting only `catalog.rs` would conclude no step-up applies.
