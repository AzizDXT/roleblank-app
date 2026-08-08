# Route security matrix

Formal backend acceptance audit, §24. Every one of the 95 entries in
`backend/src/routes.rs` `ROUTE_TABLE` (lines 62–674) has a row below.

**Method.** Each column was filled by reading the mounted handler and the service
it delegates to, not by copying `ROUTE_TABLE`. Where the declared table and the
code disagree the code is reported and the disagreement is raised as a finding
(see `audit/SECTION_23_26_FINDINGS.md`).

## How to read the columns

| Column | Meaning |
| --- | --- |
| **Auth** | `anon` — no session; `mfa-pending` — `MfaPendingSession` extractor, accepts a password-only session; `auth` — `Authenticated` extractor, refuses a pending-MFA session (`backend/src/platform/http/extract.rs:130-143`). |
| **Permission** | The code passed to `state.require` / `ScopeFilter::build` by the service. `—` when the handler takes no permission decision. |
| **Object-level authz** | `row` — the service loads the row (often `FOR UPDATE`) and builds a `TargetContext` from the *loaded* row's real department / membership before calling `state.require`. `collection` — authorised against `Target::Collection`, which `evaluator::scope_covers` admits only for `GLOBAL` (`backend/src/modules/authorization/evaluator.rs:89`); no per-object decision is taken. `filter` — the actor's scopes are translated into a SQL `WHERE` clause and no row-level `require` runs. `path-param` — authorised on the identifier the caller supplied. `—` — no authorisation decision. |
| **Principals** | Derived from `max_principal_type` in `backend/src/modules/authorization/catalog.rs`. Every code except `client.portal.*` is `Internal`; `client.portal.*` is `Any`. |
| **Step-up** | Whether a recent second factor is enforced *in code*, and where. |
| **Rate limited** | The limiter key from `backend/src/platform/http/rate_limit.rs:226-280`, or `—`. |
| **Audit event** | The `action::*` constant the handler's service writes. `—` for reads that write nothing. |
| **Client-safe** | Whether a CLIENT principal receives `404` rather than `403`, and whether the response body is a reduced client DTO. |

Verification status is stated per row group. Anything I could not settle from the
source is listed at the end under **Endpoints with no clear security decision**.

---

## 1. Health and platform (3)

| # | METHOD | PATH | Auth | Permission | Object-level authz | Principals | Step-up | Rate limited | Audit event | Client-safe |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | GET | `/health/live` | anon | — | — | anyone | no | — | — | n/a — fixed body `{"status":"ok"}`, no DB call (`system/routes.rs:60`) |
| 2 | GET | `/health/ready` | anon | — | — | anyone | no | — | — | n/a — closed two-value document; service returns bare `bool` so no driver text can reach the body (`system/service.rs:34`) |
| 3 | GET | `/metrics` | anon | — | — | anyone | no | — | — | n/a — `404` (not `403`) when `metrics_enabled=false` (`system/routes.rs:100`). Restriction is the operator's network policy. |

## 2. Bootstrap (2)

| # | METHOD | PATH | Auth | Permission | Object-level authz | Principals | Step-up | Rate limited | Audit event | Client-safe |
|---|---|---|---|---|---|---|---|---|---|---|
| 4 | GET | `/api/v1/bootstrap/status` | anon | — | — | anyone | no | **—** (no limiter; see F-11) | — | n/a — single boolean |
| 5 | POST | `/api/v1/bootstrap/root` | anon | — | — (advisory lock + `system_state FOR UPDATE`) | anyone | no | `bootstrap:ip:{ip}` | `SYSTEM.BOOTSTRAPPED`, `SYSTEM.BOOTSTRAP_REJECTED` | n/a — `404` when no operator secret configured; wrong-secret and already-initialised are the same `401` (`bootstrap/service.rs:86-91`) |

## 3. Authentication (16)

Object-level authorisation is not applicable to any of these: the subject is
always the calling session, resolved from the bearer token, never from a path
parameter. `DELETE /auth/sessions/{id}` is the only one taking an id, and
ownership is a predicate inside the `UPDATE` (`authentication/service.rs:663-680`).

| # | METHOD | PATH | Auth | Permission | Object-level authz | Principals | Step-up | Rate limited | Audit event | Client-safe |
|---|---|---|---|---|---|---|---|---|---|---|
| 6 | POST | `/api/v1/auth/login` | anon | — | — | anyone | no | `login:ip:{ip}` **and** `login:acct:{email_normalized}` | `AUTH.LOGIN_SUCCEEDED` / `AUTH.LOGIN_FAILED` / `SESSION.REVOKED` (cap eviction) | n/a — one undifferentiated `401` for every failure mode; dummy Argon2 on the unknown-account and inactive-account paths |
| 7 | POST | `/api/v1/auth/refresh` | anon | — | — (token row `FOR UPDATE`) | anyone | no | `refresh:ip:{ip}` | `AUTH.REFRESHED` / `AUTH.REFRESH_REUSE_DETECTED` | n/a — reuse detection kills the family and still returns the generic `401` |
| 8 | POST | `/api/v1/auth/logout` | **mfa-pending** (table declares `Authenticated` — see F-04) | — | — | anyone | no | — | `AUTH.LOGOUT` | n/a |
| 9 | POST | `/api/v1/auth/logout-all` | auth | — | — | anyone | no | — | `SESSION.REVOKED_ALL` | n/a |
| 10 | GET | `/api/v1/auth/me` | mfa-pending | — | — | anyone | no | — | — | n/a — a pending session gets the structurally smaller `PendingMfaMeResponse` with no capability list, no `is_root`, no `auth_level` (`authentication/service.rs:576-594`) |
| 11 | GET | `/api/v1/auth/sessions` | auth | — | self-only, in SQL | anyone | no | — | — | n/a — scoped to `principal.user_id()` in the query; no path parameter exists |
| 12 | DELETE | `/api/v1/auth/sessions/{id}` | auth | — | **SQL predicate** (`WHERE id=$1 AND user_id=$2`) | anyone | no | — | `SESSION.REVOKED` | n/a — zero rows affected renders as `404`, identical to "someone else's session" |
| 13 | POST | `/api/v1/auth/password/change` | auth | — | self | anyone | no | `login:acct:{principal email}` | `PASSWORD.CHANGED` | n/a — requires the current password even with a valid session |
| 14 | POST | `/api/v1/auth/password-reset/request` | anon | — | — | anyone | no | `pwreset:ip:{ip}` **and** `pwreset:acct:{email}` | `PASSWORD.RESET_REQUESTED` | n/a — always `202` with a body type that has no variable field |
| 15 | POST | `/api/v1/auth/password-reset/confirm` | anon | — | — (token row `FOR UPDATE`) | anyone | no | `pwreset:ip:{ip}` | `PASSWORD.RESET_COMPLETED` | n/a |
| 16 | POST | `/api/v1/auth/mfa/totp/setup` | mfa-pending | — | self | anyone | no | `mfa:sess:{sid}` **and** `mfa:user:{uid}` | `MFA.ENROLMENT_STARTED` | n/a — refuses when an ACTIVE factor already exists |
| 17 | POST | `/api/v1/auth/mfa/totp/activate` | mfa-pending | — | self (factor `FOR UPDATE`) | anyone | no | `mfa:sess` + `mfa:user` | `MFA.ACTIVATED`, `MFA.RECOVERY_CODES_GENERATED`, `MFA.REPLAY_DETECTED`, `MFA.VERIFICATION_FAILED` | n/a |
| 18 | POST | `/api/v1/auth/mfa/verify` | mfa-pending | — | self (factor `FOR UPDATE`) | anyone | no | `mfa:sess` + `mfa:user` | `AUTH.STEP_UP_COMPLETED`, `MFA.REPLAY_DETECTED`, `MFA.VERIFICATION_FAILED` | n/a |
| 19 | POST | `/api/v1/auth/mfa/recovery/verify` | mfa-pending | — | self | anyone | no | `mfa:sess` + `mfa:user` | `MFA.RECOVERY_CODE_CONSUMED`, `MFA.VERIFICATION_FAILED` | n/a |
| 20 | POST | `/api/v1/auth/mfa/recovery/regenerate` | mfa-pending extractor; `require_step_up` makes it unreachable for a pending session (`mfa.rs:535`) | — | self | anyone | **yes** — `state.require_step_up` | `mfa:sess` + `mfa:user` | `MFA.RECOVERY_CODES_GENERATED` | n/a |
| 21 | POST | `/api/v1/auth/mfa/disable` | mfa-pending extractor; `require_step_up` (`mfa.rs:586`) | — | self | anyone | **yes** | **—** (no limiter — see F-11) | `MFA.DISABLED` | n/a — additionally refused outright when `mfa_required` |

## 4. Registration and invitation acceptance (3)

| # | METHOD | PATH | Auth | Permission | Object-level authz | Principals | Step-up | Rate limited | Audit event | Client-safe |
|---|---|---|---|---|---|---|---|---|---|---|
| 22 | GET | `/api/v1/registration/config` | anon | — | — | anyone | no | — | — | n/a — two fields; unreadable setting fails closed to "disabled" (`identity/registration.rs:87-95`) |
| 23 | POST | `/api/v1/registration` | anon | — | — | anyone | no | `register:ip:{ip}` | `USER.REGISTERED` (Success and Denied) | n/a — always `202`, identical body; `principal_type=CLIENT`, `status=PENDING` are literals in code, absent from the DTO |
| 24 | POST | `/api/v1/invitations/accept` | anon | — | invitation row `FOR UPDATE`; inviter authority re-derived at acceptance | anyone | inviter's step-up is *asserted* `true` (`identity/invitations.rs:485`), deliberately | `invite-accept:ip:{ip}` | `USER.CREATED`, `INVITATION.ACCEPTED` | n/a — every rejection reason is the same `401` |

## 5. Users (6)

`iam.users.*` is `Internal` in the catalogue, so a CLIENT is refused at
`evaluator` step 3 and `state.require` renders that as `404`
(`app.rs:86`). `TargetContext::other_user` carries no department and no
membership, so only `GLOBAL` and `SELF` scopes can ever reach a user record.

| # | METHOD | PATH | Auth | Permission | Object-level authz | Principals | Step-up | Rate limited | Audit event | Client-safe |
|---|---|---|---|---|---|---|---|---|---|---|
| 25 | GET | `/api/v1/users` | auth | `iam.users.read` | **filter** — `Target::Collection` first, then a scope-derived `WHERE` (`identity/service.rs:170-211`). Narrow DENY overrides are **not** applied — see F-02 | INTERNAL | no | — | — | yes — `404` via `require` in the no-scope branch; DTO is the internal `UserResponse`, unreachable by a CLIENT |
| 26 | GET | `/api/v1/users/{id}` | auth | `iam.users.read` | **row** — `find_user` then `other_user(...)` (`identity/service.rs:233-240`) | INTERNAL | no | — | — | yes — `404` |
| 27 | PATCH | `/api/v1/users/{id}` | auth | `iam.users.update` | **row** — `find_user_for_update` → `is_root` → `require` | INTERNAL | `require_step_up_for` (no-op: not dangerous) | — | `USER.UPDATED` | yes — `deny_root` masks `ROOT_PROTECTED` to `404` for external principals (`identity/service.rs:601`) |
| 28 | POST | `/api/v1/users/{id}/suspend` | auth | `iam.users.suspend` | **row**, `FOR UPDATE` | INTERNAL | `require_step_up_for` (no-op) | — | `USER.SUSPENDED` + `SESSION.REVOKED_ALL` | yes |
| 29 | POST | `/api/v1/users/{id}/reactivate` | auth | `iam.users.suspend` | **row**, `FOR UPDATE` | INTERNAL | no-op | — | `USER.REACTIVATED` | yes |
| 30 | POST | `/api/v1/users/{id}/archive` | auth | `iam.users.archive` | **row**, `FOR UPDATE` | INTERNAL | no-op | — | `USER.ARCHIVED` + `SESSION.REVOKED_ALL` | yes |

## 6. Invitations (3)

| # | METHOD | PATH | Auth | Permission | Object-level authz | Principals | Step-up | Rate limited | Audit event | Client-safe |
|---|---|---|---|---|---|---|---|---|---|---|
| 31 | GET | `/api/v1/invitations` | auth | `iam.users.invite` | **collection** — GLOBAL only | INTERNAL | no | — | — | yes — `404` |
| 32 | POST | `/api/v1/invitations` | auth | `iam.users.invite` | **collection**. `department_id` and `client_account_id` in the body are **not authorised at all** — see **F-01** | INTERNAL | conditional: `require_step_up` when any named role carries a dangerous permission (`invitations.rs:134-136`) | — | `INVITATION.CREATED` | yes — `require` runs before any lookup. Idempotency operation `invitations.create` |
| 33 | DELETE | `/api/v1/invitations/{id}` | auth | `iam.users.invite` | **collection** — row is loaded *before* `require` but the decision does not use it (`invitations.rs:308-312`) | INTERNAL | no | — | `INVITATION.REVOKED` | yes — `404` either way for a CLIENT; internally a missing id is `404` and an existing one `403` (minor, see F-10) |

## 7. Roles and permissions (13)

`ResourceType` has no `ROLE` variant, so every role-level decision is
`Target::Collection` — GLOBAL only. That is fail-closed and documented at
`authorization/service.rs:25-33`. Verified.

| # | METHOD | PATH | Auth | Permission | Object-level authz | Principals | Step-up | Rate limited | Audit event | Client-safe |
|---|---|---|---|---|---|---|---|---|---|---|
| 34 | GET | `/api/v1/permissions` | auth | `iam.permissions.read` | **collection** | INTERNAL | no | — | — | yes |
| 35 | GET | `/api/v1/roles` | auth | `iam.roles.read` | **collection** | INTERNAL | no | — | — | yes |
| 36 | POST | `/api/v1/roles` | auth | `iam.roles.create` | **collection** + `check_role_authoring` per contained permission | INTERNAL | **yes** — explicit `state.require_step_up` (`service.rs:612`), because `iam.roles.create` is *not* dangerous and `require_step_up_for` would be a no-op | — | `ROLE.CREATED` | yes. Idempotency operation `roles.create` |
| 37 | GET | `/api/v1/roles/{id}` | auth | `iam.roles.read` | **collection** — row loaded first, decision does not use it | INTERNAL | no | — | — | yes |
| 38 | PATCH | `/api/v1/roles/{id}` | auth | `iam.roles.update` | **collection** + `check_role_authoring` against the *effective* permission set (existing set when `permissions` is absent) | INTERNAL | **yes** — explicit | — | `ROLE.UPDATED` (+ `bump_security_version` for every holder) | yes |
| 39 | DELETE | `/api/v1/roles/{id}` | auth | `iam.roles.delete` | **collection** + `check_role_authoring`; assignment count read under the row lock | INTERNAL | **yes** — explicit | — | `ROLE.DELETED` | yes |
| 40 | GET | `/api/v1/users/{id}/roles` | auth | `iam.roles.read` | **row** — subject loaded, then `other_user` target | INTERNAL | no | — | — | yes |
| 41 | POST | `/api/v1/users/{id}/roles` | auth | `iam.roles.assign` | **row** — subject `FOR UPDATE`, then `check_role_assignment` permission-by-permission | INTERNAL | **yes** — `require_step_up_for` (`iam.roles.assign` is dangerous) | — | `ROLE.ASSIGNED`; `AUTHORIZATION.DENIED` / `ROOT.PROTECTION_TRIGGERED` on refusal | yes |
| 42 | DELETE | `/api/v1/users/{id}/roles/{role_id}` | auth | `iam.roles.assign` | **row** — same guard runs on removal | INTERNAL | **yes** | — | `ROLE.UNASSIGNED` | yes |
| 43 | GET | `/api/v1/users/{id}/permissions` | auth | `iam.permissions.read` | **row** | INTERNAL | no | — | — | yes |
| 44 | GET | `/api/v1/users/{id}/permission-overrides` | auth | `iam.permissions.read` | **row** | INTERNAL | no | — | — | yes |
| 45 | POST | `/api/v1/users/{id}/permission-overrides` | auth | `iam.permissions.delegate` | **row** — subject `FOR UPDATE` + `authorise_grant` (derivability lattice) | INTERNAL | **yes** — dangerous | — | `PERMISSION.OVERRIDE_CREATED` | yes |
| 46 | DELETE | `/api/v1/users/{id}/permission-overrides/{override_id}` | auth | `iam.permissions.delegate` | **row** — override loaded scoped to the subject, then `authorise_grant` on its stored scope | INTERNAL | **yes** | — | `PERMISSION.OVERRIDE_REMOVED` | yes |

## 8. Departments (8)

`target_for` sets `department_id = Some(row.id)` — a department's own id is its
department for scope purposes (`departments/service.rs:40-46`). Verified.

| # | METHOD | PATH | Auth | Permission | Object-level authz | Principals | Step-up | Rate limited | Audit event | Client-safe |
|---|---|---|---|---|---|---|---|---|---|---|
| 47 | GET | `/api/v1/departments` | auth | `departments.read` | **filter** — `Target::Collection`, else `repo::visibility_for`. Narrow DENY overrides are **not** applied — F-02 | INTERNAL | no | — | — | yes — the `Nothing` branch routes through `state.require` so the 404 shaping and the denial metric happen in one place |
| 48 | POST | `/api/v1/departments` | auth | `departments.create` | **collection** | INTERNAL | `require_step_up_for` (no-op) | — | `DEPARTMENT.CREATED` | yes. Idempotency operation `departments.create` |
| 49 | GET | `/api/v1/departments/{id}` | auth | `departments.read` | **row** + real membership lookup | INTERNAL | no | — | — | yes |
| 50 | PATCH | `/api/v1/departments/{id}` | auth | `departments.update` | **row**, `FOR UPDATE` | INTERNAL | no-op | — | `DEPARTMENT.UPDATED` | yes |
| 51 | POST | `/api/v1/departments/{id}/archive` | auth | `departments.archive` | **row**, `FOR UPDATE` | INTERNAL | no-op | — | `DEPARTMENT.ARCHIVED` | yes |
| 52 | GET | `/api/v1/departments/{id}/members` | auth | `departments.read` | **row** | INTERNAL | no | — | — | yes |
| 53 | POST | `/api/v1/departments/{id}/members` | auth | `departments.members.manage` | **row**, `FOR UPDATE`. **But `guard_root(is_root_user(body.user_id))` runs before the row load and before `require`** — see **F-03** | INTERNAL | no-op | — | `DEPARTMENT.MEMBER_ADDED` (+ `bump_security_version`) | **no** — a CLIENT supplying the owner's id gets `403 ROOT_PROTECTED` instead of `404` |
| 54 | DELETE | `/api/v1/departments/{id}/members/{user_id}` | auth | `departments.members.manage` | **row**, `FOR UPDATE`; same pre-`require` root guard | INTERNAL | no-op | — | `DEPARTMENT.MEMBER_REMOVED` | **no** — same as row 53 |

## 9. Client accounts (9)

`target_for` sets `department_id = None` explicitly so a DEPARTMENT-scoped grant
cannot reach a client account, and `actor_is_member` means "the actor is the
account manager" (`clients/service.rs:56-64`). Verified.

| # | METHOD | PATH | Auth | Permission | Object-level authz | Principals | Step-up | Rate limited | Audit event | Client-safe |
|---|---|---|---|---|---|---|---|---|---|---|
| 55 | GET | `/api/v1/clients` | auth | `clients.read` | **filter** — `visibility_for`; narrow DENY not applied (F-02) | INTERNAL | no | — | — | yes |
| 56 | POST | `/api/v1/clients` | auth | `clients.create` | **collection** | INTERNAL | no-op | — | `CLIENT.CREATED` | yes. Idempotency operation `clients.create` |
| 57 | GET | `/api/v1/clients/{id}` | auth | `clients.read` | **row** | INTERNAL | no | — | — | yes |
| 58 | PATCH | `/api/v1/clients/{id}` | auth | `clients.update` | **row**, `FOR UPDATE` | INTERNAL | no-op | — | `CLIENT.UPDATED` | yes |
| 59 | POST | `/api/v1/clients/{id}/archive` | auth | `clients.archive` | **row**, `FOR UPDATE` | INTERNAL | no-op | — | `CLIENT.ARCHIVED` | yes |
| 60 | GET | `/api/v1/clients/{id}/members` | auth | `clients.read` | **row** | INTERNAL | no | — | — | yes |
| 61 | POST | `/api/v1/clients/{id}/members` | auth | `clients.members.manage` | **row**, `FOR UPDATE`; membership always created `PENDING` | INTERNAL | no-op | — | `CLIENT.MEMBER_ADDED` | yes |
| 62 | POST | `/api/v1/clients/{id}/members/{user_id}/activate` | auth | `clients.members.manage` | **row** + membership row, both `FOR UPDATE` | INTERNAL | no-op | — | `CLIENT.MEMBER_ACTIVATED` (+ `bump_security_version`) | yes |
| 63 | DELETE | `/api/v1/clients/{id}/members/{user_id}` | auth | `clients.members.manage` | **row** + membership row `FOR UPDATE` | INTERNAL | no-op | — | `CLIENT.MEMBER_REMOVED` | yes |

## 10. Projects (12)

| # | METHOD | PATH | Auth | Permission | Object-level authz | Principals | Step-up | Rate limited | Audit event | Client-safe |
|---|---|---|---|---|---|---|---|---|---|---|
| 64 | GET | `/api/v1/projects` | auth | `projects.read` | **filter** — `ScopeFilter::build` → `PROJECT_SCOPE_PREDICATE`, which *does* carry narrow DENYs. Does not route the denial through `state.require` (F-08) | INTERNAL | no | — | — | yes — `hide_from_external` applied explicitly at `projects/service.rs:252` |
| 65 | POST | `/api/v1/projects` | auth | `projects.create` | **request-derived target** — authorised against the *requested* `department_id`, which is also the department the row is created with. Correct: it narrows, never widens | INTERNAL | no | — | `PROJECT.CREATED` | yes. Idempotency operation `projects.create` |
| 66 | GET | `/api/v1/projects/{id}` | auth | `projects.read` | **row** + real membership lookup | INTERNAL | no | — | — | yes |
| 67 | PATCH | `/api/v1/projects/{id}` | auth | `projects.update` | **row**, `FOR UPDATE`; a department move takes a **second** `require` against the destination (`service.rs:471-477`) | INTERNAL | no | — | `PROJECT.UPDATED` | yes |
| 68 | POST | `/api/v1/projects/{id}/archive` | auth | `projects.archive` | **row**, `FOR UPDATE` | INTERNAL | no | — | `PROJECT.ARCHIVED` | yes |
| 69 | GET | `/api/v1/projects/{id}/members` | auth | `projects.read` | **row** | INTERNAL | no | — | — | yes |
| 70 | POST | `/api/v1/projects/{id}/members` | auth | `projects.members.manage` | **row**, `FOR UPDATE` | INTERNAL | no | — | `PROJECT.MEMBER_ADDED` (+ `bump_security_version`) | yes |
| 71 | DELETE | `/api/v1/projects/{id}/members/{user_id}` | auth | `projects.members.manage` | **row**, `FOR UPDATE` | INTERNAL | no | — | `PROJECT.MEMBER_REMOVED` | yes |
| 72 | GET | `/api/v1/projects/{id}/clients` | auth | `projects.read` | **row** | INTERNAL | no | — | — | yes |
| 73 | POST | `/api/v1/projects/{id}/clients` | auth | `projects.clients.share` | **row**, `FOR UPDATE` | INTERNAL | **yes** — `require_step_up_for`, deliberately *after* `require` so a CLIENT gets `404` rather than `STEP_UP_REQUIRED` (`service.rs:834-842`) | — | `PROJECT.SHARED_WITH_CLIENT`; `AUTHORIZATION.DENIED` **committed** on refusal | yes — the ordering is exactly what makes it safe |
| 74 | DELETE | `/api/v1/projects/{id}/clients/{client_account_id}` | auth | `projects.clients.share` | **row**, `FOR UPDATE` | INTERNAL | **yes** — same ordering | — | `PROJECT.UNSHARED_FROM_CLIENT`; `AUTHORIZATION.DENIED` on refusal | yes |
| 75 | GET | `/api/v1/projects/{project_id}/tasks` | auth | `tasks.read` | **filter** — the path `project_id` is a *filter only*; the task scope predicate is applied regardless (`tasks/service.rs:165-198`) | INTERNAL | no | — | — | yes |

## 11. Tasks (8)

`task_target` takes the department from the task's **project** and membership
from a real `task_assignees` lookup (`tasks/service.rs:126-136`). Verified.

| # | METHOD | PATH | Auth | Permission | Object-level authz | Principals | Step-up | Rate limited | Audit event | Client-safe |
|---|---|---|---|---|---|---|---|---|---|---|
| 76 | GET | `/api/v1/tasks` | auth | `tasks.read` | **filter** — `TASK_SCOPE_PREDICATE` | INTERNAL | no | — | — | yes |
| 77 | POST | `/api/v1/tasks` | auth | `tasks.create` | **row of the parent project**, `FOR UPDATE`, loaded before `require`; missing project is `404` in both branches so the ordering is not an oracle | INTERNAL | no | — | `TASK.CREATED` | yes. Idempotency operation `tasks.create` |
| 78 | GET | `/api/v1/tasks/{id}` | auth | `tasks.read` | **row** + project context + assignee lookup | INTERNAL | no | — | — | yes |
| 79 | PATCH | `/api/v1/tasks/{id}` | auth | `tasks.update` | **row**, `FOR UPDATE` | INTERNAL | no | — | `TASK.UPDATED`, and `TASK.CLIENT_VISIBILITY_CHANGED` as a separate record when `client_visible` moves | yes |
| 80 | DELETE | `/api/v1/tasks/{id}` | auth | `tasks.delete` | **row**, `FOR UPDATE`; cancels, never deletes | INTERNAL | no | — | `TASK.UPDATED` (**no `TASK.CANCELLED` code exists** — F-12) | yes |
| 81 | GET | `/api/v1/tasks/{id}/assignees` | auth | `tasks.read` | **row** | INTERNAL | no | — | — | yes |
| 82 | POST | `/api/v1/tasks/{id}/assignees` | auth | `tasks.assign` | **row**, `FOR UPDATE` | INTERNAL | no | — | `TASK.ASSIGNED` (+ `bump_security_version`) | yes |
| 83 | DELETE | `/api/v1/tasks/{id}/assignees/{user_id}` | auth | `tasks.assign` | **row**, `FOR UPDATE` | INTERNAL | no | — | `TASK.UNASSIGNED` (+ `bump_security_version`) | yes |

## 12. Client portal (4)

The only surface an external principal may reach. Layer 4 (the SQL visibility
predicate in `projects/visibility.rs`) is applied *before* and *independently of*
the `state.require` call, so a bug in the evaluator returns fewer rows rather
than another company's. Verified by reading both the predicate and every call
site's bind order (`projects/repo.rs:37` static-asserts `CLIENT_UID_BIND == 1`).

| # | METHOD | PATH | Auth | Permission | Object-level authz | Principals | Step-up | Rate limited | Audit event | Client-safe |
|---|---|---|---|---|---|---|---|---|---|---|
| 84 | GET | `/api/v1/client-portal/projects` | auth | `client.portal.projects.read` | **filter** — `ScopeFilter::build` presence check + `PROJECT_VISIBLE_TO_CLIENT` in the query | INTERNAL **and** CLIENT (`Any`) | no | — | — | yes — reduced `ClientProjectResponse`: no `internal_note`, no `manager_user_id`, no `department_id`, no `version`, no `created_by` |
| 85 | GET | `/api/v1/client-portal/projects/{id}` | auth | `client.portal.projects.read` | **row fetched *with* the visibility predicate** → a project that exists but is not shared produces no row and therefore `404` | INTERNAL + CLIENT | no | — | — | yes — reduced DTO |
| 86 | GET | `/api/v1/client-portal/projects/{id}/tasks` | auth | `client.portal.tasks.read` | **filter** + the parent project is re-checked through `projects::client_get` first, so an unshared project id is `404` rather than an empty page | INTERNAL + CLIENT | no | — | — | yes — reduced `ClientTaskResponse`: no `client_visible`, no `internal_note`, no `version`, no `created_by` |
| 87 | GET | `/api/v1/client-portal/tasks/{id}` | auth | `client.portal.tasks.read` | **row fetched with the predicate** (`t.client_visible` AND a live project link) → `404` | INTERNAL + CLIENT | no | — | — | yes — reduced DTO |

## 13. Settings, flags and system info (5)

| # | METHOD | PATH | Auth | Permission | Object-level authz | Principals | Step-up | Rate limited | Audit event | Client-safe |
|---|---|---|---|---|---|---|---|---|---|---|
| 88 | GET | `/api/v1/settings` | auth | `settings.read` | **collection**; `is_security_sensitive` rows are excluded **by the query**, gated on `settings.security.write` (`settings/service.rs:235-256`) | INTERNAL | no | — | — | yes |
| 89 | PUT | `/api/v1/settings/{key}` | auth | `settings.features.write` **or** `settings.security.write`, selected by the loaded row's `is_security_sensitive` | **row**, `FOR UPDATE` — this is the `ENFORCED_DYNAMICALLY` case named in `routes.rs:749` | INTERNAL | **conditional** — `require_step_up_for(settings.security.write)` when the row is sensitive | — | `SETTING.CHANGED` (Success and Denied) | yes — a coarse pre-check stops a principal with no write authority telling an existing key from a missing one |
| 90 | GET | `/api/v1/feature-flags` | auth | `settings.read` | **collection**; same sensitivity split | INTERNAL | no | — | — | yes |
| 91 | PUT | `/api/v1/feature-flags/{key}` | auth | `settings.features.write` / `settings.security.write` | **row**, `FOR UPDATE` | INTERNAL | conditional | — | `FEATURE_FLAG.CHANGED` (Success and Denied) | yes |
| 92 | GET | `/api/v1/system/info` | auth | **—** (`system/service.rs:69` takes `_principal` and calls no `require`) | — | INTERNAL **and** CLIENT | no | — | — | partially — same body for every principal by design; leaks the **key list of enabled feature flags** to a CLIENT (see F-09) |

## 14. Audit (3)

| # | METHOD | PATH | Auth | Permission | Object-level authz | Principals | Step-up | Rate limited | Audit event | Client-safe |
|---|---|---|---|---|---|---|---|---|---|---|
| 93 | GET | `/api/v1/audit/events` | auth | `audit.read` | **collection** — GLOBAL only; audit history has no department or owner | INTERNAL | no | — | — | yes |
| 94 | GET | `/api/v1/audit/events/{id}` | auth | `audit.read` | **collection** — `require` runs *before* the lookup; there is deliberately no per-event filter, so any `audit.read` holder can read any event | INTERNAL | no | — | — | yes — a malformed id is `404`, not a validation error that echoes it |
| 95 | GET | `/api/v1/audit/verify` | auth | `audit.read` | **collection** | INTERNAL | **yes** — unconditional `state.require_step_up` (`audit/service.rs:407`), because `audit.read` is not dangerous but this operation is a bulk cryptographic scan | — | — (deliberately not audited) | yes — window bounded at 100 000 entries so it cannot be its own DoS |

---

# Endpoints with no clear security decision

Nine entries. Each names what is unclear and what would settle it.

### U-1 — `POST /api/v1/invitations` (row 32): the destination department and client account are never authorised

`identity/invitations.rs:66-108` authorises only `iam.users.invite` at
`Target::Collection`. `request.department_id` and `request.client_account_id` are
validated for *mutual exclusion with the principal type* and for nothing else. On
acceptance (`invitations.rs:531-551`) they become a department membership and an
**ACTIVE** client membership. Whether that was intended cannot be determined from
the code: the module header discusses roles at length and is silent on
memberships. **Settles it:** a decision on whether `iam.users.invite` is meant to
subsume `departments.members.manage` and `clients.members.manage`. Raised as
finding **F-01 (HIGH)** because the code as written grants both.

### U-2 — `GET /api/v1/users` (row 25): which DENY overrides apply to the listing

`identity/service.rs:170-211` builds the filter from `effective_scopes`, which
removes only *GLOBAL* denies. A `DEPARTMENT`- or `RESOURCE`-scoped DENY on
`iam.users.read` is silently absent from the listing while `GET /users/{id}`
honours it. `projects` and `tasks` carry narrow denies into SQL
(`ScopeFilter::deny_department`, `deny_assigned`, `denied_resource_ids`);
`users`, `departments` and `clients` do not. It is not stated anywhere which is
the intended semantic. **Settles it:** a statement in
`docs/backend/04-authorization.md` §5 on whether a narrow DENY restricts
collections, plus a parity test. Raised as **F-02 (MEDIUM)**.

### U-3 — `POST` / `DELETE /api/v1/departments/{id}/members` (rows 53–54): the root guard runs before authorisation

`departments/service.rs:464` and `:548` call
`state.guard_root(state.is_root_user(user_id).await?)` before the department row
is read and before `state.require`. The equivalent path in `identity` explicitly
masks this for external principals and documents why at length
(`identity/service.rs:588-605`). Whether departments is a deliberate exception or
an oversight is not stated. **Settles it:** apply the same masking, or document
why the departments surface is exempt. Raised as **F-03 (MEDIUM)**.

### U-4 — `POST /api/v1/auth/logout` (row 8): declared `Authenticated`, implemented `MfaPendingSession`

`routes.rs:75` declares `Authenticated`; `authentication/routes.rs:115-117` uses
`MfaPendingSession`, and the module header at `authentication/routes.rs:13-16`
says `/logout` *must* be reachable from a pending session. Both cannot be true.
The behaviour is defensible; the declaration is wrong, and because it is wrong
the `the_mfa_pending_surface_is_minimal` test (`routes.rs:861`) never sees this
route. **Settles it:** decide which is authoritative and change the other. Raised
as **F-04 (MEDIUM)**.

### U-5 — `POST /api/v1/auth/mfa/recovery/regenerate` and `/mfa/disable` (rows 20–21)

Both are declared `Authenticated, step_up = true` but mounted with
`MfaPendingSession`. In practice `state.require_step_up` refuses any pending
session, so the effective access is `Authenticated`-equivalent — but that is a
property of the service, not of the extractor, and a future edit that removed the
step-up check would silently open both to a password-only session. **Settles it:**
either use `Authenticated` or add a test asserting a pending session is refused.
Raised as **F-05 (LOW)**.

### U-6 — `GET /api/v1/system/info` (row 92): who may see the enabled feature-flag list

The handler takes `_principal` and calls no `require`. `system/repo.rs`
`enabled_feature_flag_keys` selects **every** enabled flag key with no
`is_security_sensitive` filter, while `GET /api/v1/feature-flags` excludes
sensitive rows from readers without `settings.security.write`. The doc comment
argues "a feature flag key is not a capability", which is a reasonable position,
but the two endpoints disagree about it. **Settles it:** decide whether the
sensitivity marker governs the key as well as the value. Raised as **F-09 (LOW)**.

### U-7 — `GET /api/v1/audit/events/{id}` (row 94): no object-level filter

Every holder of `audit.read` can read every audit event, including events whose
metadata names projects, users and client accounts they cannot otherwise see. The
service comments justify collection-level authorisation for the *listing*
("audit history has no department and no owner") but say nothing about a
single-event read of an event whose target the reader has no visibility of.
Whether that is intended is not determinable from the code. **Settles it:** an
explicit statement in ADR-006 or §5 of the authorization document.

### U-8 — `POST` / `DELETE /api/v1/projects/{id}/clients` (rows 73–74): audit-on-denial is committed with no rate limit

`projects/service.rs:817-833` writes an `AUTHORIZATION.DENIED` row and **commits**
it on every refused attempt. The same pattern is in `authorization::refuse`
(`service.rs:414-442`). `audit_events` is append-only with no delete path
anywhere in the system. None of these routes is rate limited. Whether an
attacker-driven growth bound was considered is not stated. **Settles it:** a
decision on whether denial recording needs its own budget. Raised as **F-06
(MEDIUM)**.

### U-9 — every route except the eight named in §3/§4: no rate limiter at all

`RateLimitConfig::general_per_principal_per_minute` exists
(`platform/config/mod.rs:109`, default 600) and `keys::general_principal` /
`keys::general_ip` exist (`rate_limit.rs:274-279`), but nothing calls them and no
middleware installs a general limiter. Every authenticated route — including the
expensive `GET /audit/verify` and every listing — is unlimited. Whether that is a
deliberate deferral or an incomplete wiring is not stated anywhere I could find.
**Settles it:** either wire the general limiter or delete the config field and the
key builders so the gap is not disguised as a control. Raised as **F-07
(MEDIUM)**.

---

## Cross-cutting properties I verified

* **No handler with a declared permission fails to reach an authorisation
  decision.** All 71 permission-bearing rows reach either `state.require` (row
  target or collection) or `ScopeFilter::build`/`visibility_for` followed by a
  SQL predicate. There is no forgotten-authorisation route.
* **No `Path<Uuid>` reaches a decision unvalidated.** `PathId`/`PathIds`/`PathKey`
  parse and refuse without echoing the value; `authorization::routes::parse_id`
  and `audit::service::parse_uuid` do the same by hand (see F-13 on the
  divergence).
* **No SQL fragment is built from request input.** Every dynamic fragment in
  `visibility.rs`, `departments/repo.rs`, `identity/repo.rs`, `audit/repo.rs` is
  a `&'static str` chosen by a `match` on a closed enum or an allowlist lookup;
  the only `format!`-built SQL interpolates `&'static str` sort columns and
  operators taken from compile-time allowlists.
* **Every mutation authorises inside the transaction that mutates**, against a
  row read `FOR UPDATE`, with three exceptions that are correct by construction:
  `projects::create` and `departments::create`/`clients::create` (no row exists
  yet, so the decision is collection- or request-department-level), and
  `departments::add_member`/`remove_member` whose *root guard* is outside (F-03).
