# Frontend action catalogue

The bridge document. One entry per user-actionable backend operation — **92** of
them, being all 95 routes in `ROUTE_TABLE` minus the three infrastructure probes
(`/health/live`, `/health/ready`, `/metrics`), which no user action maps to.

Every `action_id`, permission, error code and audit constant below is transcribed
from the source. Nothing is invented.

## How to use this

`action_id` is a stable label for the designer and the frontend to name a control
by. It is **not** an API concept — the backend has never heard of it. Its purpose
is that a menu definition, a design mock and a permission check can all refer to
the same string.

The visibility rule, and the only sanctioned one:

```
show(action) := me.capabilities.some(c => c.permission === action.permission)
```

See `FRONTEND_CAPABILITY_CONTRACT.md` for why that is a hint and not a decision.

## Column meanings

| Column | Meaning |
|---|---|
| **Permission** | The code the service passes to `state.require`. `—` means the handler takes no permission decision. |
| **Scope** | `GLOBAL` — only a global grant reaches it (`Target::Collection`). `object` — evaluated against the loaded row, so `GLOBAL`/`DEPARTMENT`/`ASSIGNED`/`RESOURCE` (and `SELF` on user targets) all apply. `filtered` — scopes become a SQL predicate. `self` — the subject is the calling session. |
| **Principals** | `any` — no session needed. `INTERNAL` — a `CLIENT` is refused at the envelope and receives `404`. `both` — `INTERNAL` and `CLIENT`. |
| **MFA** | `yes` — the route uses the `Authenticated` extractor, so a session with `pending_mfa` is refused with `403 MFA_REQUIRED`. `pending-ok` — the `MfaPendingSession` extractor accepts a password-only session. `n/a` — anonymous. |
| **Step-up** | Whether a recent second factor is enforced. |
| **Confirm** | Whether a confirmation dialog is recommended before firing. A design judgement, derived from destructiveness and blast radius. |
| **Destructive** | Whether the operation removes access, removes data, or crosses a trust boundary. Note that **nothing in this API hard-deletes a business row** — archive and cancel are state transitions, and the runtime database role holds no `DELETE` grant on `users`. |
| **Idem.** | `key` — honours `Idempotency-Key`. `version` — takes an optimistic-concurrency token. `—` — neither. |
| **Failure codes** | Beyond the universal set documented in `FRONTEND_ERROR_CONTRACT.md`. |
| **Audit** | The `action::*` constants the service writes. |

---

## 1. Getting in (anonymous)

| action_id | Meaning | Route | Permission | Scope | Principals | MFA | Step-up | Confirm | Destructive | Idem. | Success | Failure codes | Audit |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `auth.login` | Sign in with email and password | `POST /api/v1/auth/login` | — | — | any | n/a | no | no | no | — | `200` + access token, refresh token, `expires_in`, `mfa_required` | `AUTHENTICATION_FAILED`, `RATE_LIMITED` | `AUTH.LOGIN_SUCCEEDED`, `AUTH.LOGIN_FAILED`, `SESSION.REVOKED` (session cap) |
| `auth.refresh` | Exchange a refresh token for a new pair | `POST /api/v1/auth/refresh` | — | — | any | n/a | no | no | no | — | `200` + a new token pair (the old refresh token is always rotated) | `AUTHENTICATION_FAILED`, `RATE_LIMITED` | `AUTH.REFRESHED`, `AUTH.REFRESH_REUSE_DETECTED` |
| `auth.password_reset.request` | Ask for a reset link | `POST /api/v1/auth/password-reset/request` | — | — | any | n/a | no | no | no | — | `202` + a fixed body, identical whether or not the account exists | `RATE_LIMITED` | `PASSWORD.RESET_REQUESTED` |
| `auth.password_reset.confirm` | Set a new password from a reset token | `POST /api/v1/auth/password-reset/confirm` | — | — | any | n/a | no | no | **yes** — it revokes every session | — | `200` + `{revoked_sessions}` | `AUTHENTICATION_FAILED`, `VALIDATION_FAILED`, `RATE_LIMITED` | `PASSWORD.RESET_COMPLETED`, `SESSION.REVOKED_ALL` |
| `registration.config.read` | Discover whether to render a signup form | `GET /api/v1/registration/config` | — | — | any | n/a | no | no | no | — | `200` + `{registration_available, registration_type}` | — | — |
| `registration.submit` | Self-register as an external client | `POST /api/v1/registration` | — | — | any | n/a | no | no | no | — | `202` + a fixed body. **Disabled by default** | `RESOURCE_NOT_FOUND` (signup off), `VALIDATION_FAILED`, `RATE_LIMITED` | `USER.REGISTERED` (Success and Denied) |
| `invitation.accept` | Redeem an invitation and create the account | `POST /api/v1/invitations/accept` | — | — | any | n/a | the inviter's step-up is asserted at acceptance | no | no | — | `201` + `{user_id, email, display_name, principal_type, status, mfa_enrolment_required}`. **No session is issued** — route to login | `AUTHENTICATION_FAILED` (every rejection reason), `VALIDATION_FAILED`, `RATE_LIMITED` | `USER.CREATED`, `INVITATION.ACCEPTED` |
| `system.bootstrap.status` | Has the system been set up? | `GET /api/v1/bootstrap/status` | — | — | any | n/a | no | no | no | — | `200` + `{initialized}` | — | — |
| `system.bootstrap.root` | First-run: create the system owner | `POST /api/v1/bootstrap/root` | — | — | any | n/a | no | **yes** — one-time and irreversible | no | — | `201` + the owner record | `RESOURCE_NOT_FOUND` (no operator secret configured), `AUTHENTICATION_FAILED`, `SYSTEM_ALREADY_INITIALIZED`, `VALIDATION_FAILED`, `RATE_LIMITED` | `SYSTEM.BOOTSTRAPPED`, `SYSTEM.BOOTSTRAP_REJECTED` |

## 2. Session and factors (own account)

| action_id | Meaning | Route | Permission | Scope | Principals | MFA | Step-up | Confirm | Destructive | Idem. | Success | Failure codes | Audit |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `auth.me.read` | Load the session, capability hint and MFA state | `GET /api/v1/auth/me` | — | self | both | **pending-ok** | no | no | no | — | `200` + the full or reduced projection | — | — |
| `auth.logout` | End the current session | `POST /api/v1/auth/logout` | — | self | both | **pending-ok** (see note) | no | no | yes (ends access) | — | `200` | — | `AUTH.LOGOUT` |
| `auth.logout_all` | End every session for this account | `POST /api/v1/auth/logout-all` | — | self | both | yes | no | **yes** | yes | — | `200` + `{revoked_sessions}` | — | `SESSION.REVOKED_ALL` |
| `auth.session.list` | List my own live sessions | `GET /api/v1/auth/sessions` | — | self (SQL-scoped) | both | yes | no | no | no | — | `200` + sessions with `current`, expiries, IP/UA recognition hints | — | — |
| `auth.session.revoke` | End one of my own sessions | `DELETE /api/v1/auth/sessions/{id}` | — | self (SQL predicate) | both | yes | no | yes | yes | — | `200` | `RESOURCE_NOT_FOUND` (also what somebody else's session returns) | `SESSION.REVOKED` |
| `auth.password.change` | Change my password | `POST /api/v1/auth/password/change` | — | self | both | yes | no | no | yes — revokes other sessions | — | `200` + `{revoked_sessions}` | `AUTHENTICATION_FAILED` (wrong current password), `VALIDATION_FAILED`, `RATE_LIMITED` | `PASSWORD.CHANGED` |
| `auth.mfa.totp.setup` | Begin TOTP enrolment | `POST /api/v1/auth/mfa/totp/setup` | — | self | both | **pending-ok** | no | no | no | — | `201` + `secret`, `otpauth_uri`, `algorithm`, `digits`, `period`. **The secret is shown once and can never be read back** | `MFA_ALREADY_ENROLLED`, `RATE_LIMITED` | `MFA.ENROLMENT_STARTED` |
| `auth.mfa.totp.activate` | Confirm the code and activate the factor | `POST /api/v1/auth/mfa/totp/activate` | — | self | both | **pending-ok** | no | no | no | — | `200` + `recovery_codes`, shown once | `MFA_NOT_PENDING`, `AUTHENTICATION_FAILED`, `RATE_LIMITED` | `MFA.ACTIVATED`, `MFA.RECOVERY_CODES_GENERATED`, `MFA.REPLAY_DETECTED`, `MFA.VERIFICATION_FAILED` |
| `auth.mfa.verify` | Complete MFA, or refresh the step-up window | `POST /api/v1/auth/mfa/verify` | — | self | both | **pending-ok** | no | no | no | — | `200` + `{mfa_required: false, auth_level, step_up_active}` | `AUTHENTICATION_FAILED`, `RATE_LIMITED` | `AUTH.STEP_UP_COMPLETED`, `MFA.REPLAY_DETECTED`, `MFA.VERIFICATION_FAILED` |
| `auth.mfa.recovery.verify` | Complete MFA with a recovery code | `POST /api/v1/auth/mfa/recovery/verify` | — | self | both | **pending-ok** | no | yes (it burns a code) | no | — | `200`, including `recovery_codes_remaining` | `AUTHENTICATION_FAILED`, `RATE_LIMITED` | `MFA.RECOVERY_CODE_CONSUMED`, `MFA.VERIFICATION_FAILED` |
| `auth.mfa.recovery.regenerate` | Mint a fresh set of recovery codes | `POST /api/v1/auth/mfa/recovery/regenerate` | — | self | both | yes | **YES** | **yes** — the old codes stop working | yes | — | `200` + the new codes, shown once | `STEP_UP_REQUIRED`, `MFA_NOT_ENROLLED`, `RATE_LIMITED` | `MFA.RECOVERY_CODES_GENERATED` |
| `auth.mfa.disable` | Remove the second factor | `POST /api/v1/auth/mfa/disable` | — | self | both | yes | **YES** | **yes** | **yes** — it lowers the account's own security | — | `200` + `{mfa_enrolled: false}` | `STEP_UP_REQUIRED`, `MFA_MANDATORY` (when the account requires MFA) | `MFA.DISABLED` |

> **Note on `auth.logout`**: `ROUTE_TABLE` declares this route `Authenticated`, but
> the handler uses the `MfaPendingSession` extractor so that a session stuck in
> `MFA_ENROLLMENT_REQUIRED` can dispose of its token. Code the client against the
> implementation: a pending session **can** log out.

## 3. Users

All `INTERNAL` only. All lifecycle transitions refuse the system owner
(`403 ROOT_PROTECTED`) and refuse self-target (`409 SELF_TARGET_REFUSED`).

| action_id | Meaning | Route | Permission | Scope | Principals | MFA | Step-up | Confirm | Destructive | Idem. | Success | Failure codes | Audit |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `user.list` | List user accounts | `GET /api/v1/users` | `iam.users.read` | filtered | INTERNAL | yes | no | no | no | — | `200` + a cursor page | — | — |
| `user.read` | Read one user | `GET /api/v1/users/{id}` | `iam.users.read` | object | INTERNAL | yes | no | no | no | — | `200` | `RESOURCE_NOT_FOUND` | — |
| `user.update` | Edit display name or email | `PATCH /api/v1/users/{id}` | `iam.users.update` | object | INTERNAL | yes | no | no | no | **version** | `200` + the updated user | `VERSION_CONFLICT`, `ROOT_PROTECTED`, `EMAIL_IN_USE`, `VALIDATION_FAILED` | `USER.UPDATED`, `ROOT.PROTECTION_TRIGGERED` |
| `user.suspend` | Suspend an account | `POST /api/v1/users/{id}/suspend` | `iam.users.suspend` | object | INTERNAL | yes | no | **yes** | **yes** — revokes every live session in the same transaction | **version** | `200` + the updated user | `VERSION_CONFLICT`, `ROOT_PROTECTED`, `SELF_TARGET_REFUSED`, `INVALID_STATUS_TRANSITION` | `USER.SUSPENDED`, `SESSION.REVOKED_ALL` |
| `user.reactivate` | Return a suspended account to active | `POST /api/v1/users/{id}/reactivate` | `iam.users.suspend` | object | INTERNAL | yes | no | yes | no | **version** | `200` | `VERSION_CONFLICT`, `ROOT_PROTECTED`, `SELF_TARGET_REFUSED`, `INVALID_STATUS_TRANSITION` | `USER.REACTIVATED` |
| `user.archive` | End an account's life | `POST /api/v1/users/{id}/archive` | `iam.users.archive` | object | INTERNAL | yes | no | **yes** | **yes** — the only removal the API offers, and there is no un-archive | **version** | `200` | `VERSION_CONFLICT`, `ROOT_PROTECTED`, `SELF_TARGET_REFUSED`, `INVALID_STATUS_TRANSITION` | `USER.ARCHIVED`, `SESSION.REVOKED_ALL` |

## 4. Invitations

| action_id | Meaning | Route | Permission | Scope | Principals | MFA | Step-up | Confirm | Destructive | Idem. | Success | Failure codes | Audit |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `invitation.list` | List invitations | `GET /api/v1/invitations` | `iam.users.invite` | GLOBAL | INTERNAL | yes | no | no | no | — | `200` + a page | — | — |
| `user.invite` | Issue an invitation | `POST /api/v1/invitations` | `iam.users.invite`, **plus** `departments.members.manage` and/or `clients.members.manage` for any named placement, **plus** the delegation guard on every named role | GLOBAL for the invite; object for each placement | INTERNAL | yes | **conditional** — required when any named role carries a dangerous permission | no | no | **key** | `201` + the invitation. The token is emailed, never returned | `EMAIL_IN_USE`, `DELEGATION_DENIED`, `STEP_UP_REQUIRED`, `VALIDATION_FAILED`, `IDEMPOTENCY_KEY_REUSED`, `IDEMPOTENCY_RACE` | `INVITATION.CREATED` |
| `invitation.revoke` | Cancel a pending invitation | `DELETE /api/v1/invitations/{id}` | `iam.users.invite` | GLOBAL | INTERNAL | yes | no | yes | yes | — | `200` + the revoked invitation | `INVITATION_NOT_PENDING`, `RESOURCE_NOT_FOUND` | `INVITATION.REVOKED` |

## 5. Roles and permissions

The highest-consequence surface in the product. Every write here is behind step-up.

| action_id | Meaning | Route | Permission | Scope | Principals | MFA | Step-up | Confirm | Destructive | Idem. | Success | Failure codes | Audit |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `permission.catalog.read` | Read the permission catalogue | `GET /api/v1/permissions` | `iam.permissions.read` | GLOBAL | INTERNAL | yes | no | no | no | — | `200` | — | — |
| `role.list` | List roles | `GET /api/v1/roles` | `iam.roles.read` | GLOBAL | INTERNAL | yes | no | no | no | — | `200` + a page | — | — |
| `role.read` | Read a role and its permissions | `GET /api/v1/roles/{id}` | `iam.roles.read` | GLOBAL | INTERNAL | yes | no | no | no | — | `200` | `RESOURCE_NOT_FOUND` | — |
| `role.create` | Author a role | `POST /api/v1/roles` | `iam.roles.create` + `check_role_authoring` | GLOBAL | INTERNAL | yes | **YES** | yes | no | **key** | `201` + the role | `STEP_UP_REQUIRED`, `DELEGATION_DENIED`, `UNKNOWN_PERMISSION`, `UNIQUE_VIOLATION`, `IDEMPOTENCY_KEY_REUSED`, `IDEMPOTENCY_RACE` | `ROLE.CREATED`, `AUTHORIZATION.DENIED` |
| `role.update` | Edit a role's permission set | `PATCH /api/v1/roles/{id}` | `iam.roles.update` + `check_role_authoring` | GLOBAL | INTERNAL | yes | **YES** | **yes** — it changes what every current holder may do | yes (can remove authority) | **version** | `200` | `VERSION_CONFLICT`, `STEP_UP_REQUIRED`, `DELEGATION_DENIED`, `UNKNOWN_PERMISSION` | `ROLE.UPDATED`, `AUTHORIZATION.DENIED` |
| `role.delete` | Delete a role | `DELETE /api/v1/roles/{id}` | `iam.roles.delete` | GLOBAL | INTERNAL | yes | **YES** | **yes** | **yes** | — | `204` | `ROLE_IN_USE`, `STEP_UP_REQUIRED`, `RESOURCE_NOT_FOUND` | `ROLE.DELETED`, `AUTHORIZATION.DENIED` |
| `user.roles.read` | Which roles does this user hold? | `GET /api/v1/users/{id}/roles` | `iam.roles.read` | object | INTERNAL | yes | no | no | no | — | `200` | `RESOURCE_NOT_FOUND` | — |
| `user.role.assign` | Grant a role to a user | `POST /api/v1/users/{id}/roles` | `iam.roles.assign` (**dangerous**) + `check_role_assignment` | object | INTERNAL | yes | **YES** | **yes** | no, but it is an authority change | — | `201` + the user's role list | `STEP_UP_REQUIRED`, `DELEGATION_DENIED`, `ROOT_PROTECTED`, `SUBJECT_ARCHIVED`, `ROLE_ALREADY_ASSIGNED` | `ROLE.ASSIGNED`, `AUTHORIZATION.DENIED`, `ROOT.PROTECTION_TRIGGERED` |
| `user.role.unassign` | Remove a role from a user | `DELETE /api/v1/users/{id}/roles/{role_id}` | `iam.roles.assign` (**dangerous**) | object | INTERNAL | yes | **YES** | **yes** | **yes** — removes access | — | `204` | `STEP_UP_REQUIRED`, `DELEGATION_DENIED`, `ROOT_PROTECTED`, `RESOURCE_NOT_FOUND` | `ROLE.UNASSIGNED`, `AUTHORIZATION.DENIED` |
| `user.permissions.read` | This user's effective permissions | `GET /api/v1/users/{id}/permissions` | `iam.permissions.read` | object | INTERNAL | yes | no | no | no | — | `200` | `RESOURCE_NOT_FOUND` | — |
| `user.overrides.read` | This user's permission exceptions | `GET /api/v1/users/{id}/permission-overrides` | `iam.permissions.read` — an inspection, not a grant | object | INTERNAL | yes | no | no | no | — | `200` | `RESOURCE_NOT_FOUND` | — |
| `user.override.create` | Add an ALLOW or DENY exception | `POST /api/v1/users/{id}/permission-overrides` | `iam.permissions.delegate` (**dangerous**) + `check_permission_grant` | object | INTERNAL | yes | **YES** | **yes** | no, but a DENY removes access | — | `201` + the override | `STEP_UP_REQUIRED`, `DELEGATION_DENIED`, `ROOT_PROTECTED`, `UNKNOWN_PERMISSION`, `SUBJECT_ARCHIVED` | `PERMISSION.OVERRIDE_CREATED`, `AUTHORIZATION.DENIED`, `ROOT.PROTECTION_TRIGGERED` |
| `user.override.delete` | Remove an exception | `DELETE /api/v1/users/{id}/permission-overrides/{override_id}` | `iam.permissions.delegate` (**dangerous**) | object | INTERNAL | yes | **YES** | **yes** | **yes** — removing a DENY *widens* access | — | `204` | `STEP_UP_REQUIRED`, `DELEGATION_DENIED`, `RESOURCE_NOT_FOUND` | `PERMISSION.OVERRIDE_REMOVED`, `AUTHORIZATION.DENIED` |

## 6. Departments

| action_id | Meaning | Route | Permission | Scope | Principals | MFA | Step-up | Confirm | Destructive | Idem. | Success | Failure codes | Audit |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `department.list` | List departments | `GET /api/v1/departments` | `departments.read` | filtered | INTERNAL | yes | no | no | no | — | `200` + a page | — | — |
| `department.read` | Read one department | `GET /api/v1/departments/{id}` | `departments.read` | object | INTERNAL | yes | no | no | no | — | `200` | `RESOURCE_NOT_FOUND` | — |
| `department.create` | Create a department | `POST /api/v1/departments` | `departments.create` | GLOBAL | INTERNAL | yes | no | no | no | **key** | `201` | `UNIQUE_VIOLATION`, `UNKNOWN_USER`, `VALIDATION_FAILED`, `IDEMPOTENCY_KEY_REUSED`, `IDEMPOTENCY_RACE` | `DEPARTMENT.CREATED` |
| `department.update` | Edit name, description or lead | `PATCH /api/v1/departments/{id}` | `departments.update` | object | INTERNAL | yes | no | no | no | **version** | `200` | `VERSION_CONFLICT`, `DEPARTMENT_ARCHIVED`, `UNKNOWN_USER` | `DEPARTMENT.UPDATED` |
| `department.archive` | Archive a department | `POST /api/v1/departments/{id}/archive` | `departments.archive` | object | INTERNAL | yes | no | **yes** | **yes** | **version** | `200` | `VERSION_CONFLICT`, `DEPARTMENT_ALREADY_ARCHIVED`, `DEPARTMENT_HAS_LIVE_PROJECTS` | `DEPARTMENT.ARCHIVED` |
| `department.members.read` | List department members | `GET /api/v1/departments/{id}/members` | `departments.read` | object | INTERNAL | yes | no | no | no | — | `200` + a page | `RESOURCE_NOT_FOUND` | — |
| `department.member.add` | Add someone to a department | `POST /api/v1/departments/{id}/members` | `departments.members.manage` | object | INTERNAL | yes | no | yes | no — **but it is an authority change**: department membership resolves `DEPARTMENT` scope | — | `201` + the membership | `UNKNOWN_USER`, `ALREADY_A_MEMBER`, `PRINCIPAL_TYPE_MISMATCH`, `USER_ARCHIVED`, `DEPARTMENT_ARCHIVED`, `ROOT_PROTECTED` | `DEPARTMENT.MEMBER_ADDED`, `ROOT.PROTECTION_TRIGGERED` |
| `department.member.remove` | Remove someone from a department | `DELETE /api/v1/departments/{id}/members/{user_id}` | `departments.members.manage` | object | INTERNAL | yes | no | **yes** | **yes** — removes `DEPARTMENT`-scoped authority immediately | — | `204` | `ROOT_PROTECTED`, `RESOURCE_NOT_FOUND` | `DEPARTMENT.MEMBER_REMOVED`, `ROOT.PROTECTION_TRIGGERED` |

## 7. Client accounts

| action_id | Meaning | Route | Permission | Scope | Principals | MFA | Step-up | Confirm | Destructive | Idem. | Success | Failure codes | Audit |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `client.list` | List client accounts | `GET /api/v1/clients` | `clients.read` | filtered | INTERNAL | yes | no | no | no | — | `200` + a page | — | — |
| `client.read` | Read one client account | `GET /api/v1/clients/{id}` | `clients.read` | object | INTERNAL | yes | no | no | no | — | `200` | `RESOURCE_NOT_FOUND` | — |
| `client.create` | Create a client account | `POST /api/v1/clients` | `clients.create` | GLOBAL | INTERNAL | yes | no | no | no | **key** | `201` | `UNIQUE_VIOLATION`, `UNKNOWN_USER`, `VALIDATION_FAILED`, `IDEMPOTENCY_KEY_REUSED`, `IDEMPOTENCY_RACE` | `CLIENT.CREATED` |
| `client.update` | Edit a client account | `PATCH /api/v1/clients/{id}` | `clients.update` | object | INTERNAL | yes | no | no | no | **version** | `200` | `VERSION_CONFLICT`, `CLIENT_ARCHIVED`, `UNKNOWN_USER` | `CLIENT.UPDATED` |
| `client.archive` | Archive a client account | `POST /api/v1/clients/{id}/archive` | `clients.archive` | object | INTERNAL | yes | no | **yes** | **yes** | **version** | `200` | `VERSION_CONFLICT`, `CLIENT_ALREADY_ARCHIVED` | `CLIENT.ARCHIVED` |
| `client.members.read` | List client members | `GET /api/v1/clients/{id}/members` | `clients.read` | object | INTERNAL | yes | no | no | no | — | `200` + a page | `RESOURCE_NOT_FOUND` | — |
| `client.member.add` | Attach an external user to a client account | `POST /api/v1/clients/{id}/members` | `clients.members.manage` | object | INTERNAL | yes | no | yes | no | — | `201` + the membership | `UNKNOWN_USER`, `ALREADY_A_MEMBER`, `PRINCIPAL_TYPE_MISMATCH`, `USER_ARCHIVED`, `CLIENT_ARCHIVED` | `CLIENT.MEMBER_ADDED` |
| `client.member.activate` | Activate a client membership | `POST /api/v1/clients/{id}/members/{user_id}/activate` | `clients.members.manage` | object | INTERNAL | yes | no | **yes** | no — but it is **the moment a stranger becomes a counterparty**: this is what makes company data visible outside the company | — | `200` + the membership | `MEMBERSHIP_ALREADY_ACTIVE`, `MEMBERSHIP_REMOVED`, `MEMBERSHIP_CHANGED`, `CLIENT_ARCHIVED` | `CLIENT.MEMBER_ACTIVATED` |
| `client.member.remove` | Remove a client membership | `DELETE /api/v1/clients/{id}/members/{user_id}` | `clients.members.manage` | object | INTERNAL | yes | no | yes | **yes** — the external user's world goes empty | — | `204` | `MEMBERSHIP_ALREADY_REMOVED`, `MEMBERSHIP_CHANGED`, `RESOURCE_NOT_FOUND` | `CLIENT.MEMBER_REMOVED` |

## 8. Projects

| action_id | Meaning | Route | Permission | Scope | Principals | MFA | Step-up | Confirm | Destructive | Idem. | Success | Failure codes | Audit |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `project.list` | List projects | `GET /api/v1/projects` | `projects.read` | filtered | INTERNAL | yes | no | no | no | — | `200` + a page | — | — |
| `project.read` | Read one project | `GET /api/v1/projects/{id}` | `projects.read` | object | INTERNAL | yes | no | no | no | — | `200` | `RESOURCE_NOT_FOUND` | — |
| `project.create` | Create a project | `POST /api/v1/projects` | `projects.create` | object, built from the **requested** department | INTERNAL | yes | no | no | no | **key** | `201` | `UNIQUE_VIOLATION`, `EXTERNAL_PRINCIPAL`, `VALIDATION_FAILED`, `IDEMPOTENCY_KEY_REUSED`, `IDEMPOTENCY_RACE` | `PROJECT.CREATED` |
| `project.update` | Edit a project, including moving it between departments | `PATCH /api/v1/projects/{id}` | `projects.update` — **authorised twice** on a department move, against source and destination | object | INTERNAL | yes | no | yes, for a department move | no | **version** | `200` | `VERSION_CONFLICT`, `INVALID_STATE_TRANSITION`, `EXTERNAL_PRINCIPAL` | `PROJECT.UPDATED` |
| `project.archive` | Archive a project | `POST /api/v1/projects/{id}/archive` | `projects.archive` | object | INTERNAL | yes | no | **yes** | **yes** | **version** | `200` | `VERSION_CONFLICT`, `ALREADY_ARCHIVED` | `PROJECT.ARCHIVED` |
| `project.members.read` | List project members | `GET /api/v1/projects/{id}/members` | `projects.read` | object | INTERNAL | yes | no | no | no | — | `200` | `RESOURCE_NOT_FOUND` | — |
| `project.member.add` | Add an internal member | `POST /api/v1/projects/{id}/members` | `projects.members.manage` | object | INTERNAL | yes | no | no | no — but membership resolves `ASSIGNED` scope | — | `204` | `PROJECT_ARCHIVED`, `ALREADY_A_MEMBER`, `EXTERNAL_PRINCIPAL` | `PROJECT.MEMBER_ADDED` |
| `project.member.remove` | Remove a member | `DELETE /api/v1/projects/{id}/members/{user_id}` | `projects.members.manage` | object | INTERNAL | yes | no | yes | **yes** — removes `ASSIGNED`-scoped access | — | `204` | `RESOURCE_NOT_FOUND` | `PROJECT.MEMBER_REMOVED` |
| `project.clients.read` | Which clients can see this project? | `GET /api/v1/projects/{id}/clients` | `projects.read` | object | INTERNAL | yes | no | no | no | — | `200` | `RESOURCE_NOT_FOUND` | — |
| `project.share_client` | Share a project with a client account | `POST /api/v1/projects/{id}/clients` | `projects.clients.share` (**dangerous**) | object | INTERNAL | yes | **YES** | **yes** — this is the strongest confirmation in the product | no, but it **crosses the external trust boundary** | — | `204` | `STEP_UP_REQUIRED`, `PROJECT_ARCHIVED`, `CLIENT_ACCOUNT_NOT_ACTIVE` | `PROJECT.SHARED_WITH_CLIENT`, `AUTHORIZATION.DENIED` on refusal |
| `project.unshare_client` | Revoke a client's access to a project | `DELETE /api/v1/projects/{id}/clients/{client_account_id}` | `projects.clients.share` (**dangerous**) | object | INTERNAL | yes | **YES** | **yes** | **yes** | — | `204` | `STEP_UP_REQUIRED`, `RESOURCE_NOT_FOUND` | `PROJECT.UNSHARED_FROM_CLIENT`, `AUTHORIZATION.DENIED` |
| `project.tasks.list` | List a project's tasks | `GET /api/v1/projects/{project_id}/tasks` | `tasks.read` | filtered, bounded to the project | INTERNAL | yes | no | no | no | — | `200` + a page | `RESOURCE_NOT_FOUND` | — |

## 9. Tasks

| action_id | Meaning | Route | Permission | Scope | Principals | MFA | Step-up | Confirm | Destructive | Idem. | Success | Failure codes | Audit |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `task.list` | List tasks | `GET /api/v1/tasks` | `tasks.read` | filtered | INTERNAL | yes | no | no | no | — | `200` + a page | — | — |
| `task.read` | Read one task | `GET /api/v1/tasks/{id}` | `tasks.read` | object | INTERNAL | yes | no | no | no | — | `200` | `RESOURCE_NOT_FOUND` | — |
| `task.create` | Create a task in a project | `POST /api/v1/tasks` | `tasks.create` | object, from the loaded project named in the body | INTERNAL | yes | no | no | no | **key** | `201`. A new task is always `client_visible = false` — there is no field for it | `PROJECT_ARCHIVED`, `EXTERNAL_PRINCIPAL`, `RESOURCE_NOT_FOUND`, `IDEMPOTENCY_KEY_REUSED`, `IDEMPOTENCY_RACE` | `TASK.CREATED` |
| `task.update` | Edit a task | `PATCH /api/v1/tasks/{id}` | `tasks.update` | object | INTERNAL | yes | no | no | no | **version** | `200` | `VERSION_CONFLICT`, `INVALID_STATE_TRANSITION` | `TASK.UPDATED` |
| `task.set_client_visible` | Make a task visible to, or hidden from, the client portal (the `client_visible` field of `task.update`) | `PATCH /api/v1/tasks/{id}` | `tasks.update` | object | INTERNAL | yes | no | **yes** — it moves company data across the client boundary | no | **version** | `200` | as `task.update` | `TASK.UPDATED` **and** `TASK.CLIENT_VISIBILITY_CHANGED` |
| `task.cancel` | Cancel a task | `DELETE /api/v1/tasks/{id}?version=N` | `tasks.delete` | object | INTERNAL | yes | no | **yes** | **yes**, but it is a status change — the row is never removed | **version, as an optional query parameter** | `204` | `VERSION_CONFLICT` (only when `version` is supplied), `ALREADY_CANCELLED`, `INVALID_STATE_TRANSITION` | `TASK.CANCELLED` |
| `task.assignees.read` | Who is on this task? | `GET /api/v1/tasks/{id}/assignees` | `tasks.read` — a read, not an assign capability | object | INTERNAL | yes | no | no | no | — | `200` | `RESOURCE_NOT_FOUND` | — |
| `task.assign` | Assign someone to a task | `POST /api/v1/tasks/{id}/assignees` | `tasks.assign` | object | INTERNAL | yes | no | no | no — but assignment resolves `ASSIGNED` scope | — | `204` | `TASK_CANCELLED`, `ALREADY_ASSIGNED`, `EXTERNAL_PRINCIPAL` | `TASK.ASSIGNED` |
| `task.unassign` | Remove an assignee | `DELETE /api/v1/tasks/{id}/assignees/{user_id}` | `tasks.assign` | object | INTERNAL | yes | no | yes | **yes** — removes `ASSIGNED`-scoped access | — | `204` | `RESOURCE_NOT_FOUND` | `TASK.UNASSIGNED` |

## 10. Client portal (the external surface)

Read-only throughout, and the only business surface an external principal may
reach. Every response is a reduced projection chosen by the route, not by a flag —
there is no request in which the internal serialiser could be reached by an
external principal.

| action_id | Meaning | Route | Permission | Scope | Principals | MFA | Step-up | Confirm | Destructive | Idem. | Success | Failure codes | Audit |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `portal.projects.list` | List the projects shared with me | `GET /api/v1/client-portal/projects` | `client.portal.projects.read` | `ASSIGNED`, via ACTIVE client memberships | **both** | yes | no | no | no | — | `200` + a page of `ClientProjectResponse` | — | — |
| `portal.project.read` | Read one shared project | `GET /api/v1/client-portal/projects/{id}` | `client.portal.projects.read` | `ASSIGNED` | both | yes | no | no | no | — | `200` | `RESOURCE_NOT_FOUND` | — |
| `portal.project.tasks.list` | List the visible tasks of a shared project | `GET /api/v1/client-portal/projects/{id}/tasks` | `client.portal.tasks.read` | `ASSIGNED`, and `client_visible = true` only | both | yes | no | no | no | — | `200` + a page of `ClientTaskResponse` | `RESOURCE_NOT_FOUND` | — |
| `portal.task.read` | Read one visible task | `GET /api/v1/client-portal/tasks/{id}` | `client.portal.tasks.read` | `ASSIGNED` | both | yes | no | no | no | — | `200`. Carries no `internal_note`, `created_by`, `version` or `client_visible` | `RESOURCE_NOT_FOUND` | — |

## 11. Settings, feature flags and system

| action_id | Meaning | Route | Permission | Scope | Principals | MFA | Step-up | Confirm | Destructive | Idem. | Success | Failure codes | Audit |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `settings.list` | Read every system setting | `GET /api/v1/settings` | `settings.read` | GLOBAL | INTERNAL | yes | no | no | no | — | `200` | — | — |
| `setting.update` | Change a system setting | `PUT /api/v1/settings/{key}` | `settings.features.write` **or** `settings.security.write` — decided from the loaded row's `is_security_sensitive` | GLOBAL | INTERNAL | yes | **conditional** — required for a security-sensitive key, because `settings.security.write` is dangerous | **yes** for a security-sensitive key | can be — `registration.mode` is here | **version** | `200` + the updated setting | `VERSION_CONFLICT`, `STEP_UP_REQUIRED`, `VALIDATION_FAILED`, `RESOURCE_NOT_FOUND` | `SETTING.CHANGED` (Success and Denied). **Values are not recorded for security-sensitive keys** |
| `feature_flags.list` | Read every feature flag | `GET /api/v1/feature-flags` | `settings.read` | GLOBAL | INTERNAL | yes | no | no | no | — | `200` | — | — |
| `feature_flag.update` | Toggle a feature flag | `PUT /api/v1/feature-flags/{key}` | same dynamic split as `setting.update` | GLOBAL | INTERNAL | yes | conditional, as above | **yes** for a security-sensitive flag | can be | **version** | `200` | `VERSION_CONFLICT`, `STEP_UP_REQUIRED`, `VALIDATION_FAILED`, `RESOURCE_NOT_FOUND` | `FEATURE_FLAG.CHANGED` (Success and Denied) |
| `system.info.read` | Environment, initialisation state, enabled feature keys | `GET /api/v1/system/info` | **—** (no permission is checked) | n/a | **both** — including external CLIENT principals; see `ROUTE_SECURITY_MATRIX.md` §14.3 | yes | no | no | no | — | `200` + `{environment, initialized, enabled_features}` | — | — |

## 12. Audit

Read-only by design. There is no create, update, delete or side-effecting export
route, and adding one requires an ADR, not a handler.

| action_id | Meaning | Route | Permission | Scope | Principals | MFA | Step-up | Confirm | Destructive | Idem. | Success | Failure codes | Audit |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `audit.events.list` | Browse the audit log | `GET /api/v1/audit/events` | `audit.read` | GLOBAL | INTERNAL | yes | no | no | no | — | `200` + a page | `BAD_REQUEST` (bad filter) | — |
| `audit.event.read` | Read one audit event | `GET /api/v1/audit/events/{id}` | `audit.read` | GLOBAL | INTERNAL | yes | no | no | no | — | `200` | `RESOURCE_NOT_FOUND` (a malformed id is also `404`, so the endpoint never reflects the caller's input) | — |
| `audit.verify` | Verify the tamper-evident hash chain | `GET /api/v1/audit/verify` | `audit.read` | GLOBAL | INTERNAL | yes | **YES** — the service calls `require_step_up` explicitly | no | no | — | `200` + the verification result over a bounded window | `STEP_UP_REQUIRED`, `BAD_REQUEST` / `VALIDATION_FAILED` (window out of range) | — |

---

## Cross-cutting notes for whoever builds the UI

1. **Every action marked step-up will fail the first time.** That is the design.
   Fire the request, catch `403 STEP_UP_REQUIRED`, read `step_up.window_seconds`,
   run the MFA prompt, replay. Build that as one reusable wrapper, not per screen.
2. **Nothing here hard-deletes.** `archive` and `cancel` are state transitions;
   `DELETE` on tasks cancels; there is no `DELETE /users/{id}` at all. Word the
   confirmations accordingly — "Archive" is honest, "Delete permanently" is not.
3. **`DELETE` on memberships, assignments, roles and overrides is a real removal**
   of the join row, and it removes access immediately. Those are the genuinely
   destructive actions in the product, along with `project.unshare_client`.
4. **The three highest-blast-radius actions** are `role.update` (changes what every
   holder may do), `project.share_client` (crosses the external trust boundary) and
   `client.member.activate` (turns a stranger into a counterparty). Give all three
   a deliberate, named confirmation rather than a generic "Are you sure?".
5. **Audit events with `Outcome::Denied` are written for refusals** on the
   sensitive paths — role authoring, role assignment, override changes, project
   sharing, settings writes, ROOT-targeted operations, and duplicate registrations.
   A failed action is not invisible; do not design flows that assume a 403 leaves
   no trace.
