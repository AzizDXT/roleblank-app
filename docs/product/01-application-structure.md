# 01 — Application Structure

The information architecture of RoleBlank OS: what screens exist, how they are
organised, what each one is made of structurally, which endpoint feeds it, and which
permission gates it.

**This document specifies no visual design.** No colours, no typography, no spacing,
no component library. Where it says "data table" it means *a region that lists rows
and paginates*, not a particular widget from a particular kit. The owner holds the
visual identity; this is the skeleton it dresses.

**Every endpoint named here exists.** The authority is `backend/src/routes.rs`
(`ROUTE_TABLE`, 93 entries) and `api/openapi.yaml`. Where a screen would be useful but
no endpoint backs it, it appears in §10 and nowhere else.

---

## 1. Two applications, one API

RoleBlank ships **two separate build targets** against the same `/api/v1` surface:

| Target | Principals | API surface reachable |
| --- | --- | --- |
| **Internal workspace** | `principal_type = INTERNAL` | the whole business surface, gated per route by permission |
| **Client portal** | `principal_type = CLIENT` | the four `/api/v1/client-portal/*` reads, plus the shared auth/account endpoints |

### Why two builds and not one app with a hidden menu

1. **An external user must never receive an internal bundle.** A single bundle
   containing the roles editor, the audit browser and the permission catalogue is
   handed to every CLIENT user who logs in. Menu hiding does not remove it — it ships
   the internal route table, the internal field names, the internal error strings and
   the shape of every internal DTO to an untrusted principal. The backend's client
   envelope (`04-authorization.md` §2, layer 1) stops the *requests*; it cannot
   un-ship the bundle.
2. **Route-level separation makes the mistake structurally harder.** In one app,
   exposing an internal screen to a client is a one-line regression in a conditional.
   In two apps it requires moving a file across a build boundary, which is visible in
   review and can be asserted by a build-time check ("no module under `internal/` is
   reachable from the portal entry point").
3. **The threat model already treats CLIENT as untrusted** (`02-threat-model.md` §2,
   boundary 2; adversary T2 is assumed to have full knowledge of the API contract and
   to tamper with every field). Shipping them the internal client is an own goal
   against an adversary the backend was designed around.
4. **They are different products.** The portal is four read-only screens. The
   workspace is thirty-six. Their navigation, density and vocabulary have nothing in
   common; merging them optimises nothing.

What the two builds **do** share, as a library rather than as an application: the
transport layer (bearer handling, serialised refresh, error decoding), the public
authentication screens, the MFA screens and the account screens. Sharing those is safe
because every endpoint behind them is `Anonymous`, `MfaPending`, or `Authenticated`
with **no permission requirement** — they carry no internal semantics.

### Deployment shape

Both talk to the Rust API through the BFF described in `03-authentication.md` §11.
Two BFF origins, two cookie scopes, two static bundles. The API is unaware of which
one is calling and must stay that way — no `X-App` header, no per-app branch. The API
authorises the principal, not the client.

---

## 2. Screen-state vocabulary

Every screen in this document is described against the same six states. They are not
optional; a screen that has not decided what it does in each of them is not specified.

| State | Trigger | Required behaviour |
| --- | --- | --- |
| `loading` | request in flight, no prior data | region-level placeholder; never a full-page blocker on a screen that already had data |
| `empty` | `200` with `items: []` | a statement of *why* it is empty (no rows yet, vs. filters exclude everything) and, if the actor holds the create permission, the create affordance |
| `error` | any `4xx`/`5xx` that is not handled below | render keyed on the stable `code`; show `request_id`; offer retry only for `500`/`503`/`429` |
| `forbidden` | `403 AUTHORIZATION_DENIED` | the region renders as unavailable, not as broken; no retry |
| `not_found` | `404 RESOURCE_NOT_FOUND` | in the workspace: "this no longer exists". In the portal: see `05-client-portal-boundary.md` — never the word "permission" |
| `stale` | `409 VERSION_CONFLICT` | re-read, show what changed, let the actor re-apply — never silently overwrite |

Three further states are cross-cutting and handled by the shell, not per screen:
`step_up_required` (`403 STEP_UP_REQUIRED`), `mfa_required` (`403 MFA_REQUIRED`) and
`unauthenticated` (`401`). See `04-navigation-and-state.md` §4.

---

## 3. Public surface (both applications)

Unauthenticated. Six screens, all backed by the pinned anonymous route set
(`07-api-contract.md` §11). No navigation chrome — these screens have no menu, because
there is no principal yet.

| `screen_id` | Route | Endpoints | Regions | Notes |
| --- | --- | --- | --- | --- |
| `public.bootstrap` | `/bootstrap` | `GET /api/v1/bootstrap/status`, `POST /api/v1/bootstrap/root` | status probe, owner-creation form (bootstrap secret, email, display name, password) | Reachable only while `initialized = false`. On `409 SYSTEM_ALREADY_INITIALIZED` redirect to `public.login` permanently. Response sets `mfa_enrolment_required = true` — hand straight to `auth.mfa.enrol` |
| `public.login` | `/login` | `POST /api/v1/auth/login` | credential form, error region, links to reset and (conditionally) registration | On `mfa_required = true` the session is real but pending — go to `auth.mfa.*`, do not go to the workspace. All failures are the same `401 AUTHENTICATION_FAILED`; the UI must not attempt to differentiate them |
| `public.password_reset.request` | `/password-reset` | `POST /api/v1/auth/password-reset/request` | email form, fixed acknowledgement | Always `202` with an identical body. The acknowledgement text must be the same whether or not the account exists |
| `public.password_reset.confirm` | `/password-reset/confirm?token=` | `POST /api/v1/auth/password-reset/confirm` | new-password form | Success revokes **all** sessions of that user; route to `public.login`, not into the app |
| `public.registration` | `/register` | `GET /api/v1/registration/config`, `POST /api/v1/registration` | availability gate, sign-up form, submitted acknowledgement | Config returns only `registration_available` and `registration_type`. A successful registration returns `registration_status = SUBMITTED` — the account is `PENDING` with zero memberships and can see nothing. Say so plainly |
| `public.invitation.accept` | `/invitations/accept?token=` | `POST /api/v1/invitations/accept` | token-bound form (password, optional display name) | Response carries `mfa_enrolment_required`; if true, the next screen after login is `auth.mfa.enrol` |

`GET /health/live`, `GET /health/ready` and `GET /metrics` are anonymous but are
**operator endpoints, not screens**. Nothing in either application calls them.

---

## 4. Authentication surface (both applications)

Reachable by a session with `pending_mfa = true`. While in that state **only these
screens exist** — see `04-navigation-and-state.md` §3.

| `screen_id` | Route | Endpoints | Regions | Notes |
| --- | --- | --- | --- | --- |
| `auth.mfa.enrol` | `/auth/mfa/enrol` | `GET /api/v1/auth/me`, `POST /api/v1/auth/mfa/totp/setup`, `POST /api/v1/auth/mfa/totp/activate` | secret presentation (`otpauth_uri`, base32 `secret`, `algorithm`/`digits`/`period`), code confirmation form, one-time recovery-code panel | Entered when `next_action = MFA_ENROLLMENT_REQUIRED`. The secret is returned **once**. The activate response embeds `recovery_codes` — also once. The recovery panel must require an explicit acknowledgement before it can be dismissed, because there is no endpoint to fetch them again |
| `auth.mfa.verify` | `/auth/mfa/verify` | `GET /api/v1/auth/me`, `POST /api/v1/auth/mfa/verify` | code form, link to recovery | Entered when `next_action = MFA_VERIFICATION_REQUIRED`. Response carries `auth_level`, `step_up_active` and `recovery_codes_remaining` — surface a low-remaining warning |
| `auth.mfa.recovery` | `/auth/mfa/recovery` | `POST /api/v1/auth/mfa/recovery/verify` | recovery-code form | Codes are single use. After success, prompt the actor towards `account.security.mfa` to regenerate |

---

## 5. Account surface (both applications)

Every endpoint here is `Authenticated` with **no permission requirement**, so these
screens are compiled into both bundles unchanged. They are the only internal-looking
screens a CLIENT principal ever sees, and they are safe because they are entirely
self-referential.

| `screen_id` | Route | Endpoints | Regions | Notes |
| --- | --- | --- | --- | --- |
| `account.profile` | `/account` | `GET /api/v1/auth/me` | identity block (`email`, `display_name`, `principal_type`, `is_root`), assurance block (`auth_level`, `mfa_enrolled`, `step_up_active`) | Read-only. There is no self-update endpoint — `PATCH /api/v1/users/{id}` requires `iam.users.update`, which most principals do not hold over themselves. Do not render an edit affordance you cannot honour |
| `account.security.password` | `/account/password` | `POST /api/v1/auth/password/change` | current/new password form, consequence notice | Success revokes **all other** sessions. Warn before submit, and refresh `account.sessions` after |
| `account.security.mfa` | `/account/security` | `POST /api/v1/auth/mfa/totp/setup`, `/activate`, `POST /api/v1/auth/mfa/recovery/regenerate`, `POST /api/v1/auth/mfa/disable` | enrolment state, regenerate action, disable action | Regenerate and disable are **step-up gated** and destructive. Regenerating invalidates the whole previous batch; disabling is refused by the backend for principals with `mfa_required = true` — render the outcome, do not pre-judge it |
| `account.sessions` | `/account/sessions` | `GET /api/v1/auth/sessions`, `DELETE /api/v1/auth/sessions/{id}`, `POST /api/v1/auth/logout-all` | session list (`current`, `auth_level`, `created_at`, `last_activity_at`, `client_ip_hint`, `user_agent_hint`, three expiry stamps), revoke-one action, revoke-all action | Not paginated — the response is a plain `{ sessions: [...] }`. Mark `current: true` distinctly and confirm before revoking it, because doing so ends the actor's own session. `logout-all` returns `revoked_sessions` |

---

## 6. Internal workspace

### 6.1 Navigation tree

```
internal
├── home                                   internal.home
├── Work
│   ├── Projects                           internal.projects.list
│   │   ├── New project                    internal.projects.create
│   │   └── Project                        internal.projects.detail
│   │       ├── Tasks (tab)                internal.projects.detail.tasks
│   │       ├── Team (tab)                 internal.projects.detail.members
│   │       └── Client access (tab)        internal.projects.detail.clients
│   └── Tasks                              internal.tasks.list
│       ├── New task                       internal.tasks.create
│       └── Task                           internal.tasks.detail
│           └── Assignees (tab)            internal.tasks.detail.assignees
├── Organisation
│   ├── Clients                            internal.clients.list
│   │   ├── New client                     internal.clients.create
│   │   └── Client                         internal.clients.detail
│   │       └── Members (tab)              internal.clients.detail.members
│   └── Departments                        internal.departments.list
│       ├── New department                 internal.departments.create
│       └── Department                     internal.departments.detail
│           └── Members (tab)              internal.departments.detail.members
├── People and access
│   ├── People                             internal.users.list
│   │   └── Person                         internal.users.detail
│   │       ├── Roles (tab)                internal.users.detail.roles
│   │       ├── Effective access (tab)     internal.users.detail.permissions
│   │       └── Overrides (tab)            internal.users.detail.overrides
│   ├── Invitations                        internal.invitations.list
│   │   └── New invitation                 internal.invitations.create
│   ├── Roles                              internal.roles.list
│   │   ├── New role                       internal.roles.create
│   │   └── Role                           internal.roles.detail
│   └── Permission catalogue               internal.permissions.catalogue
├── Administration
│   ├── Settings                           internal.settings.list
│   ├── Feature flags                      internal.settings.feature_flags
│   └── System information                 internal.settings.system_info
├── Audit
│   ├── Events                             internal.audit.list
│   │   └── Event                          internal.audit.detail
│   └── Chain verification                 internal.audit.verify
└── Account (shared)                       account.*
```

A nav group renders only if the actor's `/auth/me` capabilities contain at least one
permission used inside it. **This is cosmetic** — see §8.

### 6.2 Editing model

There are no separate edit screens. `PATCH` is an **edit mode of the detail screen**,
because the concurrency token (`version`) must come from the record the actor is
looking at, and a separate route invites a stale read. Create is a separate screen
because there is nothing to read first. Archive, suspend, delete, share and unshare are
confirmation dialogs raised from the detail screen, not screens.

### 6.3 Work — projects

| `screen_id` | Route | Permission | Endpoints | Regions | State notes |
| --- | --- | --- | --- | --- | --- |
| `internal.projects.list` | `/projects` | `projects.read` | `GET /api/v1/projects` | filter bar (`status` ∈ ACTIVE/PAUSED/COMPLETED/ARCHIVED, `department_id`), data table (code, name, status, manager, target date), create action | Sort allowlist is **`created_at`, `updated_at` only** — the table must not offer sortable headers for name or status. `empty` differs by filter presence |
| `internal.projects.create` | `/projects/new` | `projects.create` | `POST /api/v1/projects` | form: `code`, `name`, `description`, `manager_user_id`, `department_id`, `start_date`, `target_date`, `internal_note` | Send `Idempotency-Key`. `409 UNIQUE_VIOLATION` maps to the `code` field. `manager_user_id` picker needs `iam.users.read`; if the actor lacks it, the field is a raw identifier entry, not a picker |
| `internal.projects.detail` | `/projects/:id` | `projects.read` | `GET`, `PATCH`, `POST /api/v1/projects/{id}/archive` | detail header (name, code, status badge, `version`), summary fields, internal-note region, edit mode, archive dialog | `PATCH` and archive both take `version`. Status transitions are validated server-side (`can_transition_to`) — offer the transitions, let the backend refuse, render `409 INVARIANT_VIOLATION` |
| `internal.projects.detail.tasks` | `/projects/:id/tasks` | `projects.read` + `tasks.read` | `GET /api/v1/projects/{project_id}/tasks` | data table (title, status, priority, due date, `client_visible`) | A distinct endpoint from `/tasks?project_id=`; prefer this one, it is the scoped read. Show `client_visible` prominently — it is the external boundary |
| `internal.projects.detail.members` | `/projects/:id/team` | `projects.read`; mutate `projects.members.manage` | `GET`, `POST`, `DELETE /api/v1/projects/{id}/members/{user_id}` | member list (`display_name`, `email`, `role_in_project` ∈ MEMBER/LEAD, `added_at`), add form, remove confirmation | **Not paginated** — plain array. Membership drives `ASSIGNED` scope, so removal revokes access; say so in the confirmation |
| `internal.projects.detail.clients` | `/projects/:id/client-access` | `projects.read`; mutate `projects.clients.share` (**step-up**) | `GET`, `POST`, `DELETE /api/v1/projects/{id}/clients/{client_account_id}` | link list (`client_code`, `client_name`, `client_status`, `note`, `shared_by`, `shared_at`), share dialog, revoke dialog | The trust-boundary screen. Both mutations are dangerous and step-up gated. The dialog must state that sharing exposes the project but **not** its tasks — `client_visible` is per task and defaults to `false` |

### 6.4 Work — tasks

| `screen_id` | Route | Permission | Endpoints | Regions | State notes |
| --- | --- | --- | --- | --- | --- |
| `internal.tasks.list` | `/tasks` | `tasks.read` | `GET /api/v1/tasks` | filter bar (`project_id`, `status` ∈ TODO/IN_PROGRESS/BLOCKED/DONE/CANCELLED), data table | Sort allowlist `created_at`, `updated_at`. **There is no assignee filter** — see §10 |
| `internal.tasks.create` | `/tasks/new` | `tasks.create` | `POST /api/v1/tasks` | form: `project_id`, `title`, `description`, `priority` ∈ LOW/NORMAL/HIGH/URGENT, `due_date`, `internal_note` | `client_visible` is **not** creatable — it can only be set by `PATCH`. Do not render it here |
| `internal.tasks.detail` | `/tasks/:id` | `tasks.read` | `GET`, `PATCH`, `DELETE /api/v1/tasks/{id}?version=` | detail header with `version`, field region, `client_visible` toggle, internal note, cancel dialog | The `client_visible` toggle is an external-disclosure action: confirm it separately from the rest of the edit. `DELETE` is a **cancellation**, carries `version` as a query parameter, and returns `204` — word the dialog as "cancel", not "delete" |
| `internal.tasks.detail.assignees` | `/tasks/:id/assignees` | `tasks.read`; mutate `tasks.assign` | `GET`, `POST`, `DELETE /api/v1/tasks/{id}/assignees/{user_id}` | assignee list (`display_name`, `email`, `assigned_by`, `assigned_at`), add form, remove confirmation | Not paginated. Assignment grants `ASSIGNED` scope over the task |

### 6.5 Organisation

| `screen_id` | Route | Permission | Endpoints | Regions | State notes |
| --- | --- | --- | --- | --- | --- |
| `internal.clients.list` | `/clients` | `clients.read` | `GET /api/v1/clients` | data table (code, name, status ∈ ACTIVE/SUSPENDED/ARCHIVED, account manager) | Sort allowlist: **`created_at` only**. No server-side filters at all — do not render a filter bar |
| `internal.clients.create` | `/clients/new` | `clients.create` | `POST /api/v1/clients` | form: `code`, `name`, `description`, `account_manager_user_id` | `Idempotency-Key` |
| `internal.clients.detail` | `/clients/:id` | `clients.read` | `GET`, `PATCH`, `POST /api/v1/clients/{id}/archive` | detail header with `version`, fields, archive dialog | Archiving a client account removes its members' visibility of every shared project on the next query — state that in the dialog |
| `internal.clients.detail.members` | `/clients/:id/members` | `clients.read`; mutate `clients.members.manage` | `GET`, `POST`, `POST .../{user_id}/activate`, `DELETE .../{user_id}` | member list (`display_name`, `email`, `status` ∈ PENDING/ACTIVE/SUSPENDED/REMOVED, `grants_visibility`, `activated_at`), add form, activate action, remove action | Paginated (sort allowlist `created_at`). `grants_visibility` is the field that actually turns a client user's access on — surface it as the primary column. Activation is the moment a self-registered `PENDING` client can see anything |
| `internal.departments.list` | `/departments` | `departments.read` | `GET /api/v1/departments` | data table (code, name, status ∈ ACTIVE/ARCHIVED, lead) | Sort allowlist: `created_at` only |
| `internal.departments.create` | `/departments/new` | `departments.create` | `POST /api/v1/departments` | form: `code`, `name`, `description`, `lead_user_id` | — |
| `internal.departments.detail` | `/departments/:id` | `departments.read` | `GET`, `PATCH`, `POST /api/v1/departments/{id}/archive` | detail header with `version`, fields, archive dialog | — |
| `internal.departments.detail.members` | `/departments/:id/members` | `departments.read`; mutate `departments.members.manage` | `GET`, `POST`, `DELETE .../{user_id}` | member list (`display_name`, `email`, `role_in_department` ∈ MEMBER/LEAD, `joined_at`), add/remove | Paginated, sort allowlist **`joined_at`**. Department membership drives `DEPARTMENT` scope, so this screen changes what people can see across the whole workspace — say so |

### 6.6 People and access

This group is the escalation surface. Every mutation in it is step-up gated except
those on `internal.users.list`/`detail`.

| `screen_id` | Route | Permission | Endpoints | Regions | State notes |
| --- | --- | --- | --- | --- | --- |
| `internal.users.list` | `/people` | `iam.users.read` | `GET /api/v1/users` | filter bar (`principal_type`, `status` ∈ PENDING/ACTIVE/SUSPENDED/ARCHIVED, `search`), data table (display name, email, principal type, status, MFA enrolled) | Sort allowlist `created_at`, `updated_at`. `search` is a server-side parameter — do not filter client-side over a page |
| `internal.users.detail` | `/people/:id` | `iam.users.read` | `GET`, `PATCH`, `POST .../suspend`, `POST .../reactivate`, `POST .../archive` | detail header with `version`, identity fields, status actions, security block (`mfa_required`, `mfa_enrolled`, `security_version`) | Each status action takes `version` and an optional `reason`. There is **no delete** — never render one (`07-api-contract.md` §12). Suspend requires `iam.users.suspend`, archive `iam.users.archive`, edit `iam.users.update`; gate each button independently. Targeting ROOT returns `403 ROOT_PROTECTED` — render that as an explicit, non-retryable refusal |
| `internal.users.detail.roles` | `/people/:id/roles` | `iam.roles.read`; mutate `iam.roles.assign` (**step-up**, dangerous) | `GET /api/v1/users/{id}/roles`, `POST`, `DELETE .../roles/{role_id}` | role list (`code`, `name`, `is_system`, `allowed_principal_type`, `granted_by`, `granted_at`), assign form, unassign confirmation | Not paginated. `403 DELEGATION_DENIED` is the expected failure when the actor cannot grant what a role contains — render it as an explanation, not a bug |
| `internal.users.detail.permissions` | `/people/:id/access` | `iam.permissions.read` | `GET /api/v1/users/{id}/permissions` | effective-capability list (`permission_code` × `scopes[]`), grouped by module; subject header (`principal_type`, `is_root`) | Read-only, not paginated. This is the answer to "what can they actually do" — the union after roles, overrides and denials. For a CLIENT subject it can contain only the two `client.portal.*` codes |
| `internal.users.detail.overrides` | `/people/:id/overrides` | `iam.permissions.delegate` (**step-up**, dangerous) | `POST /api/v1/users/{id}/permission-overrides`, `DELETE .../{override_id}` | grant/deny form (`permission_code`, `effect` ∈ ALLOW/DENY, `scope`, `resource_type`+`resource_id` for RESOURCE, `expires_at`, `reason`), revoke action | **Contract gap, see §11**: no listing endpoint is declared, so this screen cannot show existing overrides. Until one is declared, render the resulting state via `internal.users.detail.permissions` and treat this screen as write-only. The form must state that DENY beats ALLOW absolutely, and that self-targeted overrides are refused outright |
| `internal.invitations.list` | `/invitations` | `iam.users.invite` | `GET /api/v1/invitations`, `DELETE /api/v1/invitations/{id}` | filter bar (`status` ∈ PENDING/ACCEPTED/REVOKED/EXPIRED), data table (email, display name, principal type, status, expires at), revoke action | Sort allowlist `created_at`, `expires_at`. Revoke returns the updated `InvitationResponse` |
| `internal.invitations.create` | `/invitations/new` | `iam.users.invite` | `POST /api/v1/invitations`, `GET /api/v1/roles`, `GET /api/v1/clients` | form: `email`, `display_name`, `principal_type`, `role_ids[]`, `department_id`, `client_account_id` | The role picker must be filtered to roles whose `allowed_principal_type` matches the chosen `principal_type`; the backend enforces this too. `client_account_id` is only meaningful for `CLIENT`. Roles are re-validated against the inviter's delegation authority *at acceptance*, so a `DELEGATION_DENIED` can surface here or never |
| `internal.roles.list` | `/roles` | `iam.roles.read` | `GET /api/v1/roles` | data table (code, name, `is_system`, `allowed_principal_type`) | Sort allowlist `code`, `name`, `created_at` — the widest in the system |
| `internal.roles.create` | `/roles/new` | `iam.roles.create` (**step-up**, dangerous) | `POST /api/v1/roles`, `GET /api/v1/permissions` | form: `code`, `name`, `description`, `allowed_principal_type`, grant builder (`permission_code` × `scope`) | The grant builder must read the catalogue, mark `is_dangerous` entries, and hide `max_principal_type = INTERNAL` permissions when `allowed_principal_type = CLIENT`. `403 DELEGATION_DENIED` names the offending permission — map it to that row |
| `internal.roles.detail` | `/roles/:id` | `iam.roles.read`; mutate `iam.roles.update` / `iam.roles.delete` (**step-up**, dangerous) | `GET`, `PATCH`, `DELETE /api/v1/roles/{id}` | detail header with `version`, grant list, edit mode, delete dialog | `is_system = true` roles cannot be modified — disable the affordances and explain, rather than letting the request fail. `PATCH` replaces the whole `permissions` array when present; the edit form must submit the full intended set, never a delta |
| `internal.permissions.catalogue` | `/permissions` | `iam.permissions.read` | `GET /api/v1/permissions` | catalogue list grouped by `module`, showing `code`, `max_principal_type`, `is_dangerous` | Not paginated, returns `{ items: [...] }`. This is reference material and the source for every permission picker in the app |

### 6.7 Administration

| `screen_id` | Route | Permission | Endpoints | Regions | State notes |
| --- | --- | --- | --- | --- | --- |
| `internal.settings.list` | `/admin/settings` | `settings.read`; mutate `settings.features.write` | `GET /api/v1/settings`, `PUT /api/v1/settings/{key}` | setting list (`key`, `value`, `value_type`, `description`, `is_security_sensitive`, `version`, `updated_by`, `updated_at`), per-row edit | Not paginated. Each `PUT` carries `version` — concurrency is per setting, not per screen. `is_security_sensitive` rows are visually separated and confirmed individually; some are additionally step-up gated server-side |
| `internal.settings.feature_flags` | `/admin/feature-flags` | `settings.read`; mutate `settings.features.write` | `GET /api/v1/feature-flags`, `PUT /api/v1/feature-flags/{key}` | flag list (`key`, `enabled`, `description`, `is_security_sensitive`, `version`), toggle | Not paginated. Toggling sends `{ enabled, version }`. A security-sensitive flag may return `403 STEP_UP_REQUIRED` — the toggle must revert optimistic state and re-issue after step-up |
| `internal.settings.system_info` | `/admin/system` | none (authenticated) | `GET /api/v1/system/info` | `environment`, `initialized`, `enabled_features[]` | The only permission-free internal read. Useful as a health surface inside the app |

### 6.8 Audit

| `screen_id` | Route | Permission | Endpoints | Regions | State notes |
| --- | --- | --- | --- | --- | --- |
| `internal.audit.list` | `/audit` | `audit.read` | `GET /api/v1/audit/events` | filter bar (`actor_user_id`, `action_code`, `target_type`, `target_id`, `outcome` ∈ SUCCESS/DENIED/FAILURE, `occurred_from`, `occurred_to`), audit timeline / data table (`seq`, `occurred_at`, actor, `action_code`, target, `outcome`) | Sort allowlist: **`occurred_at` only**, and the default direction is descending. The list is append-only; there is no create, edit or delete affordance anywhere on this screen, ever |
| `internal.audit.detail` | `/audit/:id` | `audit.read` | `GET /api/v1/audit/events/{id}` | header (`seq`, `occurred_at`, `outcome`), actor block (`actor_user_id`, `actor_principal_type`, `actor_session_id`), target block, request block (`request_id`, `source_ip_hint`), raw `metadata` viewer | `metadata` is arbitrary JSON — render it as inspectable data, not as interpreted prose |
| `internal.audit.verify` | `/audit/verify` | `audit.read` (**step-up**) | `GET /api/v1/audit/verify?from_seq=&limit=` | run form, result panel (`outcome`, `entries_checked`, `checked_from_seq`, `checked_to_seq`, `reached_chain_head`, `first_divergent_seq`, `diagnostics`) | Expensive and step-up gated despite being a `GET`. Long-running: show progress, never auto-run on navigation. A divergence result is the single loudest state in the application |

---

## 7. Client portal

Four screens plus the shared public/auth/account surface. Full rules in
`05-client-portal-boundary.md`.

```
client
├── Projects                               client.projects.list
│   └── Project                            client.projects.detail
│       ├── Tasks (tab)                    client.projects.detail.tasks
│       └── Task                           client.tasks.detail
└── Account (shared)                       account.*
```

| `screen_id` | Route | Permission | Endpoints | Regions | State notes |
| --- | --- | --- | --- | --- | --- |
| `client.projects.list` | `/projects` | `client.portal.projects.read` | `GET /api/v1/client-portal/projects` | data table (code, name, status, target date, updated at) | Query accepts **`cursor` and `limit` only** — no `sort`, no `direction`, no filters. Render no sort controls. `empty` means nothing is shared yet, which is a normal state, not an error |
| `client.projects.detail` | `/projects/:id` | `client.portal.projects.read` | `GET /api/v1/client-portal/projects/{id}` | header (name, code, status badge), dates (`start_date`, `target_date`, `completed_at`, `updated_at`), description | `ClientProjectResponse` has **no** `version`, `manager_user_id`, `department_id`, `internal_note` or `created_by`. There is no edit mode, because there is no write endpoint |
| `client.projects.detail.tasks` | `/projects/:id/tasks` | `client.portal.tasks.read` | `GET /api/v1/client-portal/projects/{id}/tasks` | data table (title, status, priority, due date) | Only tasks with `client_visible = true` are ever returned. An empty list is normal and must not imply the project has no work |
| `client.tasks.detail` | `/tasks/:id` | `client.portal.tasks.read` | `GET /api/v1/client-portal/tasks/{id}` | header (title, status badge, priority), dates, description | `ClientTaskResponse` has no `client_visible`, `internal_note`, `version`, `created_by` |

---

## 8. Capabilities drive the menu — and nothing else

`GET /api/v1/auth/me` returns `capabilities: [{ permission, scopes[] }]`. Both
applications use it to decide which nav groups, screens and action affordances to
render.

> **This is cosmetic.** The backend re-derives every decision on every request and does
> not consult, trust or even receive the client's belief about capabilities. Hiding a
> button is a courtesy to the user; it is not a control. A screen that is reachable by
> typing its URL must still behave correctly — request, receive `403`, render the
> `forbidden` state.

`security_version` increments on any privilege change. Treat a changed value as the
signal to re-fetch capabilities and re-render the menu. Details in
`04-navigation-and-state.md` §6.

---

## 9. Cross-cutting structural rules

1. **No page numbers.** Every list is keyset-paginated and returns `next_cursor` /
   `has_more`. There is no total count, no page count, no "jump to last". See
   `03-widget-catalogue.md` §1.
2. **Sort controls exist only for allowlisted fields.** Per endpoint:
   projects `created_at|updated_at`, tasks `created_at|updated_at`, users
   `created_at|updated_at`, invitations `created_at|expires_at`, clients `created_at`,
   client members `created_at`, departments `created_at`, department members
   `joined_at`, roles `code|name|created_at`, audit `occurred_at`. Anything else is
   `400` and the rejected value is not echoed back.
3. **Every mutation of a versioned resource carries `version`** read from the same
   fetch that populated the form.
4. **Create endpoints that could duplicate something consequential carry
   `Idempotency-Key`**: invitations, users, projects, clients.
5. **Destructive and boundary-crossing actions are dialogs, not inline toggles**:
   archive, suspend, revoke, unshare, unassign, role assignment, override creation,
   MFA disable, recovery regeneration, session revocation, `client_visible`.
6. **`404` handling is per application.** The workspace may say the object is gone.
   The portal may not say anything that distinguishes "absent" from "not yours".
7. **The internal note is internal.** `internal_note` appears on `ProjectResponse` and
   `TaskResponse` and is physically absent from the client types. No shared component
   may render it, so no shared component may accept it.

---

## 10. Future — not yet backed by any API

These are real product needs with **no endpoint**. Nothing in this blueprint depends on
them, and no placeholder screen, disabled menu entry or "coming soon" route should be
built for them. Building the shell first is how a UI ends up shipping a nav item that
404s for two years.

| Area | Why it cannot be specified | Reference |
| --- | --- | --- |
| **Files and attachments** | No storage layer, no upload endpoint. The absence is deliberate and removes the unrestricted-upload class entirely | `12-future-storage.md`; `07-api-contract.md` §12 |
| **Chat, comments, presence, live updates** | No WebSocket transport, no message resource. Subscription authorisation and revocation-on-privilege-change are unsolved | `11-future-realtime.md` |
| **CRM (leads, pipeline, opportunities, contacts)** | The `clients` module models an *account and its memberships*, not a sales pipeline. No such resource exists | — |
| **Finance (invoices, quotes, time tracking, budgets)** | No resource, no money type, no rounding policy, no currency handling | — |
| **Approvals and workflow** | No approval resource and no state machine beyond the fixed project/task status transitions | — |
| **AI assistance and MCP surfaces** | No AI endpoint exists. When one arrives the agent will be an ordinary principal with permissions, and its screens must attribute both the human and the agent | `10-future-ai-mcp-security.md` |
| **Notifications and an inbox** | The outbox drives email; there is no in-app notification resource to read | — |
| **Dashboards, reporting, charts** | No aggregate endpoint exists anywhere. Every list returns rows, not counts — not even a total, because pagination is keyset. A dashboard would have to be assembled by fetching pages, which is exactly the expensive-query pattern the API was designed to prevent | `07-api-contract.md` §3 |
| **"My tasks"** | `GET /api/v1/tasks` filters on `project_id` and `status` only. There is no `assignee_id` parameter. For an `ASSIGNED`-scoped employee the unfiltered list *is* their tasks, but for anyone broader it is not, so a screen labelled "my tasks" would be wrong for exactly the people most likely to open it | see §11 |
| **Global search** | `GET /api/v1/users` has a `search` parameter; nothing else does. There is no cross-resource search endpoint | — |
| **User creation from the workspace** | `iam.users.create` exists in the catalogue but **no route exercises it**. Users arrive only through invitation, registration or bootstrap. Do not build a create-user form | `routes.rs` |
| **Session administration for other users** | `iam.sessions.read` and `iam.sessions.revoke` exist in the catalogue but no route uses them. `GET /api/v1/auth/sessions` is self-only | `routes.rs` |

---

## 11. Contract gaps found while writing this

Recorded so they are decided rather than worked around silently.

1. **`GET /api/v1/users/{id}/permission-overrides` is implemented but undeclared.**
   The handler `list_overrides` is mounted in
   `backend/src/modules/authorization/routes.rs`, but the endpoint appears in neither
   `ROUTE_TABLE` nor `api/openapi.yaml`. Until it is declared — with an explicit
   permission and, given what it discloses, probably `iam.permissions.read` —
   `internal.users.detail.overrides` cannot list existing overrides, and this
   blueprint specifies it as write-only. Either declare it or remove it; an
   undocumented route is exactly what the drift test exists to prevent.
2. **`iam.users.create`, `iam.sessions.read` and `iam.sessions.revoke` are catalogued
   but unrouted.** No screen can use them. Either routes follow or the catalogue
   entries should be justified in a comment.
3. **`07-api-contract.md` §3 shows `sort=name` on `/api/v1/projects`.** The real
   allowlist in `projects/repo.rs` is `created_at`, `updated_at`. The example is
   misleading for anyone building the filter bar from the document rather than the
   code. The code is authoritative here and this blueprint follows it.
