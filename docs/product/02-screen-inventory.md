# 02 — Screen Inventory

One flat row per screen. This is the checklist a builder works through: when every row
is ticked, the application is structurally complete against the API as it exists today.

Companion documents: `01-application-structure.md` (why, and what each screen contains),
`03-widget-catalogue.md` (the widget names in the *Widgets* column),
`04-navigation-and-state.md` (routing and session rules),
`05-client-portal-boundary.md` (the CLIENT rules).

**Reading the columns**

- **App** — `public` (unauthenticated, both bundles), `shared` (compiled into both
  bundles, authenticated, no permission required), `internal`, `client`.
- **Route** — the URL pattern inside its own application. `public` and `shared` routes
  are identical in both bundles.
- **Permission** — what the actor must effectively hold for the screen's *primary read*
  to succeed. Mutation permissions are listed where they differ; each mutation
  affordance is gated independently. `—` means no permission is required.
- **Primary endpoint** — the read that populates the screen on entry. Secondary and
  mutation endpoints are in `01-application-structure.md`.
- **Widgets** — identifiers from `03-widget-catalogue.md`.
- ⚡ marks a screen containing at least one **step-up** (`403 STEP_UP_REQUIRED`)
  operation.

---

## Public — unauthenticated (6)

| `screen_id` | Title | App | Route | Permission | Primary endpoint | Widgets | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `public.bootstrap` | Initialise system | public | `/bootstrap` | — | `GET /api/v1/bootstrap/status` | `edit-form`, `error-state` | One-time. `409 SYSTEM_ALREADY_INITIALIZED` is permanent; redirect to login |
| `public.login` | Sign in | public | `/login` | — | `POST /api/v1/auth/login` | `edit-form`, `error-state` | `mfa_required = true` routes to the MFA surface, never to the app |
| `public.password_reset.request` | Reset password | public | `/password-reset` | — | `POST /api/v1/auth/password-reset/request` | `edit-form`, `acknowledgement` | Always `202`, always the same body — no existence signal |
| `public.password_reset.confirm` | Choose a new password | public | `/password-reset/confirm` | — | `POST /api/v1/auth/password-reset/confirm` | `edit-form`, `error-state` | Token in the query string; success revokes all sessions |
| `public.registration` | Register | public | `/register` | — | `GET /api/v1/registration/config` | `edit-form`, `empty-state`, `acknowledgement` | Gated by `registration_available`; result is a `PENDING` CLIENT that can see nothing |
| `public.invitation.accept` | Accept invitation | public | `/invitations/accept` | — | `POST /api/v1/invitations/accept` | `edit-form`, `error-state` | Response carries `mfa_enrolment_required` |

## Authentication — MFA-pending sessions (3)

| `screen_id` | Title | App | Route | Permission | Primary endpoint | Widgets | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `auth.mfa.enrol` | Set up authenticator | shared | `/auth/mfa/enrol` | — | `GET /api/v1/auth/me` | `edit-form`, `one-time-secret`, `error-state` | Entered on `next_action = MFA_ENROLLMENT_REQUIRED`. Secret and recovery codes are shown once |
| `auth.mfa.verify` | Verify code | shared | `/auth/mfa/verify` | — | `POST /api/v1/auth/mfa/verify` | `edit-form`, `error-state` | Entered on `next_action = MFA_VERIFICATION_REQUIRED`; surfaces `recovery_codes_remaining` |
| `auth.mfa.recovery` | Use a recovery code | shared | `/auth/mfa/recovery` | — | `POST /api/v1/auth/mfa/recovery/verify` | `edit-form`, `error-state` | Single-use codes; prompt to regenerate afterwards |

## Account — self-service, both applications (4)

| `screen_id` | Title | App | Route | Permission | Primary endpoint | Widgets | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `account.profile` | My profile | shared | `/account` | — | `GET /api/v1/auth/me` | `key-value-list`, `status-badge` | Read-only; no self-update endpoint exists |
| `account.security.password` | Change password | shared | `/account/password` | — | `POST /api/v1/auth/password/change` | `edit-form`, `confirm-dialog` | Revokes every other session on success |
| `account.security.mfa` ⚡ | Two-factor authentication | shared | `/account/security` | — | `GET /api/v1/auth/me` | `gated-action`, `confirm-dialog`, `one-time-secret`, `step-up-prompt` | Regenerate and disable are step-up gated and destructive |
| `account.sessions` | Active sessions | shared | `/account/sessions` | — | `GET /api/v1/auth/sessions` | `session-list`, `confirm-dialog` | Unpaginated; revoking `current: true` ends the actor's own session |

## Internal workspace — home (1)

| `screen_id` | Title | App | Route | Permission | Primary endpoint | Widgets | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `internal.home` | Home | internal | `/` | — | `GET /api/v1/auth/me` | `key-value-list`, `gated-action` | A launcher, not a dashboard. No aggregate endpoint exists to build one from |

## Internal workspace — work (10)

| `screen_id` | Title | App | Route | Permission | Primary endpoint | Widgets | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `internal.projects.list` | Projects | internal | `/projects` | `projects.read` | `GET /api/v1/projects` | `filter-bar`, `data-table`, `status-badge`, `empty-state`, `gated-action` | Filters `status`, `department_id`; sort `created_at\|updated_at` |
| `internal.projects.create` | New project | internal | `/projects/new` | `projects.create` | `POST /api/v1/projects` | `edit-form` | `Idempotency-Key`; `409 UNIQUE_VIOLATION` maps to `code` |
| `internal.projects.detail` | Project | internal | `/projects/:id` | `projects.read` | `GET /api/v1/projects/{id}` | `detail-header`, `key-value-list`, `edit-form`, `confirm-dialog`, `status-badge` | Edit is a mode of this screen; archive is a dialog |
| `internal.projects.detail.tasks` | Project tasks | internal | `/projects/:id/tasks` | `projects.read` + `tasks.read` | `GET /api/v1/projects/{project_id}/tasks` | `data-table`, `status-badge`, `empty-state` | Shows `client_visible` as a first-class column |
| `internal.projects.detail.members` | Project team | internal | `/projects/:id/team` | `projects.read` / `projects.members.manage` | `GET /api/v1/projects/{id}/members` | `member-list`, `confirm-dialog` | Unpaginated; membership drives `ASSIGNED` scope |
| `internal.projects.detail.clients` ⚡ | Client access | internal | `/projects/:id/client-access` | `projects.read` / `projects.clients.share` | `GET /api/v1/projects/{id}/clients` | `member-list`, `confirm-dialog`, `step-up-prompt`, `status-badge` | The external trust boundary. Sharing a project does not share its tasks |
| `internal.tasks.list` | Tasks | internal | `/tasks` | `tasks.read` | `GET /api/v1/tasks` | `filter-bar`, `data-table`, `status-badge`, `empty-state` | Filters `project_id`, `status`; no assignee filter exists |
| `internal.tasks.create` | New task | internal | `/tasks/new` | `tasks.create` | `POST /api/v1/tasks` | `edit-form` | `client_visible` is not settable at creation |
| `internal.tasks.detail` | Task | internal | `/tasks/:id` | `tasks.read` | `GET /api/v1/tasks/{id}` | `detail-header`, `key-value-list`, `edit-form`, `confirm-dialog`, `status-badge` | `DELETE` is a cancellation and takes `?version=` |
| `internal.tasks.detail.assignees` | Assignees | internal | `/tasks/:id/assignees` | `tasks.read` / `tasks.assign` | `GET /api/v1/tasks/{id}/assignees` | `member-list`, `confirm-dialog` | Unpaginated; assignment grants `ASSIGNED` scope |

## Internal workspace — organisation (8)

| `screen_id` | Title | App | Route | Permission | Primary endpoint | Widgets | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `internal.clients.list` | Client accounts | internal | `/clients` | `clients.read` | `GET /api/v1/clients` | `data-table`, `status-badge`, `empty-state`, `gated-action` | No server-side filters; sort `created_at` only |
| `internal.clients.create` | New client account | internal | `/clients/new` | `clients.create` | `POST /api/v1/clients` | `edit-form` | `Idempotency-Key` |
| `internal.clients.detail` | Client account | internal | `/clients/:id` | `clients.read` | `GET /api/v1/clients/{id}` | `detail-header`, `key-value-list`, `edit-form`, `confirm-dialog`, `status-badge` | Archiving removes members' visibility of shared projects immediately |
| `internal.clients.detail.members` | Client members | internal | `/clients/:id/members` | `clients.read` / `clients.members.manage` | `GET /api/v1/clients/{id}/members` | `member-list`, `data-table`, `status-badge`, `confirm-dialog` | Paginated (`created_at`). `grants_visibility` is the primary column |
| `internal.departments.list` | Departments | internal | `/departments` | `departments.read` | `GET /api/v1/departments` | `data-table`, `status-badge`, `empty-state`, `gated-action` | Sort `created_at` only |
| `internal.departments.create` | New department | internal | `/departments/new` | `departments.create` | `POST /api/v1/departments` | `edit-form` | — |
| `internal.departments.detail` | Department | internal | `/departments/:id` | `departments.read` | `GET /api/v1/departments/{id}` | `detail-header`, `key-value-list`, `edit-form`, `confirm-dialog`, `status-badge` | — |
| `internal.departments.detail.members` | Department members | internal | `/departments/:id/members` | `departments.read` / `departments.members.manage` | `GET /api/v1/departments/{id}/members` | `member-list`, `confirm-dialog` | Paginated (`joined_at`). Membership drives `DEPARTMENT` scope workspace-wide |

## Internal workspace — people and access (11)

| `screen_id` | Title | App | Route | Permission | Primary endpoint | Widgets | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `internal.users.list` | People | internal | `/people` | `iam.users.read` | `GET /api/v1/users` | `filter-bar`, `data-table`, `status-badge`, `empty-state` | Filters `principal_type`, `status`, `search`; sort `created_at\|updated_at` |
| `internal.users.detail` | Person | internal | `/people/:id` | `iam.users.read` | `GET /api/v1/users/{id}` | `detail-header`, `key-value-list`, `edit-form`, `confirm-dialog`, `gated-action`, `status-badge` | Suspend / reactivate / archive each carry `version`. No delete exists. ROOT target → `403 ROOT_PROTECTED` |
| `internal.users.detail.roles` ⚡ | Roles | internal | `/people/:id/roles` | `iam.roles.read` / `iam.roles.assign` | `GET /api/v1/users/{id}/roles` | `member-list`, `confirm-dialog`, `step-up-prompt` | Unpaginated. `403 DELEGATION_DENIED` is an expected, explainable outcome |
| `internal.users.detail.permissions` | Effective access | internal | `/people/:id/access` | `iam.permissions.read` | `GET /api/v1/users/{id}/permissions` | `capability-list` | Read-only union after roles, overrides and denials |
| `internal.users.detail.overrides` ⚡ | Overrides | internal | `/people/:id/overrides` | `iam.permissions.delegate` | `POST /api/v1/users/{id}/permission-overrides` | `edit-form`, `confirm-dialog`, `step-up-prompt` | **Write-only** — no declared list endpoint (see `01` §11). Self-targeting is refused outright |
| `internal.invitations.list` | Invitations | internal | `/invitations` | `iam.users.invite` | `GET /api/v1/invitations` | `filter-bar`, `data-table`, `status-badge`, `confirm-dialog` | Filter `status`; sort `created_at\|expires_at` |
| `internal.invitations.create` | New invitation | internal | `/invitations/new` | `iam.users.invite` | `POST /api/v1/invitations` | `edit-form` | Role picker filtered by `allowed_principal_type`; `Idempotency-Key` |
| `internal.roles.list` | Roles | internal | `/roles` | `iam.roles.read` | `GET /api/v1/roles` | `data-table`, `status-badge`, `gated-action` | Sort `code\|name\|created_at` — the widest allowlist in the system |
| `internal.roles.create` ⚡ | New role | internal | `/roles/new` | `iam.roles.create` | `POST /api/v1/roles` | `edit-form`, `grant-builder`, `step-up-prompt` | `DELEGATION_DENIED` names the offending permission; map it to that grant row |
| `internal.roles.detail` ⚡ | Role | internal | `/roles/:id` | `iam.roles.read` / `iam.roles.update`, `iam.roles.delete` | `GET /api/v1/roles/{id}` | `detail-header`, `grant-builder`, `edit-form`, `confirm-dialog`, `step-up-prompt` | `is_system` roles are immutable — disable and explain. `PATCH` replaces the whole grant set |
| `internal.permissions.catalogue` | Permission catalogue | internal | `/permissions` | `iam.permissions.read` | `GET /api/v1/permissions` | `key-value-list`, `status-badge` | Unpaginated reference data; feeds every permission picker |

## Internal workspace — administration (3)

| `screen_id` | Title | App | Route | Permission | Primary endpoint | Widgets | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `internal.settings.list` ⚡ | Settings | internal | `/admin/settings` | `settings.read` / `settings.features.write` | `GET /api/v1/settings` | `toggle-row`, `edit-form`, `confirm-dialog`, `step-up-prompt` | Unpaginated; `version` is per setting. Security-sensitive rows confirmed individually |
| `internal.settings.feature_flags` ⚡ | Feature flags | internal | `/admin/feature-flags` | `settings.read` / `settings.features.write` | `GET /api/v1/feature-flags` | `toggle-row`, `step-up-prompt` | `PUT { enabled, version }`. A security-sensitive flag may demand step-up |
| `internal.settings.system_info` | System information | internal | `/admin/system` | — | `GET /api/v1/system/info` | `key-value-list` | The only permission-free internal read |

## Internal workspace — audit (3)

| `screen_id` | Title | App | Route | Permission | Primary endpoint | Widgets | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `internal.audit.list` | Audit events | internal | `/audit` | `audit.read` | `GET /api/v1/audit/events` | `filter-bar`, `audit-timeline`, `status-badge`, `empty-state` | Seven filters; sort `occurred_at` only, default descending. No mutation affordance, ever |
| `internal.audit.detail` | Audit event | internal | `/audit/:id` | `audit.read` | `GET /api/v1/audit/events/{id}` | `key-value-list`, `json-inspector` | `metadata` is rendered as inspectable data, never as interpreted prose |
| `internal.audit.verify` ⚡ | Chain verification | internal | `/audit/verify` | `audit.read` | `GET /api/v1/audit/verify` | `edit-form`, `key-value-list`, `error-state`, `step-up-prompt` | Expensive `GET`, step-up gated, never auto-run. Divergence is the loudest state in the app |

## Client portal (4)

| `screen_id` | Title | App | Route | Permission | Primary endpoint | Widgets | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `client.projects.list` | Projects | client | `/projects` | `client.portal.projects.read` | `GET /api/v1/client-portal/projects` | `data-table`, `status-badge`, `empty-state` | Query is `cursor` + `limit` **only** — no sort controls, no filters |
| `client.projects.detail` | Project | client | `/projects/:id` | `client.portal.projects.read` | `GET /api/v1/client-portal/projects/{id}` | `key-value-list`, `status-badge`, `error-state` | No `version`, no edit mode, no write endpoint |
| `client.projects.detail.tasks` | Tasks | client | `/projects/:id/tasks` | `client.portal.tasks.read` | `GET /api/v1/client-portal/projects/{id}/tasks` | `data-table`, `status-badge`, `empty-state` | Only `client_visible = true` tasks are returned; empty is normal |
| `client.tasks.detail` | Task | client | `/tasks/:id` | `client.portal.tasks.read` | `GET /api/v1/client-portal/tasks/{id}` | `key-value-list`, `status-badge`, `error-state` | `404` means "not visible" — never phrase it as a permission refusal |

---

## Count

| Group | Screens |
| --- | --- |
| Public (unauthenticated) | 6 |
| Authentication (MFA-pending) | 3 |
| Account (shared, both apps) | 4 |
| Internal — home | 1 |
| Internal — work | 10 |
| Internal — organisation | 8 |
| Internal — people and access | 11 |
| Internal — administration | 3 |
| Internal — audit | 3 |
| Client portal | 4 |
| **Total** | **53** |

Per build target, counting shared screens in both:

| Build target | Screens shipped |
| --- | --- |
| Internal workspace | 6 public + 3 auth + 4 account + 36 internal = **49** |
| Client portal | 6 public + 3 auth + 4 account + 4 client = **17** |

Of the 53, **9 contain at least one step-up-gated operation** (⚡):
`account.security.mfa`, `internal.projects.detail.clients`,
`internal.users.detail.roles`, `internal.users.detail.overrides`,
`internal.roles.create`, `internal.roles.detail`, `internal.settings.list`,
`internal.settings.feature_flags`, `internal.audit.verify`. The `step-up-prompt` widget
itself is shell-level and can be raised from any of them without navigation.

**Endpoint coverage.** Of the 93 entries in `ROUTE_TABLE`, three are operator-only and
belong to no screen (`GET /health/live`, `GET /health/ready`, `GET /metrics`). Every
remaining route is reachable from at least one screen above. No screen calls a route
that is not in `ROUTE_TABLE`.

---

## Endpoint coverage map

Read this in the other direction — from the API to the screens — to confirm nothing is
stranded. Method groups are collapsed where one screen owns the whole resource.

| Endpoint group | Owning screens |
| --- | --- |
| `/health/*`, `/metrics` | **none** — operator surface, not called by either application |
| `/api/v1/bootstrap/*` | `public.bootstrap` |
| `POST /api/v1/auth/login` | `public.login` |
| `POST /api/v1/auth/refresh` | transport layer, not a screen — see `04` §5 |
| `POST /api/v1/auth/logout` | shell, from any screen; also reachable in MFA-pending mode |
| `POST /api/v1/auth/logout-all` | `account.sessions` |
| `GET /api/v1/auth/me` | shell; `account.profile`; `internal.home`; both MFA screens (reduced projection) |
| `GET /api/v1/auth/sessions`, `DELETE .../{id}` | `account.sessions` |
| `POST /api/v1/auth/password/change` | `account.security.password` |
| `POST /api/v1/auth/password-reset/request` | `public.password_reset.request` |
| `POST /api/v1/auth/password-reset/confirm` | `public.password_reset.confirm` |
| `POST /api/v1/auth/mfa/totp/setup`, `/activate` | `auth.mfa.enrol`; `account.security.mfa` |
| `POST /api/v1/auth/mfa/verify` | `auth.mfa.verify`; `step-up-prompt` from anywhere |
| `POST /api/v1/auth/mfa/recovery/verify` | `auth.mfa.recovery`; `step-up-prompt` fallback |
| `POST /api/v1/auth/mfa/recovery/regenerate` ⚡ | `account.security.mfa` |
| `POST /api/v1/auth/mfa/disable` ⚡ | `account.security.mfa` |
| `GET /api/v1/registration/config`, `POST /api/v1/registration` | `public.registration` |
| `POST /api/v1/invitations/accept` | `public.invitation.accept` |
| `GET /api/v1/users`, `GET|PATCH /users/{id}`, `suspend`, `reactivate`, `archive` | `internal.users.list`, `internal.users.detail` |
| `GET|POST /api/v1/invitations`, `DELETE /invitations/{id}` | `internal.invitations.list`, `internal.invitations.create` |
| `GET /api/v1/permissions` | `internal.permissions.catalogue`; `grant-builder` on both role screens |
| `GET /api/v1/roles`, `POST` ⚡, `GET|PATCH|DELETE /roles/{id}` ⚡ | `internal.roles.list`, `internal.roles.create`, `internal.roles.detail`; also read by `internal.invitations.create` |
| `GET|POST /users/{id}/roles`, `DELETE /users/{id}/roles/{role_id}` ⚡ | `internal.users.detail.roles` |
| `GET /users/{id}/permissions` | `internal.users.detail.permissions` |
| `POST|DELETE /users/{id}/permission-overrides` ⚡ | `internal.users.detail.overrides` |
| `/api/v1/departments*` | the four `internal.departments.*` screens |
| `/api/v1/clients*` | the four `internal.clients.*` screens; also read by `internal.invitations.create` |
| `GET|POST /api/v1/projects`, `GET|PATCH /projects/{id}`, `archive` | `internal.projects.list`, `.create`, `.detail` |
| `/projects/{id}/members*` | `internal.projects.detail.members` |
| `/projects/{id}/clients*` ⚡ | `internal.projects.detail.clients` |
| `GET /projects/{project_id}/tasks` | `internal.projects.detail.tasks` |
| `/api/v1/tasks*` | the four `internal.tasks.*` screens |
| `/api/v1/client-portal/*` | the four `client.*` screens — **and nothing else, ever** |
| `GET /api/v1/settings`, `PUT /settings/{key}` | `internal.settings.list` |
| `GET /api/v1/feature-flags`, `PUT /feature-flags/{key}` | `internal.settings.feature_flags` |
| `GET /api/v1/system/info` | `internal.settings.system_info` |
| `GET /api/v1/audit/events`, `/events/{id}` | `internal.audit.list`, `internal.audit.detail` |
| `GET /api/v1/audit/verify` ⚡ | `internal.audit.verify` |

---

## Suggested build order

Dependencies, not preferences. Each stage is usable on its own and unblocks the next.

| Stage | Screens | Why here |
| --- | --- | --- |
| **0 — transport** | none | Bearer handling, **serialised refresh** (`04` §5), problem-body decoding keyed on `code`, the step-up interceptor. Nothing above works correctly without this, and retrofitting serialised refresh into a built application is how sessions start dying under load |
| **1 — get in** | `public.bootstrap`, `public.login`, `auth.mfa.enrol`, `auth.mfa.verify`, `auth.mfa.recovery` | ROOT is bootstrapped into `MFA_ENROLLMENT_REQUIRED`, so enrolment is on the critical path to seeing anything at all |
| **2 — stay in** | `account.profile`, `account.sessions`, `account.security.password`, `account.security.mfa`, `public.password_reset.*` | `account.security.mfa` exercises step-up end to end and proves stage 0's interceptor |
| **3 — core widgets** | none | `data-table`, `detail-header`, `edit-form`, `confirm-dialog`, `error-state`, `empty-state`, `status-badge`, `filter-bar`, `gated-action` |
| **4 — work** | the ten `internal.projects.*` and `internal.tasks.*` screens | The product's reason to exist, and the widest exercise of pagination, `version` and member management |
| **5 — organisation** | the eight `internal.clients.*` and `internal.departments.*` screens | Prerequisite for the portal: without an `ACTIVE` client membership and a project link, no client user can see anything |
| **6 — the portal** | the four `client.*` screens, in their own build target | Buildable as soon as stage 5 can share a project. Small, and the boundary rules are easier to hold before the workspace has grown |
| **7 — people and access** | the eleven `internal.users.*`, `internal.invitations.*`, `internal.roles.*` and `internal.permissions.*` screens | The most intricate: delegation refusals, step-up on nearly every mutation, and the grant builder |
| **8 — administration and audit** | the six `internal.settings.*` and `internal.audit.*` screens | Independent of everything else; `internal.audit.verify` is the last piece and the least used |
| **9 — home** | `internal.home` | Built last, because what belongs on it is only knowable once the rest exists — and because there is no aggregate endpoint to make it a dashboard |
