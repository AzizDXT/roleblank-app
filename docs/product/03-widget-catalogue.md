# 03 — Widget Catalogue

The reusable structural components both applications are assembled from. Each entry
gives: what it is for, what data it takes, what states it has, and what it must do
about permissions and errors.

**These are behavioural contracts, not visual ones.** Nothing here says how a widget
looks. A widget is correct when it handles every state and every error listed, whatever
it is dressed in. Two widgets with the same identifier may look completely different in
the workspace and the portal; they must behave identically.

**Naming.** The identifiers below are the ones used in the *Widgets* column of
`02-screen-inventory.md`. They are structural role names, not implementation names.

Common vocabulary used throughout:

- **`code`** — the stable machine-readable error identifier from the RFC 9457 problem
  body (`07-api-contract.md` §2). Every widget branches on `code`, never on `title`,
  `detail`, or the HTTP status alone.
- **`request_id`** — present on every response. Any widget that renders a failure the
  user might report must surface it.
- **capability** — an entry from `/auth/me` `capabilities[]`. Used to decide whether to
  render an affordance. **Never** used to decide whether a request is allowed.

---

## 1. `data-table` — cursor-paginated list

**Purpose.** Render a page of rows from a list endpoint and move forward through the
result set.

**Takes.** A list endpoint; a column set; an optional sort allowlist; an optional
`filter-bar`; a row-activation target (usually a detail screen).

**Consumes.** `{ items: [...], next_cursor: string|null, has_more: boolean }`.

### The pagination rule, stated once and non-negotiably

Pagination is **keyset (cursor)**, not offset. The response carries `next_cursor` and
`has_more` and **nothing else** — no total count, no page count, no row count.

Therefore this widget **must not** offer:

- page numbers (`1 2 3 … 47`)
- "jump to last page"
- "go to page N"
- "showing 26–50 of 1,204"
- a scrubber, or any control whose position implies a known extent

It **may** offer: "next", "previous" (by keeping a client-side stack of the cursors
already visited — the API has no backwards cursor), page size within `1..=100`, and an
end-of-results marker when `has_more = false`.

This is not a limitation to be worked around. `07-api-contract.md` §3: offset
pagination lets a caller turn a cheap endpoint into an expensive one by incrementing a
number. A UI that offers page numbers has to synthesise them by walking every page,
which is precisely the abuse the API was designed to prevent. If a builder finds
themselves fetching pages in a loop to count rows, the design is wrong, not the API.

**Cursor discipline.** The cursor is opaque and length-bounded. Do not parse it, do not
construct it, do not persist it across sessions, and do not put it in a bookmarkable
URL as though it were stable — it encodes a position in a *particular* sort order, and
changing the sort or a filter invalidates it. Changing any filter, the sort field, or
the direction **resets the cursor stack to empty**.

### Sorting

`sort` is allowlisted per endpoint and anything else is `400`. The widget therefore
renders sort controls **only** for fields on that endpoint's allowlist. A column that
is not sortable server-side must not be rendered as clickable — sorting the visible
page client-side would sort 25 rows out of an unknown number, which is worse than not
sorting at all.

The allowlists are enumerated in `01-application-structure.md` §9. Passing the
allowlist to the widget as data (rather than hard-coding controls per screen) is what
makes this enforceable in one place.

### States

| State | Condition | Behaviour |
| --- | --- | --- |
| `loading` | first fetch | placeholder rows; keep the filter bar interactive |
| `loading_more` | fetching with a cursor | keep existing rows visible; disable "next" only |
| `ready` | `items.length > 0` | rows; "next" enabled iff `has_more` |
| `empty` | `items.length === 0`, no filters active | delegate to `empty-state`, "nothing here yet" variant |
| `empty_filtered` | `items.length === 0`, filters active | delegate to `empty-state`, "no matches" variant, with a clear-filters action |
| `end` | `has_more === false` after ≥1 page | explicit terminator; do not silently stop |
| `forbidden` | `403 AUTHORIZATION_DENIED` | delegate to `error-state`; no retry |
| `error` | anything else | delegate to `error-state` |

### Permissions

The table renders only if the actor's capabilities include the read permission — but
mounting it anyway and rendering `forbidden` from the real `403` must also work, because
capabilities are cosmetic. Per-row actions are `gated-action`s and are evaluated per
row, not per table.

### Errors

`400 VALIDATION_FAILED` from a bad `limit` or `sort` is a **bug in the widget**, not
user error: the widget owns those parameters. Surface it loudly in development and fall
back to defaults in production rather than showing the user a validation failure they
did not cause.

---

## 2. `detail-header` — record identity and the concurrency token

**Purpose.** Head a detail screen with the record's identity and status, and hold the
`version` that every subsequent mutation must present.

**Takes.** The record; the record's status vocabulary; the set of actions available on
it.

### `version` is the whole point

Editable resources carry `version`. `PATCH`, archive, suspend, reactivate and task
cancellation all send the version that was read. The header is the single owner of that
value for the screen: forms read it from the header, they do not each keep a copy.

Rules:

1. `version` is **read at fetch time and never guessed**. Do not increment it locally
   after a successful write — take the new record from the response.
2. A successful mutation response replaces the whole record in the header, including
   `version`. Two consecutive edits without an intervening re-read must work.
3. `409 VERSION_CONFLICT` puts the header into `stale`. It carries `expected` and
   `actual`. The header re-reads, and the screen shows what changed between the version
   the actor edited and the one now current. Nothing is silently overwritten and nothing
   is silently discarded.
4. `version` is **not** rendered as a user-facing number by default. It is a concurrency
   token, not a revision history — there is no endpoint to fetch version 3 of anything.

### States

| State | Behaviour |
| --- | --- |
| `loading` | skeleton header; actions disabled |
| `ready` | identity, `status-badge`, actions |
| `editing` | the screen's `edit-form` is mounted; destructive actions disabled while a draft is dirty |
| `saving` | actions disabled; the form owns the busy state |
| `stale` | conflict presentation; the actor chooses to reload or to re-apply their changes onto the current record |
| `not_found` | the record disappeared between navigation and fetch; per-app wording (see `05-client-portal-boundary.md`) |
| `forbidden` | `403`; header renders identity-less, actions absent |

### Portal note

`ClientProjectResponse` and `ClientTaskResponse` have **no `version` field**, because
there is no client write path. In the portal this widget is an identity header with no
concurrency behaviour at all. That is not a degraded mode — it is a different, simpler
contract, and the portal build must not import the version-handling code it cannot use.

---

## 3. `edit-form` — create and update

**Purpose.** Collect a request body, submit it, and map failures back onto the fields
that caused them.

**Takes.** A field schema; an endpoint and method; a `version` (updates only); an
optional `Idempotency-Key` policy.

### Field-level error mapping

The problem body carries `errors: [ { field, code, message } ]`. The form:

1. On `400 VALIDATION_FAILED`, attaches each `errors[]` entry to the control named by
   `field`, keyed on the entry's `code`.
2. Renders any entry whose `field` does not match a control as a **form-level** error.
   This must be visible, not swallowed — an unmatched field name usually means the
   form is sending something the endpoint does not have, or is missing a control.
3. Keeps the actor's input. A validation failure never clears the form.
4. Clears a field's error when that field changes, not when any field changes.

### Closed request bodies

Every request DTO is `deny_unknown_fields`. An unrecognised field is `400 BAD_REQUEST`,
not an ignored extra. Consequences for this widget:

- **Send only the fields the endpoint declares.** Do not round-trip the record you read
  — `ProjectResponse` contains `id`, `created_at`, `created_by` and `status`, and
  `UpdateProjectRequest` accepts none of those except `status`.
- **Do not send a field to make the payload "complete".** Omission and `null` are
  different: several update DTOs use a double-option (`Option<Option<T>>`) so that an
  absent key means "leave alone" and an explicit `null` means "clear it". A form that
  always sends every key will clear fields the actor never touched.
- Mass-assignment attempts (`is_root`, `principal_type`, `role_ids`, `status` on
  create, `client_visible` on create) fail with `400`. That is by design; do not add
  the field to "fix" the error.

### Error handling

| `code` | Form behaviour |
| --- | --- |
| `VALIDATION_FAILED` | map `errors[]` onto fields as above |
| `BAD_REQUEST` | form-level; a payload-shape bug — log it |
| `UNIQUE_VIOLATION` | map to the uniqueness-bearing field (`code` on projects/clients/departments/roles, `email` on invitations) |
| `REFERENCE_VIOLATION` | map to the identifier field that pointed at something absent |
| `INVARIANT_VIOLATION` | form-level; typically an illegal status transition |
| `VERSION_CONFLICT` | hand to `detail-header`'s `stale` state, do not handle locally |
| `STEP_UP_REQUIRED` | hand to `step-up-prompt`; **preserve the draft**, retry the identical request on success |
| `DELEGATION_DENIED` | form-level, and where the body names the offending permission, map it to that grant row |
| `ROOT_PROTECTED` | form-level, non-retryable, explicit |
| `AUTHORIZATION_DENIED` | form-level, non-retryable; the submit affordance should not have been rendered, so also a capability bug |
| `PAYLOAD_TOO_LARGE`, `UNSUPPORTED_MEDIA_TYPE` | transport bugs; never shown as user error |
| `RATE_LIMITED` | disable submit for `Retry-After`, then re-enable |

### Idempotency

Where the create endpoint is idempotency-bearing (invitations, users, projects,
clients), the form generates **one** `Idempotency-Key` per draft and reuses it across
retries of that draft. It generates a **new** key when the body changes — same key with
a different body is `409 IDEMPOTENCY_KEY_REUSED`, which is a correctness failure, not a
retry.

### States

`pristine` → `dirty` → `submitting` → `succeeded` | `field_errors` | `form_error` |
`step_up_pending` | `conflict`. A dirty form must warn before navigation.

---

## 4. `confirm-dialog` — destructive and boundary-crossing actions

**Purpose.** Make an irreversible or externally-visible action deliberate.

**Required for.** Archive (project, client, department, user), suspend and reactivate,
task cancellation, member and assignee removal, role unassignment, override creation
and revocation, project–client share and unshare, `client_visible` toggling, MFA
disable, recovery-code regeneration, session revocation, sign out everywhere,
invitation revocation, role deletion.

**Takes.** The action; the target's human identity; the consequence statement; the
`version` where the endpoint requires one; an optional `reason` field where the DTO
accepts one (`ArchiveProjectRequest.reason`, `SuspendUserRequest.reason`,
`ArchiveUserRequest.reason`, `CreateOverrideRequest.reason`).

**Behaviour.**

1. States the **consequence**, not the mechanism. "This removes the client's access to
   this project immediately" beats "This sets `revoked_at`".
2. Names the target explicitly. A dialog that says "Are you sure?" without saying what
   is being acted on is not a confirmation.
3. Carries the `version` from `detail-header`, so a conflict is caught here rather than
   after the actor has committed.
4. Is the natural host for `step-up-prompt` when the action is step-up gated — the
   prompt appears inside the dialog and the action proceeds without the actor losing
   their place.
5. Never pre-selects the destructive choice.
6. On failure, stays open and renders the error; it does not dismiss and leave the actor
   guessing whether anything happened.

**Consequence statements that must be present**, because the backend behaviour is
surprising otherwise:

- Sharing a project with a client account exposes the project **but not its tasks**.
- Unsharing, archiving a client account, or removing a client membership removes
  visibility **immediately, on the next request**.
- Changing a password revokes **all other** sessions.
- Regenerating recovery codes invalidates **the entire previous batch**.
- Revoking the session marked `current` ends the actor's own session.
- Removing a project member or task assignee revokes the `ASSIGNED` scope that
  membership conferred.
- Archiving a user is not deletion, and there is no deletion.

---

## 5. `step-up-prompt` — recent-second-factor challenge

**Purpose.** Satisfy `403 STEP_UP_REQUIRED` without losing the operation that triggered
it.

**Trigger.** Exclusively a `403` whose `code` is `STEP_UP_REQUIRED`. The body carries
`step_up.window_seconds`.

**Behaviour.**

1. **Reactive, never predictive.** The client does not maintain its own list of
   step-up operations. The authoritative list lives in
   `platform::security::step_up::STEP_UP_OPERATIONS` and is asserted against the route
   table by test. A client-side copy will drift, and drifting in the permissive
   direction produces a confusing failure while drifting in the restrictive direction
   produces prompts nobody needed. Attempt the operation; handle the refusal.
2. Captures a TOTP code and calls `POST /api/v1/auth/mfa/verify`.
3. **Retries the original request, byte-identical**, including the same
   `Idempotency-Key` if one was used, and the same `version`.
4. Falls back to `POST /api/v1/auth/mfa/recovery/verify` for an actor who has lost their
   authenticator.
5. `step_up_active` from `/auth/me` is a **hint** for pre-warning the actor that a
   prompt is likely. It is not a licence to skip the attempt, and it goes stale
   silently as the window expires.
6. Only one prompt may be live at a time. A second `STEP_UP_REQUIRED` arriving while a
   prompt is open queues behind it.

**States.** `idle` → `challenging` → `verifying` → `retrying_original` → `succeeded` |
`failed`. On `failed` the original operation is abandoned, not silently dropped: the
originating screen reports that the change was not applied.

**Note.** An actor with `mfa_enrolled = false` cannot satisfy a step-up. The backend
mandates enrolment for anyone holding a dangerous permission, so this should be
unreachable — if it happens, route to `account.security.mfa` rather than looping the
prompt.

---

## 6. `gated-action` — permission-conditional affordance

**Purpose.** Render an action affordance only when the actor plausibly holds the
permission for it.

**Takes.** A permission code; optionally a target, so that a scope-bearing capability
can be evaluated against it; the action.

**Behaviour.**

1. Reads `capabilities[]` from `/auth/me`. Renders if the actor holds the permission at
   any scope that could cover the target.
2. Where the capability is scoped (`ASSIGNED`, `DEPARTMENT`, `SELF`) and the target's
   membership is not known to the client, the widget **renders the affordance and lets
   the backend decide**. Guessing scope coverage client-side produces false negatives
   that look like broken software.
3. `RESOURCE`-scoped overrides are not enumerable from `/auth/me`, so the widget can
   never be complete. Optimistic rendering plus a real `403` is the correct failure
   mode.
4. Re-evaluates when `security_version` changes.

> **This widget is cosmetic and must be treated as such by everyone who uses it.** The
> backend re-derives every decision on every request. Hiding a button does not protect
> anything; it just avoids offering the user a door that is locked. A reviewer who sees
> a `gated-action` and concludes "that operation is protected" has misread the system —
> the protection is in `authorization::evaluator`, and it is also a `JOIN`.

**States.** `hidden` (no capability), `enabled`, `disabled_with_reason` (capability
held but the record's state forbids it — an `is_system` role, an already-archived
project, ROOT as target), `busy`.

Prefer `disabled_with_reason` over `hidden` when the actor holds the permission: an
explanation is more useful than an absence.

---

## 7. `empty-state`

**Purpose.** Distinguish the several different reasons a region has no content, because
they call for different next actions.

| Variant | Condition | Content |
| --- | --- | --- |
| `never` | no filters, no rows | what this collection is for, plus the create affordance if the actor holds the create permission |
| `filtered` | filters active, no matches | which filters are active, and a clear-filters action |
| `scoped` | the actor's scope is narrower than the collection | a statement that they are seeing only what they are a member of — for an `ASSIGNED`-scoped employee, an empty project list means "you are on no projects", not "there are no projects" |
| `not_shared` | portal only | nothing has been shared with this client account yet. Neutral wording; this is a normal state, not an error, and not a permission statement |

The `scoped` variant matters more than it looks. A narrow scope turns a list endpoint
into a *filtered query*, so an employee sees an empty table that is indistinguishable
from a broken one unless the UI explains it.

---

## 8. `error-state` — keyed on the stable `code`

**Purpose.** Render a failure in terms of what the actor can do about it.

**Takes.** The problem body (`code`, `status`, `request_id`, optional `errors[]`,
optional `step_up`).

**The rule.** Branch on `code`. Never on `title` or `detail` — they are human text and
may be reworded in any release. Never on `status` alone — four different `403` codes
require four different behaviours. Never on `type` — it is a stable identifier but not a
resolvable URL, and resolving it would leak error occurrence to an external host.

| `code` | Presentation | Retry |
| --- | --- | --- |
| `VALIDATION_FAILED` | field-level via `edit-form` | on correction |
| `BAD_REQUEST` | client bug; generic message, log loudly | no |
| `UNKNOWN_PERMISSION` | client bug — a permission code outside the catalogue was sent | no |
| `AUTHENTICATION_FAILED` | session ended; hand to the shell's re-authentication path | via login |
| `AUTHORIZATION_DENIED` | "you do not have access to this"; no mechanism detail | no |
| `STEP_UP_REQUIRED` | not an error state — hand to `step-up-prompt` | automatic |
| `MFA_REQUIRED` | not an error state — hand to the MFA surface | automatic |
| `ROOT_PROTECTED` | explicit, unmistakable refusal; explain that the system owner is protected | no |
| `DELEGATION_DENIED` | explain that authority cannot be granted beyond what the actor holds | no |
| `RESOURCE_NOT_FOUND` | **per application** — see `05-client-portal-boundary.md` | no |
| `UNIQUE_VIOLATION` | map to the conflicting field | on correction |
| `REFERENCE_VIOLATION` | the referenced object is missing | on correction |
| `INVARIANT_VIOLATION` | the operation is not legal in this state | no |
| `VERSION_CONFLICT` | hand to `detail-header` `stale` | after merge |
| `IDEMPOTENCY_KEY_REUSED` | client bug — same key, different body | no |
| `SYSTEM_ALREADY_INITIALIZED` | bootstrap is permanently closed; redirect to login | no |
| `PAYLOAD_TOO_LARGE` | 256 KiB exceeded | on reduction |
| `UNSUPPORTED_MEDIA_TYPE` | transport bug | no |
| `RATE_LIMITED` | honour `Retry-After`; count down | after the delay |
| `INTERNAL_ERROR` | generic apology **plus `request_id`** — it is the only handle support has | yes |
| `SERVICE_UNAVAILABLE` | dependency down | yes, with backoff |
| *unrecognised* | generic failure plus `request_id`; never render raw `detail` as though it were designed copy | yes |

**Never render `detail` verbatim as the primary message.** It is safe (it contains no
SQL, stack trace, path or hostname by construction) but it is written for a developer.
Use it as secondary text at most.

**Always render `request_id`** on `INTERNAL_ERROR`, `SERVICE_UNAVAILABLE` and any
unrecognised code.

---

## 9. `audit-timeline`

**Purpose.** Present append-only event history in sequence.

**Takes.** `AuditEventResponse[]` from `GET /api/v1/audit/events`.

**Behaviour.**

1. **No mutation affordances exist and none may be added.** There is no audit write,
   update, delete or purge endpoint, by design (ADR-006), the database rejects
   `UPDATE`/`DELETE` by trigger, and the runtime role holds only `SELECT, INSERT`. A
   context menu with "delete this entry" is not merely non-functional; it advertises a
   capability the system deliberately refuses to have.
2. Orders by `occurred_at` — the only allowlisted sort — descending by default, and
   shows `seq` alongside, because `seq` is the chain position and gaps are meaningful.
3. Renders `outcome` (`SUCCESS` | `DENIED` | `FAILURE`) as a `status-badge`. `DENIED`
   entries are the interesting ones; they must not be visually demoted.
4. Renders the actor as `actor_user_id` + `actor_principal_type`. `actor_user_id` may
   be `null` for anonymous-surface events — render "unauthenticated", not "unknown".
5. Groups by day for scanning, but never collapses or deduplicates events.
6. Links `target_type` + `target_id` through to the corresponding detail screen where
   one exists, degrading to a plain identifier where it does not (the target may be
   archived, or of a type with no screen).
7. Paginates through `data-table`'s cursor contract; the same no-page-numbers rule
   applies. The chain is unbounded and will always be the largest table in the system.
8. Surfaces `request_id` per event — it is the join key between the audit trail and the
   application logs.

**States.** As `data-table`, plus `divergence` on the verification screen: when
`GET /api/v1/audit/verify` returns a `first_divergent_seq`, the timeline marks that
position unmissably and shows the `diagnostics` block. This is the single most
important state in the application and must never be rendered as an ordinary warning.

---

## 10. `member-list` — membership with add and remove

**Purpose.** Manage a set of people attached to a record. Used for project members,
task assignees, client members, department members and role assignments.

**Takes.** A list endpoint; an add endpoint; a remove endpoint; the permission that
gates mutation; the membership's role vocabulary where it has one.

**Instances and their differences** — these are not interchangeable:

| Screen | Paginated | Extra fields | Mutation permission | Step-up |
| --- | --- | --- | --- | --- |
| `internal.projects.detail.members` | no (plain array) | `role_in_project` ∈ MEMBER/LEAD | `projects.members.manage` | no |
| `internal.tasks.detail.assignees` | no (plain array) | `assigned_by`, `assigned_at` | `tasks.assign` | no |
| `internal.departments.detail.members` | yes, sort `joined_at` | `role_in_department` ∈ MEMBER/LEAD | `departments.members.manage` | no |
| `internal.clients.detail.members` | yes, sort `created_at` | `status` ∈ PENDING/ACTIVE/SUSPENDED/REMOVED, `grants_visibility`, plus an **activate** action | `clients.members.manage` | no |
| `internal.users.detail.roles` | no (plain array) | `is_system`, `allowed_principal_type`, `granted_by` | `iam.roles.assign` | **yes** |
| `internal.projects.detail.clients` | no (plain array) | client account rather than a person; `note`, `shared_by` | `projects.clients.share` | **yes** |

**Behaviour.**

1. The add control is a person picker where the actor holds `iam.users.read`, and a
   plain identifier field where they do not. `projects.members.manage` does not imply
   the ability to browse the directory.
2. Removal is always a `confirm-dialog` and always states the access consequence.
3. Membership **is** authorisation: project membership and task assignment are what
   `ASSIGNED` scope resolves against, department membership is what `DEPARTMENT`
   resolves against, and an `ACTIVE` client membership is one half of the client
   visibility predicate. A removal here changes what someone can see across the whole
   system, and the widget must say so rather than presenting itself as an address book.
4. `403 ROOT_PROTECTED` on a role operation targeting the owner is an expected outcome,
   not a defect.
5. The client-members instance treats `grants_visibility` as the primary signal, not
   `status` — it is the field that actually determines whether that person sees
   anything.

---

## 11. `status-badge`

**Purpose.** Render a state value from a fixed, backend-defined vocabulary.

**Vocabularies** — closed sets, all of them, and the widget must reject anything
outside its set rather than inventing a rendering:

| Domain | Values |
| --- | --- |
| user | `PENDING`, `ACTIVE`, `SUSPENDED`, `ARCHIVED` |
| project | `ACTIVE`, `PAUSED`, `COMPLETED`, `ARCHIVED` |
| task | `TODO`, `IN_PROGRESS`, `BLOCKED`, `DONE`, `CANCELLED` |
| task priority | `LOW`, `NORMAL`, `HIGH`, `URGENT` |
| department | `ACTIVE`, `ARCHIVED` |
| client account | `ACTIVE`, `SUSPENDED`, `ARCHIVED` |
| client membership | `PENDING`, `ACTIVE`, `SUSPENDED`, `REMOVED` |
| invitation | `PENDING`, `ACCEPTED`, `REVOKED`, `EXPIRED` |
| session `auth_level` | `PASSWORD`, `MFA` |
| audit `outcome` | `SUCCESS`, `DENIED`, `FAILURE` |
| principal type | `INTERNAL`, `CLIENT` |
| permission `max_principal_type` | `INTERNAL`, `ANY` |
| override `effect` | `ALLOW`, `DENY` |
| scope | `GLOBAL`, `DEPARTMENT`, `ASSIGNED`, `SELF`, `RESOURCE` |

**Behaviour.**

1. Never inferred. The badge shows what the API returned; it does not compute
   "overdue" from a due date or "at risk" from anything.
2. An unrecognised value renders as the raw string, not as a default. A new enum member
   appearing is a forward-compatible response change (`07-api-contract.md` §14) and
   must degrade to something truthful.
3. Transitions are backend-validated (`can_transition_to`). The widget may offer the
   full vocabulary and let the backend refuse with `409 INVARIANT_VIOLATION`, or offer
   the legal subset — but it must handle the refusal either way, because the record may
   have moved since it was read.
4. `is_dangerous` and `is_security_sensitive` are boolean flags, not statuses. They use
   this widget's mechanics but must be distinguishable from a lifecycle state — they
   are warnings, not positions in a workflow.

---

## 12. `filter-bar`

**Purpose.** Collect the query parameters a list endpoint actually supports, and
nothing else.

**Rule.** Every control corresponds to a real query parameter on that endpoint. A
filter the endpoint does not implement cannot be faked client-side over a page of 25
rows out of an unknown total — it would be a lie.

**Supported filters, exhaustively:**

| Endpoint | Filters | Sort allowlist |
| --- | --- | --- |
| `GET /api/v1/projects` | `status`, `department_id` | `created_at`, `updated_at` |
| `GET /api/v1/tasks` | `project_id`, `status` | `created_at`, `updated_at` |
| `GET /api/v1/projects/{id}/tasks` | *(none)* | `created_at`, `updated_at` |
| `GET /api/v1/users` | `principal_type`, `status`, `search` | `created_at`, `updated_at` |
| `GET /api/v1/invitations` | `status` | `created_at`, `expires_at` |
| `GET /api/v1/clients` | *(none)* | `created_at` |
| `GET /api/v1/clients/{id}/members` | *(none)* | `created_at` |
| `GET /api/v1/departments` | *(none)* | `created_at` |
| `GET /api/v1/departments/{id}/members` | *(none)* | `joined_at` |
| `GET /api/v1/roles` | *(none)* | `code`, `name`, `created_at` |
| `GET /api/v1/audit/events` | `actor_user_id`, `action_code`, `target_type`, `target_id`, `outcome`, `occurred_from`, `occurred_to` | `occurred_at` |
| `GET /api/v1/client-portal/projects` | *(none)* | *(none — `cursor` and `limit` only)* |
| `GET /api/v1/client-portal/projects/{id}/tasks` | *(none)* | *(none — `cursor` and `limit` only)* |

Endpoints with no filters and a single sort field get **no filter bar at all**. An
empty bar is worse than none.

**Behaviour.**

1. Any change resets the cursor stack (see §1).
2. Filter state belongs in the URL so a filtered view is shareable — but the *cursor*
   does not, because it is position-in-a-sort, not a bookmark.
3. `limit` is offered within `1..=100`. Out-of-range is `400`, not clamped, so the
   control must be bounded rather than free text.
4. A rejected `sort` value is **not echoed back** in the error, so the widget cannot
   show the user what it sent. This is another reason to render controls from the
   allowlist rather than accepting arbitrary input.

---

## 13. Supporting widgets

Smaller pieces, referenced by the inventory.

### `key-value-list`

Read-only field presentation for a record. Takes an ordered field list; renders absent
optional values as explicitly absent rather than blank; never renders a field the DTO
does not contain. **`internal_note` is internal**: it exists on `ProjectResponse` and
`TaskResponse` and is physically absent from the client types, so no instance of this
widget compiled into the portal may accept it.

### `capability-list`

Renders `EffectivePermissionsResponse`: `permission_code` × `scopes[]`, grouped by
module, with the subject's `principal_type` and `is_root`. Read-only. States that this
is the *effective* result after roles, overrides and denials — not a list of role
contents. For a CLIENT subject it can only ever contain the two `client.portal.*`
codes; if it ever shows more, that is a security incident, not a display bug.

### `grant-builder`

Builds `[{ permission_code, scope }]` for role creation and editing. Reads
`GET /api/v1/permissions` for the catalogue. Marks `is_dangerous` entries distinctly.
Hides `max_principal_type = INTERNAL` permissions when `allowed_principal_type =
CLIENT`. Offers only `GLOBAL`, `DEPARTMENT`, `ASSIGNED`, `SELF` — `RESOURCE` is
overrides-only and must not appear here. On `PATCH`, submits the **complete** intended
set, never a delta, because the API replaces the array. On `403 DELEGATION_DENIED`,
maps the refusal to the offending grant row where the body identifies it.

### `toggle-row`

A settings or feature-flag row carrying its own `version`. Sends `{ enabled, version }`
or `{ value, version }` for that key alone — concurrency is per key, not per screen.
Optimistic state must revert on `403 STEP_UP_REQUIRED` and re-issue after the prompt
succeeds. `is_security_sensitive` rows require an individual `confirm-dialog`.

### `session-list`

Renders `SessionSummary[]` — unpaginated. Marks `current: true` distinctly, shows
`auth_level`, `last_activity_at` and the three expiry stamps (`access_expires_at`,
`idle_expires_at`, `absolute_expires_at`), and renders `client_ip_hint` /
`user_agent_hint` as the truncated hints they are. Revoking `current` ends the actor's
own session and must say so.

### `one-time-secret`

Presents a value the API will never return again: the TOTP `secret` and `otpauth_uri`
from setup, and the recovery-code batch from activation or regeneration. Requires an
explicit acknowledgement before it can be dismissed. Must not be persisted, cached,
logged, or placed in a URL. Offers copy and print; offers no "show again", because
there is no endpoint behind such a control.

### `acknowledgement`

A fixed, existence-neutral terminal message for the deliberately uninformative
endpoints: password-reset request (always `202`, always identical) and registration
(`registration_status = SUBMITTED`). The text is **the same regardless of outcome**.
Varying it — even in punctuation, even in timing — reintroduces the enumeration oracle
those endpoints were shaped to remove.

### `json-inspector`

Renders `AuditEventResponse.metadata`, which is arbitrary JSON. Structured, collapsible,
copyable, and explicitly presented as raw data. Never interpreted into prose: the
metadata schema varies by `action_code` and inventing a narrative from it will
eventually describe an event incorrectly, in the one place in the system where being
wrong is unacceptable.
