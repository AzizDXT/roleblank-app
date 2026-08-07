# 05 — Client Portal Boundary

Short and sharp, because the rules are short and sharp. The client portal is the only
surface an external principal touches. Everything here exists to keep it that way.

---

## 1. The whole surface

A `CLIENT` principal may reach exactly four business endpoints:

| Method | Path | Permission |
| --- | --- | --- |
| `GET` | `/api/v1/client-portal/projects` | `client.portal.projects.read` |
| `GET` | `/api/v1/client-portal/projects/{id}` | `client.portal.projects.read` |
| `GET` | `/api/v1/client-portal/projects/{id}/tasks` | `client.portal.tasks.read` |
| `GET` | `/api/v1/client-portal/tasks/{id}` | `client.portal.tasks.read` |

All four are `GET`. All four use a `client.portal.*` permission. Both facts are asserted
by test in `backend/src/routes.rs` — the portal is read-only by construction, not by
convention.

Plus the shared, permission-free session endpoints every principal holds: `/auth/login`,
`/auth/refresh`, `/auth/logout`, `/auth/logout-all`, `/auth/me`, `/auth/sessions`,
`/auth/sessions/{id}`, `/auth/password/change`, `/auth/password-reset/*`, `/auth/mfa/*`,
and the anonymous registration and invitation-acceptance routes.

That is the entire API a portal build may call. **Four reads and an account.**

---

## 2. What a CLIENT can see

| Resource | Fields returned | Type |
| --- | --- | --- |
| Project | `id`, `code`, `name`, `description`, `status`, `start_date`, `target_date`, `completed_at`, `updated_at` | `ClientProjectResponse` |
| Task | `id`, `project_id`, `title`, `description`, `status`, `priority`, `due_date`, `completed_at`, `updated_at` | `ClientTaskResponse` |
| Themselves | `MeResponse`, their own sessions, their own password and MFA factors | shared |

And only where the visibility predicate holds. A project is visible to a CLIENT user
if and only if:

- an unrevoked `project_client_links` row joins that project to a client account, **and**
- that user holds an `ACTIVE` `client_memberships` row on that account, **and**
- the client account itself is `ACTIVE`.

A task is visible if and only if `tasks.client_visible = true` **and** its project
satisfies the above. Sharing a project does **not** share its tasks;
`client_visible` is per task and defaults to `false`.

This predicate is compiled into the SQL, not applied afterwards in Rust. An invisible
row is never selected, so a bug in the permission evaluator still does not leak another
client's project. Revoking a link removes visibility on the very next query, with no
cache to invalidate.

---

## 3. What a CLIENT can never see

Not "must not be shown" — **cannot be returned**. The client response types do not
contain these fields at all; they are physically absent from the struct, not skipped
during serialisation. A skipped field is one attribute away from being included; an
absent field cannot be.

| Never | Why |
| --- | --- |
| `internal_note` on a project or task | internal commentary |
| `version` | there is no client write path, so there is no concurrency token |
| `manager_user_id`, `department_id`, `created_by` | internal org structure and attribution |
| `client_visible` | knowing a task is hidden reveals that hidden tasks exist |
| Any user, employee, department, role, permission or invitation | no route, no type, no envelope |
| Any other client account, or the existence of one | including via a project's link list |
| Any audit event, setting or feature flag | no route reachable by a CLIENT |
| Any project or task not satisfying the predicate | the row is never selected |

Beneath the response shaping sit three further layers: the permission envelope (a
`CLIENT` can never hold a permission whose `max_principal_type = INTERNAL`, checked
before any grant is looked up), the object-level decision, and the SQL visibility
predicate. The portal UI is the fourth layer and the weakest — which is why it gets its
own build.

---

## 4. Why a separate build target

An external user must never receive an internal bundle.

Hiding a menu does not remove code from a bundle. A single application containing the
roles editor, the audit browser, the permission catalogue and the client-access screen
ships all of it — route names, field names, error strings, DTO shapes, the internal
navigation tree — to every CLIENT user who logs in. The backend's envelope stops the
*requests*. It cannot un-ship the bundle.

Three more reasons, each independent:

1. **A conditional is a one-line regression.** `{isInternal && <RolesEditor/>}` is one
   inverted boolean away from catastrophe, and the mistake is invisible in review.
   Moving a file across a build boundary is not.
2. **It is assertable.** With two entry points, a build-time check can state "no module
   under `internal/` is reachable from the portal entry point" — the same class of
   guarantee as the route-table tests that pin the anonymous surface. With one entry
   point there is nothing to assert.
3. **The adversary is assumed to be competent.** T2 in the threat model is a malicious
   CLIENT user with valid credentials, full knowledge of the API contract, and a habit
   of guessing UUIDs and tampering with every field. Handing them the internal client
   as reconnaissance material is an own goal.

They are also just different products: four read-only screens against thirty-six
working ones. Merging them optimises nothing.

### Sharing without leaking

Share as a library, never as an application: the transport layer (bearer handling,
serialised refresh, error decoding), the public authentication screens, the MFA
screens, the account screens, and purely structural widgets. Every endpoint behind
those is `Anonymous`, `MfaPending`, or `Authenticated` with **no permission** — they
carry no internal semantics.

Do not share: anything that names an internal resource, anything that renders
`internal_note`, `version`, `created_by` or `client_visible`, anything that reads
`capabilities` expecting internal permission codes, and any component whose props type
mentions an internal DTO. If a widget's props type can hold an internal field, the
portal build must not import that widget.

---

## 5. The `404` rule

> A `404` from the portal means **"not visible"**. The UI must never say "you do not
> have permission".

The backend already made this decision: for an external principal, an object it cannot
see returns `404 RESOURCE_NOT_FOUND`, and an internal-only route returns `404` as well.
A `403` would confirm the object exists. The entire point is destroyed the moment the
client renders it as a permission refusal.

Consider a CLIENT user guessing a project UUID. The API returns `404` whether the
project exists and belongs to a competitor, or does not exist at all. If the portal
renders "you do not have access to this project", it has just told them the project
exists — the leak the `404` was chosen to prevent, reintroduced in a string.

**Forbidden phrasings, anywhere in the portal:**

- "You do not have permission to view this"
- "Access denied" / "Not authorised" / "Restricted"
- "This project is not shared with you"
- "Ask your account manager for access"
- "This belongs to another account"
- Anything that distinguishes "does not exist" from "exists but is not yours"

**Required phrasing:** one existence-neutral message, identical for every `404` on
every portal screen. Something of the form *"This isn't available."* — no elaboration,
no speculation, no support prompt that implies access could be arranged.

Related rules that fall out of the same principle:

1. **No `403` handling in the portal.** `AUTHORIZATION_DENIED` should be unreachable —
   a CLIENT either holds the two portal permissions or holds nothing. If one arrives,
   render the same neutral message, and log it, because it means something is wrong.
2. **`404` and `403` render identically.** Two distinguishable renderings are an oracle.
3. **Timing must not distinguish either.** Do not retry, prefetch, probe or otherwise
   spend measurably different effort on the two.
4. **An empty list is normal.** `client.projects.list` with no items means nothing has
   been shared yet. Say that neutrally; do not frame it as missing access.
5. **An empty task list is normal.** A project may be shared with no `client_visible`
   tasks. Never imply the project has no work, and never imply work is being withheld.
6. **A record that disappears was revoked.** Unshare, membership removal and account
   archival take effect immediately. The screen shows the same neutral message and
   returns to the project list. It does not say "your access was revoked".
7. **No deep-link enumeration surface.** The portal renders no identifier the user
   cannot already reach through its own navigation. Do not display raw UUIDs of
   anything, do not build "recently viewed" from arbitrary paths, and do not put an
   unresolvable identifier in a page title or a document title.
8. **The same neutrality applies to the anonymous surface.** Password reset always
   returns the same `202` body, and registration always returns the same
   `SUBMITTED` acknowledgement. The portal must not vary the wording, the layout or the
   delay by outcome.

---

## 6. Portal build checklist

Structural assertions worth enforcing rather than remembering.

- [ ] The portal entry point reaches no module under the internal tree — enforced at
      build time, failing the build, not linted.
- [ ] The portal's HTTP layer accepts only the four `/api/v1/client-portal/*` paths
      plus the shared session endpoints. Anything else is a programming error and
      throws before it reaches the network.
- [ ] No portal type declares `internal_note`, `version`, `created_by`,
      `manager_user_id`, `department_id` or `client_visible`.
- [ ] Every `404` renders one shared, existence-neutral message. Asserted by test over
      all four screens.
- [ ] No portal string contains "permission", "authorised", "denied", "restricted" or
      "access" in a refusal context. A grep test is proportionate here.
- [ ] `capabilities` from `/auth/me` is asserted on receipt to contain only
      `client.portal.projects.read` and `client.portal.tasks.read`. Anything else is
      fatal, not rendered.
- [ ] `principal_type` is asserted to be `CLIENT` on login. An `INTERNAL` principal
      arriving at the portal is a misconfiguration; refuse the session rather than
      degrading gracefully.
- [ ] No sort or filter controls exist. The portal list endpoints accept `cursor` and
      `limit` only, and nothing else.
- [ ] No page numbers and no result counts, per the cursor-pagination rule.
- [ ] The portal is served from its own origin, with its own cookie scope and its own
      BFF instance.
- [ ] Refresh is serialised in the portal's BFF exactly as in the workspace's — the
      session-family revocation applies identically, and a client user losing their
      session mid-view is a support call from someone else's company.

---

## 7. One sentence

The portal shows four kinds of read to a principal the system treats as untrusted, in
its own bundle, from its own origin, saying nothing on failure that distinguishes
absence from exclusion.
