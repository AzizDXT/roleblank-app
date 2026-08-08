# 04 — Navigation and Session State

How the two applications route, how a session moves between its states, and what each
class of failure means for navigation. Read alongside `03-authentication.md` and
`07-api-contract.md` §8–§10, which are the backend contracts this document consumes.

---

## 1. Route map — internal workspace

| Route | `screen_id` | Access |
| --- | --- | --- |
| `/bootstrap` | `public.bootstrap` | **public** |
| `/login` | `public.login` | **public** |
| `/password-reset` | `public.password_reset.request` | **public** |
| `/password-reset/confirm` | `public.password_reset.confirm` | **public** |
| `/register` | `public.registration` | **public** |
| `/invitations/accept` | `public.invitation.accept` | **public** |
| `/auth/mfa/enrol` | `auth.mfa.enrol` | MFA-pending |
| `/auth/mfa/verify` | `auth.mfa.verify` | MFA-pending |
| `/auth/mfa/recovery` | `auth.mfa.recovery` | MFA-pending |
| `/` | `internal.home` | session |
| `/account` | `account.profile` | session |
| `/account/password` | `account.security.password` | session |
| `/account/security` | `account.security.mfa` | session |
| `/account/sessions` | `account.sessions` | session |
| `/projects` | `internal.projects.list` | `projects.read` |
| `/projects/new` | `internal.projects.create` | `projects.create` |
| `/projects/:id` | `internal.projects.detail` | `projects.read` |
| `/projects/:id/tasks` | `internal.projects.detail.tasks` | `tasks.read` |
| `/projects/:id/team` | `internal.projects.detail.members` | `projects.read` |
| `/projects/:id/client-access` | `internal.projects.detail.clients` | `projects.read` |
| `/tasks` | `internal.tasks.list` | `tasks.read` |
| `/tasks/new` | `internal.tasks.create` | `tasks.create` |
| `/tasks/:id` | `internal.tasks.detail` | `tasks.read` |
| `/tasks/:id/assignees` | `internal.tasks.detail.assignees` | `tasks.read` |
| `/clients` | `internal.clients.list` | `clients.read` |
| `/clients/new` | `internal.clients.create` | `clients.create` |
| `/clients/:id` | `internal.clients.detail` | `clients.read` |
| `/clients/:id/members` | `internal.clients.detail.members` | `clients.read` |
| `/departments` | `internal.departments.list` | `departments.read` |
| `/departments/new` | `internal.departments.create` | `departments.create` |
| `/departments/:id` | `internal.departments.detail` | `departments.read` |
| `/departments/:id/members` | `internal.departments.detail.members` | `departments.read` |
| `/people` | `internal.users.list` | `iam.users.read` |
| `/people/:id` | `internal.users.detail` | `iam.users.read` |
| `/people/:id/roles` | `internal.users.detail.roles` | `iam.roles.read` |
| `/people/:id/access` | `internal.users.detail.permissions` | `iam.permissions.read` |
| `/people/:id/overrides` | `internal.users.detail.overrides` | `iam.permissions.delegate` |
| `/invitations` | `internal.invitations.list` | `iam.users.invite` |
| `/invitations/new` | `internal.invitations.create` | `iam.users.invite` |
| `/roles` | `internal.roles.list` | `iam.roles.read` |
| `/roles/new` | `internal.roles.create` | `iam.roles.create` |
| `/roles/:id` | `internal.roles.detail` | `iam.roles.read` |
| `/permissions` | `internal.permissions.catalogue` | `iam.permissions.read` |
| `/admin/settings` | `internal.settings.list` | `settings.read` |
| `/admin/feature-flags` | `internal.settings.feature_flags` | `settings.read` |
| `/admin/system` | `internal.settings.system_info` | session |
| `/audit` | `internal.audit.list` | `audit.read` |
| `/audit/:id` | `internal.audit.detail` | `audit.read` |
| `/audit/verify` | `internal.audit.verify` | `audit.read` |

## 2. Route map — client portal

| Route | `screen_id` | Access |
| --- | --- | --- |
| `/login` | `public.login` | **public** |
| `/password-reset` | `public.password_reset.request` | **public** |
| `/password-reset/confirm` | `public.password_reset.confirm` | **public** |
| `/register` | `public.registration` | **public** |
| `/invitations/accept` | `public.invitation.accept` | **public** |
| `/auth/mfa/enrol` | `auth.mfa.enrol` | MFA-pending |
| `/auth/mfa/verify` | `auth.mfa.verify` | MFA-pending |
| `/auth/mfa/recovery` | `auth.mfa.recovery` | MFA-pending |
| `/` → `/projects` | `client.projects.list` | `client.portal.projects.read` |
| `/projects` | `client.projects.list` | `client.portal.projects.read` |
| `/projects/:id` | `client.projects.detail` | `client.portal.projects.read` |
| `/projects/:id/tasks` | `client.projects.detail.tasks` | `client.portal.tasks.read` |
| `/tasks/:id` | `client.tasks.detail` | `client.portal.tasks.read` |
| `/account` | `account.profile` | session |
| `/account/password` | `account.security.password` | session |
| `/account/security` | `account.security.mfa` | session |
| `/account/sessions` | `account.sessions` | session |

`/bootstrap` **does not exist in the portal build.** It is one-time owner creation and
belongs to the internal target only.

The portal's route table contains no route whose name references a project manager, a
department, a role, a permission, an audit event, a setting, an invitation or another
client. Its 404 handler renders the portal's own not-found screen; it never falls
through to anything that reveals a route it does not serve.

### Public route rule

The six public routes are the only ones reachable with no session, matching the pinned
anonymous API surface. Everything else redirects to `/login` with the attempted path
retained for post-login return — **except** paths that do not exist in that build,
which go to `/` rather than being remembered.

---

## 3. Session lifecycle as the UI sees it

```
                 ┌──────────────┐
                 │ anonymous    │  only the public routes exist
                 └──────┬───────┘
                        │ POST /auth/login  → 200 { access_token, refresh_token,
                        │                          expires_in, mfa_required }
              ┌─────────┴──────────┐
              │                    │
   mfa_required = true   mfa_required = false
              │                    │
              ▼                    │
      ┌───────────────┐            │
      │ MFA-PENDING   │            │
      │ only /auth/*  │            │
      └───────┬───────┘            │
              │ POST /auth/mfa/verify                    (or recovery/verify,
              │ or totp/setup → totp/activate             for first enrolment)
              ▼                    │
        ┌─────────────────────────┴────┐
        │ FULL SESSION                  │  the application exists
        └──────┬────────────────────────┘
               │ 401 → re-authenticate      403 MFA_REQUIRED → back to MFA-PENDING
               │ POST /auth/logout          POST /auth/logout-all
               ▼
        ┌──────────────┐
        │ anonymous    │
        └──────────────┘
```

### 3.1 Login

`POST /api/v1/auth/login` returns `200` with `{ access_token, refresh_token,
expires_in, mfa_required, token_type }` on success and `401 AUTHENTICATION_FAILED` on
every failure mode there is — unknown account, wrong password, suspended user, archived
user. The UI **must not try to distinguish them**. The undifferentiated response is a
deliberate anti-enumeration control (`07-api-contract.md` §2); a client that infers
"this account may not exist" from timing or wording defeats it.

A `200` with `mfa_required = true` is **not a login failure and not a full session**.
It is a real session in the pending state.

### 3.2 MFA-pending mode

While `pending_mfa = true`, the backend rejects everything except `GET /auth/me`,
`POST /auth/mfa/totp/setup`, `/totp/activate`, `/verify`, `/recovery/verify` and
`POST /auth/logout`. Everything else is `403 MFA_REQUIRED`.

The UI must mirror this exactly:

1. **Only the MFA screens are reachable.** No shell, no navigation, no menu, no
   background polling, no prefetch, no capability-driven rendering. A pending session
   is not "logged in with some things hidden" — it is a session that can do three
   things.
2. `GET /api/v1/auth/me` returns the **reduced projection** (`PendingMfaMeResponse`).
   It has no `capabilities` field and no `auth_level`. Code that assumes `capabilities`
   is present will crash here; the two projections are different types and must be
   handled as such.
3. `next_action` selects the screen: `MFA_ENROLLMENT_REQUIRED` → `auth.mfa.enrol`,
   `MFA_VERIFICATION_REQUIRED` → `auth.mfa.verify`.
4. Sign out is available and works. It is the only escape that is not completing MFA.
5. Attempting a business request from this state is a **client bug**, not a
   recoverable condition. Handle the `403 MFA_REQUIRED` (§4) but treat it as evidence
   that something bypassed the routing guard.

Refreshing the browser while pending must land back in MFA-pending mode, not at login
and not in the app.

### 3.3 Full session

After `POST /auth/mfa/verify` (or `recovery/verify`, or `totp/activate` for a first
enrolment), the session reaches `auth_level = MFA` and `step_up_active = true`. Fetch
the full `/auth/me`, build the menu from `capabilities`, and route to the originally
requested path if one was retained, otherwise to the application root.

For a user with `mfa_required = false` and no enrolled factor, login yields a full
session immediately at `auth_level = PASSWORD`. Such a session **cannot satisfy
step-up**, so every dangerous operation will refuse. That is correct — the backend
mandates enrolment for anyone holding a dangerous permission — and the UI should point
these actors at `account.security.mfa` rather than looping a prompt they cannot answer.

### 3.4 Session end

| Cause | UI response |
| --- | --- |
| `POST /auth/logout` | discard tokens, return to `/login` |
| `POST /auth/logout-all` | same; report `revoked_sessions` first |
| Password changed elsewhere | this session was revoked; next request is `401` |
| Suspended or archived by an administrator | next request is `401`; the check is a join in the session query, so it takes effect immediately |
| `absolute_expires_at` reached (30 days) | refresh fails; re-authenticate. No amount of refreshing extends it |
| `idle_expires_at` reached (7 days) | same |
| Refresh reuse detected | the **entire session family** is revoked; re-authenticate. See §5 |

---

## 4. Failure taxonomy — what each response means for navigation

The four failures below look similar and mean entirely different things. Getting them
confused produces either a redirect loop or a silently discarded edit.

### `401 AUTHENTICATION_FAILED` — the session is gone

The token is expired, revoked, malformed, or belongs to a user who is no longer
`ACTIVE`. All of these produce the identical response, deliberately.

Response: attempt **one** serialised refresh (§5). If it succeeds, retry the original
request once. If it fails, discard both tokens, clear all cached state including
capabilities, and go to `/login` retaining the attempted path.

Do not retry more than once. Do not retry the refresh. A `401` on the refresh endpoint
means re-authentication, full stop.

### `403 MFA_REQUIRED` — the session is real but pending

The session exists and is valid; it has not completed a second factor. Response: leave
the application, enter MFA-pending mode, route by `next_action` from the reduced
`/auth/me`. Do **not** discard tokens — the access token is exactly what the MFA
endpoints need. Do **not** go to `/login`; the actor has already proved their password
and sending them back is both confusing and an extra Argon2id verification.

After successful verification, resume: re-fetch `/auth/me` in full and return to the
path that was interrupted.

### `403 STEP_UP_REQUIRED` — the session needs a *recent* second factor

`mfa_verified_at` is outside `AUTH_STEP_UP_WINDOW_SECONDS`. The body carries
`step_up.window_seconds`.

Response: raise `step-up-prompt`, collect a TOTP code, call
`POST /api/v1/auth/mfa/verify`, then **retry the original request unchanged** — same
method, same path, same body, same `version`, same `Idempotency-Key`. Never navigate
away and never discard the draft; losing a half-completed role definition to a
ten-minute window is the fastest way to make people stop using step-up-protected
features properly.

The client does **not** predict which operations need step-up. The authoritative list
is server-side and asserted against the route table by test. Attempt, handle the
refusal, retry.

### `409 VERSION_CONFLICT` — someone else edited it

The `version` sent is stale. The body carries `expected` and `actual`.

Response: re-read the record, present what changed between the version the actor edited
and the current one, and let them re-apply their intent onto the fresh record. Then
resubmit with the **new** `version`.

Never auto-merge. Never resubmit with `actual` to "make it work" — that is a
last-write-wins overwrite wearing a conflict handler's clothes, and it silently
destroys the other person's change. The whole point of the `version` column is that
nothing is overwritten silently (`07-api-contract.md` §4).

### Others worth naming

| Response | Navigation effect |
| --- | --- |
| `403 AUTHORIZATION_DENIED` | stay put; render the region as unavailable. Never redirect — a redirect on `403` makes deep links unusable for anyone with narrow scope |
| `403 ROOT_PROTECTED` | stay put; explicit refusal; not retryable |
| `403 DELEGATION_DENIED` | stay in the form; the actor cannot grant authority they do not hold |
| `404 RESOURCE_NOT_FOUND` | workspace: "no longer exists", offer the parent list. Portal: see `05-client-portal-boundary.md` — never mention permissions |
| `429 RATE_LIMITED` | stay put; honour `Retry-After`; never auto-retry in a loop |
| `503 SERVICE_UNAVAILABLE` | stay put; retry with backoff; do not sign the actor out |

---

## 5. Refresh must be serialised — read this twice

> **Two concurrent calls to `POST /api/v1/auth/refresh` end the session.**

Rotation is unconditional. Every successful refresh consumes the presented refresh
token and invalidates the previous access token. Consumed refresh rows are **retained**
specifically so that reuse can be detected, and a hit on a consumed row is treated as
compromise: the backend revokes the **entire session family**, revokes every unconsumed
token in it, audits `AUTH.REFRESH_REUSE_DETECTED`, and returns `401`.

The `SELECT … FOR UPDATE` in the refresh transaction makes this deterministic rather
than racy: of two concurrent refreshes, exactly one wins and the loser is classified as
reuse. This is stricter than a merely racy client deserves, and the strictness is
intended — a spurious re-login is a smaller harm than an undetected persistent session.

**This is the single easiest way to break the application.** The failure mode is
particularly nasty because it is intermittent and load-dependent: it appears when an
access token expires while several requests happen to be in flight, which is exactly
when a real user is doing something. It will not reproduce in a quiet development
session.

### The required implementation

There is exactly one refresh in flight per token holder, ever.

```
refresh_mutex: a single-slot promise/lock owned by the transport layer

on 401 for request R:
    if refresh_mutex is empty:
        refresh_mutex := start refresh(current_refresh_token)
    await refresh_mutex          ← every concurrent 401 awaits the SAME promise
    if it succeeded: retry R once with the new access token
    else:            discard tokens, go to /login
    (the first awaiter to finish clears refresh_mutex)
```

Non-negotiable rules:

1. **One refresh at a time, process-wide.** Not per request, not per screen, not per
   query client. A second `401` arriving during a refresh **waits** for the in-flight
   one; it does not start its own.
2. **One holder of the refresh token.** In the browser architecture that is the BFF
   (`03-authentication.md` §11), which holds the tokens server-side. If the BFF runs as
   more than one process or instance, the serialisation must be across instances, not
   per instance — otherwise two instances refresh the same family concurrently and kill
   it. A shared lock or session affinity is required before horizontal scaling, and
   this is a release gate, not a nice-to-have.
3. **Never refresh proactively from more than one place.** A background timer that
   refreshes on a schedule *and* a `401` handler that refreshes on demand are two
   racing refreshers. Pick one. Prefer reactive-on-`401`.
4. **Never retry a failed refresh.** A `401` from `/auth/refresh` may mean the family
   is already dead. Retrying with the same token is a *second* reuse hit against an
   already-revoked family and produces another audit event for the same incident.
5. **Never refresh on any status other than `401`.** A `403` of any kind is not an
   authentication problem, and refreshing on it accomplishes nothing except burning a
   rotation.
6. **Discard the old refresh token the instant a new one is received.** Keeping both
   and picking the wrong one is reuse.
7. **On refresh failure, clear everything**: both tokens, cached `/auth/me`,
   capabilities, `security_version`, and any in-memory record state. A stale capability
   set outliving its session is a correctness bug waiting to be a security one.
8. **Do not put the refresh token in local storage, a URL, a query parameter, a log
   line, or an error report.** Bearer header only; a token-looking query parameter is
   rejected by the API with `TOKEN_IN_QUERY_STRING`.

### Test it deliberately

Fire five business requests simultaneously against an expired access token. The correct
result is one refresh call, five successful retries, and a session that is still alive.
Anything else — five refresh calls, or a session that is now dead — is the bug this
section exists to prevent.

---

## 6. Capabilities, `security_version`, and what they do and do not do

### What `/auth/me` gives the UI

```jsonc
{
  "user_id": "…", "email": "…", "display_name": "…",
  "principal_type": "INTERNAL", "is_root": false,
  "security_version": 7, "session_id": "…",
  "auth_level": "MFA", "mfa_enrolled": true, "mfa_required": true,
  "mfa_pending": false, "step_up_active": false,
  "capabilities": [ { "permission": "projects.read", "scopes": ["ASSIGNED"] } ]
}
```

The UI uses it for four things and no others:

1. **Menu construction.** A nav group renders if the actor holds at least one
   permission used inside it.
2. **Affordance rendering.** `gated-action` reads `capabilities` to decide whether to
   render a button.
3. **Scope-aware empty states.** An actor holding `projects.read@ASSIGNED` who sees an
   empty project list is seeing "you are on no projects", not "there are no projects".
   The `scopes` array is what makes that message possible.
4. **Pre-warning about step-up.** `step_up_active = false` on a dangerous action means
   a prompt is likely. It is a courtesy, not a decision.

### The warning, stated plainly

> **Capabilities are cosmetic. The backend enforces independently and does not consult
> them.**

There is no cache. Effective permissions are recomputed from the database on every
request that needs them — two indexed queries, joined (`04-authorization.md` §11). The
client's belief about its own authority is never sent, never read and never trusted.
Beyond the permission evaluation there is a second, redundant layer for CLIENT
principals: the visibility predicate is compiled into the SQL, so an invisible row is
never selected even if the evaluator were wrong.

Consequences for the builder:

- Hiding a button prevents confusion; it prevents nothing else.
- Every screen must behave correctly when reached by typing its URL. Render, request,
  receive `403`, show the `forbidden` state. A screen that assumes it was only reached
  through a menu is broken.
- Never re-implement the delegation lattice, the scope-derivation rules or the
  step-up list in the client. They are enforced server-side, they change with the
  backend, and a client-side copy will be wrong in one direction or the other.
- `capabilities` cannot express `RESOURCE`-scoped overrides, so it is structurally
  incomplete. Optimistic rendering plus a real `403` is the only correct posture.
- For a CLIENT principal, `capabilities` can only ever contain the two
  `client.portal.*` codes — asserted by a property test over random grants. The portal
  should assert this on receipt and treat a violation as a fatal condition, not render
  whatever arrived.

### `security_version` — the re-fetch signal

`users.security_version` is bumped on **every** privilege change: role assignment and
unassignment, role permission edits, override creation and removal. It is returned by
`/auth/me` and appears on `UserResponse`.

The UI treats a change in it as the signal that its capability set has moved:

1. Cache `security_version` alongside the capability set.
2. Compare on every `/auth/me` — at minimum on application start, on return to
   foreground, after any step-up, and after any operation on `internal.users.*` or
   `internal.roles.*` that targets the actor themselves.
3. On change: re-fetch `/auth/me`, rebuild the menu, re-evaluate every `gated-action`,
   and re-run the current screen's primary read, because the actor's scope may have
   narrowed and the data on screen may no longer be within it.
4. Do **not** poll it on a timer. There is no dedicated endpoint, and polling `/auth/me`
   to watch a counter is a per-request permission recomputation for no reason. The
   backend takes effect on the very next request regardless; `security_version` exists
   so the *display* can catch up, not so authority can.

A privilege change that narrows the actor's scope takes effect on their next request
whether or not the UI noticed. If they were mid-edit, the save fails with `403` — which
is the correct outcome, and the `forbidden` state must explain it rather than looking
like a crash.

---

## 7. Navigation invariants

1. **Deep links work or fail cleanly.** Every route is reachable by URL. Unauthorised
   access renders `forbidden` in place; it does not redirect.
2. **Post-login return.** The attempted path is retained across login and MFA, and is
   honoured only if it exists in this build.
3. **MFA-pending is a mode, not a screen.** The router refuses every other route while
   the session is pending.
4. **Tabs are routes.** Project tasks, team, and client access are addressable URLs, not
   local component state — they are separate reads with separate permissions and
   separate failure states.
5. **Cursors are not in the URL; filters and sort are.** A filtered view is shareable;
   a cursor is a position in a particular ordering and is meaningless once anything
   changes.
6. **Dirty forms block navigation** with a confirmation, including a step-up prompt
   arriving mid-edit.
7. **No cross-application links.** The workspace never links to a portal URL and the
   portal never links to a workspace URL. They are different origins with different
   principals; a link between them is either broken or a boundary violation.
