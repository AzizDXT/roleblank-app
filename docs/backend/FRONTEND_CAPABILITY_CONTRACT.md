# Frontend capability contract

What `GET /api/v1/auth/me` returns, and the exact limits on what a frontend may do
with it.

Source: `backend/src/modules/authentication/dto.rs` (the response types),
`backend/src/modules/authentication/service.rs::me` (which projection is chosen),
`backend/src/modules/authorization/evaluator.rs::capability_list` (how the
capability list is built).

## The one rule

**The backend is authoritative. `capabilities` is a hint for hiding buttons and
nothing else.**

Every authorisation decision is re-derived from the database on every single
request. There is no cache: `principal::load_actor` re-reads the actor's roles,
overrides, department memberships and client memberships on each call, and
`evaluator::evaluate` runs again. Nothing about a request's outcome depends on what
the client believes.

Concretely, a frontend may use `capabilities` to decide **visibility** — whether to
render a button, a menu entry, a tab, a column. It may not use `capabilities` to
decide **correctness**: never skip a call because the hint says it would fail,
never treat a hint as proof an action succeeded, and never assume an action shown
will be permitted. A `403 AUTHORIZATION_DENIED` on a control you rendered is a bug
in your visibility logic, not a user error — but the backend refusing it is the
system working.

`capabilities` is also **coarser than the real decision**. It reports which
permissions the actor holds and at which scope *types*, not which objects those
scopes reach. Holding `projects.update` at `DEPARTMENT` tells you the button may be
worth rendering; it does not tell you the actor can edit *this* project. Object-level
decisions are taken against the loaded row and are not predictable client-side.

## Access

`GET /api/v1/auth/me` uses the `MfaPendingSession` extractor, so **a session that
has not completed MFA can call it**. That is deliberate: a client stuck in
`MFA_ENROLLMENT_REQUIRED` must be able to discover why. It is one of only a handful
of endpoints reachable in that state (the others being the `/auth/mfa/*` endpoints
and `/auth/logout`).

Requires: a valid bearer access token. Returns `200` on success, or `401
AUTHENTICATION_FAILED` if the token is invalid, expired or revoked.

## Two projections, one URL

The response is an untagged enum, so there is no wrapper object — the client sees
one of two flat shapes and must discriminate on `mfa_pending`.

### Full projection — `mfa_pending: false`

| Field | Type | Meaning |
|---|---|---|
| `user_id` | UUID | The authenticated user. |
| `email` | string | The user's own address, as stored (not the normalised form). |
| `display_name` | string | |
| `principal_type` | `"INTERNAL"` \| `"CLIENT"` | The security envelope. Fixed at account creation; **cannot** be changed by role assignment. A `CLIENT` can only ever hold `client.portal.*` permissions, whatever it is granted. |
| `is_root` | bool | True only for the single system owner. Root bypasses *permission evaluation* — not authentication, not the session checks, not MFA, not step-up. |
| `security_version` | int | Incremented whenever this user's authority changes. See "Detecting a stale capability set" below. |
| `session_id` | UUID | The current session. Safe to expose — it is not a credential, and the access-token digest is not derivable from it. Used to mark the current row in the session list. |
| `auth_level` | string | The session's authentication level as recorded on the session row. |
| `mfa_enrolled` | bool | Whether the account has an active second factor. |
| `mfa_required` | bool | Whether the account is *obliged* to hold one. When true, MFA cannot be disabled (`POST /auth/mfa/disable` answers `409 MFA_MANDATORY`). |
| `mfa_pending` | bool | Always `false` in this projection. |
| `step_up_active` | bool | Whether a second factor was verified inside the configured step-up window. **Recomputed on every call** from `sessions.mfa_verified_at`; never a stored flag, so it goes false on its own as the window closes. |
| `capabilities` | array of `{permission, scopes}` | The hint. See below. |

### Reduced projection — `mfa_pending: true`

A physically smaller type, not the same struct with fields hidden. A session that
cannot call a business endpoint has no business learning which business endpoints
it would be allowed to call.

| Field | Type | Meaning |
|---|---|---|
| `user_id`, `email`, `display_name`, `principal_type`, `security_version`, `session_id`, `mfa_enrolled`, `mfa_required` | as above | |
| `mfa_pending` | bool | Always `true`. |
| `step_up_active` | bool | Always `false` — a pending session has never verified a factor. |
| `next_action` | `"MFA_ENROLLMENT_REQUIRED"` \| `"MFA_VERIFICATION_REQUIRED"` | Which of the two MFA flows to start. |

**Absent from this projection: `capabilities`, `is_root`, `auth_level`.** Do not
write client code that reads them without first checking `mfa_pending`.

## The capability list

```json
"capabilities": [
  { "permission": "projects.read",   "scopes": ["GLOBAL"] },
  { "permission": "tasks.update",    "scopes": ["DEPARTMENT", "ASSIGNED"] }
]
```

* `permission` is a code from the catalogue (see `PERMISSION_CATALOG.md`).
* `scopes` is the list of scope types the actor effectively holds for it, after
  denials. Values: `GLOBAL`, `DEPARTMENT`, `ASSIGNED`, `SELF`, `RESOURCE`. Note the
  wire name is `SELF`.
* A permission with **no** effective scope is omitted entirely — the list contains
  only what is held. Absence means "do not render".
* The list is built from `evaluator::effective_scopes`, which already applies the
  principal envelope and removes anything killed by a `GLOBAL` DENY override. A
  *narrower* DENY is not reflected here — it is applied per object at decision
  time. So the hint can be **wider** than reality, never narrower in the GLOBAL
  case.
* **For the system owner (`is_root: true`) the list is `[{permission, ["GLOBAL"]}]`
  for every permission in the catalogue.** Do not read that as "these are grants";
  root bypasses evaluation.

### Using it for visibility

```
render(action) := capabilities.some(c => c.permission === action.permission)
```

That is the whole of the sanctioned logic. `FRONTEND_ACTION_CATALOG.md` gives the
permission for every user-actionable operation, so a single lookup table drives
every menu.

Refinements you may add, none of which change the rule above:

* If an action's `scopes` contains only `SELF`, render it on the user's own row.
* If an action is marked step-up in the action catalogue, render it but expect
  `403 STEP_UP_REQUIRED` and be ready to run the MFA prompt and replay.
* If `principal_type` is `CLIENT`, render only the client-portal surface. The
  backend enforces this independently at the envelope, before any grant is read.

## Detecting a stale capability set

`security_version` is bumped in the same transaction as any change to a user's
authority (role assigned or unassigned, override created or removed, department or
client membership changed, lifecycle status changed). Nothing depends on it for
correctness today, but it is the signal a client uses to notice its own capability
set moved.

Recommended: re-fetch `/auth/me` on window focus and after any 403, and compare
`security_version`. If it changed, re-derive every visibility decision. Do not poll
it aggressively — it is one row read per call, but every call also costs the actor
load (three queries).

Capabilities also change without `security_version` moving: `step_up_active` decays
with the clock. Never cache `step_up_active`; re-read it, or simply react to
`403 STEP_UP_REQUIRED`.

## Feature flags — **not** in this response

`/auth/me` carries no feature-flag information. Verified: the response DTO has no
such field. Flags come from two other places:

| Source | Auth | Contents | Caveat |
|---|---|---|---|
| `GET /api/v1/system/info` | any authenticated session (no permission checked) | `environment`, `initialized`, `enabled_features` — a flat list of enabled flag keys | See the warning below. |
| `GET /api/v1/feature-flags` | requires `settings.read` (INTERNAL only) | Full flag rows including `is_security_sensitive`, `description`, `version` | Administrative surface, not a client bootstrap. |
| `GET /api/v1/registration/config` | anonymous | `registration_available`, `registration_type` | The only pre-login configuration surface. See `REGISTRATION_CONTRACT.md`. |

## What should NOT be exposed further

Flagged for the frontend to handle carefully. None of these is a backend defect
except where noted.

1. **`GET /api/v1/system/info` performs no permission check and no principal-type
   reduction.** The handler ignores its principal. An external `CLIENT` principal
   receives the same `environment` string and the same list of enabled feature-flag
   keys as an administrator. The query does exclude `is_security_sensitive` flags,
   so the disclosure is bounded to enabled *non-sensitive* keys — but that bound is
   a query filter, not an enforced rule. A frontend must not treat this endpoint as
   an internal-only surface, and should not surface `enabled_features` in a
   client-portal experience. See `ROUTE_SECURITY_MATRIX.md` §14.3.
2. **Do not forward `/auth/me` to third-party services.** `email` and
   `display_name` are personal data; `capabilities` is a map of the actor's
   authority. Neither belongs in an analytics payload, a client-side error tracker's
   breadcrumbs, or a URL.
3. **Do not put `session_id` or `user_id` in a URL or a page title.** They are not
   credentials, but query strings reach access logs, browser history and `Referer`
   headers. The backend already refuses tokens in query strings outright
   (`400 BAD_REQUEST`) for exactly this reason.
4. **Never persist the access token where `/auth/me` output is persisted.** The
   access and refresh tokens are returned only by `POST /auth/login` and
   `POST /auth/refresh`; `/auth/me` deliberately contains no token material and no
   digest of one.
5. **`is_root` is a display fact, not a switch.** Do not build "root mode" client
   logic around it. The one place it legitimately drives UI is disabling controls
   that target the owner, since those always answer `403 ROOT_PROTECTED`.
6. **The capability list is per session, not per tab.** After MFA verification,
   after a role change, or after switching accounts, discard it and re-fetch.
