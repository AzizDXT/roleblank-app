# Registration contract

How accounts come into existence, what the frontend may render, and what happens
when the policy changes underneath an open page.

Sources: `backend/src/modules/identity/registration.rs`,
`backend/src/modules/identity/invitations.rs`,
`backend/src/modules/settings/service.rs`,
`backend/migrations/0008_seed_catalog.sql`.

## Verified fact: self-registration is DISABLED by default

A freshly migrated database seeds `registration.mode` to `"INVITE_ONLY"`:

```sql
-- migrations/0008_seed_catalog.sql
('registration.mode', '"INVITE_ONLY"'::jsonb, 'ENUM', true,
 'DISABLED | INVITE_ONLY | CLIENT_SELF_REGISTRATION. ...')
```

`INVITE_ONLY` does **not** allow self-registration — only
`CLIENT_SELF_REGISTRATION` does. A fresh installation therefore accepts no
anonymous signup until an operator deliberately turns it on, and the code has a
test asserting exactly that.

The setting is `is_security_sensitive = true`, so changing it requires
`settings.security.write`, which is a **dangerous** permission and therefore also
requires a recent step-up.

## The three modes

There are exactly three, parsed by an exact-case closed enum
(`RegistrationMode::parse`).

| Mode | Self-registration | Render a signup form? | Who can self-register | Initial lifecycle status | Approval required |
|---|---|---|---|---|---|
| `DISABLED` | no | **no** | nobody | — | — |
| `INVITE_ONLY` | no | **no** | nobody — accounts arrive only by invitation | — | — |
| `CLIENT_SELF_REGISTRATION` | yes | **yes** | external users only; the account is created as `principal_type = CLIENT` | `PENDING` | **yes** — an internal principal must both activate the account and link it to a client account before it can see anything or sign in |

Anything else — a mis-cased value, a value with trailing whitespace, a boolean, a
number, a JSON object, a missing row, or an unreadable database — resolves to
`DISABLED`. That is the fail-closed rule: a misconfigured registration policy must
never default to "open to the internet". An unrecognised stored value additionally
emits an `error!` log line.

A database read failure while resolving the mode is **not** propagated as a 500;
it is reported as `DISABLED`, so an outage cannot accidentally open registration
and `/registration/config` truthfully answers "closed".

## `GET /api/v1/registration/config` — the only pre-login configuration surface

Anonymous. No rate limiter on this route. Two fields and nothing more — a frontend
needs to know whether to render a signup form; it does not need the user count, the
invitation policy or the build id, and this endpoint answers to the open internet.

```json
{ "registration_available": false, "registration_type": null }
```

| Field | Type | Meaning |
|---|---|---|
| `registration_available` | bool | `true` only in `CLIENT_SELF_REGISTRATION`. |
| `registration_type` | `"client"` \| `null` | `"client"` when available, `null` otherwise. Self-registration can only ever produce a `CLIENT` principal, so there is no other value this field can take. |

**Notice what is absent**: the mode name itself is not disclosed. A frontend cannot
tell `DISABLED` from `INVITE_ONLY` from this endpoint, and must not try to.

### How a frontend should use it

* Fetch it on the login screen before rendering.
* `registration_available: false` → do not render a signup link, a signup form, or
  a "create account" route. Render only sign-in and password-reset.
* `registration_available: true` → render the client signup form, and label it
  honestly as a client/customer account.
* Treat a failure of this call as `false`. That matches the backend's own
  fail-closed behaviour.

## `POST /api/v1/registration` — anonymous client self-registration

Body: `email`, `display_name`, `password`. There is deliberately no fourth field —
`principal_type = CLIENT`, `status = PENDING` and the `client_user` role are
literals in code, and `deny_unknown_fields` rejects a body that tries to set them.

**The response never varies.** Free address, already-registered address, address
belonging to an employee — one response, byte for byte:

```
202 Accepted
{ "registration_status": "SUBMITTED",
  "message": "If this address can be registered, the account is now pending review by the company." }
```

A `201` for a new account and a `409` for a duplicate would be an
account-enumeration oracle spelled in status codes. The password is also hashed
unconditionally *before* the address is looked up, so the duplicate path is not
measurably faster than the new-account path.

Failure modes a client can see:

| Status | `code` | Meaning |
|---|---|---|
| 404 | `RESOURCE_NOT_FOUND` | Self-registration is not enabled. **The endpoint does not exist** rather than being refused — advertising a disabled capability tells an attacker which setting to go after. |
| 400 | `VALIDATION_FAILED` | Email format, display-name length, or password policy (`TOO_COMMON`, `CONTAINS_IDENTITY`, `TOO_SHORT`). |
| 429 | `RATE_LIMITED` | Three per IP per hour by default (`register:ip:{ip}`), with `Retry-After`. |

### What the new account can actually do

Nothing, until a human acts.

* `status = PENDING`, `activated_at` stays `NULL`. **No session can be issued**
  until an internal principal reviews and activates the account — the login query
  requires `users.status = 'ACTIVE'`.
* It receives exactly one role, `client_user`, which carries
  `client.portal.projects.read` and `client.portal.tasks.read` at `ASSIGNED` scope.
* It joins **no** client account. `client_memberships` is deliberately not written.
  Portal visibility resolves through an **ACTIVE** client membership joined to a
  live project link, so a self-registered account sees an empty world.

So the operator's activation path is two distinct steps, each with its own
permission: reactivate the user (`iam.users.suspend`) and add + activate a client
membership (`clients.members.manage`). A frontend building an approval queue needs
both.

An audit event is written either way: `USER.REGISTERED` with `Outcome::Success` on
a real registration, and `USER.REGISTERED` with `Outcome::Denied` and
`reason = address_already_registered` on a duplicate — so somebody grinding
addresses through this endpoint is visible in the audit log even though the caller
learns nothing.

## The other two ways an account is created

Self-registration is **not** the main path. For completeness:

| Path | Endpoint | Auth | Resulting principal | Initial status | MFA |
|---|---|---|---|---|---|
| Bootstrap | `POST /api/v1/bootstrap/root` | anonymous, but requires the operator secret `RB_BOOTSTRAP_SECRET` | `INTERNAL`, and the single system owner | `ACTIVE` | `mfa_required = true`, `mfa_enrolled = false` — the owner's first session is `pending_mfa` and can reach nothing but the MFA endpoints |
| Invitation | `POST /api/v1/invitations` then `POST /api/v1/invitations/accept` | issuing requires `iam.users.invite`; accepting is anonymous and carries the token in the **body**, never the URL | whatever the invitation says (`INTERNAL` or `CLIENT`), taken from the invitation and never from the acceptance request | `ACTIVE` | `mfa_required = true` when any invited role carries a dangerous permission |

Invitation acceptance returns `201` with
`{user_id, email, display_name, principal_type, status, mfa_enrolment_required}`
and **no session and no token** — the invitee then signs in through the ordinary
login path, which is also where MFA enrolment is enforced. A frontend must route
from "invitation accepted" to the login screen, not into an authenticated shell.

Every acceptance rejection reason — unknown token, already accepted, revoked,
expired, inviter no longer authorised — returns the same `401
AUTHENTICATION_FAILED`. Do not attempt to distinguish them.

Acceptance has its own rate-limit budget (`invite-accept:ip:{ip}`, 20/hour by
default), deliberately **separate** from self-registration's, so an attacker
hammering `/api/v1/registration` from a shared corporate NAT cannot block onboarding
for everybody behind that address.

## What happens if the mode changes while a page is open

The mode is read fresh from the database on **every** call to
`/registration/config` and on every call to `POST /registration`. Nothing is
cached, in the backend or in the token.

Consequences a frontend must handle:

1. **Signup form open, mode switched off.** The `POST` answers `404
   RESOURCE_NOT_FOUND`. Render this as "signup is not available here" and route to
   sign-in — **not** as "something went wrong". Do not retry.
2. **Login screen open, mode switched on.** The signup link simply will not be
   there until `/registration/config` is fetched again. Re-fetch it on window focus
   or on navigation to the auth screens; a long-lived login tab is the realistic case.
3. **A submission in flight when the mode flips.** The check runs after the rate
   limiter and before any validation, inside the request, so the outcome is
   whichever value was committed at that moment. There is no partial state: either
   the account was created or nothing was written.
4. **The mode never affects an existing session.** It governs account creation
   only. Turning registration off does not suspend or invalidate accounts that were
   already created under it.

Recommended client behaviour: treat `registration_available` as a short-lived
value with a small TTL (or no cache at all — the endpoint reads one row), never
persist it, and always let the `404` from `POST /api/v1/registration` be the
authority over what the config endpoint said a moment ago.

## Changing the mode (administrative)

`PUT /api/v1/settings/registration.mode`

```json
{ "value": "CLIENT_SELF_REGISTRATION", "version": 1 }
```

* Requires `settings.security.write` (dangerous → recent step-up required), because
  the row is `is_security_sensitive`.
* `value` must be a JSON **string** and must be one of the three exact-case modes;
  anything else is `400 VALIDATION_FAILED` with field code `INVALID_VALUE` or
  `INVALID_TYPE`.
* `version` is mandatory. A stale one is `409 VERSION_CONFLICT`. See
  `CONCURRENCY_CONTRACT.md`.
* Audited as `SETTING.CHANGED`. Because the row is security-sensitive, the audit
  record names the key and the actor but **not** the old or new value.
