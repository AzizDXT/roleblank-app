# Frontend error contract

Every machine-actionable error the backend actually returns, enumerated from
`backend/src/platform/errors/mod.rs` (the `AppError::code()` match is the
authority) plus the two error paths that bypass `AppError`.

## The two rules the backend commits to

1. **Branch on `code`, never on prose.** `code` is a stable SCREAMING_SNAKE
   identifier and is part of the API contract. `title` and `detail` are human text
   and may be reworded at any time. Never parse `detail`.
2. **`detail` never carries an internal fact.** No SQL, no stack trace, no file
   path, no hostname. When something fails internally the client gets a fixed
   sentence and a `request_id` to quote.

## The envelope

Every error is `application/problem+json` (RFC 9457) with `Cache-Control:
no-store`:

```json
{
  "type": "https://roleblank.internal/problems/version_conflict",
  "title": "The resource was modified by someone else",
  "status": 409,
  "code": "VERSION_CONFLICT",
  "detail": "Expected version 3 but the current version is 5. Re-read the resource and retry.",
  "request_id": "0198f3a1-6b7c-7f2a-9c31-2b4d5e6f7a8b",
  "version_conflict": { "expected": 3, "actual": 5 }
}
```

* `type` is derived mechanically as the base URI plus the lowercased `code`. It is
  **not** a live URL and must never be fetched.
* `request_id` is present whenever the request passed the request-id middleware.
  Surface it in any "something went wrong" state — it is the only handle support
  has. A client may also *supply* `X-Request-Id`; it is adopted only if it is 8–64
  characters of `[A-Za-z0-9_-]`, and the adopted value is echoed on the response.
* Three optional members appear only for specific codes:
  * `errors` — an array of `{field, code, message}`, only on `VALIDATION_FAILED`.
  * `step_up` — `{window_seconds}`, only on `STEP_UP_REQUIRED`.
  * `version_conflict` — `{expected, actual}`, only on `VERSION_CONFLICT`.

`Retry-After` is set as a response header on `RATE_LIMITED` and nowhere else.

## The catalogue

"Retryable" below means: retrying the identical request unchanged may succeed.

| `code` | HTTP | Meaning | Retryable | What the frontend should do | User-facing guidance |
|---|---|---|---|---|---|
| `VALIDATION_FAILED` | 400 | One or more body or path fields are invalid. `errors[]` names them. | No — not without changing the payload | Map each `errors[i].field` onto the form control and render `errors[i].message`. Branch on `errors[i].code`, not on the message. Never assume a field maps to a control — an unrecognised `field` should fall back to a form-level message. | "Please check the highlighted fields." |
| `BAD_REQUEST` | 400 | The request could not be understood: malformed JSON, an unrecognised body field (every DTO is `deny_unknown_fields`), an unrecognised query parameter, an unrepresentable character such as a NUL byte, or an authentication token found in the URL. | No | This is a client bug in practice. Log it with the `request_id`; do not retry. If it fires on a query string, the client is sending a filter the endpoint does not accept — sending unknown filters is refused rather than ignored, so the user never sees an unfiltered list they believe was filtered. | "Something in this request was not understood. Please reload and try again." |
| `UNKNOWN_PERMISSION` | 400 | A permission code arrived that is not in the catalogue. Treated separately from validation because it means the caller is probing the authorisation surface, and it is audited as such. | No | Only reachable from role/override editors. Refresh the permission catalogue from `GET /api/v1/permissions` and re-render the picker. | "That permission is not recognised. Refresh the page and try again." |
| `AUTHENTICATION_FAILED` | 401 | The single, deliberately undifferentiated authentication failure: unknown account, wrong password, expired or malformed token, revoked session, suspended user, consumed reset link, invalid invitation token. | Sometimes — after obtaining a new token | On any authenticated call: attempt one refresh via `POST /api/v1/auth/refresh`; if that also returns 401, clear local session state and route to login. On a login/reset/invite-accept call: this is a credential failure — show the generic message and **do not** infer anything about whether the account exists. | Login: "Those details did not work." Session: "Your session has ended. Please sign in again." |
| `AUTHORIZATION_DENIED` | 403 | The principal's effective permissions do not allow this operation. | No | Do not retry. Re-fetch `GET /api/v1/auth/me` — the capability hint may be stale — and hide the control. Treat a 403 on an action whose button you rendered as a bug in your visibility logic, not as a user error. | "You do not have permission to do this." |
| `STEP_UP_REQUIRED` | 403 | The operation needs a second-factor verification within the last `step_up.window_seconds` seconds. | Yes — after completing step-up | Read `step_up.window_seconds` from the body. Open the MFA prompt, call `POST /api/v1/auth/mfa/verify` (or `/mfa/recovery/verify`), then **replay the original request**. If the original was a create carrying an `Idempotency-Key`, replay with the same key. | "Confirm it is you to continue." |
| `MFA_REQUIRED` | 403 | The session authenticated with a password but has not completed MFA, and this endpoint is not part of the MFA surface. | Yes — after completing MFA | Route to the MFA flow. Call `GET /api/v1/auth/me` (which a pending session *can* reach) and read `next_action`: `MFA_ENROLLMENT_REQUIRED` → enrolment, `MFA_VERIFICATION_REQUIRED` → verification. | "Set up or confirm two-factor authentication to continue." |
| `ROOT_PROTECTED` | 403 | The operation targeted the system owner. Never masked as a 404, even for external principals — the refusal must be impossible to misdiagnose. | No | Permanent for that target. Disable the control on the owner's row entirely rather than letting the user discover it. | "The system owner cannot be changed through the app." |
| `DELEGATION_DENIED` | 403 | The actor tried to grant authority it does not itself hold at that scope, or to modify its own privileges. `detail` carries a short, client-safe explanation written by the delegation guard. | No | Surface `detail` — it is the one 403 variant whose `detail` is written to be shown. Re-render the role/permission picker from the actor's own capabilities. | Show the returned `detail`. |
| `RESOURCE_NOT_FOUND` | 404 | The object does not exist **or is not visible to you**. Also what an external `CLIENT` principal receives in place of `AUTHORIZATION_DENIED`, so that a refusal cannot confirm an object's existence. Also returned by disabled capabilities: `/metrics` when metrics are off, `POST /api/v1/registration` when self-registration is off, `POST /api/v1/bootstrap/root` when no operator secret is configured. | No | Never present as "deleted" — it may be "not yours". Navigate away from the detail view and refresh the list. On the registration endpoint, treat it as "signup is not available here". | "That item is not available." |
| `VERSION_CONFLICT` | 409 | Optimistic concurrency: the `version` you sent is not the row's current version. `version_conflict.expected` is what you sent, `.actual` is what the row holds now. | Yes — after re-reading | See `CONCURRENCY_CONTRACT.md`. Re-read the resource, show the user what changed, and resubmit with the new version. Never auto-retry with `.actual` — that silently overwrites the other writer. | "Someone else changed this while you were editing." |
| `IDEMPOTENCY_KEY_REUSED` | 409 | The same `Idempotency-Key` arrived with a **different** request body. | No — not with this key | This is a client bug: generate a fresh key per distinct logical operation. Do not retry with the same key. | "That request could not be repeated safely. Please try again." |
| `IDEMPOTENCY_RACE` | 409 | An identical request with the same key is still in flight and did not finish inside the server's short wait window, or the reservation could not be taken. | Yes | Back off briefly (a second or two) and retry with the **same** key. | "Still working on your previous request." |
| `SYSTEM_ALREADY_INITIALIZED` | 409 | Bootstrap is permanently closed. | No | Only reachable from the first-run screen. Route to login. | "This system is already set up." |
| `UNIQUE_VIOLATION` | 409 | A database unique constraint rejected the write — a duplicate code, email, or membership that the service did not pre-check. | No — not unchanged | Treat as a field-level duplicate. The backend deliberately does **not** name the column, so map it from the form you submitted. | "Something with that name or code already exists." |
| `REFERENCE_VIOLATION` | 409 | A foreign key rejected the write: a referenced object does not exist, or is still in use. | No | Re-fetch the pickers that supplied the ids. | "One of the linked items is no longer available." |
| `INVARIANT_VIOLATION` | 409 | A database trigger refused the operation — the ROOT and client-envelope invariants. The trigger's own message is never forwarded. | No | Treat as permanent for that combination of inputs. Log with `request_id`. | "That change is not allowed." |
| *domain conflicts* | 409 | A named business-rule conflict. The full set the code can emit is listed below. | Varies — see the table | Branch on the specific code. | Per code. |
| `PAYLOAD_TOO_LARGE` | 413 | The body exceeded the configured limit (256 KiB by default). | No | Reduce what you send. Bounded text fields exist for exactly this reason. | "That is too large to send." |
| `UNSUPPORTED_MEDIA_TYPE` | 415 | The endpoint accepts `application/json` only. Sending a form or multipart encoding is refused — that refusal is also what keeps this API free of CSRF surface. | No | Client bug: always set `Content-Type: application/json`. | — (should never reach a user) |
| `RATE_LIMITED` | 429 | A rate limit was exceeded. Carries a `Retry-After` **header** in seconds; `detail` restates it. **Newly enforced in two general layers**: a per-principal budget keyed on the user id, charged inside the authentication extractor on every authenticated route (600/min by default, 3000/min for the system owner), and a coarse per-address ceiling applied before authentication on *every* request (3000/min). These are in addition to the tight dedicated limiters on login, refresh, password reset, registration, invitation acceptance, bootstrap and MFA. **Every route can now return 429.** | Yes — after `Retry-After` | Read the `Retry-After` header, disable the action for that many seconds, and retry once. Never retry in a tight loop. Show a countdown rather than a spinner. On login specifically, do **not** infer anything about the account from a 429 — the limiter is keyed on the submitted address whether or not it exists. | "Too many attempts. Try again in N seconds." |
| `INTERNAL_ERROR` | 500 | Something failed inside the backend. The cause is logged against `request_id` and never returned. | Rarely — the request may be non-idempotent | Do **not** auto-retry a non-idempotent write. Show the `request_id` and offer a manual retry. | "Something went wrong on our side. Quote reference {request_id}." |
| `SERVICE_UNAVAILABLE` | 503 | A dependency is unreachable (the database could not be talked to at all), or the request exceeded the server timeout. The request was well-formed and may succeed on retry. | Yes | Retry with exponential backoff, up to a small bound. This is the code that distinguishes "our bug" from "try again shortly" — 500 means stop, 503 means retry. | "The service is temporarily unavailable. Retrying…" |
| `METHOD_NOT_ALLOWED` | 405 | `TRACE` and `CONNECT` are refused by middleware. Rendered as problem+json by hand, without a `request_id`. | No | Unreachable from a correct client. | — |

### Two responses that are *not* problem+json

* `GET /health/ready` answers `503` with the plain body `{"status":"not_ready"}`.
  It carries no `code`. Probes read the status line, not the body.
* `GET /metrics` answers `200` with `text/plain`.

## Domain conflict codes (409)

These arrive in the `code` field exactly like the built-in ones. They come from
`AppError::conflict(...)` call sites and are the complete set in the code read.

| `code` | Where it comes from | Retryable | Frontend action |
|---|---|---|---|
| `EMAIL_IN_USE` | Creating an invitation, or changing a user's email, for an address that already has an account. **Not** emitted by anonymous registration, which is deliberately silent. | No | Field-level error on the email input. |
| `SELF_TARGET_REFUSED` | Suspending, reactivating or archiving your own account. | No | Disable the control on your own row. |
| `INVALID_STATUS_TRANSITION` | A user lifecycle move the state machine forbids. | No | Re-read the user and re-derive which actions are legal. |
| `INVALID_STATE_TRANSITION` | A project or task status move the state machine forbids. | No | Re-read the row; the allowed next statuses changed. |
| `ALREADY_ARCHIVED` / `DEPARTMENT_ALREADY_ARCHIVED` / `CLIENT_ALREADY_ARCHIVED` / `ALREADY_CANCELLED` | The object is already in the target state. | No | Treat as success-equivalent for UI purposes: refresh and move on. |
| `DEPARTMENT_ARCHIVED` / `CLIENT_ARCHIVED` / `PROJECT_ARCHIVED` / `TASK_CANCELLED` | Writing to an archived or cancelled parent. | No | Put the view into read-only mode. |
| `DEPARTMENT_HAS_LIVE_PROJECTS` | Archiving a department that still owns live projects. | No | Tell the user what must be cleared first. |
| `UNKNOWN_USER` | A named user id does not exist or is not eligible. | No | Re-fetch the user picker. |
| `ALREADY_A_MEMBER` / `ALREADY_ASSIGNED` / `ROLE_ALREADY_ASSIGNED` | Adding a membership or assignment that already exists. | No | Refresh the member/assignee list; the state is already what the user wanted. |
| `PRINCIPAL_TYPE_MISMATCH` | Placing an INTERNAL user into a client account, or a CLIENT user into a department. | No | Filter the picker by principal type. |
| `USER_ARCHIVED` / `SUBJECT_ARCHIVED` | Granting authority to, or placing, an archived account. | No | Exclude archived users from pickers. |
| `MEMBERSHIP_ALREADY_ACTIVE` / `MEMBERSHIP_ALREADY_REMOVED` / `MEMBERSHIP_REMOVED` / `MEMBERSHIP_CHANGED` | Client-membership transitions raced or are already in the target state. | `MEMBERSHIP_CHANGED`: yes, after re-reading. Others: no. | Re-fetch the membership list. |
| `CLIENT_ACCOUNT_NOT_ACTIVE` | Sharing a project with a client account that is not ACTIVE. | No | Filter the share picker to active accounts. |
| `EXTERNAL_PRINCIPAL` | An operation named an external (CLIENT) user where only an INTERNAL user is valid — e.g. as a project member or task assignee. | No | Filter pickers to INTERNAL users. |
| `ROLE_IN_USE` | Deleting a role that is still assigned. | No | Show who holds it first. |
| `INVITATION_NOT_PENDING` | Revoking an invitation that was already accepted or revoked. | No | Refresh the invitation list. |
| `MFA_ALREADY_ENROLLED` | Starting TOTP enrolment when an active factor exists. | No | Route to verify, not enrol. |
| `MFA_NOT_PENDING` | Activating a factor that is not in the pending state. | No | Restart enrolment. |
| `MFA_NOT_ENROLLED` | Regenerating recovery codes with no factor enrolled. | No | Route to enrolment. |
| `MFA_MANDATORY` | Disabling MFA on an account whose `mfa_required` is true. | No | Hide the disable control when `mfa_required` is true. |

## Field error codes (inside `errors[]` on `VALIDATION_FAILED`)

`errors[i].message` never echoes the rejected value — echoing it is how a
validation error becomes a reflection gadget. Do not expect your input back.

| `field.code` | Meaning |
|---|---|
| `REQUIRED` | Missing or empty. |
| `TOO_SHORT` / `TOO_LONG` | Outside the length bound. |
| `TOO_MANY` | An array exceeded its item bound. |
| `INVALID_FORMAT` | Failed a grammar (email, setting key, `Idempotency-Key`, date). |
| `INVALID_UUID` | A path or body identifier is not a UUID. |
| `INVALID` / `INVALID_VALUE` / `INVALID_TYPE` | Not one of the accepted values, or the wrong JSON type for a setting. |
| `INVALID_SCOPE` | A scope type that is not legal in this position (for example `RESOURCE` on a role). |
| `OUT_OF_RANGE` | A numeric or date value outside its bound. |
| `NOT_FOUND` | A referenced id in the body does not exist. |
| `NOT_ALLOWED` / `NOT_APPLICABLE` / `NOT_EDITABLE` | The field is legal in general but not for this combination (for example `client_account_id` on an INTERNAL invitation). |
| `UNKNOWN` | An unrecognised enum member. |
| `DUPLICATE` | The array contains the same item twice. |
| `TOO_COMMON` / `CONTAINS_IDENTITY` | Password policy: the password is a known-common one, or contains the user's email or display name. |

## The retry decision, in one place

```
429  -> wait Retry-After seconds, retry once
503  -> exponential backoff, small bounded number of retries
409 IDEMPOTENCY_RACE  -> short backoff, retry with the SAME Idempotency-Key
409 VERSION_CONFLICT  -> re-read, show the user the difference, resubmit
403 STEP_UP_REQUIRED  -> run MFA verify, then replay the original request
403 MFA_REQUIRED      -> run the MFA flow from /auth/me next_action, then replay
401                   -> refresh once; on a second 401, sign out
everything else       -> do not retry
```
