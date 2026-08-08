# Concurrency contract

How a frontend performs optimistic-concurrency updates against this API.

Verified per endpoint from the request DTOs in each module's `dto.rs` and the
`version` handling in each `service.rs`. **The endpoints are not all the same** —
one of them takes the token as a query parameter, and one makes it optional.

## The model

Every versioned row carries an `integer version`, starting at `1` and incremented
by the write itself. The write is guarded in SQL:

```sql
UPDATE ... SET ..., version = version + 1
 WHERE id = $1 AND version = $2
```

Zero rows affected means somebody else committed first, and the service answers
`409 VERSION_CONFLICT` rather than overwriting. Most services additionally
re-read the row `FOR UPDATE` inside the transaction and compare before writing, so
the conflict is usually detected before the `UPDATE` runs; both paths produce the
same response.

There is no `ETag` and no `If-Match`. The token travels in the request payload.

## Where the version comes from

Read it from the response body of the resource you are about to edit. These
response types carry `version`:

| Response type | Endpoints that return it |
|---|---|
| `UserResponse` | `GET/PATCH /api/v1/users/{id}`, the suspend/reactivate/archive endpoints, `GET /api/v1/users` |
| `RoleSummaryResponse` (and `RoleDetailResponse`, which flattens it) | `GET /api/v1/roles`, `GET /api/v1/roles/{id}` |
| `DepartmentResponse` | `GET/PATCH /api/v1/departments{,/{id}}`, `POST .../archive` |
| `ClientAccountResponse` | `GET/PATCH /api/v1/clients{,/{id}}`, `POST .../archive` |
| `ProjectResponse` | `GET/PATCH /api/v1/projects{,/{id}}`, `POST .../archive` |
| `TaskResponse` | `GET/PATCH /api/v1/tasks{,/{id}}`, the task listings |
| `SettingResponse`, `FeatureFlagResponse` | `GET /api/v1/settings`, `GET /api/v1/feature-flags`, and the `PUT` responses |

**The client projections deliberately have no `version`.**
`ClientProjectResponse` and `ClientTaskResponse` omit it along with
`internal_note`, `created_by` and `client_visible`. That is consistent: the client
portal is read-only, so an external principal never needs a concurrency token.

## Where the version goes — per endpoint

### Body field, **required** (14 endpoints)

The field is `version` at the top level of the JSON body, type `integer`. It is
**not** optional: a missing `version` is `400 BAD_REQUEST`, because an absent
concurrency token must never be read as "overwrite whatever is there".

| Method | Path | Request DTO |
|---|---|---|
| PATCH | `/api/v1/users/{id}` | `UpdateUserRequest` |
| POST | `/api/v1/users/{id}/suspend` | `SuspendUserRequest` |
| POST | `/api/v1/users/{id}/reactivate` | `ReactivateUserRequest` |
| POST | `/api/v1/users/{id}/archive` | `ArchiveUserRequest` |
| PATCH | `/api/v1/roles/{id}` | `UpdateRoleRequest` |
| PATCH | `/api/v1/departments/{id}` | `UpdateDepartmentRequest` |
| POST | `/api/v1/departments/{id}/archive` | `ArchiveDepartmentRequest` |
| PATCH | `/api/v1/clients/{id}` | `UpdateClientRequest` |
| POST | `/api/v1/clients/{id}/archive` | `ArchiveClientRequest` |
| PATCH | `/api/v1/projects/{id}` | `UpdateProjectRequest` |
| POST | `/api/v1/projects/{id}/archive` | `ArchiveProjectRequest` |
| PATCH | `/api/v1/tasks/{id}` | `UpdateTaskRequest` |
| PUT | `/api/v1/settings/{key}` | `UpdateSettingRequest` |
| PUT | `/api/v1/feature-flags/{key}` | `UpdateFeatureFlagRequest` |

Note that **archive is a versioned write**, not a delete. It is a state transition
and carries the same token an edit does.

```http
PATCH /api/v1/projects/018f.../ HTTP/1.1
Content-Type: application/json

{ "version": 7, "name": "Harbour rebuild", "status": "ACTIVE" }
```

### Query parameter, **optional** (1 endpoint)

| Method | Path | Query DTO |
|---|---|---|
| DELETE | `/api/v1/tasks/{id}?version=N` | `CancelTaskQuery { version: Option<i32> }` |

A `DELETE` has no body, so the token is a query parameter. It is **optional**, and
honoured when supplied — cancelling a task somebody else has since moved to `DONE`
is exactly the lost update `version` exists to catch. Omitting it means "cancel
whatever state it is in".

**Recommendation: always send it.** The query DTO is `deny_unknown_fields`, so a
misspelled parameter is `400 BAD_REQUEST` rather than a silently unguarded delete.

### Everything else carries no version

Membership and assignment endpoints — adding or removing a project member, a
department member, a client member, a task assignee, a role assignment, a
permission override — are inserts and deletes on join rows, not edits of a
versioned row. They take no `version`, and they are guarded instead by unique
constraints and rows-affected checks, which surface as `ALREADY_A_MEMBER`,
`ALREADY_ASSIGNED`, `ROLE_ALREADY_ASSIGNED`, `MEMBERSHIP_CHANGED` or
`RESOURCE_NOT_FOUND`.

Creates take no `version` either, for the obvious reason. Use `Idempotency-Key`
there instead — see `IDEMPOTENCY_CONTRACT.md`.

## The stale-update response

```
HTTP/1.1 409 Conflict
Content-Type: application/problem+json
Cache-Control: no-store

{
  "type": "https://roleblank.internal/problems/version_conflict",
  "title": "The resource was modified by someone else",
  "status": 409,
  "code": "VERSION_CONFLICT",
  "detail": "Expected version 3 but the current version is 5. Re-read the resource and retry.",
  "request_id": "...",
  "version_conflict": { "expected": 3, "actual": 5 }
}
```

Branch on `code === "VERSION_CONFLICT"`. Read the numbers from the
`version_conflict` object, **never** from `detail` — `detail` is human text that
may be reworded at any time, and the structured pair exists precisely so the retry
loop is machine-writable.

* `expected` — the version you sent.
* `actual` — the version the row holds now.

## Correct retry behaviour

**Do not auto-retry with `version_conflict.actual`.** Resubmitting your unchanged
payload with the winner's version is a blind overwrite: it discards their change
with extra steps, and it is the exact failure optimistic concurrency exists to
prevent. The one legitimate automatic use of `actual` is deciding *how far behind*
you are for telemetry.

The correct loop:

```
1. PATCH with the version you read.
2. On 409 VERSION_CONFLICT:
     a. GET the resource again.
     b. Compare the server's fields with the user's edits.
     c. If they touch disjoint fields, you MAY re-apply the user's edits
        on top of the fresh copy and resubmit with the fresh version —
        but only if your merge is field-level, not whole-object.
     d. Otherwise show the user what changed and let them decide.
3. Cap retries. Two attempts, then hand it to the user.
```

Notes that matter in practice:

* **A PATCH is sparse.** The update DTOs use `Option<T>` with `#[serde(default)]`,
  so an absent field means "leave it alone". Re-applying only the fields the user
  actually touched is therefore natural and is the right merge granularity. Do not
  round-trip the whole object.
* **`version` is not a timestamp.** It moves on every write, including writes made
  by a different endpoint on the same row (archiving bumps it, a status change
  bumps it). Two clients editing different fields will still collide. That is
  intended.
* **A 409 is not a failure to log loudly.** It is the normal outcome of concurrent
  editing. Present it as "someone else changed this", not as an error.
* **Authorisation runs before the version check.** In every service the
  `state.require` call comes first, so a caller who is not allowed to edit the row
  gets `403`/`404` and never learns the version. Do not use a `VERSION_CONFLICT`
  to infer that a resource exists — a caller who cannot see it never reaches this
  code.
* **The version check runs before the business rules in some services and after in
  others.** Practically, a request can fail with `ALREADY_ARCHIVED`,
  `INVALID_STATE_TRANSITION` or `DEPARTMENT_HAS_LIVE_PROJECTS` *instead of*
  `VERSION_CONFLICT` even though your version was also stale. Handle both; re-read
  on either.
* **`VERSION_CONFLICT` and `Idempotency-Key` do not interact.** No versioned
  endpoint honours the idempotency header — the header is only on creates. A
  retried PATCH is not deduplicated, which is another reason not to auto-retry.

## Reference: the two ways a service detects the conflict

Both produce the same response; a client cannot and need not tell them apart.

1. **Compare-then-write.** The row is loaded `FOR UPDATE`, `row.version` is
   compared with `request.version`, and a mismatch returns immediately. Used by
   settings, feature flags, clients, departments, projects, tasks and the user
   lifecycle transitions.
2. **Guarded write.** The `UPDATE ... WHERE id = $1 AND version = $2` returns zero
   rows and the service re-reads the current version to report it. This is the
   backstop that runs even when the compare was skipped or raced, and it is why
   `version = version + 1` and `AND version = $N` appear together in every
   repository statement — a repository test asserts it.
