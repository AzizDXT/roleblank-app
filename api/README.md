# RoleBlank OS — API contract

Two artefacts live here, and they answer different questions.

| File | Question it answers |
| --- | --- |
| `openapi.yaml` | *What is the surface, exactly?* Every route, its permission, its step-up requirement, its request and response shapes, and every error it can return. |
| `requests/*.http` | *What does it feel like to use?* Runnable requests in workflow order, each annotated with what a correct response looks like. |

Neither is generated from a running server. `openapi.yaml` is written by hand and
pinned to the code by a test; the `.http` files are a hand-curated walkthrough.

---

## `openapi.yaml`

OpenAPI 3.1.0, self-contained, no external `$ref`s. It describes exactly the 93
operations in `ROUTE_TABLE` (`backend/src/routes.rs`) — no more and no less.

### Read it in a viewer

Any 3.1-capable tool will do. Nothing here needs a server running:

```bash
# Redoc (npx, no install)
npx @redocly/cli preview-docs api/openapi.yaml

# Lint it
npx @redocly/cli lint api/openapi.yaml

# Or open it in the Swagger Editor and paste the file in.
```

VS Code users: the *OpenAPI (Swagger) Editor* extension renders it in a side
panel and resolves `$ref`s as you move through the file.

### Read it as a reviewer

Two vendor extensions on every operation exist for exactly this purpose:

```yaml
x-access: Authenticated
x-required-permission: "projects.clients.share"
x-requires-step-up: true
```

They are copied verbatim from `ROUTE_TABLE`, so you can audit the authorisation
model by reading the spec rather than the router. To find everything dangerous:

```bash
grep -B12 'x-requires-step-up: true' api/openapi.yaml | grep operationId
grep -A2 'x-access: Anonymous'       api/openapi.yaml | grep -c 'security: \[\]'   # 12
```

### It cannot drift

`backend/tests/openapi_contract.rs` fails the build when the spec and the route
table disagree, in **either** direction:

```bash
cd backend && cargo test --test openapi_contract
```

It asserts that the set of `(METHOD, path)` pairs is identical, that
`security: []` appears on exactly the routes whose `Access` is `Anonymous`, and
that every `x-required-permission` and `x-requires-step-up` matches. Adding an
endpoint without documenting it fails; documenting an endpoint that does not
exist fails too, because a spec describing phantom routes misleads everyone who
uses it to reason about the attack surface.

### Things the spec says by *omitting* them

Worth knowing before you go looking:

* **No user delete.** Accounts are archived. The runtime database role holds no
  `DELETE` grant on `users` at all.
* **No audit write.** Audit rows are a side effect of the operation being
  audited. The table refuses `UPDATE`, `DELETE` and `TRUNCATE` at the database
  level, with no exception for administrators.
* **No ownership transfer.** `system_ownership` is immutable; recovery is an
  offline procedure, not an API.
* **No file upload.** Anywhere.
* **No `422`.** A body that parses but fails validation is `400` with
  `code: VALIDATION_FAILED` and an `errors` array. One bad-request status, not
  two.
* **No offset pagination and no totals.** Cursors only.

---

## `requests/*.http`

Plain-text request collections for the VS Code **REST Client** extension
(`humao.rest-client`) or the IntelliJ / JetBrains built-in HTTP client. Open a
file, click *Send Request* above any block.

| File | Contents |
| --- | --- |
| `00-bootstrap.http` | Health probes, metrics, and the one-time owner creation. |
| `01-auth-and-mfa.http` | Login, TOTP enrolment and verification, sessions, password change and reset, recovery codes, step-up. |
| `02-users-and-invitations.http` | User administration, invitations, invitation acceptance, self-registration. |
| `03-roles-and-permissions.http` | The permission catalogue, roles, assignment, per-user overrides. |
| `04-departments-and-clients.http` | Internal structure and external client accounts, and their two kinds of membership. |
| `05-projects-and-tasks.http` | Projects, members, client sharing, tasks, assignees. |
| `06-client-portal.http` | The four operations an external principal may reach — plus probes showing what it cannot. |
| `07-settings-and-audit.http` | Settings, feature flags, the audit log and chain verification. |
| `99-attack-probes.http` | Requests that **must** fail, each annotated with the expected status and `code`. |

### Credentials

**Every token and password in these files is an obvious placeholder, and it must
stay that way.** Real values go in an untracked environment file, never in a
tracked `.http` file:

* **VS Code** — add a `rest-client.environmentVariables` block to your *user*
  settings (not the workspace's), then pick the environment from the status bar.
* **IntelliJ** — put them in `http-client.private.env.json`, which the IDE's
  default `.gitignore` already excludes.

If you are about to `git add` a file containing something that begins `rb_at_`,
stop. An access token is a live session, not a test fixture.

### Run `99-attack-probes.http` deliberately

It is documentation of the security posture as much as a test tool. A probe
"passing" means the request **failed** with the stated status and `code`. Three
outcomes are defects even when the status looks right:

* a `500` where a `4xx` was expected — the input reached somewhere it should not
  have;
* an error body that quotes the rejected value back — that is how a validation
  error becomes a reflection gadget and a log-injection vector;
* two different authentication failures that produce different responses — that
  is an account-enumeration oracle.

---

## The golden flow, by hand

Start a local instance on `http://localhost:8090` with a migrated, empty
database. Then work through the files in order; each step below names the file
and the request. Everything can be done with the REST Client, but the `curl`
equivalents are given because they are copy-pasteable and show the shape.

**1. Confirm the instance is up and uninitialised.** — `00-bootstrap.http`

```bash
curl -s localhost:8090/health/ready                 # {"status":"ok"}
curl -s localhost:8090/api/v1/bootstrap/status      # {"initialized":false}
```

**2. Create the owner.** Needs the deployment's `RB_BOOTSTRAP_SECRET`. This
succeeds at most once, ever.

```bash
curl -s -X POST localhost:8090/api/v1/bootstrap/root \
  -H 'Content-Type: application/json' \
  -d '{"bootstrap_secret":"…","email":"owner@example.com",
       "display_name":"System Owner","password":"…"}'
```

You get `mfa_enrolment_required: true` and **no token**. That is the point:
bootstrap cannot mint a privileged session by itself.

**3. Log in.** — `01-auth-and-mfa.http`

```bash
curl -s -X POST localhost:8090/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"owner@example.com","password":"…"}'
```

The response carries tokens *and* `mfa_required: true`. Export the access token:

```bash
export TOK=rb_at_…
```

**4. See the reduced projection.** Prove the pending session is restricted:

```bash
curl -s localhost:8090/api/v1/auth/me -H "Authorization: Bearer $TOK"
```

No `capabilities`, no `is_root`, and `next_action:
"MFA_ENROLLMENT_REQUIRED"`. Now try a business endpoint and watch it refuse with
`403 MFA_REQUIRED`:

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
  localhost:8090/api/v1/projects -H "Authorization: Bearer $TOK"
```

**5. Enrol and activate TOTP.**

```bash
curl -s -X POST localhost:8090/api/v1/auth/mfa/totp/setup \
  -H "Authorization: Bearer $TOK"
```

Scan `otpauth_uri` into an authenticator, then activate with a live code:

```bash
curl -s -X POST localhost:8090/api/v1/auth/mfa/totp/activate \
  -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
  -d '{"code":"123456"}'
```

**Write down the recovery codes now.** They are shown once; only digests are
stored.

**6. Verify, and open the step-up window.**

```bash
curl -s -X POST localhost:8090/api/v1/auth/mfa/verify \
  -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
  -d '{"code":"123456"}'
```

`step_up_active: true`. You now have roughly ten minutes in which the dangerous
operations will be accepted. `GET /api/v1/auth/me` returns the full projection.

**7. Build the structure.** — `04-departments-and-clients.http`

Create a department, then a client account, in that order — a project can name a
department, and a share needs a client account to point at.

**8. Invite a colleague.** — `02-users-and-invitations.http`

`POST /api/v1/invitations` with `principal_type: "INTERNAL"`, a fresh
`Idempotency-Key`, and the department id from step 7. In a development
deployment the invitation token is visible in the mail outbox or the server log;
redeem it anonymously with `POST /api/v1/invitations/accept`. No session comes
back — the invitee logs in normally.

**9. Grant authority.** — `03-roles-and-permissions.http`

Create a role and assign it. Both need step-up; if the window from step 6 has
closed you will get `403 STEP_UP_REQUIRED` with a `window_seconds` hint, so
re-run step 6 and retry. Check the result with
`GET /api/v1/users/{id}/permissions`.

**10. Do some work.** — `05-projects-and-tasks.http`

Create a project, add a member, create a task. Note that the task's
`client_visible` is `false`.

**11. Cross the trust boundary — the interesting part.**

Share the project with the client account (step-up again):

```bash
curl -s -X POST localhost:8090/api/v1/projects/$PROJECT/clients \
  -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
  -d '{"client_account_id":"…","note":"Phase-one review"}'
```

Then invite an external contact (`principal_type: "CLIENT"`), attach them to the
client account, and **activate** the membership — until that activation the
membership grants nothing at all.

**12. Look through the client's eyes.** — `06-client-portal.http`

Log in as the external user and fetch the portal:

```bash
curl -s localhost:8090/api/v1/client-portal/projects \
  -H "Authorization: Bearer $CLIENT_TOK"
```

Compare it against what you saw at `/api/v1/projects/{id}` in step 10. The
project is there with nine fields; `internal_note`, `manager_user_id`,
`department_id`, `created_by` and `version` are gone — not filtered out, but
absent from a different type. Then fetch the project's tasks:

```bash
curl -s localhost:8090/api/v1/client-portal/projects/$PROJECT/tasks \
  -H "Authorization: Bearer $CLIENT_TOK"
```

**Empty.** Sharing the project did not share its tasks. Go back as an internal
user, `PATCH` the task with `"client_visible": true`, and fetch again — now it
appears. That is the whole design in one observation.

Finally, ask the client token for something internal:

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
  localhost:8090/api/v1/users -H "Authorization: Bearer $CLIENT_TOK"   # 404
```

`404`, not `403`. A refusal must not confirm that anything exists.

**13. Read the trail.** — `07-settings-and-audit.http`

Every step above left an audit row:

```bash
curl -s "localhost:8090/api/v1/audit/events?limit=50" -H "Authorization: Bearer $TOK"
```

Then verify the chain (step-up required):

```bash
curl -s "localhost:8090/api/v1/audit/verify" -H "Authorization: Bearer $TOK"
```

`valid: true` means: nobody modified, reordered or truncated the log without the
chain key. It is not a claim of tamper-proofing against somebody holding both
the database and the key — no hash chain can be.

**14. Try to break it.** — `99-attack-probes.http`

Run the whole file. Every request must fail, with the annotated status and
`code`.
