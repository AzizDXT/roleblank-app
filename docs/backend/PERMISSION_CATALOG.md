# Permission catalogue

All **42** permissions, transcribed from `backend/src/modules/authorization/catalog.rs`.
That table and the `permissions` rows seeded by `migrations/0008_seed_catalog.sql`
must agree exactly; `verify_against_database` runs at startup and **refuses to
boot** on any divergence, in either direction.

Nothing in this document is inferred. `Dangerous` is the `is_dangerous` flag;
`Envelope` is `max_principal_type`; `Routes` are the entries in
`backend/src/routes.rs` `ROUTE_TABLE` that declare the code.

## How to read the columns

**Applicable resources** — the object types a decision on this permission is
actually taken against, read from the `Target` the service constructs.
`Target::Collection` means no object: only a `GLOBAL` grant reaches it.

**Valid scopes** — two different limits apply, and both are enforced:

* *On a role*: `GLOBAL`, `DEPARTMENT`, `ASSIGNED`, `SELF`. `RESOURCE` is refused —
  a role is a reusable template and cannot name a specific object.
* *On a per-user override*: all five, including `RESOURCE`.

The column below reports which of those are **effective** for this permission,
which is narrower still: a scope that cannot reach the target type does nothing.
Where the column says "GLOBAL only (effective)", a `DEPARTMENT` grant can be
stored and will simply never authorise anything.

**Delegatable** — every permission is delegatable in principle, but only through
the delegation guard, and only by an actor that already holds it. The guard
enforces: an actor cannot grant what it does not hold (rule 1); cannot grant a
scope it cannot derive from one it holds (rule 2 — `DEPARTMENT` and `ASSIGNED` are
**incomparable**, neither can produce the other); cannot modify its own privileges
at all (rule 3); cannot target the system owner (rule 4); cannot touch a system
role (rule 5); cannot assign a role to a mismatched principal type (rule 6); a
`DENY` on the actor blocks delegation as well as access (rule 7). This column
records anything additional.

**Step-up** — "always" means the permission is `is_dangerous`, so
`state.require_step_up_for` demands a recent second factor wherever it is
exercised, and `routes.rs` has a test asserting every such route also declares
`step_up = true`. "Route-specific" means the catalogue does not flag it but named
routes demand step-up explicitly in the service.

**Envelope** — `INTERNAL only` means a `CLIENT` principal is denied at
`Decision::DenyPrincipalEnvelope` before any grant is consulted, and receives
`404` rather than `403`. `CLIENT-compatible` means `max_principal_type = ANY`.

---

## audit (1)

| Code | Description | Applicable resources | Valid scopes | Delegatable | Dangerous | Step-up | Envelope |
|---|---|---|---|---|---|---|---|
| `audit.read` | Read the append-only audit log and run the hash-chain verification. There is no write, update or delete counterpart anywhere in the API — that absence is load-bearing. | `Target::Collection` only | GLOBAL only (effective) | yes, standard guard | no | **Route-specific**: `GET /api/v1/audit/verify` calls `state.require_step_up` explicitly; the two read routes do not. | INTERNAL only |

## client portal (2)

The only two codes an external principal can ever hold. Both are read-only, and
`catalog.rs` has a test asserting that any `CLIENT`-reachable permission must end
in `.read` and must not be dangerous.

| Code | Description | Applicable resources | Valid scopes | Delegatable | Dangerous | Step-up | Envelope |
|---|---|---|---|---|---|---|---|
| `client.portal.projects.read` | Read projects through the client portal. Visibility resolves through an **ACTIVE** client membership joined to a live project–client link; the permission alone grants nothing. | `PROJECT`, via the portal projection only | `ASSIGNED` in practice (the portal handlers build a target with `actor_is_member = true` and no department) | yes | no | no | **CLIENT-compatible** |
| `client.portal.tasks.read` | Read tasks through the client portal. Additionally bounded to tasks with `client_visible = true`. | `TASK`, via the portal projection only | `ASSIGNED` in practice | yes | no | no | **CLIENT-compatible** |

## clients (5)

`clients.*` decisions build a target with `department_id = None`, so a
`DEPARTMENT`-scoped grant can never reach a client account. `actor_is_member` is
true only for the account manager, which is what `ASSIGNED` resolves against.

| Code | Description | Applicable resources | Valid scopes | Delegatable | Dangerous | Step-up | Envelope |
|---|---|---|---|---|---|---|---|
| `clients.read` | List and read client accounts and their memberships. | `CLIENT_ACCOUNT` | GLOBAL, ASSIGNED, RESOURCE, SELF (SELF never matches a client account) | yes | no | no | INTERNAL only |
| `clients.create` | Create a client account. | `Target::Collection` (no row exists yet) | GLOBAL only (effective) | yes | no | no | INTERNAL only |
| `clients.update` | Edit a client account's name, description or account manager. | `CLIENT_ACCOUNT` | GLOBAL, ASSIGNED, RESOURCE | yes | no | no | INTERNAL only |
| `clients.archive` | Archive a client account. | `CLIENT_ACCOUNT` | GLOBAL, ASSIGNED, RESOURCE | yes | no | no | INTERNAL only |
| `clients.members.manage` | Add, activate and remove client memberships. **Activation is the moment a stranger becomes a counterparty** — it is the state that makes company data visible outside the company. Also demanded, via `authorize_placement`, when an invitation names a `client_account_id`. | `CLIENT_ACCOUNT` | GLOBAL, ASSIGNED, RESOURCE | yes | no | no | INTERNAL only |

## departments (5)

`departments.*` decisions set `department_id = row.id`, so a `DEPARTMENT`-scoped
grant reaches a department the actor is an active member of.

| Code | Description | Applicable resources | Valid scopes | Delegatable | Dangerous | Step-up | Envelope |
|---|---|---|---|---|---|---|---|
| `departments.read` | List and read departments and their members. | `DEPARTMENT` | GLOBAL, DEPARTMENT, ASSIGNED, RESOURCE | yes | no | no | INTERNAL only |
| `departments.create` | Create a department. | `Target::Collection` | GLOBAL only (effective) | yes | no | no | INTERNAL only |
| `departments.update` | Edit a department's name, description or lead. | `DEPARTMENT` | GLOBAL, DEPARTMENT, ASSIGNED, RESOURCE | yes | no | no | INTERNAL only |
| `departments.archive` | Archive a department. Refused while it still owns live projects. | `DEPARTMENT` | GLOBAL, DEPARTMENT, ASSIGNED, RESOURCE | yes | no | no | INTERNAL only |
| `departments.members.manage` | Add and remove department memberships. **This is an authorisation operation**: a department membership is what resolves `DEPARTMENT` scope for every other permission. Also demanded, via `authorize_placement`, when an invitation names a `department_id`. Refuses to target the system owner. | `DEPARTMENT` | GLOBAL, DEPARTMENT, ASSIGNED, RESOURCE | yes | no | no | INTERNAL only |

## iam (15)

Three of these are **catalogued but unrouted**, deliberately. `routes.rs` has a
test that fails if a fourth appears.

| Code | Description | Applicable resources | Valid scopes | Delegatable | Dangerous | Step-up | Envelope |
|---|---|---|---|---|---|---|---|
| `iam.users.read` | List and read user accounts. A narrower-than-GLOBAL grant turns the listing into a SQL-filtered query rather than authorising "list everything". | `USER`, `Target::Collection` for the listing | GLOBAL, DEPARTMENT, SELF, RESOURCE | yes | no | no | INTERNAL only |
| `iam.users.update` | Edit a user's display name or email. Refuses to target the system owner. | `USER` | GLOBAL, DEPARTMENT, SELF, RESOURCE | yes | no | no | INTERNAL only |
| `iam.users.suspend` | Suspend **and** reactivate an account. One permission covers both directions. Suspension revokes every live session in the same transaction. Refuses self-target and the system owner. | `USER` | GLOBAL, DEPARTMENT, SELF, RESOURCE | yes | no | no | INTERNAL only |
| `iam.users.archive` | Archive an account — the only removal the API offers. There is no `DELETE /users/{id}`, and the runtime database role holds no `DELETE` grant on `users`. | `USER` | GLOBAL, DEPARTMENT, SELF, RESOURCE | yes | no | no | INTERNAL only |
| `iam.users.invite` | Issue, list and revoke invitations. Issuing additionally requires the placement permission for any named department or client account, and passes every named role through the delegation guard. | `Target::Collection` | GLOBAL only (effective) | yes | no | **Conditional**: `state.require_step_up` fires when any role on the invitation carries a dangerous permission. | INTERNAL only |
| `iam.users.create` | **Catalogued, deliberately unrouted.** Direct account creation is not exposed: it would be a path to an account with no invitation record and no accepted-terms trail. Accounts arrive only via bootstrap, invitation or self-registration. | — | — | grantable, but confers nothing | no | n/a | INTERNAL only |
| `iam.roles.read` | Read the role catalogue, a role's detail, and a user's role assignments. | `Target::Collection`; `USER` for the per-user listing | GLOBAL only for roles (there is no `ROLE` resource type, so no narrower scope can name one) | yes | no | no | INTERNAL only |
| `iam.roles.create` | Author a new role. `check_role_authoring` refuses a role containing authority the actor does not itself hold, and refuses authoring a system role. | `Target::Collection` | GLOBAL only | yes | no | **Yes, route-specific.** Not flagged dangerous, so the service calls `state.require_step_up` explicitly; `ROUTE_TABLE` declares `step_up = true`. | INTERNAL only |
| `iam.roles.update` | Edit a role's name, description or permission set. The most far-reaching authority change the API offers — it changes what every current holder may do. | `Target::Collection` | GLOBAL only | yes | no | **Yes, route-specific**, same mechanism as `create`. | INTERNAL only |
| `iam.roles.delete` | Delete a role. Refused while it is still assigned (`ROLE_IN_USE`). | `Target::Collection` | GLOBAL only | yes | no | **Yes, route-specific.** | INTERNAL only |
| `iam.roles.assign` | Assign and unassign roles. **Dangerous** — this is how authority actually reaches a person. Every assignment goes through `check_role_assignment`, which validates the role's *permissions*, not the role as an opaque unit. | `USER` | GLOBAL, DEPARTMENT, SELF, RESOURCE | yes; holder must have MFA enrolled and a recent step-up | **YES** | **Always** (dangerous) | INTERNAL only |
| `iam.permissions.read` | Read the permission catalogue, a user's effective permissions, and a user's overrides. Reading which exceptions exist is an inspection, not a grant — an auditor needs it without being handed the ability to change them. | `Target::Collection`; `USER` for the per-user views | GLOBAL for the catalogue; GLOBAL/DEPARTMENT/SELF/RESOURCE for the per-user views | yes | no | no | INTERNAL only |
| `iam.permissions.delegate` | Create and remove per-user permission overrides, including `DENY` overrides. **Dangerous** — the other way authority reaches a person. | `USER` | GLOBAL, DEPARTMENT, SELF, RESOURCE | yes; holder must have MFA enrolled and a recent step-up | **YES** | **Always** (dangerous) | INTERNAL only |
| `iam.sessions.read` | **Catalogued, deliberately unrouted.** Administering *other people's* sessions. `GET /auth/sessions` is self-only by design; exposing this needs its own review. | — | — | grantable, but confers nothing | no | n/a | INTERNAL only |
| `iam.sessions.revoke` | **Catalogued, deliberately unrouted.** Dangerous because session revocation is an availability weapon as well as a security control. | — | — | grantable, but confers nothing; step-up would apply if routed | **YES** | n/a (unrouted) | INTERNAL only |

## projects (6)

Project decisions carry the project's own `department_id` and the actor's project
membership, so both `DEPARTMENT` and `ASSIGNED` are live.

| Code | Description | Applicable resources | Valid scopes | Delegatable | Dangerous | Step-up | Envelope |
|---|---|---|---|---|---|---|---|
| `projects.read` | List and read projects, their members, and their client links. | `PROJECT` | GLOBAL, DEPARTMENT, ASSIGNED, RESOURCE | yes | no | no | INTERNAL only |
| `projects.create` | Create a project. Authorised against a target built from the **requested** `department_id`, so a department-scoped creator cannot create outside its department. | `PROJECT` (a prospective one) | GLOBAL, DEPARTMENT | yes | no | no | INTERNAL only |
| `projects.update` | Edit a project. Moving a project between departments is authorised **twice** — against the source and against the destination. | `PROJECT` | GLOBAL, DEPARTMENT, ASSIGNED, RESOURCE | yes | no | no | INTERNAL only |
| `projects.archive` | Archive a project. | `PROJECT` | GLOBAL, DEPARTMENT, ASSIGNED, RESOURCE | yes | no | no | INTERNAL only |
| `projects.members.manage` | Add and remove internal project members. Refuses external principals as members. | `PROJECT` | GLOBAL, DEPARTMENT, ASSIGNED, RESOURCE | yes | no | no | INTERNAL only |
| `projects.clients.share` | Share a project with a client account, and unshare it. **Dangerous, and the most consequential business permission in the system**: it is the control that moves company data across the external trust boundary. Both directions are audited, and a refusal is audited too. | `PROJECT` | GLOBAL, DEPARTMENT, ASSIGNED, RESOURCE | yes; holder must have MFA enrolled and a recent step-up | **YES** | **Always** (dangerous) | INTERNAL only |

## settings (3)

The split between the two write permissions is decided **per row, after it is
loaded**, from the row's `is_security_sensitive` column. That is why
`settings.security.write` appears in the catalogue but on no route.

| Code | Description | Applicable resources | Valid scopes | Delegatable | Dangerous | Step-up | Envelope |
|---|---|---|---|---|---|---|---|
| `settings.read` | Read system settings and feature flags. | `Target::Collection` | GLOBAL only (effective) | yes | no | no | INTERNAL only |
| `settings.features.write` | Write a setting or feature flag whose `is_security_sensitive` is **false**. | `Target::Collection` | GLOBAL only | yes | no | no | INTERNAL only |
| `settings.security.write` | Write a setting or feature flag whose `is_security_sensitive` is **true** — which includes `registration.mode`. **Dangerous.** Declared on no route: it is enforced dynamically by `settings::service` after the row is read, because whether a write needs it is unknowable at routing time. Audit records the key and who changed it but **never the values** of a security-sensitive setting. | `Target::Collection` | GLOBAL only | yes; holder must have MFA enrolled and a recent step-up | **YES** | **Always** (dangerous) | INTERNAL only |

## tasks (5)

Task decisions take their department from the task's **project**, and
`ASSIGNED` resolves against an active assignee row.

| Code | Description | Applicable resources | Valid scopes | Delegatable | Dangerous | Step-up | Envelope |
|---|---|---|---|---|---|---|---|
| `tasks.read` | List and read tasks and their assignees. Reading the assignee list is a read, not an assignment capability — requiring `tasks.assign` to view it would force every reader to hold a write. | `TASK` | GLOBAL, DEPARTMENT, ASSIGNED, RESOURCE | yes | no | no | INTERNAL only |
| `tasks.create` | Create a task. Authorised against the **loaded project** named in the body. A new task is always `client_visible = false`; there is no DTO field for it. | `TASK` (prospective), bounded by the project | GLOBAL, DEPARTMENT, ASSIGNED | yes | no | no | INTERNAL only |
| `tasks.update` | Edit a task, including moving `client_visible`, which additionally emits `TASK.CLIENT_VISIBILITY_CHANGED`. `project_id` cannot be changed — moving a task between projects would be a share operation wearing an edit's clothes. | `TASK` | GLOBAL, DEPARTMENT, ASSIGNED, RESOURCE | yes | no | no | INTERNAL only |
| `tasks.delete` | Cancel a task. `DELETE` never removes a row; it is a status transition and is audited as `TASK.CANCELLED`. | `TASK` | GLOBAL, DEPARTMENT, ASSIGNED, RESOURCE | yes | no | no | INTERNAL only |
| `tasks.assign` | Assign and unassign task assignees. Refuses external principals. | `TASK` | GLOBAL, DEPARTMENT, ASSIGNED, RESOURCE | yes | no | no | INTERNAL only |

---

## The dangerous set, in full

Pinned by a test in `catalog.rs` — changing it fails the build:

1. `iam.permissions.delegate`
2. `iam.roles.assign`
3. `iam.sessions.revoke` (unrouted)
4. `projects.clients.share`
5. `settings.security.write` (dynamically enforced)

A dangerous permission carries three consequences: exercising it requires a recent
step-up; granting it requires a recent step-up; and the holder must have MFA
enrolled. An invitation naming a role that contains any of them is created with
`mfa_required = true`, so the invitee's first session lands in
`MFA_ENROLLMENT_REQUIRED` rather than relying on a prompt they could ignore.

## The system owner

`is_root` is a single row in `system_ownership`, not a role and not a column on
`users`. Root bypasses **permission evaluation only** — `evaluator::evaluate`
returns `AllowRootOwnership` at step 1, after authentication, session validity,
MFA and step-up have already been satisfied. Root's capability list therefore
reports every catalogued permission at `GLOBAL`, and that is a projection of the
bypass, not a set of grants. No API operation may target the owner: the
application answers `403 ROOT_PROTECTED` and the database refuses independently.
