# 04 — Authorization

## 1. The rule

**Deny unless explicitly allowed.** Every authenticated route declares a required
permission. Every route that touches an identified resource performs a *second*,
object-level decision after the resource is loaded. There is no route that is merely
"authenticated".

There is exactly one bypass in the entire system — system ownership — and it is not a role.

## 2. The four layers a request passes

```
 1. ENVELOPE      principal type vs. permission.max_principal_type
                  A CLIENT can never hold an INTERNAL-only permission. Checked first,
                  before any grant is even looked up.

 2. POLICY        deny-by-default evaluation of roles + overrides -> a set of scopes

 3. OBJECT        does any granted scope actually cover *this* resource?

 4. VISIBILITY    (CLIENT principals only) the repository query itself carries the
                  client-visibility predicate, so an invisible row is never loaded
                  even if layers 1–3 were wrong.
```

Layer 4 is deliberate redundancy. Layers 1–3 are code; layer 4 is a `JOIN`. A bug in the
evaluator does not leak another client's project, because the row was never selected.

## 3. Permission codes

`<module>.<resource>.<action>` — lowercase, dot-separated, immutable once shipped. They
exist in exactly two places that must agree: the Rust catalogue
(`modules::authorization::catalog::PERMISSIONS`) and the `permissions` table, seeded by a
migration. A startup check compares them and **refuses to boot on divergence**, so a
permission cannot be silently added in code and be missing in the database.

Each entry carries:

| Attribute | Meaning |
| --- | --- |
| `code` | the identifier |
| `module` | grouping for the catalogue endpoint |
| `max_principal_type` | `INTERNAL` = internal principals only; `ANY` = a CLIENT may hold it |
| `is_dangerous` | granting *or exercising* it requires step-up and mandates MFA enrolment |

Unknown codes are not "unmatched" — they are a hard `DENY`, and an unknown code arriving
from a request is additionally a `400 UNKNOWN_PERMISSION`, because it means the caller is
probing.

### Catalogue (as shipped)

```
iam.users.read              iam.users.create           iam.users.update
iam.users.suspend           iam.users.archive          iam.users.invite
iam.roles.read              iam.roles.create           iam.roles.update
iam.roles.delete            iam.roles.assign           *
iam.permissions.read        iam.permissions.delegate   *
iam.sessions.read           iam.sessions.revoke        *
departments.read            departments.create         departments.update
departments.archive         departments.members.manage
clients.read                clients.create             clients.update
clients.archive             clients.members.manage
projects.read               projects.create            projects.update
projects.archive            projects.members.manage    projects.clients.share  *
tasks.read                  tasks.create               tasks.update
tasks.assign                tasks.delete
settings.read               settings.features.write    settings.security.write *
audit.read
client.portal.projects.read   (max_principal_type = ANY)
client.portal.tasks.read      (max_principal_type = ANY)
```

`*` marks `is_dangerous = true`. Everything unmarked is `max_principal_type = INTERNAL`.
Only the two `client.portal.*` codes are reachable by a CLIENT principal at all.

## 4. Scopes

Five scope types. No more, and no scripting language.

| Scope | Covers |
| --- | --- |
| `GLOBAL` | every object of the relevant type |
| `DEPARTMENT` | objects whose department is one the actor is an active member of |
| `ASSIGNED` | objects the actor is an active member/assignee of |
| `SELF` | only the actor's own user record |
| `RESOURCE(type, id)` | exactly one named object — **overrides only**, never on a role |

A grant is `(permission_code, scope)`. Roles carry `GLOBAL | DEPARTMENT | ASSIGNED | SELF`.
User overrides may additionally carry `RESOURCE`.

## 5. Evaluation algorithm (normative)

This is the exact order implemented in `authorization::evaluator::evaluate`.

```
evaluate(actor, permission_code, target) -> Decision

 0. actor.session must be valid, non-pending-MFA, and the user ACTIVE
    (established before the evaluator is ever called)

 1. if system_ownership.root_user_id == actor.user_id:
        return Allow(RootOwnership)          // the one bypass; see §7 for its limits

 2. let perm = catalog.get(permission_code)
        None => return Deny(UnknownPermission)

 3. if actor.principal_type == CLIENT and perm.max_principal_type == INTERNAL:
        return Deny(PrincipalEnvelope)       // before any grant lookup

 4. grants  := role_permissions of the actor's assigned roles      (ALLOW, scoped)
             ∪ user_permission_overrides where effect = ALLOW and not expired
    denials := user_permission_overrides where effect = DENY and not expired

 5. for d in denials with d.permission_code == permission_code:
        if scope_covers(d.scope, actor, target):
            return Deny(ExplicitDeny)        // DENY always beats ALLOW

 6. if grants for permission_code is empty:
        return Deny(NoGrant)

 7. for g in grants with g.permission_code == permission_code:
        if scope_covers(g.scope, actor, target):
            return Allow(Granted(g.scope))

 8. return Deny(OutOfScope)
```

Two properties follow, and both are asserted by `proptest`:

- **DENY is absolute within its scope.** Adding roles can never overturn a matching DENY,
  because step 5 runs before step 7 and never consults `grants`.
- **A CLIENT can never hold an INTERNAL permission**, for any random combination of roles,
  overrides and targets, because step 3 precedes all grant collection.

### `scope_covers`

```
GLOBAL              -> true
SELF                -> target is User(actor.user_id)
DEPARTMENT          -> target.department_id ∈ actor.active_department_ids
ASSIGNED            -> actor ∈ target.active_members   (project members, task assignees,
                                                        client memberships)
RESOURCE(t, id)     -> target.type == t && target.id == id
```

`target = None` (a collection endpoint) is covered only by `GLOBAL`; every narrower scope
turns a list endpoint into a *filtered* query rather than a permitted one. This is why
listing is implemented as "permission gate + scope-derived SQL predicate", never as
"fetch all, then filter in Rust".

## 6. Delegation guard

An administrator granting authority is the sharpest escalation edge in the system. The
guard runs on: role creation, role permission changes, role assignment, and user override
creation.

```
can_delegate(actor, permission_code, requested_scope) -> bool

  if actor is ROOT                       -> true
  if permission is_dangerous and session lacks recent step-up -> false (STEP_UP_REQUIRED)
  let actor_scopes = scopes the actor effectively holds for permission_code
      (evaluated with the same evaluator, so an explicit DENY on the actor
       removes the ability to delegate it — a DENY is not just an access block,
       it is a delegation block)
  if actor_scopes is empty               -> false
  return actor_scopes.any(|a| derivable(a, requested_scope))
```

### The derivation lattice

Scopes are **not** totally ordered, and pretending they are is how privilege escalation
gets shipped. `DEPARTMENT` and `ASSIGNED` are incomparable: an actor whose authority is
bounded by their department must not be able to mint `ASSIGNED` authority, because the
grantee could be assigned to a project in a *different* department.

```
  actor holds        may delegate
  ─────────────      ──────────────────────────────
  GLOBAL             GLOBAL, DEPARTMENT, ASSIGNED, SELF, RESOURCE(any)
  DEPARTMENT         DEPARTMENT, SELF
  ASSIGNED           ASSIGNED, SELF
  SELF               SELF
  RESOURCE(t, id)    RESOURCE(t, id)          (that exact object only)
```

Every other pair is denied. Additional hard rules, each with its own test:

1. An actor may not create or modify a role marked `is_system`.
2. An actor may not assign a role that contains **any** permission it cannot itself
   delegate at that permission's scope — checked per permission, not per role.
3. An actor may not create an override for **itself** (`actor_id == subject_id`) on any
   permission. Self-modification of privilege is refused outright rather than
   analysed — the analysis is where the bugs live.
4. An actor may not target ROOT with any authorisation operation.
5. An actor may not assign a role whose `allowed_principal_type` conflicts with the
   subject's principal type. Enforced again by a database trigger.
6. A `DENY` override may be created by anyone who could grant the corresponding `ALLOW`;
   removing a `DENY` requires the same authority. (Removal is an escalation; addition is
   a restriction.)

## 7. ROOT — the single bypass, and what it does *not* bypass

`evaluate` returns `Allow(RootOwnership)` for the owner. That is the whole of the
exception, and it is reached only after the request has already satisfied:

- a valid, unrevoked, unexpired session belonging to an `ACTIVE` user
- `pending_mfa = false` (ROOT has `mfa_required = true`, so this means a verified factor)
- step-up recency for any operation on the step-up list
- request validation and input limits
- rate limiting
- audit logging — ROOT actions are audited exactly like everyone else's

ROOT is not an unauthenticated bypass, not an MFA bypass, and not an audit bypass.

There is deliberately **no** `if user.is_admin { allow }` anywhere in the codebase. A CI
grep test fails the build if such a pattern is reintroduced. The built-in *System
Administrator* role is an ordinary role holding ordinary permissions; it is powerful, it is
still subordinate, and it can be inspected and reduced like any other role.

## 8. Built-in roles

| Code | Principal type | Contents |
| --- | --- | --- |
| `system_administrator` | INTERNAL | Broad IAM/business permissions at `GLOBAL`, **excluding** `settings.security.write` and `iam.permissions.delegate`, which ROOT grants deliberately. `is_system = true` |
| `employee` | INTERNAL | `projects.read@ASSIGNED`, `tasks.read@ASSIGNED`, `tasks.update@ASSIGNED`, `departments.read@DEPARTMENT`, `iam.users.read@SELF`. `is_system = true` |
| `client_user` | CLIENT | `client.portal.projects.read@ASSIGNED`, `client.portal.tasks.read@ASSIGNED`. `is_system = true` |

A newly invited employee receives `employee` and nothing else unless the inviter
explicitly — and within its own delegation authority — adds more.

## 9. CLIENT visibility (layer 4)

The predicate compiled into every client-facing query:

```sql
-- a project is visible to CLIENT user :uid iff
EXISTS (
  SELECT 1
    FROM project_client_links pcl
    JOIN client_memberships   cm ON cm.client_account_id = pcl.client_account_id
    JOIN client_accounts      ca ON ca.id = pcl.client_account_id
   WHERE pcl.project_id = p.id
     AND pcl.revoked_at IS NULL
     AND cm.user_id     = :uid
     AND cm.status      = 'ACTIVE'
     AND ca.status      = 'ACTIVE'
)

-- a task is visible to CLIENT user :uid iff
   t.client_visible = true  AND  <the project predicate above for t.project_id>
```

Two consequences worth stating because they are easy to get wrong:

- Sharing a project with a client does **not** expose its tasks. `tasks.client_visible`
  is per-task, defaults to `false`, and must be set explicitly by an internal principal.
- Revoking a link (`revoked_at`) removes visibility immediately, on the next query, with
  no cache to invalidate.

## 10. `404` vs `403`

| Situation | Response |
| --- | --- |
| CLIENT requests an object it cannot see | **`404 RESOURCE_NOT_FOUND`** — a `403` would confirm the object exists |
| CLIENT calls an internal-only route | **`404`** — the route's existence is not the client's business |
| INTERNAL principal lacks a permission on a resource that exists and is within the company | **`403 AUTHORIZATION_DENIED`** — existence disclosure inside the company is acceptable and a `404` here would make operational support impossible |
| Any principal targets ROOT with a forbidden authorisation operation | **`403 ROOT_PROTECTED`** — ROOT's existence is not a secret; the refusal should be unmistakable |

The rule is applied per-principal-type, not blanket, and is implemented once in
`AppError::for_principal` rather than at each call site.

## 11. Caching

**There is none.** Effective permissions are recomputed from the database on every request
that needs them (two indexed queries, joined). Measurements are in
`PERFORMANCE_REPORT.md`. `users.security_version` exists and is bumped on every privilege
change so that a future cache has a correct invalidation key, and so that `/auth/me`
clients can detect that their capability set changed — but no cache is introduced before
there is a measurement demanding one. Stale authority is a security bug; a few hundred
microseconds is not.
