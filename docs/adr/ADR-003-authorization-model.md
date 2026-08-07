# ADR-003 — Authorization model

**Status:** Accepted · **Date:** 2026-08-07

## Context

RoleBlank OS has internal staff with graded authority and external clients who must see
only what is explicitly shared. Administrators must be able to delegate, but must not be
able to manufacture authority they do not hold. The model has to remain auditable by a
human reviewer years from now.

## Decision

**RBAC + a closed set of five scopes + explicit per-user ALLOW/DENY overrides**, evaluated
deny-by-default, with a hard principal-type envelope checked before any grant lookup, and a
delegation guard built on an explicitly *partial* scope-derivation order.

Rejected: a general policy language (Cedar/OPA-style, or JSON rules in the database).

## Rationale

**Why not a policy engine.** A policy DSL moves the security-critical logic out of the type
system, out of code review, and into database rows that administrators can edit. The brief
is explicit — "do not create a generic policy language nobody can audit". The entire
evaluator here is one function with eight numbered steps (`04-authorization.md` §5), it is
`proptest`-verified, and a reviewer can hold all of it in their head. When the module count
grows, scopes may be *added* to the closed enum with a compiler-enforced exhaustiveness
check across every match site — the enum is the migration mechanism.

**Why the envelope is checked first.** Client isolation must not depend on the correctness
of grant collection. `principal_type = CLIENT` + `permission.max_principal_type = INTERNAL`
is a refusal that happens before roles or overrides are read at all, so no misconfigured
role, no stray override, and no bug in the grant query can produce an internal capability
for an external principal. A `proptest` generates random role/override/target combinations
and asserts the property holds for all of them.

**Why explicit DENY exists and always wins.** Real organisations need "this person, not
this thing" without dismantling a role. Evaluating denials before allows — and never
consulting the allow set once a matching denial is found — makes "add another role to
escape a DENY" structurally impossible rather than merely unlikely.

**Why the scope order is partial.** `DEPARTMENT` and `ASSIGNED` are incomparable. Treating
scopes as a single integer ladder (`GLOBAL > DEPARTMENT > ASSIGNED > SELF`) would let a
department-bounded manager mint `ASSIGNED` authority, whose grantee could then be assigned
to a project in another department — a silent lateral escalation. The lattice therefore
enumerates the legal derivations, and every unlisted pair is denied:

```
GLOBAL      → GLOBAL, DEPARTMENT, ASSIGNED, SELF, RESOURCE(*)
DEPARTMENT  → DEPARTMENT, SELF
ASSIGNED    → ASSIGNED, SELF
SELF        → SELF
RESOURCE(x) → RESOURCE(x)
```

**Why self-delegation is refused outright.** Any actor modifying its own privileges is
refused (`actor_id == subject_id` → deny) rather than analysed for whether the change is an
escalation. The analysis is subtle, the refusal is not, and no legitimate workflow requires
it — ROOT performs privilege changes for others, and ROOT's own authority is ownership, not
a grant.

**Why no caching.** Correctness over speed, per the brief. `users.security_version` exists
as a future cache key and as a change signal in `/auth/me`, but the evaluator reads the
database every time. A cache with a subtly wrong invalidation path preserves revoked
privileges — a security bug traded for microseconds.

## Consequences

- Two indexed queries per authorised request (role grants, overrides). Measured.
- Adding a scope type is a compile error at every match site until handled — intentional.
- List endpoints cannot be "authorise then fetch all"; a narrow scope compiles into a SQL
  predicate. This is more work per endpoint and is the reason BOLA is hard to reintroduce.
- Administrators cannot escalate by role composition: role assignment is validated
  permission-by-permission against the actor's own effective grants, not role-by-role.

## Alternatives rejected

| Alternative | Why not |
| --- | --- |
| Cedar / OPA / JSON policies in the DB | Unauditable at review time; moves security into editable data |
| Pure RBAC, no scopes | Forces `GLOBAL`-only roles, which makes least privilege impossible |
| ReBAC (Zanzibar-style) | Powerful and correct for large graphs, but a whole subsystem with its own consistency semantics; unjustified at this scale |
| Ownership-only checks (`resource.owner_id == actor.id`) | Cannot express departments, delegation, or client sharing |
| Totally ordered scopes | Permits the DEPARTMENT→ASSIGNED lateral escalation described above |
