# ADR-004 — The ROOT_OWNER invariant

**Status:** Accepted · **Date:** 2026-08-07

## Context

RoleBlank OS has exactly one application owner. If that ownership can be removed, disabled
or transferred through runtime application functionality, then a single application defect,
a single over-permissive role, or a single compromised administrator is sufficient to take
the company's operating system. This is asset A1 in the threat model.

## Decision

**System ownership is a singleton row in `system_ownership`, not a role, not a flag, and
not a permission.** It is established exactly once at bootstrap and is immutable through
every runtime path. It is enforced independently at three layers.

### Layer 1 — schema

```sql
CREATE TABLE system_ownership (
    id             boolean PRIMARY KEY DEFAULT true CHECK (id),
    root_user_id   uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    established_at timestamptz NOT NULL DEFAULT now()
);
```

`id boolean PRIMARY KEY CHECK (id)` admits one row and only one row. A second owner is a
primary-key violation, not a business-rule violation. `ON DELETE RESTRICT` means the owner
row cannot be removed while ownership references it.

### Layer 2 — triggers

- `trg_system_ownership_immutable`: `BEFORE UPDATE OR DELETE` → `RAISE EXCEPTION`,
  unconditionally. There is no argument, no actor, and no escape.
- `trg_system_ownership_internal_only`: the referenced user must be `INTERNAL`.
- `trg_users_protect_root`: on `users`, `BEFORE UPDATE OR DELETE`, consulting
  `system_ownership` — refuses `DELETE`, refuses any `status <> 'ACTIVE'`, refuses any
  `principal_type <> 'INTERNAL'`, refuses `mfa_required = false`.

### Layer 3 — database privileges

The runtime role (`roleblank_app`) is granted **no** `DELETE` on `users`, **no** `INSERT`,
`UPDATE` or `DELETE` on `system_ownership`, and is not the owner of any table — so it cannot
`ALTER TABLE … DISABLE TRIGGER`. The migrator role that owns the schema is not the role the
application connects as.

### Layer 4 — application

`RootGuard` is consulted by every service that could target a user: suspend, archive,
update, role assignment, override creation, session revocation, bulk operations. Bulk
endpoints filter the owner out of their target set *before* acting, so "select all" cannot
sweep it up. `ROOT_PROTECTED` is a distinct, unmistakable error code.

## Explicitly *not* provided

**Ownership transfer is not an API.** There is no endpoint, no service method, and no
permission for it. Sections 9 and 120 of the brief require this, and the reasoning is that
a transfer capability is precisely the capability an attacker wants: any code path that can
legitimately move ownership is a code path that can be abused to steal it.

Disaster recovery — the genuine case where the owner is unreachable — is an **offline
procedure** requiring direct database access with the migrator/owner role, performed under
change control, and documented in `08-operations.md` §Ownership recovery. It leaves an
audit event and is deliberately inconvenient.

## What ROOT still is subject to

Ownership is an *authorisation* bypass only. ROOT must still present a valid, unrevoked
session belonging to an `ACTIVE` user, must have completed MFA (`mfa_required` is forced
true and cannot be unset), must satisfy step-up recency for sensitive operations, and is
audited identically to every other principal. ROOT is not an unauthenticated back door.

## Availability

ROOT is a single point of failure by design, which creates a denial-of-service target: an
attacker who could lock the owner out by submitting bad passwords would have disabled the
company. Therefore **ROOT is never permanently locked**. Failed authentication against the
owner is throttled with exponential backoff (shared with every other account) but never
converts into a lockout state. This is tested by `root_not_lockable`.

## Consequences

- Losing the ROOT credentials **and** all recovery codes requires the offline procedure.
- Twelve distinct attack vectors against ROOT are exercised by `tests/security/root_attack.rs`,
  including direct SQL executed as the runtime role — proving the database refuses even
  when the application is bypassed entirely.
- A future "break-glass second owner" would require an ADR superseding this one, not a
  quiet schema change.

## Alternatives rejected

| Alternative | Why not |
| --- | --- |
| `users.is_root boolean` | A column on a table administrators legitimately update — one wrong `UPDATE … SET` away from disaster |
| A `roles` row named `root` | Reachable by the role-management API; makes ownership ordinary data |
| Application-only enforcement | A single application bug becomes sufficient. The brief requires DB-level enforcement |
| An ownership-transfer endpoint gated by step-up | Creates the exact code path an attacker needs; offline recovery achieves the legitimate case without it |
| Multiple owners | Removes the "exactly one" invariant that makes the singleton PK possible |
