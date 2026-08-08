# Backend acceptance audit — §3 ROOT destruction, §4 privilege escalation, §5 CLIENT isolation, §6 authentication

**Scope.** Sections 3–6 of the backend acceptance audit.
**Method.** Every claim below was re-derived against the working tree by executing
tests, not by reading prior reports. Attacks were driven through the real router,
the real service functions, and real PostgreSQL connections opened as the runtime
role (`roleblank_app`) and as the schema owner (`roleblank_migrator`).
**Environment.** `rust:1-bookworm` container on `roleblank_net`, against
`roleblank-postgres`. Each test gets its own database cloned from a migrated
template, so no test observes another's rows.

**Result:** `cargo test --test security_suite` — **142 passed, 0 failed**
(83 at the start of this audit). 45 of those tests were added by this audit; a
further 3 were contributed concurrently by another agent into
`escalation_matrix.rs` while this section was being written.

---

## 1. Defects found

Five findings. **No CRITICAL or HIGH defect was found in the application itself
across sections 3–6.** The single HIGH (F-5) is in the *test harness*: it has no
production impact, but it can void the security gate that everything else in this
report depends on, so it is rated on what it costs to trust the suite. Every
destructive, escalating, cross-tenant and authentication-bypass attack listed in
§2 was already refused by the system before this audit began; the sections below
record the three places where the *reasoning* behind a refusal is weaker than the
refusal itself, and one place where a documented invariant is narrower than its
prose suggests.

I want to be explicit that this is the honest result and not a soft one: the
attacks in §2 include the ones that normally succeed — permission caching in the
token, `403`-vs-`404` existence oracles, DENY escape by role addition, role
composition escalation, TOTP replay, refresh-token reuse, and self-promotion via
a self-authored role. All were refused, and the evidence is the table in §2.

---

### F-1 — `mfa_required` is not applied when a dangerous permission is granted to an existing account

| | |
|---|---|
| **Severity** | **LOW** (fails closed; forward-looking risk) |
| **Status** | Open — reported, regression test added, no code change made |
| **Regression test** | `auth_attacks::a_dangerous_permission_granted_without_mfa_fails_closed` |

**Description.** The permission catalogue documents `is_dangerous` as: *"Granting
or exercising it requires a recent step-up, **and mandates that the holder has MFA
enrolled**"* (`backend/src/modules/authorization/catalog.rs:19-22`). That mandate
is implemented on exactly one path — invitation acceptance, which derives
`mfa_required` from the invited roles at
`backend/src/modules/identity/invitations.rs:506`. It is **not** implemented when
dangerous authority is added to an account that already exists, i.e. by
`authz_service::assign_role` (`backend/src/modules/authorization/service.rs:1008`)
or `authz_service::create_override`
(`backend/src/modules/authorization/service.rs:1288`). Both call
`bump_security_version` (`backend/src/app.rs:173`); neither touches
`users.mfa_required`.

**Attack scenario.** The owner grants an existing employee
`iam.permissions.delegate@GLOBAL`. That employee has never enrolled a second
factor. They now hold, on paper, the single most dangerous permission in the
system on a password-only account.

**Why it is LOW and not HIGH.** It fails *closed*, and this is asserted rather than
assumed. Step-up is derived per request from `sessions.mfa_verified_at`
(`backend/src/modules/authentication/principal.rs:56-66`), and that column is
written only by `repo::mark_mfa_verified`, called only from the three genuine MFA
endpoints. An account with no enrolled factor therefore can never satisfy the
step-up window, and every use of the dangerous permission returns
`403 STEP_UP_REQUIRED`. The regression test grants the full delegation kit to an
unenrolled account, confirms the session is live and non-pending, confirms a
*non*-dangerous permission works, and then confirms every dangerous use is refused
and that zero rows were written.

**Why it is still worth fixing.** The safety property rests entirely on "nothing
but a real factor can set `mfa_verified_at`". Any future trusted-device flow, SSO
assertion, or administrative step-up override turns this from an onboarding
inconvenience into a privilege-escalation path, and today there is nothing that
would fail if it did. The operational symptom is also poor: the grant is audited
as successful, and the grantee simply cannot use it, with no signal to the granter.

**Fix.** In `assign_role` and `create_override`, after the delegation guard
succeeds, set `users.mfa_required = true` for the subject when the role or the
permission is dangerous — mirroring
`invitations.rs:506`'s `summaries.iter().any(role_is_dangerous)`. Then extend
`a_dangerous_permission_granted_without_mfa_fails_closed` to additionally assert
`mfa_required` is now true and the subject's next login is `pending_mfa`.

---

### F-2 — the ROOT guard is not the first check in `delete_override`

| | |
|---|---|
| **Severity** | **INFO** (not exploitable; defence-in-depth ordering) |
| **Status** | Open — reported, covered by a regression test that asserts the refusal without freezing the weaker code |
| **Regression test** | `root_destruction::the_authorisation_service_refuses_the_owner_when_called_directly` |

**Description.** ADR-004 layer 4 states that `guard_root` is *"the first thing
every user-targeting operation calls, before authorisation, before validation and
before any write"* (`backend/src/modules/identity/mod.rs:16-18`). Every operation
audited holds to that except `authz_service::delete_override`
(`backend/src/modules/authorization/service.rs:1407`), which looks the override
row up at line **1448** and returns `AppError::NotFound` *before* reaching
`authorise_grant`, which is where `subject_is_root` is evaluated. Targeting the
owner therefore yields `404 RESOURCE_NOT_FOUND` rather than `403 ROOT_PROTECTED`.

**Attack scenario.** None that works. The owner can never hold a permission
override: `create_override` refuses the owner as its first substantive check, the
owner is the first user created by bootstrap so no override can predate ownership,
and ownership is immutable so no override-holder can later become the owner. The
lookup therefore always returns `None` and the operation is always refused.

**Impact of leaving it.** Two things degrade. The refusal is no longer audited as
`ROOT.PROTECTION_TRIGGERED`, so an attacker probing the owner through this one
route does not appear in the intrusion-detection feed that
`root_attack::every_attempt_on_the_owner_is_recorded_and_the_record_cannot_be_erased`
relies on. And the invariant now depends on a three-step argument about bootstrap
ordering rather than on a guard, which is exactly the kind of reasoning that stops
being true after an unrelated change.

**Fix.** Move the subject-is-root check ahead of the override lookup in
`delete_override`, matching `assign_role`/`unassign_role`/`create_override`:

```rust
let subject = load_locked_subject(state, &mut tx, user_id).await?;
if subject.is_root { return Err(refuse(..., AppError::RootProtected).await); }
```

Then tighten the regression test's `matches!(deleted, Err(RootProtected) | Err(NotFound))`
to `RootProtected` alone. The test deliberately accepts both today rather than
asserting `NotFound`, so that fixing the ordering does not require editing the test
to something weaker.

---

### F-3 — the database-layer ROOT invariant covers lifecycle and envelope, not credentials

| | |
|---|---|
| **Severity** | **INFO** (documentation accuracy; no additional capability conferred) |
| **Status** | Open — reported; the invariant that *is* claimed is fully tested |
| **Regression test** | `root_destruction::the_runtime_role_cannot_destroy_the_owner_of_a_live_system`, `root_destruction::the_trigger_refuses_even_a_privileged_connection` |

**Description.** `migrations/0009_runtime_grants.sql:44` grants the runtime role
`SELECT, INSERT, UPDATE` on `users` and `credentials`, and the ROOT protection
trigger (`migrations/0001_system_and_identity.sql:163-207`) guards exactly four
things on the owner's row: `status`, `principal_type`, `mfa_required`, and `id`,
plus an unconditional `DELETE` refusal.

I verified empirically, as `roleblank_app` against a seeded owner, that the
runtime role **can**:

* `UPDATE users SET email = ..., email_normalized = ...` on the owner — `UPDATE 1`
* `UPDATE users SET display_name = ...` on the owner — `UPDATE 1`
* `INSERT`/`UPDATE` the owner's row in `credentials` — `INSERT 0 1`

and **cannot** suspend, archive, un-activate, demote, un-MFA, delete, re-id, or
re-own it (all `ERROR: ... rb_users_protect_root()` or a privilege failure).

**Attack scenario.** An attacker with arbitrary SQL execution inside the API
process rewrites the owner's credential row, or takes the owner's email address
and drives the password-reset flow.

**Why this is INFO and not a vulnerability.** The same role holds
`GRANT ... INSERT ... ON sessions`, so an attacker at that level can simply insert
a session row for the owner and authenticate as ROOT directly. Rewriting the
credential confers nothing the position did not already confer. Privilege
separation here is not claimed to survive code execution in the process — it is
claimed to prevent the application from *destroying* the owner and from rewriting
the audit trail, and both of those hold completely.

**Fix.** Documentation, not code. The comment block in
`migrations/0009_runtime_grants.sql:80-91` should say that the invariant the
runtime role cannot breach is the owner's **existence, lifecycle state and
envelope**, and that credential and profile columns are inside the application's
own authority by design. Optionally, extend `rb_users_protect_root` to pin the
owner's `email_normalized` as well — cheap, and it removes the reset-flow path.

---

### F-4 — a bounded administrator cannot assign the built-in `employee` role

| | |
|---|---|
| **Severity** | **INFO** (correct behaviour; usability consequence worth recording) |
| **Status** | Working as designed — recorded because it was mistaken for a defect during this audit |
| **Regression test** | `escalation_matrix::a_deny_cannot_be_escaped_by_adding_another_role` (comment) |

**Description.** Role assignment is validated permission by permission
(`backend/src/modules/authorization/delegation.rs:159-197`), so assigning a role
requires holding *every* permission it contains, at a derivable scope. The
built-in `employee` role contains `departments.read@DEPARTMENT` and
`projects.read@ASSIGNED` (`migrations/0008_seed_catalog.sql:119-124`). An
administrator holding `projects.read@DEPARTMENT` cannot derive `@ASSIGNED` —
correctly, since the two are incomparable — and so cannot onboard an employee at
all.

This is the composition-safe behaviour and must not be relaxed: the alternative is
the classic escalation where `iam.roles.assign` alone lets an actor hand out a role
containing authority it lacks. It is recorded here only because it is
counter-intuitive, and because the natural "fix" (checking only `iam.roles.assign`)
would be a HIGH-severity regression. Three of my own tests initially failed against
it; all three were the test being wrong.

**Fix.** None. If onboarding needs to be delegable, grant the delegating role the
union of `employee`'s contents explicitly — do not weaken the check.

---

### F-5 — concurrently running test binaries destroy each other's template database

| | |
|---|---|
| **Severity** | **HIGH** (test infrastructure only — no production impact — but it can silently void the entire security gate) |
| **Status** | Open — reported only; the fix belongs in `tests/common/mod.rs`, which this section may not modify |
| **Regression test** | none possible from inside the harness that exhibits the bug |

**Description.** `ensure_template` in `backend/tests/common/mod.rs:95-120` builds
the shared template database. Its `OnceCell` guard is **per test binary**, but the
resource it guards is **global to the PostgreSQL server**, and the function does
this before every binary's first test:

```rust
SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = 'roleblank_test_template';
DROP DATABASE IF EXISTS roleblank_test_template;
CREATE DATABASE roleblank_test_template OWNER roleblank_migrator;
-- then runs all migrations into it
```

`cargo test` runs the ten test binaries in parallel. Each one therefore kills every
connection to the template — *including another binary's in-flight
`CREATE DATABASE ... TEMPLATE roleblank_test_template`* — then drops and rebuilds
it. Binary B's clone fails against a template binary A has just removed.

**Evidence.** The failure is `PgDatabaseError { code: "3D000", message: "template
database \"roleblank_test_template\" does not exist" }` raised at
`tests/common/mod.rs:149` (`clone the template`). Three further signatures confirm
the mechanism rather than a logic fault:

* the failing set **rotates between runs** — across four consecutive `cargo test`
  runs it was `{hardening}`, `{integration, race}`,
  `{failure_injection, golden_scenario, hardening}`, then `{security}`;
* failing binaries finish in **0.07–0.5 s**, far too fast to have executed their
  assertions — they abort in `TestApp::spawn`, before any request is made;
* every suite passes when run alone immediately afterwards, against a byte-identical
  tree. `security_suite` reported `67 passed / 74 failed` in one parallel run and
  `141 passed / 0 failed` seconds later with no change to any file.

**The worst observation.** While another agent was running its own tests against
the same database, `cargo test --test race_suite` — a single binary, run entirely
on its own from this session — produced:

```
test result: FAILED. 0 passed; 58 failed; ... finished in 2.25s
```

Fifty-eight failures, none of which executed a single assertion; every one aborted
in `TestApp::spawn` with error `3D000`. **A suite in this state reports failure, but
it could just as easily be made to report success** — the same race that removes
the template can also leave a *stale* one in place, since `ensure_template` runs
migrations only into the template it just built. A binary that clones a template
another binary built from an older schema would run its assertions against the
wrong database and pass or fail for reasons unrelated to the code.

**Why it matters.** A security suite that fails a fraction of the time for reasons
unrelated to security is a security suite people learn to re-run rather than read.
This one is the CI gate for §3–§6; the first time it flakes, the next real
regression it catches will be assumed to be the same flake. It also means two
engineers — or two agents — cannot run tests against a shared development database
at the same time, which is precisely what happened throughout this audit and is why
every number in this report was taken from an isolated run.

**Fix.** Any one of these, in `tests/common/mod.rs`:

* build the template under a PostgreSQL **advisory lock** so only one binary
  creates it and the others wait, and only rebuild when the migration set has
  actually changed (compare `_sqlx_migrations` rather than dropping unconditionally);
* or give each binary its own template name (`roleblank_test_template_<binary>`),
  removing the shared resource entirely;
* or stop dropping it: create it only `IF NOT EXISTS` and let a `make db-reset`
  handle schema changes.

Bounding CI to one test binary at a time (`cargo test -- --test-threads=…` does
*not* do this; `cargo test --test <name>` in sequence does) is a workaround, not a
fix — it leaves two developers sharing a database broken.

---

## 2. Evidence — attacks the system already refused

Every row was executed against the current working tree. `Observed` is the status
and the stable `code`, never prose.

### §3 — ROOT destruction

| # | Layer | Attack | Observed |
|---|---|---|---|
| 1 | HTTP | `PATCH /users/{root}` rename | `403 ROOT_PROTECTED` |
| 2 | HTTP | `PATCH /users/{root}` change email | `403 ROOT_PROTECTED` |
| 3 | HTTP | `POST /users/{root}/suspend` | `403 ROOT_PROTECTED` |
| 4 | HTTP | `POST /users/{root}/archive` | `403 ROOT_PROTECTED` |
| 5 | HTTP | `POST /users/{root}/reactivate` | `403 ROOT_PROTECTED` |
| 6 | HTTP | the owner performing 3–5 **on itself** | `403 ROOT_PROTECTED` |
| 7 | HTTP | `DELETE /users/{root}` | `405` — the route does not exist |
| 8 | HTTP | `POST /users/{root}/roles` (assign) | `403 ROOT_PROTECTED` |
| 9 | HTTP | `DELETE /users/{root}/roles/{role}` (unassign) | `403 ROOT_PROTECTED` |
| 10 | HTTP | `POST /users/{root}/permission-overrides` effect `ALLOW` | `403 ROOT_PROTECTED` |
| 11 | HTTP | `POST /users/{root}/permission-overrides` effect `DENY` | `403 ROOT_PROTECTED` |
| 12 | HTTP | the owner granting itself a `DENY` | `403 ROOT_PROTECTED` |
| 13 | HTTP | admin revoking the owner's session by id | `404 RESOURCE_NOT_FOUND` |
| 14 | HTTP | admin `POST /auth/logout-all` (self-scoped; owner unaffected) | `200`, owner still `200` on `/auth/me` |
| 15 | HTTP | smuggle `principal_type: CLIENT` into `PATCH /users/{root}` | `400 BAD_REQUEST` |
| 16 | HTTP | assign the CLIENT-only role to the owner | `403 ROOT_PROTECTED` |
| 17 | HTTP | invite the owner's address as `CLIENT` | `4xx`, owner unchanged |
| 18 | HTTP | `POST /bootstrap/root` again (anon / admin / owner) | `409 SYSTEM_ALREADY_INITIALIZED` |
| 19 | HTTP | invitation carrying `is_root: true` | `400 BAD_REQUEST` |
| 20 | HTTP | 14 bulk / mass-mutation shapes (`/users/bulk`, `/users/batch`, `DELETE /users`, `PATCH /users`, `/users/{id}/demote`, `/system/ownership`, `/system/transfer-ownership`, …) | all `404` or `405` — no such route |
| 21 | HTTP | `PUT` and `DELETE` on all five owner resource paths | never `200`/`204` |
| 22 | HTTP | 25 failed logins against the owner | `401 AUTHENTICATION_FAILED` then `429 RATE_LIMITED` + `Retry-After`; no lockout, session survives, owner logs in after reset |
| 23 | Service | `identity_service::update_user(root)` | `Err(RootProtected)` |
| 24 | Service | `identity_service::suspend_user(root)` | `Err(RootProtected)` |
| 25 | Service | `identity_service::archive_user(root)` | `Err(RootProtected)` |
| 26 | Service | `identity_service::reactivate_user(root)` | `Err(RootProtected)` |
| 27 | Service | `authz_service::assign_role(root)` — as admin **and** as the owner | `Err(RootProtected)` |
| 28 | Service | `authz_service::unassign_role(root)` — both actors | `Err(RootProtected)` |
| 29 | Service | `authz_service::create_override(root)` `ALLOW`/`DENY` — both actors | `Err(RootProtected)` |
| 30 | Service | `authz_service::delete_override(root)` — both actors | refused (`NotFound`; see **F-2**) |
| 31 | DB (runtime role) | `DELETE FROM users WHERE id = root` | privilege denied |
| 32 | DB (runtime role) | `DELETE FROM users WHERE id IS NOT NULL` | privilege denied |
| 33 | DB (runtime role) | `UPDATE users SET status='SUSPENDED'/'ARCHIVED'/'PENDING'` on owner | trigger `rb_users_protect_root` |
| 34 | DB (runtime role) | `UPDATE users SET principal_type='CLIENT'` on owner | trigger |
| 35 | DB (runtime role) | `UPDATE users SET mfa_required=false` on owner | trigger |
| 36 | DB (runtime role) | `UPDATE users SET id = gen_random_uuid()` on owner | trigger |
| 37 | DB (runtime role) | `UPDATE system_ownership SET root_user_id = <admin>` | privilege denied |
| 38 | DB (runtime role) | `INSERT INTO system_ownership` (second owner) | refused (singleton PK) |
| 39 | DB (runtime role) | `DELETE FROM system_ownership` / `TRUNCATE system_ownership` | privilege denied |
| 40 | DB (runtime role) | `TRUNCATE users CASCADE` | privilege denied |
| 41 | DB (runtime role) | `DROP TRIGGER trg_users_protect_root` | not the table owner |
| 42 | DB (runtime role) | `ALTER TABLE users DISABLE TRIGGER trg_users_protect_root` | not the table owner |
| 43 | DB (runtime role) | `ALTER TABLE users DISABLE TRIGGER ALL` | not the table owner |
| 44 | DB (runtime role) | `DROP TRIGGER trg_system_ownership_immutable` | not the table owner |
| 45 | DB (runtime role) | `DROP TABLE system_ownership CASCADE` | not the table owner |
| 46 | DB (runtime role) | `CREATE OR REPLACE FUNCTION rb_users_protect_root()` as a no-op | no `CREATE` on schema `public` |
| 47 | DB (runtime role) | `ALTER TABLE users ADD COLUMN owner_override boolean` | not the table owner |
| 48 | DB (runtime role) | `ALTER TABLE users OWNER TO roleblank_app` | refused |
| 49 | DB (runtime role) | `GRANT ALL ON users` / `ON system_ownership` to itself, then retry `DELETE` | grant confers nothing; `DELETE` still denied† |
| 50 | DB (runtime role) | `SET ROLE postgres` / `SET ROLE roleblank_migrator` | refused |
| 51 | DB (runtime role) | `SET SESSION AUTHORIZATION postgres` | refused |
| 52 | DB (runtime role) | `ALTER ROLE roleblank_app SUPERUSER` | refused |
| 53 | DB (runtime role) | `GRANT roleblank_migrator TO roleblank_app` | refused |
| 54 | DB (schema owner) | delete / suspend / archive / demote / un-MFA the owner | trigger refuses even the owner of the schema |
| 55 | DB (schema owner) | move, delete or duplicate the ownership row | trigger refuses |
| 56 | End state | after the full campaign | exactly **1** ownership row; owner `ACTIVE` / `INTERNAL` / `mfa_required = true`; token still valid; `audit.read` still allowed; fresh login succeeds and is `mfa_required: true` |

† PostgreSQL does not error when a `GRANT` confers nothing — it warns and reports
success. Asserting the statement's outcome here would have produced a test that
fails against a *correct* database. The test asserts the resulting privilege
instead; the comment in `root_destruction.rs` records why.

### §4 — privilege escalation (actor: a deliberately limited administrator)

The actor holds the full delegation kit plus `iam.users.{read,update,suspend}`,
`tasks.read@GLOBAL` and `projects.read@DEPARTMENT`, and a recent second factor.
Every refusal below is therefore about *what it may hand out*, never about whether
it may call the endpoint.

| # | Attack | Observed |
|---|---|---|
| 1 | grant `audit.read` / `clients.read` / `departments.create` / `projects.update` / `iam.users.archive` / `settings.features.write` at `GLOBAL`/`DEPARTMENT`/`ASSIGNED`/`SELF` (24 combinations) | `403 DELEGATION_DENIED`; 0 rows written |
| 2 | grant the dangerous `settings.security.write` / `projects.clients.share`, same 8 combinations | `403 DELEGATION_DENIED`; 0 rows |
| 3 | create a `DENY` for any of the 8 unheld permissions | `403 DELEGATION_DENIED` |
| 4 | control: grant `tasks.read@GLOBAL`, which it does hold | `201 Created` |
| 5 | author a role containing each of the 8 unheld permissions | `403 DELEGATION_DENIED`; 0 custom roles created |
| 6 | author a legal role, then `PATCH` it to add `audit.read` / `settings.security.write` | `403 DELEGATION_DENIED`; role contents unchanged |
| 7 | widen `projects.read` from `DEPARTMENT` to `GLOBAL` | `403 DELEGATION_DENIED` |
| 8 | move `projects.read` sideways from `DEPARTMENT` to `ASSIGNED` | `403 DELEGATION_DENIED` |
| 9 | derive `RESOURCE` scope from `DEPARTMENT` | `403 DELEGATION_DENIED` |
| 10 | author a role widening `projects.read` to `GLOBAL` | `403 DELEGATION_DENIED` |
| 11 | grant **itself** `audit.read` | `403 DELEGATION_DENIED` |
| 12 | grant **itself** `tasks.read`, which it already holds | `403 DELEGATION_DENIED` |
| 13 | assign **itself** the built-in administrator or employee role | `403 DELEGATION_DENIED` |
| 14 | delete a `DENY` that was placed **on itself** | `403 DELEGATION_DENIED`; own grants unchanged |
| 15 | author a legal role, then assign it **to itself** | `403 DELEGATION_DENIED`; 0 assignments |
| 16 | two limited admins: A grants B a permission A holds | `201 Created` (legitimate) |
| 17 | two limited admins: B then grants A `audit.read` / `settings.security.write` | `403 DELEGATION_DENIED` |
| 18 | two limited admins: B widens A's `projects.read` to `GLOBAL` | `403 DELEGATION_DENIED` |
| 19 | **escape a `DENY` by piling on roles**: victim under `tasks.read@GLOBAL` DENY, then given the built-in `employee` role, a custom `tasks.read@GLOBAL` role, and a fresh `ALLOW@SELF` override | still `403 AUTHORIZATION_DENIED` on `/tasks` and `/tasks/{id}`; `/auth/me` does not advertise `tasks.read` |
| 20 | convert a CLIENT to INTERNAL via `PATCH principal_type` | `400 BAD_REQUEST` (unknown field) |
| 21 | assign an INTERNAL role to a CLIENT | `403 DELEGATION_DENIED` |
| 22 | grant `tasks.read` / `iam.users.read` (INTERNAL-only) to a CLIENT | `403 DELEGATION_DENIED` |
| 23 | write that override directly as the **schema owner** | database envelope trigger refuses |
| 24 | assign a CLIENT role to an INTERNAL principal | `403 DELEGATION_DENIED` |
| 25 | assign the built-in `system_administrator` role to a victim | `403 DELEGATION_DENIED`; victim holds nothing |
| 26 | assign the built-in `system_administrator` role to itself | `403 DELEGATION_DENIED` |
| 27 | `PATCH` the built-in `system_administrator` role — as the limited admin **and as the owner** | `403` for both |
| 28 | grant `tasks.read.admin` / `*` / `iam.*` / `TASKS.READ` / `system.root` | `400 UNKNOWN_PERMISSION` (probe, not a plain validation error) |
| 29 | put a `RESOURCE`-scoped permission on a role | `400` |
| 30 | create an override already expired (`2000-01-01`) | `400` |
| 31 | grant an override to an `ARCHIVED` account | `409 SUBJECT_ARCHIVED` |
| 32 | assign a role to an `ARCHIVED` account | `409 SUBJECT_ARCHIVED` |
| 33 | assign a role / grant / `DENY` / suspend against the **owner** | `403 ROOT_PROTECTED`; owner holds no grants |

### §5 — CLIENT isolation

The governing rule is that a refusal must not confirm existence. Assertions compare
**status, the full header set, the body, and the body length**, with only
`request_id` removed — a difference in `content-length` alone is an oracle that no
JSON-level comparison would see.

| # | Attack | Observed |
|---|---|---|
| 1 | control: A reads its own shared project / visible task | `200 OK` |
| 2 | A reads B's project; A reads a nonexistent id | **byte-identical** `404 RESOURCE_NOT_FOUND` |
| 3 | A reads an internal (never-shared) project vs. a nonexistent id | byte-identical `404` |
| 4 | A reads B's task vs. a nonexistent id | byte-identical `404` |
| 5 | A reads a `client_visible = false` task **inside its own project** vs. a nonexistent id | byte-identical `404` |
| 6 | A reads an internal-project task vs. a nonexistent id | byte-identical `404` |
| 7 | A lists tasks of B's project vs. of a nonexistent project | byte-identical `404` |
| 8 | A reads an employee / the owner / a colleague through `/users/{id}` vs. a nonexistent id | byte-identical `404` |
| 9 | same for `/projects/{id}`, `/tasks/{id}`, `/departments/{id}`, `/clients/{id}`, `/roles/{id}` (11 objects) | byte-identical `404` |
| 10 | same for 7 sub-resource routes (`/projects/{id}/members`, `/clients/{id}/members`, `/users/{id}/roles`, `/users/{id}/permissions`, `/tasks/{id}/assignees`, …) | byte-identical `404` |
| 11 | 12 identifier spellings of B's project id — uppercase, `urn:uuid:`, dashless, `%00`, `%20`, trailing `.`/`/`/`?`/`#`, `%2F..%2F` traversal | all `4xx`; never returns the object |
| 12 | `POST`/`PUT`/`PATCH`/`DELETE` on a real vs. a nonexistent id, across 4 route families (16 pairs) | identical status **and** identical body in every pair |
| 13 | forged keyset cursor built from B's project id | rejected, or repositions A's own query; never returns B's row |
| 14 | B's real `next_cursor` replayed by A | never returns B's row |
| 15 | page all the way through with `limit=1` | yields exactly A's one project |
| 16 | 12 smuggled query params (`include=internal_note`, `fields=*`, `expand=members`, `all=true`, `client_visible=false`, `principal_type=INTERNAL`, …) | `400` — unknown parameters are a parse failure, not silently ignored |
| 17 | `include`/`fields`/`expand` on the single-object portal route | never yields `internal_note`, `manager_user_id`, `created_by`, or the note's text |
| 18 | A grants itself a permission / a portal permission / an internal role / the admin role | `404 RESOURCE_NOT_FOUND` |
| 19 | A joins client account B; A shares an internal project with itself; A adds itself to an internal project | `404 RESOURCE_NOT_FOUND` |
| 20 | A creates a role; A issues an invitation | `404 RESOURCE_NOT_FOUND`; 0 roles, 0 invitations in the database |
| 21 | after all of 18–20: A's grants and visible world | unchanged — 1 role, 0 overrides, 1 visible project |
| 22 | 11 internal collections (`/users`, `/roles`, `/permissions`, `/departments`, `/clients`, `/projects`, `/tasks`, `/invitations`, `/audit/events`, `/settings`, `/feature-flags`) | `404` with **no** `items`, `total` or `count` — never an empty successful page |
| 23 | `/system/info` (authenticated, permissionless — a client reaches it) | carries no population counts, no topology, no host or database detail |

### §6 — authentication

| # | Attack | Observed |
|---|---|---|
| 1 | 12 password failure modes — wrong, nonexistent account with wrong and with *correct* password, empty, 4096-char, Unicode (RTL override + combining mark + astral emoji), trailing `NUL`, trailing space — each against a real and a fake address | all **byte-identical** `401 AUTHENTICATION_FAILED` |
| 2 | 7 malformed login payloads (missing / null / numeric / array / object password, `is_root: true`, `role_ids: [...]`), each against a real and a fake address | identical status and identical body within every pair |
| 3 | 400 KB login body | `413 PAYLOAD_TOO_LARGE` (transport, before any lookup) |
| 4 | password-reset request for a real vs. a fake address | identical response bytes; only the server-side outbox differs (1 queued) |
| 5 | 7 wrong TOTP codes — `000000`, `999999`, too short, too long, non-numeric, empty, whitespace | `401 AUTHENTICATION_FAILED`; a genuine code then succeeds |
| 6 | 12 consecutive wrong TOTP codes | `401` then `429 RATE_LIMITED` with `Retry-After` |
| 7 | replay a consumed TOTP code from the same session | `401 AUTHENTICATION_FAILED` |
| 8 | replay it from a **different session** of the same user | `401 AUTHENTICATION_FAILED` |
| 9 | audit trail after 7–8 | ≥ 2 × `MFA.REPLAY_DETECTED`; watermark set and never moves backwards |
| 10 | reuse a consumed recovery code (same session) | `401 AUTHENTICATION_FAILED` |
| 11 | reuse it from another session | `401 AUTHENTICATION_FAILED` |
| 12 | spend **another account's** recovery code | `401 AUTHENTICATION_FAILED`; that account's live-code count unchanged |
| 13 | first recovery-code use | `200`, remaining count decremented by exactly 1 |
| 14 | disable MFA from a session with no recent second factor | `403 STEP_UP_REQUIRED` / `MFA_REQUIRED`; `mfa_enrolled` still true |
| 15 | regenerate recovery codes from that session | `403` |
| 16 | disable MFA on the owner **with** a fresh factor | `409 MFA_MANDATORY`; owner's flags unchanged |
| 17 | privileged (owner) password-only login reaching `/users`, `/roles`, `/audit/events`, `/settings`, `/projects`, `/auth/sessions` | `403 MFA_REQUIRED` on every one |
| 18 | the same session writing: grant an override, assign a role, `logout-all` | `403` |
| 19 | `/auth/me` on a pending session | `200`, reports `mfa_required: true`, and does **not** carry the owner's capability list |
| 20 | 8 invalid bearer tokens — revoked, expired, suspended user's, well-formed random, malformed, empty, refresh-token-as-access, wrong prefix | all **byte-identical** `401 AUTHENTICATION_FAILED` |
| 21 | password reset, then the two sessions that predated it | both `401 AUTHENTICATION_FAILED` |
| 22 | reuse the reset token | `4xx` |
| 23 | login with the pre-reset password / the new password | `401` / `200` |
| 24 | refresh rotation | both access and refresh tokens change; new pair works |
| 25 | replay the consumed refresh token | `4xx`, and the **whole family** dies — the currently-live access token and the current refresh token both stop working, with a recorded revocation reason |
| 26 | dangerous permission granted to an unenrolled account, then used | `403 STEP_UP_REQUIRED`; 0 rows written (see **F-1**) |
| **27** | **change a user's permissions while they hold a live session** — see below | **the next request uses the new permissions** |

**#27, the single most important test**
(`auth_attacks::a_live_session_uses_the_new_permissions_on_the_very_next_request`).
One session is issued at the top and the same bearer string is used throughout;
between requests the authority is changed through the real HTTP surface. Six
transitions, in both directions:

| Step | Change made | The very next request |
|---|---|---|
| 0 | — (no authority) | `403 AUTHORIZATION_DENIED` |
| 1 | `ALLOW tasks.read@GLOBAL` override created | `200 OK` |
| 2 | that override deleted | `403 AUTHORIZATION_DENIED` |
| 3 | a role carrying `tasks.read@GLOBAL` assigned | `200 OK` |
| 4 | a `DENY tasks.read@GLOBAL` override created | `403 AUTHORIZATION_DENIED` |
| 5 | that `DENY` deleted | `200 OK` |
| 6 | the role unassigned | `403 AUTHORIZATION_DENIED` |

No re-login, no token refresh, no waiting for expiry. Additionally asserted:
`security_version` is bumped, the session is **not** revoked by the privilege
change (a privilege change is not a session kill and must not be implemented as
one), `/auth/me`'s capability list moves in step with the evaluator in both
directions, and the session's identity is unchanged at the end.

`auth_attacks::scope_changes_also_apply_on_the_next_request` proves the same for
*reach* rather than for grants: a `DEPARTMENT`-scoped holder gains and then loses
access to a project by joining and leaving the department, one request later each
time; and suspension kills the live session on its next request.

---

## 3. Tests added

All under `backend/tests/security/`, registered in `backend/tests/security_suite.rs`.

| File | Tests added here | Section |
|---|---|---|
| `root_destruction.rs` | 8 | §3 — route, service, runtime role, trigger, end-to-end |
| `escalation_matrix.rs` | 14 | §4 — the deliberately limited administrator |
| `client_isolation.rs` | 8 | §5 — byte-level indistinguishability |
| `auth_attacks.rs` | 15 | §6 — passwords, second factors, privilege freshness |
| **Total added** | **45** | |

`escalation_matrix.rs` now holds 17 tests: a concurrent agent appended three
invitation-placement tests to it while this section was being written. One of them
(`an_invitation_cannot_place_an_account_into_an_unmanaged_department`) called this
file's `escalation_denied` helper, which deliberately accepts only
`DELEGATION_DENIED` and `STEP_UP_REQUIRED`. The system's actual refusal is
`403 AUTHORIZATION_DENIED`, which is the *correct* code — that inviter holds
`departments.members.manage` at no scope at all, so it is an authorisation denial
and not a lattice denial. I corrected the assertion in that test to expect the
accurate code rather than widening the shared helper, because widening it would
have blunted the fourteen lattice tests that depend on `AUTHORIZATION_DENIED`
being distinguishable from a delegation refusal.

No file under `backend/src/` was modified: no defect found in sections 3–6
warranted a code change, and I did not want to alter production code on the
strength of a finding I had classified as INFO or LOW.

---

## 4. Verification

Every suite passes. Run them **one binary at a time, with nothing else using the
development database** — see F-5 for why that qualifier is load-bearing.
`security_suite` was additionally run three times consecutively and reported
`141 passed; 0 failed` on each (the suite grew to 142 immediately afterwards, by a
concurrent agent's addition, and remained green).

| Suite | Result |
|---|---|
| `roleblank_backend` unit tests | 596 passed, 0 failed |
| `failure_injection` | 10 passed, 0 failed |
| `golden_scenario` | 1 passed, 0 failed |
| `hardening_suite` | 34 passed, 0 failed |
| `integration_suite` | 155 passed, 0 failed |
| `openapi_contract` | 5 passed, 0 failed |
| `race_suite` | 58 passed, 0 failed |
| `router_registry` | 5 passed, 0 failed |
| **`security_suite`** | **142 passed, 0 failed** |

`security_suite` was **83** tests green at the start of this audit and **142** green
at the end. The count moved from 138 → 141 → 142 during the final verification pass
as concurrent agents added tests to files outside this section; it was green at
every one of those points. The number that belongs to this section is the **45 tests
added here**, all of which pass.

### A caveat about bare `cargo test` — see F-5

A plain `cargo test` runs all ten test binaries **concurrently**, and under that
load a rotating subset of suites fails. This is a harness defect, not a
correctness regression, and it is written up as **F-5** below. Run one binary at a
time and everything is green.

---

## 5. What I could not test, and why

1. **Real clock passage.** Absolute session lifetime, idle timeout and the natural
   expiry of a TOTP step are exercised by writing past timestamps into the database
   rather than by waiting. The refusal logic is therefore proven; a bug that lives
   only in how "now" is obtained would not be caught here. `sessions::classify_refresh`
   is separately unit-tested at its boundaries.
2. **Genuine parallelism against the ROOT invariant.** The suite runs each test in
   its own database and the destructive attacks are sequential. A race between, say,
   a bootstrap and a concurrent ownership insert is covered by `race/bootstrap.rs`,
   which I do not own; I did not duplicate it.
3. **Transport-layer attacks.** Tests drive the router in-process via
   `tower::ServiceExt::oneshot`, so TLS, HTTP/2 framing, header smuggling between a
   proxy and the application, and the real body-size limit as enforced by a socket
   are out of reach. The `413` in §6 row 3 is the middleware's limit, not a socket's.
4. **`ALTER SYSTEM` / superuser-level database attacks.** Attempted as the runtime
   role and refused, but a compromise of the `postgres` superuser is outside every
   layer of the ROOT invariant by construction and there is nothing to assert.
5. **Timing as an oracle beyond login.** `attack_probes::login_timing_does_not_reveal_whether_an_account_exists`
   covers login. I did not build timing harnesses for the MFA or the
   permission-override paths; in-process test timings are too noisy to make such an
   assertion trustworthy, and a flaky timing assertion in a security suite is worse
   than none.
6. **F-1's fix is unverified.** I reported it rather than implementing it: the
   change belongs in `src/modules/authorization/service.rs`, and I did not want to
   modify production code for a LOW finding that fails closed while a concurrent
   agent was working nearby. The regression test is in place and will need one added
   assertion once the fix lands.
7. **A moving target.** Another agent edited `backend/src/` (`platform/errors`,
   `platform/http/extract`, `identity/routes`, `clients/routes`,
   `departments/routes` and others) and `backend/tests/` throughout this section's
   execution. Every result above was re-run against the tree as it stood at the end,
   and `security_suite` was green on that final state — but these sections should be
   re-run once the other sections settle, because a §3–§6 property could be broken
   by a later edit to a file this section does not own.
