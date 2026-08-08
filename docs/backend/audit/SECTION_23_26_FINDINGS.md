# §23 security source review and §26 architecture sanity — findings

Formal backend acceptance audit. **Manual source review only** — no tests were
run and no source file was modified. Every claim cites `file:line`.

British-English spelling throughout. Severities: CRITICAL / HIGH / MEDIUM / LOW /
INFO.

Two phrases are used deliberately and mean different things:

* **"Verified"** — I traced the whole path in the source and the property holds
  for every branch I could reach.
* **"Looks safe, not verified"** — the code reads correctly but the property
  depends on something I could not settle from `backend/src` alone (a database
  trigger, a migration, a runtime grant, or a test I was not permitted to read).

The companion route inventory is `docs/backend/ROUTE_SECURITY_MATRIX.md`.

---

## Summary

| Severity | Count | IDs |
| --- | --- | --- |
| CRITICAL | 0 | — |
| HIGH | 1 | F-01 |
| MEDIUM | 6 | F-02, F-03, F-04, F-06, F-07, A-01 |
| LOW | 6 | F-05, F-08, F-09, F-10, F-13, A-02 |
| INFO | 5 | F-11, F-12, F-14, A-03, A-04 |

No fail-open path, no forgotten route authorisation, no shadow-admin bypass, no
default-allow and no panic path was found in non-test code. Those four are
reported as **verified negatives** in §7 below, because "we looked and it is not
there" is a result worth recording.

---

## 1. HIGH

### F-01 — An invitation places its subject into an arbitrary department or client account with no authorisation for that placement

**Severity: HIGH.** Privilege escalation and cross-boundary data exposure.

**Where.**
`backend/src/modules/identity/invitations.rs:66-108` (creation),
`backend/src/modules/identity/invitations.rs:531-551` (acceptance),
`backend/src/modules/identity/repo.rs:805-829` (`insert_client_membership`),
`backend/src/modules/identity/repo.rs:841-859` (`insert_department_membership`).

**What the code does.** `create_invitation` takes exactly one authorisation
decision:

```rust
// invitations.rs:71
state.require(principal, PERM_USERS_INVITE, &Target::Collection)?;
```

`request.department_id` and `request.client_account_id` are then checked only for
*mutual exclusion with the principal type* (`invitations.rs:90-103`) and stored
verbatim. At acceptance the service writes:

```rust
// invitations.rs:531-542 — "ACTIVE, unlike self-registration"
repo::insert_client_membership(&mut tx, client_account_id, new_user_id,
                               "ACTIVE", invitation.invited_by).await?;
// invitations.rs:543-551
repo::insert_department_membership(&mut tx, department_id, new_user_id,
                                   invitation.invited_by).await?;
```

`insert_client_membership` sets `activated_at = now()` when the status is
`'ACTIVE'` (`repo.rs:816`).

**Why it matters.** Both writes are authority changes that the rest of the
codebase guards far more heavily:

* `clients::add_member` requires `clients.members.manage`, runs
  `require_step_up_for`, and can **only** create a `PENDING` membership
  (`clients/service.rs:512-566`). Making one visible is a *separate* endpoint,
  a separate authorisation decision and a separate audit event, and the module
  header calls it "the moment company data becomes visible to someone outside the
  company" (`clients/service.rs:607-612`). The invitation path produces an
  `ACTIVE` membership in one step.
* `departments::add_member` requires `departments.members.manage`, runs
  `require_step_up_for`, guards ROOT, and calls `bump_security_version`
  (`departments/service.rs:444-539`). Department membership resolves
  `DEPARTMENT` scope (`principal.rs:232-243`), so it is a privilege change by the
  codebase's own definition (`departments/service.rs:461-464` says so explicitly).

The delegation guard does not close this. `check_role_assignment` validates
*roles and their permissions* (`delegation.rs:165-198`); it has no concept of a
membership.

**Attack scenario.** An internal principal holding `iam.users.invite` and
`clients.read` — a plausible recruiting/onboarding role, and one that
`iam.users.invite` is deliberately *not* dangerous in order to support
(`catalog.rs:181-186`) — reads the client-account list, invites an
attacker-controlled address as `principal_type = CLIENT` with
`client_account_id` set to the highest-value customer. On acceptance the new
external account holds an `ACTIVE` membership of that account and therefore sees
every project linked to it through `PROJECT_VISIBLE_TO_CLIENT`
(`projects/visibility.rs:56-66`) plus every task flagged `client_visible`. The
actor never held `clients.members.manage`, never held `projects.clients.share`,
and was never asked for a second factor.

The department variant is the same shape: a holder of `iam.users.invite` alone
can place a new internal account into any department, conferring every
`DEPARTMENT`-scoped grant that department carries.

**Proposed fix.** In `create_invitation`, authorise the placement in the same way
the direct endpoints do, before the invitation row is written:

* when `request.client_account_id.is_some()`, load the client account and call
  `state.require(principal, clients::MEMBERS_MANAGE, &target_for(&row, ...))`
  plus `state.require_step_up_for(...)`;
* when `request.department_id.is_some()`, load the department and call
  `state.require(principal, departments::MEMBERS_MANAGE, &target_for(&row, ...))`.

Re-check both at acceptance against the inviter's *current* authority, exactly as
the role set already is (`invitations.rs:439-501`) — otherwise the same
"authority outlives the inviter" hole the role re-check exists to close reopens
for memberships.

Consider additionally making the invited client membership `PENDING` rather than
`ACTIVE`, so that the "a stranger becomes a counterparty" decision stays in one
place. That is a product decision; the authorisation gap above is not.

---

## 2. MEDIUM

### F-02 — A narrow DENY override does not restrict the users, departments or clients listings

**Severity: MEDIUM.** Authorisation logic duplicated three ways, and two copies
drop a rule the third enforces.

**Where.**
`backend/src/modules/identity/service.rs:170-211`,
`backend/src/modules/departments/repo.rs:152-182` (`visibility_for`),
`backend/src/modules/clients/repo.rs:152-182` (`visibility_for`),
versus `backend/src/modules/projects/visibility.rs:213-236` (`ScopeFilter::build`).

**What the code does.** `ScopeFilter::build` walks `actor.denies` and carries
`deny_department`, `deny_assigned` and `denied_resource_ids` into the SQL
predicate (`visibility.rs:127-133`, `:154-160`). The other three listings build
their filter from `evaluator::effective_scopes` alone, which removes **only** a
`GLOBAL` deny (`evaluator.rs:127-134`). A `DEPARTMENT`-, `ASSIGNED`- or
`RESOURCE`-scoped DENY is therefore invisible to
`GET /api/v1/users`, `GET /api/v1/departments` and `GET /api/v1/clients`.

The single-object reads honour it correctly: `evaluate` checks denials before
allows and `scope_covers` matches the narrow scope (`evaluator.rs:43-52`).

**Attack scenario.** An administrator revokes one person's access to the Legal
department by creating a `DENY departments.read @ RESOURCE(DEPARTMENT, legal)`
override. `GET /api/v1/departments/{legal}` correctly returns `403`.
`GET /api/v1/departments` still returns the Legal row. The override reads as
effective in `GET /users/{id}/permission-overrides` and in
`GET /users/{id}/permissions`, so nobody has a reason to look further.

This is the "duplicated authorization logic that could drift" case, and it has
already drifted.

**Proposed fix.** Give the three listings the same deny handling. The cheapest
correct version is to reuse `ScopeFilter` (which is generic over `ResourceType`
already) rather than maintain a fourth translation; failing that, extend
`visibility_for` and the `identity` inline branch to consult `actor.denies` and
add a property test asserting that for every `(actor, permission, resource)` the
listing and `evaluate` agree on inclusion. `authorization/properties.rs` is the
natural home — it already proves the evaluator's own DENY precedence
(`properties.rs:177`, `:192`) but nothing proves the listings match it.

### F-03 — `departments` reveals the system owner's user id to unauthorised and external callers

**Severity: MEDIUM.** Existence/identity disclosure across the client envelope.

**Where.** `backend/src/modules/departments/service.rs:464` and
`backend/src/modules/departments/service.rs:548`.

**What the code does.**

```rust
// departments/service.rs:464 — before the row is loaded, before `require`
state.guard_root(state.is_root_user(request.user_id).await?)?;
```

`guard_root` returns `AppError::RootProtected` → `403 ROOT_PROTECTED`
(`app.rs:116-121`, `errors/mod.rs:183-187`). Because it runs before
`state.require`, **any** authenticated principal — including a CLIENT, whose
handler is a plain `Authenticated` extractor — can distinguish the owner's user
id (`403 ROOT_PROTECTED`) from every other id (`403 AUTHORIZATION_DENIED`, or
`404` once the CLIENT's envelope denial is masked).

The identity module identified this exact problem and fixed it, at length:

> `is_root` is checked *before* authorisation, so an external CLIENT that
> supplies the owner's identifier receives `403` where every other identifier —
> real or invented — receives `404`. That difference identifies the system
> owner's user id to a principal that is not permitted to know any internal user
> exists at all
> — `backend/src/modules/identity/service.rs:588-596`

`departments` did not get the same treatment.

**Attack scenario.** An external CLIENT principal (or an internal principal with
no `departments.*` grant) posts candidate user ids to
`POST /api/v1/departments/{any-uuid}/members` and reads the status/code pair. The
owner's id is the one that answers `ROOT_PROTECTED`. Candidate ids are cheap to
obtain: an audit event's `actor_user_id`, a project's `manager_user_id`, or a
`created_by` field.

**Proposed fix.** Move the root guard to after `state.require` (it is already
inside the transaction there), or route it through the same masking
`identity::deny_root` uses:

```rust
if principal.is_external() { AppError::NotFound } else { AppError::RootProtected }
```

Factoring that masking into `AppState` — e.g. `guard_root_for(principal, is_root)`
— would stop the next module repeating the mistake. Note that
`AppError::hide_from_external` deliberately does *not* cover `RootProtected`
(`errors/mod.rs:330-335`, and the reasoning at `identity/service.rs:597-600`), so
the masking must stay explicit.

Also check `clients::add_member`, which has no root guard at all: that one is
correct — the subject is required to be a `CLIENT` principal
(`clients/service.rs:539`) and `system_ownership`'s insert trigger refuses a
non-INTERNAL owner (`migrations/0001_system_and_identity.sql:122-125`), so the
subject cannot be root. That reasoning is stated in the source
(`clients/service.rs:537-538`). **Verified.**

### F-04 — `POST /api/v1/auth/logout` is declared `Authenticated` but implemented `MfaPendingSession`, and the guard test cannot see it

**Severity: MEDIUM.** Not an exploitable hole; a false attestation plus a
disabled guard.

**Where.** `backend/src/routes.rs:75` versus
`backend/src/modules/authentication/routes.rs:115-117`.

**What the code does.** `ROUTE_TABLE` is described as "the single place a reviewer
can see the whole authenticated surface, including which routes are anonymous and
which require step-up" (`routes.rs:7-8`). It declares
`r("POST", "/api/v1/auth/logout", Authenticated, None, false)`. The handler uses
`MfaPendingSession`, and the module header says it must
(`authentication/routes.rs:13-16`). The behaviour is the right one — a session
stuck in `MFA_ENROLMENT_REQUIRED` must be able to dispose of its token — but the
declaration is false.

The consequence is not cosmetic. `the_mfa_pending_surface_is_minimal`
(`routes.rs:861-878`) asserts that every `MfaPending` path starts with
`/api/v1/auth/mfa/` or is `/api/v1/auth/me`. `/logout` is neither, so it is only
absent from that test's scope because it is mis-declared. The test that bounds
the pending-MFA attack surface is silently not covering one of its members.

**Proposed fix.** Declare `/logout` as `MfaPending` and widen the assertion to
allow `/api/v1/auth/logout` explicitly, with the reason. The OpenAPI drift test
will also need the corresponding spec change. Do **not** change the handler to
`Authenticated`.

### F-06 — An authenticated principal can force unbounded growth of an append-only table with no delete path

**Severity: MEDIUM.** Storage exhaustion / audit-log dilution.

**Where.**
`backend/src/modules/projects/service.rs:817-833` and `:921-936`,
`backend/src/modules/authorization/service.rs:414-442` (`refuse`),
`backend/src/modules/settings/service.rs:348-369` and `:448-466`.

**What the code does.** Each of these writes an `AUTHORIZATION.DENIED` (or
`SETTING.CHANGED` / `ROOT.PROTECTION_TRIGGERED`) audit row and then **commits it
deliberately**, so the record survives the refusal. That design is right — the
comments explaining it are among the better ones in the codebase
(`authorization/service.rs:408-413`).

What is missing is a bound. None of these routes is rate limited (see F-07), and
`audit_events` is append-only by construction: no `UPDATE`, no `DELETE`, no
`TRUNCATE`, and the runtime role holds only `SELECT, INSERT`
(`audit/routes.rs:3-14`). Every write also takes the chain advisory lock
(`audit/mod.rs:325`), so it serialises every other audit append in the system.

**Attack scenario.** An authenticated internal principal with no `projects.*`
grant, holding one valid project UUID, loops
`POST /api/v1/projects/{id}/clients`. Each request produces one committed audit
row and one advisory-lock acquisition. There is no limiter, no quota and no
mechanism to remove the rows afterwards. At a modest 200 req/s that is ~17 M rows
per day in a table designed to be kept forever, plus contention on the single
chain lock that every legitimate mutation in the system also needs.

**Proposed fix.** Either (a) wire the already-configured general per-principal
limiter (F-07) so denial recording inherits a budget, or (b) give
denial-recording its own cheap suppression — e.g. record at most one
`AUTHORIZATION.DENIED` per `(actor, permission, target)` per minute and carry a
count — or (c) both. Option (b) alone preserves the intrusion-detection value at
a fraction of the volume.

### F-07 — The general rate limiter is configured and keyed but never installed

**Severity: MEDIUM.** A control that is documented, budgeted and absent.

**Where.**
`backend/src/platform/config/mod.rs:109` (`general_per_principal_per_minute`),
`backend/src/platform/config/mod.rs:123` (default 600),
`backend/src/platform/http/rate_limit.rs:274-279`
(`keys::general_principal`, `keys::general_ip`),
`backend/src/platform/http/middleware.rs:142-166` (`apply`).

**What the code does.** The config field and both key builders exist. Neither key
builder is called from anywhere in `backend/src` except the key-collision unit
test (`rate_limit.rs:485-486`). `middleware::apply` installs panic capture,
request id, timeout, body limit, method guard, CORS and security headers — and no
rate-limit layer. Only eight endpoints are limited at all, all of them in
`authentication`, `identity` and `bootstrap` (see the matrix, §3–§4).

Consequently `GET /api/v1/audit/verify` — which the service itself describes as
"a bulk cryptographic scan" bounded at 100 000 HMAC recomputations
(`audit/service.rs:57-59`, `:388-395`) — is callable at line rate by any holder
of `audit.read`, and so is every listing.

**Proposed fix.** Add a middleware that consumes
`keys::general_principal(user_id)` for authenticated requests and
`keys::general_ip(ip)` otherwise, at the configured quota. If the intention is to
defer this, delete the config field and both key builders instead: a control that
exists in configuration but not in code is worse than an acknowledged gap,
because a reviewer reading `config/mod.rs` will believe it is enforced. Also note
that `RateLimitConfig` is constructed with `::default()` at
`config/mod.rs:483` and reads no environment variables at all, so an operator
cannot tune any of the eight limits that *are* enforced — worth stating in
`docs/backend/08-operations.md` either way.

---

## 3. LOW

### F-05 — Two step-up endpoints rely on the service, not the extractor, to exclude a pending-MFA session

**Severity: LOW.** Defence-in-depth gap, currently benign.

`backend/src/modules/authentication/routes.rs:226-245` mounts
`/mfa/recovery/regenerate` and `/mfa/disable` with `MfaPendingSession`, while
`routes.rs:137-150` declares both `Authenticated`. Today the services call
`state.require_step_up` first (`mfa.rs:535`, `mfa.rs:586`), and a pending session
by construction has never verified a factor, so it is refused. But the exclusion
is a consequence of one line in a service rather than a property of the type, and
`Authenticated` exists precisely so that "a handler that forgets to think about
MFA gets the safe behaviour" (`extract.rs:5-8`).

**Fix.** Use `Authenticated` on both, or add a test asserting a pending session
receives `403 STEP_UP_REQUIRED` and never reaches the body.

### F-08 — Two listing paths refuse without going through `state.require`, so the denial is neither metered nor logged

**Severity: LOW.** Observability gap on an authorisation denial.

`backend/src/modules/projects/service.rs:247-253`, `:981-983` and
`backend/src/modules/tasks/service.rs:183-185`, `:717-719` return
`AppError::AuthorizationDenied.hide_from_external(...)` directly. `state.require`
is the one place that increments `metrics.authz_denial(reason)` and emits the
`"authorization denied"` log line with the actor, the permission and the reason
(`app.rs:65-87`). `departments::list` and `clients::list` get this right — they
route the `Nothing` branch back through `state.require` specifically so "the
denial metric, the log line and the 404-instead-of-403 shaping all happen in
exactly one place" (`departments/service.rs:162-167`).

**Fix.** Do the same in `projects::list`, `projects::client_list`,
`tasks::list` and `tasks::client_list_for_project`.

### F-09 — `GET /api/v1/system/info` returns security-sensitive feature-flag keys to any principal, including a CLIENT

**Severity: LOW.**

`backend/src/modules/system/repo.rs:30-38` selects every enabled flag key with no
`is_security_sensitive` filter. `GET /api/v1/feature-flags` excludes sensitive
rows from anyone without `settings.security.write`
(`settings/service.rs:259-271`), and the repo comment for
`enabled_feature_flag_keys` says the sensitivity marker is withheld because it
"tells a caller which toggles are worth attacking" — while returning the key
itself. `system::info` takes `_principal` and performs no `require`
(`system/service.rs:69`), so an external CLIENT receives the list.

**Fix.** Filter on `is_security_sensitive = false` in
`enabled_feature_flag_keys`, or gate the field on `settings.read`. The former is
one line and preserves the endpoint's "authentication and nothing else" contract.

### F-10 — Loading a row before authorising creates a small existence oracle on three routes

**Severity: LOW.** Internal-only; acceptable per `docs/backend/04-authorization.md`
§10 but inconsistent with the surrounding code.

`identity/invitations.rs:308-312` (`DELETE /invitations/{id}`),
`authorization/service.rs:518-521` (`GET /roles/{id}`),
`authorization/service.rs:695-699` (`PATCH /roles/{id}`) and `:846-848`
(`DELETE /roles/{id}`) all load the row and return `404` before the
`Target::Collection` authorisation runs. An unauthorised *internal* principal can
therefore distinguish a real id (`403`) from an invented one (`404`).

For an external CLIENT this is harmless — `require` renders as `404` either way —
and `get_role` documents the reasoning (`service.rs:516-517`). It is recorded
here only because `audit::get_event` takes the opposite order
(`audit/service.rs:305-317`: authorise first, then look up), and one of the two
conventions should win.

**Fix.** Prefer the audit ordering wherever the decision is `Target::Collection`,
since a collection-level decision needs no row.

### F-13 — Three independent UUID path parsers, one of which accepts inputs the others reject

**Severity: LOW.** Duplicated logic that has already diverged.

* `platform/http/extract.rs:297-299` — `parse_path_uuid`. Explicitly does **not**
  trim: "accepting `" <uuid> "` where axum refused it would be a new acceptance,
  and this change is meant to alter errors, not behaviour" (`extract.rs:293-296`),
  with a test pinning it (`extract.rs:509-514`).
* `modules/authorization/routes.rs:58-61` — `parse_id`. Calls `raw.trim()`, and
  its own test asserts that `"  {id} "` **is** accepted (`routes.rs:245`).
* `modules/audit/service.rs:77-82` — `parse_uuid`. Also trims.

So `/api/v1/departments/%20{uuid}%20` is a `400` and
`/api/v1/roles/%20{uuid}%20` is a `200`. Nothing is exploitable here — a UUID is
a UUID once parsed — but the module that went to the trouble of writing a
"do not simplify these back to `Path<Uuid>`" essay (`extract.rs:247-282`) is being
bypassed by two modules that predate it, and the divergence is asserted by tests
on both sides, so neither will ever notice the other.

**Fix.** Use `PathId` / `PathIds` in `authorization::routes` and `audit::routes`
and delete both local parsers. `audit::get_event` additionally wants the
"malformed id is a `404`" behaviour, which is a two-line wrapper over `PathId`.

---

## 4. INFO

### F-11 — Two endpoints in the sensitive set have no rate limiter

`POST /api/v1/auth/mfa/disable` calls `state.require_step_up` but not
`enforce_mfa_limits` (`mfa.rs:581-598`), unlike every other MFA endpoint.
`GET /api/v1/bootstrap/status` has no limiter at all
(`bootstrap/service.rs:29-42`); it returns one boolean, so the exposure is
trivial, but it is an anonymous endpoint that touches the database on every call.
Both are cheap to close. Subsumed by F-07 if the general limiter is wired.

### F-12 — Cancelling a task is recorded as `TASK.UPDATED`

`tasks/service.rs:538-554` records cancellation under `action::TASK_UPDATED` with
`status` in the metadata, because "there is no dedicated `TASK.CANCELLED` action
code in the audit catalogue, and `modules::audit` is not this module's to extend".
The reasoning is honest and the metadata answers the question, but an auditor
filtering `action_code = TASK.CANCELLED` gets an empty page and concludes nothing
was cancelled — the exact failure mode `audit::service::validate_action_code`
argues against when it refuses to validate against a snapshot of the constant list
(`audit/service.rs:99-109`). Adding the constant is a one-line change to a file
the tasks module does not own; that is a coordination problem, not a technical one.

### F-14 — `audit_events.source_ip_hint` is stored but not covered by the hash chain

`audit/mod.rs:379` binds `source_ip_hint` into the insert; `chain::ChainedEntry`
(`chain.rs:37-51`) does not carry it, and `canonical_bytes` (`chain.rs:111-152`)
therefore does not hash it. The exclusion is consistent with the module's stated
rule — "a field NOT in this struct is not protected" (`chain.rs:33-36`) — and it
is the *only* substantive column excluded. An adversary with `UPDATE` on
`audit_events` (which the runtime role does not have, but a compromised
superuser or a restored backup would) can rewrite every source IP in the log
without breaking verification. Given that the chain's whole claim is about an
adversary holding the database (`chain.rs:5-13`), this is worth either fixing or
stating explicitly in ADR-006.

Note the fix is not free: adding a field changes every existing entry's digest,
so it needs a chain version marker or a re-anchor procedure.

---

## 5. Things that look like defects and are not

Recorded so the next reviewer does not re-open them.

* **`app.rs:140` — `SELECT root_user_id FROM system_ownership WHERE id`.** Reads
  like a truncated predicate. It is valid: `system_ownership.id` is
  `boolean PRIMARY KEY DEFAULT true CHECK (id)`
  (`migrations/0001_system_and_identity.sql:107`), so `WHERE id` is the singleton
  selector. The same idiom appears at `bootstrap/service.rs:31`, `:139`, `:205`
  and `audit/mod.rs:395`. **Verified.**
* **`config/mod.rs:394` and `:397` — `unwrap_or_else(|| Secret::new(vec![0u8; 32]))`
  on the encryption and audit-chain keys.** A zero key would be catastrophic. It
  is unreachable: both `unwrap_or_else` arms are taken only when the
  corresponding `errors.push(...)` has already run (`:330-342`), and
  `errors.into_result()?` at `:503` returns before `Ok(config)` at `:504`. The
  placeholders exist only so the struct can be built before the error check.
  **Verified** — but it is a fragile pattern: reordering those two lines turns a
  configuration error into a silently zero-keyed deployment. Constructing
  `SecurityConfig` after `into_result()` would remove the possibility.
* **`chain.rs:160-166` — `entry_hash` returns `vec![0u8; 32]` on
  `HmacSha256::new_from_slice` failure.** A constant digest would make the chain
  forgeable. `Hmac::new_from_slice` accepts any key length and cannot return
  `InvalidLength`, which the comment states. **Verified** by construction, though
  it depends on a property of the `hmac` crate rather than on anything local.
* **`identity/service.rs:200` — `filters.department_ids = Some(vec![])` when the
  actor is in no department.** An empty array is not `NULL`, so the SQL guard
  `$5::uuid[] IS NULL` is false and the `EXISTS ... = ANY('{}')` subquery matches
  nothing (`identity/repo.rs:240-245`). Fails closed. **Verified.**
* **`principal.rs:63` — `time::Duration::try_from(window).unwrap_or(Duration::ZERO)`.**
  On failure the window becomes zero, which makes `has_recent_step_up` always
  false. Fails closed, and there is a test for it
  (`principal.rs:362-364`). **Verified.**
* **`rate_limit.rs:169-179` — poisoned-mutex recovery via `into_inner()`.** This
  *is* a fail-open in the strict sense: after a panic in a limiter caller the
  bucket table is used anyway. The comment argues the alternative (hard-failing
  every request forever) is worse, and the panic is itself an alarm. Accepted.
* **`rate_limit.rs:184-188` — a saturated key table allows an untracked request.**
  Also deliberate fail-open, with the reasoning stated and a test
  (`rate_limit.rs:455-469`). The eviction ordering is the interesting part and it
  is correct: emptiest buckets survive longest, so an attacker cannot flush their
  own penalty by rotating keys (`rate_limit.rs:126-144`, test at `:427-450`).
  **Verified.**
* **`invitations.rs:485` — `has_recent_step_up: true` at acceptance.** Reads like
  a hard-coded bypass. It is a deliberate, documented decision: step-up recency
  was proved by the inviter at creation (`invitations.rs:134-136`) and cannot be
  re-proved by a principal who is not present; what is re-checked at acceptance is
  *authority*, including any DENY added since. **Verified.**
* **`extract.rs:171-174` — `MfaPendingSession` accepts completed sessions too.**
  Intended: an already-verified user may still manage their factors. The safe
  default is `Authenticated`, which is what everything else uses.

---

## 6. Panic-path review

`grep -rn "unwrap()\|expect(\|panic!\|todo!\|unimplemented!" backend/src/ --include=*.rs`
returns 333 hits. Excluding everything at or after each file's first
`#[cfg(test)]` marker leaves **five**, all in one place:

```
backend/src/platform/config/net.rs:142  IpNet::parse("127.0.0.0/8").expect("static CIDR")
backend/src/platform/config/net.rs:143  IpNet::parse("::1/128").expect("static CIDR")
backend/src/platform/config/net.rs:144  IpNet::parse("10.0.0.0/8").expect("static CIDR")
backend/src/platform/config/net.rs:145  IpNet::parse("172.16.0.0/12").expect("static CIDR")
backend/src/platform/config/net.rs:146  IpNet::parse("192.168.0.0/16").expect("static CIDR")
```

**All five are legitimate.** Each parses a `&'static str` CIDR literal that is
visible on the same line; the parse is total for these inputs, the values cannot
be influenced by a request, and the function builds the *development-only*
trusted-proxy default (production with no `RB_TRUSTED_PROXIES` uses
`TrustedProxies::default()`, which trusts nothing —
`config/mod.rs:440-453`). A failure would be a compile-time-visible typo, and it
would happen at startup, not under load. No fix recommended.

Two further classes were checked and are clean:

* **Indexing.** The only non-test slice indexing in the codebase is
  `outbox/mod.rs:374` — `bytes[14], bytes[15]` on `Uuid::as_bytes()`, which
  returns `&[u8; 16]`, so the index is checked at compile time.
* **Integer arithmetic.** Every conversion that could truncate uses
  `i64::try_from(...).unwrap_or(...)` or a `checked_*`/`saturating_*` form:
  `sessions.rs:50-52` (`checked_add` with a bounded fallback),
  `sessions.rs:112-116` (`checked_add`, refuses to wrap, with a test),
  `outbox/mod.rs:352-358` (`clamp` + `checked_shl` + `saturating_mul` + `min`),
  `audit/service.rs:378` (`saturating_sub`/`saturating_add`/`max(1)` with a test
  for `i64::MIN`). **Verified.**
* **`unwrap_or` on booleans.** The only ones are `catalog::is_dangerous`
  (`catalog.rs:306`, `unwrap_or(false)` — the safe direction: an unknown code is
  not dangerous, and the *evaluator* separately hard-denies it) and
  `system/repo.rs:19` (`unwrap_or(false)` — a missing singleton row reads as "not
  initialised", which is both safe and true). **Verified.**

---

## 7. Verified negatives

Each of these was actively hunted for and not found.

* **Fail-open.** Every `None`/error path in an authorisation decision denies:
  `catalog::get` → `DenyUnknownPermission` (`evaluator.rs:34-36`);
  `envelope_permits` returns `false` for an unknown code (`catalog.rs:310-316`);
  `scope_covers` refuses an incoherent scope (`evaluator.rs:83-85`);
  `load_actor` skips an unparseable `scope_type`, an object-less `RESOURCE` grant
  and an unrecognised `effect`, logging each at `error!`
  (`principal.rs:196-227`); `ScopeFilter::build` skips an incoherent deny rather
  than interpreting it (`visibility.rs:219-221`); `scope_from_row` refuses rather
  than treating a corrupt grant as absent (`authorization/service.rs:258-295`);
  `registration::current_mode` reports `Disabled` on a database error
  (`registration.rs:87-95`); every `*_of(row)` status parser returns
  `AppError::Internal` rather than a nearest-plausible value.
* **Forgotten route authorisation.** All 71 permission-bearing routes reach a
  decision. See the matrix.
* **Shadow admin bypass.** There is no `if is_admin` anywhere. The single bypass
  is `actor.is_root` at `evaluator.rs:29-31`, read from `system_ownership` on
  every request (`principal.rs:102-105`), reached only after authentication,
  session validity, MFA and step-up, and it does **not** bypass the permission
  catalogue — an unknown code is still unknown for root
  (`evaluator.rs:531-540`). `delegation` additionally refuses root as a *target*
  before consulting `actor.is_root` (`delegation.rs:82-84` runs before `:119`),
  and refuses system-role authoring for root as well (`delegation.rs:213-218`).
* **Default allow.** No `_ => true`, no `_ => Ok(())` in an authorisation
  position. The three `_ => Ok(())` arms found are business-rule predicates with
  a safe default (`clients/service.rs:144` — "any status except ARCHIVED is
  addable"; `:188` — "any status except REMOVED is removable";
  `departments/service.rs:113` — same). `MaxPrincipalType::permits`,
  `ScopeType::parse`, `PrincipalType::parse`, `Effect::parse` and
  `ResourceType::parse` are all exact-match with `None`/`false` defaults.
* **TOCTOU.** Every mutation opens the transaction, re-reads the subject
  `FOR UPDATE`, then authorises, then mutates, then audits, then commits. Spot-
  checked in all eight mutating modules. The three exceptions are correct by
  construction and named in the matrix's closing section. `bootstrap` adds an
  advisory lock plus a `FOR UPDATE` re-read plus a schema-level singleton
  (`bootstrap/service.rs:114-155`); `authentication::issue_session` counts the
  session cap inside the transaction (`service.rs:195-214`);
  `refresh` locks the token row and gates the consume on rows-affected even
  though the lock is held (`service.rs:406-410`); `mfa` locks the factor row
  before reading `last_used_step` (`mfa.rs:8-11`, `:238`, `:361`).
* **Unsafe trust of a path parameter, header or client id.** `TargetContext` is
  built from loaded rows everywhere except `projects::create`, where the
  request's `department_id` is used — correctly, because it is also the
  department the new row gets, so the decision can only narrow.
  `SubjectFacts` has no constructor taking a caller-supplied `principal_type` or
  `is_root` (`authorization/service.rs:82-95`). `ClientIp` honours
  `X-Forwarded-For` only from a configured trusted peer
  (`extract.rs:44-64`, `config/mod.rs:440-453`) and the result is never used for
  authorisation (`authentication/service.rs:47-52`). Tokens in a query string are
  refused with a *distinct* error rather than ignored (`extract.rs:73-85`).
* **Data leakage through a response type.** Every projection is field-by-field,
  never `From<Row>`, and `identity::user_response` says why
  (`identity/service.rs:88-91`). The client portal uses structurally separate
  DTOs on separate routes, so "there is no request in which the internal
  serialiser could be reached by an external principal"
  (`projects/routes.rs:66-70`). `AuditMetadata` refuses any key *containing* a
  secret-bearing fragment and marks it `__redacted` (`audit/mod.rs:222-239`).
  `AppError::detail` never carries an internal fact, and the sqlx `From` impl
  maps driver errors to fixed labels (`errors/mod.rs:459-534`). One residual leak
  is F-09.
* **`#![forbid(unsafe_code)]`** — present at `backend/src/lib.rs:1`, so the
  claim `middleware.rs:119` makes about it holds. **Verified.**

---

# §26 — Architecture sanity

The design is, on the whole, **not** over-built. The layering is thin (routes →
service → repo, plus a pure `authorization` core), there is no DI container, no
event bus, no CQRS, no repository trait, no generic "handler" abstraction, and
`AppState` is a plain struct of `Arc`s whose docstring explains that choice
(`app.rs:4-6`). Exactly one trait exists for a genuinely pluggable dependency
(`RateLimiter`) and one for an external boundary (`MailProvider`); both are
justified by a second implementation that is specified rather than imagined.
Closed enums are used where a policy DSL would have been the over-built choice,
and ADR-003 records that decision.

Four things are over-built or dead, and one of them affects an operational claim.

### A-01 — The metrics module is 1 072 lines and records two series

**Severity: MEDIUM** (affects an operational claim, not correctness).

`backend/src/platform/observability/metrics.rs` exposes twelve public methods.
Grepping all of `backend/src` outside that file, exactly **two** are ever called:

```
backend/src/app.rs:70   self.metrics.authz_denial(decision.reason());
backend/src/app.rs:163  self.metrics.audit_written();
```

`http_request`, `latency`, `latency_ms`, `auth_failure`, `rate_limit_event`,
`outbox_failure`, `db_pool` and `http_series_count` are called from nowhere, and
`middleware::apply` (`middleware.rs:142-166`) installs no metrics layer, so HTTP
request counts and latencies are never observed at all.

This matters beyond dead code because `GET /metrics` carries a prominent warning:

> a scrape target reachable from the internet publishes request volumes, error
> rates and authorisation-denial counts, which is a live feed of how an attack is
> progressing
> — `backend/src/modules/system/routes.rs:88-91`

Two of those three are not published. An operator reading that comment will
believe they have request-rate and error-rate telemetry, and will not discover
otherwise until they need it.

**Recommendation.** Either wire the HTTP metrics layer (a `from_fn` recording
`http_request` and `latency` around `next.run`, using the matched route pattern —
the module already labels by pattern to bound cardinality), or delete the eight
unused methods and correct the `/metrics` comment. Do not leave it as is: the gap
between the documented control and the implemented one is the problem, not the
line count.

### A-02 — `platform/http/endpoints.rs` is a fourth copy of the route list that nothing consumes

**Severity: LOW.**

`backend/src/platform/http/endpoints.rs` is 383 lines of path constants whose
module doc says it exists "so that no call site — a test, a client generator, an
operational script — has to spell a path out by hand" (`endpoints.rs:3-5`).
Grepping `backend/src` and `backend/tests` finds **no** reference to
`endpoints::` outside the file itself. The only thing that consumes it is its own
in-file test.

The system now has four descriptions of the same route set: `ROUTE_TABLE`
(`routes.rs:62`), this module, `api/openapi.yaml` and `api/endpoints.json`.
`ROUTE_TABLE` and the OpenAPI document are cross-checked by
`tests/openapi_contract.rs`, and `ROUTE_TABLE` and the mounted router by
`tests/router_registry.rs`. This module is checked only against itself.

**Recommendation.** Delete it, or make the tests use it (`tests/common` building
request URLs from these constants would give it a purpose and would catch a path
typo in a test rather than in a 404 assertion that passes for the wrong reason).
Keeping an unreferenced registry is worse than having none: it will drift, and
its drift is invisible.

### A-03 — Ten unused public items, several of which are fake future-proofing

**Severity: INFO**, except where noted.

| Item | Where | Note |
| --- | --- | --- |
| `AppState::root_user_id` | `app.rs:138-145` | Never called. `is_root_user` covers every real use. |
| `AppState::not_found_or_denied` | `app.rs:187-193` | Never called, and duplicates `AppError::hide_from_external` (`errors/mod.rs:330`). Two ways to express one rule is exactly the drift risk the codebase argues against elsewhere. Worth deleting for that reason rather than for tidiness. |
| `evaluator::holds_any` | `evaluator.rs:149-151` | Used only by its own test. Its docstring claims it is "used to build the capability list returned by `GET /api/v1/auth/me`" — `capability_list` calls `effective_scopes` directly (`evaluator.rs:158-173`). The comment is wrong, which is the actual harm. |
| `evaluator::grant` | `evaluator.rs:177-187` | Never called anywhere, including tests outside its own. |
| `evaluator::_assert_types` | `evaluator.rs:189-190` | A no-op `#[allow(dead_code)]` marker. |
| `audit::denial` | `audit/mod.rs:416-418` | "Convenience for the very common 'audit a denial' case" — used by no call site; every real denial builds the event inline. |
| `identity::service::without_root` | `identity/service.rs:615-620` | "Exposed for every future bulk endpoint." There are no bulk endpoints. Textbook fake future-proofing. |
| `OutboxWorker::with_derived_id` | `outbox/mod.rs:487` | `cli.rs:243` uses `OutboxWorker::new`; `with_derived_id` is referenced only from a doc link. |
| `keys::general_principal`, `keys::general_ip` | `rate_limit.rs:274-279` | See F-07 — these are the visible half of an uninstalled control, so they are MEDIUM in that context, not INFO. |
| `mfa::_factor_summary` | `mfa.rs:637-642` | Explicitly `#[allow(dead_code)]`: "retained so a future factor type does not have to reinvent the shape". Delete it; the shape is four lines. |

**Recommendation.** Delete all of them. Two carry a real cost rather than a
cosmetic one — `not_found_or_denied` (a second implementation of a security rule)
and `holds_any` (a docstring that misdescribes how `/auth/me` works) — and those
two are worth doing regardless of appetite for the rest.

### A-04 — Three independent scope-to-SQL translations

**Severity: INFO** as an architecture observation; the concrete consequence is
F-02 (MEDIUM).

`ScopeFilter` + `PROJECT_SCOPE_PREDICATE` / `TASK_SCOPE_PREDICATE`
(`projects/visibility.rs`), `visibility_for` + `ScopePredicate`
(`departments/repo.rs:82-182`, duplicated in `clients/repo.rs`), and the inline
branch in `identity::list_users` (`identity/service.rs:170-211`) all answer the
same question — "translate the actor's effective scopes into a `WHERE` clause" —
with three different data structures and three different levels of fidelity to
the evaluator.

Each is individually well-written and well-commented. Collectively they are the
single largest maintenance risk in the authorisation layer, because the evaluator
is the specification and nothing checks that the three translations still
implement it. `authorization/properties.rs` proves the evaluator's own
properties exhaustively (`properties.rs:142-396`) and proves nothing about the
SQL.

**Recommendation.** Not a rewrite. Add a property test asserting, for generated
actors and generated resources, that inclusion by each translation agrees with
`evaluator::evaluate` on the corresponding `Target::Resource`. That test would
have caught F-02 the day it was written, and it is the cheapest possible
insurance against the next divergence. Consolidating the three into one generic
`ScopeFilter` is the better long-term answer but is a larger change and should
follow the test, not precede it.

### Things I checked and found appropriately sized

* **No unnecessary dependencies observed** in the code I read: `sqlx`, `axum`,
  `tower-http`, `argon2`, `hmac`/`sha2`, `time`, `uuid`, `serde`,
  `proptest` (dev), `tokio-util`. Each has a visible, single purpose. I did not
  read `Cargo.toml`, so this is "looks proportionate", not verified.
* **No premature distribution.** One process, one database, an in-process rate
  limiter that is honestly documented as wrong for a second replica
  (`rate_limit.rs:1-7`), and a transactional outbox that exists because the
  alternative is losing mail — not because a queue looked architectural.
* **The audit chain is not over-engineered.** Length-prefixed fields, canonical
  JSON, an HMAC keyed separately from the AEAD key, and a head record that
  catches tail truncation. Each element defends a specific attack named in the
  tests (`chain.rs:394-475`). The claim in the module header is stated precisely
  and does not overreach (`chain.rs:5-13`).
* **`Idempotent<T>` and `platform::http::idempotency`** are the right size: the
  key is only reachable by destructuring, so a handler cannot accept the header
  and ignore it (`idempotency.rs:66-78`), and the fingerprint is over raw bytes
  with the trade-off stated (`idempotency.rs:11-20`).
* **The four-layer authorisation model** (envelope → policy → object → SQL
  predicate) is deliberate redundancy, not duplication: layers 1–3 are one code
  path and layer 4 is a different mechanism entirely, so a bug in the first three
  returns fewer rows rather than another company's
  (`projects/visibility.rs:1-24`). That is the one place in this codebase where
  I would resist any simplification.
