# Backend acceptance audit — §7, §8, §14, §15, §16

**Scope.** §7 race campaign, §8 database invariants, §14 idempotency, §15 transactional
outbox, §16 audit integrity.

**Method.** Everything below was executed against PostgreSQL 18.4 in the project's
dev container (`rust:1-bookworm`, `roleblank_net`). No result in this report is
reasoned about; every number is copied from a test run. Race tests use a
`tokio::sync::Barrier` so that all N requests are released at the same instant — a
spawn loop is not a race, because the first request usually completes before the
last is scheduled.

Measured distributions are printed by the suites themselves (`RACE-EVIDENCE`,
`OUTBOX-EVIDENCE`, `AUDIT-EVIDENCE` lines) so that the evidence in this document can
be regenerated rather than trusted:

```
cargo test --test race_suite --test security_suite -- --nocapture
```

---

## 1. Defects found

| # | Severity | Title | Status |
|---|----------|-------|--------|
| F-1 | **HIGH** | `accept_invitation` self-deadlocks the connection pool; invitation acceptance fails completely under concurrency | **Fixed, regression test added** |
| F-2 | LOW | Non-owner `principal_type` transitions are unguarded at the database level | Open — documented, application-protected |
| F-3 | LOW | Single-use token consumption has no database-level guard | Open — by design, documented |
| F-4 | INFO | `/audit/verify` diagnostics expose stored chain digests | Not a defect — deliberate, justified |
| F-5 | INFO | Test harness rebuilt a shared template database per binary, so concurrent test runs corrupted each other | **Fixed** (by concurrent work, not by this audit) — test infrastructure only |

---

### F-1 — HIGH — `accept_invitation` self-deadlocks the connection pool

**Status:** Fixed in this audit. Regression test added and passing.

**Affected code:** `backend/src/modules/identity/invitations.rs:440` and `:455`
(pre-fix line numbers), inside `accept_invitation`.

**What was wrong.** The function opened a transaction and took `SELECT … FOR UPDATE`
on the invitation row, and then — while still holding that transaction and that row
lock — called two helpers that each acquire *their own* connection from the same
bounded pool:

```rust
let mut tx = state.begin().await?;                                  // holds connection #1
let invitation = repo::find_invitation_by_token_for_update(&mut tx, …)  // holds the row lock
…
let inviter = repo::actor_basics(&state.db, invitation.invited_by)   // asks for connection #2
let inviter_actor = principal::load_actor(&state.db, …)              // asks for connections #3-#5
```

Once the number of simultaneous acceptances reaches the pool size, every in-flight
task holds one connection and every task is waiting for another connection that only
a peer could release. Nothing can make progress. The requests queued behind the row
lock are then killed by `statement_timeout` (15 s) and the rest by `acquire_timeout`.

**Why it is HIGH, not a test artefact.** The trigger condition is
`concurrent acceptances ≥ pool size`. Production defaults are
`RB_DB_MAX_CONNECTIONS=10` (`backend/.env.example:38`), so ten simultaneous
acceptances are sufficient — well within one company's onboarding burst, and within
the endpoint's own per-IP quota of 20/hour. The consequences compound:

1. **The feature fails outright.** Not "degrades" — in the measured run, *zero* of
   fifty acceptances succeeded. The invitee cannot create their account at all.
2. **The blast radius is the whole service.** The exhausted pool is shared by every
   endpoint, so while the deadlock persists every other request is starved too. A
   handful of invitation links turns into a service-wide outage.
3. **It is reachable by anyone holding an invitation token** — i.e. every new hire,
   and anyone who intercepted one link.

**Attack scenario.** An attacker who has obtained (or been legitimately sent) one
invitation token replays acceptance ~10-20 times concurrently from a single address.
Every database connection in the pool is consumed for the duration of
`statement_timeout`. Repeating this once every 15 seconds holds the entire API in a
starved state for as long as they care to continue, at a cost of one HTTP request per
connection. The per-IP quota (20/hour) does not prevent this because the quota is
*larger* than the pool.

**Measured evidence — before the fix** (50 concurrent acceptances of one valid token):

```
RACE-EVIDENCE invitation_accept x50: n=50
  statuses={429: 30, 500: 3, 503: 17}
  codes={"INTERNAL_ERROR": 3, "RATE_LIMITED": 30}
elapsed: 30.38s
```

Zero successes. 17×503 are `PoolTimedOut`; 3×500 are the requests queued on the row
lock, killed by `statement_timeout` (`SQLSTATE 57014`), which
`platform/errors/mod.rs` maps through its unhandled-SQLSTATE arm to
`AppError::Internal` — so an anonymous caller receives a 500.

**Measured evidence — after the fix** (identical test):

```
RACE-EVIDENCE invitation_accept x50: n=50
  statuses={201: 1, 401: 19, 429: 30}
  codes={"AUTHENTICATION_FAILED": 19, "RATE_LIMITED": 30}
elapsed: 0.52s
```

Exactly one account, every loser a clean refusal, and a 58× reduction in wall time.

**The fix.** Two changes, both minimal and confined to the acceptance path:

1. `backend/src/modules/identity/repo.rs` — `actor_basics` is now generic over
   `sqlx::Executor`, so it can run on a transaction's own connection instead of
   requiring a second pool slot. Existing callers passing `&PgPool` are unaffected.
2. `backend/src/modules/identity/invitations.rs` — the inviter's delegation context
   (`load_actor`, three queries) is now built **before** `state.begin()`, and the
   authoritative "is the inviter still ACTIVE" re-check runs **inside** the
   transaction on `&mut *tx`, costing no second connection.

Hoisting `load_actor` costs nothing in correctness: those reads were already issued
on a *different* connection with its own snapshot, so being inside the transaction
never made them consistent with the invitation row. The freshness check that actually
matters — a suspension landing while the request was queued on the lock — is now
performed on the transaction's own connection, which is strictly *better* than
before. A guard was also added: if the locked row's `invited_by` disagrees with the
preview the context was built from, the request is refused rather than validated
against the wrong principal.

**Regression test.**
`tests/race/invitation_accept.rs::fifty_simultaneous_acceptances_still_create_exactly_one_user`
— asserts `server_errors() == 0`, at most one success, and that the account count and
the consumed-invitation count both equal the success count.

**Related hardening (not applied).** The generic pattern "acquire a second pooled
connection while holding a transaction" was swept for across `src/**`; this was the
only genuine occurrence. `clients/service.rs:680` matches the textual pattern but is
after `tx.commit()` and is safe. A lint or review rule for this shape would be
worthwhile, because the failure mode is invisible until concurrency reaches pool
size.

---

### F-2 — LOW — Non-owner `principal_type` transitions are unguarded at the database level

**Affected code:** `backend/migrations/0001_system_and_identity.sql:163`
(`rb_users_protect_root`).

The ROOT user's `principal_type` is pinned by trigger, and the column carries
`CHECK (principal_type IN ('INTERNAL','CLIENT'))`. Nothing else constrains it. An
ordinary employee can be converted `INTERNAL → CLIENT` by anyone holding the
migration role, and the conversion does **not** cascade: the user keeps
`user_role_assignments` rows for INTERNAL-only roles, a state the client-envelope
triggers would have refused at insert time.

**Why LOW.** It requires migration-role database access, which is already outside the
application's trust boundary. The application never performs this transition. It is
recorded because the client envelope is otherwise enforced *in the database*, and a
reader could reasonably assume this column was covered too — it is not.

**Test:** `database_invariants::a_non_owner_principal_transition_is_constrained_only_by_the_value_set`
— asserts the current behaviour explicitly, and will fail if a cascade or guard is
added, prompting this document to be updated.

---

### F-3 — LOW — Single-use token consumption has no database-level guard

`password_reset_tokens` and `session_refresh_tokens` have a unique index on
`token_hash`, so a token can never be duplicated into a second live credential. They
place **no** constraint on `consumed_at`: a direct `UPDATE … SET consumed_at = NULL`
re-opens a spent token.

Single use is enforced entirely by the application, by the consuming statement's
`WHERE consumed_at IS NULL` predicate evaluated inside a `FOR UPDATE` transaction.
That gate was verified under contention (§7 below: one success in 50 for password
reset, one in 50 for refresh rotation), so the invariant holds — but it holds in one
layer, not two.

**Why LOW and not a required fix.** Adding a database guard would mean a trigger
refusing `consumed_at` transitions from non-null to null, which is cheap; it is
recorded as a hardening opportunity rather than a defect because the application-level
gate is proven and the attack requires database access.

**Test:** `database_invariants::a_token_digest_is_unique_but_consumption_is_an_application_invariant`.

---

### F-4 — INFO — `/audit/verify` diagnostics expose stored chain digests

When the verifier detects divergence it returns a `diagnostics` object containing
`stored_entry_hash_hex` and `stored_prev_hash_hex` for the offending row. This is
**not** a defect:

- The endpoint requires `audit.read` *and* a recent second factor.
- Digests are not secrets. Forging the chain requires the HMAC chain key, which lives
  outside the database and never leaves the process.
- The diagnostics are what let an auditor locate the damage.

The *listing* endpoint (`/audit/events`) correctly exposes no chain material, and
`tests/integration/settings_audit_system.rs` holds that line. Recorded here only
because `TestResponse::assert_no_secrets()` bans the substring `entry_hash` outright,
so any test calling it against `/audit/verify` will fail confusingly; the §16 tests
use a targeted check instead and document why.

---

### F-5 — INFO — Shared template database made concurrent test runs mutually destructive

**Status: fixed during this audit, by concurrent work on `tests/common/mod.rs` — not
by this audit, which does not own that file.** Recorded here because it materially
affected how the evidence above had to be gathered, and because it is a useful
cautionary result in its own right.

`ensure_template()` used to **drop and recreate** `roleblank_test_template`
unconditionally, once per test binary. The template is server-global but the
`OnceCell` guarding it is per-binary, so two `cargo test` processes against the same
PostgreSQL destroyed each other's template mid-clone.

**Why this is worth recording even though it is test-only.** It does not merely cause
flakes — it manufactures failures *and* casts doubt on green runs, which is precisely
the property you cannot tolerate in the machinery that produces audit evidence. It
was measured directly. Two consecutive runs of the same three suites, same code:

| Run | Template-related panics | Failures |
|---|---|---|
| Concurrent with another test process | 47 | 55 |
| Sole process on the server | 0 | **0** |

Every affected test passed in isolation, and the failing assertions were never in the
code under test — they were `tests/common/mod.rs:149` (`clone the template`),
`:113` (`create the template`), or a fixture immediately downstream of a half-built
template. That 47 → 0 / 55 → 0 pairing is what justifies attributing the failures to
contention rather than to product behaviour, and it is why the results in this report
were all taken from runs verified to be the sole process on the server.

The fix now in place takes a PostgreSQL **advisory lock** — the right primitive,
because it lives in the server the processes already share — exclusively for
recreation and shared for cloning, and only recreates when the template is missing or
built from a different migration set.

---

## 2. §8 — Database invariants

Tested **directly against PostgreSQL**, bypassing HTTP entirely, on a per-test
throwaway database. "Application protected" means a service-layer check refuses it;
"Database protected" means the statement is refused even when the application is
bypassed completely.

| Invariant | Application protected | Database protected | Tested (test name) |
|---|---|---|---|
| FK — credentials/sessions/tokens/MFA/role assignments must reference a real principal | Yes | Yes (FK) | `foreign_keys_refuse_orphaned_rows` |
| FK — a grant must name a real role and a catalogued permission | Yes | Yes (FK) | `foreign_keys_refuse_orphaned_rows` |
| FK — a referenced user cannot be erased (`ON DELETE RESTRICT`) | Yes (no delete route) | Yes | `a_referenced_user_cannot_be_erased` |
| Unique — permission code | Yes | Yes (PK) | `a_duplicate_permission_code_is_impossible` |
| Unique — one PENDING invitation per address | Yes | Yes (partial unique index) | `only_one_pending_invitation_per_address_can_exist` |
| Unique — token digest cannot be duplicated | Yes | Yes (unique index) | `a_token_digest_is_unique_but_consumption_is_an_application_invariant` |
| CHECK — user status, principal type, scope type, RESOURCE scope needs an object | Yes | Yes (CHECK) | `invalid_enum_values_are_refused_by_check_constraints` |
| CHECK — email must be stored normalised | Yes | Yes (CHECK) | `invalid_enum_values_are_refused_by_check_constraints` |
| Case-insensitive email uniqueness | Yes | Yes (unique on `email_normalized`) | `duplicate_emails_differing_only_in_case_are_impossible` |
| ROOT ownership is a singleton | Yes | Yes (PK + trigger) | `a_second_owner_is_impossible` |
| ROOT ownership cannot be moved or removed | Yes | Yes (trigger) | `ownership_cannot_be_moved_or_removed` |
| ROOT owner cannot be deleted, suspended, archived, demoted or have MFA disabled | Yes | Yes (trigger) | `the_owner_cannot_be_deleted_suspended_archived_or_demoted` |
| ROOT owner survives a bulk statement (whole statement refused) | n/a | Yes (trigger) | `a_bulk_suspend_cannot_catch_the_owner` |
| An external principal can never become the owner | Yes | Yes (trigger) | `an_external_principal_can_never_become_the_owner` |
| Invalid role assignment — CLIENT principal cannot receive an INTERNAL role | Yes | Yes (trigger) | `a_client_principal_cannot_receive_an_internal_role` |
| Invalid role assignment — INTERNAL permission cannot attach to a client role | Yes | Yes (trigger) | `an_internal_permission_cannot_be_attached_to_a_client_role` |
| Invalid role assignment — INTERNAL permission cannot be ALLOWed for a CLIENT | Yes | Yes (trigger) | `an_internal_permission_cannot_be_allowed_for_a_client_principal` |
| Membership tables enforce the principal boundary both ways | Yes | Yes (trigger) | `membership_tables_enforce_the_principal_boundary` |
| Invalid principal transition — owner's type is immutable | Yes | Yes (trigger) | `the_owner_cannot_be_deleted_suspended_archived_or_demoted` |
| Invalid principal transition — **non-owner** INTERNAL→CLIENT | Yes | **No** (value set only) — see F-2 | `a_non_owner_principal_transition_is_constrained_only_by_the_value_set` |
| Consumed-token reuse — token cannot be re-consumed | Yes (`FOR UPDATE` + rows-affected gate) | **No** — see F-3 | `a_token_digest_is_unique_but_consumption_is_an_application_invariant`; enforcement proven under load by §7 |
| Audit UPDATE denial | Yes (no route) | Yes (trigger) | `audit_events_cannot_be_updated_deleted_or_truncated_even_by_the_schema_owner` |
| Audit DELETE denial | Yes (no route) | Yes (trigger) | `audit_events_cannot_be_updated_deleted_or_truncated_even_by_the_schema_owner` |
| Audit TRUNCATE denial (bypasses row triggers) | n/a | Yes (statement trigger) | `audit_events_cannot_be_updated_deleted_or_truncated_even_by_the_schema_owner` |
| Audit chain head cannot rewind or be deleted | Yes | Yes (trigger) | `the_audit_chain_head_cannot_move_backwards` |
| System initialisation cannot be reverted | Yes | Yes (trigger) | `system_initialisation_cannot_be_reverted` |
| Runtime schema ALTER denial | n/a | Yes (not table owner) | `runtime_role::the_runtime_role_cannot_alter_the_schema`; `the_runtime_role_could_not_have_tampered_at_all` |
| Runtime role cannot disable audit triggers or drop the table | n/a | Yes (ownership) | `the_runtime_role_could_not_have_tampered_at_all` |
| Migration role separation — runtime role is not superuser, no CREATEDB/CREATEROLE, owns nothing | n/a | Yes (role attributes) | `runtime_role::the_runtime_role_is_not_a_superuser_and_owns_nothing` |
| Migration role separation — runtime role cannot rewrite migration history | n/a | Yes (grants) | `runtime_role::the_runtime_role_cannot_rewrite_migration_history` |
| Migration role separation — DELETE granted on exactly five tables | n/a | Yes (grants) | `runtime_role::delete_is_granted_on_exactly_the_expected_tables` |
| PUBLIC has no privileges on the schema | n/a | Yes | `runtime_role::public_has_no_privileges_on_the_schema` |

Two rows are honest "No"s (F-2, F-3). Everything else is defended in both layers.

---

## 3. §7 — Race campaign: measured results

All figures are observed counts from a single run of `cargo test --test race_suite
-- --nocapture`. Every race uses a `tokio::sync::Barrier` sized to the full
concurrency, so no request is released until all of them have arrived.

| Race | Concurrency | Successes | Conflicts / refusals | Rate-limited | 5xx | Database verdict |
|---|---|---|---|---|---|---|
| ROOT bootstrap | **100** | **1** (201) | 4 × 409 `SYSTEM_ALREADY_INITIALIZED` | 95 × 429 `RATE_LIMITED` | **0** | 1 ownership row, 1 user row, `initialized_at` set |
| Invitation acceptance (one token) | **50** | **1** (201) | 19 × 401 `AUTHENTICATION_FAILED` | 30 × 429 `RATE_LIMITED` | **0** | 1 account, invitation consumed exactly once |
| Password-reset consumption (one token) | **50** | **1** (200) | 4 × 401 `AUTHENTICATION_FAILED` | 45 × 429 `RATE_LIMITED` | **0** | 1 token row, `consumed_at` set once; final password is the winner's; 0 live sessions |
| Refresh rotation (one token) | **50** | **1** (200) | 49 × 401 `AUTHENTICATION_FAILED` | 0 | **0** | 0 live refresh tokens; session revoked `REFRESH_REUSE_DETECTED`; **49 reuse events audited** |
| Versioned PATCH — project | **50** | **1** (200) | 49 × 409 `VERSION_CONFLICT` | 0 | **0** | `version` 1 → 2 (exactly once); surviving name is the winner's; 1 `PROJECT.UPDATED` audit row |
| Versioned PATCH — task | **50** | **1** (200) | 49 × 409 `VERSION_CONFLICT` | 0 | **0** | `version` 1 → 2 (exactly once); surviving title is the winner's; 1 `TASK.UPDATED` audit row |

Raw evidence lines:

```
RACE-EVIDENCE bootstrap_root x100:        n=100 statuses={201: 1, 409: 4, 429: 95}
RACE-EVIDENCE invitation_accept x50:      n=50  statuses={201: 1, 401: 19, 429: 30}
RACE-EVIDENCE password_reset_confirm x50: n=50  statuses={200: 1, 401: 4, 429: 45}
RACE-EVIDENCE refresh_rotation x50:       n=50  statuses={200: 1, 401: 49}
RACE-EVIDENCE refresh_rotation x50:       reuse_events_audited=49
RACE-EVIDENCE project_patch x50:          n=50  statuses={200: 1, 409: 49}
RACE-EVIDENCE task_patch x50:             n=50  statuses={200: 1, 409: 49}
```

**Notes on the numbers, stated plainly.**

- **Rate limiters do most of the refusing, and that is correct.** 95 of 100 bootstrap
  attempts and 45 of 50 reset confirmations never reach the transaction, because the
  per-IP quotas (bootstrap 5/hour, password reset 5/hour, invitation acceptance
  20/hour) refuse them first. A hundred simultaneous bootstrap attempts from one
  address *is* an attack. This does mean the number of requests genuinely contending
  for the row is smaller than the headline concurrency: **~5 for bootstrap, ~5 for
  password reset, 20 for invitation acceptance, 50 for refresh and both PATCH
  races** (which have no comparable per-IP quota). The row-level property is
  additionally proven at low concurrency by the pre-existing two-way tests, which
  bypass no defence.
- **Refresh rotation is deliberately harsh.** All 49 losers are treated as *reuse*,
  not merely rejected, and each raises its own audit event — so the whole token
  family is revoked and the user must log in again. That is the intended trade
  (ADR-005): the system cannot distinguish an honest double-submit from a thief, and
  if it could, so could an attacker.
- **Every loser in every race carries a stable machine-readable `code`.** Assertions
  are on the code, never on prose.
- **No race produced a single 5xx.** This is asserted, not observed in passing:
  `Tally::server_errors() == 0` is a hard assertion in every race test. It is the
  assertion that caught F-1.

---

## 4. §14 — Idempotency

| Property | Result | Test |
|---|---|---|
| Same key + same body → the same safe result, replayed, one resource | Pass | `a_retry_with_the_same_key_and_body_replays_the_stored_response` |
| Same key + **different** body → deterministic `409 IDEMPOTENCY_KEY_REUSED` | Pass | `the_same_key_with_a_different_body_is_refused` |
| Concurrency on one key — 2 simultaneous identical POSTs → one resource | Pass | `two_simultaneous_identical_posts_create_one_resource` |
| Concurrency on one key — 10 simultaneous identical POSTs → one resource | Pass | `ten_simultaneous_identical_posts_create_one_resource` |
| Principal A cannot reach principal B's key | Pass | `one_principals_key_does_not_touch_anothers` |
| The key is scoped by operation as well as by principal | Pass | `the_key_is_scoped_by_operation_as_well_as_by_principal` |
| A request without a key writes no record | Pass | `a_request_without_a_key_writes_no_record` |
| A failed create releases the key for a corrected retry | Pass | `a_failed_create_releases_the_key_for_a_corrected_retry` |
| A malformed key is rejected, never silently discarded | Pass | `a_malformed_key_is_rejected_rather_than_discarded` |

The record is keyed `(principal_id, operation, idempotency_key)` with a SHA-256
fingerprint taken over the **raw request bytes before deserialisation**. Byte-level
fingerprinting means a body with an unknown extra field is *not* treated as the same
request as one without — which matters, because that is the mass-assignment surface.
The cost is that a client which re-serialises its retry with different whitespace
receives a 409 rather than a replay; that is the safe direction to be wrong in.

Cross-principal isolation is structural rather than checked: the principal id is part
of the record's key, so principal A's lookup cannot return principal B's row at all.
The test confirms A's reuse of B's key creates a *new* resource for A rather than
replaying B's response — i.e. no cross-tenant read.

No defects found in §14.

---

## 5. §15 — Transactional outbox

### Semantics verdict — stated honestly

> **Delivery is at-least-once. It is not exactly-once, and it cannot be.**

A handler must therefore be written to assume **the same event may be dispatched more
than once**, and must be safe to run twice.

The reason is structural, not a shortcoming of this implementation. The worker
claims a row, calls the mail provider, and only then marks the row `SENT`. A process
killed in that window — a deploy, an OOM kill, a node eviction — leaves a row that
*was* delivered but still looks claimable, and the next worker delivers it again.
Closing that window would require a distributed transaction spanning PostgreSQL and a
third-party mail API, which neither side offers. The trade is deliberate and correct:
a duplicate password-reset email is acceptable, a missing one is not.

What *is* exactly-once is the **enqueue** side: the outbox row and the state change
that caused it commit or roll back together, atomically, with no window. `enqueue`
takes `&mut Transaction` rather than a pool specifically so that no call site can
express the broken alternative.

This is verified, not assumed:

```
OUTBOX-EVIDENCE at-least-once: one event delivered twice, by Some("once") then Some("twice")
```

### Results

| Property | Result | Test |
|---|---|---|
| DB commit succeeds while the mail provider fails → **work is not lost** | Pass | `a_mail_provider_outage_does_not_lose_the_work` |
| Provider recovers → the event is delivered, failure history preserved | Pass | `a_mail_provider_outage_does_not_lose_the_work` |
| Outbox row **rolls back with its transaction** (no side effect for a rolled-back change) | Pass | `an_outbox_row_shares_the_fate_of_its_transaction` |
| Outbox row survives commit, `PENDING`, `attempts = 0` | Pass | `an_outbox_row_shares_the_fate_of_its_transaction` |
| Redelivery after a crash between "provider accepted" and "row marked SENT" | Pass (**at-least-once demonstrated**) | `delivery_is_at_least_once_so_a_redelivery_is_possible` |
| Two workers claiming simultaneously never claim the same event twice | Pass (6 workers, barrier) | `concurrent_workers_never_claim_the_same_event_twice` |
| Duplicate claim prevented across *consecutive* polls (claim lease) | Pass | `concurrent_workers_never_claim_the_same_event_twice`, `a_future_dated_event_is_never_claimed` |
| Retry backoff grows and is capped | Pass | `retry_backoff_grows_between_attempts_and_is_capped` |
| Max attempts exhausted → `DEAD` | Pass | `exhausting_the_attempt_budget_moves_the_row_to_dead` |
| Unknown event type → `DEAD` on the first attempt, not retried 8 times | Pass | `an_unknown_event_type_is_dead_lettered_on_the_first_attempt` |
| Worker cancelled mid-batch releases its unattempted claims | Pass | `a_cancelled_worker_stops_without_abandoning_a_claim` |
| Worker cancelled before starting claims nothing | Pass | `a_worker_cancelled_before_starting_claims_nothing` |
| Every event type the application enqueues has a handler | Pass | `every_event_the_application_enqueues_is_deliverable` |

Provider-outage evidence:

```
OUTBOX-EVIDENCE after provider outage: status=FAILED attempts=1 last_error=Some("no mail provider is configured")
OUTBOX-EVIDENCE after recovery:        status=SENT   attempts=1
```

The failed attempt is still visible on the row after the eventual success —
`mark_sent` deliberately does not touch `attempts`, so an outage is not tidied away
by the recovery. `claimed_by` is likewise preserved on success, which is what makes
the two-dispatch evidence above readable.

Concurrency defence is layered: `FOR UPDATE SKIP LOCKED` inside the claiming `UPDATE`
handles workers claiming at the *same instant*, and a `claimed_at` lease handles
*consecutive* polls — the latter is necessary because a claimed row is deliberately
left `PENDING` (so a crash between claiming and delivering does not strand it in a
status nothing sweeps), which would otherwise let a worker polling milliseconds later
re-claim it.

No defects found in §15.

---

## 6. §16 — Audit integrity

**The claim under test**, quoted from `src/modules/audit/chain.rs`:

> Any modification, deletion or reordering of `audit_events` performed **without the
> chain key** is detected by the verifier.

This is explicitly *not* tamper-proofing: an adversary holding both the database and
the chain key can rewrite the chain consistently. The chain is useful because the key
lives outside the database.

`chain.rs` already had unit tests over synthetic entries, which prove the algorithm.
They did **not** prove that the rows this application actually writes verify, nor that
a real edit to a real table is caught. That gap is now closed end-to-end.

### Safety of method

Every tamper test runs against the **per-test throwaway database** created by
`TestApp::spawn()` (`rb_test_<uuid>`), which is dropped when the test ends. No
database outside the test is read or written. Tampering is performed as the
**migration role** (the table's owner) by disabling the append-only trigger around the
statement and re-enabling it immediately, so the verifier examines a table in its
normal state with only the *data* changed.

### Results

Several genuinely sensitive events are created first by driving the real router:
bootstrap, login, TOTP enrolment and two department creations — 7 chained entries.

| Scenario | Verifier outcome | Located at | Test |
|---|---|---|---|
| Untampered chain (baseline) | `INTACT`, `entries_checked = 7`, `reached_chain_head = true` | — | `a_genuine_chain_verifies_intact` |
| `outcome` rewritten on a middle row | **`HASH_MISMATCH`** | `first_divergent_seq = 4` | `rewriting_an_audit_row_is_detected` |
| `metadata` rewritten on a middle row | **`HASH_MISMATCH`** | `first_divergent_seq = 4` | `rewriting_audit_metadata_is_detected` |
| Middle row deleted | **`MISSING_SEQUENCE`** | `first_divergent_seq = 4` | `deleting_an_audit_row_is_detected` |
| Most recent row deleted (tail truncation) | **`HEAD_MISMATCH`** | `first_divergent_seq = 6` | `truncating_the_audit_tail_is_detected` |

Raw evidence:

```
AUDIT-EVIDENCE untampered:     {"outcome":"INTACT","entries_checked":7,"checked_from_seq":1,"checked_to_seq":7,"reached_chain_head":true}
AUDIT-EVIDENCE rewritten seq=4:{"outcome":"HASH_MISMATCH","first_divergent_seq":4,"entries_checked":3,…}
AUDIT-EVIDENCE metadata seq=4: {"outcome":"HASH_MISMATCH","first_divergent_seq":4,"entries_checked":3,…}
AUDIT-EVIDENCE deleted seq=4:  {"outcome":"MISSING_SEQUENCE","first_divergent_seq":4,"entries_checked":3,…}
AUDIT-EVIDENCE truncated head=7:{"outcome":"HEAD_MISMATCH","first_divergent_seq":6,"entries_checked":6,…}
```

The baseline matters: a verifier that reported damage on an untouched chain would
detect nothing, it would simply always complain. `INTACT` over exactly 7 of 7 entries
is what makes the four detections meaningful.

Tail truncation deserves a note. A truncated tail is *internally consistent* — every
surviving link still checks out — so the links alone cannot catch it. Only the
separately maintained `audit_chain_head` knows how far the chain is supposed to
reach, which is precisely why that record exists. This is the shape of a cover-up
performed immediately after the act, and it is caught.

### The runtime role could not have made any of these changes

The tests above needed the **migration** role. If the identity the application runs as
could do the same, a compromised application process could rewrite its own history and
every result above would be moot. Verified as `roleblank_app`, all refused:

| Attempt as the runtime role | Result |
|---|---|
| `ALTER TABLE audit_events DISABLE TRIGGER trg_audit_events_append_only` | Refused (not the table owner) |
| `ALTER TABLE audit_events DISABLE TRIGGER ALL` | Refused |
| `UPDATE audit_events …` | Refused (no grant) |
| `DELETE FROM audit_events …` | Refused (no grant) |
| `TRUNCATE audit_events` | Refused |
| `DROP TABLE audit_events` | Refused |

The chain length is asserted unchanged afterwards, so nothing partially applied.

**Test:** `the_runtime_role_could_not_have_tampered_at_all`.

No defects found in §16.

---

## 7. Verification

### Required suites — all green

```
cargo test --test race_suite --test failure_injection --test security_suite

test result: ok. 10 passed;  0 failed   (failure_injection)
test result: ok. 58 passed;  0 failed   (race_suite)
test result: ok. 142 passed; 0 failed   (security_suite)
                 ───────────
                 210 passed;  0 failed
```

Of the 142 in `security_suite`, the 26 `database_invariants` tests are the ones this
audit owns; all 26 pass.

**One out-of-scope failure, recorded rather than hidden.** A later run of
`security_suite` — after concurrent work added a new §4 suite — showed
`142 passed; 1 failed`, the failure being
`escalation_matrix::a_targeted_denial_hides_the_department_from_the_listing_too`
(`tests/security/escalation_matrix.rs:1193`). That file did not exist when this audit
began and belongs to the §4 workstream, which is actively editing it. It appears to
be a genuine finding — a `DENY` override on a specific department is honoured by the
object decision but not applied to the listing endpoint, so the denied department is
still returned in `GET /departments`. It is **not** caused by any change in this
audit: none of the files this audit touched are involved, and all 26
`database_invariants` tests pass in the same run. It is flagged here so it is not
lost, and is left to the workstream that owns it.

### Whole suite — not regressed

```
cargo test --no-fail-fast

596 + 10 + 1 + 34 + 155 + 5 + 58 + 5 + 142  =  1006 passed;  0 failed;  4 ignored
```

Baseline at the start of this audit was **906 passed, 1 failed** — the single failure
being the pre-existing `invitation_accept` race that turned out to be F-1. The count
has since grown past 906 because other work added suites concurrently; the figure
that matters is **0 failed**, against 1 before.

Both runs above were taken while verified to be the sole `cargo test` process on the
server, for the reason set out in F-5. The contrast is itself measured: the same
three suites, same code, run concurrently with another test process produced 55
failures and 47 template-related panics; run alone, 0 and 0.

Tests added or raised by this audit:

| File | Change |
|---|---|
| `tests/race/fixtures.rs` | Added `Tally` and `race()` — a barrier-based race runner that records the full outcome distribution by status and by stable `code`, and prints it as `RACE-EVIDENCE` |
| `tests/race/bootstrap.rs` | 100 concurrent; now records the distribution and asserts zero 5xx |
| `tests/race/invitation_accept.rs` | 20 → **50** concurrent; asserts zero 5xx (this caught F-1) |
| `tests/race/password_reset.rs` | Added **50** concurrent; one well-defined final password, all sessions revoked, token consumed once |
| `tests/race/refresh_rotation.rs` | 8 → **50** concurrent; no second chain, reuse detection fires, family revoked |
| `tests/race/optimistic_concurrency.rs` | 10 → **50** on projects, added **50** on tasks; both prove `version` moved exactly once and the winner's value survived |
| `tests/race/outbox_worker.rs` | Added transaction fate-sharing, provider-outage durability, and at-least-once redelivery |
| `tests/security/database_invariants.rs` | Added FK/RESTRICT coverage, token-consumption boundary, principal-transition boundary, and the complete §16 tamper-detection suite |

Source changed (defect fix only):

| File | Change |
|---|---|
| `src/modules/identity/repo.rs` | `actor_basics` made generic over `sqlx::Executor` |
| `src/modules/identity/invitations.rs` | `accept_invitation` no longer acquires a second pooled connection while holding a transaction |
