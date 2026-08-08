# Findings register — final backend acceptance audit

Working register. Every entry is either **verified by execution** against the
clean-room instance or explicitly marked as a source-reading claim awaiting proof.
Severity is assigned on demonstrated impact, not on how alarming the code looks.

The audit's own recurring lesson, stated once here so it is not lost in the detail:
**a green suite describes the tests, not the system.** Every finding below except
F-07 and F-08 was invisible to a 622-test suite that reported zero failures.

## Severity gate status

| Severity | Open | Fixed |
|---|---|---|
| CRITICAL | 0 | 0 |
| HIGH | **0** | 7 |
| MEDIUM | 1 | 4 |
| LOW | 6 | 2 |
| INFO | 13 | 0 |

Consolidated across all workstreams. The per-section detail lives in
`SECTION_3_6_FINDINGS.md`, `SECTION_7_16_FINDINGS.md`, `SECTION_9_13_FINDINGS.md`
and `SECTION_23_26_FINDINGS.md`; the narrative and the verdict are in
`../FINAL_ACCEPTANCE_REPORT.md`.

The single open MEDIUM is the rate-limiter / audit-growth chain (M-A there).

---

## F-01 — HIGH — Runtime role cannot read `permissions` — **FIXED**

The application could not boot at all against a correctly provisioned database:
`roleblank_app` was never granted `SELECT` on `permissions`, which `serve` reads at
startup. Every prior test run connected as `roleblank_migrator`, so the suite never
exercised the role the product actually runs as.

*Fix:* `backend/migrations/0010_grant_permission_catalogue.sql`.
*Regression:* `the_runtime_role_can_read_every_table_in_the_schema`,
`the_runtime_role_can_execute_the_startup_queries`.

## F-02 — HIGH — `setval()` needs `UPDATE` on the sequence — **FIXED**

`USAGE` on a sequence permits `nextval`, not `setval`. `audit::append` calls
`setval`, so **every audited mutation** — that is, every write in the system —
returned `500` under the runtime role.

*Fix:* same migration. *Regression:*
`the_runtime_role_can_perform_the_whole_audit_append` replays all four statements
of the real append as `roleblank_app`.

## F-03 — MEDIUM — Invitation acceptance shared the registration rate-limit key — **FIXED**

Acceptance and public registration counted against one bucket, so ordinary
onboarding traffic from behind a single NAT could exhaust the quota and lock out
invited colleagues. A cross-flow denial of service on the one path into the company.

*Fix:* dedicated `invitation_accept_ip` key plus its own configurable quota.

## F-04 — LOW — Database outage reported `500`, not `503` — **FIXED**

`sqlx::Error::Io`/`Tls`/`PoolTimedOut`/`PoolClosed` mapped to a generic internal
error. Clients cannot tell "retry me" from "this request is broken", and operator
alerting misclassifies an infrastructure outage as an application bug.

*Fix:* those variants now map to `ServiceUnavailable`.

## F-05 — HIGH — Invitation placement was never authorised — **FIXED**

`POST /api/v1/invitations` authorised only `iam.users.invite@Collection`. The
`department_id` and `client_account_id` fields were validated for *coherence* and
never authorised against the thing they named — yet on acceptance both become real
memberships, and the client membership is written **ACTIVE**.

**Escalation by proxy, proven end to end.** The attacker never gains a permission;
they mint a *second account* that holds one, at an address they control:

| Step | Result before the fix |
|---|---|
| Attacker reads the classified project | `403` — correctly denied |
| Attacker adds a member to that department directly | `403` — correctly denied |
| Attacker invites a proxy **into that same department** | `201` — **accepted** |
| Proxy reads the classified project | `200` — **confirmed escalation** |

Both controls prove the system's own judgement was that this principal must not
reach that department. The invitation body bypassed it.

The equivalent CLIENT attack is blocked today, but only *incidentally* — by the
role-delegation guard, because `client.portal.*` is `max_principal_type = CLIENT`
and an INTERNAL actor can never hold it. Nothing was checking the placement, so
that protection was an accident of an unrelated rule.

*Reproducers:* `scripts/exploit_department_placement.sh` (escalation chain),
`scripts/exploit_invitation_placement.sh` (client variant, blocked).
*Fix:* `departments::service::authorize_placement` and
`clients::service::authorize_placement`, called from `create_invitation` inside the
transaction against the locked row. Each module authorises its own placement so the
scope semantics stay where they are owned.
*Regression:* three tests in `escalation_matrix.rs`, including a **positive** case
proving the guard is an authorisation check and not a blanket refusal.
*Verified after fix:* exploit re-run → `403`; legitimate ROOT flow → unaffected.

## F-06 — MEDIUM — Department routes identified the system owner to a CLIENT — **FIXED**

`guard_root` ran *before* authorisation on `POST`/`DELETE
/departments/{id}/members`. It answers `403 ROOT_PROTECTED`, while every other
subject id answers `404` to an external principal. The difference was a usable
oracle confirming the owner's user id — and that internal users exist at all — to a
principal outside the company. That is threat-model boundary 2 losing to a
diagnostic nicety. `identity/service.rs` had already identified and solved exactly
this (via `deny_root`, which masks to `404` for external callers); departments
never got the treatment.

Measured on the live clean-room instance, same request, same tokens:

| Subject id | Before | After |
|---|---|---|
| the owner | `403 ROOT_PROTECTED` | `404 RESOURCE_NOT_FOUND` |
| an unknown user | `404 RESOURCE_NOT_FOUND` | `404 RESOURCE_NOT_FOUND` |

*Fix:* the guard now runs after `require` and `require_step_up_for`. Ordering does
not weaken the protection — `require` judges the *actor*, `guard_root` the
*subject*, and the subject is still refused; it only stops the system answering a
question the caller was never allowed to ask. An internal principal still receives
the unmistakable `403 ROOT_PROTECTED` the documentation promises.
*Regression:* `the_department_routes_do_not_identify_the_owner_to_a_client`, which
asserts both the masking and that the protection itself still fires.

## F-07 — HIGH (evidence integrity) — The test harness is not safe against concurrent runs — **FIXED**

Re-rated from LOW to HIGH on a second workstream's evidence: it does not affect the
product, but it can silently void the security gate in *either* direction, which is
worse than a defect that only fails loudly. One suite was observed reporting an
entire file as failed having executed zero assertions.

*Fix:* a PostgreSQL advisory lock — exclusive to recreate, shared to clone — plus
recreate-only-when-the-migration-set-differs, so the common case touches nothing.

While fixing it I introduced, and then caught, a self-deadlock of exactly the kind
another workstream had just reported in `accept_invitation`: `small_pool` is
`max_connections(1)`, so holding the lock connection starved every subsequent DDL
call on the same pool. Recorded because it is the same lesson twice in one audit —
**hold a lock and a pool at once and you will deadlock against yourself.**

## F-07-orig — LOW — original rating, superseded above

Each test binary's setup runs `DROP DATABASE IF EXISTS roleblank_test_template`
followed by `CREATE`. Two `cargo test` processes against one PostgreSQL therefore
destroy each other's template mid-run, and the victim reports failures
(`3D000: template database ... does not exist`) that have nothing to do with the
code under test.

This produced a **false FAIL** during this audit: a combined run reported 65
failures while `integration_suite` alone was 155/155 green, because parallel agent
runs were sharing the same server.

Not a product defect, but a defect in the evidence-production machinery, which is
why it is recorded rather than waved away: it can manufacture failures *and*, run
the other way, cast doubt on green results. Suggested fix: derive the template name
per run (PID or a run id), or take a PostgreSQL advisory lock around template setup.

## F-08 — INFO — Vestigial `state.guard_root(false)` calls — **OPEN**

`identity/service.rs:263` and `:457` call `state.guard_root(false)`, which is
unconditionally a no-op. The real protection on those paths is the `deny_root(...)`
call immediately above, which also masks the refusal for external principals and
records the attempt. Harmless today, but it reads as if root protection lives there,
which is precisely the kind of thing a future maintainer relies on. Left unchanged
during a freeze; worth deleting when the file is next touched.
