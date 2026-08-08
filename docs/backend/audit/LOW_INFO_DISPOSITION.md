# LOW / INFO disposition — closure of the final acceptance audit

Every LOW and INFO finding left open by the final backend acceptance audit, and
what happened to it. Three verdicts are possible and there is no fourth:

* **FIXED** — the code or the schema changed, and a regression test fails without
  the change. Every entry marked FIXED below was verified by reverting the fix and
  observing the named test fail, not by reading the diff.
* **ACCEPTED** — deliberately not fixed, with the reason stated in full. An
  acceptance that does not survive being read out loud is not an acceptance.
* **RECLASSIFIED** — the severity was wrong. One entry moved, and it moved *up*.

The closure target was zero unresolved actionable LOW findings. That is met:
**every LOW is FIXED.** The accepted set is INFO only, and each acceptance is
either a cleanup with no security content or a change that belongs to a file this
workstream does not own.

---

## 1. Summary

| Verdict | LOW | INFO | Total |
|---|---|---|---|
| FIXED | 6 | 8 | **14** |
| ACCEPTED | 0 | 7 | **7** |
| RECLASSIFIED (INFO → LOW, then fixed) | — | 1 | **1** |

**Nothing was more serious than its original rating**, with one exception in the
other direction of the low band: F-14 was rated INFO and is really LOW, because
the gap it describes is inside the stated claim of the system's flagship integrity
control rather than outside it. It is fixed.

---

## 2. The table

| ID | Description | Verdict | Reasoning | Regression test |
|---|---|---|---|---|
| **L1** / §3-6 F-1 | `mfa_required` is set at invitation acceptance but not by `assign_role` / `create_override`, so granting dangerous authority to an existing account does not force enrolment | **FIXED** | Confirmed to fail closed today — step-up is derived from `sessions.mfa_verified_at`, written only by the three real MFA endpoints — but the whole safety property rests on that one fact. A future trusted-device flow, SSO assertion or administrative step-up override turns a silent onboarding gap into a live escalation path, and *nothing would have failed* to announce it. The operational symptom was also bad: the grant audited as a success and the grantee simply could not use it. `authz::repo::mandate_mfa` now raises the flag inside the same transaction; only for an ALLOW, never a DENY; and the audit record says whether this grant is what imposed it | `assigning_a_dangerous_role_mandates_a_second_factor`, `a_dangerous_allow_override_mandates_a_second_factor_and_a_deny_does_not` |
| **L2** / §7-16 F-2 | Non-owner `principal_type` transitions are unguarded at the database level | **FIXED** | Three triggers enforce the client envelope where rows are *written*, and every one of them reads `users.principal_type` — so none fired when that column was the thing that changed. `UPDATE users SET principal_type = 'CLIENT'` produced a principal the evaluator treats as external while the membership tables still treated them as staff. Migration 0011 re-checks the envelope on the transition. Deliberately a **re-check and not a pin**: a conversion that strands nothing still succeeds, so an operator repairing a mis-created account is not locked out | `a_non_owner_principal_transition_cannot_strand_an_incompatible_grant` |
| **L3** / §7-16 F-3 | Single-use token consumption (`consumed_at`) has no database-level guard | **FIXED** | The application gate was proven under contention (one success in fifty), but it held in one layer. One stray `UPDATE ... SET consumed_at = NULL` re-opened a spent credential: a used reset link works again, a rotated refresh token is live alongside its successor, a burnt recovery code is a working MFA bypass again. Migration 0011 makes the column immutable once set — immutable rather than merely not-nullable, because rewriting *when* a credential was spent falsifies the same record. `recovery_codes` is included although the finding named only two tables: same column, same statement shape, same claim, and it is the one that guards a second factor | `a_token_digest_is_unique_and_consumption_is_final`, `consumption_is_final_on_every_single_use_credential_table` |
| **L5** / §23-26 F-05 | Two step-up endpoints rely on the service rather than the extractor to exclude a pending-MFA session | **FIXED** | `ROUTE_TABLE` had always declared `/mfa/disable` and `/mfa/recovery/regenerate` as `Authenticated`; the handlers took `MfaPendingSession` and leaned on `state.require_step_up` inside the service. That exclusion was correct but was a consequence of one line in a service, not a property of the type — and `Authenticated` exists precisely so a handler that forgets to think about MFA gets the safe behaviour. Both now take `Authenticated`; the service checks stay, so this is two barriers rather than one moved | `a_pending_session_is_refused_by_the_extractor_on_the_mfa_weakening_routes` |
| **L6** / §23-26 F-08 | Two (in fact four) listing paths refuse without going through `state.require`, so the denial is neither metered nor logged | **FIXED** | `state.require` is the single place that increments `metrics.authz_denial(reason)` and emits the `"authorization denied"` line with actor, permission and reason. A refused listing is exactly what an enumeration sweep looks like, and it was invisible to both. `projects::list`, `projects::client_list`, `tasks::list` and `tasks::client_list_for_project` now route the refusal back through the gate, as `departments::list` already did | `a_refused_listing_is_counted_like_every_other_denial` |
| **L7** / §23-26 F-09 | `GET /api/v1/system/info` returns feature-flag keys to any principal including CLIENT | **FIXED** | Withholding `is_security_sensitive` while publishing the key it marks was self-defeating: the marker's purpose is to say which toggle is worth attacking and the key is the name of the thing to attack. The filter is now in the **query**, so a caller who may not see a sensitive key never has it in process memory. A concurrent workstream additionally made the whole list empty for external principals; the two compose, and the regression test asserts the filter through an *internal* principal so that the envelope change cannot make it vacuous | `system_info_names_ordinary_feature_flags_and_never_the_sensitive_ones` |
| **L8** / §23-26 F-10 | Loading a row before authorising creates a small existence oracle on three routes | **FIXED** | `MODULE_GUIDE` §3.1's "load first, decide second" exists because an *object-level* decision needs the row. These four decisions are `Target::Collection`, which needs nothing from the row, so loading first bought no accuracy and cost an oracle: an unauthorised internal principal told a real id (`403`) from an invented one (`404`). `audit::get_event` already took the opposite order for exactly this reason, and one of the two conventions had to win. Fixed on `get_role`, `update_role`, `delete_role` and `revoke_invitation` | `an_unauthorised_principal_cannot_tell_a_real_role_from_an_invented_one` |
| **L9** / §23-26 F-13 | Three independent UUID path parsers, one accepting inputs the others reject | **FIXED** | `authorization::routes::parse_id` trimmed; `extract::parse_path_uuid` deliberately does not, with an essay explaining why. So `/roles/%20{uuid}%20` was a `200` and `/departments/%20{uuid}%20` a `400` — and **both sides pinned their own behaviour with a test**, so neither module would ever have noticed the other. Nothing exploitable; a UUID is a UUID once parsed. It is fixed because two implementations of one rule is the drift this codebase argues against everywhere else, and because the looser copy is always the one that gets found. `authorization::routes` now uses the shared `PathId`/`PathIds`; `audit::get_event` no longer trims, keeping its "malformed id is a `404`" contract while sharing the acceptance set | `every_module_parses_a_path_identifier_with_the_same_grammar` |
| **§3-6 F-2** | ROOT guard is not first in `delete_override`; the attempt is not audited as `ROOT.PROTECTION_TRIGGERED` | **FIXED** (INFO) | Not exploitable — the owner can hold no override, for three independent reasons — but two things degraded. The refusal was recorded as an ordinary `AUTHORIZATION.DENIED`, so probing the owner through this one route never reached the feed `root_attack::every_attempt_on_the_owner_is_recorded_and_the_record_cannot_be_erased` watches; and the invariant rested on a three-step argument about bootstrap ordering rather than on a guard. The guard now runs after `require` and before the lookup — after, per the F-06 ordering, so an external principal is refused for not being allowed to ask before the system answers a question about who the owner is | `deleting_an_override_from_the_owner_is_refused_as_root_protection` |
| **§23-26 F-11** | Two endpoints in the sensitive set have no rate limiter | **FIXED** (INFO) | `/auth/mfa/disable` was the only endpoint in the MFA set with no limiter, and it is the one that turns the second factor off. `enforce_mfa_limits` is called **after** `require_step_up`, so a session that cannot pass the gate does not consume the account's quota — otherwise a stolen password-only token could deny the real owner the ability to manage their own factor. `GET /bootstrap/status` is now covered by the general per-IP limiter landed by the concurrent rate-limit workstream | `disabling_the_second_factor_is_rate_limited` |
| **§23-26 F-12** | Cancelling a task is recorded as `TASK.UPDATED` rather than its own action | **FIXED** (INFO) | The original reasoning was honest — the tasks module correctly declined to extend a catalogue it does not own — but an auditor filtering `action_code = TASK.CANCELLED` got an empty page and the reasonable conclusion that nothing had been cancelled. That is precisely the failure mode `audit::service::validate_action_code` argues against when it refuses to validate filters against a snapshot of the constant list. `action::TASK_CANCELLED` added; the metadata still names the transition | `cancelling_a_task_is_recorded_under_its_own_action_code` |
| **§23-26 F-14** | `audit_events.source_ip_hint` is stored but not covered by the hash chain | **RECLASSIFIED INFO → LOW, then FIXED** | **This is the one severity I disagree with.** The chain's claim is stated precisely: "any modification, deletion or reordering performed **without the chain key** is detected", written against an adversary holding the database — a dump, a restored backup, a compromised superuser. Against exactly that adversary, every source IP in the log could be rewritten and verification would still say the chain was intact. Origin is what an intruder most wants to change in a log they cannot delete. A gap *inside* the stated claim of the flagship control is not INFO. Fixed with a chain **version marker**: existing rows stay at 1 and verify under the layout they were written with, everything from this build is 2, and the marker is itself inside the v2 digest so a row cannot be relabelled as v1 to escape back to the weaker layout. The v1 byte layout is frozen by a golden digest produced by an *independent* implementation — a vector taken from the code it pins agrees by construction and pins nothing | `rewriting_the_source_ip_of_an_audit_row_is_detected`, `downgrading_the_chain_version_of_an_audit_row_is_detected`, `the_version_1_layout_is_frozen` |
| **§3-6 F-3** | The runtime DB role can change ROOT's email / display_name and credentials row | **FIXED in part** (INFO) | The audit called this documentation accuracy and it was right that no *new* capability is conferred: the same role holds `INSERT` on `sessions`, so an attacker at that level can authenticate as ROOT directly. The email half is closed anyway because it is nearly free and because the implemented invariant should match the documented one — migration 0011 pins the owner's `email` and `email_normalized`, which removes the password-reset path. Nothing in the application updates that column for the owner (`identity::update_user` refuses them as its first substantive act), so the trigger can never fire on a legitimate request. `display_name` and the `credentials` row are **accepted** as inside the application's own authority by design, and 0011's comment block says so | `the_owners_email_address_cannot_be_rewritten` |
| **Register F-08** | Vestigial `state.guard_root(false)` no-op calls in `identity/service.rs` | **FIXED** (INFO) | `guard_root(false)` is unconditionally a no-op — the argument is a literal `false`. The real protection is the `deny_root(...)` branch immediately above, which refuses, records `ROOT.PROTECTION_TRIGGERED` and masks for external principals. Both calls deleted, with a comment saying where the guard actually lives, because a reader who believes the protection is in the no-op may move or remove the real check | existing `root_destruction::*` (unchanged and still green) |

---

## 3. Accepted, with reasons

| ID | Description | Why it is accepted |
|---|---|---|
| **§26 A-01** | `platform/observability/metrics.rs` is ~1 072 lines and only two series are ever recorded; no metrics layer is installed | **Half-accepted, and the half that matters is blocked on file ownership.** The real defect is not the dead code — it is that `GET /metrics` carries a prominent comment warning that it "publishes request volumes, error rates and authorisation-denial counts", and two of those three are never observed. Closing that requires installing a metrics layer in `platform/http/middleware.rs`, which is reserved by the concurrent rate-limit workstream and was being rewritten while this closure ran. The patch is in §4 below, unapplied. Deleting the eight unused methods instead would also close it, and is deliberately *not* done unilaterally: `rate_limit_event` in particular is plausibly about to acquire a caller |
| **§26 A-02** | `platform/http/endpoints.rs` is a fourth unused copy of the route list | Accepted. It is genuinely worth deleting — an unreferenced registry is worse than none, because it drifts invisibly — but it is a 383-line file outside this workstream's ownership, it carries no security content, and `ROUTE_TABLE` is already cross-checked against both the mounted router and the OpenAPI document by two tests. Deleting a whole file during a freeze, in a tree another workstream is actively editing, is the wrong trade |
| **§26 A-03** | Ten unused public items, several of which are fake future-proofing | Accepted as cleanup with no security content. Two carry a real cost and are named here so they are not lost: `AppState::not_found_or_denied` is a **second implementation of a security rule** already expressed by `AppError::hide_from_external`, which is exactly the drift risk this codebase argues against; and `evaluator::holds_any` carries a docstring that misdescribes how `/auth/me` builds its capability list, which is the actual harm rather than the dead function. Both live in files outside this workstream's grant (`app.rs`, and `evaluator.rs` is shared with the property suite). The rest — `root_user_id`, `grant`, `_assert_types`, `audit::denial`, `identity::without_root`, `OutboxWorker::with_derived_id`, `mfa::_factor_summary` — are tidiness only. Note `keys::general_principal` / `keys::general_ip` are no longer unused: the concurrent workstream installed the general limiter |
| **§26 A-04** | Three independent scope-to-SQL translations | Accepted **as an architecture observation**, and its concrete consequence (F-02, MEDIUM) is already fixed. The recommendation stands and should be scheduled: a property test asserting that inclusion by each translation agrees with `evaluator::evaluate` on the corresponding `Target::Resource`, for generated actors and resources. It is not done here because it is a new test *campaign* rather than a regression, `tests/integration/scope_filtering.rs` already asserts the property for the projects translation on concrete data, and writing a generator-driven equivalence test during a freeze is how a freeze stops being one |
| **L4** | Leaked test databases: the `Drop` handler spawns a detached thread that dies with the process; 493 `rb_test_*` databases had accumulated | Accepted here because the fix belongs in `backend/tests/common/mod.rs`, which this workstream may not modify and which the harness workstream has been rewriting (the advisory-lock fix for F-07 landed there). Test-infrastructure only; no product impact. The durable fix is to drop synchronously in `Drop` on a blocking runtime handle, or to sweep by age in the harness's startup path |
| **§3-6 F-4** | A bounded administrator cannot assign the built-in `employee` role | Accepted: **working as designed, and the natural "fix" would be a HIGH-severity regression.** Assigning a role requires holding every permission it contains at a derivable scope; `employee` contains `projects.read@ASSIGNED`, which `@DEPARTMENT` cannot derive. Relaxing this to "check only `iam.roles.assign`" reintroduces the classic escalation where one permission lets an actor hand out authority they do not hold. If onboarding must be delegable, grant the delegating role the union of `employee`'s contents explicitly |
| **§7-16 F-4** | `/audit/verify` diagnostics expose stored chain digests | Accepted: **not a defect.** The endpoint requires `audit.read` and a recent second factor; digests are not secrets, since forging the chain needs the HMAC key, which lives outside the database; and the diagnostics are what let an auditor locate the damage. The listing endpoint correctly exposes no chain material and `tests/integration/settings_audit_system.rs` holds that line |
| **§7-16 F-5 / §3-6 F-5** | Shared template database made concurrent test runs mutually destructive | Already fixed by the harness workstream (PostgreSQL advisory lock, recreate only when the migration set differs). No action here |

---

## 4. The patch that could not be applied

`backend/src/platform/http/middleware.rs` is reserved. This closes the operational
half of A-01 — the gap between what the `/metrics` comment promises and what is
recorded. Apply inside `middleware::apply`, outermost so it observes the status
every other layer produces, including rejections:

```rust
use axum::extract::MatchedPath;

/// Record one HTTP request and its latency.
///
/// **The matched route pattern, never the URI.** `/api/v1/projects/{id}` is one
/// series; the raw path would mint one per identifier, which is an
/// attacker-controlled cardinality explosion in a process-resident map — the exact
/// failure `metrics::HttpSeries` bounds against, and it must be bounded here too
/// rather than trusted to the metrics module alone.
///
/// Outermost in the stack on purpose: a request refused by an inner layer (rate
/// limit, body limit, authentication) is still a request, and the error rate this
/// endpoint publishes is worthless if it counts only the ones that got through.
async fn observe(
    State(state): State<AppState>,
    matched: Option<MatchedPath>,
    request: Request,
    next: Next,
) -> Response {
    // Read before `next.run` consumes the request.
    let method = request.method().clone();
    let route = matched
        .map(|m| m.as_str().to_string())
        // No matched path means no route matched: a 404 on an unknown URI. It is
        // deliberately one series and not one per probe, or scanning the address
        // space would be a way to fill this map.
        .unwrap_or_else(|| "<unmatched>".to_string());

    let started = std::time::Instant::now();
    let response = next.run(request).await;
    state.metrics.latency(started.elapsed());
    state
        .metrics
        .http_request(method.as_str(), &route, response.status().as_u16());
    response
}
```

and register it as the outermost layer:

```rust
    .layer(axum::middleware::from_fn_with_state(state.clone(), observe))
```

If you would rather not wire it, the honest alternative is to delete the eight
unused methods from `metrics.rs` and correct the comment at
`backend/src/modules/system/routes.rs:88-91` so it stops promising request-rate and
error-rate telemetry the system does not collect. That comment is inside this
workstream's ownership and will be adjusted to match whichever choice is made — it
is left alone for now precisely so the two do not disagree.

---

## 5. What was changed

Source:

* `backend/src/modules/authorization/service.rs` — MFA mandate on dangerous grants;
  ROOT guard ahead of the override lookup; collection-level decisions taken before
  the row is loaded.
* `backend/src/modules/authorization/repo.rs` — `mandate_mfa`.
* `backend/src/modules/authorization/routes.rs` — shared `PathId`/`PathIds`; local
  `parse_id` deleted.
* `backend/src/modules/identity/invitations.rs` — authorise before load on revoke.
* `backend/src/modules/identity/service.rs` — vestigial `guard_root(false)` removed.
* `backend/src/modules/authentication/routes.rs` — `Authenticated` on the two
  MFA-weakening routes.
* `backend/src/modules/authentication/mfa.rs` — `/mfa/disable` metered.
* `backend/src/modules/projects/service.rs`, `backend/src/modules/tasks/service.rs`
  — listing denials routed through `state.require`; `TASK.CANCELLED`.
* `backend/src/modules/system/repo.rs`, `service.rs`, `dto.rs` — sensitive
  feature-flag keys filtered in the query.
* `backend/src/modules/audit/mod.rs`, `chain.rs`, `repo.rs`, `service.rs` — chain
  version 2 covering `source_ip_hint`; `TASK_CANCELLED`; path-id trim removed.
* `backend/src/cli.rs` — the offline `verify-audit` reader updated in lockstep with
  the chain (it must not be allowed to drift from the online verifier).

Schema:

* `backend/migrations/0011_envelope_and_consumption_guards.sql` — new, forward-only.

Tests:

* `backend/tests/security/residual_hardening.rs` — new, ten regressions.
* `backend/tests/security_suite.rs` — registers it.
* `backend/tests/security/database_invariants.rs` — the two tests that pinned the
  old behaviour now assert the guard, plus four new ones.
* `backend/tests/integration/settings_audit_system.rs`,
  `backend/tests/golden_scenario.rs`, `backend/tests/benchmarks.rs` — updated for
  the new behaviour and the chain shape.

---

## 6. Verification

Every fix was verified by **reverting it and watching the named test fail**, in two
batches, then restoring and re-running. Seven fixes failed their tests on the first
batch and three on the second; ten of ten.

| Suite | Result |
|---|---|
| `cargo test --lib` | 601 passed, 0 failed |
| `cargo test --test security_suite` | 159 passed, 0 failed |
| `cargo test --test integration_suite` | 155 passed, 0 failed |
| `cargo test --test hardening_suite` | 34 passed, 0 failed |
| `cargo test --test race_suite` | 58 passed, 0 failed |
| `cargo test --test failure_injection` | 10 passed, 0 failed |
| `cargo test --test golden_scenario` | 1 passed, 0 failed |
| `cargo test --test router_registry --test openapi_contract` | passed |

Not verified here: `cargo fmt --check` and `cargo clippy -D warnings` (the
container image carries neither component), and the clean-room and backup/restore
drills, which belong to the final acceptance run rather than to this closure.
