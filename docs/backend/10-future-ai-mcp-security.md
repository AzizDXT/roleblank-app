# 10 — Future AI / MCP Security Contract

**Status: nothing in this document is built.** There is no AI surface, no MCP server, no
model client, and no outbound HTTP call anywhere in the crate today (`02-threat-model.md`
§5 records the absence of egress as a decision). This document is the contract that any
future AI or MCP integration must satisfy *before* it ships. It is binding: a design that
contradicts anything here is rejected, not negotiated.

Adversary **T9** in `02-threat-model.md` — "future AI/MCP agent, runs inside the system, may
be prompt-injected" — is the adversary this document defends against. Control **TH-45** is
this file.

## 1. The contract in one sentence

**An AI agent is a principal, not a component.** It authenticates, it holds a role, it is
authorised per action by the evaluator in `04-authorization.md` §5, it is audited, and it
is bounded — exactly like a person, with strictly less authority than the person who
invoked it.

Everything below follows from refusing the alternative: an agent that is "part of the
backend" and therefore reaches the database, the repositories, or a privileged bypass.

## 2. What the agent never gets, and the failure each refusal prevents

| Never | Concrete failure it prevents |
| --- | --- |
| Database credentials / a connection string | A prompt-injected agent with a pool handle is a `DELETE FROM audit_events` away from erasing A5. The runtime role is already restricted (`SELECT, INSERT` on `audit_events`, no `DELETE` on `users`), but handing an attacker-steerable component *any* SQL surface makes the database triggers the only remaining boundary — the exact single-layer failure `02-threat-model.md` §2 forbids |
| Direct SQL, a query-building tool, or a "run this read-only query" escape hatch | A read-only query tool still crosses the CLIENT→INTERNAL envelope, because the visibility predicate of `04-authorization.md` §9 lives in the repository layer, not in the database. "Read-only" is not "in scope" |
| Repository (`modules/*/repo.rs`) access | Repositories are `pub(super)`/private by design (`01-architecture.md` §3). They carry no authorisation of their own; the service layer is where authorisation happens. Reaching a repository skips layers 1–3 entirely |
| ROOT ownership, or any path to it | ROOT is the one bypass in the evaluator (`04-authorization.md` §7, ADR-004). An agent that can be talked into using it is an unauthenticated escalation with a language interface |
| Any `is_dangerous` permission | Those permissions require MFA enrolment and recent step-up (`03-authentication.md` §8). An agent session has no second factor to present, so granting one produces either a permanently failing agent or pressure to weaken step-up. Neither is acceptable |
| The delegation surface (`iam.permissions.delegate`, `iam.roles.assign`) | An agent that can grant permissions can grant itself out of every other control in this document |
| Its own bespoke authorisation logic, cache, or "trusted internal" flag | Two evaluators means two sets of bugs and one of them is unreviewed. There is exactly one evaluator |

## 3. The agent as a principal

A configured AI agent is a real row in `users`, not a synthetic identity assembled at
request time.

| Field | Value | Why |
| --- | --- | --- |
| `principal_type` | `INTERNAL` | The envelope has two values (`05-data-model.md` §2). An agent acting inside the company is internal; it must never be `CLIENT`, because CLIENT is the external-firm boundary and reusing it would give an agent client-portal semantics |
| `status` | `ACTIVE` / `SUSPENDED` | Suspending the row kills the agent's sessions on their next request, via the existing user-status join in the session lookup (`03-authentication.md` §3). This is the fastest available stop button and it needs no new machinery |
| roles | one dedicated, non-`is_system` role per agent | Least privilege is per-agent, not per-"AI". A summarisation agent and a task-triage agent do not share a role |
| `mfa_required` | `false` | A machine has no authenticator app. This is *only* survivable because the agent's role contains no `is_dangerous` permission — see §7 rule 4 |
| `is_root` (via `system_ownership`) | never | Enforced already: the table has no API surface and rejects `UPDATE`/`DELETE` unconditionally |

**Sessions.** The agent must not log in with a password through `/auth/login`. It needs a
distinct machine-credential flow — a registered credential exchanged for an ordinary opaque
`rb_at_` session token — which **has not been designed yet**. Two properties are fixed in
advance regardless of how it is designed:

1. It issues an *ordinary* session row. No new token type, no bearer format exempt from the
   per-request lookup of `03-authentication.md` §1. Revocation must work identically.
2. `mfa_verified_at` stays `NULL`, so every step-up operation returns `STEP_UP_REQUIRED`
   for an agent automatically. This is a useful accident of the existing design and should
   be preserved deliberately rather than relied on silently.

## 4. The call path

```
  human ──"summarise project X, close its stale tasks"──▶ agent runtime
                                        tool call (allowlisted, typed args) │
                                                                            ▼
      ┌───────────────────────────────────────────────────────────────────────┐
      │ roleblank-api — the SAME axum route, application service, evaluator,   │
      │ audit writer and rate limiter a human request passes through           │
      └───────────────────────────────────────────────────────────────────────┘
                          Authorization: Bearer rb_at_… (the agent's own session)
```

There is no second entry point. An MCP server, if one is built, is a **client of the HTTP
API** — a separate process holding the agent's session token, translating tool calls into
the same requests a Flutter app would make. It is not a module inside the binary with
in-process access to `AppState`, because that would place a language-steered component
inside the trust boundary the layering of `01-architecture.md` §2 exists to maintain.

A consequence worth stating: if a capability is not exposed as an HTTP endpoint with a
declared permission, the agent cannot have it.

## 5. Attribution: every mutation names two parties

The audit schema (`05-data-model.md` §8) already carries what is needed; no new columns.

| Audit field | Value for an AI-initiated action |
| --- | --- |
| `actor_user_id` | the **agent's** user id — the principal whose authority was actually exercised |
| `actor_principal_type` | `INTERNAL` |
| `actor_session_id` | the agent's session |
| `metadata.on_behalf_of` | the user id of the human who invoked the agent |
| `metadata.agent` | the agent's stable identifier and configuration version |
| `metadata.invocation_id` | correlates every action produced by one human request |

`actor_user_id` is the agent and not the human on purpose. The authority exercised was the
agent's role; recording the human there would claim a capability check that never happened
and would make the audit log lie about which grant permitted the write. The human is
recorded as *causation*, in `metadata`, where it is queryable but not confused with
authority.

The inverse mistake is equally bad: attributing to the agent alone loses the ability to
answer "what did this agent do because of that person's request", the first question anyone
asks after an incident. `metadata` remains subject to the sanitising writer — prompts, model outputs, and tool
arguments may contain secrets or user-supplied content and must be truncated and stripped
like any other user-controlled logged value (`02-threat-model.md` TH-32, TH-35). Full
prompt text does not belong in `audit_events`.

## 6. Prompt injection is a confused-deputy problem

An agent reads a task description, a project note, or a client-supplied comment; that text
contains instructions; the model cannot reliably distinguish "data I was asked to summarise"
from "instructions I was given". Any content the agent reads is therefore **untrusted input
that can steer the agent's tool calls**.

The correct framing: the agent is a deputy holding authority on someone's behalf, and an
attacker who can write text into the system can influence what the deputy asks for. This is
structurally identical to CSRF or to a SSRF-capable fetcher — the request is *authentic*,
and the question is only whether it is *authorised*.

**Therefore the security boundary is the agent's permission set, not the agent's
instructions.** The design assumption is that an attacker can make the agent attempt any
tool call in its allowlist with any arguments. The system is acceptable only if that
assumption produces bounded damage.

### Why "the system prompt tells it not to" is not a control

- It has no enforcement point. Nothing in the request path can verify that an instruction was
  followed; there is no code that could return `403` because the model misbehaved.
- It is not testable in the sense this codebase uses the word. `deny_beats_allow` is a
  property test over all inputs; "the model usually complies" is a measurement of a
  distribution that degrades silently when the model, the prompt, or the input changes.
- It fails open. Every other control here fails closed: unknown permission → deny, empty
  grants → deny, invisible row → never selected. An ignored instruction produces an *action*,
  not a refusal.

Instruction-level guardrails and injection classifiers may be added as defence in depth. They
are never counted as the reason an action is safe.

### What the actual controls are

1. **Per-agent least privilege.** The blast radius of a fully injected agent is exactly its
   role — nothing more. This is the only control that holds when the model is completely
   compromised, which is why it is first.
2. **Tool-level allowlists.** Each agent is configured with an explicit list of tools
   (endpoints + methods). A tool absent from the list cannot be invoked even if a permission
   would have allowed it. The permission set and the tool list are two independent
   restrictions, and an action needs both. The allowlist is server-side configuration, not
   something the agent runtime can extend at request time.
3. **The evaluator, unchanged.** Object-level checks, the client envelope, explicit DENY
   overrides, and the scope lattice all apply to the agent principal with no special case.
   An agent scoped `ASSIGNED` sees what a person scoped `ASSIGNED` sees.
4. **Approval gates for a configured operation set.** Destructive actions, anything crossing
   the client boundary, and anything bulk should require a human to confirm before the
   mutation commits. This is layered *on top of* authorisation, never a substitute for it —
   an approval prompt clicked through reflexively is a weaker control than a denial.
5. **Bounds** (§8), so that "allowed but repeated ten thousand times" is also a refusal.

## 7. Rules that must never be relaxed

1. **No database credentials, no SQL, no repository access, for any agent, ever** — including
   "read-only", including "just for analytics", including during development against a
   production-shaped database.
2. **No agent holds ROOT ownership, and no code path lets an agent act as ROOT.** The
   `RootOwnership` bypass in the evaluator is reachable by exactly one user id.
3. **Every agent action goes through the application service layer and the same evaluator.**
   No in-process shortcut, no `AppState` handle in an MCP module, no "trusted internal
   caller" flag.
4. **An agent's role contains no permission with `is_dangerous = true`**, and no permission
   in `iam.roles.*` / `iam.permissions.*`. An agent must not be able to change authority —
   its own or anyone's.
5. **Every AI-initiated mutation is audited with `actor_user_id` = the agent and
   `metadata.on_behalf_of` = the invoking human.** An unattributable agent action is a
   defect, not a logging gap.
6. **The agent's effective authority never exceeds the invoking human's.** If a person cannot
   perform an action themselves, asking an agent to do it must not succeed. This requires an
   explicit intersection check at invocation — the agent's grants ∩ the human's grants —
   because the agent's own role is otherwise independent of who invoked it.
7. **No agent-only endpoints, no agent-only bypasses of input limits, idempotency, or rate
   limiting.**
8. **Prompt-level instructions are never counted as a control** in any design review, threat
   model row, or test.

## 8. Bounds, cost, and the kill switch

An agent differs from a person in one operationally important way: it can issue thousands of
authorised requests per minute, and authorisation says yes to each one. Volume is therefore
its own control surface.

| Bound | Enforcement | What it prevents |
| --- | --- | --- |
| Requests per agent principal | The existing `trait RateLimiter` (`01-architecture.md` §4), keyed on the principal, not only the IP — an agent runtime is one IP | A looping or injected agent saturating the pool and denying service to people (asset A8) |
| Mutations per invocation | A per-`invocation_id` counter in the agent runtime *and* a server-side ceiling | "Close every task in every project" executed literally, one authorised request at a time |
| Model/token spend per agent and per tenant | Agent runtime, with a hard stop | Cost exhaustion as a denial-of-service, and the incentive to raise limits during an incident |
| Wall-clock / step ceiling per invocation | Agent runtime | Unbounded reasoning loops |
| Body and array limits | Already global (256 KB, `page_size ≤ 100`) | Nothing agent-specific needed; the limits are not relaxed for agents |
| `Idempotency-Key` on agent mutations | Existing middleware | Retry storms from a runtime that treats a timeout as "try again" |

### The kill switch

Feature flag **`ai.assistant`**, stored in `feature_flags` (`05-data-model.md` §7), default
`enabled = false`, `is_security_sensitive = true` — so changing it is on the step-up list
and is audited (`03-authentication.md` §8). Flipping it off must stop new agent invocations
immediately and revoke live agent sessions.

**A feature flag is not an access control.** It is a single boolean read from a table an
administrator can edit; it has no notion of principal, resource, or scope; and a flag check
missed on one route is a silent hole with no second layer behind it. Authorisation must deny
an agent's request *independently of the flag's value*, so that:

- an operator enabling the flag prematurely does not grant authority, only reachability;
- a bug that reads the flag as `true` (a caching mistake, a default in a test harness, a
  misparsed config) exposes endpoints that still refuse the agent's principal;
- turning the flag off is a fast, coarse stop — not the thing standing between an injected
  agent and the audit table.

The flag is what allows the surface to be built and tested behind it; §7 is what makes the
surface safe when it is on.

## 9. Egress, still closed

An MCP client or model call is the first outbound HTTP request this backend would ever make,
which retires the "SSRF: not applicable" row in `02-threat-model.md` §5. The hardened egress
layer of `06-security-controls.md` §Egress is a prerequisite: an allowlist of destination
hosts, no user- or model-controlled URLs, DNS rebinding protection, explicit timeouts, and a
bounded response size. A model endpoint URL is configuration, never input.

## 10. What is deliberately left undesigned

Recorded so their absence is visible rather than assumed: the machine-credential flow and
its rotation story (§3); the tool-manifest format and where it is stored; the approval
queue's data model and expiry semantics; whether agent sessions get a shorter absolute
lifetime than the 30-day human ceiling (they probably should); and how the agent-∩-human
authority intersection of rule 6 is computed given that the evaluator is uncached
(`04-authorization.md` §11). Each is a design task with its own review; none may be resolved
by weakening §7.
