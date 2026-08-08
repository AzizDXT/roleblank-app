# Backend freeze manifest

The frozen contract a frontend may be built against. Every number here was produced
by a command run against this tree, not carried forward from an earlier report.

## Freeze point

Every verification in this manifest was run against the tree contained in commit
`1165eb6`. This document and the closure report are committed immediately after it,
because a manifest cannot contain its own hash; nothing executable differs between
the two commits.

| | |
|---|---|
| Branch | `audit/final-acceptance` |
| Freeze commit | **`1165eb6`** — "Backend closure: rate limiting, mail transport, and every LOW closed" |
| Backend version | `0.1.0-foundation` |
| Migration head | `0011_envelope_and_consumption_guards.sql` (11 migrations) |
| Working tree at freeze | clean |

## Contract artifacts

| Artifact | Value |
|---|---|
| `api/openapi.json` | sha256 `2977aa7b63ee1270…` — 74 paths, **95 operations** |
| `api/openapi.yaml` | sha256 `4619263ad194a417…` — **95 operations** |
| Permission catalogue | **42** permissions, sha256 `461b44aa331d7f7a…` (codes only, order-independent) |
| Route table | **95** routes |
| `ROUTE_SECURITY_MATRIX.md` | regenerated at closure; 95 routes, 14 columns |
| `FRONTEND_ACTION_CATALOG.md` | 92 actions (95 routes less 3 health probes) |

The two OpenAPI artifacts are held in agreement by a test
(`the_json_artifact_and_the_yaml_source_agree`), because only the YAML was
previously checked against the route table while the JSON is what a frontend
generates from — two documents meant to be identical and validated differently
eventually disagree.

## Verification at freeze

| Gate | Result |
|---|---|
| `cargo test --all-targets` | **1 046 passed, 0 failed**, 4 ignored (benchmarks, run separately) |
| `cargo fmt --all --check` | PASS |
| `cargo clippy --all-targets --all-features -D warnings` | PASS |
| `cargo audit` | PASS — 263 crate dependencies, 0 vulnerabilities |
| `cargo deny check` | PASS — advisories, bans, licenses, sources |
| Coverage | **91.16% region / 92.95% function / 93.34% line** |
| Clean-room phases 1 / 2 / 3 | 0 failures each (fresh database, fresh secrets, runtime role) |
| Backup → destroy → restore | byte-identical state, chain intact, 0 `pg_restore` warnings |
| Production config refusal | 9 of 9 unsafe configurations refused at startup |
| Exploit reproducers | both blocked |
| Two suites concurrently | 314 tests, 0 failures, no template destruction |

## Findings at freeze

| Severity | Open |
|---|---|
| CRITICAL | **0** |
| HIGH | **0** |
| MEDIUM | **0** |
| LOW | **0 actionable** (all fixed with regression tests, or accepted with reasons in `audit/LOW_INFO_DISPOSITION.md`) |
| INFO | 4 classified and accepted; 3 were reversed and fixed |

## Known limitations

Stated plainly. None of these blocks the frontend contract; all of them would
mislead someone who assumed otherwise.

1. **Rate limiting is per process.** There is no cross-instance enforcement and none
   is claimed. Running more than one API instance requires a distributed
   implementation of the `RateLimiter` trait first (release gate RR-3).
2. **Mail delivery is at-least-once.** The outbox claims, sends, then marks sent; a
   crash in that window re-delivers. Handlers must be safe to run twice.
3. **SMTP is selectable and configured-checked, but has never delivered to a real
   server.** The transport, both TLS modes, the required-field refusals and the
   port-25 refusal are tested, and `RB_MAIL_PROVIDER=smtp` is verified to be
   accepted by a live process. Actual delivery to a mail provider is untested here
   because no production credentials exist in this environment.

   An earlier revision of this manifest said SMTP was "implemented but never
   exercised". That was too generous: `Config::from_env` had no `smtp` arm at all,
   so the transport could not be selected by any configuration, and the validator's
   own remediation text told operators to set a value that refused startup. Found
   by the final adversarial sweep, fixed, and recorded here rather than quietly
   corrected.
4. **Test databases leak.** The harness `Drop` spawns a detached cleanup thread that
   dies with the process. Bounded per run, cleaned by `rb.ps1 db-reset`.
5. **Real clock passage is simulated.** Expiry is tested by writing past timestamps;
   a defect in how "now" is obtained would not be caught.
6. **In-process transport for most tests.** TLS, HTTP/2 framing and proxy header
   smuggling are not reachable by the suites that drive the router directly. The
   clean-room and log-injection work do use real sockets.
7. **A PostgreSQL superuser is outside the model.** Every ROOT and audit invariant is
   enforced against the runtime role and the schema owner, not against a superuser.

## Out of scope, deliberately not built

Chat, messaging, channels, realtime/WebSocket, calendar, finance, CRM, HSE, AI/MCP,
file uploads, search platform, billing, and multi-tenant SaaS support. Where a
future boundary mattered it is documented (`10-future-ai-mcp-security.md`,
`11-future-realtime.md`, `12-future-storage.md`); none of it is coded.

## Frontend implementation rules

> **The frontend may consume this contract but may not infer additional privileges
> or routes.**

Concretely:

* **Only the 95 documented routes exist.** A route not in the matrix is not a route.
* **Capabilities from `/auth/me` are for visibility only.** Hide what a user cannot
  do; never assume a hidden action is therefore forbidden, and never assume a shown
  action will succeed. The backend re-derives every decision on every request.
* **Error codes are the contract, not HTTP status alone.** Branch on the stable
  `code` in the problem+json body (`FRONTEND_ERROR_CONTRACT.md`).
* **`404` may mean "forbidden".** For external principals the backend deliberately
  masks refusals as not-found. Do not build UI that distinguishes them.
* **Concurrency is explicit.** Send the `version` you loaded; handle the conflict
  code rather than retrying blindly (`CONCURRENCY_CONTRACT.md`).
* **Retries need `Idempotency-Key`** on the endpoints that accept it
  (`IDEMPOTENCY_CONTRACT.md`).
* **`429` is normal, not an error state.** Honour `Retry-After`.
* **Never display a control whose action is not in `FRONTEND_ACTION_CATALOG.md`** —
  that catalogue is the list of things a button can truthfully do.

Any change to the route table, the permission catalogue, or the error codes breaks
this freeze and must be re-issued as a new manifest.
