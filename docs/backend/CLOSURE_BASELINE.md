# Closure baseline — verified state before any closure change

Recorded at the start of the backend closure phase. Everything here was produced by
running a command against the tree, not copied from a previous report. Where an
earlier report disagrees with the code, the code wins and the disagreement is noted.

## Audited point

| | |
|---|---|
| Branch | `audit/final-acceptance` |
| Commit | `2363a9ebbf0667870a83fea177ba133be5fc6b92` |
| Working tree | **clean** (`git status --short` empty) |
| Migration head | `0010_grant_permission_catalogue.sql` |
| CI | `.github/workflows/backend-ci.yml` |
| `main` | untouched, 3 commits behind; nothing pushed |

Commit history:

```
2363a9e Final acceptance audit: seven HIGH defects found and fixed
5d6d6de Path<Uuid> rejections bypassed the error contract in seven modules
9c76338 Adversarial round: eight real defects found and fixed
5532939 RoleBlank OS backend foundation
```

## Carried-forward numbers — treated as claims, not facts

The previous acceptance report states 1 009 tests passing, 0 failures, 93.66% line
coverage, all four gates green, clean-room green, backup/restore green. These are
**context only** at this point. They are re-derived from scratch in
`BACKEND_CLOSURE_REPORT.md`; nothing in this closure relies on them.

## Open findings inherited

| Severity | Count | Status entering closure |
|---|---|---|
| CRITICAL | 0 | — |
| HIGH | 0 | 7 found and fixed in the previous phase |
| MEDIUM | **1** | the general rate limiter — **reproduced, see below** |
| LOW | 6 | to be triaged to zero actionable |
| INFO | 13 | to be classified |

## The MEDIUM, reproduced against this exact commit

Confirmed at source: `middleware::apply` installs security headers, CORS, a method
guard, a body limit, a timeout, request-id and panic capture — **and no rate-limit
layer**. `keys::general_principal` and `keys::general_ip` exist and are referenced
from exactly one place in the whole crate: a key-collision unit test.

Confirmed by execution against a live instance running this build, 60 requests per
principal, each to an endpoint that principal may not use
(`scripts/repro_rate_limit.sh`):

| Principal | Endpoint | Status codes | `429`s | Audit rows written |
|---|---|---|---|---|
| employee | `POST /projects/{id}/clients` | `403` | **0** | **60** |
| client A | `GET /users` | `404` | **0** | 0 |
| client A | `GET /audit/events` | `404` | **0** | 0 |
| administrator | `GET /projects` | `403` | **0** | 0 |
| ROOT | `GET /projects` | `200` | **0** | 0 |

Two things this pins down more precisely than the previous report did:

1. **No general limiter exists for any authenticated principal**, including ROOT.
2. **The amplifier is specifically the committed-denial paths.** A refusal that is
   masked to `404` writes nothing; a refusal that deliberately commits an
   `AUTHORIZATION.DENIED` row writes one row per request, on a table with no delete
   path for the runtime role, taking the global audit-chain lock each time. Growth
   is exactly 1:1 with attacker request volume.

Authorisation itself is correct in every case — the defect is that being refused
costs the system more than it costs the attacker.

## Inconsistencies found between reports and code

| Claim | Reality |
|---|---|
| `FINAL_ACCEPTANCE_REPORT.md` §7 rates this MEDIUM partly because "the attack is self-evidencing" | True, but the reproduction shows the `404`-masked refusals write **no** audit row at all, so an attacker who prefers stealth simply picks those endpoints and is equally unlimited while leaving no evidence. The rate-limit gap is therefore broader than the audit-growth gap, and the two must be fixed separately. |
| `RateLimitConfig` documented as operator-tunable | Constructed with `::default()`; reads no environment variables. None of the eight enforced limits is tunable. |

## Test inventory entering closure

Not re-run at baseline (a run was in progress by another workstream when this was
written); re-derived in full for the closure report. The suite files present are:
`integration_suite`, `security_suite`, `race_suite`, `hardening_suite`,
`failure_injection`, `openapi_contract`, `router_registry`, `golden_scenario`,
`benchmarks`, plus the crate's unit tests.

## Unresolved risks carried into closure

1. The general rate limiter (above) — the single open MEDIUM.
2. Six LOW findings not yet triaged to a verdict.
3. Thirteen INFO findings not yet classified.
4. `RateLimitConfig` is not environment-tunable.
5. No cross-instance rate-limit enforcement exists, and none is claimed.
