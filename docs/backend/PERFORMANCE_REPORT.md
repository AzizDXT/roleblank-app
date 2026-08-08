# Performance Report

**Date of measurement:** 2026-08-07
**Method:** release build, real HTTP load against a real PostgreSQL.
**Every number below was produced by an executed run.** Nothing is estimated,
extrapolated, or carried forward from an earlier report. Where a measurement was
not taken, or was taken under a caveat, that is stated rather than filled in.

This report replaces an earlier version whose numbers came from in-process
micro-benchmarks (`tests/benchmarks.rs`). Those measured cryptographic primitives
in isolation; they did not measure the server. This one drives the actual API over
the network.

---

## 1. Environment

| Item | Value |
| --- | --- |
| Host | Windows 11 Home 10.0.26200 |
| Host CPU | Intel Core Ultra 9 290HX Plus — 24 physical / 24 logical cores |
| Host RAM | 63.37 GB |
| Cores visible to the containers | 24 |
| RAM visible to the containers | 31.03 GB (Docker Desktop VM allocation) |
| Toolchain | `rustc 1.97.1 (8bab26f4f 2026-07-14)`, `cargo 1.97.1` |
| Build profile | **release** (`opt-level = 3`, `lto = "thin"`, `codegen-units = 1`, `strip = "symbols"`) |
| Binary | `target/release/roleblank-api`, 9 435 152 bytes |
| Database | `postgres:18.4-alpine`, data checksums enabled, `max_connections=400`, `shared_buffers=256MB` |
| Load generator | **`oha` 1.15.0** (`ghcr.io/hatoo/oha:latest`), in containers on the same Docker network |
| Network path | container → container over the `roleblank_net` bridge (no host loopback hop, no TLS) |

Everything runs containerised because the Windows host enforces an Application
Control policy that refuses to execute freshly compiled unsigned binaries
(`os error 4551`). See `00-reconnaissance.md` §3.

### Application configuration as measured

Defaults were used throughout. **Nothing was tuned to improve a number.**

| Setting | Value | Where it comes from |
| --- | --- | --- |
| `RB_DB_MAX_CONNECTIONS` | 32 | default `(cpu_count * 2).clamp(5, 32)` |
| `RB_DB_MIN_CONNECTIONS` | 1 | default |
| `RB_AUTH_HASHING_MAX_CONCURRENCY` | 8 | default `cpu_count.min(8)` |
| Argon2id | m=19 456 KiB, t=2, p=1 | default |
| `RB_ENV` | `development` | required to run without TLS / secret manager |
| Session TTLs, body limits, page sizes | defaults | — |

### Data volume under test

A dedicated database (`roleblank_perf`) on the same PostgreSQL server, migrated by
the real `migrate` command and populated **through the public HTTP API only** — no
direct SQL writes, so every row is one the application itself would produce.

| Table | Rows |
| --- | --- |
| `users` | 1 (the ROOT owner) |
| `departments` | 1 |
| `client_accounts` | 1 |
| `projects` | 40 |
| `tasks` | 400 |
| `audit_events` | 760 |

This is a **small** dataset. The collection reads below return the first page of 25
from 40 projects and 400 tasks. Numbers here therefore characterise the request
path — authentication, authorisation, serialisation — and not index behaviour at
scale. A missing index on a million-row table would not show up here, and this
report does not claim otherwise.

---

## 2. How the scenarios are split, and why

Two populations are measured and reported **separately, never blended**:

- **Normal API traffic** — reads whose cost is dominated by the database and the
  per-request authentication path.
- **Authentication (`POST /auth/login`)** — dominated by Argon2id, which is
  memory-hard *by design* and intentionally three to four orders of magnitude more
  expensive than anything else here.

Mixing even a small share of logins into the general run would drag the aggregate
p95/p99 toward the Argon2id cost and tell the truth about neither population.

A second split matters just as much and is the main finding of this report:
**single-session load and multi-session load are not the same measurement.** Every
authenticated request writes to its own `sessions` row, so driving load through one
bearer token measures row-lock contention on one tuple, not the API. Both are
reported.

---

## 3. Normal API — results

### 3.1 Unauthenticated baseline (single generator, c=50, 30 s)

| Endpoint | Conc. | Requests | p50 | p95 | p99 | req/s | Errors |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `GET /health/live` | 50 | 7 277 296 | **0.17 ms** | 0.45 ms | 0.69 ms | **242 524** | 0.00 % |
| `GET /health/ready` | 50 | 796 416 | **1.51 ms** | 3.93 ms | 7.94 ms | **26 543** | 0.00 % |

`/health/live` touches neither the database nor authentication: it is the floor,
and it establishes that neither the HTTP stack nor the Tokio runtime is a
constraint at any load this system will see. `/health/ready` adds one pool checkout
and one trivial round trip; the ~26 500/s it sustains is the baseline database tax,
and it is *twenty times* what any authenticated endpoint achieves. That gap is the
subject of §5.

### 3.2 Authenticated, **one** bearer token (single generator, c=50, 30 s)

| Endpoint | Conc. | Requests | p50 | p95 | p99 | req/s | Errors |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `GET /api/v1/auth/me` | 50 | 35 756 | 32.37 ms | 101.07 ms | 153.95 ms | 1 193 | 0.00 % |
| `GET /api/v1/projects?limit=25` | 50 | 35 396 | 32.22 ms | 101.92 ms | 170.38 ms | 1 181 | 0.00 % |
| `GET /api/v1/tasks?limit=25` | 50 | 38 251 | 31.06 ms | 90.31 ms | 134.56 ms | 1 277 | 0.00 % |
| `GET /api/v1/users/{id}/permissions` | 50 | 39 789 | 29.92 ms | 86.30 ms | 126.26 ms | 1 328 | 0.00 % |

`GET /api/v1/users/{id}/permissions` is the authorisation-heavy endpoint: it loads
the target user's role-derived grants and per-user overrides and evaluates the
entire 47-entry permission catalogue against them.

**The result that matters is the flatness of that column.** Four endpoints with
very different work — a 2.6 KiB identity read, a 12.3 KiB project page, a 10.4 KiB
task page, and a full authorisation evaluation — all land within 12 % of each
other. When endpoints with different work cost the same, the cost is not in the
endpoints. It is in what they share.

### 3.3 Concurrency sweep, `GET /auth/me`, one token (10 s each)

| Concurrency | p50 | p95 | p99 | req/s |
| ---: | ---: | ---: | ---: | ---: |
| 1 | **1.88 ms** | 4.57 ms | 11.88 ms | 420 |
| 4 | 3.56 ms | 19.93 ms | 43.35 ms | 632 |
| 16 | 8.26 ms | 26.86 ms | 39.26 ms | **1 497** |
| 50 | 28.30 ms | 85.13 ms | 123.95 ms | 1 379 |
| 100 | 65.69 ms | 168.55 ms | 350.03 ms | 1 201 |

A single authenticated request costs **1.88 ms**. Throughput peaks near c=16 and
then *falls* as concurrency rises while latency grows super-linearly. That shape —
throughput decreasing under added load — is contention, not saturation.

### 3.4 Authenticated, **eight distinct sessions** (8 generators × c=6 = 48 concurrent, 30 s)

Same user, same permissions, same data; the only change is that the load is spread
over eight `sessions` rows instead of one.

| Endpoint | Conc. | Requests | p50 (range) | p95 (range) | p99 (range) | req/s | Errors |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `GET /api/v1/auth/me` | 48 | 102 148 | **8.84–9.11 ms** | 39.05–40.43 ms | 68.55–71.10 ms | **3 406** | 0.00 % |
| `GET /api/v1/projects?limit=25` | 48 | 37 843 | 11.72–12.21 ms | 49.43–57.37 ms | 95.97–111.90 ms | 1 263 | 0.00 % |
| `GET /api/v1/tasks?limit=25` | 48 | 38 901 | 10.23–10.38 ms | 23.14–23.95 ms | 41.06–42.98 ms | 1 298 | 0.00 % |
| `GET /api/v1/users/{id}/permissions` | 48 | 38 106 | 14.21–14.51 ms | 23.87–25.96 ms | 33.29–42.35 ms | 1 272 | 0.00 % |

**Derivation, stated because it affects how these should be read.** `oha` cannot
rotate a header per request, so eight generator containers were run in parallel,
one bearer token each. Throughput is the **sum** of the eight reported rates; the
percentile columns give the **range across the eight generators**, not a merged
distribution. The generators agreed closely (see the narrow ranges), so the range
is a fair summary — but it is a range of eight separate measurements, not a single
population percentile, and it is not presented as one.

Spreading `/auth/me` over eight sessions raised throughput **2.5×** (1 379 → 3 406
req/s) and cut p50 **3.2×** (28.3 → ~9.0 ms) at the same concurrency. Nothing else
changed. The collection reads improved in latency but not in throughput, because
they hit a second limit described below.

---

## 4. Authentication — measured separately

`POST /api/v1/auth/login` is both intentionally expensive (Argon2id) and
intentionally rate limited (10 per IP per minute; 5 per account per minute, reset
on success). **A throughput number for this endpoint would be meaningless** — it
would measure the rate limiter. Latency is the honest measurement, and the sampler
paces itself to stay inside the quota so that no 429 is ever counted as a login.

Measured with a purpose-written sampler (stdlib Python, one request in flight per
source IP) rather than `oha`, because `oha` cannot pace to a per-IP quota and
because 429 responses — which return in ~150 µs — must be excluded from the latency
population rather than silently averaged into it.

| Scenario | Concurrency | Requests | p50 | p95 | p99 | min | max | Errors |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `POST /api/v1/auth/login` | 6 (6 source IPs × 1) | 120 | **27.97 ms** | 52.25 ms | 65.01 ms | 23.29 ms | 103.24 ms | **0.00 %** |

Pacing: 20 logins per source IP, 6.5 s apart (9.2/min/IP, under the 10/min quota),
across 6 container IPs — 120 requests, all `200`, no 429 and no other status.
Mean 32.27 ms, standard deviation 10.95 ms.

A cross-check with `oha` at c=1 (sequential, 8 successful logins) gave p50 32.76 ms
with a 44.15 ms maximum, consistent with the above.

**Reading this.** ~28 ms at p50 for a full login — Argon2id verification at
m=19 456 KiB / t=2 / p=1, plus session creation, plus an audit append — is the
right side of the trade-off. It is expensive enough to be meaningful against
offline cracking and cheap enough that a human does not perceive it. The p99 of
65 ms reflects contention for the 8-permit hashing semaphore at concurrency 6,
which is the semaphore doing its job.

**What was deliberately not done:** login was not driven at high concurrency. Doing
so measures the queue in front of the hasher and then the rate limiter, and reports
429 latency as if it were login performance. An earlier attempt at c=8 without
pacing produced 46 `429`s out of 64 requests and percentiles in the hundreds of
microseconds — a textbook example of the misleading result this pacing exists to
avoid. It is not reported as a login measurement.

Worst-case resident memory devoted to hashing remains permits × m_cost =
8 × 19 MiB ≈ **152 MiB**; size containers accordingly (`08-operations.md` §10).
**No change to the Argon2id cost factor is warranted by these numbers.**

---

## 5. The bottleneck, identified

**Every authenticated request performs a write.** `authentication::principal`
issues, after the session lookup and before any endpoint work:

```sql
UPDATE sessions SET last_activity_at = now() WHERE id = $1 AND revoked_at IS NULL
```

It runs outside any transaction, so it is its own auto-commit transaction and its
own WAL flush. This was not inferred from the code; it was **observed in
`pg_stat_activity` while load was running**.

Sampled during `GET /auth/me` at c=50 with **one** session:

| wait_event_type | wait_event | state | backends |
| --- | --- | --- | ---: |
| LWLock | LockManager | active | 14 |
| Lock | tuple | active | 10 |
| Lock | transactionid | active | 4 |
| — | (on CPU) | active | 3 |

…with **30 of 32 pool connections executing that single `UPDATE` statement.**

Sampled again during `GET /api/v1/projects` at c=48 with **eight** sessions:

| wait_event_type | wait_event | state | backends |
| --- | --- | --- | ---: |
| Lock | transactionid | active | 10 |
| Lock | tuple | active | 9 |
| LWLock | WALWrite | active | 5 |
| Lock | extend | active | 1 |
| IO | WalSync | active | 1 |

…with **32 of 32 pool connections on the same `UPDATE`.** Spreading over eight
sessions removed most of the *tuple* contention (which is why `/auth/me` went 2.5×
faster) and exposed the layer underneath: **WAL write and fsync**. That is why the
collection reads did not gain throughput — they were never limited by the tuple
lock alone.

Container CPU during that sample: API **84 %** of one core-equivalent, PostgreSQL
**175 %**. Neither is near the 24 cores available. The API process held steady at
**~126 MiB** RSS and PostgreSQL at **~980 MiB**. **This system is not CPU-bound and
not memory-bound at these rates; it is bound on WAL durability for a bookkeeping
write.**

### Is it worth fixing?

The write exists for a real reason: `last_activity_at` is what makes the idle
session TTL work, and idle timeout is a security control (ADR-005). It cannot
simply be deleted.

But the *frequency* is not load-bearing. The idle TTL default is **seven days**
(`RB_SESSION_IDLE_TTL_SECONDS=604800`). Writing the timestamp on every single
request buys precision that no policy consumes. Updating it at most once per N
seconds per session — a conditional `AND last_activity_at < now() - interval 'N
seconds'` — would enforce a seven-day idle timeout exactly as well while removing
one WAL-flushing write from the great majority of authenticated requests. The
headroom this would recover is large: the same instance serves 26 543 req/s on
`/health/ready`, which does a pool checkout and a read round trip and nothing else.

**No change was made, and no post-fix number is claimed.** This audit is not
permitted to modify source, so the fix is recommended and quantified here rather
than applied. A re-measurement belongs in the change that makes it.

### DB pool behaviour

Pool size is 32 (`(24 cores × 2).clamp(5, 32)`). Under every authenticated scenario
the pool was **fully checked out and blocked on the session `UPDATE`**, not on the
endpoint's own query. Raising `RB_DB_MAX_CONNECTIONS` would not help and would
likely hurt: the contention is a row lock and a WAL flush, and more concurrent
writers to the same rows make both worse. **The pool is correctly sized; it is
simply being spent on the wrong statement.** No `acquire_timeout` errors and no
`503`s were observed in any run — error rate was 0.00 % in every scenario.

---

## 6. A control that is configured but not enforced

`RateLimitConfig::general_per_principal_per_minute` (default 600) and the key
builders `keys::general_principal` / `keys::general_ip` exist, are documented, and
are **referenced only from `#[cfg(test)]` code**. No production path calls them.

This was confirmed by the load runs, not only by reading the source: 35 756
requests to `GET /auth/me` from a single principal in 30 seconds — 3 575× the
configured 600/minute budget — returned **zero** `429`s. Only the specific
authentication flows (login, refresh, MFA, password reset, registration, invitation
accept, bootstrap) are actually rate limited.

It is recorded here because it materially affects how these numbers should be read:
the throughput figures above are the server's real capacity precisely *because* no
general limiter intervened. It is filed as a defect in
`audit/SECTION_17_20_FINDINGS.md` (F-3).

---

## 7. Reproducing this

```bash
# 1. A perf database on the dev PostgreSQL, migrated with the real command.
docker run --rm --network roleblank_net \
  -e DATABASE_URL="postgres://roleblank_migrator:dev_migrator_pw@roleblank-postgres:5432/roleblank_perf" \
  -e RB_ENCRYPTION_KEY=... -e RB_AUDIT_CHAIN_KEY=... -e RB_BOOTSTRAP_SECRET=... \
  -v roleblank_target:/work/target -w /work rust:1-bookworm \
  /work/target/release/roleblank-api migrate

# 2. The release API against it.
docker run -d --name rb-perf-api --network roleblank_net \
  -e RB_ENV=development \
  -e DATABASE_URL="postgres://roleblank_app:dev_app_pw@roleblank-postgres:5432/roleblank_perf" \
  -e RB_BIND_ADDRESS=0.0.0.0:8080 -e RB_ENCRYPTION_KEY=... -e RB_AUDIT_CHAIN_KEY=... \
  -e RB_BOOTSTRAP_SECRET=... -v roleblank_target:/t debian:bookworm-slim \
  /t/release/roleblank-api serve

# 3. Bootstrap, enrol TOTP, seed, and mint sessions through the public API,
#    then drive the single-token scenarios.
export RB_LOAD_TEST_TOKEN='rb_at_...'
./scripts/load_test.sh
```

`scripts/load_test.sh` runs the single-token scenarios in §3.1–3.2. The
**multi-session** comparison in §3.4, the concurrency sweep in §3.3 and the paced
login sampler in §4 are not in that script; they were run ad hoc for this audit and
are the runs that produced the §5 diagnosis.

---

## 8. What these numbers are not

- **Not a capacity model.** One machine, one configuration, a 441-row dataset, no
  TLS, no proxy, no network latency between client and server. Compare runs against
  each other, not against an SLO taken from another environment.
- **Not an index audit.** 40 projects and 400 tasks fit in shared buffers. Nothing
  here would reveal a missing index.
- **Not a multi-user profile.** All load came from one user's sessions. Real traffic
  spreads across many users, which changes both the contention picture and the
  authorisation resolution profile.
- **Not tuned.** Every setting is a default. No number here was produced by
  changing a configuration to make it look better.

---

## 9. Final acceptance audit — re-measured

Re-measured on the final tree after all fixes, release profile, in a container on a
shared 24-core development host. **Nothing was reconfigured to improve a number**,
which is the whole point of re-recording them here.

### CPU-bound primitives

| Operation | p50 | p95 | p99 |
|---|---|---|---|
| authorisation `evaluate` (44 grants, 5 denials) | 28 ns | 30 ns | 42 ns |
| `evaluate` (deny, out of scope) | 21 ns | 23 ns | 32 ns |
| `capability_list` (whole catalogue) | 1.94 µs | 2.15 µs | 3.62 µs |
| audit `entry_hash` (HMAC-SHA256 + canonical encoding) | 518 ns | 587 ns | 783 ns |
| token generation (32 CSPRNG bytes) | 329 ns | 354 ns | 390 ns |
| token hashing (SHA-256) | 53 ns | 56 ns | 57 ns |
| AEAD seal (XChaCha20-Poly1305) | 1.36 µs | 1.47 µs | 1.53 µs |
| AEAD open | 1.17 µs | 1.21 µs | 1.28 µs |
| TOTP verify (3-step window) | 479 ns | 490 ns | 500 ns |

### End-to-end HTTP (50 samples each, real router, real database)

| Endpoint | p50 | p95 | max |
|---|---|---|---|
| `GET /health/ready` | 1.3 ms | 1.8 ms | 6.7 ms |
| `GET /api/v1/auth/me` | 2.6 ms | 3.1 ms | 6.3 ms |
| `GET /api/v1/projects` | 3.2 ms | 12.3 ms | 19.8 ms |
| `GET /api/v1/tasks` | 5.3 ms | 12.1 ms | 14.4 ms |

### `POST /auth/login`, and why it is reported separately

A naive 50-sample run reported **p50 = 1.2 ms**. That number is wrong, and the way
it is wrong is worth more than the measurement.

Only the first three requests were real logins. The remaining 17 were `429`s,
refused by the per-account limiter *before* any password hashing, and they are
fast precisely because the control works. Averaged together they produce a login
latency that looks eight times better than reality.

The honest figures, restricted to the requests that returned `200`:

| Sample | 1 | 2 | 3 |
|---|---|---|---|
| latency | 18.1 ms | 15.6 ms | 14.9 ms |

That is the Argon2id cost (m = 19 456 KiB, t = 2, p = 1) behaving as designed.

**The lesson for anyone re-running these:** a benchmark that does not record status
codes will flatter any system that has a working rate limiter. Always separate the
work from the refusals.

### The number that matters most

The evaluator at **28 ns** is the cost that a permission cache would remove. It is
the reason no cache exists, and the reason authorisation is re-derived on every
request instead of being carried in the token — a decision this audit specifically
attacked (a live session reflects a grant change on the very next request) and
could not break.

### The real audit-chain cost

Not the 518 ns hash. Appends serialise on
`SELECT … FROM audit_chain_head FOR UPDATE` — deliberate, ADR-006, RR-6. Audit
finding **M-A** abuses exactly this: 100 refused requests from an unprivileged
account produced 101 committed audit rows in 2 s with zero rate limiting, each one
taking that global lock.


---

## 10. Closure re-measurement, and a correction

Re-measured after the rate limiter and metrics layers were installed. All samples
asserted `200`; the endpoint list is the successful data path, not the refusal path.

| Endpoint | p50 | p95 | p99 |
|---|---|---|---|
| `GET /health/ready` | 1.0 ms | 1.4 ms | 1.6 ms |
| `GET /api/v1/auth/me` | 4.0 ms | 4.6 ms | 6.0 ms |
| `GET /api/v1/users` | 4.9 ms | 6.0 ms | 6.3 ms |
| `GET /api/v1/tasks` | 5.4 ms | 6.0 ms | 6.1 ms |
| `GET /api/v1/projects` | 5.9 ms | 7.1 ms | 7.1 ms |
| denied endpoint (`403` + audit row) | 7.2 ms | 10.7 ms | 12.2 ms |

**The correction.** An earlier pass in this closure drove `/projects` and `/tasks`
with an employee token and counted only `5xx`, which was zero. Every one of those
requests was in fact a `403`: the measurement was of the refusal path, presented as
the data path. Recorded here because it is exactly the failure this project keeps
finding — a green number that measured the wrong thing — and because the honest
figures are ~2 ms higher.

The limiter and metrics layers cost **one to two milliseconds** on an authenticated
request: one token-bucket check, one timer, one counter. Under 16–32 concurrent
in-flight requests there were **zero 5xx**. Throughput is deliberately not quoted:
the harness spawns a `curl` process per request and measures itself, not the server.
