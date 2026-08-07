# Performance Report

**Date of measurement:** 2026-08-07
**Every number below was produced by an executed run.** Nothing here is estimated,
extrapolated, or copied from another system. Where a measurement was not taken,
that is stated rather than filled in.

---

## 1. Environment

| Item | Value |
| --- | --- |
| Host | Windows 11 Home 10.0.26200 |
| CPU | Intel Core Ultra 9 290HX Plus — 24 physical / 24 logical cores |
| RAM | 63.37 GB |
| Execution environment | `rust:1-bookworm` container (rustc 1.97.1, identical to the host toolchain) |
| Cores visible to the process | 24 |
| Build profile | **release** (`opt-level = 3`, `lto = "thin"`, `codegen-units = 1`) |
| Target | x86_64 |
| Database | `postgres:18.4-alpine`, data checksums enabled, same Docker network |

Everything runs containerised because the Windows host enforces an Application
Control policy that refuses to execute freshly compiled unsigned binaries
(`os error 4551`). See `00-reconnaissance.md` §3.

Reproduce with:

```bash
cargo test --release --test benchmarks -- --ignored --nocapture
```

The harness is `backend/tests/benchmarks.rs`. It reports **percentiles, not means**:
a mean hides the tail, and the tail is what a user experiences. Each measurement
warms up first, because the first call pays allocator and page-fault costs that are
not representative of steady state.

---

## 2. Password hashing — the decisive parameter

Argon2id at m=19 456 KiB, t=2, p=1 — the configured production defaults, measured
as configured. This is the single most consequential performance decision in the
system: too cheap and an offline attacker with the database grinds passwords; too
expensive and a login flood turns our own KDF into an amplification weapon against
us (TH-34).

| Operation | n | p50 | p95 | p99 | max | mean |
| --- | --- | --- | --- | --- | --- | --- |
| hash (sequential) | 30 | **19.13 ms** | 26.18 ms | 26.52 ms | 26.52 ms | 18.41 ms |
| verify (sequential) | 30 | **19.74 ms** | 27.72 ms | 36.10 ms | 36.10 ms | 20.16 ms |

### Under concurrency, with the bounding semaphore active (8 permits)

| Concurrent verifications | Total | Per operation | Throughput |
| --- | --- | --- | --- |
| 1 | 28.07 ms | 28.07 ms | 35.6 /s |
| 4 | 39.36 ms | 9.84 ms | 101.6 /s |
| 8 | 58.06 ms | 7.26 ms | 137.8 /s |
| 16 | 82.15 ms | 5.14 ms | 194.8 /s |
| 32 | 148.99 ms | 4.66 ms | **214.8 /s** |

**Reading these numbers.** Throughput keeps rising past the 8-permit bound because
the permits gate *concurrent Argon2 work*, not queueing — waiting requests are
cheap. It plateaus around 215/s, which is the machine's real ceiling for this cost
factor. Latency per request degrades gracefully rather than collapsing: at 32
concurrent the wall-clock is 149 ms, not a timeout.

### The conclusion drawn

- **~19 ms per verification is the right side of the trade-off.** It is expensive
  enough to be meaningful against offline attack and cheap enough that a legitimate
  login is not perceptibly slow.
- **Worst-case resident memory devoted to hashing = permits × m_cost = 8 × 19 MiB
  ≈ 152 MiB.** Size the container accordingly (`08-operations.md` §10). Without the
  semaphore, 24 concurrent logins would be 456 MiB of memory doing nothing but
  rejecting an attacker.
- The bound plus the rate limiter (10 login attempts per IP per minute, 5 per
  account) is what makes an intentionally memory-hard KDF safe on a public endpoint.
- **No change to the cost factor is warranted by these numbers.** They meet current
  OWASP guidance and the operational envelope is comfortable.

---

## 3. Per-request cryptographic primitives

Everything on the authenticated request path that is not a database round trip.

| Operation | n | p50 | p95 | p99 | max |
| --- | --- | --- | --- | --- | --- |
| Token generation (32 CSPRNG bytes) | 10 000 | 432 ns | 441 ns | 481 ns | 25.57 µs |
| Token hashing (SHA-256) | 100 000 | **53 ns** | 56 ns | 57 ns | 30.35 µs |
| AEAD seal (XChaCha20-Poly1305) | 10 000 | 1.355 µs | 1.445 µs | 1.515 µs | 29.39 µs |
| AEAD open | 10 000 | 1.160 µs | 1.197 µs | 1.273 µs | 51.70 µs |
| TOTP verify (3-step window) | 10 000 | 480 ns | 491 ns | 518 ns | 8.43 µs |

**Token hashing at 53 ns validates a design decision.** SHA-256 rather than a KDF
is correct here because the input is already 256 bits of uniform randomness — there
is no low-entropy secret for a slow hash to protect. Had this used Argon2, every
authenticated request would have paid ~19 ms instead of 53 ns, a factor of roughly
**360 000**, for no security gain (ADR-002).

TOTP verification evaluates all three candidate steps unconditionally so the work
does not depend on which step matched; 480 ns is that full three-step cost.

The `max` column reflects occasional OS scheduling interruptions, not algorithmic
variance — p99 sits within a few percent of p50 throughout.

---

## 4. Authorisation evaluation

The evaluator runs on every authorised request. It is pure and synchronous, so this
is exactly the policy cost with no database noise. Measured against a realistic
administrator: all 44 catalogued permissions at global scope, 5 resource-scoped
denials, 3 department memberships.

| Operation | n | p50 | p95 | p99 | max |
| --- | --- | --- | --- | --- | --- |
| `evaluate` — allow, 44 grants + 5 denials | 100 000 | **27 ns** | 29 ns | 42 ns | 35.38 µs |
| `evaluate` — deny, out of scope | 100 000 | 22 ns | 23 ns | 23 ns | 8.42 µs |
| `capability_list` — whole catalogue | 10 000 | 1.936 µs | 2.142 µs | 2.226 µs | 68.00 µs |

**This settles the caching question.** `docs/backend/04-authorization.md` §11 states
that no permission cache exists because correctness beats speed. These numbers show
the choice costs essentially nothing: **27 nanoseconds** per decision. A cache would
remove 27 ns and introduce an invalidation path whose failure mode is *preserving
revoked privileges*. That trade is not worth making, and now there is a measurement
saying so rather than an assertion.

The denial path is *faster* than the allow path (22 ns vs 27 ns), which is expected
— denials short-circuit — and is not a timing oracle: the difference is dominated by
the database round trip that precedes and follows it, and the outcome is already
visible in the response.

`capability_list` at ~2 µs walks all 44 permissions and is called once per
`GET /auth/me`, not per request.

---

## 5. Audit chain

| Operation | n | p50 | p95 | p99 | max |
| --- | --- | --- | --- | --- | --- |
| `entry_hash` — HMAC-SHA256 over the canonical encoding | 100 000 | 532 ns | 597 ns | 1.129 µs | 352.97 µs |

**The hash is not the cost.** At 532 ns it is irrelevant next to a database round
trip. The real cost of the audit chain is that appends serialise on
`SELECT … FROM audit_chain_head FOR UPDATE`, held until the writing transaction
commits. That is a deliberate correctness-over-throughput decision (ADR-006): it is
what makes the chain well-defined under concurrency, because without it two
concurrent inserts could read the same `prev_hash` and produce a fork that
verification could not distinguish from tampering.

**This serialisation has not yet been measured end to end.** See §7.

---

## 6. What the test suite tells us about throughput

Not a benchmark, but a real datapoint from an executed run:

| Suite | Tests | Wall clock |
| --- | --- | --- |
| Unit (`--lib`) | 577 | 0.92 s |
| Golden end-to-end scenario | 1 | 0.60 s |
| OpenAPI contract | 5 | 0.01 s |
| Race suite (incl. 100 concurrent bootstraps) | 7 | 0.57 s |
| Security suite (adversarial + database) | 23 | 0.84 s |
| **Total** | **613** | **~2.9 s** |

The golden scenario alone performs a bootstrap (one Argon2 hash), two logins (two
verifications), MFA enrolment and activation, a simulated process restart and a full
audit-chain verification — in 0.60 s, of which roughly 60 ms is Argon2. Each of the
23 security tests provisions its own PostgreSQL database by cloning a migrated
template; 23 database clones plus their queries in 0.84 s indicates the schema and
its indexes are not a bottleneck at this scale.

The race suite fires **100 simultaneous bootstrap attempts** and settles in 0.57 s,
with exactly one succeeding.

---

## 7. Not measured — stated rather than estimated

| Measurement | Status | Command |
| --- | --- | --- |
| End-to-end HTTP throughput and latency percentiles under load | **NOT MEASURED** | `./scripts/load_test.sh` (needs `RB_LOAD_TEST_TOKEN` and a running API) |
| Audit-chain append serialisation under concurrent writers | **NOT MEASURED** | The `FOR UPDATE` contention in §5 is reasoned about, not benchmarked |
| Database connection-pool behaviour under sustained load | **NOT MEASURED** | Pool defaults are `min(cpu × 2, 32)`, chosen from PostgreSQL contention guidance, not from a measurement on this workload |
| `EXPLAIN ANALYZE` on the session-lookup and effective-permission queries | **NOT RUN** | Indexes exist and are documented per access path in `05-data-model.md` §10, but no query plan has been captured |
| Memory profile of the running server | **NOT MEASURED** | Only the hashing worst case (152 MiB) is derived, and that is arithmetic, not observation |

These are the measurements that need a running server and a load generator. The
scripts exist (`scripts/load_test.sh`, using `oha` in a container) but have not been
executed, so no numbers are claimed for them.

---

## 8. Bottleneck assessment

Based on what *was* measured:

1. **Password hashing dominates the login path** — ~19 ms against ~53 ns for token
   hashing and ~27 ns for authorisation. Deliberate, bounded, and the reason login
   is rate limited separately from everything else.
2. **Authorisation is free** at 27 ns and is not worth optimising or caching.
3. **The remaining cost of a typical authenticated request is the database**, which
   is precisely what has not been measured yet. Any tuning effort should start
   there — with `EXPLAIN ANALYZE` on the session lookup, which runs once per
   request and is the hottest query in the system.
4. **The audit chain's global serialisation is the most likely first scaling
   ceiling.** It is a known, documented trade with a known remedy (per-partition
   chains, a schema change rather than a redesign). It should be measured before it
   is believed to be a problem, and before it is "fixed".

No optimisation has been performed. Nothing here has been tuned on the basis of
imagination.
