# 01 — Architecture

## 1. Shape

RoleBlank OS is a **modular monolith**: one deployable Rust binary, one PostgreSQL
database, explicit internal module boundaries. There are no microservices, no message
broker, no Kubernetes, no service mesh, and no distributed cache. Nothing in the current
requirement set justifies the failure modes those would introduce.

```
                       ┌──────────────────────────────────────────┐
  future web BFF ─────▶│                                          │
  future Flutter ─────▶│         roleblank-api (one binary)       │──▶ PostgreSQL 18
  future MCP/AI  ─────▶│                                          │    (single source
                       └──────────────────────────────────────────┘     of truth)
                                       │
                                       └── outbox worker (same process, own task)
```

## 2. Layering

Requests flow strictly downward. A layer never reaches around the one below it.

```
   HTTP transport        axum routers, extractors, middleware
        │                • parses and bounds input
        │                • never contains a business rule
        ▼
   Application service   modules/*/service.rs
        │                • owns the transaction boundary
        │                • calls the authorization engine with resource context
        │                • emits audit events and outbox events in the same tx
        ▼
   Domain / policy       modules/authorization, domain enums, invariants
        │                • pure, synchronous, heavily unit-tested
        ▼
   Repository            modules/*/repo.rs — explicit SQLx, explicit columns
        │                • parameterised SQL only
        │                • carries the CLIENT visibility predicate into the query
        ▼
   PostgreSQL            constraints, triggers, privilege separation
                         • the last line of defence, not the only one
```

**Why the transaction boundary is in the service layer:** authorisation decisions that
depend on database state (project membership, client links, department membership) must
not be made before the transaction that mutates that state — otherwise the check and the
write straddle a window in which the world changed (TOCTOU). For sensitive mutations the
service opens the transaction, re-reads the resource `FOR UPDATE` where relevant,
authorises, mutates, audits, and commits.

## 3. Module map

```
backend/src/
  main.rs                 CLI: serve | migrate | verify-audit | check-config
  app.rs                  AppState assembly + router composition
  routes.rs               THE canonical route table (also drives the OpenAPI diff test)

  platform/
    config/               typed configuration, environment profiles, fail-closed validation
    database/             pool construction, transaction helpers, migration runner
    errors/               AppError -> RFC 9457 problem+json, stable error codes
    http/                 request-id, security headers, body limits, CORS, trusted proxy,
                          rate limiting, idempotency, extractors (CurrentPrincipal…)
    observability/        tracing JSON layer, log sanitisation, metrics registry
    crypto/               CSPRNG tokens, token hashing, AEAD (key-versioned), Argon2id, TOTP
    security/             step-up policy, password policy, timing-safe helpers

  modules/
    system/               health, readiness, public config, settings, feature flags
    bootstrap/            first-run ROOT creation (race-safe, single-shot)
    identity/             users, lifecycle, invitations, registration modes
    authentication/       login, sessions, refresh rotation, MFA, recovery, password reset
    authorization/        permission catalogue, scopes, evaluator, delegation guard
    departments/          departments + memberships
    clients/              client accounts + client memberships
    projects/             projects, memberships, client links, client projection
    tasks/                tasks, assignees, client visibility
    audit/                append-only audit writer + hash chain + verification
    outbox/               transactional outbox + worker + mail provider abstraction

  shared/                 pagination, cursors, validation primitives, DTO helpers
```

Every module exposes: `mod.rs` (public surface), `routes.rs`, `service.rs`, `repo.rs`,
`dto.rs`, `domain.rs`. A module never calls another module's `repo` directly — only its
`service`. This is enforced by Rust visibility (`pub(crate)` on services,
`pub(super)`/private on repositories).

## 4. What is deliberately *not* abstracted

- **No generic `Repository<T>` trait.** Each repository writes the SQL its module needs,
  with explicit column lists. Generic repositories hide `SELECT *` and make it impossible
  to see, at review time, whether a password hash is being pulled into memory.
- **No policy DSL / rule engine.** Authorisation is a small, readable Rust function over a
  fixed set of scope types. A JSON policy language stored in the database would be
  unreviewable and would move security logic out of code review and out of the type system.
- **No ORM.**
- **No dependency-injection container.** `AppState` is a plain struct of `Arc`s.

The one abstraction that *is* introduced is `trait RateLimiter` and `trait MailProvider`,
because both have a known, already-specified second implementation (Redis; SMTP) and the
call sites must not change when it arrives.

## 5. Concurrency and background work

- Tokio multi-threaded runtime.
- The **outbox worker** runs as a supervised task in the same process, claiming rows with
  `FOR UPDATE SKIP LOCKED`. Running it in-process is safe because claiming is atomic in
  the database; running several API instances later requires no change.
- **Password hashing is bounded** by a semaphore (`ARGON2_MAX_CONCURRENCY`). Argon2id is
  intentionally expensive; without a bound, a login flood turns the memory cost into a
  denial-of-service against the whole process. See `docs/backend/06-security-controls.md`.
- Graceful shutdown: SIGTERM/SIGINT → stop accepting connections → bounded drain of
  in-flight requests → cancel the outbox worker (which finishes or releases its current
  claim) → close the pool.

## 6. Identifiers

UUIDv7 everywhere (`uuid` crate, `now_v7()`). Time-ordered so B-tree indexes stay dense,
and 74 bits of randomness so they are not enumerable. **They are still never treated as
authorisation.** Possessing a project UUID grants nothing; see `04-authorization.md`.

## 7. Consequential trade-offs (full rationale in the ADRs)

| Decision | Alternative rejected | Why |
| --- | --- | --- |
| SQLx **runtime** query API | `query!` compile-time macros | Compile-time macros require a live database or checked-in `.sqlx` metadata at build time. That couples CI and every developer build to a database and makes the "offline metadata is stale" failure mode silent. Real-PostgreSQL integration tests give stronger evidence than compile-time column checking. **ADR-001** |
| Hand-authored OpenAPI + route-diff test | `utoipa` derive macros | 93 endpoints × derive macros is a large macro surface over exactly the handlers a reviewer most needs to read plainly. The diff test gives the contract-drift protection that macros were wanted for. **ADR-001** |
| Opaque server-side sessions | JWT access tokens | Permissions must be revocable *immediately*. A signed token that carries authority is, by construction, valid until it expires. **ADR-002 / ADR-005** |
| ROOT as a `system_ownership` singleton | a `roles` row named `root` | A role row is data an administrator can reach. Ownership must not be reachable by the same code paths that manage roles. **ADR-004** |
| Audit hash chain serialised by a head row | per-row independent hashes | Independent hashes detect modification but not deletion or reordering. **ADR-006** |
| No Redis | Redis for rate limits/sessions | One source of truth. In-process limiting is honest about its single-instance scope and sits behind a trait. **ADR-001** |
