# ADR-001 — Backend architecture

**Status:** Accepted · **Date:** 2026-08-07 · **Supersedes:** none

## Context

RoleBlank OS must carry years of company operations — identity, projects, finance, chat,
files, AI agents — without a rewrite of its identity, authorisation or persistence
foundations. The team is small. The deployment target is a single company, not a SaaS
fleet. The build environment (see `00-reconnaissance.md`) forbids executing freshly
compiled binaries on the Windows host.

## Decision

1. **Modular monolith.** One Rust binary, one PostgreSQL database. Modules are Rust modules
   with an explicit service layer, not network services.
2. **PostgreSQL 18 is the only source of truth.** No Redis, no MongoDB, no secondary store,
   no message broker. Asynchronous side effects use a PostgreSQL-backed transactional
   outbox.
3. **SQLx runtime query API**, not the compile-time `query!` macros.
4. **Hand-authored OpenAPI**, not derive macros, with an automated route-diff test.
5. **All builds and tests execute inside `rust:1-bookworm`** via `scripts/rb.ps1`.

## Rationale

**Monolith over microservices.** The failure modes microservices introduce — distributed
transactions, partial failure, cross-service authorisation drift, N× deployment surface —
are all *security-relevant* here, and none of them buy anything at one-company scale. A
single process can hold an authorisation decision and its mutation in one database
transaction. That is the property this system most needs (TH-43), and it is exactly the
property distribution destroys.

**No Redis.** Two authoritative stores means two things that can disagree about whether a
session is revoked. Rate limiting is the only genuine candidate, and it sits behind
`trait RateLimiter` with a documented single-instance limitation (RR-3) and a release gate
before horizontal scaling.

**Runtime SQLx over `query!` macros.** The macros verify SQL against a live database at
*compile time*, which means either every build needs a database, or a `.sqlx` metadata
directory must be committed and kept fresh. The second option fails silently: stale
metadata compiles green against a schema that has changed. Explicit `query_as` with named
columns plus a real-PostgreSQL integration suite gives stronger evidence — the tests run
the actual statements against the actual schema. Cost accepted: typos in SQL surface at
test time rather than compile time. Mitigation: no repository is untested.

**Hand-authored OpenAPI.** Annotating ~70 handlers with `utoipa` macros puts a large macro
expansion directly on top of the code a security reviewer most needs to read literally
(§109 of the brief explicitly forbids macro ceremony that obscures security behaviour).
The value the macros provide is drift protection, and that is obtained more directly: the
router is built from one canonical route table (`src/routes.rs`), and a test asserts that
the table and `api/openapi.yaml` describe the same set of `(method, path)` pairs with the
same authentication requirement. Drift fails the build.

**Containerised toolchain.** Not a preference — the host physically cannot run the output
of `cargo build` (`os error 4551`). The container carries the identical rustc 1.97.1.

## Consequences

- Horizontal scaling is possible (the outbox claims with `FOR UPDATE SKIP LOCKED`) but
  requires the distributed rate limiter first. Recorded as a gate, not a surprise.
- CI compiles without a database; migrations and integration tests need one.
- Adding an endpoint without updating `api/openapi.yaml` fails the test suite.
- Developers on this machine cannot use host `cargo check`/IDE integration until the
  Application Control policy is adjusted. That is an operator decision.

## Alternatives rejected

| Alternative | Why not |
| --- | --- |
| Microservices | Breaks transactional authorisation; no scaling requirement exists |
| Event sourcing | Enormous complexity for a system whose audit needs are met by an append-only log |
| GraphQL | Object-level authorisation on an arbitrary graph is far harder to prove correct than on explicit REST resources |
| Diesel / SeaORM | ORMs encourage entity-as-DTO, which is the direct cause of mass-assignment and secret-serialisation bugs |
| WSL-based toolchain | No Rust installed in WSL; Docker was already present and reproducible |
