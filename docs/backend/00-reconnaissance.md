# 00 — Repository Reconnaissance

**Date of reconnaissance:** 2026-08-07
**Target:** `C:\Users\abdul\Desktop\RoleBlank\RoleBlank-app`
**Performed before any application code was written.**

---

## 1. What existed

Nothing.

| Check | Result |
| --- | --- |
| `Get-ChildItem -Force -Recurse` on the project root | **0 items** — the directory was completely empty |
| `git status` in the project root | `fatal: not a git repository` |
| `git status` in the parent (`Desktop\RoleBlank`) | `fatal: not a git repository` |
| Existing Cargo workspace | none |
| Existing backend source | none |
| Existing migrations / SQL | none |
| Existing Docker / Compose files | none |
| Existing CI configuration | none |
| Existing documentation | none |
| Existing `.env` / configuration | none |
| Existing RoleBlank visual identity assets | none present in this tree |

The sibling directory `Desktop\RoleBlank\Bank_Muscat_Print_Pack_2026-07-19` is unrelated
to this task and was **not** inspected further, **not** modified, and is outside the
project root.

**Consequence:** there was no user work to preserve inside the project root, no naming
convention to inherit, and no architectural conflict to resolve. This is a greenfield
build. A git repository was initialised (`git init -b main`) inside the project root
only; nothing was pushed anywhere and no remote was configured.

---

## 2. Host environment

| Component | Value |
| --- | --- |
| OS | Windows 11 Home 10.0.26200 |
| CPU | Intel Core Ultra 9 290HX Plus — 24 physical / 24 logical cores |
| RAM | 63.37 GB |
| Rust (host) | rustc 1.97.1 (8bab26f4f 2026-07-14), cargo 1.97.1 |
| Git | 2.55.0.windows.3 |
| Docker | 29.6.2 (Docker Desktop, WSL2 backend), Compose v5.3.1 |
| WSL | Ubuntu, WSL2 default — **no Rust toolchain installed inside WSL** |
| `psql` client on host | **not installed** |

### Locally available container images (no pull required)

- `rust:1-bookworm` — verified to contain **rustc 1.97.1**, identical to the host toolchain
- `postgres:18.4-alpine`
- `postgres:17-alpine`, `postgres:16-alpine`

### Ports already in use on the host

`5433`, `9000`, `8080` are bound by pre-existing containers belonging to other
projects (`tenderai-*`, `social-research-monitor-*`, `wc-live`). Those containers were
left untouched. RoleBlank therefore claims:

- **`127.0.0.1:5440`** — development PostgreSQL
- **`127.0.0.1:8090`** — development API

---

## 3. BLOCKING environmental finding — Windows Application Control

This is the single most consequential discovery of the reconnaissance phase and it
shapes the entire developer workflow.

**The Windows host enforces an Application Control (WDAC/Smart App Control) policy that
refuses to execute freshly produced, unsigned executables.**

Evidence — two independent reproductions:

1. `cargo install sqlx-cli --locked` (building under `%TEMP%`):

   ```
   error: failed to run custom build command for `generic-array v0.14.7`
   Caused by: could not execute process
     `C:\Users\abdul\AppData\Local\Temp\cargo-installRRw30v\release\build\generic-array-.../build-script-build`
     (never executed)
   Caused by: An Application Control policy has blocked this file. (os error 4551)
   ```

2. `cargo build` inside the project directory itself (i.e. **not** a `%TEMP%` problem):

   ```
   error: failed to run custom build command for `icu_properties_data v2.2.0`
   Caused by: could not execute process
     `C:\...\RoleBlank-app\backend\target\debug\build\icu_properties_data-.../build-script-build`
     (never executed)
   Caused by: An Application Control policy has blocked this file. (os error 4551)
   ```

`rustc.exe` itself runs fine because the distributed toolchain binaries are signed. Every
*newly compiled* binary — build scripts, test harnesses, the API binary — is blocked.

### Resolution adopted

**All compilation, testing and Rust tooling runs inside a Linux container.** The
`rust:1-bookworm` image already present on the machine carries the exact same
rustc 1.97.1, so the toolchain is not being downgraded or diverged.

Verified working: a full `cargo build` of the complete dependency tree finished inside
the container in 21.4 s.

This is documented, not hidden. `scripts/rb.ps1` is a thin wrapper that echoes every
`docker run` invocation it performs. Consequences recorded for the reports:

- Any tool that must be `cargo install`-ed (`cargo-audit`, `cargo-deny`, `cargo-llvm-cov`,
  `cargo-mutants`, `cargo-fuzz`, `sqlx-cli`, `oha`) is installed **inside the container**,
  not on the host.
- `cargo-fuzz` additionally requires a nightly toolchain; see §6.
- Host-side developer ergonomics (IDE `cargo check`) will not work on this machine
  without either signing the artefacts or relaxing the policy. That is an operator
  decision, not a backend design decision.

---

## 4. Reusable vs. missing

**Reusable:** the Docker daemon, the local `postgres:18.4-alpine` and `rust:1-bookworm`
images, 24 cores and 63 GB RAM for meaningful concurrency and load testing.

**Missing — everything else**, i.e. the whole deliverable: Cargo manifest, migrations,
platform layer, IAM, authorisation engine, business modules, tests, OpenAPI, Docker
artefacts, CI, operational scripts and documentation.

---

## 5. Dependency baseline resolved

`cargo build` resolved **256 crates**. The security-relevant pins actually selected:

| Crate | Version | Role |
| --- | --- | --- |
| `axum` | 0.8.9 | HTTP framework |
| `tokio` | 1.53.1 | async runtime |
| `tower-http` | 0.6.11 | middleware (CORS, body limit, timeout, tracing) |
| `hyper` | 1.11.0 | HTTP implementation |
| `sqlx` | 0.9.0 | PostgreSQL access, migrations |
| `rustls` | 0.23.43 | TLS for database connections |
| `argon2` | 0.5.3 | password hashing (Argon2id) |
| `password-hash` | 0.5.0 | PHC string format |
| `chacha20poly1305` | 0.10.1 | AEAD for TOTP secret encryption (XChaCha20-Poly1305) |
| `sha2` | 0.10.9 | session/reset/invite token hashing, audit chain |
| `sha1` | 0.10.7 | HMAC-SHA1 primitive required by RFC 6238 TOTP |
| `hmac` | 0.12.1 | HMAC construction |
| `subtle` | 2.6.1 | constant-time comparison |
| `rand` | 0.9.5 | CSPRNG (`OsRng`) |
| `zeroize` | 1.9.0 | wiping secrets from memory |
| `uuid` | 1.24.0 | UUIDv7 identifiers |
| `time` | 0.3.55 | `timestamptz` mapping |
| `data-encoding` | 2.11.1 | base32 (TOTP) / base64url (tokens) |
| `tracing-subscriber` | 0.3.23 | structured JSON logging |
| `proptest` | 1.11.0 | property-based security tests (dev) |

Version rationale and per-crate justification live in `docs/backend/06-security-controls.md`.
No alpha/beta/nightly dependency was selected. No git dependency was selected.

---

## 6. Risks identified up front

| # | Risk | Handling |
| --- | --- | --- |
| R1 | Application Control blocks host builds | All builds containerised; documented above; recorded as an environmental constraint in every report |
| R2 | `cargo fuzz` needs nightly + `cargo install` | Fuzz targets are written and a runner script is provided, but execution is expected to be **BLOCKED** on this host. It will be reported as BLOCKED with the exact command, never as PASS |
| R3 | SQLx compile-time macros (`query!`) require a live database or checked-in offline metadata at build time, coupling CI to a database | Decision: use the **runtime** query API (`sqlx::query_as` + explicit `FromRow`) throughout. CI compiles without a database. Trade-off (loss of compile-time SQL verification) is compensated by real-PostgreSQL integration tests. See ADR-001 |
| R4 | A generic OpenAPI derive-macro layer across ~70 endpoints adds heavy macro surface that obscures security behaviour (violates the "no macro ceremony" rule) | Decision: hand-author the OpenAPI 3.1 contract and add an automated test that diffs the router's real route table against the spec. See ADR-001 |
| R5 | Argon2id memory cost is itself a DoS surface under concurrent login floods | Bounded-concurrency semaphore in front of all password hashing + per-IP and per-account rate limiting. Benchmarked, not guessed |
| R6 | PostgreSQL 18 images changed the expected volume mount point to `/var/lib/postgresql` | Discovered during reconnaissance (the container refused to start with the PG≤17 layout). Compose and scripts use the PG18 layout |
| R7 | A single ROOT_OWNER that cannot be recovered is an availability risk | ROOT lockout is deliberately throttled, never permanently locked (§27 of the brief). Ownership replacement is an offline, documented procedure — see ADR-004 |
| R8 | Bind-mounting the Windows filesystem into the build container is slow for many small files | `target/` and the cargo registry live in **named Docker volumes**, not on the bind mount |

---

## 7. Assumptions recorded

1. **Single company, no SaaS tenancy.** No `organization_id` is introduced. `CLIENT` is a
   restricted external principal type, not a tenant.
2. **One deployable backend** (modular monolith). Module boundaries are enforced by Rust
   module visibility and an explicit service layer, not by network boundaries.
3. **PostgreSQL is the only source of truth.** No Redis, no secondary store. Rate limiting
   is in-process behind a trait so a distributed backend can be added later without
   touching call sites.
4. **No frontend is produced by this task.** No HTML, CSS, React, Next.js or Flutter file
   is created. The only client-facing artefacts are an OpenAPI document and `.http`
   request collections.
5. **Email delivery is deliberately not implemented.** A `MailProvider` trait plus
   development sinks exist; a production SMTP/API provider is explicitly deferred and
   production startup **fails closed** if a real provider is required but unconfigured.
   No fake "email sent" success is ever returned.
6. **Timestamps are `timestamptz`, stored and reasoned about in UTC.**
7. **Identifiers are UUIDv7** — time-ordered, index-friendly, and non-guessable enough
   that they are still never used as an authorisation mechanism.

---

## 8. Proposed implementation sequence

1. Architecture, threat model, ADRs *(this phase's prerequisite)*
2. Configuration, error model, HTTP scaffolding, observability, graceful shutdown
3. Database schema + privilege separation + ROOT/audit database-level invariants
4. Crypto helpers (token generation/hashing, AEAD, Argon2id, TOTP)
5. Bootstrap + system ownership
6. Authentication, sessions, refresh rotation, MFA, step-up
7. Authorisation engine, permission catalogue, delegation guard
8. Users, invitations, lifecycle, password reset
9. Departments, client accounts, memberships
10. Projects, tasks, client project sharing and client projections
11. Settings, feature flags, registration modes
12. Audit hash chain + verification command
13. Idempotency + transactional outbox + worker
14. OpenAPI, Docker, CI, developer scripts, API collection
15. Test suites — unit, integration, adversarial, race, property
16. Execute all gates, self-attack pass, write the three evidence reports

Implementation did not begin until items 1–3 of Phase B were coherent on paper.
