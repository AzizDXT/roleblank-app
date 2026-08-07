# Module implementation guide

The contract every business module follows. It exists so that a reviewer reading
any module already knows where the authorisation decision is, where the transaction
boundary is, and where the audit event is written.

## 1. File layout

```
src/modules/<name>/
  mod.rs        pub use of the router + service; nothing else public
  routes.rs     axum handlers — parse, delegate, serialise. NO business rules.
  service.rs    transaction boundary, authorisation, audit, invariants
  repo.rs       explicit SQL, explicit columns, parameterised always
  dto.rs        request and response types (they are NEVER the same struct)
  domain.rs     enums and value objects (optional)
```

A module calls another module's `service`, never its `repo`.

## 2. The shared API surface

```rust
use crate::app::AppState;
use crate::platform::errors::{AppError, AppResult};
use crate::platform::http::extract::{Authenticated, ClientIp, Json, UserAgentHint};
use crate::modules::authorization::domain::{
    ActorContext, Decision, PrincipalType, ResourceType, Scope, ScopeType, Target, TargetContext,
};
use crate::modules::audit::{self, AuditEvent, AuditMetadata, Outcome, action};
use crate::shared::pagination::{Cursor, Page, PageQuery, PageRequest};
use crate::shared::validation as v;
```

### `AppState` (in `src/app.rs`) — read it before writing a service

| Member | Use |
| --- | --- |
| `state.db` | `PgPool` |
| `state.begin().await?` | open a transaction |
| `state.require(&principal, PERM, &target)?` | **the** authorisation gate |
| `state.decide(&principal, PERM, &target)` | decision without acting (to audit a denial) |
| `state.require_step_up(&principal)?` | recent-MFA gate |
| `state.require_step_up_for(&principal, PERM)?` | step-up only if the permission is dangerous |
| `state.guard_root(subject_is_root)?` | refuse an operation targeting the owner |
| `state.is_root_user(id).await?` | is this user the owner |
| `state.audit(&mut tx, event).await?` | append an audit event inside the transaction |
| `state.bump_security_version(&mut tx, user_id).await?` | after any privilege change |
| `state.config` | `Arc<Config>` — limits, TTLs, page sizes |

### `Authenticated`

`Authenticated(pub Principal)`, `Deref` to `Principal`.
`principal.user_id()`, `.is_root()`, `.is_external()`,
`.session.{session_id, principal_type, security_version, display_name, email, mfa_enrolled}`,
`.actor` (the `ActorContext` the evaluator needs).

`Authenticated` **rejects MFA-pending sessions automatically**. Use it everywhere.

## 3. The five rules

### 3.1 Authorise against the loaded row, never the path parameter

```rust
// WRONG — this is route-level authorisation wearing an object-level costume
state.require(&p, PERM, &Target::Resource(TargetContext::new(ResourceType::Project, id)))?;

// RIGHT — load first, then build the target from what the row actually says
let row = repo::find(&mut tx, id).await?.ok_or(AppError::NotFound)?;
let is_member = repo::is_active_member(&mut tx, id, p.user_id()).await?;
let target = Target::Resource(
    TargetContext::new(ResourceType::Project, row.id)
        .with_department(row.department_id)
        .with_membership(is_member),
);
state.require(&p, PERM, &target)?;
```

`Target::Collection` is for list endpoints and is covered **only** by `GLOBAL`
scope. A narrower scope means the listing must be a *filtered query* — build the
`WHERE` clause from the actor's scopes. Never fetch everything and filter in Rust.

### 3.2 Authorise inside the transaction for mutations

```rust
let mut tx = state.begin().await?;
let row = repo::find_for_update(&mut tx, id).await?.ok_or(AppError::NotFound)?;
state.require(&p, PERM, &target)?;            // after the row is locked
repo::update(&mut tx, ...).await?;
state.audit(&mut tx, event).await?;
tx.commit().await?;
```

Checking before opening the transaction leaves a window in which the world changes
(TH-43).

### 3.3 Request DTOs are closed; response DTOs are explicit

```rust
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]           // MANDATORY on every request DTO (TH-12)
pub struct CreateProjectRequest { pub name: String, /* ... */ }
```

A request DTO must not contain `id`, `status`, `version`, `created_by`,
`principal_type`, `role_ids`, `permissions`, or any ownership field unless the
endpoint explicitly authorises changing it.

Response DTOs are hand-written and never derived from a database row struct. For
anything an external principal can see there are **two** types:

```rust
pub struct ProjectResponse { /* internal view */ }
pub struct ClientProjectResponse { /* strictly fewer fields */ }
```

`internal_note` and equivalents must be physically absent from the client type, not
merely skipped during serialisation.

### 3.4 Optimistic concurrency on every editable resource

Update requests carry `version: i32`. The `UPDATE` is
`... WHERE id = $1 AND version = $2` with `SET version = version + 1`; zero rows
affected means re-read and return:

```rust
Err(AppError::VersionConflict { expected: requested, actual: current })
```

Never silently overwrite.

### 3.5 Client visibility is a SQL predicate, not a post-filter

Every query serving a `CLIENT` principal carries:

```sql
EXISTS (SELECT 1
          FROM project_client_links pcl
          JOIN client_memberships cm ON cm.client_account_id = pcl.client_account_id
          JOIN client_accounts    ca ON ca.id = pcl.client_account_id
         WHERE pcl.project_id = p.id
           AND pcl.revoked_at IS NULL
           AND cm.user_id = $uid
           AND cm.status  = 'ACTIVE'
           AND ca.status  = 'ACTIVE')
```

so an invisible row is never loaded even if the policy layer were wrong. Tasks
additionally require `t.client_visible = true` — sharing a project does not share
its tasks.

## 4. Repositories

- `sqlx::query_as::<_, Row>(...)` with `#[derive(sqlx::FromRow)]`. **No `query!`
  macros** (ADR-001).
- Explicit column lists. Never `SELECT *` — it is how a password hash reaches memory.
- Parameterised binds only. Dynamic `ORDER BY` comes from
  `PageRequest::resolve(..)`, which returns a `&'static str` chosen from an
  allowlist; a user string never reaches SQL.
- Take `&mut Transaction` when the caller owns a transaction; `&PgPool` for reads.

## 5. Errors

Return `AppError`. Never `unwrap`, `expect`, `panic!`, `todo!`, or
`unimplemented!` in non-test code. A malformed request must never kill the process.

`AppError::NotFound` for anything an external principal cannot see;
`AppError::AuthorizationDenied` for an internal principal — `state.require` already
applies this rule, so just propagate what it returns.

## 6. Audit

Every state change writes an audit event **inside the same transaction**:

```rust
state.audit(&mut tx, AuditEvent::new(action::PROJECT_UPDATED, Outcome::Success)
    .actor(p.user_id(), p.session.principal_type, Some(p.session.session_id))
    .target("PROJECT", project.id)
    .meta(AuditMetadata::new().changed("name").changed("status"))).await?;
```

Denied attempts at sensitive operations are audited with `Outcome::Denied`.
Metadata is a closed builder — passwords, tokens, TOTP secrets and whole request
bodies are refused by it and must never be attempted.

## 7. Validation

`shared::validation` — `validate_email`, `required_text`, `optional_text`,
`validate_code`, `validate_role_code`, `validate_array_len`, `parse_enum`, plus the
`MAX_*` constants, which match the database `CHECK` constraints exactly. Validate
in the service, not the handler, so a direct service call is equally protected.

## 8. Style

- Comments explain **why**, tied to the concrete failure prevented. No comment that
  restates the code.
- British-English spelling in prose (authorise, serialise, behaviour).
- Tests live beside the code in `#[cfg(test)] mod tests` and must include negative
  and adversarial cases. Pure logic must be testable without a database.
- `they/them` for any person referred to in prose.
