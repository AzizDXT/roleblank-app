# 05 — Data Model

PostgreSQL 18 is the single source of truth. Every identifier is `uuid` (v7 generated in
the application), every instant is `timestamptz` stored in UTC, every money-like or exact
value would be `numeric` (none exist yet), and no timestamp is ever a string.

## 1. Ownership and system state

```
system_state
  id                boolean  PK  DEFAULT true  CHECK (id)      -- singleton by construction
  initialized_at    timestamptz NULL                            -- NULL ⇒ bootstrap available
  created_at        timestamptz NOT NULL DEFAULT now()

system_ownership
  id                boolean  PK  DEFAULT true  CHECK (id)      -- singleton by construction
  root_user_id      uuid     NOT NULL REFERENCES users(id) ON DELETE RESTRICT
  established_at    timestamptz NOT NULL DEFAULT now()
```

`id boolean PRIMARY KEY CHECK (id)` admits exactly one row, forever, without a trigger.
A second `INSERT` is a primary-key violation — the strongest form the database offers.

**Immutability triggers** (`trg_system_ownership_immutable`): `BEFORE UPDATE OR DELETE`
raises unconditionally. There is no application code path to either statement; the trigger
exists so that a future bug, a stray migration, or an interactive session using the runtime
role cannot become the exception.

`system_ownership.root_user_id` additionally enforces on insert that the referenced user is
`principal_type = 'INTERNAL'` — a CLIENT can never become the owner even by direct SQL.

## 2. Identity

```
users
  id                uuid PK
  email             text NOT NULL                         -- as the user typed it
  email_normalized  text NOT NULL UNIQUE                  -- lower(trim(email)); the identity
  display_name      text NOT NULL  CHECK (length between 1 and 200)
  principal_type    text NOT NULL  CHECK (IN ('INTERNAL','CLIENT'))
  status            text NOT NULL  CHECK (IN ('PENDING','ACTIVE','SUSPENDED','ARCHIVED'))
  mfa_required      boolean NOT NULL DEFAULT false
  mfa_enrolled      boolean NOT NULL DEFAULT false
  security_version  integer NOT NULL DEFAULT 1             -- bumped on any privilege change
  version           integer NOT NULL DEFAULT 1             -- optimistic concurrency
  created_at, updated_at, archived_at, suspended_at
```

Email uniqueness is on `email_normalized`, so `Ali@x.com` and `ali@x.com` cannot both
exist. Normalisation is `lower(trim(...))` and nothing more: no dot-stripping, no
plus-address folding — over-normalising silently merges distinct real mailboxes.

### ROOT protection triggers on `users`

`trg_users_protect_root` — `BEFORE UPDATE OR DELETE`, and it consults `system_ownership`
rather than any denormalised flag:

| Statement | Behaviour when the row is the owner |
| --- | --- |
| `DELETE` | `RAISE EXCEPTION` — always |
| `UPDATE … SET status <> 'ACTIVE'` | `RAISE EXCEPTION` |
| `UPDATE … SET principal_type <> 'INTERNAL'` | `RAISE EXCEPTION` |
| `UPDATE … SET mfa_required = false` | `RAISE EXCEPTION` |

The runtime role additionally has **no `DELETE` grant on `users` at all**, so even a
non-owner user cannot be hard-deleted by the application — the lifecycle is archive, never
erase, which preserves historical references and audit meaning.

```
credentials
  user_id           uuid PK REFERENCES users(id) ON DELETE RESTRICT
  password_hash     text NOT NULL          -- PHC string: $argon2id$v=19$m=…,t=…,p=…$…
  password_updated_at timestamptz NOT NULL
  must_change       boolean NOT NULL DEFAULT false
```

Split from `users` so that the ordinary user query — which runs on every authenticated
request — physically cannot return a password hash. This is a schema-level answer to
"never accidentally serialise a secret", not a discipline-level one.

## 3. Sessions

```
sessions
  id uuid PK
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT
  access_token_hash   bytea NOT NULL UNIQUE      -- SHA-256, never the token
  access_expires_at   timestamptz NOT NULL
  idle_expires_at     timestamptz NOT NULL
  absolute_expires_at timestamptz NOT NULL
  auth_level          text NOT NULL CHECK (IN ('PASSWORD','MFA'))
  pending_mfa         boolean NOT NULL DEFAULT false
  mfa_verified_at     timestamptz NULL
  last_activity_at    timestamptz NOT NULL
  revoked_at          timestamptz NULL
  revocation_reason   text NULL CHECK (IN ('LOGOUT','LOGOUT_ALL','PASSWORD_CHANGED',
                                           'PASSWORD_RESET','USER_SUSPENDED','USER_ARCHIVED',
                                           'ADMIN_REVOKED','REFRESH_REUSE_DETECTED','EXPIRED'))
  client_ip_hint      text NULL              -- sanitised, ≤45 chars
  user_agent_hint     text NULL              -- sanitised, ≤200 chars
  created_at

session_refresh_tokens
  id uuid PK
  session_id  uuid NOT NULL REFERENCES sessions(id) ON DELETE RESTRICT
  token_hash  bytea NOT NULL UNIQUE
  generation  integer NOT NULL
  expires_at  timestamptz NOT NULL
  consumed_at timestamptz NULL
  replaced_by uuid NULL REFERENCES session_refresh_tokens(id)
  created_at
  UNIQUE (session_id, generation)
```

Consumed refresh rows are **kept**. Deleting them would delete the evidence that makes
reuse detection possible. Retention is bounded by a documented cleanup job that only
removes rows whose session ended long ago.

```
mfa_factors
  id uuid PK, user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT
  factor_type       text NOT NULL CHECK (IN ('TOTP'))
  status            text NOT NULL CHECK (IN ('PENDING','ACTIVE','DISABLED'))
  secret_ciphertext bytea NOT NULL          -- XChaCha20-Poly1305
  secret_nonce      bytea NOT NULL CHECK (octet_length = 24)
  key_version       integer NOT NULL        -- enables rotation without re-encrypting eagerly
  last_used_step    bigint NULL             -- replay defence
  created_at, activated_at, disabled_at
  UNIQUE INDEX (user_id, factor_type) WHERE status IN ('PENDING','ACTIVE')

recovery_codes
  id uuid PK, user_id uuid NOT NULL, batch_id uuid NOT NULL
  code_hash bytea NOT NULL UNIQUE, created_at, consumed_at timestamptz NULL

password_reset_tokens
  id uuid PK, user_id uuid NOT NULL, token_hash bytea NOT NULL UNIQUE
  expires_at, consumed_at timestamptz NULL, created_at
  requested_ip_hint text NULL

invitations
  id uuid PK
  email text NOT NULL, email_normalized text NOT NULL
  principal_type text NOT NULL CHECK (IN ('INTERNAL','CLIENT'))
  client_account_id uuid NULL REFERENCES client_accounts(id)
  department_id     uuid NULL REFERENCES departments(id)
  token_hash bytea NOT NULL UNIQUE
  status text NOT NULL CHECK (IN ('PENDING','ACCEPTED','REVOKED','EXPIRED'))
  invited_by uuid NOT NULL REFERENCES users(id)
  accepted_user_id uuid NULL REFERENCES users(id)
  expires_at, accepted_at, revoked_at, created_at
  CHECK (principal_type = 'CLIENT' OR client_account_id IS NULL)
  UNIQUE INDEX (email_normalized) WHERE status = 'PENDING'

invitation_roles
  invitation_id uuid, role_id uuid, scope_type text
  PRIMARY KEY (invitation_id, role_id)
```

The partial unique index on pending invitations is what makes "invite the same person
twice" a deterministic conflict instead of two live tokens.

## 4. Authorization

```
permissions
  code               text PK CHECK (code ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$')
  module             text NOT NULL
  description        text NOT NULL
  max_principal_type text NOT NULL CHECK (IN ('INTERNAL','ANY'))
  is_dangerous       boolean NOT NULL DEFAULT false

roles
  id uuid PK
  code text NOT NULL UNIQUE CHECK (code ~ '^[a-z][a-z0-9_]*$')
  name text NOT NULL, description text NOT NULL DEFAULT ''
  is_system boolean NOT NULL DEFAULT false
  allowed_principal_type text NOT NULL CHECK (IN ('INTERNAL','CLIENT'))
  version integer NOT NULL DEFAULT 1
  created_at, updated_at, created_by

role_permissions
  role_id uuid REFERENCES roles(id) ON DELETE RESTRICT
  permission_code text REFERENCES permissions(code) ON DELETE RESTRICT
  scope_type text NOT NULL CHECK (IN ('GLOBAL','DEPARTMENT','ASSIGNED','SELF'))
  granted_at, granted_by
  PRIMARY KEY (role_id, permission_code)

user_role_assignments
  id uuid PK
  user_id uuid REFERENCES users(id) ON DELETE RESTRICT
  role_id uuid REFERENCES roles(id) ON DELETE RESTRICT
  granted_by uuid, granted_at
  UNIQUE (user_id, role_id)

user_permission_overrides
  id uuid PK
  user_id uuid REFERENCES users(id) ON DELETE RESTRICT
  permission_code text REFERENCES permissions(code) ON DELETE RESTRICT
  effect text NOT NULL CHECK (IN ('ALLOW','DENY'))
  scope_type text NOT NULL CHECK (IN ('GLOBAL','DEPARTMENT','ASSIGNED','SELF','RESOURCE'))
  resource_type text NULL, resource_id uuid NULL
  expires_at timestamptz NULL
  reason text NOT NULL DEFAULT ''
  granted_by uuid NOT NULL, granted_at
  CHECK ((scope_type = 'RESOURCE') = (resource_id IS NOT NULL AND resource_type IS NOT NULL))
  UNIQUE (user_id, permission_code, effect, scope_type,
          coalesce(resource_id, '00000000-0000-0000-0000-000000000000'))
```

Three database-level guards back the client envelope and the delegation guard:

- `trg_role_assignment_principal_match` — rejects assigning a role whose
  `allowed_principal_type` differs from the subject's `principal_type`.
- `trg_role_permission_envelope` — rejects adding an `INTERNAL`-only permission to a role
  whose `allowed_principal_type = 'CLIENT'`.
- `trg_override_envelope` — rejects an `ALLOW` override of an `INTERNAL`-only permission
  for a `CLIENT` user.

Each is redundant with an application check. That redundancy is the point: TH-08 and TH-09
must not be defeatable by one bug.

## 5. Company structure

```
departments            id, code UNIQUE, name, description, status(ACTIVE|ARCHIVED),
                       lead_user_id NULL, version, timestamps
department_memberships id, department_id, user_id, role_in_department(MEMBER|LEAD),
                       joined_at, removed_at NULL
                       UNIQUE INDEX (department_id, user_id) WHERE removed_at IS NULL
                       trigger: user must be INTERNAL
```

No parent/child hierarchy. It is not needed by any module in this scope, and a self
-referencing tree brings cycle prevention, transitive visibility and recursive
authorisation queries with it. Adding it later is an additive migration; removing an
unnecessary one later is not. Recorded as a deliberate omission.

```
client_accounts        id, code UNIQUE, name, status(ACTIVE|SUSPENDED|ARCHIVED),
                       account_manager_user_id NULL REFERENCES users(id),
                       version, timestamps
                       trigger: account manager must be INTERNAL
client_memberships     id, client_account_id, user_id,
                       status(PENDING|ACTIVE|SUSPENDED|REMOVED),
                       invited_by, created_at, updated_at, activated_at
                       UNIQUE (client_account_id, user_id)
                       trigger: user must be CLIENT
```

A user may belong to several client accounts — the membership table is the relationship,
never a `users.client_id` column, precisely so that assumption never has to be unwound.

### `SUSPENDED` exists in the schema and has no endpoint that produces it

`client_memberships.status` and `client_accounts.status` both admit `SUSPENDED`, and
the visibility predicate correctly treats it as granting nothing. But the API offers
only `add_member` → `PENDING`, `activate` → `ACTIVE`, and `remove` → `REMOVED`.
**Nothing sets `SUSPENDED`.**

This was found while writing integration tests: the full `PENDING → ACTIVE →
SUSPENDED → REMOVED` walk is not API-drivable, and the tests set the column directly
to assert the behaviour *from* that state (reinstatement by `activate`, and no
visibility while suspended).

It is a gap rather than a bug — the state is honoured everywhere it is read, and an
operator can set it by hand — but "suspend a client's access without removing the
relationship" is an obvious operational need and there is no way to ask for it.
Recorded here rather than quietly adding an endpoint, because it needs a decision
about who may suspend and whether it is a dangerous permission.

## 6. Operations

```
projects              id, code UNIQUE, name, description,
                      status(ACTIVE|PAUSED|COMPLETED|ARCHIVED),
                      manager_user_id REFERENCES users(id),
                      department_id NULL REFERENCES departments(id),
                      start_date date NULL, target_date date NULL,
                      CHECK (target_date IS NULL OR start_date IS NULL OR target_date >= start_date),
                      version, created_by, timestamps
project_memberships   id, project_id, user_id, role_in_project(MEMBER|LEAD),
                      added_by, added_at, removed_at NULL
                      UNIQUE INDEX (project_id,user_id) WHERE removed_at IS NULL
                      trigger: user must be INTERNAL
project_client_links  id, project_id, client_account_id, shared_by, shared_at,
                      revoked_at NULL, revoked_by NULL, note
                      UNIQUE INDEX (project_id, client_account_id) WHERE revoked_at IS NULL
tasks                 id, project_id NOT NULL, title, description,
                      status(TODO|IN_PROGRESS|BLOCKED|DONE|CANCELLED),
                      priority(LOW|NORMAL|HIGH|URGENT), due_date date NULL,
                      client_visible boolean NOT NULL DEFAULT false,
                      version, created_by, timestamps, completed_at
task_assignees        id, task_id, user_id, assigned_by, assigned_at, removed_at NULL
                      UNIQUE INDEX (task_id,user_id) WHERE removed_at IS NULL
                      trigger: user must be INTERNAL
```

`client_visible` defaults to `false` and is a *task* property, not inherited from the
project. Sharing a project never silently exposes its task list.

## 7. Platform

```
system_settings   key text PK, value jsonb NOT NULL, value_type text NOT NULL,
                  is_security_sensitive boolean NOT NULL DEFAULT false,
                  description, version, updated_by, updated_at
feature_flags     key text PK, enabled boolean NOT NULL DEFAULT false,
                  is_security_sensitive boolean NOT NULL DEFAULT false,
                  description, version, updated_by, updated_at

idempotency_records
  id uuid PK
  principal_id uuid NOT NULL, operation text NOT NULL, idempotency_key text NOT NULL
  request_fingerprint bytea NOT NULL                -- SHA-256 of the canonical body
  status text NOT NULL CHECK (IN ('IN_PROGRESS','COMPLETED'))
  response_status integer NULL, response_body jsonb NULL
  created_at, completed_at, expires_at
  UNIQUE (principal_id, operation, idempotency_key)

outbox_events
  id uuid PK, event_type text NOT NULL, payload jsonb NOT NULL
  status text NOT NULL CHECK (IN ('PENDING','SENT','FAILED','DEAD'))
  attempts integer NOT NULL DEFAULT 0, max_attempts integer NOT NULL DEFAULT 8
  available_at timestamptz NOT NULL DEFAULT now()
  claimed_at, claimed_by text NULL, last_error text NULL
  created_at, completed_at
  INDEX (status, available_at) WHERE status IN ('PENDING','FAILED')
```

The idempotency key is scoped by `(principal, operation, key)` so one principal's key can
never replay another's response, and the body fingerprint turns "same key, different body"
into `409 IDEMPOTENCY_KEY_REUSED` instead of a wrong replay.

## 8. Audit

```
audit_events
  seq          bigserial PRIMARY KEY        -- chain order
  id           uuid NOT NULL UNIQUE
  occurred_at  timestamptz NOT NULL DEFAULT now()
  actor_user_id uuid NULL REFERENCES users(id) ON DELETE RESTRICT
  actor_principal_type text NULL
  actor_session_id uuid NULL
  action_code  text NOT NULL
  target_type  text NULL, target_id uuid NULL
  outcome      text NOT NULL CHECK (IN ('SUCCESS','DENIED','FAILURE'))
  request_id   text NULL
  source_ip_hint text NULL
  metadata     jsonb NOT NULL DEFAULT '{}'
  prev_hash    bytea NULL
  entry_hash   bytea NOT NULL

audit_chain_head
  id boolean PK DEFAULT true CHECK (id)
  last_seq bigint NOT NULL DEFAULT 0
  last_hash bytea NULL
```

Append is serialised by `SELECT … FROM audit_chain_head FOR UPDATE` inside the writing
transaction, which is what makes the chain well-defined under concurrency.
`entry_hash = HMAC-SHA256(chain_key, canonical(prev_hash ‖ seq ‖ id ‖ occurred_at ‖ actor ‖
action ‖ target ‖ outcome ‖ metadata))`, with a strictly specified canonical encoding
(length-prefixed fields — see `modules::audit::chain`). The chain key lives **outside** the
database.

`trg_audit_events_append_only` raises on `UPDATE` and on `DELETE`, unconditionally. The
runtime role is granted only `SELECT, INSERT`. The exhaustive list of what may never enter
`metadata` (passwords, any token, TOTP secrets, keys, full request bodies) is enforced by a
sanitising writer and asserted by test.

## 9. Foreign-key deletion policy

**No `ON DELETE CASCADE` appears anywhere in the schema.** Every foreign key is
`ON DELETE RESTRICT`. This was reviewed key by key.

The reasoning: every parent in this model is either a security principal or a business
record with historical meaning. There is no parent whose disappearance *should* silently
remove children — and cascade is exactly the mechanism by which "archive a department"
would one day quietly delete its audit trail. Lifecycle is expressed as
`archived`/`revoked`/`removed_at`/`status`, never as `DELETE`.

The only tables the runtime role may `DELETE` from at all are `idempotency_records` and
`outbox_events`, both of which are bounded caches of completed work with documented
retention. Everything else is append-or-update only, by grant.

## 10. Indexes and why each exists

| Index | Access path it serves |
| --- | --- |
| `users(email_normalized)` UNIQUE | login, invitation/registration collision check |
| `users(principal_type, status)` | internal user listing, suspended-account sweeps |
| `sessions(access_token_hash)` UNIQUE | **the hottest query in the system** — one per authenticated request |
| `sessions(user_id) WHERE revoked_at IS NULL` | "revoke all my sessions", session listing |
| `session_refresh_tokens(token_hash)` UNIQUE | refresh lookup |
| `session_refresh_tokens(session_id, generation)` UNIQUE | rotation ordering |
| `user_role_assignments(user_id)` | effective-permission query, every authorised request |
| `role_permissions(role_id)` | same query, second join |
| `user_permission_overrides(user_id, permission_code)` | same query, override leg |
| `department_memberships(user_id) WHERE removed_at IS NULL` | `DEPARTMENT` scope resolution |
| `project_memberships(user_id) WHERE removed_at IS NULL` | `ASSIGNED` scope resolution |
| `project_client_links(client_account_id) WHERE revoked_at IS NULL` | client project visibility |
| `client_memberships(user_id) WHERE status='ACTIVE'` | client visibility predicate |
| `tasks(project_id, status)` | task listing within a project |
| `tasks(project_id) WHERE client_visible` | client task projection |
| `audit_events(occurred_at DESC, seq DESC)` | audit listing / cursor pagination |
| `audit_events(actor_user_id, occurred_at DESC)` | "what did this principal do" |
| `outbox_events(available_at) WHERE status IN ('PENDING','FAILED')` | worker claim scan |
| `idempotency_records(expires_at)` | expiry sweep |

`EXPLAIN` output for the authentication and effective-permission queries is recorded in
`PERFORMANCE_REPORT.md`.
