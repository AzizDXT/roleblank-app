# 08 — Operations

Everything an operator needs to run RoleBlank OS, and the reasoning behind the
parts that look inconvenient.

## 1. Environments

| Mode | `RB_ENV` | Posture |
| --- | --- | --- |
| Development | `development` | `.env` is loaded; loopback/RFC1918 proxies trusted; OpenAPI served; text logs |
| Test | `test` | As development, but `.env` still loaded and every test gets its own database |
| Production | `production` | `.env` is **not** read; strict validation; startup fails on any relaxation |

Production startup refuses to bind a port when any of the following is true. Each
corresponds to a real way a deployment has historically gone wrong.

- `RB_CORS_ALLOWED_ORIGINS` contains `*`, a non-`https://` origin, or a trailing slash
- `RB_PUBLIC_BASE_URL` is not `https://`, or points at localhost
- `RB_ENCRYPTION_KEY` or `RB_AUDIT_CHAIN_KEY` is all zero, the wrong length, or contains
  placeholder text (`changeme`, `example`, `insecure`, `dev_`, …)
- the two keys are **identical**
- `RB_BOOTSTRAP_SECRET` is shorter than 32 characters or contains placeholder text
- `DATABASE_URL` connects as `postgres`, `roleblank_migrator`, `root` or `admin`
- `DATABASE_URL` contains `sslmode=disable`
- Argon2 parameters are below the OWASP floor (19 456 KiB, 2 iterations)
- `RB_EXPOSE_OPENAPI` is on
- `RB_LOG_JSON` is off
- `RB_MAIL_PROVIDER` is a development sink

All problems are reported together, not one per restart.

```bash
roleblank-api check-config     # same validation, no port bound — use as a deploy gate
```

## 2. Database roles — the separation and why

Two identities, always.

| Role | Owns the schema | Used by | May |
| --- | --- | --- | --- |
| `roleblank_migrator` | **yes** | `roleblank-api migrate`, only | DDL on its own schema |
| `roleblank_app` | no | the running API | DML, per explicit grants |

The runtime role cannot drop a table, alter the schema, disable a trigger, rewrite
migration history, create anything in `public`, delete a user, or modify an audit
event. Verified by executing those statements as that role — see
`tests/security/runtime_role.rs`.

### Provisioning

Development:

```powershell
.\scripts\rb.ps1 db-provision      # runs ops/sql/provision_dev.sql
```

Production — adapt `ops/sql/provision_dev.sql`, with real credentials from the
secret manager and **without** the `CREATEDB` grant the development migrator has
(that exists only so the test harness can create throwaway databases):

```sql
CREATE ROLE roleblank_migrator LOGIN PASSWORD :'migrator_pw'
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION;
CREATE ROLE roleblank_app LOGIN PASSWORD :'app_pw'
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION;
CREATE DATABASE roleblank OWNER roleblank_migrator;
\connect roleblank
ALTER SCHEMA public OWNER TO roleblank_migrator;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON DATABASE roleblank FROM PUBLIC;
GRANT CONNECT ON DATABASE roleblank TO roleblank_app, roleblank_migrator;
GRANT ALL   ON SCHEMA public TO roleblank_migrator;
GRANT USAGE ON SCHEMA public TO roleblank_app;
```

Table grants are applied by migration `0009_runtime_grants.sql`. Default privileges
for future tables are deliberately **not** granted: a new table should be an
explicit decision about what the runtime role may do with it.

## 3. Migrations

```bash
roleblank-api migrate      # as the migrator role, explicitly, before deploying
```

Never folded into `serve`. Implicit migration on startup races every replica of a
rolling deploy against the same schema change and turns a bad migration into an
outage rather than a failed step. `serve` refuses to start when the schema is
behind the binary, so the ordering is enforced rather than documented.

Migrations are **forward-only**. There are no down migrations: an automatic
rollback of a schema change against live data is how data gets destroyed.

### Destructive schema change — expand, migrate, contract

Never in one release.

1. **Expand** — add the new column/table as nullable, deploy, write to both.
2. **Migrate** — backfill in batches, verify, run both paths in production.
3. **Contract** — a later release stops writing the old shape; a release after
   *that* drops it, once rollback to the previous version is no longer needed.

A column is dropped only when no deployed version still reads it. Write the plan in
the migration's header comment before writing the SQL.

## 4. First-run bootstrap

```bash
export RB_BOOTSTRAP_SECRET="$(openssl rand -base64 48)"    # into the secret manager
roleblank-api migrate
roleblank-api serve

curl -s https://os.example.com/api/v1/bootstrap/status      # {"initialized": false}

curl -X POST https://os.example.com/api/v1/bootstrap/root \
  -H 'Content-Type: application/json' \
  -d '{"bootstrap_secret":"'"$RB_BOOTSTRAP_SECRET"'",
       "email":"owner@company.com",
       "display_name":"System Owner",
       "password":"<a long passphrase>"}'
```

The owner lands in `MFA_ENROLMENT_REQUIRED`: it can log in, but the session reaches
only `/api/v1/auth/mfa/*` until a TOTP factor is activated. Complete enrolment
immediately and **store the recovery codes offline** — they are displayed once.

**Then remove `RB_BOOTSTRAP_SECRET` from production secret configuration.** The
endpoint refuses to run a second time regardless, but a secret with no remaining
purpose is pure risk.

## 5. Key management and rotation

| Key | Rotatable | Procedure |
| --- | --- | --- |
| `RB_ENCRYPTION_KEY` | yes | below |
| `RB_AUDIT_CHAIN_KEY` | yes, with care | below |
| `RB_BOOTSTRAP_SECRET` | n/a | delete after initialisation |
| database passwords | yes | standard credential rotation; the app reconnects |

### Encryption key rotation

Every ciphertext stores its `key_version`, so rotation does not require a
big-bang re-encryption.

1. Generate a new key. Set `RB_ENCRYPTION_KEY` to it and bump
   `RB_ENCRYPTION_KEY_VERSION`.
2. Set `RB_ENCRYPTION_KEY_PREVIOUS` and `RB_ENCRYPTION_KEY_PREVIOUS_VERSION` to the
   outgoing pair. Deploy. New writes use the new version; old rows still decrypt.
3. Re-enrol or re-encrypt affected factors. Only `mfa_factors` is encrypted today,
   so the affected population is small and can simply be asked to re-enrol.
4. Once no row references the old version, remove the `_PREVIOUS` variables.

Removing the previous key too early makes the affected rows permanently
unreadable. The application reports an unknown key version distinctly from a
decryption failure, so this shows up as an operational error rather than as a
false tampering signal.

### Audit chain key rotation

Rotating this key means entries written under the old key can only be verified
with the old key. **Retain every historical chain key** for as long as the audit
history it covers is retained. Record the rotation point (the `seq` at which the
new key took effect) alongside the keys.

Store a copy of the chain key somewhere the database administrator cannot reach.
If the same person holds both the database and the key, the tamper-evidence claim
in ADR-006 is void — not weakened, void.

## 6. Ownership recovery (offline, deliberately inconvenient)

There is **no ownership-transfer API**. Any code path that could legitimately move
ownership is a code path an attacker wants. ADR-004 explains the reasoning.

If the owner's credentials, authenticator and every recovery code are lost:

1. Declare a change-controlled maintenance window. Two people, both recorded.
2. Take a verified backup (§8) and verify the audit chain **before** touching
   anything: `roleblank-api verify-audit`. Record the result.
3. Stop the API.
4. As a database superuser — not the migrator, not the app role:

```sql
BEGIN;
-- The triggers exist to stop the application. This is the documented exception,
-- performed by a human, with the service stopped, under change control.
ALTER TABLE system_ownership DISABLE TRIGGER trg_system_ownership_immutable;
ALTER TABLE users            DISABLE TRIGGER trg_users_protect_root;

-- Point ownership at an existing, ACTIVE, INTERNAL user.
UPDATE system_ownership SET root_user_id = '<new-owner-uuid>';
UPDATE users SET mfa_required = true WHERE id = '<new-owner-uuid>';

-- Record it in the audit log itself. The chain will not verify across this entry
-- unless it is written through the application, so write it here AND record the
-- event out of band in the change record.
INSERT INTO audit_events (id, action_code, outcome, metadata, entry_hash)
VALUES (gen_random_uuid(), 'ROOT.PROTECTION_TRIGGERED', 'SUCCESS',
        '{"procedure":"offline_ownership_recovery"}'::jsonb,
        decode(repeat('00',32),'hex'));

ALTER TABLE users            ENABLE TRIGGER trg_users_protect_root;
ALTER TABLE system_ownership ENABLE TRIGGER trg_system_ownership_immutable;
COMMIT;
```

5. Restart, log in as the new owner, complete MFA enrolment, store the new recovery
   codes offline.
6. Re-run `verify-audit`. **It will report a break at the manually inserted entry.**
   That is correct and expected — record the `seq` in the change record so a future
   auditor can distinguish a documented recovery from an attack.

## 7. Health, readiness and shutdown

| Endpoint | Meaning |
| --- | --- |
| `GET /health/live` | the process is running. No database call — a liveness probe that fails during a database blip causes a restart loop that makes the outage worse |
| `GET /health/ready` | the database is reachable **and** the schema matches the binary. `503` otherwise |

Neither leaks a hostname, a driver message, a schema version or any topology.

Shutdown on SIGTERM/SIGINT: stop accepting connections → drain in-flight requests →
cancel the outbox worker and wait up to 15 s → close the pool. Set the orchestrator's
termination grace period to **at least 45 s**; a shorter one converts a clean drain
into a hard kill.

## 8. Backups

```bash
./scripts/backup_dev.sh                       # pg_dump -Fc into backups/
RB_CONFIRM_RESTORE=yes ./scripts/restore_dev.sh
```

Production requirements:

- **Logical** (`pg_dump -Fc`) daily, for portability and selective restore.
- **Physical / PITR** — WAL archiving with a documented recovery window. Logical
  backups alone mean the recovery point is "last night".
- **Encrypted at rest** with a key that is *not* the application's encryption key.
  A backup encrypted with the key stored next to it is not encrypted.
- **Retention**: 7 daily, 4 weekly, 12 monthly. Longer for audit-bearing data if
  regulation requires it — the audit table is never pruned by the application.
- **The chain key must be backed up separately** and its restore tested, or restored
  audit history is unverifiable.

> **A backup that has never been restored is not a backup.** Restore to a scratch
> database monthly and verify: row counts on `users` and `audit_events`, then
> `roleblank-api verify-audit` against the restored copy. `restore_dev.sh` prints
> those counts for exactly this reason. Record each drill.

## 9. Observability

- Logs: JSON on stdout, one object per line. Correlate on `request_id`, which is
  also returned to the client in `X-Request-Id` and stored on audit events.
- Metrics: `GET /metrics`, Prometheus text. Deliberately carries **no**
  principal-identifying labels. Restrict it by network policy — it is not
  authenticated, because a metrics scraper that has to authenticate is a metrics
  scraper that stops working during an incident.

Alert on, at minimum:

| Signal | Why |
| --- | --- |
| `auth_failures_total` rate spike | credential stuffing |
| `authz_denials_total` rate spike | a compromised account probing, or a broken deployment |
| `AUTH.REFRESH_REUSE_DETECTED` audit events | **token theft — investigate immediately** |
| `ROOT.PROTECTION_TRIGGERED` audit events | someone attempted to modify the owner |
| `outbox_failures_total`, rows in `DEAD` | side effects are being lost |
| `db_pool_idle` at zero, sustained | pool exhaustion is imminent |
| `/health/ready` failing | schema drift or database loss |
| `verify-audit` non-zero exit | **tampering or corruption** |

Run `verify-audit` on a schedule (daily) and export the verified head `seq` and
hash to a location the database administrator cannot write. That export is what
turns "the chain verifies" into evidence.

## 10. Capacity and tuning

Measure before changing anything; the numbers observed on the reference machine are
in `PERFORMANCE_REPORT.md`.

- **Pool size**: default `min(cpu * 2, 32)`. PostgreSQL degrades above roughly
  `cores * 2–4` active connections because of lock and buffer contention. More
  connections is usually slower, not faster.
- **Argon2 concurrency**: `RB_AUTH_HASHING_MAX_CONCURRENCY` × `RB_ARGON2_MEMORY_KIB`
  is the worst-case resident memory devoted to password hashing. At the defaults
  that is 8 × 19 MiB ≈ 152 MiB. Size the container accordingly.
- **Audit throughput**: audited mutations serialise on the chain-head lock. This is
  a deliberate correctness-over-throughput choice (ADR-006). If it ever binds, the
  remedy is per-partition chains, which is a schema change, not a redesign.

## 11. Deployment posture

The development compose file is **not** production orchestration. Production
additionally requires:

- TLS terminated at the edge; the API itself speaks plain HTTP inside the network
- `RB_TRUSTED_PROXIES` set to the edge's CIDRs — otherwise rate limiting keys on the
  proxy's address and every client shares one bucket
- the database **not** published on any external interface
- secrets injected at runtime, never baked into an image
- non-root user (the image uses uid 10001), read-only root filesystem, all Linux
  capabilities dropped, CPU and memory limits set
- network segmentation between the API and the database
- `/metrics` reachable only from the scraper

**Horizontal scaling is gated.** Rate limiting is currently per-process (RR-3). A
second replica silently multiplies every quota by the replica count. The Redis
implementation of `trait RateLimiter` must ship *before* a second replica does.

## 12. Deferred, and what it means operationally

| Deferred | Operational consequence today |
| --- | --- |
| Production mail provider | Password reset and invitation emails are **not delivered**. Production refuses to start with a development sink; set `RB_MAIL_PROVIDER=disabled` to acknowledge, which makes those flows fail loudly rather than silently. Onboarding must be done by an administrator creating accounts directly until a provider ships |
| Distributed rate limiting | Single replica only |
| File storage | No upload surface exists |
| Realtime / chat | No WebSocket surface exists |
| AI / MCP | No agent surface exists; the `ai.assistant` flag is off and is not an access control |

---

## 13. Rate limiting

Full design and reasoning: `docs/backend/RATE_LIMIT_ARCHITECTURE.md`. What an
operator needs day to day:

**Three classes.** Per-operation anonymous budgets (login, MFA, reset,
registration, invitation acceptance, bootstrap); a general authenticated budget
keyed on the **user id**; and a coarse pre-authentication ceiling keyed on the
client address.

**Every limit is tunable**, and none may be zero — a zero quota would refuse every
request, so it is rejected at startup rather than read as "unlimited". Names and
defaults are in `backend/.env.example`.

**Tuning during an incident.** Tighten `RB_RATE_GENERAL_PER_PRINCIPAL_PER_MINUTE`
first: it is keyed per user, so it slows one abusive account without touching
anyone else. Reach for `RB_RATE_GENERAL_PER_IP_PER_MINUTE` only when the source is
an address rather than an account, and remember that a corporate NAT is a crowd.

**ROOT is not exempt**, only larger (`RB_RATE_GENERAL_ROOT_PER_MINUTE`). No lockout
is possible: the buckets refill continuously, and the authenticated budget is keyed
on the user id, so an external attacker cannot consume the owner's budget without
the owner's token.

**Single instance only.** Enforcement is per process. Running more than one API
instance requires a distributed implementation of the `RateLimiter` trait first —
recorded as release gate RR-3.

## 14. Mail

**Production requires a delivery path.** `RB_MAIL_PROVIDER=smtp` is the production
transport: SMTP over TLS, either implicit (port 465) or with STARTTLS *required*
(port 587). Opportunistic STARTTLS is not offered, and port 25 is refused —
it is the relay port, is blocked on many networks, and its failure mode looks
exactly like "invitations stopped working".

Startup **fails** if:

* a development sink is configured in production;
* `RB_MAIL_PROVIDER=smtp` is set with any of host, username, password or from empty;
* `RB_MAIL_PROVIDER=disabled` in production **without** `RB_MAIL_ALLOW_DISABLED=true`.

That last one is deliberate and was a closure change. Invitations are the only path
to an internal account and password reset is the only path back into an existing
one, so a production deployment with no mail can neither onboard nor recover a
single user. It never *pretended* to deliver — `DisabledProvider` has always
returned an error — but it used to boot looking perfectly healthy. An operator who
genuinely wants that posture (accounts provisioned by other means) can still have
it, but has to say so out loud.

**Nothing logs a delivery URL or token.** Log lines carry the recipient *domain*
only: the local part is frequently the person's real name and is enough to
enumerate accounts from a log export.

**Delivery is at-least-once.** The worker claims a message, calls the provider, then
marks it sent; a crash in that window re-delivers. Closing that window would need a
distributed transaction across PostgreSQL and a third-party mail API, so instead the
property is documented and the handlers are safe to run twice.
