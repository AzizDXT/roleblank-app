# ADR-006 — Audit integrity

**Status:** Accepted · **Date:** 2026-08-07

## Context

Audit history is asset A5. An administrator who can edit it can erase their own escalation.
The requirement is *tamper-evidence* — not tamper-proofing, which is impossible against an
adversary who owns the infrastructure.

## Decision

Four independent controls, plus an explicitly bounded claim.

1. **No mutating surface.** The API exposes `GET /api/v1/audit/events` and nothing else.
   There is no update, no delete, no bulk operation, no admin escape hatch.
2. **Database triggers.** `trg_audit_events_append_only` raises on `UPDATE` and on `DELETE`,
   unconditionally, with no actor-dependent branch.
3. **Privilege separation.** The runtime role holds `SELECT, INSERT` on `audit_events` and
   nothing else. It does not own the table, so it cannot `ALTER TABLE … DISABLE TRIGGER`.
4. **HMAC-SHA256 hash chain** with the key held outside the database.

### Chain construction

```
entry_hash = HMAC-SHA256(chain_key, canonical_bytes)

canonical_bytes = LP(prev_hash) ‖ LP(seq_be) ‖ LP(id) ‖ LP(occurred_at_unix_nanos_be)
                ‖ LP(actor_user_id) ‖ LP(actor_principal_type) ‖ LP(actor_session_id)
                ‖ LP(action_code) ‖ LP(target_type) ‖ LP(target_id)
                ‖ LP(outcome) ‖ LP(request_id) ‖ LP(metadata_canonical_json)

LP(x)  = 8-byte big-endian length ‖ bytes(x)          (absent field ⇒ length 0xFFFF_FFFF_FFFF_FFFF)
```

Length prefixing every field is not decoration: without it, `("ab","c")` and `("a","bc")`
serialise identically, and an attacker could shift content across field boundaries while
preserving the hash. `metadata_canonical_json` sorts object keys recursively so that
serialisation order cannot vary the digest.

### Concurrency

Appends serialise on `SELECT … FROM audit_chain_head FOR UPDATE`, taken inside the writing
transaction. Two concurrent audited operations therefore produce a well-defined chain order,
and the chain head is updated in the same transaction as the row it describes.

## The claim, stated exactly

> Any modification, deletion or reordering of `audit_events` performed **without the chain
> key** is detected by `roleblank-api verify-audit`.

That is the entire claim. It is **not** claimed that audit history is tamper-proof. An
adversary holding both the database and the chain key can rewrite the chain consistently
and no verification will notice. This is inherent: the verifier and the forger would hold
identical capabilities. The mitigations that make the claim useful in practice are
operational — the chain key is a separate secret from the database credentials, and export
of verified chain heads to an external location is documented in `08-operations.md`.

`verify-audit` reports: rows scanned, first divergent `seq` if any, whether the head matches
the last row, and a non-zero exit code on any failure.

## What must never enter an audit record

Passwords, password hashes, access/refresh tokens or their digests, reset tokens, invitation
tokens, TOTP secrets, recovery codes, encryption keys, and complete request bodies. The
audit writer takes a typed, closed metadata structure rather than an arbitrary map, and a
test asserts that no known-secret value can round-trip into `metadata`.

## Operational vs. audit logging

Deliberately separate systems. Operational logs (`tracing`, JSON to stdout) are for
debugging and are expected to be rotated and discarded by infrastructure. Audit events are
business/security accountability records in PostgreSQL and are never rotated by log tooling.
Someone with permission to clear logs has no path to audit history.

## Consequences

- Audited mutations are globally serialised on the chain head. At company write volumes this
  is measured and acceptable; the number is in `PERFORMANCE_REPORT.md`. If it ever becomes a
  bottleneck the remedy is per-partition chains, which is a schema change, not a redesign.
- Rotating the chain key invalidates verification of prior entries unless the old key is
  retained. The `verify-audit` command therefore accepts a key *set*, and rotation procedure
  is documented.
- `audit_events` grows without bound. Retention is a policy decision documented in
  `08-operations.md`; the application never deletes.

## Alternatives rejected

| Alternative | Why not |
| --- | --- |
| Plain SHA-256 chain (no key) | Anyone who can write rows can recompute the whole chain; provides no evidence at all |
| Per-row independent hashes | Detects field edits but not deletion or reordering — the two things an attacker actually does |
| Append to an external WORM store synchronously | Introduces an external dependency in the commit path; a store outage would block business writes |
| Blockchain / external notary | Enormous complexity; the realistic adversary is a malicious administrator, not a global one |
| PostgreSQL logical replication to a locked replica | Good defence-in-depth and **recommended in operations**, but it is infrastructure, not an application control, and does not detect pre-replication tampering |
