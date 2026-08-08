# Idempotency contract

Which endpoints honour `Idempotency-Key`, and exactly what the header promises.

Sources: `backend/src/platform/http/idempotency.rs` (the request wiring),
`backend/src/modules/outbox/idempotency.rs` (the record, the fingerprint, the
replay), and the six call sites.

## The endpoints — exactly six

Only these read the header. It is honoured on **creates and nothing else**: there
is no idempotent `PATCH`, no idempotent `DELETE`, and no idempotent membership or
assignment endpoint.

| Method | Path | Internal `operation` name | Required? |
|---|---|---|---|
| POST | `/api/v1/roles` | `roles.create` | optional |
| POST | `/api/v1/invitations` | `invitations.create` | optional |
| POST | `/api/v1/departments` | `departments.create` | optional |
| POST | `/api/v1/clients` | `clients.create` | optional |
| POST | `/api/v1/projects` | `projects.create` | optional |
| POST | `/api/v1/tasks` | `tasks.create` | optional |

**On every other endpoint the header is ignored entirely.** Sending it there is
harmless but buys nothing — the request is not deduplicated. Do not build a retry
strategy that assumes otherwise.

Two creates are conspicuously **not** on the list, and their absence is
deliberate:

* `POST /api/v1/registration` and `POST /api/v1/invitations/accept` — anonymous,
  so there is no principal to scope a key to. The record's uniqueness is
  `(principal_id, operation, key)`; an unscoped namespace would let one caller
  replay another's response by guessing a key.
* `POST /api/v1/bootstrap/root` — protected by an advisory lock and a permanent
  `409`, which is a stronger guarantee than a 24-hour record.

## Required or optional

**Always optional.** A request with no `Idempotency-Key` behaves exactly as it did
before the feature existed: the handler runs, no record is written, and there is no
extra database round trip. Idempotency is opt-in per request.

**Recommendation for the frontend: always send one on those six endpoints.** Send
a fresh UUIDv4 per distinct user intention — generated when the form is first
submitted, not per network attempt — and reuse that same key for every retry of
that intention.

## Key format

Validated by `IdempotencyKey::parse` before the body is even read, so an oversized
or control-bearing key is refused without buffering the document it came with.

| Rule | Value |
|---|---|
| Length | 8–200 bytes inclusive |
| Alphabet | printable ASCII `0x21`–`0x7E` — no spaces, no control characters, no non-ASCII |
| Case | significant; the key is stored verbatim |

A UUID is the recommended choice. A ULID works. A timestamp alone does not — below
8 characters the key space is small enough to collide between concurrent clients.

**An invalid key is an error, not a silent ignore.** Rejections:

| Condition | Response |
|---|---|
| Shorter than 8 | `400 VALIDATION_FAILED`, `errors[0].field = "Idempotency-Key"`, `code = "TOO_SHORT"` |
| Longer than 200 | `400 VALIDATION_FAILED`, `code = "TOO_LONG"` |
| Contains a space, a control character, or non-ASCII | `400 VALIDATION_FAILED`, `code = "INVALID_FORMAT"` |

Silently discarding a malformed key would hand the client a *non*-idempotent
request it believes is idempotent, which is the exact failure the module exists to
prevent. Control characters are rejected rather than sanitised for the same reason:
a sanitised key is a different key, and would defeat the deduplication the caller
asked for. (It is also a log-injection vector — a `\r\n` in the header would forge
a log record.)

The header name is lowercase `idempotency-key` on the wire and is on the CORS
allow-list, so a browser can send it cross-origin.

## Scoping

A record is keyed on `(principal_id, operation, idempotency_key)`.

* **Per principal.** Your key can never replay another user's response, and theirs
  can never replay yours.
* **Per operation.** The same key on `POST /projects` and `POST /tasks` are two
  independent records. You may reuse one key across different endpoints, though
  there is no reason to.

## Replay behaviour

The fingerprint is a **SHA-256 over the raw request bytes**, taken before
deserialisation. Two consequences a client must internalise:

1. **Byte-identical retries replay.** Serialise the body once and resend those
   exact bytes. Do not re-serialise from an object on retry — a different key
   ordering, different whitespace, or a differently formatted number produces a
   different fingerprint and therefore a `409`, not a replay. That is the safe
   direction to be wrong in, but it is a real trap.
2. **Unknown fields are not normalised away.** A fingerprint over the parsed value
   would make a body with a smuggled field equal to one without; bytes are the
   honest unit.

| Situation | Response |
|---|---|
| First request with this key | The handler runs. Success is `201 Created` with the created resource. The status and body are stored. |
| Retry, same key, **byte-identical** body, first attempt completed | The stored response is replayed **verbatim** — same status (`201`), same body. Indistinguishable from the original. |
| Retry, same key, **different** body | `409 IDEMPOTENCY_KEY_REUSED`. |
| Retry arrives while the first is still in flight | The server polls the record for up to **1.5 seconds** (every 25 ms) and replays the winner's response if it lands in time. If the window closes first: `409 IDEMPOTENCY_RACE`. |
| The first attempt **failed** (validation, authorisation, a constraint) | The reservation is **released**. The key is free again, and a corrected retry — same key, corrected body — is served normally rather than being poisoned for 24 hours. |
| The response body exceeded 256 KiB | The record is still marked complete (the key stays consumed), but the stored body is the sentinel `{"_replay_body_omitted": true}`. A replay then returns that instead of the resource. Not reachable with the current response shapes, but a client should not crash on it. |

The 1.5-second wait exists because the common case is a client that fired twice
because the first response was slow. Answering `409` immediately would error a
request that is about to succeed. The window is deliberately far below the 30-second
request timeout so a duplicate can never be the thing that holds a connection open.

## Key lifetime

**24 hours**, from the moment the key is first reserved. A scheduled sweep deletes
records past `expires_at`.

Long enough to cover any realistic retry, including a human retrying the next
morning. After that window the key is forgotten: reusing it will create a **second**
object rather than replaying. If your client persists pending operations across
days, either regenerate the key or accept that the deduplication guarantee has
expired.

The request body itself is never stored — only the 32-byte digest. A create body
can contain a password, and a 24-hour retention table is not a place for one.

## What the frontend should do on retry

```
On network failure / timeout / 5xx on one of the six create endpoints:

  1. Retry with the SAME Idempotency-Key and the SAME body bytes.
  2. 201 -> done. You cannot tell a fresh create from a replay, and you
            do not need to: the resource exists exactly once.
  3. 409 IDEMPOTENCY_RACE -> back off ~1-2s, retry with the same key.
                             Cap at two or three attempts.
  4. 409 IDEMPOTENCY_KEY_REUSED -> your body changed. This is a client bug.
                             Do NOT retry with this key; surface it.
  5. 4xx other -> the work did not happen and the key was released.
                  Fix the payload and retry with the same key if you like.
  6. 503 -> the dependency was down. Retry with the same key after backoff.
```

Concrete rules that follow:

* **Generate the key at intent time, not at send time.** One key per "user pressed
  Create", reused across every attempt of that press. A key generated per HTTP
  attempt provides no protection at all.
* **Freeze the serialised body with the key.** Store the exact bytes alongside the
  key in whatever retry queue you use.
* **A double-submitted form is the case this solves.** If your create button can be
  pressed twice, the second press with the same key replays the first response
  rather than creating a duplicate. This is the correct fix for double-submit; a
  client-side disabled button is a nicety, not a guarantee.
* **Do not use `Idempotency-Key` as a client-side identifier.** It is not returned
  in the response body and it is not the resource id.
* **`Content-Type: application/json` is mandatory on these endpoints.** The
  `Idempotent<T>` extractor enforces the same strict content type as the ordinary
  JSON extractor; anything else is `415 UNSUPPORTED_MEDIA_TYPE`, checked before the
  key is even parsed.
* **Replaying after a step-up prompt works.** When a create answers
  `403 STEP_UP_REQUIRED`, the reservation was released, so completing MFA and
  replaying with the same key is served as a fresh request. This is the intended
  flow for `POST /api/v1/roles` and for `POST /api/v1/invitations` carrying a
  dangerous role.

## What it does not promise

* It does not make the operation idempotent *in the domain*. It replays a stored
  HTTP response; it does not re-derive one. If the resource has since been edited,
  the replayed body is the body as it was at creation.
* It does not span principals, operations, or the 24-hour window.
* It does not apply to updates, deletes, or membership changes. For those, use
  `version` (see `CONCURRENCY_CONTRACT.md`) and treat the endpoint's own conflict
  codes — `ALREADY_A_MEMBER`, `ALREADY_ASSIGNED`, `ALREADY_ARCHIVED` — as the
  "already done" signal.
