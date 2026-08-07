# 11 — Future Realtime (WebSocket / Chat) Requirements

**Status: not built.** There is no WebSocket route, no upgrade handler, and no chat module
in the crate. The API is request/response only, which is why several controls in
`02-threat-model.md` can be stated as simply as they are — "the server is authoritative on
every request" (`03-authentication.md` §2) is a sentence that stops being true the moment a
socket stays open for an hour.

This document is the requirement set a realtime layer must satisfy before it ships, written
now because the properties that are cheap to design in are expensive to retrofit:
revocation, per-subscription authorisation, and backpressure all have to exist from the
first commit or they never do.

## 1. Why this is not "just add a `/ws` route"

The existing security model rests on a structural assumption: **authority is re-derived from
the database on every request** (no caching, `04-authorization.md` §11), so a role change or
a session revocation takes effect on the *next* request, and the next request is at most a
few seconds away.

A WebSocket inverts that. One authorisation decision at connect time can govern hours of
data flow: every control that was "checked per request" becomes "checked once unless
something makes it check again", and building that "something" is the substance of §6.

## 2. Risks a long-lived connection introduces that a request/response API does not

| Risk | Why request/response is immune | What the realtime layer must do |
| --- | --- | --- |
| **Stale authority** | Permissions are re-read per request; a revoked grant is dead within one request | Re-evaluate on privilege change and on a bounded interval; drop subscriptions that no longer authorise |
| **Revocation does not land** | Revocation is one `UPDATE`; the next lookup fails | An explicit revocation signal that closes the socket (§6) — the socket is not doing lookups on its own |
| **Server-initiated push to the wrong principal** | The server only ever answers; it never volunteers data | Every outbound frame is addressed by subscription, and every subscription was authorised for that principal individually |
| **Unbounded connection lifetime as a resource** | A request ends | Idle timeouts, absolute connection lifetime, per-principal connection caps |
| **Backpressure / slow consumer** | The response is written and the socket closes | Bounded per-connection send queue; drop the connection rather than buffering without limit |
| **Rate limiting has no natural unit** | One request = one unit, limited per IP/account/operation | Limit inbound frames per connection *and* aggregate per principal across connections |
| **Cross-origin reachability** | The API reads no cookies, so a hostile page gains nothing (`02-threat-model.md` §5) | `Origin` validation becomes load-bearing once the BFF introduces cookies (§9) |
| **Credential placement** | Bearer header only, and a token in a query string is actively rejected | The browser `WebSocket` constructor cannot set headers — hence §4 |
| **Audit volume** | One action, one audit row | Per-frame auditing is infeasible; audit connection lifecycle and mutations only (§10) |

## 3. Transport

**WSS only in production.** Startup validation refuses a configuration that permits plain
`ws://` outside the development profile, in the same fail-closed style as the CORS and
secret checks (`02-threat-model.md` TH-37, TH-41). A downgraded socket exposes the bearer
token and every message body to any network position between the client and the edge, and
unlike a plain HTTP request there is no redirect-to-HTTPS that happens before the credential
is sent.

The upgrade traverses the same edge proxy and trusted-proxy handling as HTTP, so client IP
attribution for rate limiting keeps the guarantees of TH-38 rather than inventing a second
answer to "who is this".

## 4. Connection authentication

The connection carries **the same opaque `rb_at_` bearer token** as the HTTP API. No new
token type, no socket-specific credential, no long-lived "realtime key" — a second
credential type is a second revocation path, and the second one is always the one that gets
forgotten.

Two acceptable placements:

1. **`Sec-WebSocket-Protocol` header.** The client sends two subprotocol values — a protocol
   name and the token — and the server echoes back only the protocol name. This is the one
   header the browser `WebSocket` constructor can influence, which is why it is used despite
   being a slight abuse of the field's purpose.
2. **A post-connect auth frame.** The socket opens unauthenticated in a `PENDING_AUTH` state
   accepting exactly one message type — the auth frame — with a short deadline after which
   the server closes the connection. Until authenticated it may subscribe to nothing and
   receives nothing. This mirrors the `pending_mfa` session state of `03-authentication.md`
   §4: a real connection with a hard gate in front of every capability.

Whichever is chosen, validation is the existing session lookup — digest, `revoked_at IS
NULL`, all four expiry checks, owning user `ACTIVE`, `pending_mfa = false`. A session in
`pending_mfa` must not be able to open a socket at all; otherwise the socket becomes the
window in which a password-only session can act, which §4 of the authentication document
exists to eliminate.

### Why not a query-string token

`wss://api.example.com/ws?token=rb_at_…` is the most common pattern in the wild and it is
refused here, for the same reason TH-36 already rejects tokens in query strings on the HTTP
API — the API returns `TOKEN_IN_QUERY_STRING` rather than quietly accepting one:

- Query strings are written to edge-proxy and load-balancer access logs by default, where
  they are retained, shipped to log aggregation, and readable by anyone with log access —
  turning a credential into a log artefact.
- They appear in `Referer` headers, browser history, crash reports, and error-tracking
  payloads.
- Log redaction is a denylist maintained by hand; the first new proxy or log-format change
  reintroduces the leak silently.

The upgrade URL must therefore contain no credential material. If the transport ever needs a
fallback that cannot set headers, the answer is the post-connect auth frame, not the URL.

## 5. Subscription authorisation

Authentication at connect answers "who". It answers nothing about "what".

- **Every subscription is authorised individually, at subscribe time**, through the same
  evaluator with the same resource context as the equivalent HTTP read. Subscribing to
  project `X` runs the identical decision as `GET /projects/X`, including the object-level
  check and, for CLIENT principals, the visibility predicate of `04-authorization.md` §9.
- **There is no wildcard subscription.** No "subscribe to all projects", no server-side
  fan-out that filters afterwards. A narrow scope compiles into a filtered set of explicit
  subscriptions, for the same reason list endpoints compile scopes into SQL predicates
  rather than fetching everything and filtering in Rust.
- **A denied subscription follows the `404`/`403` rule of `04-authorization.md` §10** — a
  CLIENT asking about an invisible resource gets the not-found form, so the socket does not
  become an existence oracle that the HTTP API refuses to be.
- **Outbound frames are addressed by subscription, never broadcast.** The publisher resolves
  which subscriptions match an event; a connection receives a frame only because it holds an
  authorised subscription for that exact resource.
- **Field-level projection is re-applied per recipient.** A task event delivered to a CLIENT
  subscriber carries the client projection, not the internal representation, using the
  service layer's projection shared with the HTTP path — not re-implemented in the realtime
  module, because two projections drift and the drift is a disclosure.

## 6. Revocation and privilege change

This is the requirement most likely to be skipped and the one with the worst failure mode: a
suspended user, or a user whose role was just removed, continuing to receive live data.

Since the socket performs no per-request session lookup, revocation must be *pushed*:

```
  service layer mutation                       realtime layer
  ─────────────────────────                    ──────────────────────────────────
  session revoked / user suspended  ─┐
  password changed (revokes all)    ─┤
  role assigned / removed           ─┼─▶ revocation signal channel ─▶ connection registry
  override added / removed          ─┤    (in-process broadcast today;                │
  client link revoked               ─┘     durable pub/sub when multi-instance)        ▼
                                                             affected sockets: close (session
                                                             revoked) or re-evaluate every
                                                             subscription (authority changed)
```

Requirements on that channel:

- **Emitted inside the same transaction as the change**, or from the transactional outbox, so
  a committed revocation cannot fail to produce a signal. A best-effort notification issued
  after commit is lost on a crash between the two, leaving a live socket with dead authority.
- **`users.security_version` is the correlation key.** It is already bumped on every
  privilege change (`04-authorization.md` §11) precisely so a consumer can detect that a
  principal's capability set changed; a connection holding an older value must re-evaluate.
- **Session revocation closes the socket** with a defined close code, rather than merely
  unsubscribing. The connection's authority came from that session; without it there is no
  principal left to serve.
- **A bounded re-evaluation interval as a backstop** (minutes, not hours), so that a lost
  signal degrades to a delay rather than to an indefinite stale grant. The signal is the
  mechanism; the interval is the safety net for the signal failing.
- **Multi-instance correctness is a release gate**, in the same shape as RR-3 for rate
  limiting: an in-process broadcast is honest for one instance and silently wrong for two,
  because the socket and the mutation may land on different processes. Horizontal scaling
  requires the durable channel *before* deployment, not after.

## 7. Message and connection bounds

| Bound | Requirement | Rationale |
| --- | --- | --- |
| Max frame size | Well below the 256 KB HTTP body limit; frames are not a bulk-transfer channel | A parser fed unbounded input is the cheapest denial-of-service available (TH-33) |
| Max message size after fragment reassembly | Explicit ceiling; abort the connection on exceed | Reassembly is where "small frames" become a large allocation |
| Inbound frames per connection | Token bucket per connection | One socket must not be able to spend the whole process budget |
| Inbound frames per principal | Aggregate across that principal's connections | Otherwise the per-connection limit is bypassed by opening more connections |
| Concurrent connections per principal | Hard cap, connection refused past it | Bounds a compromised or buggy client; also bounds a future AI agent runtime (`10-future-ai-mcp-security.md` §8) |
| Concurrent connections per process | Hard cap with a clear refusal | Protects asset A8; a socket costs memory and a task even when idle |
| Subscriptions per connection | Hard cap | Each subscription is an authorisation decision and a routing entry |
| Send queue depth per connection | Bounded; on overflow close the connection | A slow consumer must not be able to make the server buffer without limit |
| Heartbeat | Server-initiated ping on an interval; close on missed pongs | Half-open TCP connections otherwise accumulate as invisible leaks |
| Idle timeout | Close after a period with no application traffic | An idle authenticated socket is standing authority with no purpose |
| Absolute connection lifetime | Close and require reconnect, independent of activity | Forces re-authentication periodically, bounding the value of any single stolen token; mirrors the session `absolute_expires_at` ceiling |

Every refusal above is a defined close code with a stable meaning, so a client can
distinguish "you were rate limited, back off" from "your session is gone, re-authenticate"
from "server is shutting down, reconnect". A single opaque close code produces reconnect
storms, which turn a small failure into an outage.

## 8. Graceful shutdown

The existing shutdown sequence (`01-architecture.md` §5) drains in-flight requests. Sockets
must join it: stop accepting upgrades, send a "server going away" close to open connections
with a jittered deadline, then terminate. Without jitter every client reconnects
simultaneously and the restarted process is immediately overwhelmed.

## 9. Origin validation

Today the API reads no cookies, so a hostile page cannot make an authenticated request on a
user's behalf and `Origin` is not load-bearing. **That changes when the BFF introduces
cookies** (`03-authentication.md` §11). WebSockets are not subject to the same-origin policy
in the way `fetch` is — a cross-origin upgrade is not blocked by CORS — so a cookie-bearing
socket opened from an attacker's page would be authenticated. Therefore:

- Validate `Origin` against an explicit allowlist on every upgrade, defaulting to deny, with
  production startup refusing a wildcard exactly as it does for CORS (TH-37).
- Keep the Rust API's own authentication header-only. If the BFF terminates the socket and
  proxies, the cookie/CSRF obligation stays with the BFF, and the API's surface is unchanged.

## 10. Audit and visibility

- **Audit connection lifecycle and authorisation outcomes**, not payloads: connection opened
  (principal, session, source-IP hint, request id), authentication failed, subscription
  authorised, subscription **denied**, connection closed with reason. Denied subscriptions
  are the signal that matters — a principal probing resource ids over a socket is the same
  behaviour `bola_suite` covers on HTTP and it must be equally visible.
- **Every mutation performed over the socket is audited identically to the HTTP path**, with
  the same `action_code` values. A chat message that changes state is a mutation.
- **Per-frame audit rows are not written.** The audit chain is globally serialised (RR-6);
  making it the write path for realtime traffic would make it the bottleneck and would bury
  security-relevant entries in noise. Message content, if it must be retained, belongs in a
  domain table, not in `audit_events`.
- Metrics that make abuse observable: open connections, connections per principal, frames in
  and out, send-queue high-water marks, close codes by reason, subscription denials.

## 11. Rules that must never be relaxed

1. No credential in a URL or query string, on the upgrade or anywhere else.
2. No plain `ws://` in production; the check fails startup, not a request.
3. No subscription without an individual authorisation decision, and no wildcard
   subscription.
4. Session revocation closes the socket; privilege change re-evaluates every subscription.
5. No realtime-specific token type, evaluator, or projection — the socket reuses the session
   model of `03-authentication.md` and the evaluator of `04-authorization.md` unchanged.
6. Every buffer, queue, and counter is bounded before the feature ships, not after the first
   incident.
