# Rate limiting architecture

What is enforced, where, with which key, and — as importantly — what is **not**
enforced. A control that is documented more confidently than it is implemented is
worse than an acknowledged gap, because a reviewer stops looking.

## The defect this design closes

Before closure, `middleware::apply` installed security headers, CORS, a method
guard, a body limit, a timeout, request-id and panic capture — and no rate limiter.
`keys::general_principal` and `keys::general_ip` existed and were called from
exactly one place in the crate: a key-collision unit test.

Measured against a live instance, 60 requests per principal to an endpoint that
principal may not use:

| Principal | Endpoint | Before | After |
|---|---|---|---|
| employee | `POST /projects/{id}/clients` | `403`×60, **0** × `429`, **60 audit rows** | `403`×20, `429`×40, **20 audit rows** |
| client | `GET /users` | `404`×60, **0** × `429` | `404`×20, `429`×40 |
| client | `GET /audit/events` | `404`×60, **0** × `429` | `429`×60 (budget already spent) |
| administrator | `GET /projects` | `403`×60, **0** × `429` | `403`×20, `429`×40 |
| ROOT | `GET /projects` | `200`×60, **0** × `429` | `200`×40, `429`×20 |

The audit table is append-only by construction — the runtime role holds only
`SELECT, INSERT` — and every append takes the global chain lock that every
legitimate mutation also needs. So the pre-fix shape was: **cheap for the attacker,
expensive and irreversible for the defender.** That asymmetry, not the `403` itself,
was the defect. Authorisation was correct throughout, before and after.

Reproducer: `scripts/repro_rate_limit.sh`.

## The three classes

### 1. Anonymous operation budgets — unchanged

Per-operation, mostly per-address, on the flows an unauthenticated caller can
reach: bootstrap, login (per IP *and* per account), MFA verification (per session),
token refresh, password reset, registration, invitation acceptance.

These keep **separate budgets on purpose**. Merging them has already caused one
production-shaped bug: invitation acceptance shared the registration bucket, so an
attacker hammering public registration could block invited colleagues behind the
same corporate NAT, and onboarding was capped at three people per hour per office.
`keys::invitation_accept_ip` carries that history in its own doc comment.

Login additionally resets its bucket on success, so someone who mistyped a password
four times is not still penalised afterwards.

### 2. General authenticated budget — new, and the main control

Applied in the principal extractors (`platform/http/extract.rs`), which is the
first point at which the principal is known.

**Keyed on the user id.** Both alternatives are wrong in a way that matters here:

* *Keyed on the address* — an office behind one NAT is many people sharing one
  budget, and one compromised machine starves its colleagues. This product's users
  are company staff; shared egress is the normal case, not the exception.
* *Keyed on the session* — sessions are cheap to mint with stolen credentials, so a
  compromised account would multiply its budget simply by logging in again.

A user id is the only key that gets both right, and both directions are pinned by
tests (`two_users_behind_one_address_do_not_share_a_budget`,
`one_principal_cannot_multiply_its_budget_with_more_sessions`).

**Ordering.** Authenticate → resolve principal → **charge the budget** → MFA gate →
authorisation → resource work. Charging before the MFA gate is deliberate and was a
bug fix: with the gate first, a session that had proved a password but not a second
factor was refused *before* reaching the limiter and could therefore repeat the
request for free, while the server paid a session lookup each time. The live
reproduction caught it — the administrator row above showed `429=0` where every
other principal was bounded. Pinned by
`a_session_pending_mfa_is_charged_the_general_budget`.

**It does not replace authorisation.** Every authorisation decision runs exactly as
before. Passing the limiter makes a request no more authorised than it was, and a
throttled response reveals nothing about whether the target exists — both pinned by
tests.

### 3. Pre-authentication address ceiling — new, coarse, deliberately generous

A middleware layer keyed on the client address, applied to every request before
authentication.

Its job is narrow: resolving a bearer token costs a database query *whether or not
the token is genuine*, so without this an attacker with invented tokens forces one
query per request while never authenticating. It cannot distinguish a busy office
from an attacker sharing its address, which is precisely why its quota is high and
why it is not the control that governs normal traffic.

It sits innermost in the layer stack, so it runs immediately before the handler's
extractors — after request-id assignment and inside the header layers, so a `429`
still comes back shaped like every other response.

## ROOT

ROOT is **not exempt**. An unbounded owner session is still a way to hurt the
system, and the owner is the likeliest target of a stolen-token attack.

ROOT gets a *larger* budget (`general_root_per_minute`, default 3 000/min against
600/min), for one reason: the owner is the account that puts the company back
together during an incident, and throttling it to an ordinary quota at exactly that
moment would be a self-inflicted outage.

**No lockout is possible.** Three properties combine:

1. The bucket refills continuously — it is a token bucket, not a fixed window — so
   an exhausted budget recovers on its own. There is no state requiring an
   administrator to intervene, which matters because for ROOT there is no such
   administrator.
2. The general budget is keyed on the **user id**, so an external attacker cannot
   consume ROOT's budget without ROOT's token. Sending bad requests at the system
   from outside cannot lock the owner out.
3. Only the anonymous *login* budget is address-keyed, and it resets on success.

The residual case is an attacker sharing ROOT's egress address consuming the coarse
address ceiling. That ceiling is set high, refills continuously, and applies before
authentication for everyone equally.

## Response contract

`429 Too Many Requests`, `application/problem+json`, stable code `RATE_LIMITED`,
and a `Retry-After` header in seconds. `Retry-After` is also exposed through CORS,
so a browser client can read it.

The body carries no limiter key, no user id, and no threshold — a throttled caller
learns that they must slow down, not how the budget is computed. Pinned by
`a_throttled_request_returns_the_documented_contract`.

Quota exhaustion never produces `500`.

## Configuration

Every limit is an environment variable, falling back to the default. Previously
`RateLimitConfig` was built with `Default::default()` and read nothing at all, so an
operator facing abuse could not tighten a single limit without a rebuild — a control
that existed in configuration but not in configuration. That is closed.

| Variable | Default |
|---|---|
| `RB_RATE_LOGIN_PER_IP_PER_MINUTE` | 10 |
| `RB_RATE_LOGIN_PER_ACCOUNT_PER_MINUTE` | 5 |
| `RB_RATE_MFA_PER_SESSION_PER_MINUTE` | 5 |
| `RB_RATE_REFRESH_PER_IP_PER_MINUTE` | 60 |
| `RB_RATE_PASSWORD_RESET_PER_IP_PER_HOUR` | 5 |
| `RB_RATE_REGISTRATION_PER_IP_PER_HOUR` | 3 |
| `RB_RATE_INVITATION_ACCEPT_PER_IP_PER_HOUR` | 20 |
| `RB_RATE_BOOTSTRAP_PER_IP_PER_HOUR` | 5 |
| `RB_RATE_GENERAL_PER_PRINCIPAL_PER_MINUTE` | 600 |
| `RB_RATE_GENERAL_ROOT_PER_MINUTE` | 3 000 |
| `RB_RATE_GENERAL_PER_IP_PER_MINUTE` | 3 000 |

A quota of `0` is **rejected at startup** rather than read as "unlimited". Zero
would refuse every request, and silently inverting a security value into its
opposite is exactly what a security control must never do.

## Failure behaviour

The limiter is in-process and infallible: it cannot return an error, only a
decision, so there is no "limiter unavailable" path that could fail open. Eviction
under memory pressure drops the **most-refilled** buckets first, never the
least-recently-used — LRU was exploitable, because an attacker could park a bucket
and have it evicted while it was still nearly exhausted.

## Current limitation: single instance only

**Enforcement is per process. There is no cross-instance enforcement, and none is
claimed.** Running two API instances behind a load balancer today would give each
principal one budget per instance.

This is acceptable now because the deployment is a single API container, and
`RR-3` in the threat model already records it as a release gate. Redis was
deliberately *not* introduced: adding distributed infrastructure for a distribution
that does not exist would be paying complexity for a hypothetical.

What makes the change cheap later is that everything goes through one narrow trait:

```rust
pub trait RateLimiter: Send + Sync {
    async fn check(&self, key: &str, quota: u32, window: Duration) -> RateLimitDecision;
    async fn reset(&self, key: &str);
}
```

`AppState` holds `Arc<dyn RateLimiter>`, and every call site — the anonymous
operations, the general extractor charge, the address ceiling — goes through it.
A Redis implementation is a new type implementing two methods; nothing else moves.

**Before running more than one instance**, a distributed implementation is
required. The keys are already namespaced (`general:user:`, `general:ip:`,
`login:acct:` …) so they can share a keyspace without collision — a property with
its own unit test.

## Route classes

| Class | Applies to | Key | Default |
|---|---|---|---|
| `anonymous-operation` | bootstrap, login, MFA verify, refresh, password reset, registration, invitation acceptance | operation-specific: IP, account, or session | per operation, see table above |
| `general-authenticated` | every route requiring a principal | user id | 600/min (ROOT 3 000/min) |
| `address-ceiling` | every request, before authentication | client IP | 3 000/min |

A route in `anonymous-operation` is charged its own budget *and* the address
ceiling. A route in `general-authenticated` is charged the principal budget *and*
the address ceiling. The two authenticated charges are not double-counted against
each other: they are different keys answering different questions ("is this account
doing too much?" and "is this address doing too much?").

## What is deliberately *not* rate limited

Health probes (`/health/live`, `/health/ready`) pass the address ceiling like
anything else but have no principal budget, because they are unauthenticated by
design and a monitoring system polling them is the intended behaviour.
