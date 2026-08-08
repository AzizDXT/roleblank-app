# Frontend build prompt — mobile-first, then desktop

Paste the block below to start frontend implementation. It is written against the
**frozen** backend contract (`docs/backend/BACKEND_FREEZE_MANIFEST.md`), and every
file and number it cites was verified to exist.

Two notes before the prompt itself:

* **"Mobile-first" here means viewport, not platform.** One responsive web
  application, implemented at the smallest screen first and progressively enhanced.
  No native app, no Flutter, no React Native.
* **The visual identity is the owner's, not the builder's.** The prompt forbids
  inventing a palette or typography and requires a token layer instead, so the real
  identity drops in later by changing tokens rather than by rewriting components.

---

```
# ROLEBLANK OS — FRONTEND IMPLEMENTATION (MOBILE-FIRST)

You are building the frontend for RoleBlank OS, an internal company operating
system. The backend is COMPLETE and FROZEN. Your job is to build a web application
against a fixed contract — not to design a product, and not to change the backend.

## 0. THE ONE RULE

The backend contract is frozen. You may consume it. You may NOT infer additional
routes, permissions, fields or behaviours from it.

If something you need does not exist in the contract, STOP and say so. Do not
invent an endpoint, do not guess a field name, do not assume a permission. A
missing capability is a conversation, not something to work around.

## 1. READ FIRST — these are the specification

Backend contract (authoritative, frozen):
- docs/backend/BACKEND_FREEZE_MANIFEST.md      — what is frozen, and the rules for you
- docs/backend/ROUTE_SECURITY_MATRIX.md        — all 95 routes, 14 columns each
- docs/backend/FRONTEND_ERROR_CONTRACT.md      — every machine-actionable error code
- docs/backend/FRONTEND_CAPABILITY_CONTRACT.md — what /auth/me returns and how to use it
- docs/backend/FRONTEND_ACTION_CATALOG.md      — 92 actions: route, permission, audit event
- docs/backend/PERMISSION_CATALOG.md           — 42 permissions
- docs/backend/CONCURRENCY_CONTRACT.md         — optimistic concurrency, per endpoint
- docs/backend/IDEMPOTENCY_CONTRACT.md         — which endpoints take Idempotency-Key
- docs/backend/REGISTRATION_CONTRACT.md        — registration modes and what UI to show
- api/openapi.json                             — generate the API client from this

Product structure (already specified — do not redesign it):
- docs/product/01-application-structure.md     — every screen, its endpoint, its permission
- docs/product/02-screen-inventory.md          — 48 screens: 36 internal, 6 client portal, 6 public
- docs/product/03-widget-catalogue.md          — the reusable widgets and every state each must handle
- docs/product/04-navigation-and-state.md      — routing, session lifecycle, failure taxonomy
- docs/product/05-client-portal-boundary.md    — the external surface, and why it is separate

Read 01 and 04 in full before writing any code. They already answer most of the
questions you would otherwise guess at.

## 2. WHAT YOU ARE BUILDING

TWO applications on one API:

1. **Internal workspace** — `principal_type = INTERNAL`, 36 screens. Staff.
2. **Client portal** — `principal_type = CLIENT`, 6 screens, the four
   `/api/v1/client-portal/*` reads plus shared auth. External customers.

They share an API client, an auth layer and a widget library. They do NOT share
navigation, and the client portal must never render an internal affordance. Read
docs/product/05-client-portal-boundary.md before touching it.

## 3. MOBILE-FIRST — WHAT IT ACTUALLY MEANS HERE

Build every screen at **360 × 640 first**, in a real narrow viewport, and only then
widen. Do not build desktop and add media queries afterwards; that produces layouts
that technically reflow and are miserable to use.

Breakpoints — three, no more:
- base   (0px+)     phone, single column, this is the DEFAULT and needs no query
- md     (768px+)   tablet, two columns where it genuinely helps
- lg     (1280px+)  desktop, persistent navigation, multi-column

Rules:
- CSS is written mobile-first: unprefixed rules are the phone; `min-width` queries add.
- Every interactive target is at least 44 × 44 CSS pixels.
- Nothing horizontally scrolls except a deliberate, contained scroller.
- Type scale starts readable on a phone (16px body minimum — never 14px).
- Test every screen at 360px before you consider it done.

**The hard part is the data tables, so plan for it.** The internal workspace is
mostly lists: users, roles, projects, tasks, clients, departments, audit. A table
does not work at 360px. The rule:

- base: each row becomes a **card** — primary identifier as the heading, two or
  three supporting fields, and the row's actions in an overflow menu.
- md and up: the same data becomes a real table.

Build this once as the `data-table` widget with both renderings. Do not solve it
per screen, and do not ship a table in a horizontal scroller as the phone answer.

The client portal matters most here: external users are the most likely to be on a
phone, and it is the surface a customer judges the company by.

## 4. RTL AND ARABIC ARE FIRST-CLASS

**This is not covered by the existing documents — treat it as a requirement anyway.**
The product is for an Arabic-speaking company.

- Layout must work in `dir="rtl"` from the first commit, not as a later port.
- Use logical CSS properties (`margin-inline-start`, not `margin-left`; `inset-inline`,
  not `left`/`right`). This is the single decision that makes RTL nearly free.
- Never encode direction in an icon name or a hard-coded arrow. Chevrons flip.
- All user-visible strings go through an i18n layer from day one, even if there is
  only one locale at first. Retrofitting this costs ten times more.
- Numbers, dates and times: pick one formatting policy, apply it centrally.

## 5. DESIGN TOKENS — DO NOT INVENT AN IDENTITY

The owner has the visual identity. You do not.

- Build a token layer: colour, spacing, radius, typography, shadow, motion.
- Use neutral placeholder values, and say clearly in the README that they are
  placeholders.
- Every component consumes tokens. No hard-coded hex, no magic pixel values.
- Do not copy another product's look. Do not add decorative animation.

When the real identity arrives, changing tokens must be enough.

## 6. BACKEND BEHAVIOURS THAT SHAPE THE UI

These are the ones that break naive frontends. All are documented; they are
repeated here because ignoring any one of them produces a broken app.

**`404` can mean "forbidden".** For external principals the backend deliberately
masks refusals as not-found. Never build UI that distinguishes "does not exist"
from "not allowed" — you would be inventing a distinction the backend refuses to
make.

**Capabilities are a hint, not authority.** `/auth/me` returns what the user holds.
Use it to hide navigation and disable actions. Never assume a shown action will
succeed — always handle the refusal. The backend re-derives every decision on every
request.

**Branch on the `code`, not the HTTP status.** Every error is
`application/problem+json` with a stable `code`. Build one error mapper, used
everywhere. The critical ones:

- `AUTHENTICATION_FAILED` (401) — session gone. Clear it, route to login.
- `MFA_REQUIRED` (403) — session real but pending. Route to the MFA screen. Do NOT
  log the user out; they are mid-flow.
- `STEP_UP_REQUIRED` (403) — needs a *recent* second factor. Prompt for it, then
  retry the original action. Do not lose what they were doing.
- `RATE_LIMITED` (429) — normal, not an error state. Honour `Retry-After`, show a
  calm message, do not hammer.
- `VERSION_CONFLICT` (409) — someone else edited it. Show what changed and let the
  user decide. Never silently overwrite.
- `SERVICE_UNAVAILABLE` (503) — transient. Offer retry, do not clear state.

**Optimistic concurrency is explicit.** Editable resources carry `version`. Send the
one you loaded. The mechanism differs per endpoint — 14 endpoints take it as a body
field, one as a query parameter. Check CONCURRENCY_CONTRACT.md per endpoint; do not
assume.

**Retries need `Idempotency-Key`** on the six create endpoints that accept it. A
user double-tapping "Create" on a phone is the normal case, not the edge case.

**Sessions have three states** — logged out, MFA-pending, full — and the routing
rules for each are in docs/product/04-navigation-and-state.md §3. Implement that
state machine once, properly, before building screens on top of it.

## 7. ORDER OF WORK

Do these in order. Do not start screens before phase 3 is solid.

1. **Skeleton** — project, TypeScript strict, token layer, i18n + RTL, routing.
2. **API client** — generated from api/openapi.json. Typed. One error mapper.
3. **Session state machine** — login, MFA enrolment, MFA verify, step-up, refresh,
   logout, revocation. Per docs/product/04. This is the foundation; get it right.
4. **Widget library** — the widgets in docs/product/03, each handling every state
   that document lists: loading, empty, error, forbidden, and the populated case.
   `data-table` with its card/table split is the biggest one.
5. **Client portal** — only 6 screens, one clean boundary, most likely to be on a
   phone. Build it first as the proof that mobile-first works.
6. **Internal workspace** — 36 screens, in the order of docs/product/02.
7. **Hardening** — keyboard navigation, focus management, screen reader labels,
   reduced-motion, error recovery, slow-network behaviour.

## 8. DEFINITION OF DONE — PER SCREEN

A screen is not done until all of these are true:

- [ ] Renders correctly at 360px, 768px and 1280px
- [ ] Works in both `dir="ltr"` and `dir="rtl"`
- [ ] Handles: loading, empty, error, forbidden, and populated
- [ ] Every action's failure codes are handled per §6
- [ ] Actions the user lacks permission for are hidden or disabled, from capabilities
- [ ] Keyboard reachable; visible focus; sensible tab order
- [ ] No hard-coded colour, spacing or string
- [ ] The endpoint and permission match docs/product/01 exactly

## 9. DO NOT

- Do not modify anything under `backend/`. It is frozen.
- Do not add a route, permission or field that is not in the contract.
- Do not build chat, realtime, calendar, finance, CRM, file upload, or AI. Out of scope.
- Do not invent branding, or copy another product's visual language.
- Do not build a desktop layout first "and make it responsive later".
- Do not put a wide table in a horizontal scroller and call it mobile support.
- Do not trust capabilities as authorisation.
- Do not distinguish 404-not-found from 404-forbidden in the UI.

## 10. WHEN YOU ARE UNSURE

Say so, and say exactly what is missing. A wrong assumption baked into 48 screens
is far more expensive than one question. The backend went through three adversarial
audits precisely because assumptions that looked reasonable turned out to be false;
the same discipline applies here.

Start with phase 1. Before writing code, tell me your stack choice and why, and
confirm you have read docs/product/01 and docs/product/04.
```
