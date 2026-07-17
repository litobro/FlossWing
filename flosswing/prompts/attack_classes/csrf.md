# Attack class: csrf

A state-changing endpoint authorizes requests using only ambient
credentials — session cookies the browser attaches automatically — with
no defense that a cross-site page cannot forge. Because a victim's
browser sends the cookie on any request an attacker's page triggers, the
attacker can drive the action without reading the response. The bug
lives at an authenticated, mutating endpoint that lacks an anti-CSRF
check; it does not apply to endpoints that don't change state or don't
rely on cookies.

## What to look for

A route handler that (a) performs a state change (create/update/delete,
money movement, permission change, mail send), (b) is authenticated via
a cookie/session, and (c) has no unforgeable per-request check.

- **Missing CSRF token.** An unsafe-method handler (POST/PUT/PATCH/
  DELETE) with no synchronizer-token or double-submit check — framework
  CSRF middleware disabled, `@csrf_exempt`, `csrf: false`, Spring
  Security `.csrf().disable()`, or a form with no hidden token field
  the server verifies.
- **Cookie attributes.** Session cookie set without `SameSite`
  (`Set-Cookie` lacking `SameSite=Lax/Strict`), which historically left
  cross-site sends unblocked — note it as weakening but confirm the
  endpoint check is also absent.
- **No Origin/Referer check.** A cookie-authenticated JSON/mutating
  endpoint that inspects neither `Origin` nor `Referer` and requires no
  custom header.
- **State-changing GET.** A handler reachable by `GET` (or that ignores
  method) that mutates state — trivially triggerable via `<img>`/
  `<script>`/link, needing no token at all.

## Evidence

Hunt's v0.3 toolset is `read_file`, `list_dir`, `grep`, `find_definition`,
`find_callers`, and `record_finding` — there is no `compile_and_run`, so a
finding cannot carry a real execution result. Use `find_definition` and
`find_callers` to trace how untrusted data reaches the sink. A finding should
carry `file`, `function`, `line_start`, `line_end` at the sink plus a
`description` of that flow, and a short **textual** `poc_code` sketch of the
triggering input. Do **not** fabricate a `poc_result` — leave it unset.
Confidence: `likely` when you can trace the flow end-to-end, `speculative`
when a link in the chain is unclear. Do **not** use `confirmed`; it requires
execution Hunt cannot perform in v0.3.

## Common false positives

- A CSRF token is issued and verified on unsafe methods (framework
  middleware enabled, hidden token field checked). The safe shape — do
  not report it.
- Session cookies are `SameSite=Strict` or `Lax` and the mutating
  endpoints use unsafe methods (Lax blocks cross-site POST). Treat as
  defended absent a specific bypass.
- A JSON API that requires a custom request header (e.g.
  `X-Requested-With`, `Content-Type: application/json` enforced),
  which a cross-site form cannot set without CORS preflight consent.
- Non-cookie auth: the endpoint authorizes via a bearer token /
  `Authorization` header the browser does not attach automatically.

## Stop condition

After one pass through the `scope_hint`, stop. Record zero or more
findings via `record_finding`. Recording zero findings is a valid
outcome.
