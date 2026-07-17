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

You have `read_file`, `list_dir`, `grep`, `find_definition`,
`find_callers`, and `record_finding` (plus `compile_and_run`, rarely
useful here). A finding should carry `file`, `function`, `line_start`,
`line_end` at the handler and its route registration; a `description`
establishing the three conditions — the state change, that auth is
cookie/session-based, and that no token/Origin/custom-header check
guards it; and a `poc_code` sketch of the cross-site form or `fetch`
(with `credentials: 'include'`) that would drive the action. CSRF turns
on browser cookie behavior the sandbox cannot reproduce, so
`compile_and_run` is generally non-probative here. Use
`confidence=likely` when you trace an unprotected mutating cookie-auth
handler end-to-end; `confirmed` only with a reachability trace showing
no middleware/decorator interposes a check; `speculative` when the auth
model or a global CSRF filter's coverage is unclear.

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
