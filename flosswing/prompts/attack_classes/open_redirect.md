# Attack class: open_redirect

A user-controlled value is used as a redirect destination without an
allowlist, so an attacker can send a victim from a trusted origin to
an attacker-controlled site — enabling phishing or leaking tokens
(OAuth `redirect_uri`, session tokens, `next`-style parameters). The
bug lives where attacker data becomes the target of a redirect
(a `Location` header, an HTML meta-refresh, or a client-side location
assignment) with no destination check.

## What to look for

A redirect target that traces back to attacker input (`?next=`,
`?url=`, `?returnTo=`, `redirect_uri`, `Referer`, posted form fields)
reaching a redirect sink.

- **Python.** `flask.redirect(request.args["next"])`,
  Django `HttpResponseRedirect(user_url)` /
  `redirect(user_url)`, or manually setting the `Location` header from
  user data.
- **JavaScript / Node.** `res.redirect(req.query.url)` (Express),
  `reply.redirect(...)` (Fastify), or setting `Location` directly;
  client-side `window.location = userValue` /
  `location.assign(userValue)` and `<meta http-equiv="refresh">` built
  from user input.
- **Go.** `http.Redirect(w, r, userURL, code)` or writing a `Location`
  header from a request-derived value.
- **Java.** `response.sendRedirect(userUrl)`, Spring
  `"redirect:" + userValue` view names, or setting the `Location`
  header from request data.

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

- The destination is validated against an allowlist of hosts/paths, or
  coerced to a relative path (leading-slash-only, host stripped) before
  redirecting. This is the safe shape — do not report it.
- The `next`/return URL is signed or is an opaque server-side token
  mapped to a fixed destination.
- The redirect target is a compile-time constant or fixed config value
  the attacker cannot influence.

## Stop condition

After one pass through the `scope_hint`, stop. Record zero or more
findings via `record_finding`. Recording zero findings is a valid
outcome.
