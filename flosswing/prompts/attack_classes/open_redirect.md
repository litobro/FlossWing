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

You have `read_file`, `list_dir`, `grep`, `find_definition`,
`find_callers`, `compile_and_run`, and `record_finding`. Trace the
redirect target from the request field to the sink and confirm no
allowlist or relative-only enforcement sits between them. A finding
should carry `file`, `function`, `line_start`, `line_end` at the
redirect call and a `description` naming the parameter and why an
absolute external URL survives to the `Location`. A `compile_and_run`
PoC is often only partially probative here (redirection is a
protocol-level effect, not local execution): a PoC that invokes the
handler and shows the emitted `Location` equal to an external
attacker URL supports `confidence=confirmed`; a clean end-to-end
dataflow trace without execution is `likely`; uncertainty about
whether the value reaches the header unfiltered is `speculative`.

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
