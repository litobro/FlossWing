# Attack class: crlf_injection

Untrusted data containing carriage-return / line-feed characters
(`\r`, `\n`, or their encodings) is injected into a newline-delimited
protocol context — most importantly HTTP response headers — where the
CR/LF is interpreted as a field or message boundary. This yields header
injection and response splitting (forged `Set-Cookie`, injected
`Location`, a spliced body) and, in mail contexts, email header
injection. The bug lives where a raw user value becomes part of a
header line without CR/LF being rejected or stripped.

## What to look for

A header or protocol field constructed from attacker input (query
params, form fields, path segments, values echoed back into responses)
where the value can carry `\r\n`:

- **HTTP response headers.** `setHeader`/`addHeader`, `Response.headers[...] = value`,
  `res.setHeader`/`res.writeHead`, `w.Header().Set`, adding a header
  from a user value. High-signal targets: `Location` built from a
  `?url=`/`?next=` param for a redirect, and `Set-Cookie` built from a
  user-supplied name or value.
- **Redirects.** `redirect(user_url)` / `sendRedirect(user_url)` where
  the URL is taken raw from the request — the `Location` header is the
  sink.
- **Email headers.** `To`/`Cc`/`Subject`/`From` set from user input via
  an SMTP/mail library — a newline lets the attacker inject extra
  recipients or headers.
- **Per language.** Java `HttpServletResponse.setHeader`/`sendRedirect`;
  Python `django.http.HttpResponse(...)` header assignment,
  `flask.redirect`, raw WSGI header tuples; Node `res.setHeader`,
  `res.writeHead`; Go `http.ResponseWriter.Header().Set` /
  `http.Redirect`.

This class is about *protocol headers*. It overlaps with
`log_injection` (CR/LF into log lines) — keep those under that class and
keep this one focused on headers.

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

- The framework or server rejects or strips CR/LF in header values
  before writing them — most modern HTTP stacks (recent Node, Go
  `net/http`, servlet containers) do this by default. Not a finding.
- The value is validated against a strict charset (e.g. a URL/host
  allowlist, an alphanumeric token) that excludes CR and LF.
- The value is percent-encoded / header-encoded before insertion, so
  newlines cannot survive into the wire format.
- The header value is a program-controlled constant, not user input.

## Stop condition

After one pass through the `scope_hint`, stop. Record zero or more
findings via `record_finding`. Recording zero findings is a valid
outcome.
