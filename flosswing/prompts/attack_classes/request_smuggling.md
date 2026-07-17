# Attack class: request_smuggling

Two HTTP processors on the same connection — typically a front-end proxy
and a back-end server — disagree on where one request ends and the next
begins, letting an attacker prepend a hidden request that the back-end
attributes to the next client. The bug lives in framing: how the code
emits, forwards, or parses `Content-Length` (CL) and
`Transfer-Encoding` (TE), and whether two hops can be made to interpret
the same bytes differently (CL.TE, TE.CL, TE.TE).

## What to look for

Code that produces or parses HTTP message framing in a way that another
hop can read differently:

- **Emitting both CL and TE.** Response or forwarded-request
  construction that sets *both* `Content-Length` and
  `Transfer-Encoding: chunked` on the same message. A conformant server
  must drop CL when TE is present; code that emits both invites
  disagreement.
- **Hand-rolled chunked parsing.** Custom chunk-size decoding — reading
  the hex length, trimming CRLF, handling the terminating `0\r\n\r\n` —
  instead of a vetted library. Look for lenient size parsing (accepting
  leading `+`, `0x`, whitespace, or trailing chars after the hex).
- **Lenient / ambiguous TE handling.** Accepting obsolete line folding,
  duplicated `Transfer-Encoding` headers, `Transfer-Encoding: chunked`
  with unexpected casing or extra tokens (`chunked, identity`), or
  treating an unrecognized TE as "no encoding" and falling back to CL.
- **Forwarding without normalization.** Reverse-proxy / gateway code
  that copies inbound headers to the upstream request verbatim without
  re-deriving framing, so a client's ambiguous CL/TE combination reaches
  the back-end intact.

Concentrate on custom HTTP parsers, reverse-proxy and request-forwarding
paths, and any manual chunk decoding.

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

- A single, well-behaved server that uses a vetted HTTP library with
  strict framing and rejects messages carrying conflicting CL/TE — and
  there is no proxying or forwarding layer for a second interpretation.
- Chunked handling delegated entirely to the standard library's HTTP
  parser rather than hand-rolled.
- Framing derived fresh on each hop (the forwarder recomputes CL/TE and
  strips inbound framing headers) rather than copied verbatim.
- Code that explicitly rejects requests with both CL and TE, or with
  duplicate/ambiguous `Transfer-Encoding`.

## Stop condition

After one pass through the `scope_hint`, stop. Record zero or more
findings via `record_finding`. Recording zero findings is a valid
outcome.
