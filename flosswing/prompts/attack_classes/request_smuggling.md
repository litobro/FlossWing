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

You have `read_file`, `list_dir`, `grep`, `find_definition`,
`find_callers`, `compile_and_run`, and `record_finding`. The proof is
that *two* processors can disagree, which usually means reasoning about a
proxy-to-backend hop rather than a single runnable program — so a
`framing-construction trace` (e.g. showing the forwarder emits both CL
and TE, or the chunk parser accepts a size a peer would reject) is
normally the ceiling at `confidence=likely`. A `compile_and_run` PoC can
sometimes confirm one half — feed a crafted request to the hand-rolled
parser and show it frames the body differently than the spec requires —
which raises that parser's finding to `confirmed`; full two-hop
desync is rarely reproducible in the sandbox. If the forwarding or
dual-processor topology is unclear, it is `speculative`. A finding
should carry `file`, `function`, `line_start`, `line_end` at the framing
emit/parse site and a `description` naming the CL/TE disagreement
(CL.TE / TE.CL / TE.TE) and the two hops that would differ.

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
