# Attack class: ssrf

Server-Side Request Forgery: the server issues an outbound request to
a URL or host that is derived from untrusted input, letting an attacker
point the server at internal services, cloud metadata endpoints
(`169.254.169.254`), loopback, or link-local ranges it should never
reach. The bug lives where attacker-controlled data becomes the target
of an HTTP/network client call without a scheme-and-host allowlist.

## What to look for

A URL, host, port, or full request target that traces back to
attacker input (request bodies, query params, webhook config, uploaded
document URLs, redirect-following) reaching an outbound-request sink.

- **Python.** `requests.get/post(url)`, `urllib.request.urlopen`,
  `httpx`/`aiohttp` client calls, and helpers that fetch a
  user-supplied URL (image proxies, link unfurlers, webhook senders).
- **JavaScript / Node.** `fetch(url)`, `axios(url)`, `http.request`/
  `https.get` with a user-built target, and SSRF-prone libraries like
  `request`/`got`/`node-fetch`.
- **Go.** `http.Get`/`http.Post`, `http.NewRequest` + `client.Do`, and
  any `net.Dial`/`net/http` transport pointed at a user host.
- **Java.** `HttpClient.send`, `URL.openConnection`/`openStream`,
  `RestTemplate`/`WebClient`/`OkHttpClient` calls to a user URL.
- **General smells.** Webhook registration, "fetch this URL" import
  features, PDF/screenshot renderers, and any redirect-following client
  where the initial or redirected host is attacker-influenced.

## Evidence

You have `read_file`, `list_dir`, `grep`, `find_definition`,
`find_callers`, `compile_and_run`, and `record_finding`. This attack
class permits network in the sandbox (`network_permitted=True`), so a
`compile_and_run` PoC is feasible: stand up a controlled loopback
listener in the same PoC (bind `127.0.0.1:<port>`), drive the sink
with that URL, and show the server-side fetch reaching it — pass
`network=True` and attach the `poc_result`. A finding should carry
`file`, `function`, `line_start`, `line_end` at the request sink and a
`description` tracing the host/URL from entry point to sink. A PoC
that demonstrates the fetch reaching a chosen internal target earns
`confidence=confirmed`; an end-to-end dataflow trace without execution
is `likely`; an unclear link in the chain is `speculative`.

## Common false positives

- The client enforces a scheme + host allowlist (or blocks private,
  loopback, and link-local ranges after DNS resolution) before the
  request. This is the safe shape — do not report it.
- The target host is a compile-time constant or fixed config value the
  attacker cannot influence.
- An SSRF-hardened wrapper (pinned resolver, no-redirect policy,
  egress-filtered client) mediates all outbound calls in scope.

## Stop condition

After one pass through the `scope_hint`, stop. Record zero or more
findings via `record_finding`. Recording zero findings is a valid
outcome.
