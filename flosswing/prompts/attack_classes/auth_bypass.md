# Attack class: auth_bypass

Authentication — proving *who* the caller is — is missing or
defeatable on a protected route or operation. The bug lives where a
request that should require valid credentials is served without them,
or with credentials that are checked incorrectly: an unguarded
endpoint, a broken credential comparison, a signature that is never
verified, or a hardcoded backdoor. This is **authentication**, not
authorization. If the caller *is* authenticated but reaches data or
actions belonging to another principal (IDOR, missing ownership
check, privilege escalation), that is `broken_authorization` — record
it there, not here.

## What to look for

A protected handler or operation whose authentication gate is absent,
short-circuited, or forgeable.

- **Python.** Flask/Django/FastAPI routes missing `@login_required` /
  auth dependencies while sibling routes have them; `==` comparison of
  a submitted token/password against a secret; JWT decoded with
  `verify=False` or `algorithms` accepting `none`.
- **JavaScript / Node.** Express/Koa/Nest routes registered without the
  auth middleware that guards the rest; `jwt.verify` replaced by
  `jwt.decode` (no signature check); `alg: "none"` accepted; a
  submitted secret compared with `===`.
- **Go.** `net/http` handlers mounted outside the auth middleware
  chain; `jwt.Parse` with a keyfunc that returns a key for `alg=none`
  or ignores the method; `hmac`/token compared with `==` instead of
  `hmac.Equal`.
- **Java.** Spring Security config with a permissive `antMatcher`/
  `permitAll()` over a sensitive path; filters not applied to a
  controller; JWT libraries configured to skip signature validation.
- **Any language.** A hardcoded username/password/token that grants
  access (`if user == "admin" && pass == "s3cr3t"`), a debug/skip-auth
  flag reachable in production, or credential comparison that leaks via
  early return / non-constant-time equality.

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

- The framework enforces authentication globally (default-deny) and the
  route in scope inherits that gate; the apparent "missing decorator"
  is redundant.
- Credential/token comparison uses a constant-time verified primitive
  (`hmac.compare_digest`, `hmac.Equal`, `MessageDigest.isEqual`) and a
  properly verified signature.
- The "backdoor-looking" value is only reachable in a test harness or
  behind a dev-only flag that cannot be set in production.

## Stop condition

After one pass through the `scope_hint`, stop. Record zero or more
findings via `record_finding`. Recording zero findings is a valid
outcome.
