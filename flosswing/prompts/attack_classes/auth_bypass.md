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

You have `read_file`, `list_dir`, `grep`, `find_definition`,
`find_callers`, `compile_and_run`, and `record_finding`. Use
`find_callers` / `grep` to confirm the route is actually reachable and
that no upstream middleware enforces auth. A finding should carry
`file`, `function`, `line_start`, `line_end` at the gate (or its
absence) and a `description` explaining why an unauthenticated request
succeeds. When the flaw is a forgeable token or bad comparison, a
`compile_and_run` PoC that mints an `alg=none`/unsigned token or
demonstrates the comparison accepting a crafted value earns
`confidence=confirmed` (attach `poc_result`). A traced-but-unexecuted
bypass is `likely`; an unproven reachability or unclear middleware
chain is `speculative`.

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
