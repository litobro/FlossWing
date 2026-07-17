# Attack class: hardcoded_secrets

A credential — password, API key, token, private key, or connection
string — is embedded as a literal in source or config and would grant
access if it reached a running production system. The bug is a *shipped*
secret, not merely a string that looks like one.

## What qualifies

A literal credential that (a) is used as a real authentication value by
production code paths, and (b) is not overridden by operator
configuration or environment at deploy time. The finding must argue *how
the value reaches production* — which prod code reads it, and why a
deployment would not replace it.

## Disqualifiers — do NOT confirm at high/medium (report at `info` or reject)

- **Self-describing placeholders / vendor defaults:** `changeme`,
  `change_me`, `Ch@ngeTh!sPa33w0rd`, `devpass`, `password`, `admin`,
  `minioadmin`, `example`, `sample`, `<YOUR_...>`, `${...}` template
  markers. These are prompts to the operator, not secrets.
- **Low-entropy / dictionary-word values.** A real key is high-entropy;
  a short English word or obvious phrase is a default.
- **Localhost / private-range hosts** (`localhost`, `127.0.0.1`,
  RFC-1918). Dev-stack wiring, not a production credential.
- **Dev/test/example artifacts:** `test/`, `tests/`, `fixtures/`,
  `examples/`, `docker-compose*.yml`, `*.template`, CI config. These are
  not deployed.
- **Env-overridden defaults:** `os.environ.get("KEY", DEFAULT)` — the
  literal is a fallback the operator replaces; report the *missing
  fail-closed* as `info` at most, not a shipped secret.

## Evidence

A secret cannot be *executed*, so a PoC that merely re-prints the literal
is **non-probative** — do not treat it as confirmation. Confirmation
requires a deployment-reachability argument: the value is read by
production code and survives deployment. Absent that, prefer `info`
severity or `rejected`.
