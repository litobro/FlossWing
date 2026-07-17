# Attack-class library expansion + fragment backfill

**Date:** 2026-07-16
**Status:** Approved (design), pending implementation
**Scope:** Additive. No tool-contract, schema, or migration changes.

## Problem

Two gaps in the current attack-class library:

1. **In-scope but unimplemented.** `flosswing/attack_classes.py` registers 26 v1
   attack classes, but only two (`command_injection`, `hardcoded_secrets`) have an
   authored Hunt prompt fragment in `flosswing/prompts/attack_classes/`. The other
   24 fall through `load_attack_class_fragment()` to `_GENERIC_FRAGMENT_FALLBACK`,
   which biases the Hunter toward `confidence='speculative'` and a single pass — so
   those classes produce weak, low-signal findings.
2. **Missing common vuln types.** Several high-value classes are absent from the
   registry entirely: broken authorization (IDOR/BOLA), TOCTOU races, SSTI, ReDoS,
   CRLF/header injection, HTTP request smuggling, and the LDAP/NoSQL/XPath/log
   injection family.

This change (a) adds 10 new attack classes and (b) authors fragments for **all**
missing classes — the 24 pre-existing gaps plus the 10 new ones (34 fragments).

## New attack classes (registry 26 → 36)

| Name | `language_scope` | Boundary |
|---|---|---|
| `broken_authorization` | web | Object-/function-level authZ missing after authN (IDOR/BOLA). Distinct from `auth_bypass`, which is authN. |
| `toctou` | polyglot | Time-of-check ≠ time-of-use races on files / shared state. |
| `ssti` | web | Untrusted data reaches a template engine as *template*, not data → code exec. |
| `redos` | polyglot | Catastrophic-backtracking regex over attacker-controlled input → CPU DoS. |
| `crlf_injection` | web | Injected CR/LF into headers/response → header injection / response splitting. |
| `request_smuggling` | web | TE/CL desync between front-end and back-end HTTP parsers. |
| `ldap_injection` | web | Untrusted data into an LDAP filter/DN. |
| `nosql_injection` | web | Operator/object injection into NoSQL queries (`$where`, `$gt`, …). |
| `xpath_injection` | web | Untrusted data into an XPath expression. |
| `log_injection` | web | Forged / CRLF-injected log lines (log forging, ANSI/control smuggling). |

All 10 get `network_default=False, network_permitted=False` (none need loopback
like `ssrf`). `crlf_injection`/`request_smuggling` and `ssti`/`redos` are kept as
separate classes — they don't share a detection shape.

## Fragments to author (34 total)

**Pre-existing gaps (24):** `path_traversal`, `ssrf`, `auth_bypass`,
`insecure_deserialization`, `xxe`, `open_redirect`, `buffer_overflow`,
`use_after_free`, `integer_overflow`, `format_string`, `null_deref`, `sqli`,
`xss`, `csrf`, `prototype_pollution`, `unsafe_yaml`, `unsafe_pickle`,
`java_deserialization`, `nil_deref_in_error_path`, `unsafe_pointer_misuse`,
`goroutine_leak`, `unsafe_audit`, `unwrap_in_reachable_path`, `soundness_bug`.

**New (10):** the 10 classes above.

## Fragment template

Matches the house style of the two existing fragments:

- `# Attack class: <name>`
- Definition paragraph — the precise boundary where the bug lives.
- `## What to look for` — per-language sections for `polyglot`/`web` classes;
  single-language focus for the C/C++, Go, Rust classes.
- `## Evidence` — reflects Hunt's **current** tool set: `read_file`, `list_dir`,
  `grep`, `find_definition`, `find_callers`, `compile_and_run`, `record_finding`.
  Where a PoC is safely runnable in the sandbox, a finding *may* carry a real
  `poc_result` via `compile_and_run`. (The two existing fragments' "v0.3 — no
  `compile_and_run`, leave `poc_result` unset" note is now stale and is corrected
  as part of this change.) Confidence `likely`/`speculative` rules preserved.
- `## Common false positives` (or `## Disqualifiers`) — the safe shapes not to report.
- `## Stop condition` — one pass through `scope_hint`, zero findings is valid.

Fragments treat repo contents as untrusted data (prompt-injection aware), consistent
with the Recon/Hunt system prompts.

## Files touched

1. `flosswing/attack_classes.py` — 10 new `REGISTRY` entries.
2. `ARCHITECTURE.md` § Recon "v1 attack class library" — add the 10 names under a
   new grouping. *(Operator-curated; edited on explicit instruction.)*
3. `flosswing/prompts/system/recon.md` — extend the hardcoded "Valid attack-class
   values" list, or Recon cannot enqueue the new classes.
4. `flosswing/prompts/attack_classes/*.md` — 34 new fragment files.
5. `flosswing/prompts/attack_classes/{command_injection,hardcoded_secrets}.md` —
   touch up the stale v0.3 `compile_and_run` language for library consistency.
6. `tests/unit/test_attack_classes.py` — add the new names to the sample assertion,
   **and** a new guardrail test: every `REGISTRY` name has an authored fragment
   file, so the generic fallback only ever fires for genuinely-unknown input.

## Non-goals

- No new `language_scope` value (all 10 fit `web`/`polyglot`).
- No tool-contract, schema, or Alembic changes.
- No eval-corpus additions — corpus only has `command_injection` ground truth, so
  recall on the new classes is not claimed; this change only asserts they load and
  validate.

## Verification

Run from the worktree dir against the main-root venv:

- `ruff check .`
- `mypy --strict flosswing`
- `pytest tests/unit` (esp. `test_attack_classes.py`, incl. the new guardrail)
