# Attack class: prototype_pollution

(JavaScript / Node.) Untrusted property keys are merged or assigned into
an object and reach the special keys `__proto__`, `constructor`, or
`prototype`, mutating `Object.prototype` itself. Because nearly every
object inherits from it, a polluted prototype changes application-wide
behavior — enabling denial of service, logic bypass, or, when the
polluted property later reaches a dangerous sink, RCE. The bug lives
where attacker-controlled *keys* (not just values) flow into a
recursive write without filtering the dangerous keys.

## What to look for

A code path where keys from attacker-controlled input (parsed JSON/query
strings, form bodies, YAML, config uploads) drive writes into an object
without rejecting `__proto__`/`constructor`/`prototype`.

- **Recursive merge / extend.** Hand-rolled deep-merge/`extend`/
  `defaultsDeep`/`assignDeep` that recurses into nested objects and
  copies keys verbatim, including when the source key is `__proto__`.
- **Set-by-path helpers.** `set(obj, path, value)` /
  `setValue`/`deepSet` where `path` is a user string like
  `a.b.__proto__.polluted` split and walked without key filtering.
- **Dynamic assignment in a loop.** `for (const k of keys) obj[k] =
  src[k]` or `obj[userKey] = val` where `userKey` originates from
  untrusted input.
- **Vulnerable library versions.** Known-bad `lodash.merge`/`.set`/
  `.defaultsDeep`, `merge`, `deep-extend`, `dot-prop`, `hoek`, etc.,
  below their patched releases — check the version and call site.

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

- The code filters keys, skipping/rejecting `__proto__`, `constructor`,
  and `prototype` before writing. The safe shape — do not report it.
- Data is stored in a `Map`, or in a null-prototype object
  (`Object.create(null)` / `{ __proto__: null }`), which has no
  prototype to pollute.
- `Object.freeze(Object.prototype)` (or `--frozen-intrinsics`) is in
  effect, so prototype writes are inert.
- Input is validated against a schema that constrains keys to a known
  allowlist before any merge.
- Only values (never keys) come from user input — the key set is
  program-controlled.

## Stop condition

After one pass through the `scope_hint`, stop. Record zero or more
findings via `record_finding`. Recording zero findings is a valid
outcome.
