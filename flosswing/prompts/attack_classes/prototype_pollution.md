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

You have `read_file`, `list_dir`, `grep`, `find_definition`,
`find_callers`, `compile_and_run`, and `record_finding`. A finding
should carry `file`, `function`, `line_start`, `line_end` at the
merge/set/assign sink; a `description` tracing how untrusted keys reach
the recursive write and why `__proto__`/`constructor`/`prototype` are
not filtered; and a `poc_code` payload such as
`{"__proto__": {"polluted": true}}` or a path `constructor.prototype.x`.
This class *is* PoC-friendly in the sandbox: a self-contained Node
snippet that feeds the payload to the sink and then reads
`({}).polluted` (or the injected property on a fresh object)
demonstrates pollution — attach `poc_result` for `confidence=confirmed`.
Trace untrusted keys into the sink end-to-end without running →
`likely`; if the key source or the recursion path is unclear →
`speculative`.

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
