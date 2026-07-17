# Attack class: unwrap_in_reachable_path

A panicking operation — `.unwrap()`, `.expect()`, direct slice indexing
`v[i]`, an explicit `panic!`, or integer division/remainder — is applied to
a value influenced by untrusted input and is reachable from an entry point,
so a crafted request crashes the process (denial of service). The bug is a
reachable panic on attacker-controlled data, not any `unwrap` anywhere.
This class is Rust only.

## What to look for

- **`unwrap` / `expect` on parsed input.** A `Result`/`Option` produced from
  request bytes, query params, headers, deserialization, or file contents,
  unwrapped without handling the `Err`/`None` an attacker can force (bad
  UTF-8, malformed JSON, missing field, out-of-range number).
- **Indexing with an attacker index or length.** `v[i]` / `s[a..b]` /
  `&buf[n..]` where `i`, `a`, `b`, or `n` comes from untrusted input — an
  out-of-bounds index panics; a slice range past the end panics.
- **Division / remainder by an attacker value.** `a / b` or `a % b` where `b`
  can be zero — an integer divide-by-zero panics.
- **Explicit `panic!` / `unreachable!` / `assert!`** on a condition an
  attacker can violate, on a path reachable from a handler.
- **`unwrap` on a lock, channel, or numeric conversion** (`try_into().unwrap()`)
  where the failure case is attacker-reachable.

Trace reachability from an entry point (HTTP handler, message consumer, CLI
arg, parser) to the panic site — an unwrap buried in dead or test-only code
is not this bug.

## Evidence

You have `read_file`, `list_dir`, `grep`, `find_definition`,
`find_callers`, `compile_and_run`, and `record_finding`. Aim for:

- `file`, `function`, `line_start`, `line_end` — pointing at the panicking
  operation, and cite the entry point and the tainted value in the
  description.
- A `description` establishing the path: where untrusted input enters, how it
  reaches this value unvalidated, and which crafted input forces the
  `Err`/`None`/out-of-bounds/zero.
- A `poc_code` PoC is decisive. A self-contained Rust program that feeds the
  triggering input and **panics** (`called Option::unwrap() on a None value`,
  `index out of bounds`, `attempt to divide by zero`) is direct proof. Run
  it through `compile_and_run` and attach the returned `poc_result`.
- Confidence: `confirmed` only when a `compile_and_run` PoC panics or a
  reachability trace connects an entry point to the panic on attacker data;
  `likely` when the path is traced but not executed; `speculative` when
  reachability or taint is unclear.

## Common false positives

- The input is validated (parsed-and-checked, length-guarded, non-zero
  ensured) so the `None`/`Err`/out-of-bounds/zero case cannot occur on the
  reachable path.
- `unwrap` on a compile-time or just-established invariant: a literal, a
  value inserted one line above, a `Regex` built from a constant, an index
  produced by `.enumerate()` or a preceding `if i < len` guard.
- Panics confined to tests, benches, examples, or build scripts — not
  reachable from a production entry point.

## Stop condition

After one pass through the `scope_hint`, stop. Record zero or more findings
via `record_finding`. Recording zero findings is a valid outcome.
