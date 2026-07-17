# Attack class: unsafe_audit

An `unsafe` block relies on a safety invariant that is not actually upheld
at that call site, so the code can trigger undefined behavior — a
dangling/misaligned/null deref, an out-of-bounds read, or a
layout-incompatible reinterpretation. The bug is a *specific unmet
precondition* of an `unsafe` operation, judged from the surrounding code,
not the presence of `unsafe` itself. This class is Rust only.

## What to look for

- **Raw pointer deref of a suspect pointer.** `*p` / `&*p` /
  `ptr::read(p)` where `p` may be null, dangling (points into freed or moved
  data), or misaligned for its type. Especially pointers derived from
  `as` casts, `Box::into_raw` without a matching lifetime, or offsets.
- **`mem::transmute` between layout-incompatible types.** Transmutes across
  types with different size, alignment, or validity invariants (e.g. into a
  `bool`, `char`, reference, or enum with niche); lifetime-extending
  transmutes (`transmute::<&'a T, &'static T>`).
- **`get_unchecked` / `get_unchecked_mut` with an untrusted index.** An
  index derived from request/file input passed to unchecked slice access
  with no preceding bounds check — an out-of-bounds read/write.
- **FFI calls violating the C contract.** Passing a wrong-length buffer, a
  null where the callee requires non-null, a non-NUL-terminated string, or
  mismatched ownership/lifetime across the `extern` boundary.
- **`slice::from_raw_parts` with an unvalidated length.** Building a slice
  from a pointer and a length that is attacker-influenced or not proven to
  match the real allocation — reads past the end.

## Evidence

You have `read_file`, `list_dir`, `grep`, `find_definition`,
`find_callers`, `compile_and_run`, and `record_finding`. Aim for:

- `file`, `function`, `line_start`, `line_end` — pointing at the `unsafe`
  operation, and name the specific invariant that is not upheld.
- A `description` establishing the gap: what the operation requires, why the
  surrounding code does not guarantee it, and what input reaches it.
- A `poc_code` PoC is decisive. A self-contained Rust program that drives the
  block with invalidating input and **panics, aborts, or exhibits UB
  detectable under Miri** (`cargo miri run` reporting UB) — or a plain
  build that segfaults / triggers a bounds abort — is direct proof. Run it
  through `compile_and_run` and attach the returned `poc_result`.
- Confidence: `confirmed` only when a `compile_and_run` PoC (Miri UB report,
  panic, or crash) or a reachability trace demonstrates the invariant being
  violated by reachable input; `likely` when the unmet precondition is
  traced but not executed; `speculative` when the invariant argument is
  unclear.

## Common false positives

- The invariant is documented in a `// SAFETY:` comment *and* provable from
  local context — e.g. the index was just bounds-checked, the pointer came
  from a live `&mut`, the length matches a just-allocated buffer.
- Standard sound patterns: `NonNull`, `MaybeUninit` used with
  `assume_init` only after full initialization, `get_unchecked` on a
  compile-time-known index, transmutes between provably identical layouts.
- FFI where the C contract is met and the buffer/lifetime discipline is
  correct.

## Stop condition

After one pass through the `scope_hint`, stop. Record zero or more findings
via `record_finding`. Recording zero findings is a valid outcome.
