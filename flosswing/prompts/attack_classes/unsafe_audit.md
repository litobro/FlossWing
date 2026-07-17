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
