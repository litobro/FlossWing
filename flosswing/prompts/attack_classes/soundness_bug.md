# Attack class: soundness_bug

A *safe* API — a function or trait impl with no `unsafe` in its signature —
lets ordinary safe caller code trigger undefined behavior. The unsafety is
encapsulated behind a safe surface whose preconditions the type system does
not enforce, so a caller who writes only safe Rust can still reach UB. The
bug is the unsound *boundary*, not the `unsafe` block itself. This class is
Rust only.

## What to look for

- **`unsafe` behind a safe fn with caller-violable preconditions.** A public
  safe function whose internal `unsafe` is sound only if the caller passes
  (say) an in-bounds index or a valid length, but nothing in the signature
  or body enforces that — a safe caller can pass a violating value.
- **Lifetime-extending transmutes exposed safely.** A safe API that hands out
  a reference whose lifetime was extended (via `transmute` or raw-pointer
  round-trip) beyond the data it borrows, letting safe code hold a dangling
  reference.
- **Hand-written `Send` / `Sync` impls that are not thread-safe.** `unsafe
  impl Send`/`Sync` on a type containing `Rc`, a raw pointer, or interior
  mutability without synchronization — safe code can then share it across
  threads and race.
- **Returning references into freed or moved data.** A safe method returning
  `&T` (or an iterator/guard) that borrows from a local, a moved value, or a
  buffer freed before the reference dies.
- **Exposing uninitialized or invalid memory.** A safe API returning a value
  read from `MaybeUninit` before initialization, or constructing a type with
  an invalid bit pattern (out-of-range `enum`, non-UTF-8 `str`, `bool` ≠ 0/1).

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

- The soundness argument holds for *all* safe inputs: the safe signature (via
  types, bounds checks inside, or `unsafe fn` on the truly-unchecked entry)
  makes the precondition impossible to violate from safe code.
- `unsafe` correctly encapsulated — the invariant is re-established inside the
  function before the `unsafe` op regardless of arguments.
- `unsafe impl Send`/`Sync` that is genuinely justified (e.g. the raw pointer
  is only ever accessed under a mutex, or the type is deeply immutable).
- Reference-returning APIs whose lifetimes are correctly tied to the borrow
  by the signature (`&self` → `&'_ T`).

## Stop condition

After one pass through the `scope_hint`, stop. Record zero or more findings
via `record_finding`. Recording zero findings is a valid outcome.
