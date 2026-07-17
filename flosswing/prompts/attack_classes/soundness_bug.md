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

You have `read_file`, `list_dir`, `grep`, `find_definition`,
`find_callers`, `compile_and_run`, and `record_finding`. Aim for:

- `file`, `function`, `line_start`, `line_end` — pointing at the safe API
  boundary that is unsound, and name the invariant a safe caller can break.
- A `description` establishing the unsoundness: the internal assumption, why
  the safe signature fails to enforce it, and the sequence of *safe* calls
  that reaches UB.
- A `poc_code` PoC is decisive. A self-contained Rust program that uses only
  safe code against the API and **exhibits UB under Miri** (`cargo miri run`
  reporting the violation) or crashes/miscompiles is direct proof — the key
  is that the PoC contains no `unsafe`. Run it through `compile_and_run` and
  attach the returned `poc_result`.
- Confidence: `confirmed` only when a `compile_and_run` PoC (safe-only,
  Miri UB or crash) or a reachability trace shows safe code reaching UB;
  `likely` when the unsound path is traced but not executed; `speculative`
  when the soundness argument is unclear.

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
