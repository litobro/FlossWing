# Attack class: unsafe_pointer_misuse

An `unsafe.Pointer` is used in a way that breaks the documented safety
rules of the `unsafe` package, so the garbage collector or the memory model
can invalidate the pointer out from under the code — causing corruption,
a moved-object read, or a crash. The bug is the specific pattern that
violates one of the allowed `unsafe.Pointer` conversion rules, not the mere
presence of `unsafe`. This class is Go only.

## What to look for

- **`uintptr` stored then reconverted.** A `uintptr` value held in a
  variable, struct field, or across a statement boundary and later converted
  back to `unsafe.Pointer`. A `uintptr` is just a number; the GC does not
  track it, so the object may be moved or freed before the reconversion.
- **Pointer arithmetic split across statements.** `p := uintptr(ptr)` on one
  line and `unsafe.Pointer(p + offset)` on a later line. The arithmetic and
  the conversion back must be a single expression; splitting them opens the
  GC window.
- **Hand-built `reflect.SliceHeader` / `reflect.StringHeader`.** Constructing
  these structs by hand and taking `unsafe.Pointer` of them. Their `Data`
  field is a `uintptr` that does not keep the backing array alive — the
  documented-unsafe pattern. (`unsafe.Slice` / `unsafe.String` are the
  sanctioned replacements.)
- **Type-punning that breaks alignment or aliasing.** Casting
  `*T1` → `unsafe.Pointer` → `*T2` where `T2` has stricter alignment than
  `T1`, or where the two types alias the same bytes with incompatible layout.
- **Converting between incompatible pointer types** with no size/layout
  relationship — reinterpreting a small struct as a larger one, reading past
  the original allocation.

## Evidence

You have `read_file`, `list_dir`, `grep`, `find_definition`,
`find_callers`, `compile_and_run`, and `record_finding`. Aim for:

- `file`, `function`, `line_start`, `line_end` — pointing at the offending
  conversion, and name which `unsafe.Pointer` rule it violates.
- A `description` explaining the mechanism: why the GC or the memory model
  can invalidate the pointer here, and what the observable corruption is.
- A `poc_code` PoC where feasible. A self-contained Go program that
  demonstrates the misuse and **fails under `-race` or crashes** — or, for
  the `uintptr`-across-statements case, one where `go vet`'s `unsafeptr`
  check flags the pattern — is strong evidence. Run it through
  `compile_and_run` and attach the returned `poc_result`. Note that GC-timing
  bugs are probabilistic, so a clean run does not disprove the finding;
  a trace-based argument may be the strongest available evidence.
- Confidence: `confirmed` only when a `compile_and_run` PoC (or vet/race
  report) or a reachability trace demonstrates the rule violation reaching
  a live use; `likely` when the misuse pattern is traced but not executed;
  `speculative` when the layout/lifetime argument is uncertain.

## Common false positives

- Conversions matching the allowed patterns: same-statement pointer
  arithmetic, `syscall.Syscall`-style `uintptr(unsafe.Pointer(&x))` passed
  directly as a syscall argument, or `unsafe.Pointer` ↔ `*T` round-trips
  with no intervening `uintptr`.
- `unsafe.Slice`, `unsafe.String`, `unsafe.Add`, `unsafe.Offsetof`,
  `unsafe.Sizeof`, `unsafe.Alignof` used as documented.
- A conversion where the alignment and lifetime are locally provable and
  documented, and no `uintptr` escapes the expression.

## Stop condition

After one pass through the `scope_hint`, stop. Record zero or more findings
via `record_finding`. Recording zero findings is a valid outcome.
