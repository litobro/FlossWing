# Attack class: nil_deref_in_error_path

A value is dereferenced after a function returned a non-nil `error`, or on
an error path where a nil pointer, interface, or map is returned alongside
the error and a caller then uses it. When the error is ignored or mishandled,
the accompanying value is nil and the deref panics. The bug lives at the
gap between "a call failed" and "the code used the result anyway." This
class is Go only.

## What to look for

- **Result used before the `err` check.** A `v, err := f()` followed by a
  read or method call on `v` that appears *before* — or on a branch that
  skips — the `if err != nil` guard.
- **`(nil, err)` returned, then deref'd by an ignoring caller.** A function
  whose error path returns `return nil, err` (nil pointer/interface), and a
  caller that writes `v, _ := f()` or otherwise drops the error and
  dereferences `v`.
- **Nil map write.** A `map` field or variable that is only conditionally
  initialized, then written via `m[k] = ...` on a path where `make` never
  ran — a write to a nil map panics (reads are fine).
- **Type assertion without comma-ok.** `x := i.(T)` (single-return form) on
  an interface that can hold a different or nil dynamic type — panics on
  mismatch. The `x, ok := i.(T)` form is the safe shape.
- **Deref of an interface holding a nil pointer.** A method called on an
  interface value whose concrete pointer is nil, where the method body
  dereferences the receiver.

## Evidence

You have `read_file`, `list_dir`, `grep`, `find_definition`,
`find_callers`, `compile_and_run`, and `record_finding`. Aim for:

- `file`, `function`, `line_start`, `line_end` — pointing at the *deref*
  site, and cite the producing call (and its error path) in the description.
- A `description` establishing the flow: which call can return a nil value,
  why the error that accompanies it is ignored or bypassed, and where the
  nil value is then dereferenced.
- A `poc_code` PoC is decisive. A small self-contained Go program that
  reproduces the shape and **panics** with `runtime error: invalid memory
  address or nil pointer dereference` (or `assignment to entry in nil map`,
  or an interface conversion panic) is direct proof. Run it through
  `compile_and_run` and attach the returned `poc_result`.
- Confidence: `confirmed` only when a `compile_and_run` PoC panics or a
  reachability trace shows the nil value reaching the deref; `likely` when
  both the nil-producing path and the deref are traced but not executed;
  `speculative` when it is unclear the error path and the deref can co-occur.

## Common false positives

- The error is checked and handled (return, continue, log-and-skip) before
  any use of the result — the safe shape, do not report it.
- The value is provably non-nil on the path in question: a fresh `&T{}`, a
  `make`'d map, or a constructor that never returns nil alongside a non-nil
  error.
- A type assertion guarded by comma-ok, or preceded by a type switch that
  establishes the dynamic type.
- A nil map that is only *read*, never written, on the reachable path.

## Stop condition

After one pass through the `scope_hint`, stop. Record zero or more findings
via `record_finding`. Recording zero findings is a valid outcome.
