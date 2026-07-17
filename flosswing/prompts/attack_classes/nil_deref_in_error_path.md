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
