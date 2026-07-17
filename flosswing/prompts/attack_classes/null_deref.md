# Attack class: null_deref

A pointer that can legitimately be NULL is dereferenced on a reachable path
without a guarding null check, and an attacker can force the NULL — most
often by making an allocation or lookup fail, or by supplying input that
selects the not-found branch. The result is a crash (denial of service) and
occasionally worse on platforms where page zero is mappable. This class is
C/C++ only.

## What to look for

- **Unchecked allocation results.** `malloc`, `calloc`, `realloc`,
  `strdup`, `strndup`, `aligned_alloc`, or C++ `new (std::nothrow)` whose
  return is dereferenced (or `memcpy`'d into) without a `!= NULL` check.
  Attacker-influenced sizes make failure inducible.
- **Unchecked lookup / accessor returns.** Functions documented to return
  NULL on miss or error: `strchr`/`strstr`/`strrchr`, `getenv`, `fopen`,
  `fdopen`, `gets`-style readers, hash/map lookups, `dlsym`, XML/JSON node
  getters, `find`-style helpers returning a pointer — dereferenced on a
  path an attacker can steer to the miss case.
- **Unchecked parse/decode results.** A parser or accessor that returns
  NULL for malformed input, followed by a field access through the returned
  pointer — a malformed request drives the NULL.
- **Return value ignored then used.** A function whose contract is
  "returns NULL on failure" called for its side effect, with the result
  later dereferenced through an alias.
- **C++ shapes.** A `T*` from a raw `find`, from `dynamic_cast<T*>` (yields
  NULL on failure), from `.get()` on an empty smart pointer, or a
  `std::optional` / pointer accessed without checking; also a reference
  bound from a dereferenced possibly-null pointer.

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

- The pointer is provably non-NULL at the deref: allocated-and-checked just
  above, or an invariant guarantees non-NULL on this path.
- A prior null check guards the deref (`if (!p) return;` / early-out /
  `assert(p)` in a build where the failure path is truly unreachable).
- Allocators configured to abort on failure rather than return NULL
  (`new` without `nothrow` throws `std::bad_alloc`; a wrapper that
  `abort()`s on NULL) — the deref is never reached with NULL.
- A lookup whose miss case cannot be attacker-selected (keys are
  program-controlled and known present).

## Stop condition

After one pass through the `scope_hint`, stop. Record zero or more findings
via `record_finding`. Recording zero findings is a valid outcome.
