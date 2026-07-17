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

You have `read_file`, `list_dir`, `grep`, `find_definition`,
`find_callers`, `compile_and_run`, and `record_finding`. Aim for:

- `file`, `function`, `line_start`, `line_end` — pointing at the deref
  site, and cite the NULL-producing call in the description.
- A `description` explaining what makes the pointer NULL (which call can
  return NULL and under what attacker-reachable condition) and why no check
  intervenes before the deref.
- A `poc_code` PoC is decisive. A small self-contained C/C++ program that
  forces the NULL (e.g. an allocation-failure shim, a lookup miss, or
  malformed input) and reaches the deref will **crash with SIGSEGV** — the
  signal appears in `poc_result.run.signal`, and AddressSanitizer reports a
  `SEGV on unknown address 0x000000000000` (a null deref). Run it through
  `compile_and_run` and attach the returned `poc_result`.
- Confidence: `confirmed` only when a `compile_and_run` PoC (SIGSEGV / ASan
  null-address report) or a reachability trace demonstrates the deref;
  `likely` when the NULL source and the unchecked deref are traced but not
  run; `speculative` when reachability of the NULL case is unclear.

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
