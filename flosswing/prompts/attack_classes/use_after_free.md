# Attack class: use_after_free

A pointer is dereferenced after the memory it refers to has been released,
or memory is released twice. This includes classic use-after-free
(`free`/`delete` then later read/write through the same pointer),
double-free, and dangling pointers left by reallocation or by returning the
address of a stack local. The bug is temporal: the access is spatially
in-bounds but happens at the wrong time. This class is C/C++ only.

## What to look for

- **Free-then-use.** A `free(p)` / `delete p` / `delete[] p` followed on a
  reachable path by a read or write through `p` (or an alias of `p`).
  Especially in error-handling and cleanup paths where one branch frees and
  a later shared branch still touches the pointer.
- **Double-free.** Two frees of the same allocation with no reassignment
  between them — often via two aliases, or a free in both an error path and
  the normal path that fall through to a common `free`.
- **Dangling after realloc.** `p = realloc(q, n)` where old aliases of `q`
  are used afterward — `realloc` may move the block, invalidating every
  other pointer into it.
- **Return of a stack address.** A function returning `&local`, a pointer
  to a local array, or a `std::string_view` / pointer into a local that
  outlives the frame.
- **C++ container/iterator invalidation.** Holding a pointer, reference, or
  iterator into a `std::vector` (or `std::string`) across a `push_back`,
  `insert`, `resize`, `reserve`, `emplace_back`, or `erase` that can
  reallocate or shift elements — the saved handle now dangles.
- **Use-after-move.** Reading a `std::unique_ptr`, `std::string`, or other
  moved-from object after `std::move`, then dereferencing (moved-from
  `unique_ptr` is null; moved-from containers are valid-but-unspecified —
  a deref of the moved-from smart pointer is the sharp case).
- **Ownership handed off then reused.** A pointer passed to a function or
  container that takes ownership and frees it, then used by the caller.

## Evidence

You have `read_file`, `list_dir`, `grep`, `find_definition`,
`find_callers`, `compile_and_run`, and `record_finding`. Aim for:

- `file`, `function`, `line_start`, `line_end` — pointing at the *use* site
  (the deref after free), and cite the freeing site in the description.
- A `description` establishing both events and the path between them: where
  the memory is freed, where it is used, and why the two can occur in that
  order for one allocation.
- A `poc_code` PoC is decisive. A small self-contained C/C++ program that
  reproduces the free-then-use (or double-free) and **crashes under
  AddressSanitizer** — a `heap-use-after-free` or `attempting double-free`
  report, or a `SIGSEGV` — is direct proof. Run it through
  `compile_and_run` and attach the returned `poc_result`. For container
  invalidation, a PoC that provokes the reallocation and reads the stale
  pointer under ASan is the cleanest demonstration.
- Confidence: `confirmed` only when a `compile_and_run` PoC (ASan) or a
  reachability trace demonstrates the temporal violation; `likely` when the
  free and the later use are both traced but not executed; `speculative`
  when the ordering or aliasing is uncertain.

## Common false positives

- Pointer set to `NULL` (or reassigned to a fresh allocation) immediately
  after `free`, and null-checked before any later use.
- Clear single ownership with no aliasing: the freed pointer goes out of
  scope and is never touched again.
- RAII / smart pointers (`std::unique_ptr`, `std::shared_ptr`,
  `std::vector` owning its storage) where lifetime is tied to scope and no
  raw alias escapes.
- A saved iterator/pointer used only across container operations that do
  **not** invalidate it (e.g. `std::list`/`std::map` node stability, or a
  `vector` index re-fetched rather than a cached pointer).

## Stop condition

After one pass through the `scope_hint`, stop. Record zero or more findings
via `record_finding`. Recording zero findings is a valid outcome.
