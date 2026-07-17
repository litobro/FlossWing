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
