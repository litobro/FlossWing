# Attack class: buffer_overflow

A read or write crosses the boundary of a stack or heap buffer because a
length or index derived from untrusted input is never bounded against the
buffer's capacity. The bug lives at the copy/index site: the memory
operation itself is legal C/C++, but the size or offset it uses can exceed
the destination. This class is C/C++ only.

## What to look for

The canonical shape: attacker-controlled data (argv, stdin, `read`/`recv`
bytes, file contents, environment variables, parsed protocol fields)
reaches a memory operation whose length or index is not clamped to the
destination's size.

- **Unbounded string copies.** `strcpy`, `strcat`, `sprintf`, `vsprintf`,
  `gets`, and `scanf`/`sscanf` with a bare `%s` (no field-width) — none of
  these know the destination size, so any source longer than the buffer
  overflows. `sprintf(buf, "%s", user)` into a fixed `char buf[N]` is the
  textbook case.
- **Length-taking copies with an unchecked length.** `memcpy`, `memmove`,
  `strncpy`, `strncat`, `snprintf`, `read`, `recv` where the *count*
  argument comes from untrusted input (a header field, a parsed length
  prefix, `strlen(src)`) rather than the destination capacity.
- **Attacker-sized allocation on the stack.** `alloca(n)` or a C99 VLA
  `char buf[n]` where `n` traces to input — overflows the stack frame or
  lets a later write land past it.
- **Unchecked array indexing.** `arr[i] = ...` or `arr[i]` where `i` comes
  from input and no `i < capacity` (and `i >= 0` for signed `i`) guard
  precedes it. Watch for the index computed by arithmetic (see also
  integer_overflow).
- **Off-by-one on the NUL terminator.** A loop or copy that fills exactly
  `N` bytes into a `char[N]` and then writes a terminator at `buf[N]`, or
  `strncpy` that fills the buffer and leaves it unterminated so a later
  `strlen`/`strcpy` runs off the end.
- **C++ idioms.** `std::vector::operator[]` / `std::string::operator[]` /
  `.data()[i]` with an unchecked index (unlike `.at()`, no bounds check);
  `memcpy` into a `std::array` or `.data()` buffer with a wrong length.

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

- Bounded variants used correctly: `strncpy`/`snprintf`/`memcpy` whose
  count is the *destination* capacity (e.g. `sizeof buf`, or `sizeof buf - 1`
  with an explicit terminator), not the source length.
- The length is validated against capacity before the copy (`if (len <
  sizeof buf)`), or the input is otherwise clamped upstream.
- Fixed compile-time sizes indexed only by constants or values provably in
  range (loop counter bounded by the same constant).
- `std::string`/`std::vector` growth via `push_back`, `append`, `+=`,
  `resize` — these reallocate; they don't overflow.

## Stop condition

After one pass through the `scope_hint`, stop. Record zero or more findings
via `record_finding`. Recording zero findings is a valid outcome.
