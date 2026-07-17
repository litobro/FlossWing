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

You have `read_file`, `list_dir`, `grep`, `find_definition`,
`find_callers`, `compile_and_run`, and `record_finding`. Aim for:

- `file`, `function`, `line_start`, `line_end` — pointing at the copy or
  index site, not just the buffer declaration.
- A `description` tracing the length/index from its untrusted source to the
  sink, and stating why nothing bounds it against the destination size.
- A `poc_code` PoC is decisive here. A small self-contained C/C++ program
  that feeds an oversized input to the vulnerable shape and **crashes under
  AddressSanitizer** (`-fsanitize=address`) — a `heap-buffer-overflow` /
  `stack-buffer-overflow` report, or a raw `SIGSEGV` — is direct proof.
  Run it through `compile_and_run` and attach the returned `poc_result`;
  the `signal`/`stderr` fields carry the ASan diagnostic.
- Confidence: `confirmed` only when a `compile_and_run` PoC (ASan/segfault)
  or a reachability trace demonstrates the overrun; `likely` when you can
  trace the unbounded length end-to-end but did not execute it;
  `speculative` when the buffer size or the input bound is unclear.

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
