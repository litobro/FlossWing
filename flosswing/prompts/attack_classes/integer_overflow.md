# Attack class: integer_overflow

Arithmetic on an attacker-controlled integer wraps, truncates, or changes
sign, and the corrupted result then drives a size, allocation, index, or
bounds decision. The overflow itself is often silent; the damage is the
downstream memory operation that trusts the wrong number. This class is
C/C++ only, and it is frequently the root cause behind a buffer_overflow or
heap corruption — record it where the arithmetic goes wrong.

## What to look for

- **Multiplication in an allocation size.** `malloc(n * size)`,
  `calloc`-style hand-rolled `n * elem`, `realloc(p, count * width)` where
  `n`/`count` is attacker-controlled and the product overflows `size_t` —
  the allocation is too small, and the subsequent fill overflows it.
- **Addition in a size or offset.** `malloc(len + header)` or
  `p + user_offset` where the sum wraps, yielding a tiny allocation or an
  out-of-range pointer.
- **Signed overflow (undefined behavior).** `int` arithmetic on
  input-derived values (`a + b`, `a * b`, `-INT_MIN`) that overflows — UB
  the optimizer may fold away a subsequent check, or that produces a
  negative length.
- **Narrowing casts before a bounds check.** `size_t`/`long` value from
  input truncated into an `int`/`short`/`unsigned char` (`int len =
  recv_len;`) so a large real length becomes small or negative, defeating a
  later `if (len < cap)` test.
- **Subtraction underflow used as a length.** `size_t remaining = end -
  start;` or `len - offset` where the subtrahend can exceed the minuend,
  producing a huge unsigned value that is then used as a copy count or loop
  bound.
- **Sign-confusion in comparisons.** A signed length compared against an
  unsigned capacity, where a negative input passes the check and is then
  reinterpreted as a large unsigned count by `memcpy`/`read`.

## Evidence

You have `read_file`, `list_dir`, `grep`, `find_definition`,
`find_callers`, `compile_and_run`, and `record_finding`. Aim for:

- `file`, `function`, `line_start`, `line_end` — pointing at the arithmetic
  site, and name the downstream sink (the allocation, `memcpy`, or index)
  the corrupted value feeds.
- A `description` tracing the operand from its untrusted source, the
  specific way it overflows/truncates/underflows, and the memory decision
  that then trusts it.
- A `poc_code` PoC is decisive. A small self-contained C/C++ program that
  supplies the boundary input and **trips a sanitizer** —
  UndefinedBehaviorSanitizer (`-fsanitize=undefined`) reporting
  `signed-integer-overflow`/`shift`, or AddressSanitizer catching the
  resulting `heap-buffer-overflow` from the undersized allocation — is
  direct proof. Run it through `compile_and_run` and attach the returned
  `poc_result`. Note the wrapped value in `stdout` and the ASan/UBSan
  report in `stderr`.
- Confidence: `confirmed` only when a `compile_and_run` PoC (UBSan/ASan or
  a demonstrated undersized buffer) or a reachability trace shows the
  overflow driving a bad memory op; `likely` when the arithmetic and its
  use are traced but not run; `speculative` when the operand's range or
  reachability is unclear.

## Common false positives

- Checked or saturating arithmetic: an explicit `if (n > SIZE_MAX / size)`
  guard before the multiply, a saturating clamp, or `__builtin_mul_overflow`
  / `__builtin_add_overflow` whose result is tested.
- An explicit size cap on the input before the arithmetic (`if (count >
  MAX) reject`), so overflow cannot occur.
- Arithmetic on values provably bounded by construction (fixed constants,
  a prior range check that dominates the operation).
- Wraparound on a value that never feeds a size/index/bounds decision (a
  pure hash, a counter that is only compared for equality).

## Stop condition

After one pass through the `scope_hint`, stop. Record zero or more findings
via `record_finding`. Recording zero findings is a valid outcome.
