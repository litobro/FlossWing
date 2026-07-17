# Attack class: format_string

Untrusted data is passed as the *format* argument of a `printf`-family
function instead of as a data argument. Because format specifiers direct
the function to read (and with `%n`, write) from the variadic argument
list, an attacker who controls the format string can disclose stack/heap
memory (`%x`, `%s`, `%p`) or corrupt memory (`%n`). The bug is the
argument *position*: the same data is harmless as a `%s` operand and
dangerous as the template. This class is C/C++ only.

## What to look for

- **User data in the format slot.** `printf(user)`, `fprintf(fp, user)`,
  `sprintf(buf, user)`, `snprintf(buf, n, user)`, `vprintf(user, ap)`,
  `syslog(pri, user)`, `err`/`warn`, `asprintf`, and any custom logging
  wrapper that forwards its argument straight into a `printf`-family call
  as the format. The tell is a non-literal first (format) argument that
  traces to input.
- **Wrapper functions.** A logging/error helper declared with
  `__attribute__((format(printf, ...)))` or one that internally calls
  `vfprintf(fp, fmt, ap)` — trace `fmt` back through its callers; the sink
  is wherever a caller passes untrusted data as that `fmt`.
- **Indirect format strings.** The format comes from a variable, a struct
  field, a config/localization/`gettext` lookup, or a network/file field
  rather than a string literal at the call site. Follow the variable to its
  origin.
- **C++ note.** Idiomatic C++ (`std::ostream <<`, `std::format` with a
  compile-time-checked literal) is not vulnerable, but C++ code frequently
  still calls C `printf`/`syslog`/`fprintf` — treat those exactly as in C.
  A runtime `fmt::runtime(user)` / `vformat(user, ...)` with an untrusted
  format is the same bug.

## Evidence

You have `read_file`, `list_dir`, `grep`, `find_definition`,
`find_callers`, `compile_and_run`, and `record_finding`. Aim for:

- `file`, `function`, `line_start`, `line_end` — pointing at the
  `printf`-family call whose format argument is untrusted.
- A `description` tracing the format argument from its untrusted source to
  the call, and confirming it is the *format* parameter, not a `%s`
  operand.
- A `poc_code` PoC is decisive. A small self-contained C/C++ program that
  reaches the sink with a crafted format (e.g. a string of `%x`/`%p` to
  dump argument memory, or `%n` to attempt a write) demonstrates the
  vulnerability: memory bytes appear in `stdout`, or the `%n` write faults
  with `SIGSEGV` (visible in `poc_result.run.signal`), and AddressSanitizer
  may report the invalid access. Run it through `compile_and_run` and
  attach the returned `poc_result`. Compiling with `-Wformat-security`
  producing a diagnostic in `build.stderr` is corroborating evidence.
- Confidence: `confirmed` only when a `compile_and_run` PoC (leaked bytes
  or a `%n` crash) or a reachability trace demonstrates the flaw; `likely`
  when the untrusted format is traced to the sink but not executed;
  `speculative` when the format argument's origin is unclear.

## Common false positives

- A constant/literal format string with the user data supplied as a
  matching `%s`/`%d` argument: `printf("%s", user)`, `syslog(LOG_ERR,
  "%s", user)`. This is the correct, safe shape — do not report it.
- A format string built only from program-controlled literals (no
  untrusted data in the format itself).
- C++ stream insertion (`std::cout << user`) or `std::format("{}", user)`
  with a literal template — the value is data, never a format directive.

## Stop condition

After one pass through the `scope_hint`, stop. Record zero or more findings
via `record_finding`. Recording zero findings is a valid outcome.
