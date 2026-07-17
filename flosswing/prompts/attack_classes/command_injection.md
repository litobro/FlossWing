# Attack class: command_injection

Untrusted data flows into a string that is then handed to a shell
interpreter — `/bin/sh`, `/bin/bash`, `cmd.exe`, or any equivalent —
where shell metacharacters (`; & | $(...) `` ${...}`) cause execution
of attacker-controlled commands. The bug lives at the boundary where
data becomes a shell command.

## What to look for

The canonical shape across languages: a function builds a shell
command string by concatenation, interpolation, or formatting using
data that ultimately traces back to attacker-controlled input (CLI
argv, HTTP request bodies and query strings, file contents, stdin,
environment variables, IPC messages), then hands that string to the
language's shell-passthrough subprocess APIs.

Language-by-language indicators:

- **Python.** A subprocess call whose argument is a single concatenated
  string AND whose API runs the string through `/bin/sh` — the
  shell-passthrough flag is set, or the convenience wrapper that
  forwards to a system shell is used. The `shell=True` flag and the
  top-level "run this string in the system shell" stdlib helpers are
  the high-signal smells.
- **Go.** The shell-spawn child-process family — the standard library
  command-execution helper when the first argument is `sh` or `bash`
  and the second is `-c` followed by a string built from untrusted
  input. Direct calls with unparsed user data as the program name or
  as a flag-bearing arg are the same bug in different clothing.
- **JavaScript / Node.** The shell-spawning child-process helpers
  (the variant that runs a string through `/bin/sh` rather than the
  argv-list variant) when the string is built from request data.
  Templates that pipe a request field directly into a shell string
  are textbook.
- **Java.** Runtime exec-string overloads (the one-string form goes
  through the system shell on some platforms) or any process-builder
  whose command list begins with `sh -c` or `cmd /c` and ends with a
  user-built string.
- **C / C++.** Any libc API that takes a single command-line string
  and routes it through the system shell. The "pipe-open" and
  "system-shell-exec" wrappers are the obvious ones. The exec-with-
  path-search family with an unsanitized first argument shows up too.
- **Rust.** The standard-library command builder configured with
  `sh -c <user>` — same shape, just spelled out.

## Evidence a finding should include

You have `read_file`, `list_dir`, `grep`, `find_definition`,
`find_callers`, `compile_and_run`, and `record_finding`. Aim for:

- `file`, `function`, `line_start`, `line_end` — pointing at the
  shell-passthrough call site.
- A 1–3 sentence `description` of the argument flow: where the user
  data enters, how it reaches the sink, and why it isn't escaped.
- A `poc_code` sketch showing what input would demonstrate the bug.
  When you can build a self-contained PoC, run it through
  `compile_and_run` and attach the returned `poc_result`; otherwise
  leave that field unset.
- Confidence: `confirmed` only when a `compile_and_run` PoC (or a
  reachability trace) actually demonstrates execution; `likely` if you
  can trace the argument flow end-to-end but did not run it;
  `speculative` if a piece of the chain is unclear.

## Common false positives

- The shell-passthrough call is reached only with a literal string
  the program controls (no untrusted data in scope).
- The data passes through a documented escaping / argv-splitting
  helper before reaching the sink.
- The subprocess call uses the argv-list form, not the shell-string
  form. This is the safe shape — do not record it as a finding.

## Stop condition

After one pass through the `scope_hint`, stop. Record zero or more
findings via `record_finding`. Recording zero findings is a valid
outcome.
