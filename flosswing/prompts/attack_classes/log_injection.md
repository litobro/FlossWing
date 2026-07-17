# Attack class: log_injection

Untrusted data is written to a log without neutralizing CR/LF or control
characters, so an attacker can forge or split log entries. By embedding
a newline plus a well-formed line, an attacker injects fabricated
records (log spoofing), corrupts downstream log parsers and SIEM
ingestion, or smuggles terminal-escape (ANSI) sequences that mislead
whoever reads the log in a console. A related shape is passing user data
as the logger *format string*, which can crash or leak via format
specifiers. The bug lives where a raw request field reaches the log
message with no newline/control-char neutralization.

## What to look for

A logging call whose message interpolates request-derived data
(user-agent, username, path, referrer, header values, request body
fields) with no sanitization.

- **Python.** `logging` calls — `logger.info(f"login {username}")`,
  `logger.warning("bad path: " + request.path)` — where the interpolated
  value is a raw request field. Also the anti-pattern of user data *as
  the format string*: `logger.info(user_input)` or `logger.info(user_input
  % args)`, which is both an injection and a format bug.
- **Java.** SLF4J/Log4j/Logback `log.info("user {} in", userInput)` or
  concatenated `log.info("user " + userInput)` with CRLF-bearing input.
  (Note this class is about forged log lines; template-lookup RCE like
  Log4Shell is a different concern.)
- **JavaScript / Node.** `console.log`/`winston`/`pino` messages built by
  concatenation or template literals from `req.headers`, `req.body`,
  `req.query` without escaping newlines.
- **Go / others.** `log.Printf("user=%s", userInput)` and structured
  loggers where the value is placed in a free-text message field rather
  than an escaped key.

## Evidence

You have `read_file`, `list_dir`, `grep`, `find_definition`,
`find_callers`, and `compile_and_run`, reporting through
`record_finding`. Trace the request field into the log call with
`find_callers`/`grep` and check for any newline/control-char stripping
or structured-field encoding on the path. A finding should carry
`file`, `function`, `line_start`, `line_end` at the log call, a
`description` tracing the untrusted field into the message and noting the
absence of CR/LF neutralization, and a `poc_code` payload showing a
forged line (input containing `\n` followed by a fake `INFO ...` record,
or an ANSI escape). `compile_and_run` helps here: logging is
self-contained, so a small harness that logs the crafted input and shows
the captured output split into a forged second line (or a format-string
value being interpreted) earns `confidence=confirmed` — attach
`poc_result`. A clean end-to-end trace without execution is `likely`; an
unclear source or uncertain reachability is `speculative`. Severity is
usually low/medium unless the forged lines feed a security-critical
parser or the format-string path enables a leak/crash.

## Common false positives

- Newlines/control characters are encoded or stripped before logging, or
  the framework applies such sanitization (e.g. an encoding log
  formatter/filter).
- Structured logging (JSON or key/value) where the user value is a
  discrete, escaped field — an injected newline stays inside the field's
  quoted value and cannot forge a new record.
- The value is a program-controlled constant or already an allow-listed
  token (an enum, a numeric id), not free-form attacker text.
- The interpolated value is not attacker-controlled.

## Stop condition

After one pass through the `scope_hint`, stop. Record zero or more
findings via `record_finding`. Recording zero findings is a valid
outcome.
