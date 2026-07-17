# Attack class: redos

A regular expression with catastrophic backtracking is evaluated against
attacker-controlled input, so a crafted string forces the engine into
super-linear (often exponential) work and exhausts CPU — a denial of
service. The bug lives where an ambiguous pattern meets an untrusted,
unbounded subject on a backtracking engine.

## What to look for

Patterns whose structure lets the engine match the same text many
ways, applied to request data (bodies, query params, headers,
uploaded content, user-agent strings):

- **Nested quantifiers** — `(a+)+`, `(a*)*`, `(a+)*` — a quantified
  group inside another quantifier.
- **Overlapping alternation under a quantifier** — `(a|a)*`,
  `(\d|\d\d)+`, `(x|xy)+` — branches that can match the same input.
- **Unbounded `.*`/`.+` around ambiguous groups** — `(.*)*`, `(.*a){n}`,
  long chains of optional segments before a required tail.
- **Where it runs.** Backtracking engines: Python `re`, JavaScript
  `RegExp`, Java `java.util.regex`, .NET `Regex`, PCRE. The dangerous
  case is one of these evaluating such a pattern against input whose
  length is not capped before matching.

**Linear-time engines are out of scope.** Go's `regexp` (RE2) and
Rust's `regex` crate guarantee linear time and cannot catastrophically
backtrack — a scary-looking pattern there is a **false positive** for
ReDoS. Note the engine explicitly and do not report it.

## Evidence

You have `read_file`, `list_dir`, `grep`, `find_definition`,
`find_callers`, `compile_and_run`, and `record_finding`. This is the one
class where execution is decisive: build a `compile_and_run` PoC that
compiles the exact pattern on the same engine and times it against a
short pathological input versus a benign one of equal length. A
super-linear blow-up (e.g. seconds on a few dozen characters) is strong
`confidence=confirmed` evidence — attach the timing in `poc_result`.
Without a run, an end-to-end trace showing the untrusted subject reaching
the vulnerable pattern with no length cap is `likely`. If you cannot
confirm the input is attacker-controlled or that the pattern actually
backtracks, it is `speculative`. A finding should carry `file`,
`function`, `line_start`, `line_end` at the pattern (or the match call)
and a `description` naming the engine, the ambiguous construct, and the
input path.

## Common false positives

- **Linear-time engine** (RE2 via Go `regexp`, Rust `regex`) — cannot
  backtrack catastrophically. Not a finding.
- The subject's length is hard-capped before matching (short, bounded
  input) so worst-case cost stays trivial.
- Anchored patterns with no ambiguous overlap, or fixed-width quantifiers
  small enough that backtracking cannot explode.
- Atomic groups `(?>...)` or possessive quantifiers (`a++`, `a*+`) that
  disable the backtracking that ReDoS depends on.
- The pattern is a compile-time constant matched only against
  program-controlled strings, not untrusted input.

## Stop condition

After one pass through the `scope_hint`, stop. Record zero or more
findings via `record_finding`. Recording zero findings is a valid
outcome.
