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
