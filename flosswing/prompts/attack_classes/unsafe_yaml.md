# Attack class: unsafe_yaml

YAML from an untrusted source is parsed with a loader that can
instantiate arbitrary language objects from YAML tags, turning a data
format into a code-execution vector. YAML's type tags let a document
name a class or callable the loader will construct; a permissive loader
honors them, so a crafted document runs attacker-chosen code during
parsing. The bug lives at a parse call that uses a full/unsafe loader on
data the attacker controls — not at YAML parsing in general.

## What to look for

A parse of attacker-controlled bytes (request bodies, uploaded files,
config fetched from a network peer, message payloads) with a loader that
resolves language-object tags.

- **Python.** `yaml.load(data)` without `Loader=SafeLoader` (the
  one-argument form is unsafe on old PyYAML), `yaml.load(data,
  Loader=Loader)`, `yaml.unsafe_load`, or `Loader=FullLoader` on hostile
  input. The smoking gun in the document itself is a
  `!!python/object:...`, `!!python/object/apply:...`, or
  `!!python/name:...` tag.
- **Ruby.** `YAML.load(data)` / `Psych.load(data)` on untrusted input
  (unsafe before the Psych 4 default flip), which can revive arbitrary
  Ruby objects via `!ruby/object:` tags.
- **Other loaders.** Any language binding whose "full"/"unsafe" load
  entry point deserializes tagged objects, applied to untrusted bytes.

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

- `yaml.safe_load` / `Loader=SafeLoader` (Python) or `YAML.safe_load` /
  `Psych.safe_load` (Ruby). The safe shape — do not report it.
- A loader restricted to a schema that resolves only core scalar/
  collection types and rejects application tags.
- The parsed YAML is program-controlled (a bundled config file the
  attacker cannot modify), not attacker-supplied input.
- `FullLoader` on genuinely trusted, non-attacker-reachable input —
  note the fragility but do not rate it as a live vulnerability absent
  an untrusted source.

## Stop condition

After one pass through the `scope_hint`, stop. Record zero or more
findings via `record_finding`. Recording zero findings is a valid
outcome.
