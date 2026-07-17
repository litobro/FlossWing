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

You have `read_file`, `list_dir`, `grep`, `find_definition`,
`find_callers`, `compile_and_run`, and `record_finding`. A finding
should carry `file`, `function`, `line_start`, `line_end` at the parse
call; a `description` tracing where the untrusted YAML enters, that the
loader honors object tags, and why nothing restricts it to a safe
schema; and a `poc_code` document using a language-object tag (e.g. a
`!!python/object/apply:os.system` payload) that would execute on parse.
This class is PoC-friendly: a self-contained snippet that calls the same
loader on a benign-but-observable tagged payload (e.g. one that writes a
marker file or returns a sentinel) inside the sandbox demonstrates
object instantiation — attach `poc_result` for `confidence=confirmed`.
Trace untrusted bytes into an unsafe loader end-to-end without running →
`likely`; if the input's untrustedness or the loader mode is unclear →
`speculative`.

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
