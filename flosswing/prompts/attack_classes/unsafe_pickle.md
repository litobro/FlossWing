# Attack class: unsafe_pickle

Untrusted bytes are handed to Python's `pickle` (or a module that wraps
it) for deserialization. Unpickling is not parsing — it can construct
arbitrary objects and invoke `__reduce__` / `__setstate__` callables, so
attacker-controlled input reaching an unpickle sink is remote code
execution. The bug lives at the boundary where data of external
provenance becomes a live Python object graph.

## What to look for

The canonical shape: a value that traces back to attacker-controlled
input (an HTTP body, a cache/queue payload, a file, a socket, an
environment-derived path) flows into a deserialization sink whose format
is the pickle wire format.

- **Direct sinks.** `pickle.load` / `pickle.loads`, `cPickle`,
  `_pickle`, and the pickle-compatible `copyreg`/`__reduce__` machinery.
  `shelve` (pickle-backed key/value store) and `dbm`-of-pickles count.
- **Wrappers that default to pickle.** `pandas.read_pickle`,
  `numpy.load(..., allow_pickle=True)`, `joblib.load`,
  `torch.load` (default `weights_only=False`), `dill`, `cloudpickle`.
  Treat these as pickle sinks unless the safe mode is explicitly set.
- **Transport carriers.** A cache or message layer configured with a
  pickle serializer (e.g. a Celery/queue `serializer="pickle"`, a
  Django/Flask cache using the pickle backend) turns any producer of
  that channel into an input path — trace whether an attacker can write
  to the channel.

Grep leads: `pickle.load`, `read_pickle`, `allow_pickle=True`,
`torch.load`, `serializer="pickle"`, `Unpickler`.

## Evidence a finding should include

You have `read_file`, `list_dir`, `grep`, `find_definition`,
`find_callers`, `compile_and_run`, and `record_finding`. Aim for:

- `file`, `function`, `line_start`, `line_end` at the unpickle call
  site, plus the argument-flow story from the external source to the
  sink in `description`.
- A `poc_code` sketch: a malicious payload class whose `__reduce__`
  returns an innocuous marker (e.g. writing a file under `/scratch` or
  returning a sentinel), showing that unpickling executes it. When you
  can build a self-contained harness that feeds the payload to the
  sink, run it through `compile_and_run` and attach the `poc_result`.
- Confidence: `confirmed` only when a `compile_and_run` PoC actually
  demonstrates code execution through the sink (or a trace proves
  attacker reachability); `likely` if you can trace external input to
  the sink end-to-end but did not run it; `speculative` if the input's
  provenance or reachability is unclear.

## Common false positives

- The unpickled bytes are program-controlled and never cross a trust
  boundary (a local cache the process itself wrote and no attacker can
  influence). Trace the provenance before recording.
- The value is signed/HMAC-verified before unpickling and the key is
  not attacker-known — the integrity check gates the sink.
- A safe mode is explicitly selected: `numpy.load(..., allow_pickle=False)`,
  `torch.load(..., weights_only=True)`, or a JSON/msgpack serializer in
  place of pickle. These are the safe shapes — do not report them.
- Test/fixture code that unpickles its own committed fixtures.

## Stop condition

After one pass through the `scope_hint`, stop. Record zero or more
findings via `record_finding`. Recording zero findings is a valid
outcome.
