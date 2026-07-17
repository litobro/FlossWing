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
