# Attack class: toctou

A resource's state is *checked* and then *used* in a separate,
non-atomic step, and an attacker who shares access to that resource can
change it in the window between the two operations (time-of-check to
time-of-use). The bug lives where a check and the action it guards
resolve the resource independently — by name, by key, by row — instead
of operating atomically on a single handle.

## What to look for

The canonical shape: a guard that inspects a resource by an
indirect reference (a path, a lock name, a DB key), followed by a
distinct operation that re-resolves that same reference and acts on
whatever it now points to. The attacker's move is to swap the target
(replace a file with a symlink, win a create race, mutate a shared row)
after the check and before the use.

- **C / C++.** `access()`/`stat()`/`lstat()` then `open()`/`fopen()`
  on the same path; check-then-`open(O_CREAT)` without `O_EXCL`;
  following a path an attacker can replace with a symlink. The safe
  shape is `open(..., O_CREAT|O_EXCL|O_NOFOLLOW)`, `openat` with flags,
  or `mkstemp`, then `fstat()` on the returned *fd*.
- **Python.** `os.path.exists()`/`os.path.isfile()`/`os.access()` then
  `open()` on the same string path; check-then-write to a predictable
  temp path instead of `tempfile.mkstemp`/`NamedTemporaryFile`;
  `os.path.islink` guards that re-`open` by name.
- **Go.** `os.Stat()`/`os.Lstat()` then `os.Open()`/`os.OpenFile()` on
  the path; create races without `O_EXCL` in the `OpenFile` flags.
- **Java.** `File.exists()`/`canWrite()` then `new FileOutputStream(f)`;
  `File.createNewFile` used as a lock without atomic guarantees.
- **Shared state.** A read of a DB row or shared-memory value, a
  decision based on it, then a write — with no enclosing transaction,
  `SELECT ... FOR UPDATE`, compare-and-swap, or held lock.

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

- The operation is already atomic: `O_CREAT|O_EXCL`, `openat` with
  `O_NOFOLLOW`, `mkstemp`/`mkdtemp`, or a compare-and-swap primitive.
- The action operates on a file descriptor / handle obtained *once*
  (e.g. `fstat` on an already-open fd) rather than re-resolving the
  path by name — no window exists.
- The check and use are inside a held lock, a single DB transaction, or
  a `SELECT ... FOR UPDATE`, so no other actor can interleave.
- The resource lives in a private, non-shared location the attacker
  cannot write to or race on.

## Stop condition

After one pass through the `scope_hint`, stop. Record zero or more
findings via `record_finding`. Recording zero findings is a valid
outcome.
