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

You have `read_file`, `list_dir`, `grep`, `find_definition`,
`find_callers`, `compile_and_run`, and `record_finding`. Establish two
things: that the check and the use resolve the resource *separately*
(same path/key re-referenced, not a shared fd/handle), and that an
attacker can reach the intervening window (shared directory, predictable
name, concurrent request path). Races are hard to trigger
deterministically, so a `compile_and_run` PoC that reliably wins the
window is rarely achievable — a traced check-then-use gap on an
attacker-reachable resource is normally the ceiling at
`confidence=likely`. Reserve `confirmed` for the rare case where you
either land a reproducible race in the sandbox or trace an unambiguous
reachability path from an untrusted entry point to both operations. An
unclear link — you cannot show the attacker shares the resource, or the
two operations may actually be atomic — is `speculative`. A finding
should carry `file`, `function`, `line_start`, `line_end` spanning the
check and the use, and a `description` naming the resource, the window,
and the attacker's swap.

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
