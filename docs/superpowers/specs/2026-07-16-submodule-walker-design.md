# Submodule-aware symbol-index walker

**Issue:** #38 — "Symbol-index walker silently skips git submodule contents"
**Date:** 2026-07-16
**Status:** Approved design, pre-implementation
**Touches:** `flosswing/index/walker.py`, `flosswing/index/build.py`,
`flosswing/orchestrator.py`, plus tests. No tool-contract, schema, or
migration change.

## Problem

When a target repo uses git submodules, `flosswing scan <superproject>`
indexes **none** of the submodule code, silently. Two independent causes in
`flosswing/index/walker.py::_walk_git`:

1. `git ls-files -z` does not recurse into submodules — at the superproject
   level each submodule is listed as a single *gitlink* (the directory path),
   not the files inside it.
2. Gitlink entries are directories, so the `abs_path.is_file()` guard drops
   them anyway.

Net result: zero submodule files reach the extractor. The scan appears to
succeed and produces a report, but whole codebases are invisible with no
warning — the worst failure mode for a security tool. Reference: design
decision #5 in `docs/specs/2026-06-02-v0.5-symbol-index-design.md`.

## Approach (decided)

Option A ("use `git ls-files --recurse-submodules`") folded together with a
warning for the case that flag cannot cover (uninitialized submodules), and
the warning surfaced to the operator via the run banner — not log-only.

Rejected alternatives:

- **Explicit per-submodule recursion** (parse `.gitmodules` / gitlinks, run
  `git ls-files` per submodule, prefix paths). More code and more owned edge
  cases (nested submodules, path prefixing) for no benefit when the local git
  supports `--recurse-submodules` and the manual-walk fallback already covers
  git failures.
- **Warning-only** (the issue's stated minimum). Makes under-coverage visible
  but does not fix coverage — operators still fall back to the manual
  per-submodule workaround.

### Why the downstream plumbing needs no change

Submodule working trees live physically **inside** the superproject
directory. With `--recurse-submodules`, `git ls-files` lists submodule files
with superproject-relative paths (e.g. `assemblyline-base/foo.py`). Therefore:

- `build.py` computing `rel = str(abs_path.relative_to(repo))` still works —
  the file is genuinely under `repo`.
- The extractor's `file` field stays a clean repo-relative POSIX path.
- The out-of-tree guard in `_walk_git`
  (`str(resolved).startswith(str(repo_resolved))`) still **passes** for real
  submodule files (they resolve under `repo_root`) and still **catches** any
  symlink inside a submodule that escapes `repo_root`. No guard change.
- Git recurses into nested submodules for free.

## Changes

### 1. `flosswing/index/walker.py::_walk_git` — recurse into submodules

Add `--recurse-submodules` to the existing `git ls-files -z` invocation:

```python
["git", "-C", str(repo_root), "ls-files", "-z", "--recurse-submodules"]
```

Everything else in `_walk_git` is unchanged. Initialized submodules now have
their files listed and yielded; the `is_file()` guard passes them (real
files, not gitlinks); the out-of-tree guard is unchanged.

The existing error handling stays: a `git` that does not support the flag (or
any other `ls-files` failure) is caught by the current `returncode != 0` /
exception branches and falls back to `_walk_manual`. The manual walk already
descends into submodule working-tree directories, so coverage degrades
gracefully rather than silently dropping to zero.

### 2. `flosswing/index/walker.py` — detect uninitialized submodules

`--recurse-submodules` silently omits submodules that are declared in the
superproject index but not checked out. New helper to make that visible:

```python
def find_uninitialized_submodules(repo_root: Path) -> list[str]:
    """Return repo-relative paths of submodules declared in the index but
    not checked out (no working tree). Empty in non-git mode or when there
    are no submodules."""
```

Implementation:

- Run `git -C <repo_root> ls-files -z --stage`. Each record is
  `<mode> <object> <stage>\t<path>`; `-z` NUL-separates records so paths need
  no unquoting. Gitlink entries have mode `160000`.
- For each gitlink path, the submodule is **covered** iff its working tree
  has a `.git` entry: `(repo_root / path / ".git").exists()` (git puts a
  `.git` file, not a dir, in a checked-out submodule — `exists()` covers
  both). Return the paths that are **not** covered.
- Any `git` failure / missing binary → return `[]` (best-effort; the coverage
  fix already degraded to the manual walk in that case). Non-UTF-8 gitlink
  paths are skipped with a `logger.warning`, matching `_walk_git`.

This is a separate function (not folded into the `walk()` generator) so
`walk()` stays a pure file-yielding generator and the detection cost is paid
exactly once by `build.py`.

### 3. `flosswing/index/build.py` — populate the result

- Add a field to `IndexBuildResult`:

  ```python
  submodules_skipped: list[str] = field(default_factory=list)
  ```

- In `build_index`, after the walk (git mode is decided inside `walk`, so call
  the helper unconditionally — it returns `[]` when not applicable):

  ```python
  submodules_skipped = walker_mod.find_uninitialized_submodules(repo)
  for path in submodules_skipped:
      _log(log_fh, f"submodule not checked out, skipped: {path}")
  ```

  and pass `submodules_skipped=submodules_skipped` into the returned
  `IndexBuildResult`.

### 4. `flosswing/orchestrator.py` — surface in the banner

Under the `index:` block (currently `orchestrator.py:548-554`), add a line
that only appears when the list is non-empty:

```
    submodules_skipped: 2 (vendor/foo, ext/bar)
                        run `git submodule update --init --recursive` to include them
```

When the list is empty, no line is emitted (keep the banner quiet on the
common path). Guard for `index_result is None` like the surrounding lines.

## Testing

Walker unit tests build real git repos in a tmp dir (existing pattern), so
these use real `git init` + `git submodule add`:

- **Initialized submodule indexed.** Superproject with one initialized
  submodule containing an in-allowlist source file → `walk()` yields that file
  with a superproject-relative path (`<submodule>/<file>`).
- **Uninitialized submodule detected, not indexed.** Superproject with a
  gitlink in its index but no checked-out working tree →
  `find_uninitialized_submodules` returns that path, and `walk()` does not
  yield any file under it.
- **No submodules.** `find_uninitialized_submodules` returns `[]`; `walk()`
  unaffected.
- **Symlink-escape guard regression.** A symlink inside a submodule pointing
  outside `repo_root` is still skipped by the out-of-tree guard.
- **Git-failure fallback.** `ls-files` failure still falls back to
  `_walk_manual` (existing test, confirm still green).

`build.py` / orchestrator:

- **Result carries skipped list.** `build_index` populates
  `submodules_skipped` from the helper.
- **Banner line present iff non-empty.** Orchestrator banner includes the
  `submodules_skipped` line when the list is non-empty and omits it otherwise.

## Non-goals / scope guard

- No tool-contract change (`docs/tool-contracts.md` untouched).
- No schema or Alembic migration — `IndexBuildResult` is an in-memory
  dataclass, not a DB row.
- No change to the written report file. Surfacing is banner + `index_build.log`
  only. Adding `submodules_skipped` to the report is a separate follow-up if
  desired.
- No auto-`git submodule update` — the target repo is read-only; we only
  detect and warn. The operator initializes submodules themselves.
