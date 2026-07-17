# Submodule-aware symbol-index walker — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `flosswing scan <superproject>` index the code inside initialized git submodules, and make skipped (uninitialized) submodules visible to the operator instead of silently dropped.

**Architecture:** Add `--recurse-submodules` to the `git ls-files` call in `walker.py::_walk_git` (submodule files live under `repo_root`, so downstream path handling and the out-of-tree guard are unchanged). Add a `find_uninitialized_submodules()` helper that reports declared-but-not-checked-out submodules; `build_index` carries them on `IndexBuildResult.submodules_skipped`, and the orchestrator banner shows a line when non-empty.

**Tech Stack:** Python 3.11+, `subprocess` + `git`, pytest / pytest-asyncio. Design spec: `docs/superpowers/specs/2026-07-16-submodule-walker-design.md`. Issue #38.

## Global Constraints

- Python 3.11+, full type hints. `ruff check` and `mypy --strict` must pass (config in `pyproject.toml`).
- Tool contracts are frozen — no change to `docs/tool-contracts.md`. This work touches none.
- No schema/Alembic migration — `IndexBuildResult` is an in-memory dataclass, not a DB row.
- No write access to the target repo — detect/warn only; never run `git submodule update`.
- Existing walker unit tests **mock** `subprocess.run` (they fake `.git` with `mkdir`); follow that pattern, do not shell out to real git.
- `git ls-files` timeout constant already exists: `_GIT_LS_FILES_TIMEOUT_SECONDS` in `walker.py`.
- Commit messages reference the spec/issue (e.g. "per docs/superpowers/specs/2026-07-16-submodule-walker-design.md").

---

### Task 1: Recurse into submodules in `_walk_git`

**Files:**
- Modify: `flosswing/index/walker.py:87-92` (the `git ls-files` argv in `_walk_git`)
- Test: `tests/unit/test_index_walker.py`

**Interfaces:**
- Consumes: nothing new.
- Produces: no signature change. `walk()` now yields files inside initialized submodules with superproject-relative paths (e.g. `vendor/lib/mod.py`).

- [ ] **Step 1: Write the failing test**

Add to `tests/unit/test_index_walker.py`:

```python
def test_walker_git_mode_recurses_submodules(tmp_path: Path) -> None:
    """--recurse-submodules is passed and submodule files are yielded."""
    repo = _make_git_repo(tmp_path, {
        "glue.py": "pass\n",
        "vendor/lib/mod.py": "def f(): pass\n",  # inside a submodule work-tree
    })
    fake_output = b"glue.py\x00vendor/lib/mod.py\x00"
    fake_proc = MagicMock(returncode=0, stdout=fake_output, stderr=b"")
    with patch.object(subprocess, "run", return_value=fake_proc) as m:
        files = sorted(
            str(p.relative_to(repo)) for p, _ in walker.walk(
                repo, languages_allowlist={"python"}
            )
        )
    args, _ = m.call_args
    assert "--recurse-submodules" in args[0]
    assert files == ["glue.py", "vendor/lib/mod.py"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_index_walker.py::test_walker_git_mode_recurses_submodules -v`
Expected: FAIL — `assert "--recurse-submodules" in args[0]` fails (flag not yet added).

- [ ] **Step 3: Add the flag**

In `flosswing/index/walker.py::_walk_git`, change the argv:

```python
        proc = subprocess.run(
            [
                "git", "-C", str(repo_root),
                "ls-files", "-z", "--recurse-submodules",
            ],
            capture_output=True,
            timeout=_GIT_LS_FILES_TIMEOUT_SECONDS,
            check=False,
        )
```

- [ ] **Step 4: Pin the flag in the existing git-mode test**

In `test_walker_git_mode_used_when_dot_git_exists`, after the existing `assert "-z" in cmd`, add:

```python
    assert "--recurse-submodules" in cmd
```

- [ ] **Step 5: Run the walker tests to verify they pass**

Run: `pytest tests/unit/test_index_walker.py -v`
Expected: PASS (all, including the fallback tests — argv change doesn't affect the failure branches).

- [ ] **Step 6: Commit**

```bash
git add flosswing/index/walker.py tests/unit/test_index_walker.py
git commit -m "Index initialized submodule files via git ls-files --recurse-submodules (issue #38)

Per docs/superpowers/specs/2026-07-16-submodule-walker-design.md.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 2: `find_uninitialized_submodules` helper

**Files:**
- Modify: `flosswing/index/walker.py` (add helper + export in `__all__`)
- Test: `tests/unit/test_index_walker.py`

**Interfaces:**
- Consumes: nothing new.
- Produces: `def find_uninitialized_submodules(repo_root: Path) -> list[str]` — repo-relative paths of submodules declared in the index (gitlink, mode `160000`) whose working tree has no `.git` entry. Returns `[]` in non-git mode, on any git failure, or when there are no submodules. Ordering follows `git ls-files` (already sorted).

- [ ] **Step 1: Write the failing tests**

Add to `tests/unit/test_index_walker.py`:

```python
def test_find_uninitialized_submodules_reports_unchecked_out(
    tmp_path: Path,
) -> None:
    repo = _make_git_repo(tmp_path, {"src/keep.py": "pass\n"})
    # ext/bar is a checked-out submodule (has a .git marker file);
    # vendor/foo is declared but never initialized (no working tree).
    (repo / "ext" / "bar").mkdir(parents=True)
    (repo / "ext" / "bar" / ".git").write_text("gitdir: ../.git/modules/bar\n")
    stage_output = (
        b"100644 1111111111111111111111111111111111111111 0\tsrc/keep.py\x00"
        b"160000 2222222222222222222222222222222222222222 0\tvendor/foo\x00"
        b"160000 3333333333333333333333333333333333333333 0\text/bar\x00"
    )
    fake_proc = MagicMock(returncode=0, stdout=stage_output, stderr=b"")
    with patch.object(subprocess, "run", return_value=fake_proc):
        result = walker.find_uninitialized_submodules(repo)
    assert result == ["vendor/foo"]


def test_find_uninitialized_submodules_empty_without_submodules(
    tmp_path: Path,
) -> None:
    repo = _make_git_repo(tmp_path, {"src/keep.py": "pass\n"})
    stage_output = (
        b"100644 1111111111111111111111111111111111111111 0\tsrc/keep.py\x00"
    )
    fake_proc = MagicMock(returncode=0, stdout=stage_output, stderr=b"")
    with patch.object(subprocess, "run", return_value=fake_proc):
        assert walker.find_uninitialized_submodules(repo) == []


def test_find_uninitialized_submodules_empty_in_non_git_mode(
    tmp_path: Path,
) -> None:
    repo = _make_repo(tmp_path, {"src/keep.py": "pass\n"})  # no .git
    with patch.object(subprocess, "run") as m:
        assert walker.find_uninitialized_submodules(repo) == []
    assert not m.called  # short-circuits before shelling out


def test_find_uninitialized_submodules_empty_on_git_failure(
    tmp_path: Path,
) -> None:
    repo = _make_git_repo(tmp_path, {"src/keep.py": "pass\n"})
    fake_proc = MagicMock(returncode=128, stdout=b"", stderr=b"fatal")
    with patch.object(subprocess, "run", return_value=fake_proc):
        assert walker.find_uninitialized_submodules(repo) == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/unit/test_index_walker.py -k find_uninitialized_submodules -v`
Expected: FAIL — `AttributeError: module 'flosswing.index.walker' has no attribute 'find_uninitialized_submodules'`.

- [ ] **Step 3: Implement the helper**

Add to `flosswing/index/walker.py` (after `_walk_manual`, before `__all__`):

```python
def find_uninitialized_submodules(repo_root: Path) -> list[str]:
    """Repo-relative paths of submodules declared in the index but not
    checked out.

    `git ls-files --recurse-submodules` silently omits submodules that have
    no working tree, which would under-cover the scan without warning. This
    surfaces them so the caller can warn the operator.

    Enumerates gitlink entries (mode 160000) via `git ls-files --stage` and
    returns those whose working tree lacks a `.git` entry. Returns [] in
    non-git mode, on any git failure, or when there are no submodules.
    """
    if not (repo_root / ".git").exists():
        return []
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo_root), "ls-files", "-z", "--stage"],
            capture_output=True,
            timeout=_GIT_LS_FILES_TIMEOUT_SECONDS,
            check=False,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as e:
        logger.warning("git ls-files --stage unavailable (%s)", e)
        return []
    if proc.returncode != 0:
        logger.warning(
            "git ls-files --stage returned %d", proc.returncode
        )
        return []

    skipped: list[str] = []
    for entry in proc.stdout.split(b"\x00"):
        if not entry:
            continue
        # Record layout: "<mode> <object> <stage>\t<path>".
        meta, _tab, path_bytes = entry.partition(b"\t")
        if not path_bytes:
            continue
        if meta.split(b" ", 1)[0] != b"160000":  # not a gitlink
            continue
        try:
            rel = path_bytes.decode("utf-8")
        except UnicodeDecodeError:
            logger.warning(
                "skipping non-utf-8 submodule path from git ls-files"
            )
            continue
        # A checked-out submodule work-tree has a `.git` file (or dir).
        if not (repo_root / rel / ".git").exists():
            skipped.append(rel)
    return skipped
```

- [ ] **Step 4: Export the helper**

Change the last line of `flosswing/index/walker.py`:

```python
__all__ = ["find_uninitialized_submodules", "walk"]
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/unit/test_index_walker.py -k find_uninitialized_submodules -v`
Expected: PASS (4 tests).

- [ ] **Step 6: Commit**

```bash
git add flosswing/index/walker.py tests/unit/test_index_walker.py
git commit -m "Add find_uninitialized_submodules to detect skipped submodules (issue #38)

Per docs/superpowers/specs/2026-07-16-submodule-walker-design.md.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 3: Carry `submodules_skipped` on `IndexBuildResult`

**Files:**
- Modify: `flosswing/index/build.py` — `IndexBuildResult` dataclass (`:63-72`), and `build_index` (call helper + log + return field, around `:154` and `:296`)
- Test: `tests/unit/test_index_build.py`

**Interfaces:**
- Consumes: `walker_mod.find_uninitialized_submodules(repo) -> list[str]` (Task 2). `build.py` already imports `from flosswing.index import walker as walker_mod`.
- Produces: `IndexBuildResult.submodules_skipped: list[str]` (default `[]`), populated with the helper's result.

- [ ] **Step 1: Write the failing test**

Add to `tests/unit/test_index_build.py`:

```python
@pytest.mark.asyncio
async def test_build_index_surfaces_uninitialized_submodules(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from flosswing.index import walker as walker_mod

    run_id, artifact_id = _make_run_and_artifact()
    repo = _make_python_repo(isolated_db)
    scratch = isolated_db / "runs" / run_id / "index"
    scratch.mkdir(parents=True)

    monkeypatch.setattr(
        walker_mod,
        "find_uninitialized_submodules",
        lambda _repo: ["vendor/foo"],
    )

    result = await build_index(
        run_id=run_id, recon_artifact_id=artifact_id, repo=repo,
        languages={"python"}, session_factory=st_session.session_factory(),
        scratch_dir=scratch,
    )
    assert result.submodules_skipped == ["vendor/foo"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_index_build.py::test_build_index_surfaces_uninitialized_submodules -v`
Expected: FAIL — `AttributeError: 'IndexBuildResult' object has no attribute 'submodules_skipped'`.

- [ ] **Step 3: Add the dataclass field**

In `flosswing/index/build.py`, `IndexBuildResult`:

```python
@dataclass
class IndexBuildResult:
    symbols: int = 0
    call_sites: int = 0
    entry_points: int = 0
    files_parsed: int = 0
    files_skipped: int = 0
    duration_ms: int = 0
    languages: list[str] = field(default_factory=list)
    submodules_skipped: list[str] = field(default_factory=list)
```

- [ ] **Step 4: Detect + log in `build_index`**

In `build_index`, immediately after the walk loop ends (after the `_log(... f"extracted symbols=...")` block near `:154-158`), add:

```python
        submodules_skipped = walker_mod.find_uninitialized_submodules(repo)
        for _sub in submodules_skipped:
            _log(log_fh, f"submodule not checked out, skipped: {_sub}")
```

- [ ] **Step 5: Return the field**

In the `return IndexBuildResult(...)` near `:296`, add the argument (keep existing args as-is):

```python
        return IndexBuildResult(
            ...,  # existing fields unchanged
            submodules_skipped=submodules_skipped,
        )
```

- [ ] **Step 6: Run test to verify it passes**

Run: `pytest tests/unit/test_index_build.py::test_build_index_surfaces_uninitialized_submodules -v`
Expected: PASS.

- [ ] **Step 7: Run the full index_build suite (no regressions)**

Run: `pytest tests/unit/test_index_build.py -v`
Expected: PASS — existing tests default `submodules_skipped` to `[]` (real `_make_python_repo` has no `.git`, so the helper returns `[]`).

- [ ] **Step 8: Commit**

```bash
git add flosswing/index/build.py tests/unit/test_index_build.py
git commit -m "Carry submodules_skipped on IndexBuildResult (issue #38)

Per docs/superpowers/specs/2026-07-16-submodule-walker-design.md.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 4: Surface skipped submodules in the run banner

**Files:**
- Modify: `flosswing/orchestrator.py` — `summary_lines` construction (`:538-554`)
- Test: `tests/unit/test_orchestrator.py`

**Interfaces:**
- Consumes: `IndexBuildResult.submodules_skipped` (Task 3).
- Produces: banner behaviour only. When `submodules_skipped` is non-empty, two lines appear under the `index:` block; when empty, no line is added.

- [ ] **Step 1: Write the failing test**

Add to `tests/unit/test_orchestrator.py` (mirror the fakes in `test_orchestrator_runs_index_build_between_recon_and_hunt`):

```python
def test_orchestrator_banner_lists_uninitialized_submodules(
    fresh_db: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from flosswing import orchestrator
    from flosswing.index.build import IndexBuildResult
    from flosswing.stages import gapfill as gapfill_stage
    from flosswing.stages import hunt as hunt_stage
    from flosswing.stages import index_build as index_build_stage
    from flosswing.stages import recon as recon_stage
    from flosswing.stages import validate as validate_stage

    async def fake_recon(**kwargs: object) -> RunReconResult:
        return _recon_with_index()

    async def fake_index_build(**kwargs: object) -> IndexBuildResult:
        return IndexBuildResult(
            symbols=4, call_sites=2, entry_points=1, files_parsed=1,
            files_skipped=0, duration_ms=10, languages=["python"],
            submodules_skipped=["vendor/foo"],
        )

    async def fake_hunt(**kwargs: object) -> HuntStageResult:
        return _hunt(processed=1, succeeded=1, findings=1)

    async def fake_validate(**kwargs: object) -> ValidateStageResult:
        return _validate(processed=1, confirmed=1)

    async def fake_gapfill(**kwargs: object) -> GapfillStageResult:
        return _gapfill()

    monkeypatch.setattr(recon_stage, "run", fake_recon)
    monkeypatch.setattr(index_build_stage, "run", fake_index_build)
    monkeypatch.setattr(hunt_stage, "run", fake_hunt)
    monkeypatch.setattr(validate_stage, "run", fake_validate)
    monkeypatch.setattr(gapfill_stage, "run", fake_gapfill)

    result = asyncio.run(orchestrator.run_scan(_cfg(tmp_path)))
    assert "submodules_skipped: 1" in result.summary
    assert "vendor/foo" in result.summary
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_orchestrator.py::test_orchestrator_banner_lists_uninitialized_submodules -v`
Expected: FAIL — `"submodules_skipped: 1"` not in summary.

- [ ] **Step 3: Build the conditional banner lines**

In `flosswing/orchestrator.py`, immediately **before** the `summary_lines = [` assignment (near `:538`), add:

```python
        _index_extra_lines: list[str] = []
        if index_result and index_result.submodules_skipped:
            _subs = index_result.submodules_skipped
            _index_extra_lines.append(
                f"    submodules_skipped: {len(_subs)} ({', '.join(_subs)})"
            )
            _index_extra_lines.append(
                "                        run `git submodule update --init "
                "--recursive` to include them"
            )
```

- [ ] **Step 4: Splice the lines into the index block**

In the `summary_lines` list, change the `duration_ms` line to be followed by the spliced lines:

```python
            f"    duration_ms:       {index_result.duration_ms if index_result else 0}",
            *_index_extra_lines,
            "  hunt:",
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/unit/test_orchestrator.py::test_orchestrator_banner_lists_uninitialized_submodules -v`
Expected: PASS.

- [ ] **Step 6: Run the full orchestrator suite (empty case stays clean)**

Run: `pytest tests/unit/test_orchestrator.py -v`
Expected: PASS — other tests use `IndexBuildResult` with the default empty `submodules_skipped`, so `_index_extra_lines` is empty and no line is emitted.

- [ ] **Step 7: Commit**

```bash
git add flosswing/orchestrator.py tests/unit/test_orchestrator.py
git commit -m "Surface skipped submodules in run banner (issue #38)

Per docs/superpowers/specs/2026-07-16-submodule-walker-design.md.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 5: Full verification pass

**Files:** none (verification only).

- [ ] **Step 1: Run the full unit suite**

Run: `pytest tests/unit -q`
Expected: PASS, no regressions.

- [ ] **Step 2: Lint**

Run: `ruff check flosswing tests`
Expected: no errors.

- [ ] **Step 3: Type-check**

Run: `mypy --strict flosswing`
Expected: no errors. (`submodules_skipped: list[str]` and `find_uninitialized_submodules -> list[str]` are fully annotated.)

- [ ] **Step 4: Manual smoke (optional, needs a real submodule repo)**

If a real submodule-based repo is handy, run `flosswing scan <superproject>` and confirm: (a) submodule source files appear in the symbol counts, (b) an uninitialized submodule produces the `submodules_skipped:` banner line. Skip if no such repo is available — the unit tests cover the logic.

---

## Self-Review

**Spec coverage:**
- Design §1 (recurse-submodules) → Task 1. ✓
- Design §2 (`find_uninitialized_submodules`) → Task 2. ✓
- Design §3 (`IndexBuildResult` field + log) → Task 3. ✓
- Design §4 (banner line) → Task 4. ✓
- Design "Testing" bullets → covered across Tasks 1–4; symlink-escape guard is already pinned by the existing `test_walker_ignores_paths_outside_repo` (unchanged by the argv-only edit) and git-failure fallback by the existing fallback tests. ✓
- Non-goals (no schema/contract/report change, no auto-init) → respected; Task 5 lint/type gate enforces the code-quality rules. ✓

**Placeholder scan:** No TBD/TODO; every code step shows full code. ✓

**Type consistency:** `find_uninitialized_submodules(repo_root: Path) -> list[str]` defined in Task 2 is consumed by name in Task 3; `submodules_skipped: list[str]` defined in Task 3 is read in Task 4. Names match across tasks. ✓
