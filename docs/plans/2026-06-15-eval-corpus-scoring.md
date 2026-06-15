# Eval corpus-scoring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the `flosswing/eval/` subsystem and wire the `flosswing eval` subcommand so it scores pipeline findings against TOML ground-truth manifests (precision/recall/F1), either by running the full pipeline or by re-scoring an existing run.

**Architecture:** Three eval modules per `ARCHITECTURE.md` — `corpus.py` (TOML manifest registry + pydantic models), `scoring.py` (pure matcher producing precision/recall/F1), `runner.py` (scan-or-rescore orchestration + rendering). The deterministic core (corpus + scoring + `--from-run` scoring) is unit-tested in CI; the pipeline-running path is operator-run / `FLOSSWING_INTEGRATION`-gated. Findings come from the Report stage's loader (promoted to a public `load_report`) filtered to operator-facing confirmed primaries.

**Tech Stack:** Python 3.11, `tomllib` (stdlib), `pydantic`, `click`, SQLAlchemy (state DB), `pytest`. No new dependencies.

**Spec:** `docs/specs/2026-06-15-eval-design.md`

**Conventions every task follows:**
- Every new `.py` file starts with the GPLv3 header block used across the package (copy verbatim from `flosswing/errors.py:1-15`), then `"""docstring"""`, then `from __future__ import annotations`.
- Gates after each implementation task: `ruff check .`, `mypy --strict flosswing`, `pytest tests/unit -q`.
- Commit at the end of each task with a spec-referencing message.

---

### Task 1: Promote `report._load` to a public `load_report`

**Files:**
- Modify: `flosswing/stages/report.py` (add public wrapper near `_load`, ~line 281)
- Test: `tests/unit/test_stages_report_load.py` (add one test)

- [ ] **Step 1: Write the failing test**

Add to `tests/unit/test_stages_report_load.py`:

```python
def test_load_report_public_wrapper(isolated_db: Path) -> None:
    """The public load_report() returns the same projection as _load()."""
    run_id = str(ULID())
    _seed_run(run_id)
    task_id = _seed_task(run_id)
    fid = _seed_finding(run_id=run_id, task_id=task_id)

    public = report_stage.load_report(run_id, st_session.session_factory())

    assert public.run.id == run_id
    assert [f.id for f in public.findings] == [fid]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_stages_report_load.py::test_load_report_public_wrapper -v`
Expected: FAIL with `AttributeError: module 'flosswing.stages.report' has no attribute 'load_report'`

- [ ] **Step 3: Add the public wrapper**

In `flosswing/stages/report.py`, immediately after the `_load` function definition (after its `return` block ends), add:

```python
def load_report(run_id: str, session_factory: SessionFactory) -> ReportV1:
    """Public wrapper over :func:`_load`.

    Stable entry point for callers outside the Report stage (e.g. the eval
    runner) that need the operator-facing ReportV1 projection. Behaviour is
    identical to ``_load``; ``_load`` is retained for internal callers.
    """
    return _load(run_id, session_factory)
```

(`SessionFactory` and `ReportV1` are already imported/defined in `report.py`.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/unit/test_stages_report_load.py -q`
Expected: PASS (all tests, including the new one)

- [ ] **Step 5: Gates + commit**

```bash
ruff check . && mypy --strict flosswing && pytest tests/unit -q
git add flosswing/stages/report.py tests/unit/test_stages_report_load.py
git commit -m "Add public report.load_report wrapper per docs/specs/2026-06-15-eval-design.md runner section"
```

---

### Task 2: `EvalConfigError` + `corpus.py` registry

**Files:**
- Modify: `flosswing/errors.py` (add `EvalConfigError` near the end of the error classes, before the "Credential scrubber" banner ~line 548)
- Create: `flosswing/eval/corpus.py`
- Test: `tests/unit/test_eval_corpus.py`

- [ ] **Step 1: Add the error class**

In `flosswing/errors.py`, just before the `# ----- Credential scrubber` banner (line ~548), add:

```python
class EvalConfigError(FlosswingError):
    """Raised when an eval ground-truth manifest is missing or invalid.

    Operator-facing (CLI), not an agent tool error — no wire code in
    docs/tool-contracts.md. The CLI maps it to exit 2.
    """

    code = "eval_config_invalid"
    retryable = False
```

- [ ] **Step 2: Write the failing tests**

Create `tests/unit/test_eval_corpus.py` (prepend the GPLv3 header from `flosswing/errors.py:1-15`):

```python
from __future__ import annotations

from pathlib import Path

import pytest

from flosswing.errors import EvalConfigError
from flosswing.eval import corpus


def _write(tmp_path: Path, name: str, body: str) -> Path:
    p = tmp_path / f"{name}.toml"
    p.write_text(body, encoding="utf-8")
    return p


_VALID = """
name = "demo"
repo = "demo"
description = "a demo"

[[vuln]]
id = "v1"
file = "src/a.py"
line_start = 10
line_end = 12
attack_class = "command_injection"
"""


def test_load_manifest_valid(tmp_path: Path) -> None:
    entry = corpus.load_manifest(_write(tmp_path, "demo", _VALID))
    assert entry.name == "demo"
    assert entry.repo == "demo"
    assert len(entry.vulns) == 1
    v = entry.vulns[0]
    assert v.id == "v1"
    assert v.attack_class == "command_injection"
    assert v.tolerance == corpus.DEFAULT_TOLERANCE  # default applied


def test_load_manifest_name_must_match_stem(tmp_path: Path) -> None:
    body = _VALID.replace('name = "demo"', 'name = "other"')
    with pytest.raises(EvalConfigError) as e:
        corpus.load_manifest(_write(tmp_path, "demo", body))
    assert "demo.toml" in str(e.value)


def test_load_manifest_line_end_before_start(tmp_path: Path) -> None:
    body = _VALID.replace("line_end = 12", "line_end = 9")
    with pytest.raises(EvalConfigError):
        corpus.load_manifest(_write(tmp_path, "demo", body))


def test_load_manifest_duplicate_vuln_id(tmp_path: Path) -> None:
    body = _VALID + """
[[vuln]]
id = "v1"
file = "src/b.py"
line_start = 1
line_end = 1
attack_class = "path_traversal"
"""
    with pytest.raises(EvalConfigError) as e:
        corpus.load_manifest(_write(tmp_path, "demo", body))
    assert "duplicate" in str(e.value).lower()


def test_load_manifest_missing_required_field(tmp_path: Path) -> None:
    body = _VALID.replace('attack_class = "command_injection"', "")
    with pytest.raises(EvalConfigError):
        corpus.load_manifest(_write(tmp_path, "demo", body))


def test_load_manifest_malformed_toml(tmp_path: Path) -> None:
    with pytest.raises(EvalConfigError):
        corpus.load_manifest(_write(tmp_path, "demo", "this is = = not toml"))


def test_load_corpus_sorted_and_empty(tmp_path: Path) -> None:
    assert corpus.load_corpus(tmp_path) == []
    _write(tmp_path, "bbb", _VALID.replace('name = "demo"', 'name = "bbb"').replace('repo = "demo"', 'repo = "bbb"'))
    _write(tmp_path, "aaa", _VALID.replace('name = "demo"', 'name = "aaa"').replace('repo = "demo"', 'repo = "aaa"'))
    names = [e.name for e in corpus.load_corpus(tmp_path)]
    assert names == ["aaa", "bbb"]


def test_find_entry_missing_raises(tmp_path: Path) -> None:
    with pytest.raises(EvalConfigError):
        corpus.find_entry("nope", manifest_dir=tmp_path)
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `pytest tests/unit/test_eval_corpus.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'flosswing.eval.corpus'`

- [ ] **Step 4: Implement `corpus.py`**

Create `flosswing/eval/corpus.py` (prepend the GPLv3 header block from `flosswing/errors.py:1-15`):

```python
"""Eval ground-truth manifest registry.

Loads and validates TOML manifests (shipped as package data under
flosswing/eval/ground_truth/) into CorpusEntry objects. Pure file IO +
pydantic validation — no DB, no API. See docs/specs/2026-06-15-eval-design.md.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from pydantic import BaseModel, ValidationError

from flosswing.errors import EvalConfigError

DEFAULT_TOLERANCE = 10
DEFAULT_MANIFEST_DIR = Path(__file__).resolve().parent / "ground_truth"


class GroundTruthVuln(BaseModel):
    id: str
    file: str
    line_start: int
    line_end: int
    attack_class: str
    tolerance: int = DEFAULT_TOLERANCE
    cve: str | None = None
    severity: str | None = None
    notes: str | None = None


class CorpusEntry(BaseModel):
    name: str
    repo: str
    description: str = ""
    vulns: list[GroundTruthVuln]


def load_manifest(path: Path) -> CorpusEntry:
    """Parse and validate one manifest file into a CorpusEntry.

    Raises EvalConfigError (naming the path) on any parse or validation
    failure: malformed TOML, missing/invalid fields, name != file stem,
    line_end < line_start, or duplicate vuln ids.
    """
    try:
        with path.open("rb") as fh:
            data = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise EvalConfigError(f"{path}: cannot read manifest: {exc}") from exc

    try:
        entry = CorpusEntry.model_validate(data)
    except ValidationError as exc:
        raise EvalConfigError(f"{path}: invalid manifest: {exc}") from exc

    if entry.name != path.stem:
        raise EvalConfigError(
            f"{path}: manifest name {entry.name!r} != file stem {path.stem!r}"
        )

    seen: set[str] = set()
    for v in entry.vulns:
        if v.line_end < v.line_start:
            raise EvalConfigError(
                f"{path}: vuln {v.id!r} has line_end {v.line_end} "
                f"< line_start {v.line_start}"
            )
        if v.id in seen:
            raise EvalConfigError(f"{path}: duplicate vuln id {v.id!r}")
        seen.add(v.id)

    return entry


def load_corpus(manifest_dir: Path = DEFAULT_MANIFEST_DIR) -> list[CorpusEntry]:
    """Load every ``*.toml`` manifest in ``manifest_dir``, sorted by name.

    A missing or empty directory yields ``[]`` (not an error).
    """
    if not manifest_dir.is_dir():
        return []
    entries = [load_manifest(p) for p in sorted(manifest_dir.glob("*.toml"))]
    return sorted(entries, key=lambda e: e.name)


def find_entry(
    name: str, manifest_dir: Path = DEFAULT_MANIFEST_DIR
) -> CorpusEntry:
    """Return the corpus entry named ``name`` or raise EvalConfigError."""
    path = manifest_dir / f"{name}.toml"
    if not path.is_file():
        raise EvalConfigError(
            f"no corpus entry named {name!r} in {manifest_dir}"
        )
    return load_manifest(path)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/unit/test_eval_corpus.py -q`
Expected: PASS (8 tests)

- [ ] **Step 6: Gates + commit**

```bash
ruff check . && mypy --strict flosswing && pytest tests/unit -q
git add flosswing/errors.py flosswing/eval/corpus.py tests/unit/test_eval_corpus.py
git commit -m "Add eval corpus registry + EvalConfigError per docs/specs/2026-06-15-eval-design.md corpus section"
```

---

### Task 3: `scoring.py` — pure matcher + precision/recall/F1

**Files:**
- Create: `flosswing/eval/scoring.py`
- Test: `tests/unit/test_eval_scoring.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_eval_scoring.py` (prepend the GPLv3 header):

```python
from __future__ import annotations

from flosswing.eval.corpus import GroundTruthVuln
from flosswing.eval import scoring
from flosswing.eval.scoring import ScoredFinding


def _gt(id: str, file: str, ls: int, le: int, ac: str, tol: int = 10) -> GroundTruthVuln:
    return GroundTruthVuln(
        id=id, file=file, line_start=ls, line_end=le, attack_class=ac, tolerance=tol
    )


def _f(file: str, ls: int, le: int, ac: str) -> ScoredFinding:
    return ScoredFinding(file=file, line_start=ls, line_end=le, attack_class=ac)


def test_exact_match() -> None:
    r = scoring.score(
        [_gt("g", "a.py", 10, 10, "command_injection")],
        [_f("a.py", 10, 10, "command_injection")],
    )
    assert (r.true_positives, r.false_positives, r.false_negatives) == (1, 0, 0)
    assert r.precision == 1.0 and r.recall == 1.0 and r.f1 == 1.0


def test_within_tolerance_boundary() -> None:
    gt = [_gt("g", "a.py", 10, 10, "command_injection", tol=5)]
    assert scoring.score(gt, [_f("a.py", 15, 15, "command_injection")]).true_positives == 1
    assert scoring.score(gt, [_f("a.py", 16, 16, "command_injection")]).true_positives == 0


def test_attack_class_mismatch_no_match() -> None:
    r = scoring.score(
        [_gt("g", "a.py", 10, 10, "command_injection")],
        [_f("a.py", 10, 10, "path_traversal")],
    )
    assert (r.true_positives, r.false_positives, r.false_negatives) == (0, 1, 1)


def test_file_mismatch_no_match() -> None:
    r = scoring.score(
        [_gt("g", "a.py", 10, 10, "command_injection")],
        [_f("b.py", 10, 10, "command_injection")],
    )
    assert r.true_positives == 0 and r.false_positives == 1 and r.false_negatives == 1


def test_two_findings_one_gt_extra_is_fp() -> None:
    r = scoring.score(
        [_gt("g", "a.py", 10, 14, "command_injection")],
        [
            _f("a.py", 10, 10, "command_injection"),
            _f("a.py", 14, 14, "command_injection"),
        ],
    )
    assert (r.true_positives, r.false_positives, r.false_negatives) == (1, 1, 0)
    assert r.precision == 0.5 and r.recall == 1.0


def test_recall_zero_when_no_findings() -> None:
    r = scoring.score([_gt("g", "a.py", 10, 10, "command_injection")], [])
    assert r.true_positives == 0 and r.false_negatives == 1
    assert r.precision is None  # no findings -> precision undefined
    assert r.recall == 0.0
    assert r.f1 is None


def test_empty_ground_truth_precision_none() -> None:
    r = scoring.score([], [_f("a.py", 1, 1, "command_injection")])
    assert r.recall is None and r.precision == 0.0 and r.false_positives == 1


def test_per_attack_class_breakdown() -> None:
    r = scoring.score(
        [
            _gt("g1", "a.py", 10, 10, "command_injection"),
            _gt("g2", "b.py", 20, 20, "path_traversal"),
        ],
        [
            _f("a.py", 10, 10, "command_injection"),
            _f("c.py", 99, 99, "path_traversal"),
        ],
    )
    assert r.by_attack_class["command_injection"].true_positives == 1
    assert r.by_attack_class["command_injection"].false_positives == 0
    assert r.by_attack_class["path_traversal"].true_positives == 0
    assert r.by_attack_class["path_traversal"].false_negatives == 1
    assert r.by_attack_class["path_traversal"].false_positives == 1


def test_aggregate_sums_and_recomputes() -> None:
    r1 = scoring.score(
        [_gt("g", "a.py", 10, 10, "command_injection")],
        [_f("a.py", 10, 10, "command_injection")],
    )
    r2 = scoring.score(
        [_gt("g", "b.py", 10, 10, "command_injection")],
        [_f("z.py", 1, 1, "command_injection")],
    )
    agg = scoring.aggregate([r1, r2])
    assert agg.true_positives == 1 and agg.false_positives == 1 and agg.false_negatives == 1
    assert agg.precision == 0.5 and agg.recall == 0.5
    assert agg.matches == []  # indices are per-report, not aggregatable
    assert agg.by_attack_class["command_injection"].true_positives == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/unit/test_eval_scoring.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'flosswing.eval.scoring'`

- [ ] **Step 3: Implement `scoring.py`**

Create `flosswing/eval/scoring.py` (prepend the GPLv3 header):

```python
"""Pure precision/recall/F1 scorer for eval.

Matches pipeline findings against ground-truth vulns: same file, same
attack class, finding location within ±tolerance of the ground-truth
location, at most one finding per ground-truth entry. No DB, no API —
a deterministic function of its inputs. See docs/specs/2026-06-15-eval-design.md.
"""

from __future__ import annotations

from dataclasses import dataclass

from pydantic import BaseModel

from flosswing.eval.corpus import GroundTruthVuln


@dataclass(frozen=True)
class ScoredFinding:
    """Minimal projection of a pipeline finding used for scoring."""

    file: str
    line_start: int
    line_end: int
    attack_class: str


class Match(BaseModel):
    gt_id: str
    finding_index: int
    line_distance: int


class ClassScore(BaseModel):
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float | None
    recall: float | None


class ScoreReport(BaseModel):
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float | None
    recall: float | None
    f1: float | None
    matches: list[Match]
    by_attack_class: dict[str, ClassScore]


def _interval_distance(a0: int, a1: int, b0: int, b1: int) -> int:
    """Gap between intervals [a0,a1] and [b0,b1]; 0 if they overlap."""
    if a1 < b0:
        return b0 - a1
    if b1 < a0:
        return a0 - b1
    return 0


def _ratio(num: int, den: int) -> float | None:
    """num/den, or None when den == 0 (undefined)."""
    return None if den == 0 else num / den


def _f1(precision: float | None, recall: float | None) -> float | None:
    if precision is None or recall is None:
        return None
    if precision + recall == 0:
        return 0.0
    return 2 * precision * recall / (precision + recall)


def score(
    ground_truth: list[GroundTruthVuln], findings: list[ScoredFinding]
) -> ScoreReport:
    """Score ``findings`` against ``ground_truth``.

    Greedy assignment: ground-truth entries are processed in order; each
    consumes the closest still-unmatched candidate finding (ties broken by
    line_start, then finding index). Unmatched findings are false positives;
    unmatched ground-truth entries are false negatives.
    """
    consumed: set[int] = set()
    matches: list[Match] = []
    for gt in ground_truth:
        best_key: tuple[int, int, int] | None = None
        best_idx: int | None = None
        for i, f in enumerate(findings):
            if i in consumed or f.file != gt.file or f.attack_class != gt.attack_class:
                continue
            dist = _interval_distance(
                f.line_start, f.line_end, gt.line_start, gt.line_end
            )
            if dist > gt.tolerance:
                continue
            key = (dist, f.line_start, i)
            if best_key is None or key < best_key:
                best_key, best_idx = key, i
        if best_idx is not None and best_key is not None:
            consumed.add(best_idx)
            matches.append(
                Match(gt_id=gt.id, finding_index=best_idx, line_distance=best_key[0])
            )

    tp = len(matches)
    fp = len(findings) - tp
    fn = len(ground_truth) - tp
    precision = _ratio(tp, len(findings))
    recall = _ratio(tp, len(ground_truth))

    matched_idx = {m.finding_index for m in matches}
    matched_gt = {m.gt_id for m in matches}
    classes = sorted(
        {g.attack_class for g in ground_truth} | {f.attack_class for f in findings}
    )
    by_class: dict[str, ClassScore] = {}
    for c in classes:
        gt_c = [g for g in ground_truth if g.attack_class == c]
        find_c = [i for i, f in enumerate(findings) if f.attack_class == c]
        tp_c = sum(1 for g in gt_c if g.id in matched_gt)
        fp_c = sum(1 for i in find_c if i not in matched_idx)
        fn_c = len(gt_c) - tp_c
        by_class[c] = ClassScore(
            true_positives=tp_c,
            false_positives=fp_c,
            false_negatives=fn_c,
            precision=_ratio(tp_c, tp_c + fp_c),
            recall=_ratio(tp_c, tp_c + fn_c),
        )

    return ScoreReport(
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        precision=precision,
        recall=recall,
        f1=_f1(precision, recall),
        matches=matches,
        by_attack_class=by_class,
    )


def aggregate(reports: list[ScoreReport]) -> ScoreReport:
    """Combine per-repo reports into one. ``matches`` is dropped (indices are
    per-report and not comparable across repos)."""
    tp = sum(r.true_positives for r in reports)
    fp = sum(r.false_positives for r in reports)
    fn = sum(r.false_negatives for r in reports)
    class_keys = sorted({c for r in reports for c in r.by_attack_class})
    by_class: dict[str, ClassScore] = {}
    for c in class_keys:
        parts = [r.by_attack_class[c] for r in reports if c in r.by_attack_class]
        tpc = sum(p.true_positives for p in parts)
        fpc = sum(p.false_positives for p in parts)
        fnc = sum(p.false_negatives for p in parts)
        by_class[c] = ClassScore(
            true_positives=tpc,
            false_positives=fpc,
            false_negatives=fnc,
            precision=_ratio(tpc, tpc + fpc),
            recall=_ratio(tpc, tpc + fnc),
        )
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    return ScoreReport(
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        precision=precision,
        recall=recall,
        f1=_f1(precision, recall),
        matches=[],
        by_attack_class=by_class,
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/unit/test_eval_scoring.py -q`
Expected: PASS (9 tests)

- [ ] **Step 5: Gates + commit**

```bash
ruff check . && mypy --strict flosswing && pytest tests/unit -q
git add flosswing/eval/scoring.py tests/unit/test_eval_scoring.py
git commit -m "Add eval scorer (precision/recall/F1) per docs/specs/2026-06-15-eval-design.md scoring section"
```

---

### Task 4: Ground-truth manifests for the existing fixtures

**Files:**
- Create: `flosswing/eval/ground_truth/v02_smoke.toml`
- Create: `flosswing/eval/ground_truth/v08_dedupe_smoke.toml`
- Test: `tests/unit/test_eval_manifests.py`

Line numbers come from the corpus sources. In `tests/corpus/v02_smoke/src/example/cli.py`, the command-injection sink is at line 16 (a shell command built from user input inside `greet`). In `tests/corpus/v08_dedupe_smoke/app.py`, lines 10 and 14 are two shell-command sinks inside one function `run_ops` — a single root-cause vulnerability the Dedupe stage should collapse to one finding.

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_eval_manifests.py` (prepend the GPLv3 header):

```python
from __future__ import annotations

from flosswing.eval import corpus


def test_packaged_manifests_load_and_validate() -> None:
    """Every shipped ground-truth manifest parses and validates."""
    entries = corpus.load_corpus()  # DEFAULT_MANIFEST_DIR
    by_name = {e.name: e for e in entries}
    assert {"v02_smoke", "v08_dedupe_smoke"} <= set(by_name)

    v02 = by_name["v02_smoke"]
    assert v02.repo == "v02_smoke"
    assert len(v02.vulns) == 1
    assert v02.vulns[0].attack_class == "command_injection"
    assert v02.vulns[0].file == "src/example/cli.py"

    # One real root-cause vuln despite two sinks (dedupe collapses them).
    v08 = by_name["v08_dedupe_smoke"]
    assert len(v08.vulns) == 1
    assert v08.vulns[0].attack_class == "command_injection"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_eval_manifests.py -q`
Expected: FAIL (assertion: the two names are not present — manifests don't exist yet)

- [ ] **Step 3: Create the manifests**

Create `flosswing/eval/ground_truth/v02_smoke.toml`:

```toml
name = "v02_smoke"
repo = "v02_smoke"
description = "Tiny Python CLI with one shell-command injection sink."

[[vuln]]
id = "cmdi-greet"
file = "src/example/cli.py"
line_start = 16
line_end = 16
attack_class = "command_injection"
notes = "greet() builds a shell command from user input — command injection."
```

Create `flosswing/eval/ground_truth/v08_dedupe_smoke.toml`:

```toml
name = "v08_dedupe_smoke"
repo = "v08_dedupe_smoke"
description = "One shell-injection root cause with two sinks in one function."

[[vuln]]
id = "cmdi-run-ops"
file = "app.py"
line_start = 10
line_end = 14
attack_class = "command_injection"
tolerance = 5
notes = "run_ops() has two shell-command sinks (lines 10, 14); dedupe should yield a single primary finding."
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/unit/test_eval_manifests.py -q`
Expected: PASS

Note on packaging: hatchling includes non-Python package files in the wheel by default (the same mechanism that ships `flosswing/prompts/system/*.md` and `flosswing/sandbox/images/*`), so no `pyproject.toml` change is required for the `.toml` manifests. This test guards the editable-install path; wheel inclusion follows the existing prompt/image precedent.

- [ ] **Step 5: Gates + commit**

```bash
ruff check . && mypy --strict flosswing && pytest tests/unit -q
git add flosswing/eval/ground_truth/ tests/unit/test_eval_manifests.py
git commit -m "Add eval ground-truth manifests for smoke fixtures per docs/specs/2026-06-15-eval-design.md"
```

---

### Task 5: `runner.py` — scoring an existing run + rendering

This task implements the **deterministic** runner surface (`score_run`, `render_scorecard`, `run_evaluation` for the `--from-run` path, and the `EvalResult`/`RepoResult` models). The pipeline-running helpers (`run_and_score` and the scan branch of `run_evaluation`) are also implemented here but are exercised only by the gated integration test in Task 7.

**Files:**
- Create: `flosswing/eval/runner.py`
- Test: `tests/unit/test_eval_runner.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_eval_runner.py` (prepend the GPLv3 header). It seeds a state DB directly (mirroring `tests/unit/test_stages_report_load.py`) and scores via the report loader:

```python
from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from ulid import ULID

from flosswing.eval.corpus import CorpusEntry, GroundTruthVuln
from flosswing.eval import runner
from flosswing.state import session as st_session
from flosswing.state.models import Finding, HuntTask, Run


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


@pytest.fixture()
def isolated_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    monkeypatch.setenv("FLOSSWING_DB_URL", f"sqlite:///{tmp_path}/state.db")
    monkeypatch.setattr(st_session, "_cached_engine", None, raising=False)
    monkeypatch.setattr(st_session, "_cached_session_factory", None, raising=False)
    yield tmp_path


def _seed_run(run_id: str) -> None:
    with st_session.session_scope() as s:
        s.add(Run(
            id=run_id, target_repo_path="/tmp/x", target_repo_sha=None,
            depth="standard", budget_total=100, budget_used=1,
            started_at=_now(), finished_at=_now(), status="completed",
            config_json='{"model": "claude-opus-4-7"}', flosswing_version="1.0.1",
        ))


def _seed_task(run_id: str) -> str:
    tid = str(ULID())
    with st_session.session_scope() as s:
        s.add(HuntTask(
            id=tid, run_id=run_id, attack_class="command_injection",
            scope_hint="src/", rationale="", priority="normal", source="recon",
            parent_finding_id=None, status="completed", created_at=_now(),
            started_at=_now(), finished_at=_now(), findings_count=0,
        ))
    return tid


def _seed_finding(run_id: str, tid: str, *, file: str, line: int,
                  status: str = "confirmed", attack_class: str = "command_injection",
                  dedupe_role: str | None = None,
                  primary_finding_id: str | None = None) -> str:
    fid = str(ULID())
    with st_session.session_scope() as s:
        s.add(Finding(
            id=fid, run_id=run_id, hunt_task_id=tid, attack_class=attack_class,
            file=file, function="fn", line_start=line, line_end=line,
            severity="high", confidence="likely", status=status,
            title="t", description="d" * 60, poc_code=None, poc_result_json=None,
            suggested_fix=None, created_at=_now(), reachable=None,
            dedupe_role=dedupe_role, dedupe_cluster_id=None,
            primary_finding_id=primary_finding_id,
        ))
    return fid


_ENTRY = CorpusEntry(
    name="v02_smoke", repo="v02_smoke", description="",
    vulns=[GroundTruthVuln(
        id="cmdi", file="src/example/cli.py", line_start=16, line_end=16,
        attack_class="command_injection",
    )],
)


def test_score_run_confirmed_primary_matches(isolated_db: Path) -> None:
    run_id = str(ULID())
    _seed_run(run_id)
    tid = _seed_task(run_id)
    _seed_finding(run_id, tid, file="src/example/cli.py", line=16)

    report = runner.score_run(run_id, _ENTRY)
    assert report.true_positives == 1
    assert report.false_positives == 0
    assert report.recall == 1.0


def test_score_run_excludes_unconfirmed_and_nonprimary(isolated_db: Path) -> None:
    run_id = str(ULID())
    _seed_run(run_id)
    tid = _seed_task(run_id)
    primary = _seed_finding(run_id, tid, file="src/example/cli.py", line=16,
                            dedupe_role="primary")
    # A duplicate (non-primary) on the same spot must be ignored, not counted FP.
    _seed_finding(run_id, tid, file="src/example/cli.py", line=16,
                  dedupe_role="duplicate", primary_finding_id=primary)
    # An uncertain finding elsewhere must be excluded by default.
    _seed_finding(run_id, tid, file="src/other.py", line=99, status="uncertain")

    report = runner.score_run(run_id, _ENTRY)
    assert report.true_positives == 1
    assert report.false_positives == 0


def test_score_run_include_uncertain(isolated_db: Path) -> None:
    run_id = str(ULID())
    _seed_run(run_id)
    tid = _seed_task(run_id)
    _seed_finding(run_id, tid, file="src/example/cli.py", line=16)
    _seed_finding(run_id, tid, file="src/other.py", line=99, status="uncertain")

    report = runner.score_run(run_id, _ENTRY, include_uncertain=True)
    assert report.true_positives == 1
    assert report.false_positives == 1  # the uncertain finding now counts


def test_run_evaluation_from_run(isolated_db: Path, tmp_path: Path) -> None:
    run_id = str(ULID())
    _seed_run(run_id)
    tid = _seed_task(run_id)
    _seed_finding(run_id, tid, file="src/example/cli.py", line=16)

    # Manifest dir containing just v02_smoke.
    mdir = tmp_path / "gt"
    mdir.mkdir()
    (mdir / "v02_smoke.toml").write_text(
        'name = "v02_smoke"\nrepo = "v02_smoke"\n\n'
        '[[vuln]]\nid = "cmdi"\nfile = "src/example/cli.py"\n'
        'line_start = 16\nline_end = 16\nattack_class = "command_injection"\n',
        encoding="utf-8",
    )
    result = runner.run_evaluation(
        manifest_dir=mdir, corpus_root=Path("tests/corpus"),
        from_run=run_id, corpus_name="v02_smoke",
    )
    assert len(result.repos) == 1
    assert result.repos[0].run_id == run_id
    assert result.aggregate.true_positives == 1


def test_render_scorecard_contains_metrics(isolated_db: Path) -> None:
    run_id = str(ULID())
    _seed_run(run_id)
    tid = _seed_task(run_id)
    _seed_finding(run_id, tid, file="src/example/cli.py", line=16)
    report = runner.score_run(run_id, _ENTRY)
    result = runner.EvalResult(
        repos=[runner.RepoResult(name="v02_smoke", run_id=run_id, score=report)],
        aggregate=report,
    )
    text = runner.render_scorecard(result)
    assert "v02_smoke" in text
    assert "precision" in text.lower()
    assert "recall" in text.lower()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/unit/test_eval_runner.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'flosswing.eval.runner'`

- [ ] **Step 3: Implement `runner.py`**

Create `flosswing/eval/runner.py` (prepend the GPLv3 header):

```python
"""Eval runner: score an existing run or run the pipeline then score.

`score_run` / `run_evaluation(--from-run)` / `render_scorecard` are pure
(no API) and unit-tested. `run_and_score` and the scan branch drive the real
pipeline via orchestrator.run_scan and are operator-run / integration-gated.
See docs/specs/2026-06-15-eval-design.md.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from pydantic import BaseModel

from flosswing import config as fcfg
from flosswing import orchestrator
from flosswing.eval import corpus as eval_corpus
from flosswing.eval import scoring
from flosswing.eval.corpus import CorpusEntry
from flosswing.eval.scoring import ScoredFinding, ScoreReport
from flosswing.stages import report as report_stage
from flosswing.state import session as st_session

_ELIGIBLE_DEDUPE_ROLES: frozenset[str | None] = frozenset({None, "primary"})


class RepoResult(BaseModel):
    name: str
    run_id: str
    score: ScoreReport


class EvalResult(BaseModel):
    repos: list[RepoResult]
    aggregate: ScoreReport


def _empty_score() -> ScoreReport:
    return ScoreReport(
        true_positives=0, false_positives=0, false_negatives=0,
        precision=None, recall=None, f1=None, matches=[], by_attack_class={},
    )


def _scored_findings_for_run(
    run_id: str, *, include_uncertain: bool
) -> list[ScoredFinding]:
    """Operator-facing findings for ``run_id`` projected for scoring.

    Filters to confirmed (plus uncertain when requested) findings that are
    dedupe primaries or unclustered — the same eligibility the operator sees.
    """
    report = report_stage.load_report(run_id, st_session.session_factory())
    allowed = {"confirmed"} | ({"uncertain"} if include_uncertain else set())
    out: list[ScoredFinding] = []
    for f in report.findings:
        if f.status not in allowed:
            continue
        if f.dedupe_role not in _ELIGIBLE_DEDUPE_ROLES:
            continue
        out.append(ScoredFinding(
            file=f.file, line_start=f.line_start,
            line_end=f.line_end, attack_class=f.attack_class,
        ))
    return out


def score_run(
    run_id: str, entry: CorpusEntry, *, include_uncertain: bool = False
) -> ScoreReport:
    """Score an existing run's findings against a corpus entry. No API."""
    findings = _scored_findings_for_run(run_id, include_uncertain=include_uncertain)
    return scoring.score(entry.vulns, findings)


def run_and_score(
    entry: CorpusEntry, *, corpus_root: Path, include_uncertain: bool = False
) -> tuple[str, ScoreReport]:
    """Run the full pipeline against the entry's repo, then score it.

    API-touching; operator-run / integration-gated.
    """
    repo_root = (corpus_root / entry.repo).resolve()
    cfg = fcfg.resolve(
        repo_root=repo_root, model=None,
        recon_token_budget=None, hunt_token_budget=None,
        validate_token_budget=None, gapfill_token_budget=None,
        dedupe_token_budget=None, trace_token_budget=None,
        trace_max_depth=None, auto_render=False, output_formats=["json"],
    )
    result = asyncio.run(orchestrator.run_scan(cfg))
    return result.run_id, score_run(
        result.run_id, entry, include_uncertain=include_uncertain
    )


def run_evaluation(
    *,
    manifest_dir: Path = eval_corpus.DEFAULT_MANIFEST_DIR,
    corpus_root: Path,
    from_run: str | None = None,
    corpus_name: str | None = None,
    include_uncertain: bool = False,
) -> EvalResult:
    """Score one existing run (``from_run``) or scan+score the corpus."""
    if from_run is not None:
        if corpus_name is None:
            raise ValueError("corpus_name is required with from_run")
        entry = eval_corpus.find_entry(corpus_name, manifest_dir)
        rep = score_run(from_run, entry, include_uncertain=include_uncertain)
        return EvalResult(
            repos=[RepoResult(name=entry.name, run_id=from_run, score=rep)],
            aggregate=rep,
        )

    entries = (
        [eval_corpus.find_entry(corpus_name, manifest_dir)]
        if corpus_name is not None
        else eval_corpus.load_corpus(manifest_dir)
    )
    repos: list[RepoResult] = []
    for entry in entries:
        run_id, rep = run_and_score(
            entry, corpus_root=corpus_root, include_uncertain=include_uncertain
        )
        repos.append(RepoResult(name=entry.name, run_id=run_id, score=rep))
    agg = scoring.aggregate([r.score for r in repos]) if repos else _empty_score()
    return EvalResult(repos=repos, aggregate=agg)


def _fmt(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.3f}"


def render_scorecard(result: EvalResult) -> str:
    """Render a human-readable scorecard (per-repo rows + aggregate)."""
    lines = ["repo                 TP  FP  FN  precision  recall  f1"]
    for r in result.repos:
        s = r.score
        lines.append(
            f"{r.name:<20} {s.true_positives:>3} {s.false_positives:>3} "
            f"{s.false_negatives:>3}  {_fmt(s.precision):>9}  "
            f"{_fmt(s.recall):>6}  {_fmt(s.f1)}"
        )
    a = result.aggregate
    lines.append(
        f"{'AGGREGATE':<20} {a.true_positives:>3} {a.false_positives:>3} "
        f"{a.false_negatives:>3}  {_fmt(a.precision):>9}  "
        f"{_fmt(a.recall):>6}  {_fmt(a.f1)}"
    )
    return "\n".join(lines)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/unit/test_eval_runner.py -q`
Expected: PASS (5 tests)

- [ ] **Step 5: Gates + commit**

```bash
ruff check . && mypy --strict flosswing && pytest tests/unit -q
git add flosswing/eval/runner.py tests/unit/test_eval_runner.py
git commit -m "Add eval runner (score_run/run_evaluation/render) per docs/specs/2026-06-15-eval-design.md runner section"
```

---

### Task 6: Wire the `flosswing eval` CLI command

**Files:**
- Modify: `flosswing/cli.py:247-250` (replace the stub `eval_` command)
- Test: `tests/unit/test_cli_eval.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_cli_eval.py` (prepend the GPLv3 header). Reuses the same seeding approach; drives the CLI with `click.testing.CliRunner`:

```python
from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from click.testing import CliRunner
from ulid import ULID

from flosswing.cli import main
from flosswing.state import session as st_session
from flosswing.state.models import Finding, HuntTask, Run


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


@pytest.fixture()
def isolated_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    monkeypatch.setenv("FLOSSWING_DB_URL", f"sqlite:///{tmp_path}/state.db")
    monkeypatch.setattr(st_session, "_cached_engine", None, raising=False)
    monkeypatch.setattr(st_session, "_cached_session_factory", None, raising=False)
    yield tmp_path


def _seed(run_id: str, *, file: str = "src/example/cli.py", line: int = 16) -> None:
    with st_session.session_scope() as s:
        s.add(Run(
            id=run_id, target_repo_path="/tmp/x", target_repo_sha=None,
            depth="standard", budget_total=100, budget_used=1,
            started_at=_now(), finished_at=_now(), status="completed",
            config_json='{"model": "m"}', flosswing_version="1.0.1",
        ))
    tid = str(ULID())
    with st_session.session_scope() as s:
        s.add(HuntTask(
            id=tid, run_id=run_id, attack_class="command_injection",
            scope_hint="src/", rationale="", priority="normal", source="recon",
            parent_finding_id=None, status="completed", created_at=_now(),
            started_at=_now(), finished_at=_now(), findings_count=0,
        ))
    with st_session.session_scope() as s:
        s.add(Finding(
            id=str(ULID()), run_id=run_id, hunt_task_id=tid,
            attack_class="command_injection", file=file, function="greet",
            line_start=line, line_end=line, severity="high", confidence="likely",
            status="confirmed", title="t", description="d" * 60, poc_code=None,
            poc_result_json=None, suggested_fix=None, created_at=_now(),
            reachable=None, dedupe_role=None, dedupe_cluster_id=None,
            primary_finding_id=None,
        ))


def _mdir(tmp_path: Path) -> Path:
    d = tmp_path / "gt"
    d.mkdir()
    (d / "v02_smoke.toml").write_text(
        'name = "v02_smoke"\nrepo = "v02_smoke"\n\n'
        '[[vuln]]\nid = "cmdi"\nfile = "src/example/cli.py"\n'
        'line_start = 16\nline_end = 16\nattack_class = "command_injection"\n',
        encoding="utf-8",
    )
    return d


def test_eval_from_run_prints_scorecard(isolated_db: Path, tmp_path: Path) -> None:
    run_id = str(ULID())
    _seed(run_id)
    res = CliRunner().invoke(main, [
        "eval", "--from-run", run_id, "--corpus", "v02_smoke",
        "--manifest-dir", str(_mdir(tmp_path)),
    ])
    assert res.exit_code == 0, res.output
    assert "v02_smoke" in res.output
    assert "AGGREGATE" in res.output


def test_eval_from_run_requires_corpus(isolated_db: Path, tmp_path: Path) -> None:
    run_id = str(ULID())
    _seed(run_id)
    res = CliRunner().invoke(main, [
        "eval", "--from-run", run_id, "--manifest-dir", str(_mdir(tmp_path)),
    ])
    assert res.exit_code == 2
    assert "corpus" in res.output.lower()


def test_eval_min_recall_gate_fails(isolated_db: Path, tmp_path: Path) -> None:
    # Seed a finding in the WRONG place so recall is 0 -> gate fails.
    run_id = str(ULID())
    _seed(run_id, file="src/wrong.py", line=999)
    res = CliRunner().invoke(main, [
        "eval", "--from-run", run_id, "--corpus", "v02_smoke",
        "--manifest-dir", str(_mdir(tmp_path)), "--min-recall", "0.5",
    ])
    assert res.exit_code == 1
    assert "v02_smoke" in res.output  # scorecard still printed


def test_eval_unknown_corpus_exits_2(isolated_db: Path, tmp_path: Path) -> None:
    run_id = str(ULID())
    _seed(run_id)
    res = CliRunner().invoke(main, [
        "eval", "--from-run", run_id, "--corpus", "nope",
        "--manifest-dir", str(_mdir(tmp_path)),
    ])
    assert res.exit_code == 2


def test_eval_json_output(isolated_db: Path, tmp_path: Path) -> None:
    run_id = str(ULID())
    _seed(run_id)
    out = tmp_path / "card.json"
    res = CliRunner().invoke(main, [
        "eval", "--from-run", run_id, "--corpus", "v02_smoke",
        "--manifest-dir", str(_mdir(tmp_path)), "--json", str(out),
    ])
    assert res.exit_code == 0
    assert out.exists()
    assert '"true_positives"' in out.read_text(encoding="utf-8")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/unit/test_cli_eval.py -q`
Expected: FAIL (the stub prints "not implemented"; assertions on scorecard/exit codes fail)

- [ ] **Step 3: Replace the `eval_` stub**

In `flosswing/cli.py`, replace the stub (lines 247-250) with:

```python
@main.command(name="eval")
@click.option("--from-run", "from_run", default=None,
              help="Score an existing run instead of scanning (no API). Requires --corpus.")
@click.option("--corpus", "corpus_name", default=None,
              help="Corpus entry name (manifest stem).")
@click.option("--manifest-dir", "manifest_dir", default=None,
              type=click.Path(file_okay=False, dir_okay=True),
              help="Ground-truth dir (default: packaged flosswing/eval/ground_truth).")
@click.option("--corpus-root", "corpus_root", default="tests/corpus",
              type=click.Path(file_okay=False, dir_okay=True),
              help="Root for resolving a manifest's repo dir on the scan path.")
@click.option("--include-uncertain", "include_uncertain", is_flag=True, default=False,
              help="Also score findings with status 'uncertain'.")
@click.option("--json", "json_out", default=None,
              type=click.Path(dir_okay=False),
              help="Write the scorecard JSON to this path.")
@click.option("--min-recall", "min_recall", type=float, default=None,
              help="Exit non-zero if aggregate recall < value.")
@click.option("--min-precision", "min_precision", type=float, default=None,
              help="Exit non-zero if aggregate precision < value.")
def eval_(
    from_run: str | None,
    corpus_name: str | None,
    manifest_dir: str | None,
    corpus_root: str,
    include_uncertain: bool,
    json_out: str | None,
    min_recall: float | None,
    min_precision: float | None,
) -> None:
    """Run the eval corpus and score against known-CVE ground truth."""
    import json as _json

    from flosswing import errors as _errors
    from flosswing.eval import corpus as _corpus
    from flosswing.eval import runner as _runner

    if from_run is not None and corpus_name is None:
        click.echo("--from-run requires --corpus", err=True)
        sys.exit(2)

    mdir = Path(manifest_dir) if manifest_dir else _corpus.DEFAULT_MANIFEST_DIR
    try:
        result = _runner.run_evaluation(
            manifest_dir=mdir,
            corpus_root=Path(corpus_root),
            from_run=from_run,
            corpus_name=corpus_name,
            include_uncertain=include_uncertain,
        )
    except (_errors.EvalConfigError, _errors.RunNotFoundError) as e:
        click.echo(_errors.scrub(e.message), err=True)
        sys.exit(2)

    click.echo(_runner.render_scorecard(result))
    if json_out is not None:
        Path(json_out).write_text(
            _json.dumps(result.model_dump(), indent=2, sort_keys=True),
            encoding="utf-8",
        )

    agg = result.aggregate
    if min_recall is not None and (agg.recall is None or agg.recall < min_recall):
        sys.exit(1)
    if min_precision is not None and (
        agg.precision is None or agg.precision < min_precision
    ):
        sys.exit(1)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/unit/test_cli_eval.py -q`
Expected: PASS (5 tests)

- [ ] **Step 5: Gates + commit**

```bash
ruff check . && mypy --strict flosswing && pytest tests/unit -q
git add flosswing/cli.py tests/unit/test_cli_eval.py
git commit -m "Wire flosswing eval CLI per docs/specs/2026-06-15-eval-design.md CLI section"
```

---

### Task 7: Gated integration test + README + final verification

**Files:**
- Create: `tests/integration/test_eval_smoke.py`
- Modify: `README.md` (add a `flosswing eval` usage subsection under Usage)

- [ ] **Step 1: Add the gated integration test**

Create `tests/integration/test_eval_smoke.py` (prepend the GPLv3 header). Mirrors the existing gating style in `tests/integration/` (skip unless `FLOSSWING_INTEGRATION=1`):

```python
from __future__ import annotations

import os
from pathlib import Path

import pytest

from flosswing.eval import corpus, runner

pytestmark = pytest.mark.skipif(
    os.environ.get("FLOSSWING_INTEGRATION") != "1",
    reason="integration test; set FLOSSWING_INTEGRATION=1 to run (hits the real API)",
)


def test_eval_runs_full_pipeline_against_v02_smoke() -> None:
    """Default eval path: scan v02_smoke end-to-end, then score.

    Asserts the command produces a structured result, NOT a specific score
    (LLM output is non-deterministic).
    """
    entry = corpus.find_entry("v02_smoke")
    result = runner.run_evaluation(
        corpus_root=Path("tests/corpus"), corpus_name="v02_smoke",
    )
    assert len(result.repos) == 1
    assert result.repos[0].name == "v02_smoke"
    assert (
        result.aggregate.true_positives + result.aggregate.false_negatives
        == len(entry.vulns)
    )
```

- [ ] **Step 2: Verify it skips in normal CI**

Run: `pytest tests/integration/test_eval_smoke.py -q`
Expected: `1 skipped` (FLOSSWING_INTEGRATION not set)

- [ ] **Step 3: Add README usage**

In `README.md`, under the Usage section (after the `### Scan a repo` block, before the License section), add a `### Score against the eval corpus` subsection documenting the three invocations and the manifest location. Use real fenced code blocks:

- `flosswing eval --from-run <run_id> --corpus v02_smoke` — re-score an existing run, no API call, deterministic.
- `flosswing eval` — run the full pipeline against every registered corpus repo, then score (hits the API; operator-run, like the integration tests).
- `flosswing eval --from-run <run_id> --corpus v02_smoke --min-recall 0.8` — gate a prompt change on a recall floor.

State that ground-truth manifests live in `flosswing/eval/ground_truth/<name>.toml` and that a finding counts as a true positive when it matches on file, attack class, and location (within a per-entry line tolerance).

- [ ] **Step 4: Full verification**

Run:
```bash
ruff check .
mypy --strict flosswing
pytest tests/unit -q
flosswing --help
```
Expected: ruff clean; mypy clean; all unit tests pass (including the ~28 new eval tests); `eval` listed in CLI help.

- [ ] **Step 5: Commit**

```bash
git add tests/integration/test_eval_smoke.py README.md
git commit -m "Add gated eval integration smoke + README usage per docs/specs/2026-06-15-eval-design.md"
```

---

## Self-Review

**Spec coverage:**
- Ground-truth TOML format + pydantic validation → Task 2 (`corpus.py`). ✓
- `corpus.py` registry (load_manifest/load_corpus/find_entry) → Task 2. ✓
- `scoring.py` pure matcher, precision/recall/F1, per-class, aggregate → Task 3. ✓
- Match rule (file + attack class + ±tolerance, one finding per GT, extras = FP) → Task 3 tests + `score`. ✓
- `runner.py` score_run / run_and_score / run_evaluation / render → Task 5. ✓
- Operator-facing filter (confirmed + primary/unclustered; `--include-uncertain`) → Task 5 `_scored_findings_for_run`. ✓
- `load_report` public wrapper → Task 1. ✓
- CLI surface (all options, exit codes 0/1/2, --json) → Task 6. ✓
- Manifests for both fixtures → Task 4. ✓
- Unit tests in CI; integration gated → Tasks 2/3/4/5/6 (unit), Task 7 (gated). ✓
- Manifests as package data outside scanned repos → Task 4 (location + packaging note). ✓
- `--corpus-root` for repo resolution on scan path only → Task 5/6. ✓
- Determinism (total tie-break; sorted JSON) → Task 3 `score`, Task 6 `sort_keys=True`. ✓
- Error handling via `errors.scrub`, exit 2 for config/run errors → Task 6. ✓

**Placeholder scan:** No TBD/TODO/"handle edge cases". Every code step shows full code. The only ellipses are inside docstrings — intentional. ✓

**Type consistency:** `ScoredFinding`, `ScoreReport`, `ClassScore`, `Match`, `GroundTruthVuln`, `CorpusEntry`, `EvalResult`, `RepoResult` names are used identically across Tasks 3/5/6. `score_run(run_id, entry, *, include_uncertain)`, `run_evaluation(*, manifest_dir, corpus_root, from_run, corpus_name, include_uncertain)`, `render_scorecard(result)`, `load_report(run_id, session_factory)` signatures match between definition and call sites. ✓
