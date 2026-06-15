# TUI Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `flosswing tui`, an interactive terminal dashboard that lists runs, shows live scan progress, drills into findings, reviews agent sessions, and launches new scans — all read-only against `state.db` plus a subprocess launcher for the existing CLI.

**Architecture:** New `flosswing/tui/` package. `data.py` is the only DB-touching module and returns plain frozen dataclasses (no ORM leakage); `launcher.py` is the only subprocess-touching module; `screens/*` are pure Textual views; `app.py` owns the screen stack and global keys. Scan progress is read from `state.db` on a per-screen poll timer; scans run as detached child processes (`python -m flosswing.cli scan …`).

**Tech Stack:** Python 3.11+, Textual (new dependency, pulls `rich`), SQLAlchemy 2.0 (existing), Click (existing CLI), pytest + Textual `run_test()` pilot for tests.

**Spec:** `docs/specs/2026-06-15-tui-dashboard-design.md`

**Environment note for the executor:** This worktree uses the parent repo's virtualenv. Run Python as
`/home/tdang/projects/personal/FlossWing/.venv/bin/python` (call it `$PY` below). Run tests with `$PY -m pytest …`. `textual` is installed in Task 1.

---

## File structure

```
flosswing/tui/
  __init__.py            # empty package marker
  data.py                # read-only query layer -> frozen dataclasses
  launcher.py            # spawn/track scan & report child processes
  app.py                 # Textual App + RunsScreen mount + global bindings
  screens/
    __init__.py
    runs.py              # RunsScreen (initial)
    run_detail.py        # RunDetailScreen (live)
    findings.py          # FindingsScreen
    finding_detail.py    # FindingDetailScreen
    sessions.py          # SessionsScreen
    new_scan.py          # NewScanScreen (ModalScreen) + QuitGuard (ModalScreen)
flosswing/cli.py         # MODIFY: add `tui` command (lazy import)
pyproject.toml           # MODIFY: add `textual` dependency + mypy override
tests/unit/
  test_tui_data.py       # data.py tests (seeded in-memory DB)
  test_tui_launcher.py   # launcher.py tests (mocked subprocess)
  test_tui_screens.py    # screen smoke tests via run_test()
```

**Decisions baked in (from spec + codebase audit):**
- Progress is **inferred** from which rows exist; `data.py._derive_stages` is the one non-trivial bit and is unit-tested directly.
- `runs.budget_used` is written only at run completion, so live token/cost totals are summed from `agent_sessions` instead.
- `runs.budget_total` is a deprecated literal — **never displayed**.
- The public `report.load_report` wrapper is not on this branch; use the stable private projection `flosswing.stages.report._load(run_id, session_factory) -> ReportV1`.
- Report deliberately does **not** scrub finding text (upstream scrubs at DB-write time). The TUI follows that precedent: display DB text as-is; scrub only error/stderr text via `errors.scrub` (mirrors `cli.py report`).
- Refresh is **per-screen** (`set_interval` in each live screen's `on_mount`), not a single global timer — cleaner unit boundaries; live screens poll only their own data.

---

## Task 1: Dependency, package skeleton, and `flosswing tui` command

**Files:**
- Modify: `pyproject.toml` (dependencies + mypy override)
- Create: `flosswing/tui/__init__.py`
- Create: `flosswing/tui/screens/__init__.py`
- Create: `flosswing/tui/app.py` (minimal placeholder App; fleshed out in Task 6)
- Modify: `flosswing/cli.py` (add `tui` command)
- Test: `tests/unit/test_tui_cli.py`

- [ ] **Step 1: Add the dependency and install it**

In `pyproject.toml`, add `"textual"` to `[project.dependencies]` (after `"python-ulid",`):

```toml
    "python-ulid",
    "textual",
```

And add a mypy override block (after the existing override that lists `claude_agent_sdk` etc. — a new array entry is fine, or extend the existing `module` list). Add this new block at the end of the mypy section:

```toml
[[tool.mypy.overrides]]
# Textual ships py.typed but rich internals occasionally lack precise stubs;
# only silence missing-imports, keep our own code strictly typed.
module = ["rich.*"]
ignore_missing_imports = true
```

Install into the worktree venv:

Run: `/home/tdang/projects/personal/FlossWing/.venv/bin/python -m pip install textual`
Expected: textual + rich install successfully.

- [ ] **Step 2: Create the package skeleton**

Create `flosswing/tui/__init__.py` with the standard GPL header (copy the 15-line header block from the top of `flosswing/cli.py`) followed by:

```python
"""FlossWing terminal dashboard (`flosswing tui`)."""
```

Create `flosswing/tui/screens/__init__.py` with the same GPL header followed by:

```python
"""Screen classes for the FlossWing TUI."""
```

Create `flosswing/tui/app.py` with the GPL header followed by a minimal placeholder (replaced in Task 6):

```python
"""Textual application entry point for the FlossWing dashboard."""

from __future__ import annotations


def run() -> None:
    """Launch the dashboard. Fleshed out in a later task."""
    from textual.app import App, ComposeResult
    from textual.widgets import Footer, Static

    class _Placeholder(App[None]):
        BINDINGS = [("q", "quit", "Quit")]

        def compose(self) -> ComposeResult:
            yield Static("FlossWing TUI — under construction")
            yield Footer()

    _Placeholder().run()
```

- [ ] **Step 3: Write the failing test for the CLI command**

Create `tests/unit/test_tui_cli.py` (GPL header omitted here for brevity — include it):

```python
"""flosswing.cli `tui` command wiring."""

from __future__ import annotations

from unittest import mock

from click.testing import CliRunner

from flosswing import cli


def test_tui_command_registered() -> None:
    runner = CliRunner()
    result = runner.invoke(cli.main, ["tui", "--help"])
    assert result.exit_code == 0
    assert "dashboard" in result.output.lower()


def test_tui_command_invokes_app_run() -> None:
    runner = CliRunner()
    with mock.patch("flosswing.tui.app.run") as run_mock:
        result = runner.invoke(cli.main, ["tui"])
    assert result.exit_code == 0
    run_mock.assert_called_once_with()
```

- [ ] **Step 4: Run the test to verify it fails**

Run: `$PY -m pytest tests/unit/test_tui_cli.py -v`
Expected: FAIL — `tui` command does not exist (`No such command 'tui'`).

- [ ] **Step 5: Add the `tui` command to `cli.py`**

In `flosswing/cli.py`, add after the `eval_` command (before `if __name__ == "__main__":`):

```python
@main.command(name="tui")
def tui() -> None:
    """Launch the interactive terminal dashboard for browsing runs and findings."""
    # Lazy import: keep textual + the TUI import graph off the startup path
    # of scan/report/eval (mirrors the lazy state import in `report`).
    from flosswing.tui import app as tui_app

    tui_app.run()
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `$PY -m pytest tests/unit/test_tui_cli.py -v`
Expected: PASS (2 tests).

- [ ] **Step 7: Commit**

```bash
git add pyproject.toml flosswing/tui/__init__.py flosswing/tui/screens/__init__.py flosswing/tui/app.py flosswing/cli.py tests/unit/test_tui_cli.py
git commit -m "Add flosswing tui command + package skeleton per docs/plans/2026-06-15-tui-dashboard.md Task 1

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: `data.py` — dataclasses and `list_runs`

**Files:**
- Create: `flosswing/tui/data.py`
- Test: `tests/unit/test_tui_data.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_tui_data.py` (include GPL header). This file's fixtures are reused by Tasks 3–4, so define them fully now:

```python
"""flosswing.tui.data — read-only query layer."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from flosswing.state import session as st_session
from flosswing.state.models import (
    AgentSession,
    Finding,
    HuntTask,
    ReconArtifact,
    Run,
    Symbol,
    Validation,
)
from flosswing.tui import data


def _iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


@pytest.fixture()
def isolated_db(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[Path]:
    monkeypatch.setenv("FLOSSWING_DB_URL", f"sqlite:///{tmp_path}/state.db")
    monkeypatch.setattr(st_session, "_cached_engine", None, raising=False)
    monkeypatch.setattr(
        st_session, "_cached_session_factory", None, raising=False
    )
    yield tmp_path


def _add_run(run_id: str, *, status: str = "completed", path: str = "/tmp/r") -> None:
    with st_session.session_scope() as s:
        s.add(
            Run(
                id=run_id,
                target_repo_path=path,
                target_repo_sha=None,
                depth="standard",
                budget_total=20,
                budget_used=0,
                started_at=_iso(),
                finished_at=_iso() if status != "running" else None,
                status=status,
                config_json="{}",
                flosswing_version="test",
            )
        )


def _add_finding(finding_id: str, run_id: str, *, status: str = "confirmed") -> None:
    with st_session.session_scope() as s:
        s.add(
            HuntTask(
                id=f"task-{finding_id}",
                run_id=run_id,
                attack_class="command_injection",
                scope_hint="src/x.c",
                source="recon",
                status="completed",
                created_at=_iso(),
            )
        )
        s.add(
            Finding(
                id=finding_id,
                run_id=run_id,
                hunt_task_id=f"task-{finding_id}",
                attack_class="command_injection",
                file="src/x.c",
                function="parse",
                line_start=10,
                line_end=12,
                severity="high",
                confidence="confirmed",
                status=status,
                title="Command injection in parse()",
                description="User input flows to system().",
                poc_code="print('poc')",
                poc_result_json='{"exit_code": 0, "stdout": "pwned"}',
                suggested_fix="Use execve with a fixed argv.",
                created_at=_iso(),
            )
        )


def test_list_runs_orders_newest_first_with_counts(isolated_db: Path) -> None:
    _add_run("run-a", status="completed")
    _add_run("run-b", status="running")
    _add_finding("f1", "run-b")
    _add_finding("f2", "run-b")

    rows = data.list_runs()

    assert [r.id for r in rows] == ["run-b", "run-a"]  # newest started_at first
    by_id = {r.id: r for r in rows}
    assert by_id["run-b"].findings_count == 2
    assert by_id["run-a"].findings_count == 0
    assert by_id["run-b"].status == "running"
    assert by_id["run-b"].short_id  # non-empty display id


def test_list_runs_empty(isolated_db: Path) -> None:
    assert data.list_runs() == []
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `$PY -m pytest tests/unit/test_tui_data.py -v`
Expected: FAIL — `flosswing.tui.data` has no `list_runs` (ImportError / AttributeError).

- [ ] **Step 3: Create `data.py` with dataclasses and `list_runs`**

Create `flosswing/tui/data.py` (include GPL header):

```python
"""Read-only query layer for the FlossWing TUI.

This is the ONLY TUI module that touches SQLAlchemy. Every function opens a
read session, snapshots rows into frozen dataclasses before the scope
closes, and returns those dataclasses. No ORM entity escapes this module.

Display text is shown as-is: finding/title/description text is already
credential-scrubbed by the upstream stage that wrote it (see
flosswing.stages.report module docstring). Only error/stderr text elsewhere
in the TUI is run through flosswing.errors.scrub.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import func, select

from flosswing.state import session as st_session
from flosswing.state.models import (
    AgentSession,
    Finding,
    Run,
)


def _short_id(run_id: str) -> str:
    """Last 8 chars of a ULID — enough to disambiguate in a list."""
    return run_id[-8:] if len(run_id) > 8 else run_id


@dataclass(frozen=True)
class RunRow:
    id: str
    short_id: str
    target_repo_path: str
    status: str
    started_at: str
    finished_at: str | None
    findings_count: int


def list_runs() -> list[RunRow]:
    """All runs, newest started_at first, with finding counts."""
    with st_session.session_scope() as s:
        counts = dict(
            s.execute(
                select(Finding.run_id, func.count()).group_by(Finding.run_id)
            ).all()
        )
        runs = (
            s.execute(select(Run).order_by(Run.started_at.desc()))
            .scalars()
            .all()
        )
        return [
            RunRow(
                id=r.id,
                short_id=_short_id(r.id),
                target_repo_path=r.target_repo_path,
                status=r.status,
                started_at=r.started_at,
                finished_at=r.finished_at,
                findings_count=int(counts.get(r.id, 0)),
            )
            for r in runs
        ]
```

(The `AgentSession` import is unused now but is used in Task 3 — add it in Task 3 to keep ruff green. For this task, import only `Finding`, `Run`. Adjust the import line to `from flosswing.state.models import Finding, Run`.)

- [ ] **Step 4: Run the test to verify it passes**

Run: `$PY -m pytest tests/unit/test_tui_data.py -v`
Expected: PASS (2 tests).

- [ ] **Step 5: Lint check**

Run: `/home/tdang/projects/personal/FlossWing/.venv/bin/ruff check flosswing/tui/data.py`
Expected: no errors (no unused imports).

- [ ] **Step 6: Commit**

```bash
git add flosswing/tui/data.py tests/unit/test_tui_data.py
git commit -m "Add tui.data.list_runs read-only query per docs/plans/2026-06-15-tui-dashboard.md Task 2

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: `data.py` — `run_progress` and `_derive_stages`

**Files:**
- Modify: `flosswing/tui/data.py`
- Test: `tests/unit/test_tui_data.py` (append)

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_tui_data.py`:

```python
def _add_recon(run_id: str) -> None:
    with st_session.session_scope() as s:
        s.add(
            ReconArtifact(
                id=f"recon-{run_id}",
                run_id=run_id,
                languages_json="[]",
                build_commands_json="[]",
                trust_boundaries_json="[]",
                subsystems_json="[]",
                notes="",
                recorded_at=_iso(),
            )
        )


def _add_hunt_task(
    task_id: str, run_id: str, *, status: str, source: str = "recon"
) -> None:
    with st_session.session_scope() as s:
        s.add(
            HuntTask(
                id=task_id,
                run_id=run_id,
                attack_class="path_traversal",
                scope_hint="src/y.c",
                source=source,
                status=status,
                created_at=_iso(),
                findings_count=0,
            )
        )


def _add_session(run_id: str, *, stage: str, in_tok: int, out_tok: int, cost: float) -> None:
    with st_session.session_scope() as s:
        s.add(
            AgentSession(
                id=f"sess-{run_id}-{stage}-{in_tok}",
                run_id=run_id,
                stage=stage,
                task_id=None,
                finding_id=None,
                model="claude-sonnet-4-6",
                system_prompt_hash="x",
                input_tokens=in_tok,
                output_tokens=out_tok,
                cost_usd=cost,
                duration_ms=1000,
                outcome="completed",
                started_at=_iso(),
                finished_at=_iso(),
            )
        )


def test_run_progress_none_for_missing_run(isolated_db: Path) -> None:
    _add_run("exists")
    assert data.run_progress("ghost") is None


def test_run_progress_stage_derivation_and_totals(isolated_db: Path) -> None:
    _add_run("run-x", status="running")
    _add_recon("run-x")
    _add_hunt_task("t1", "run-x", status="completed")
    _add_hunt_task("t2", "run-x", status="running")
    _add_hunt_task("t3", "run-x", status="pending")
    _add_finding("f1", "run-x", status="confirmed")
    _add_session("run-x", stage="recon", in_tok=100, out_tok=50, cost=0.01)
    _add_session("run-x", stage="hunt", in_tok=200, out_tok=80, cost=0.02)

    p = data.run_progress("run-x")
    assert p is not None
    assert p.run_id == "run-x"
    assert p.hunt_total == 4  # 3 added here + 1 from _add_finding's task
    # done = not in (pending, running): t1 + _add_finding's "completed" task
    assert p.hunt_done == 2
    assert p.tokens_used == 100 + 50 + 200 + 80
    assert round(p.cost_usd, 4) == 0.03
    assert p.findings_total == 1
    assert p.findings_by_status["confirmed"] == 1

    stages = {st.name: st.state for st in p.stages}
    assert stages["Recon"] == "done"
    assert stages["Hunt"] == "active"  # some done, some not, run running
    # No validations rows -> Validate pending while run is running
    assert stages["Validate"] == "pending"


def test_run_progress_gapfill_detected_from_source(isolated_db: Path) -> None:
    _add_run("run-g", status="completed")
    _add_hunt_task("g1", "run-g", status="completed", source="gapfill")
    p = data.run_progress("run-g")
    assert p is not None
    stages = {st.name: st.state for st in p.stages}
    assert stages["Gapfill"] == "done"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `$PY -m pytest tests/unit/test_tui_data.py -k run_progress -v`
Expected: FAIL — `run_progress` not defined.

- [ ] **Step 3: Implement `run_progress` and `_derive_stages`**

In `flosswing/tui/data.py`, update the imports to:

```python
from flosswing.state.models import (
    AgentSession,
    DedupeCluster,
    Finding,
    HuntTask,
    ReconArtifact,
    Run,
    Symbol,
    Trace,
    Validation,
)
```

Add these dataclasses and functions after `list_runs`:

```python
_STAGE_ORDER = (
    "Recon",
    "Index",
    "Hunt",
    "Validate",
    "Gapfill",
    "Dedupe",
    "Trace",
    "Report",
)


@dataclass(frozen=True)
class StageState:
    name: str
    state: str  # "done" | "active" | "pending" | "n/a"


@dataclass(frozen=True)
class HuntTaskRow:
    attack_class: str
    scope_hint: str
    status: str
    findings_count: int


@dataclass(frozen=True)
class RunProgress:
    run_id: str
    short_id: str
    target_repo_path: str
    status: str
    started_at: str
    finished_at: str | None
    stages: list[StageState]
    hunt_done: int
    hunt_total: int
    tokens_used: int
    cost_usd: float
    findings_total: int
    findings_by_status: dict[str, int]
    hunt_tasks: list[HuntTaskRow]


def _stage(name: str, done: bool, *, active_if_running: bool, run_running: bool) -> StageState:
    """Generic stage state: done if `done`; else active when the run is still
    running and this stage could plausibly be the active one; else pending."""
    if done:
        return StageState(name, "done")
    if run_running and active_if_running:
        return StageState(name, "active")
    return StageState(name, "pending" if run_running else "n/a")


def _derive_stages(
    *,
    run_running: bool,
    recon_done: bool,
    index_done: bool,
    hunt_total: int,
    hunt_done: int,
    gapfill_done: bool,
    n_validations: int,
    n_clusters: int,
    n_traces: int,
    findings_total: int,
) -> list[StageState]:
    """Infer per-stage state purely from which rows exist.

    The state DB has no 'current stage' column, so each stage's state is
    derived from its own evidence. A stage with no evidence is 'pending'
    while the run is still running and 'n/a' once it has stopped.
    """
    hunt_finished = hunt_total > 0 and hunt_done == hunt_total
    hunt_active = hunt_total > 0 and not hunt_finished
    return [
        _stage("Recon", recon_done, active_if_running=not recon_done, run_running=run_running),
        _stage("Index", index_done, active_if_running=recon_done and not index_done, run_running=run_running),
        StageState("Hunt", "done" if hunt_finished else ("active" if hunt_active else ("pending" if run_running else "n/a"))),
        _stage("Validate", n_validations > 0, active_if_running=findings_total > 0, run_running=run_running),
        _stage("Gapfill", gapfill_done, active_if_running=False, run_running=run_running),
        _stage("Dedupe", n_clusters > 0, active_if_running=findings_total > 0, run_running=run_running),
        _stage("Trace", n_traces > 0, active_if_running=findings_total > 0, run_running=run_running),
        # Report leaves no DB row; we cannot confirm it ran. Show n/a always.
        StageState("Report", "n/a"),
    ]


def run_progress(run_id: str) -> RunProgress | None:
    """Live progress for one run, or None if the run does not exist."""
    with st_session.session_scope() as s:
        run = s.get(Run, run_id)
        if run is None:
            return None
        run_running = run.status == "running"

        recon_done = (
            s.execute(
                select(ReconArtifact.id).where(ReconArtifact.run_id == run_id).limit(1)
            ).first()
            is not None
        )
        index_done = (
            s.execute(
                select(Symbol.id).where(Symbol.run_id == run_id).limit(1)
            ).first()
            is not None
        )

        tasks = (
            s.execute(select(HuntTask).where(HuntTask.run_id == run_id))
            .scalars()
            .all()
        )
        hunt_total = len(tasks)
        hunt_done = sum(1 for t in tasks if t.status not in ("pending", "running"))
        gapfill_done = any(t.source == "gapfill" for t in tasks)
        hunt_tasks = [
            HuntTaskRow(t.attack_class, t.scope_hint, t.status, t.findings_count)
            for t in tasks
        ]

        findings = (
            s.execute(select(Finding).where(Finding.run_id == run_id))
            .scalars()
            .all()
        )
        findings_total = len(findings)
        by_status: dict[str, int] = {}
        for f in findings:
            by_status[f.status] = by_status.get(f.status, 0) + 1

        n_validations = int(
            s.execute(
                select(func.count())
                .select_from(Validation)
                .join(Finding, Validation.finding_id == Finding.id)
                .where(Finding.run_id == run_id)
            ).scalar()
            or 0
        )
        n_traces = int(
            s.execute(
                select(func.count())
                .select_from(Trace)
                .join(Finding, Trace.finding_id == Finding.id)
                .where(Finding.run_id == run_id)
            ).scalar()
            or 0
        )
        n_clusters = int(
            s.execute(
                select(func.count())
                .select_from(DedupeCluster)
                .where(DedupeCluster.run_id == run_id)
            ).scalar()
            or 0
        )

        tokens_used = int(
            s.execute(
                select(
                    func.coalesce(
                        func.sum(AgentSession.input_tokens + AgentSession.output_tokens),
                        0,
                    )
                ).where(AgentSession.run_id == run_id)
            ).scalar()
            or 0
        )
        cost_usd = float(
            s.execute(
                select(func.coalesce(func.sum(AgentSession.cost_usd), 0.0)).where(
                    AgentSession.run_id == run_id
                )
            ).scalar()
            or 0.0
        )

        stages = _derive_stages(
            run_running=run_running,
            recon_done=recon_done,
            index_done=index_done,
            hunt_total=hunt_total,
            hunt_done=hunt_done,
            gapfill_done=gapfill_done,
            n_validations=n_validations,
            n_clusters=n_clusters,
            n_traces=n_traces,
            findings_total=findings_total,
        )

        return RunProgress(
            run_id=run.id,
            short_id=_short_id(run.id),
            target_repo_path=run.target_repo_path,
            status=run.status,
            started_at=run.started_at,
            finished_at=run.finished_at,
            stages=stages,
            hunt_done=hunt_done,
            hunt_total=hunt_total,
            tokens_used=tokens_used,
            cost_usd=cost_usd,
            findings_total=findings_total,
            findings_by_status=by_status,
            hunt_tasks=hunt_tasks,
        )
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `$PY -m pytest tests/unit/test_tui_data.py -v`
Expected: PASS (all tests, including Task 2's).

- [ ] **Step 5: Commit**

```bash
git add flosswing/tui/data.py tests/unit/test_tui_data.py
git commit -m "Add tui.data.run_progress + stage derivation per docs/plans/2026-06-15-tui-dashboard.md Task 3

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: `data.py` — findings list, finding detail, sessions

**Files:**
- Modify: `flosswing/tui/data.py`
- Test: `tests/unit/test_tui_data.py` (append)

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_tui_data.py`:

```python
def test_findings_list_maps_rows(isolated_db: Path) -> None:
    _add_run("run-f", status="completed")
    _add_finding("f1", "run-f", status="confirmed")
    rows = data.findings_list("run-f")
    assert len(rows) == 1
    assert rows[0].id == "f1"
    assert rows[0].title == "Command injection in parse()"
    assert rows[0].severity == "high"
    assert rows[0].status == "confirmed"


def test_findings_list_missing_run_is_empty(isolated_db: Path) -> None:
    assert data.findings_list("nope") == []


def test_finding_detail_includes_poc_result(isolated_db: Path) -> None:
    _add_run("run-d", status="completed")
    _add_finding("f1", "run-d", status="confirmed")
    d = data.finding_detail("run-d", "f1")
    assert d is not None
    assert d.id == "f1"
    assert d.poc_code == "print('poc')"
    assert d.poc_result is not None and "pwned" in d.poc_result
    assert d.suggested_fix is not None
    assert "src/x.c" in d.location


def test_finding_detail_missing_returns_none(isolated_db: Path) -> None:
    _add_run("run-d2", status="completed")
    assert data.finding_detail("run-d2", "ghost") is None


def test_list_sessions(isolated_db: Path) -> None:
    _add_run("run-s", status="completed")
    _add_session("run-s", stage="recon", in_tok=100, out_tok=50, cost=0.01)
    rows = data.list_sessions("run-s")
    assert len(rows) == 1
    assert rows[0].stage == "recon"
    assert rows[0].input_tokens == 100
    assert rows[0].outcome == "completed"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `$PY -m pytest tests/unit/test_tui_data.py -k "findings_list or finding_detail or list_sessions" -v`
Expected: FAIL — functions not defined.

- [ ] **Step 3: Implement the three functions**

In `flosswing/tui/data.py`, add these imports near the top (after existing imports):

```python
import json

from flosswing.stages import report as report_stage
```

Add the dataclasses and functions at the end of the module:

```python
@dataclass(frozen=True)
class FindingListRow:
    id: str
    title: str
    attack_class: str
    file: str
    severity: str
    confidence: str
    status: str
    reachable: str | None


@dataclass(frozen=True)
class FindingDetail:
    id: str
    title: str
    attack_class: str
    location: str
    severity: str
    confidence: str
    status: str
    description: str
    poc_code: str | None
    poc_result: str | None
    suggested_fix: str | None
    verdict: str | None
    verdict_rationale: str | None
    reachable: str | None
    trace_rationale: str | None
    call_chain: list[str]


def _run_exists(run_id: str) -> bool:
    with st_session.session_scope() as s:
        return s.get(Run, run_id) is not None


def findings_list(run_id: str) -> list[FindingListRow]:
    """Findings for a run in report display order, or [] if the run is absent."""
    if not _run_exists(run_id):
        return []
    report = report_stage._load(run_id, st_session.session_factory())
    return [
        FindingListRow(
            id=f.id,
            title=f.title,
            attack_class=f.attack_class,
            file=f.file,
            severity=f.severity,
            confidence=f.confidence,
            status=f.status,
            reachable=f.reachable,
        )
        for f in report.findings
    ]


def _format_poc_result(raw: str | None) -> str | None:
    if raw is None:
        return None
    try:
        return json.dumps(json.loads(raw), indent=2)
    except (ValueError, TypeError):
        return raw


def _format_call_chain(chain: list[dict[str, object]]) -> list[str]:
    hops: list[str] = []
    for hop in chain:
        sym = hop.get("symbol") or hop.get("function") or "?"
        file = hop.get("file") or ""
        line = hop.get("line")
        loc = f"{file}:{line}" if line is not None else str(file)
        hops.append(f"{sym}  ({loc})" if loc else str(sym))
    return hops


def finding_detail(run_id: str, finding_id: str) -> FindingDetail | None:
    """Full detail for one finding, or None if run/finding absent."""
    if not _run_exists(run_id):
        return None
    report = report_stage._load(run_id, st_session.session_factory())
    match = next((f for f in report.findings if f.id == finding_id), None)
    if match is None:
        return None

    # poc_result is not on ReportFinding; read it directly.
    with st_session.session_scope() as s:
        row = s.get(Finding, finding_id)
        poc_result_raw = row.poc_result_json if row is not None else None

    fn = f" ({match.function})" if match.function else ""
    location = f"{match.file}:{match.line_start}-{match.line_end}{fn}"
    return FindingDetail(
        id=match.id,
        title=match.title,
        attack_class=match.attack_class,
        location=location,
        severity=match.severity,
        confidence=match.confidence,
        status=match.status,
        description=match.description,
        poc_code=match.poc_code,
        poc_result=_format_poc_result(poc_result_raw),
        suggested_fix=match.suggested_fix,
        verdict=match.validation.verdict if match.validation else None,
        verdict_rationale=match.validation.rationale if match.validation else None,
        reachable=match.trace.reachable if match.trace else match.reachable,
        trace_rationale=match.trace.rationale if match.trace else None,
        call_chain=_format_call_chain(match.trace.call_chain) if match.trace else [],
    )


@dataclass(frozen=True)
class SessionRow:
    stage: str
    model: str
    input_tokens: int
    output_tokens: int
    cost_usd: float
    outcome: str
    refusal_text: str | None
    error_text: str | None


def list_sessions(run_id: str) -> list[SessionRow]:
    """Agent sessions for a run, ordered by start time."""
    with st_session.session_scope() as s:
        rows = (
            s.execute(
                select(AgentSession)
                .where(AgentSession.run_id == run_id)
                .order_by(AgentSession.started_at.asc())
            )
            .scalars()
            .all()
        )
        return [
            SessionRow(
                stage=r.stage,
                model=r.model,
                input_tokens=r.input_tokens,
                output_tokens=r.output_tokens,
                cost_usd=r.cost_usd,
                outcome=r.outcome,
                refusal_text=r.refusal_text,
                error_text=r.error_text,
            )
            for r in rows
        ]
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `$PY -m pytest tests/unit/test_tui_data.py -v`
Expected: PASS (all data tests).

- [ ] **Step 5: Type + lint check**

Run: `/home/tdang/projects/personal/FlossWing/.venv/bin/mypy --strict flosswing/tui/data.py && /home/tdang/projects/personal/FlossWing/.venv/bin/ruff check flosswing/tui/data.py`
Expected: no errors. (If mypy complains about `report_stage._load` accessing a private symbol, that is allowed — mypy does not enforce underscore privacy. If it flags the `call_chain` `dict[str, object]` access, the `.get(...)` returns `object`; the `or` chain keeps it `object`, and `str(...)`/f-strings accept `object`, so it types fine.)

- [ ] **Step 6: Commit**

```bash
git add flosswing/tui/data.py tests/unit/test_tui_data.py
git commit -m "Add tui.data findings/detail/sessions queries per docs/plans/2026-06-15-tui-dashboard.md Task 4

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: `launcher.py` — spawn and track child processes

**Files:**
- Create: `flosswing/tui/launcher.py`
- Test: `tests/unit/test_tui_launcher.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_tui_launcher.py` (include GPL header):

```python
"""flosswing.tui.launcher — scan/report child process management."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

from flosswing.tui import launcher


def test_build_scan_argv_minimal() -> None:
    argv = launcher.build_scan_argv(Path("/tmp/repo"), depth="standard", formats=["md", "json"], hunt_token_budget=None)
    assert argv[:4] == [sys.executable, "-m", "flosswing.cli", "scan"]
    assert "/tmp/repo" in argv
    assert "--depth" in argv and "standard" in argv
    assert "--format" in argv and "md,json" in argv
    assert "--hunt-token-budget" not in argv


def test_build_scan_argv_with_budget() -> None:
    argv = launcher.build_scan_argv(Path("/tmp/repo"), depth="deep", formats=["md"], hunt_token_budget=150000)
    assert "--hunt-token-budget" in argv
    assert "150000" in argv
    assert "deep" in argv


def test_build_report_argv() -> None:
    argv = launcher.build_report_argv("run-123")
    assert argv == [sys.executable, "-m", "flosswing.cli", "report", "run-123"]


def test_spawn_scan_starts_process_and_tracks_it(tmp_path: Path) -> None:
    fake = mock.MagicMock()
    fake.poll.return_value = None  # alive
    with mock.patch("flosswing.tui.launcher.subprocess.Popen", return_value=fake) as popen:
        proc = launcher.spawn_scan(tmp_path, depth="standard", formats=["md"], hunt_token_budget=None)
    popen.assert_called_once()
    assert proc.is_alive() is True
    # log path is under the flosswing runs dir
    assert proc.log_path.name == "tui-scan.log"


def test_proc_is_alive_false_after_exit() -> None:
    fake = mock.MagicMock()
    fake.poll.return_value = 0
    proc = launcher.ChildProcess(popen=fake, log_path=Path("/tmp/x.log"), kind="scan")
    assert proc.is_alive() is False
    assert proc.returncode == 0


def test_terminate_escalates_to_kill() -> None:
    fake = mock.MagicMock()
    # Still alive after SIGTERM (wait raises TimeoutExpired), then killed.
    import subprocess as _sp

    fake.wait.side_effect = [_sp.TimeoutExpired(cmd="scan", timeout=5), 0]
    proc = launcher.ChildProcess(popen=fake, log_path=Path("/tmp/x.log"), kind="scan")
    proc.terminate(grace_seconds=5)
    fake.terminate.assert_called_once()
    fake.kill.assert_called_once()
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `$PY -m pytest tests/unit/test_tui_launcher.py -v`
Expected: FAIL — `flosswing.tui.launcher` does not exist.

- [ ] **Step 3: Implement `launcher.py`**

Create `flosswing/tui/launcher.py` (include GPL header):

```python
"""Spawn and track `flosswing scan` / `flosswing report` child processes.

This is the only TUI module that starts subprocesses. It never touches the
state DB; progress is read separately via `flosswing.tui.data`. Children are
launched as `python -m flosswing.cli …` so they work regardless of whether a
`flosswing` console script is on PATH.
"""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

_RUNS_DIR = Path.home() / ".flosswing" / "runs"


def build_scan_argv(
    path: Path,
    *,
    depth: str,
    formats: list[str],
    hunt_token_budget: int | None,
) -> list[str]:
    """Construct argv for a scan child process."""
    argv = [
        sys.executable,
        "-m",
        "flosswing.cli",
        "scan",
        str(path),
        "--depth",
        depth,
        "--format",
        ",".join(formats),
    ]
    if hunt_token_budget is not None:
        argv += ["--hunt-token-budget", str(hunt_token_budget)]
    return argv


def build_report_argv(run_id: str) -> list[str]:
    """Construct argv for a report re-render child process."""
    return [sys.executable, "-m", "flosswing.cli", "report", run_id]


@dataclass
class ChildProcess:
    """A spawned child plus its captured-output log path."""

    popen: subprocess.Popen[bytes]
    log_path: Path
    kind: str  # "scan" | "report"

    def is_alive(self) -> bool:
        return self.popen.poll() is None

    @property
    def returncode(self) -> int | None:
        return self.popen.poll()

    def terminate(self, grace_seconds: float = 5.0) -> None:
        """SIGTERM, then SIGKILL if the child does not exit within the grace."""
        if not self.is_alive():
            return
        self.popen.terminate()
        try:
            self.popen.wait(timeout=grace_seconds)
        except subprocess.TimeoutExpired:
            self.popen.kill()
            self.popen.wait(timeout=grace_seconds)


def _open_log(kind: str) -> Path:
    """A timestamp-free, kind-specific log path under the runs dir.

    The scan child generates its own run_id, so we cannot name the log after
    it up front; a single rolling log per launch is sufficient for post-hoc
    inspection. Existing content is truncated on each launch.
    """
    _RUNS_DIR.mkdir(parents=True, exist_ok=True)
    return _RUNS_DIR / f"tui-{kind}.log"


def spawn_scan(
    path: Path,
    *,
    depth: str,
    formats: list[str],
    hunt_token_budget: int | None,
) -> ChildProcess:
    argv = build_scan_argv(
        path, depth=depth, formats=formats, hunt_token_budget=hunt_token_budget
    )
    log_path = _open_log("scan")
    log = open(log_path, "wb")  # noqa: SIM115 — handle owned by the child's lifetime
    popen = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT)
    return ChildProcess(popen=popen, log_path=log_path, kind="scan")


def spawn_report(run_id: str) -> ChildProcess:
    argv = build_report_argv(run_id)
    log_path = _open_log("report")
    log = open(log_path, "wb")  # noqa: SIM115
    popen = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT)
    return ChildProcess(popen=popen, log_path=log_path, kind="report")
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `$PY -m pytest tests/unit/test_tui_launcher.py -v`
Expected: PASS (6 tests). Note: `spawn_scan`'s test patches `subprocess.Popen`, so no real `open(...)` of a log under `$HOME` should occur — but `_open_log` does create `~/.flosswing/runs/`. That is acceptable (mkdir is idempotent and harmless). If isolation is desired, the test may also `monkeypatch.setattr(launcher, "_RUNS_DIR", tmp_path)`.

- [ ] **Step 5: Type + lint check**

Run: `/home/tdang/projects/personal/FlossWing/.venv/bin/mypy --strict flosswing/tui/launcher.py && /home/tdang/projects/personal/FlossWing/.venv/bin/ruff check flosswing/tui/launcher.py`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add flosswing/tui/launcher.py tests/unit/test_tui_launcher.py
git commit -m "Add tui.launcher scan/report child process management per docs/plans/2026-06-15-tui-dashboard.md Task 5

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: `app.py` + `RunsScreen`

**Files:**
- Modify: `flosswing/tui/app.py`
- Create: `flosswing/tui/screens/runs.py`
- Test: `tests/unit/test_tui_screens.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_tui_screens.py` (include GPL header). Define a shared seeding fixture reused by Tasks 7–9:

```python
"""flosswing.tui screen smoke tests via Textual's run_test() pilot."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from flosswing.state import session as st_session
from flosswing.state.models import (
    AgentSession,
    Finding,
    HuntTask,
    Run,
)
from flosswing.tui.app import FlosswingTUI


def _iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


@pytest.fixture()
def seeded_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    monkeypatch.setenv("FLOSSWING_DB_URL", f"sqlite:///{tmp_path}/state.db")
    monkeypatch.setattr(st_session, "_cached_engine", None, raising=False)
    monkeypatch.setattr(st_session, "_cached_session_factory", None, raising=False)
    run_id = "01JTESTRUN0000000000000000"
    with st_session.session_scope() as s:
        s.add(
            Run(
                id=run_id,
                target_repo_path="/tmp/curl",
                target_repo_sha=None,
                depth="standard",
                budget_total=20,
                budget_used=0,
                started_at=_iso(),
                finished_at=_iso(),
                status="completed",
                config_json="{}",
                flosswing_version="test",
            )
        )
        s.add(
            HuntTask(
                id="task-1",
                run_id=run_id,
                attack_class="command_injection",
                scope_hint="src/x.c",
                source="recon",
                status="completed",
                created_at=_iso(),
                findings_count=1,
            )
        )
        s.add(
            Finding(
                id="find-1",
                run_id=run_id,
                hunt_task_id="task-1",
                attack_class="command_injection",
                file="src/x.c",
                function="parse",
                line_start=10,
                line_end=12,
                severity="high",
                confidence="confirmed",
                status="confirmed",
                title="Command injection in parse()",
                description="User input flows to system().",
                poc_code="print('poc')",
                poc_result_json='{"stdout": "pwned"}',
                suggested_fix="Use execve.",
                created_at=_iso(),
            )
        )
        s.add(
            AgentSession(
                id="sess-1",
                run_id=run_id,
                stage="hunt",
                task_id="task-1",
                finding_id=None,
                model="claude-sonnet-4-6",
                system_prompt_hash="x",
                input_tokens=200,
                output_tokens=80,
                cost_usd=0.02,
                duration_ms=1000,
                outcome="completed",
                started_at=_iso(),
                finished_at=_iso(),
            )
        )
    yield run_id


@pytest.mark.asyncio
async def test_runs_screen_lists_run(seeded_db: str) -> None:
    app = FlosswingTUI()
    async with app.run_test() as pilot:
        await pilot.pause()
        # The run's short id and repo path appear on the runs screen.
        text = app.screen.query_one("#runs-table").__class__.__name__
        assert text == "DataTable"
        # Table has at least one data row.
        from textual.widgets import DataTable

        table = app.screen.query_one("#runs-table", DataTable)
        assert table.row_count == 1
```

Note: tests use the explicit `@pytest.mark.asyncio` marker — the established pattern in this repo (see `tests/unit/test_sandbox_docker_args.py` and `tests/unit/test_stages_validate.py`). `pytest-asyncio` is already a dev dependency; no `pyproject.toml` change is needed.

- [ ] **Step 2: Run the test to verify it fails**

Run: `$PY -m pytest tests/unit/test_tui_screens.py -v`
Expected: FAIL — `FlosswingTUI` / `RunsScreen` not defined.

- [ ] **Step 3: Implement `RunsScreen`**

Create `flosswing/tui/screens/runs.py` (include GPL header):

```python
"""Runs list — the initial screen."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Static

from flosswing.tui import data


class RunsScreen(Screen[None]):
    BINDINGS = [
        ("enter", "open_run", "Open"),
        ("n", "new_scan", "New scan"),
        ("r", "render_report", "Re-render report"),
        ("q", "request_quit", "Quit"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        yield DataTable(id="runs-table", cursor_type="row")
        yield Static("", id="runs-empty")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#runs-table", DataTable)
        table.add_columns("Run", "Repo", "Status", "Findings", "Started")
        self.refresh_rows()
        # Poll so newly-launched / still-running scans appear and update.
        self.set_interval(2.0, self.refresh_rows)

    def refresh_rows(self) -> None:
        table = self.query_one("#runs-table", DataTable)
        rows = data.list_runs()
        # Preserve cursor position across refresh.
        cursor = table.cursor_row
        table.clear()
        for r in rows:
            badge = "running" if r.status == "running" else r.status
            table.add_row(
                r.short_id,
                r.target_repo_path,
                badge,
                str(r.findings_count),
                r.started_at,
                key=r.id,
            )
        empty = self.query_one("#runs-empty", Static)
        empty.update(
            "No runs yet — press [b]n[/b] to start a scan." if not rows else ""
        )
        if rows and 0 <= cursor < len(rows):
            table.move_cursor(row=cursor)

    def _selected_run_id(self) -> str | None:
        table = self.query_one("#runs-table", DataTable)
        if table.row_count == 0:
            return None
        row_key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key
        return row_key.value

    def action_open_run(self) -> None:
        run_id = self._selected_run_id()
        if run_id is not None:
            from flosswing.tui.screens.run_detail import RunDetailScreen

            self.app.push_screen(RunDetailScreen(run_id))

    def action_new_scan(self) -> None:
        from flosswing.tui.screens.new_scan import NewScanScreen

        self.app.push_screen(NewScanScreen())

    def action_render_report(self) -> None:
        run_id = self._selected_run_id()
        if run_id is None:
            return
        from flosswing.tui import launcher

        try:
            self.app.track_child(launcher.spawn_report(run_id))
            self.notify(f"Re-rendering report for {run_id[-8:]}…")
        except Exception as e:  # noqa: BLE001 — surface, never crash the UI
            from flosswing import errors

            self.notify(f"report failed: {errors.scrub(str(e))}", severity="error")

    def action_request_quit(self) -> None:
        self.app.action_request_quit()
```

Note: `action_open_run` is bound to `enter`, but `DataTable` also emits `RowSelected` on Enter. To avoid double navigation, rely on the binding only and do not also handle `on_data_table_row_selected` here.

- [ ] **Step 4: Implement `FlosswingTUI` in `app.py`**

Replace `flosswing/tui/app.py` contents (keep the GPL header) with:

```python
"""Textual application entry point for the FlossWing dashboard."""

from __future__ import annotations

from textual.app import App

from flosswing.tui.launcher import ChildProcess


class FlosswingTUI(App[None]):
    """Read-only dashboard over state.db plus a scan/report launcher."""

    TITLE = "FlossWing"
    SUB_TITLE = "vulnerability research dashboard"

    def __init__(self) -> None:
        super().__init__()
        self._children: list[ChildProcess] = []

    def on_mount(self) -> None:
        from flosswing.tui.screens.runs import RunsScreen

        self.push_screen(RunsScreen())

    def track_child(self, child: ChildProcess) -> None:
        """Register a spawned child so the quit guard can manage it."""
        self._children.append(child)

    def live_children(self) -> list[ChildProcess]:
        return [c for c in self._children if c.is_alive()]

    def action_request_quit(self) -> None:
        """Quit, but guard against killing a live scan we launched."""
        live = [c for c in self.live_children() if c.kind == "scan"]
        if not live:
            self.exit()
            return
        from flosswing.tui.screens.new_scan import QuitGuard

        self.push_screen(QuitGuard(live))


def run() -> None:
    """Launch the dashboard (called by `flosswing tui`)."""
    FlosswingTUI().run()
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `$PY -m pytest tests/unit/test_tui_screens.py -v`
Expected: This test imports `RunDetailScreen`, `NewScanScreen`, `QuitGuard` only lazily inside actions, so the module import succeeds even though those screens don't exist yet. PASS (1 test).

If the test fails because `new_scan`/`run_detail` modules are imported at class-definition time anywhere, ensure all cross-screen imports are inside methods (lazy), as written.

- [ ] **Step 6: Commit**

```bash
git add flosswing/tui/app.py flosswing/tui/screens/runs.py tests/unit/test_tui_screens.py pyproject.toml
git commit -m "Add FlosswingTUI app + RunsScreen per docs/plans/2026-06-15-tui-dashboard.md Task 6

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: `RunDetailScreen` + `SessionsScreen`

**Files:**
- Create: `flosswing/tui/screens/run_detail.py`
- Create: `flosswing/tui/screens/sessions.py`
- Test: `tests/unit/test_tui_screens.py` (append)

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_tui_screens.py`:

```python
@pytest.mark.asyncio
async def test_run_detail_shows_stage_strip_and_pushes(seeded_db: str) -> None:
    from flosswing.tui.screens.run_detail import RunDetailScreen

    app = FlosswingTUI()
    async with app.run_test() as pilot:
        await pilot.pause()
        app.push_screen(RunDetailScreen(seeded_db))
        await pilot.pause()
        from textual.widgets import Static

        strip = app.screen.query_one("#stage-strip", Static)
        rendered = str(strip.renderable)
        assert "Recon" in rendered and "Hunt" in rendered


@pytest.mark.asyncio
async def test_sessions_screen_lists_session(seeded_db: str) -> None:
    from flosswing.tui.screens.sessions import SessionsScreen

    app = FlosswingTUI()
    async with app.run_test() as pilot:
        await pilot.pause()
        app.push_screen(SessionsScreen(seeded_db))
        await pilot.pause()
        from textual.widgets import DataTable

        table = app.screen.query_one("#sessions-table", DataTable)
        assert table.row_count == 1
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `$PY -m pytest tests/unit/test_tui_screens.py -k "run_detail or sessions" -v`
Expected: FAIL — screens not defined.

- [ ] **Step 3: Implement `RunDetailScreen`**

Create `flosswing/tui/screens/run_detail.py` (include GPL header):

```python
"""Run detail — stage progress, budget, Hunt task table."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Static

from flosswing.tui import data

_GLYPH = {"done": "✓", "active": "▶", "pending": "…", "n/a": "·"}


class RunDetailScreen(Screen[None]):
    BINDINGS = [
        ("f", "findings", "Findings"),
        ("s", "sessions", "Sessions"),
        ("escape", "app.pop_screen", "Back"),
    ]

    def __init__(self, run_id: str) -> None:
        super().__init__()
        self._run_id = run_id

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("", id="stage-strip")
        yield Static("", id="run-meta")
        yield DataTable(id="hunt-table", cursor_type="row")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#hunt-table", DataTable)
        table.add_columns("Attack class", "Scope", "Status", "Findings")
        self.refresh_view()
        self.set_interval(2.0, self.refresh_view)

    def refresh_view(self) -> None:
        p = data.run_progress(self._run_id)
        strip = self.query_one("#stage-strip", Static)
        meta = self.query_one("#run-meta", Static)
        if p is None:
            strip.update("run not found")
            meta.update("")
            return
        self.sub_title = f"{p.short_id}  {p.target_repo_path}  [{p.status}]"
        strip.update(
            "  ".join(f"{_GLYPH[st.state]} {st.name}" for st in p.stages)
        )
        meta.update(
            f"Hunt {p.hunt_done}/{p.hunt_total}   "
            f"findings {p.findings_total}   "
            f"tokens {p.tokens_used:,}   "
            f"cost ${p.cost_usd:.2f}"
        )
        table = self.query_one("#hunt-table", DataTable)
        cursor = table.cursor_row
        table.clear()
        for t in p.hunt_tasks:
            table.add_row(t.attack_class, t.scope_hint, t.status, str(t.findings_count))
        if p.hunt_tasks and 0 <= cursor < len(p.hunt_tasks):
            table.move_cursor(row=cursor)
        # Stop polling once the run is terminal.
        if p.status != "running":
            self._stop_polling()

    def _stop_polling(self) -> None:
        for timer in list(self._timers):
            timer.stop()

    def action_findings(self) -> None:
        from flosswing.tui.screens.findings import FindingsScreen

        self.app.push_screen(FindingsScreen(self._run_id))

    def action_sessions(self) -> None:
        from flosswing.tui.screens.sessions import SessionsScreen

        self.app.push_screen(SessionsScreen(self._run_id))
```

Note on `self._timers`: Textual tracks active timers on a widget. If `self._timers` is not available in the installed Textual version, replace `_stop_polling` with capturing the timer handle: store `self._poll = self.set_interval(...)` in `on_mount` and call `self._poll.stop()`. Use whichever the installed version supports; verify during Step 5.

- [ ] **Step 4: Implement `SessionsScreen`**

Create `flosswing/tui/screens/sessions.py` (include GPL header):

```python
"""Agent sessions for a run."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header

from flosswing.tui import data


class SessionsScreen(Screen[None]):
    BINDINGS = [("escape", "app.pop_screen", "Back")]

    def __init__(self, run_id: str) -> None:
        super().__init__()
        self._run_id = run_id

    def compose(self) -> ComposeResult:
        yield Header()
        yield DataTable(id="sessions-table", cursor_type="row")
        yield Footer()

    def on_mount(self) -> None:
        self.sub_title = "agent sessions"
        table = self.query_one("#sessions-table", DataTable)
        table.add_columns("Stage", "Model", "In", "Out", "Cost", "Outcome", "Note")
        for r in data.list_sessions(self._run_id):
            note = ""
            if r.outcome == "refused" and r.refusal_text:
                note = f"refused: {r.refusal_text[:40]}"
            elif r.error_text:
                note = f"error: {r.error_text[:40]}"
            table.add_row(
                r.stage,
                r.model,
                str(r.input_tokens),
                str(r.output_tokens),
                f"${r.cost_usd:.2f}",
                r.outcome,
                note,
            )
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `$PY -m pytest tests/unit/test_tui_screens.py -v`
Expected: PASS. If `_stop_polling` raised (missing `self._timers`), apply the handle-based alternative from the Step 3 note and re-run.

- [ ] **Step 6: Type + lint check**

Run: `/home/tdang/projects/personal/FlossWing/.venv/bin/mypy --strict flosswing/tui/screens/run_detail.py flosswing/tui/screens/sessions.py && /home/tdang/projects/personal/FlossWing/.venv/bin/ruff check flosswing/tui/screens/`
Expected: no errors.

- [ ] **Step 7: Commit**

```bash
git add flosswing/tui/screens/run_detail.py flosswing/tui/screens/sessions.py tests/unit/test_tui_screens.py
git commit -m "Add RunDetailScreen + SessionsScreen per docs/plans/2026-06-15-tui-dashboard.md Task 7

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: `FindingsScreen` + `FindingDetailScreen`

**Files:**
- Create: `flosswing/tui/screens/findings.py`
- Create: `flosswing/tui/screens/finding_detail.py`
- Test: `tests/unit/test_tui_screens.py` (append)

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_tui_screens.py`:

```python
@pytest.mark.asyncio
async def test_findings_screen_lists_finding(seeded_db: str) -> None:
    from flosswing.tui.screens.findings import FindingsScreen

    app = FlosswingTUI()
    async with app.run_test() as pilot:
        await pilot.pause()
        app.push_screen(FindingsScreen(seeded_db))
        await pilot.pause()
        from textual.widgets import DataTable

        table = app.screen.query_one("#findings-table", DataTable)
        assert table.row_count == 1


@pytest.mark.asyncio
async def test_finding_detail_renders_poc(seeded_db: str) -> None:
    from flosswing.tui.screens.finding_detail import FindingDetailScreen

    app = FlosswingTUI()
    async with app.run_test() as pilot:
        await pilot.pause()
        app.push_screen(FindingDetailScreen(seeded_db, "find-1"))
        await pilot.pause()
        from textual.widgets import Static

        body = app.screen.query_one("#finding-body", Static)
        rendered = str(body.renderable)
        assert "Command injection" in rendered
        assert "pwned" in rendered  # poc result rendered
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `$PY -m pytest tests/unit/test_tui_screens.py -k "findings_screen or finding_detail" -v`
Expected: FAIL — screens not defined.

- [ ] **Step 3: Implement `FindingsScreen`**

Create `flosswing/tui/screens/findings.py` (include GPL header):

```python
"""Findings list for a run."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header

from flosswing.tui import data


class FindingsScreen(Screen[None]):
    BINDINGS = [
        ("enter", "open_finding", "Open"),
        ("escape", "app.pop_screen", "Back"),
    ]

    def __init__(self, run_id: str) -> None:
        super().__init__()
        self._run_id = run_id

    def compose(self) -> ComposeResult:
        yield Header()
        yield DataTable(id="findings-table", cursor_type="row")
        yield Footer()

    def on_mount(self) -> None:
        self.sub_title = "findings"
        table = self.query_one("#findings-table", DataTable)
        table.add_columns("Severity", "Conf.", "Status", "Reach", "Class", "Title")
        for f in data.findings_list(self._run_id):
            table.add_row(
                f.severity,
                f.confidence,
                f.status,
                f.reachable or "-",
                f.attack_class,
                f.title,
                key=f.id,
            )

    def action_open_finding(self) -> None:
        table = self.query_one("#findings-table", DataTable)
        if table.row_count == 0:
            return
        finding_id = table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
        if finding_id is None:
            return
        from flosswing.tui.screens.finding_detail import FindingDetailScreen

        self.app.push_screen(FindingDetailScreen(self._run_id, finding_id))
```

- [ ] **Step 4: Implement `FindingDetailScreen`**

Create `flosswing/tui/screens/finding_detail.py` (include GPL header):

```python
"""Single finding detail — PoC, validation, trace, suggested fix."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.screen import Screen
from textual.widgets import Footer, Header, Static

from flosswing.tui import data
from flosswing.tui.data import FindingDetail


def _render(d: FindingDetail) -> str:
    lines: list[str] = []
    lines.append(f"# {d.title}")
    lines.append(f"{d.attack_class}  ·  {d.severity}/{d.confidence}  ·  {d.status}")
    lines.append(f"location: {d.location}")
    if d.reachable:
        lines.append(f"reachability: {d.reachable}")
    lines.append("")
    lines.append("## Description")
    lines.append(d.description or "(none)")
    if d.poc_code:
        lines.append("")
        lines.append("## PoC")
        lines.append(d.poc_code)
    if d.poc_result:
        lines.append("")
        lines.append("## PoC result")
        lines.append(d.poc_result)
    if d.verdict:
        lines.append("")
        lines.append(f"## Validation: {d.verdict}")
        lines.append(d.verdict_rationale or "")
    if d.call_chain:
        lines.append("")
        lines.append("## Trace")
        if d.trace_rationale:
            lines.append(d.trace_rationale)
        for i, hop in enumerate(d.call_chain):
            lines.append(f"  {i}. {hop}")
    if d.suggested_fix:
        lines.append("")
        lines.append("## Suggested fix")
        lines.append(d.suggested_fix)
    return "\n".join(lines)


class FindingDetailScreen(Screen[None]):
    BINDINGS = [("escape", "app.pop_screen", "Back")]

    def __init__(self, run_id: str, finding_id: str) -> None:
        super().__init__()
        self._run_id = run_id
        self._finding_id = finding_id

    def compose(self) -> ComposeResult:
        yield Header()
        with VerticalScroll():
            yield Static("", id="finding-body")
        yield Footer()

    def on_mount(self) -> None:
        self.sub_title = "finding"
        d = data.finding_detail(self._run_id, self._finding_id)
        body = self.query_one("#finding-body", Static)
        body.update(_render(d) if d is not None else "finding not found")
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `$PY -m pytest tests/unit/test_tui_screens.py -v`
Expected: PASS (all screen tests).

- [ ] **Step 6: Type + lint check**

Run: `/home/tdang/projects/personal/FlossWing/.venv/bin/mypy --strict flosswing/tui/screens/findings.py flosswing/tui/screens/finding_detail.py && /home/tdang/projects/personal/FlossWing/.venv/bin/ruff check flosswing/tui/screens/`
Expected: no errors.

- [ ] **Step 7: Commit**

```bash
git add flosswing/tui/screens/findings.py flosswing/tui/screens/finding_detail.py tests/unit/test_tui_screens.py
git commit -m "Add FindingsScreen + FindingDetailScreen per docs/plans/2026-06-15-tui-dashboard.md Task 8

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 9: `NewScanScreen` modal + `QuitGuard` modal

**Files:**
- Create: `flosswing/tui/screens/new_scan.py`
- Test: `tests/unit/test_tui_screens.py` (append)

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_tui_screens.py`:

```python
@pytest.mark.asyncio
async def test_new_scan_modal_spawns_scan(seeded_db: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from unittest import mock

    from flosswing.tui import launcher
    from flosswing.tui.screens.new_scan import NewScanScreen

    spawned = {}

    def fake_spawn(path, *, depth, formats, hunt_token_budget):  # type: ignore[no-untyped-def]
        spawned["path"] = str(path)
        spawned["depth"] = depth
        child = mock.MagicMock()
        child.is_alive.return_value = False
        child.kind = "scan"
        return child

    monkeypatch.setattr(launcher, "spawn_scan", fake_spawn)

    app = FlosswingTUI()
    async with app.run_test() as pilot:
        await pilot.pause()
        screen = NewScanScreen()
        app.push_screen(screen)
        await pilot.pause()
        # Set the path input to an existing dir and submit.
        from textual.widgets import Input

        path_input = app.screen.query_one("#scan-path", Input)
        path_input.value = str(tmp_path)
        app.screen.action_submit()
        await pilot.pause()
    assert spawned["path"] == str(tmp_path)


@pytest.mark.asyncio
async def test_quit_guard_detach_exits(seeded_db: str) -> None:
    from unittest import mock

    from flosswing.tui.screens.new_scan import QuitGuard

    child = mock.MagicMock()
    child.is_alive.return_value = True
    child.kind = "scan"

    app = FlosswingTUI()
    async with app.run_test() as pilot:
        await pilot.pause()
        guard = QuitGuard([child])
        app.push_screen(guard)
        await pilot.pause()
        app.screen.action_detach()
        await pilot.pause()
    # Detach must NOT terminate the child.
    child.terminate.assert_not_called()
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `$PY -m pytest tests/unit/test_tui_screens.py -k "new_scan or quit_guard" -v`
Expected: FAIL — `new_scan` module not defined.

- [ ] **Step 3: Implement `new_scan.py` (both modals)**

Create `flosswing/tui/screens/new_scan.py` (include GPL header):

```python
"""New-scan form and the quit-guard, both modal screens."""

from __future__ import annotations

from pathlib import Path

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, Select, Static

from flosswing.tui.launcher import ChildProcess

_DEPTHS = [("standard", "standard"), ("deep", "deep")]
_FORMATS = ["md", "json", "sarif"]


class NewScanScreen(ModalScreen[None]):
    BINDINGS = [("escape", "app.pop_screen", "Cancel")]

    def compose(self) -> ComposeResult:
        with Vertical(id="new-scan-box"):
            yield Label("New scan")
            yield Input(value=str(Path.cwd()), placeholder="repo path", id="scan-path")
            yield Select(_DEPTHS, value="standard", id="scan-depth", allow_blank=False)
            yield Input(value="md,json", placeholder="formats (comma sep)", id="scan-formats")
            yield Input(placeholder="hunt token budget (optional)", id="scan-budget")
            yield Static("", id="scan-error")
            with Horizontal():
                yield Button("Start", variant="primary", id="scan-start")
                yield Button("Cancel", id="scan-cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "scan-start":
            self.action_submit()
        else:
            self.app.pop_screen()

    def action_submit(self) -> None:
        from flosswing.tui import launcher

        err = self.query_one("#scan-error", Static)
        path_str = self.query_one("#scan-path", Input).value.strip()
        path = Path(path_str)
        if not path.is_dir():
            err.update(f"not a directory: {path_str}")
            return

        depth = str(self.query_one("#scan-depth", Select).value)
        formats = [
            f.strip()
            for f in self.query_one("#scan-formats", Input).value.split(",")
            if f.strip()
        ]
        bad = [f for f in formats if f not in _FORMATS]
        if not formats or bad:
            err.update(f"invalid format(s): {', '.join(bad) or '(empty)'}")
            return

        budget_str = self.query_one("#scan-budget", Input).value.strip()
        budget: int | None = None
        if budget_str:
            try:
                budget = int(budget_str)
            except ValueError:
                err.update("token budget must be an integer")
                return

        try:
            child = launcher.spawn_scan(
                path, depth=depth, formats=formats, hunt_token_budget=budget
            )
        except Exception as e:  # noqa: BLE001 — surface, never crash the UI
            from flosswing import errors

            err.update(f"failed to start scan: {errors.scrub(str(e))}")
            return

        self.app.track_child(child)
        self.app.pop_screen()
        self.notify("Scan started — watch the runs list for progress.")


class QuitGuard(ModalScreen[None]):
    """Shown when quitting with a live scan child the TUI launched."""

    BINDINGS = [
        ("d", "detach", "Detach"),
        ("k", "kill", "Kill"),
        ("escape", "app.pop_screen", "Cancel"),
    ]

    def __init__(self, live: list[ChildProcess]) -> None:
        super().__init__()
        self._live = live

    def compose(self) -> ComposeResult:
        with Vertical(id="quit-guard-box"):
            yield Label(f"{len(self._live)} scan(s) still running.")
            with Horizontal():
                yield Button("Detach (leave running)", variant="primary", id="qg-detach")
                yield Button("Kill", variant="error", id="qg-kill")
                yield Button("Cancel", id="qg-cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "qg-detach":
            self.action_detach()
        elif event.button.id == "qg-kill":
            self.action_kill()
        else:
            self.app.pop_screen()

    def action_detach(self) -> None:
        # Leave children running; just exit the UI.
        self.app.exit()

    def action_kill(self) -> None:
        for child in self._live:
            child.terminate()
        self.app.exit()
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `$PY -m pytest tests/unit/test_tui_screens.py -v`
Expected: PASS (all screen tests).

- [ ] **Step 5: Type + lint check**

Run: `/home/tdang/projects/personal/FlossWing/.venv/bin/mypy --strict flosswing/tui/screens/new_scan.py && /home/tdang/projects/personal/FlossWing/.venv/bin/ruff check flosswing/tui/screens/new_scan.py`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add flosswing/tui/screens/new_scan.py tests/unit/test_tui_screens.py
git commit -m "Add NewScanScreen + QuitGuard modals per docs/plans/2026-06-15-tui-dashboard.md Task 9

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 10: Finalize — full suite, types, lint, and a manual smoke run

**Files:** none new; verification + any fixups.

- [ ] **Step 1: Run the full test suite**

Run: `$PY -m pytest -p no:cacheprovider`
Expected: all prior tests (467 passed, 14 skipped baseline) plus the new TUI tests pass; 0 failures.

- [ ] **Step 2: Strict type check across the package**

Run: `/home/tdang/projects/personal/FlossWing/.venv/bin/mypy --strict flosswing/tui flosswing/cli.py`
Expected: `Success: no issues found`. Fix any issues inline (common: add return type annotations, narrow `Optional`).

- [ ] **Step 3: Lint the whole package**

Run: `/home/tdang/projects/personal/FlossWing/.venv/bin/ruff check flosswing/tui flosswing/cli.py tests/unit/test_tui_*.py`
Expected: `All checks passed!`.

- [ ] **Step 4: Manual smoke run (interactive, optional but recommended)**

Run: `$PY -m flosswing.cli tui`
Expected: the dashboard launches, shows the runs list (or the empty state). Press `q` to quit (no live scan → immediate exit). If you have a prior run in `~/.flosswing/state.db`, press `enter` to drill in, `f` for findings, `enter` on a finding, `esc` back, `s` for sessions. This is a non-automated check; note any rendering glitches and fix.

- [ ] **Step 5: Final commit (if any fixups were made)**

```bash
git add -A
git commit -m "Finalize TUI dashboard: full suite + strict types + lint green per docs/plans/2026-06-15-tui-dashboard.md Task 10

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Self-review notes (for the implementer)

- **Spec coverage:** Runs list (Task 6), run detail + stage strip + budget-as-token-totals (Task 7), findings list + detail with PoC/validation/trace/fix (Task 8), sessions with refusals surfaced (Task 7), new-scan with path+depth+format+budget (Task 9), quit guard detach/kill/cancel (Task 9), report re-render (Task 6 `action_render_report`), read-only DB access + scrub-only-errors (Task 2/4), lazy CLI import (Task 1). All spec sections map to a task.
- **Textual API caveats to verify at implementation time** (versions drift): `DataTable.coordinate_to_cell_key(...).row_key.value`, `move_cursor(row=...)`, `Select(allow_blank=...)`, and the timer-stop mechanism in `RunDetailScreen` (`self._timers` vs storing the handle). The plan flags the fallback for the timer case; apply the analogous check if a `DataTable`/`Select` signature differs in the installed version. These are the only version-sensitive spots.
- **No placeholders:** every step shows full code or an exact command + expected output.
```
