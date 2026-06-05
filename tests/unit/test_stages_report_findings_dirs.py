"""flosswing.stages.report._write_findings_dirs — per-finding directories.

Per docs/specs/2026-06-02-v1.0-report-design.md § Per-finding directories.

Covers:
- A CONFIRMED finding gets a ``findings/<id>/finding.md`` AND
  ``findings/<id>/poc.py`` when ``poc_code`` is present.
- A CONFIRMED finding with ``poc_code is None`` gets only ``finding.md``
  (no ``poc.py``).
- Findings with status NOT IN ('confirmed') get NO directory.
- The returned dir count is correct.
- ``findings/`` parent is always created even with zero CONFIRMED rows.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from ulid import ULID

from flosswing.stages import report as report_stage
from flosswing.state import session as st_session
from flosswing.state.models import (
    Finding,
    HuntTask,
    Run,
)


def _now_iso() -> str:
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


def _seed_run(run_id: str) -> None:
    with st_session.session_scope() as s:
        s.add(
            Run(
                id=run_id,
                target_repo_path="/tmp/x",
                target_repo_sha=None,
                depth="standard",
                budget_total=100,
                budget_used=0,
                started_at=_now_iso(),
                finished_at=_now_iso(),
                status="completed",
                config_json='{"model": "claude-opus-4-7"}',
                flosswing_version="1.0.0",
            )
        )


def _seed_task(run_id: str) -> str:
    task_id = str(ULID())
    with st_session.session_scope() as s:
        s.add(
            HuntTask(
                id=task_id,
                run_id=run_id,
                attack_class="command_injection",
                scope_hint="src/",
                rationale="",
                priority="normal",
                source="recon",
                parent_finding_id=None,
                status="completed",
                created_at=_now_iso(),
                started_at=_now_iso(),
                finished_at=_now_iso(),
                findings_count=0,
            )
        )
    return task_id


def _seed_finding(
    *,
    run_id: str,
    task_id: str,
    status: str = "confirmed",
    poc_code: str | None = None,
    title: str = "shell injection",
    file: str = "src/a.py",
) -> str:
    fid = str(ULID())
    with st_session.session_scope() as s:
        s.add(
            Finding(
                id=fid,
                run_id=run_id,
                hunt_task_id=task_id,
                attack_class="command_injection",
                file=file,
                function="some_fn",
                line_start=10,
                line_end=12,
                severity="high",
                confidence="likely",
                status=status,
                title=title,
                description=(
                    "A reasonable description, fifty chars or more for realism."
                ),
                poc_code=poc_code,
                poc_result_json=None,
                suggested_fix=None,
                created_at=_now_iso(),
            )
        )
    return fid


def _load(run_id: str) -> report_stage.ReportV1:
    return report_stage._load(run_id, st_session.session_factory())


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_confirmed_with_poc_writes_finding_md_and_poc_py(
    isolated_db: Path, tmp_path: Path,
) -> None:
    """CONFIRMED + poc_code → both ``finding.md`` AND ``poc.py``."""
    run_id = str(ULID())
    _seed_run(run_id)
    task_id = _seed_task(run_id)
    fid = _seed_finding(
        run_id=run_id, task_id=task_id, status="confirmed",
        poc_code="print('proof')\n",
    )

    output_dir = tmp_path / "out"
    output_dir.mkdir()
    report = _load(run_id)
    dirs_written, bytes_written = report_stage._write_findings_dirs(
        report, output_dir
    )

    finding_md = output_dir / "findings" / fid / "finding.md"
    poc_py = output_dir / "findings" / fid / "poc.py"
    assert finding_md.exists()
    assert poc_py.exists()
    assert poc_py.read_text(encoding="utf-8") == "print('proof')\n"
    assert dirs_written == 1
    assert bytes_written > 0


def test_confirmed_without_poc_writes_only_finding_md(
    isolated_db: Path, tmp_path: Path,
) -> None:
    """CONFIRMED + poc_code IS NULL → only ``finding.md`` (no ``poc.py``)."""
    run_id = str(ULID())
    _seed_run(run_id)
    task_id = _seed_task(run_id)
    fid = _seed_finding(
        run_id=run_id, task_id=task_id, status="confirmed", poc_code=None,
    )

    output_dir = tmp_path / "out"
    output_dir.mkdir()
    report = _load(run_id)
    dirs_written, _ = report_stage._write_findings_dirs(
        report, output_dir
    )

    finding_dir = output_dir / "findings" / fid
    assert (finding_dir / "finding.md").exists()
    assert not (finding_dir / "poc.py").exists()
    assert dirs_written == 1


def test_non_confirmed_statuses_get_no_directory(
    isolated_db: Path, tmp_path: Path,
) -> None:
    """Findings in pending_validation / uncertain / rejected / superseded
    get NO directory in ``findings/``."""
    run_id = str(ULID())
    _seed_run(run_id)
    task_id = _seed_task(run_id)
    statuses = ("pending_validation", "uncertain", "rejected", "superseded")
    seeded_ids: list[str] = []
    for st in statuses:
        seeded_ids.append(
            _seed_finding(
                run_id=run_id, task_id=task_id, status=st,
                file=f"src/{st}.py", poc_code="print('x')\n",
            )
        )

    output_dir = tmp_path / "out"
    output_dir.mkdir()
    report = _load(run_id)
    dirs_written, _ = report_stage._write_findings_dirs(
        report, output_dir
    )

    findings_root = output_dir / "findings"
    assert findings_root.exists()
    for fid in seeded_ids:
        assert not (findings_root / fid).exists(), (
            f"non-confirmed finding {fid} should not have a directory"
        )
    assert dirs_written == 0


def test_dirs_written_count_matches_confirmed(
    isolated_db: Path, tmp_path: Path,
) -> None:
    """Mix of statuses → dirs_written equals the number of CONFIRMED rows."""
    run_id = str(ULID())
    _seed_run(run_id)
    task_id = _seed_task(run_id)
    # Three confirmed, two not.
    for i in range(3):
        _seed_finding(
            run_id=run_id, task_id=task_id, status="confirmed",
            file=f"src/c{i}.py", poc_code=f"print({i})\n",
        )
    _seed_finding(
        run_id=run_id, task_id=task_id, status="uncertain",
        file="src/u.py",
    )
    _seed_finding(
        run_id=run_id, task_id=task_id, status="rejected",
        file="src/r.py",
    )

    output_dir = tmp_path / "out"
    output_dir.mkdir()
    report = _load(run_id)
    dirs_written, _ = report_stage._write_findings_dirs(
        report, output_dir
    )
    assert dirs_written == 3


def test_findings_root_always_created_even_without_confirmed(
    isolated_db: Path, tmp_path: Path,
) -> None:
    """The ``findings/`` directory exists after a call even when zero
    findings were CONFIRMED."""
    run_id = str(ULID())
    _seed_run(run_id)
    task_id = _seed_task(run_id)
    # Only an uncertain finding.
    _seed_finding(
        run_id=run_id, task_id=task_id, status="uncertain",
    )

    output_dir = tmp_path / "out"
    output_dir.mkdir()
    report = _load(run_id)
    dirs_written, _ = report_stage._write_findings_dirs(
        report, output_dir
    )

    findings_root = output_dir / "findings"
    assert findings_root.exists()
    assert findings_root.is_dir()
    # No subdirectories were written.
    assert dirs_written == 0
    assert list(findings_root.iterdir()) == []


def test_poc_extension_follows_source_file_typescript(
    isolated_db: Path, tmp_path: Path,
) -> None:
    """A TS finding writes ``poc.ts``, not ``poc.py``. Regression from
    2026-06-04 SFA scan where every PoC landed at ``.py`` regardless
    of language."""
    run_id = str(ULID())
    _seed_run(run_id)
    task_id = _seed_task(run_id)
    fid = _seed_finding(
        run_id=run_id, task_id=task_id, status="confirmed",
        poc_code="export const exploit = () => {};\n",
        file="src/api/routes/portal.ts",
    )

    output_dir = tmp_path / "out"
    output_dir.mkdir()
    report = _load(run_id)
    report_stage._write_findings_dirs(report, output_dir)

    poc_ts = output_dir / "findings" / fid / "poc.ts"
    poc_py = output_dir / "findings" / fid / "poc.py"
    assert poc_ts.exists(), "TS source must produce poc.ts"
    assert not poc_py.exists()
    assert poc_ts.read_text(encoding="utf-8").startswith("export const exploit")


def test_poc_extension_tsx_normalises_to_ts(
    isolated_db: Path, tmp_path: Path,
) -> None:
    """TSX is the same language as TS; normalise to ``poc.ts`` so the
    operator can find it without thinking about JSX syntactic sugar."""
    run_id = str(ULID())
    _seed_run(run_id)
    task_id = _seed_task(run_id)
    fid = _seed_finding(
        run_id=run_id, task_id=task_id, status="confirmed",
        poc_code="<Component />\n",
        file="src/web/Foo.tsx",
    )

    output_dir = tmp_path / "out"
    output_dir.mkdir()
    report = _load(run_id)
    report_stage._write_findings_dirs(report, output_dir)

    poc_ts = output_dir / "findings" / fid / "poc.ts"
    poc_tsx = output_dir / "findings" / fid / "poc.tsx"
    assert poc_ts.exists()
    assert not poc_tsx.exists()


def test_poc_extension_unknown_source_extension_falls_back_to_txt(
    isolated_db: Path, tmp_path: Path,
) -> None:
    """Source files with unrecognised extensions get ``poc.txt`` so
    the file always has a non-empty extension (no zero-suffix paths
    that confuse operators or tooling)."""
    run_id = str(ULID())
    _seed_run(run_id)
    task_id = _seed_task(run_id)
    fid = _seed_finding(
        run_id=run_id, task_id=task_id, status="confirmed",
        poc_code="some opaque content\n",
        file="config/weird.unknownext",
    )

    output_dir = tmp_path / "out"
    output_dir.mkdir()
    report = _load(run_id)
    report_stage._write_findings_dirs(report, output_dir)

    poc_txt = output_dir / "findings" / fid / "poc.txt"
    assert poc_txt.exists()
