"""flosswing.stages.report.render — empty-run and edge-case behaviour.

Per docs/specs/2026-06-02-v1.0-report-design.md § Graceful degradation
and § Determinism. Covers:

- A Run with zero findings: ``report.md`` and ``report.json`` write
  correctly; summary shows zeros; ``findings/`` exists but is empty.
- A Run with ``status='errored'`` renders partial state without raising.
- ``--format json`` only (no ``md``): ``report.md`` is NOT written;
  ``report.json`` IS written; ``findings/`` is still created.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from ulid import ULID

from flosswing.stages import report as report_stage
from flosswing.state import session as st_session
from flosswing.state.models import Run


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


def _seed_run(
    run_id: str,
    *,
    status: str = "completed",
    config_json: str = '{"model": "claude-opus-4-7"}',
) -> None:
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
                status=status,
                config_json=config_json,
                flosswing_version="1.0.0",
            )
        )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_render_empty_run_writes_both_formats(
    isolated_db: Path, tmp_path: Path,
) -> None:
    """Zero-findings run: report.md + report.json written; findings/
    exists but is empty; summary shows zeros."""
    run_id = str(ULID())
    _seed_run(run_id)

    output_dir = tmp_path / "out"
    result = report_stage.render(
        run_id=run_id,
        session_factory=st_session.session_factory(),
        output_dir=output_dir,
        formats=["md", "json"],
    )

    md_path = output_dir / "report.md"
    json_path = output_dir / "report.json"
    findings_root = output_dir / "findings"

    assert md_path.exists()
    assert json_path.exists()
    assert findings_root.exists()
    assert list(findings_root.iterdir()) == []

    j = json.loads(json_path.read_text(encoding="utf-8"))
    assert j["summary"]["findings_total"] == 0
    assert j["summary"]["findings_confirmed"] == 0
    assert j["summary"]["clusters_total"] == 0

    assert set(result.formats_written) == {"md", "json"}
    assert result.findings_dirs_written == 0


def test_render_errored_run_does_not_raise(
    isolated_db: Path, tmp_path: Path,
) -> None:
    """A run with ``status='errored'`` still renders partial state."""
    run_id = str(ULID())
    _seed_run(run_id, status="errored")

    output_dir = tmp_path / "out"
    result = report_stage.render(
        run_id=run_id,
        session_factory=st_session.session_factory(),
        output_dir=output_dir,
        formats=["md", "json"],
    )

    assert (output_dir / "report.md").exists()
    assert (output_dir / "report.json").exists()
    j = json.loads((output_dir / "report.json").read_text(encoding="utf-8"))
    assert j["run"]["status"] == "errored"
    assert set(result.formats_written) == {"md", "json"}


def test_render_json_only_skips_markdown(
    isolated_db: Path, tmp_path: Path,
) -> None:
    """``formats=['json']`` writes report.json but NOT report.md;
    ``findings/`` is still created."""
    run_id = str(ULID())
    _seed_run(run_id)

    output_dir = tmp_path / "out"
    result = report_stage.render(
        run_id=run_id,
        session_factory=st_session.session_factory(),
        output_dir=output_dir,
        formats=["json"],
    )

    assert not (output_dir / "report.md").exists()
    assert (output_dir / "report.json").exists()
    assert (output_dir / "findings").exists()
    assert result.formats_written == ["json"]
