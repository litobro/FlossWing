"""flosswing.stages.report._render_json — JSON output shape.

Per docs/specs/2026-06-02-v1.0-report-design.md § JSON schema. Covers:

- ``schema_version`` is the literal string ``"1.0"``.
- ``rendered_at`` is ISO-8601 UTC with the Z suffix.
- Round-trip: ``ReportV1.model_validate_json(_render_json(report))``
  reconstructs an equal Pydantic shape.
- An empty findings list serialises as ``"findings": []``.
"""

from __future__ import annotations

import json
import re
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
    file: str = "src/a.py",
    severity: str = "high",
    status: str = "confirmed",
    title: str = "shell injection",
    description: str = (
        "A reasonable description, fifty chars or more for realism."
    ),
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
                severity=severity,
                confidence="likely",
                status=status,
                title=title,
                description=description,
                poc_code=None,
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


def test_json_schema_version_literal_one_zero(isolated_db: Path) -> None:
    """The JSON output has ``schema_version: "1.0"``."""
    run_id = str(ULID())
    _seed_run(run_id)
    report = _load(run_id)

    j = json.loads(report_stage._render_json(report))
    assert j["schema_version"] == "1.0"


def test_json_rendered_at_is_iso_z(isolated_db: Path) -> None:
    """``rendered_at`` parses as ISO-8601 UTC ending in Z."""
    run_id = str(ULID())
    _seed_run(run_id)
    report = _load(run_id)
    j = json.loads(report_stage._render_json(report))
    pattern = re.compile(
        r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$"
    )
    assert pattern.match(j["rendered_at"]), j["rendered_at"]


def test_json_round_trip_via_model_validate_json(
    isolated_db: Path,
) -> None:
    """``ReportV1.model_validate_json(_render_json(report))`` reconstructs
    an equal Pydantic value."""
    run_id = str(ULID())
    _seed_run(run_id)
    task_id = _seed_task(run_id)
    _seed_finding(
        run_id=run_id, task_id=task_id, severity="high",
    )
    _seed_finding(
        run_id=run_id, task_id=task_id, severity="low",
        file="src/b.py", title="another finding",
    )

    report = _load(run_id)
    serialized = report_stage._render_json(report)
    round_tripped = report_stage.ReportV1.model_validate_json(serialized)
    assert round_tripped == report


def test_json_empty_findings_serializes_as_empty_array(
    isolated_db: Path,
) -> None:
    """No findings produces ``"findings": []`` in the JSON dump."""
    run_id = str(ULID())
    _seed_run(run_id)
    report = _load(run_id)
    serialized = report_stage._render_json(report)
    j = json.loads(serialized)
    assert j["findings"] == []
    assert j["dedupe_clusters"] == []
