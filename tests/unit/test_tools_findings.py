"""tools/findings.py: state-writing tool implementations."""

from __future__ import annotations

import json
from collections.abc import Iterator

import pytest
from ulid import ULID

from flosswing.errors import (
    InvalidAttackClassError,
    ReconAlreadyRecordedError,
)
from flosswing.state import session as st_session
from flosswing.state.models import HuntTask, ReconArtifact, Run
from flosswing.tools.findings import (
    AddHuntTaskInput,
    RecordReconArtifactInput,
    add_hunt_task,
    record_recon_artifact,
)


@pytest.fixture()
def fresh_db(monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    monkeypatch.setenv("FLOSSWING_DB_URL", "sqlite:///:memory:")
    st_session._cached_engine = None  # type: ignore[attr-defined]
    st_session._cached_session_factory = None  # type: ignore[attr-defined]
    run_id = str(ULID())
    with st_session.session_scope() as s:
        s.add(
            Run(
                id=run_id,
                target_repo_path="/tmp/x",
                depth="standard",
                budget_total=20,
                started_at="2026-05-25T00:00:00Z",
                config_json="{}",
                flosswing_version="0.2.0",
            )
        )
    yield run_id
    st_session._cached_engine = None  # type: ignore[attr-defined]
    st_session._cached_session_factory = None  # type: ignore[attr-defined]


def test_record_recon_artifact_writes_row(fresh_db: str) -> None:
    out = record_recon_artifact(
        RecordReconArtifactInput(
            languages=["python"],
            build_commands={"primary": "pip install ."},
            entry_points=[],
            trust_boundaries=[],
            subsystems=[],
            notes="hello",
        ),
        run_id=fresh_db,
    )
    assert out.artifact_id
    with st_session.session_scope() as s:
        rows = s.query(ReconArtifact).all()
        assert len(rows) == 1
        assert json.loads(rows[0].languages_json) == ["python"]


def test_record_recon_artifact_twice_raises(fresh_db: str) -> None:
    inp = RecordReconArtifactInput(
        languages=["python"],
        build_commands={},
        entry_points=[],
        trust_boundaries=[],
        subsystems=[],
        notes="",
    )
    record_recon_artifact(inp, run_id=fresh_db)
    with pytest.raises(ReconAlreadyRecordedError):
        record_recon_artifact(inp, run_id=fresh_db)


def test_add_hunt_task_accepts_valid(fresh_db: str) -> None:
    out = add_hunt_task(
        AddHuntTaskInput(
            attack_class="command_injection",
            scope_hint="src/cli/exec.py",
            rationale="user input flows here",
        ),
        run_id=fresh_db,
        source="recon",
        budget_total=20,
    )
    assert out.accepted is True
    assert out.task_id
    with st_session.session_scope() as s:
        assert s.query(HuntTask).count() == 1


def test_add_hunt_task_rejects_invalid_class(fresh_db: str) -> None:
    with pytest.raises(InvalidAttackClassError):
        add_hunt_task(
            AddHuntTaskInput(
                attack_class="not_a_real_class",
                scope_hint="src/",
                rationale="",
            ),
            run_id=fresh_db,
            source="recon",
            budget_total=20,
        )


def test_add_hunt_task_budget_exhausted(fresh_db: str) -> None:
    for i in range(3):
        add_hunt_task(
            AddHuntTaskInput(
                attack_class="sqli",
                scope_hint=f"file{i}.py",
                rationale="",
            ),
            run_id=fresh_db,
            source="recon",
            budget_total=3,
        )
    out = add_hunt_task(
        AddHuntTaskInput(
            attack_class="sqli",
            scope_hint="overflow.py",
            rationale="",
        ),
        run_id=fresh_db,
        source="recon",
        budget_total=3,
    )
    assert out.accepted is False
    assert out.reason
