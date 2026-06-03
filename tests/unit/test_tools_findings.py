"""tools/findings.py: state-writing tool implementations."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest
from ulid import ULID

from flosswing.errors import (
    FlosswingError,
    InvalidAttackClassError,
    ReconAlreadyRecordedError,
)
from flosswing.state import session as st_session
from flosswing.state.models import Finding, HuntTask, ReconArtifact, Run
from flosswing.tools.findings import (
    AddHuntTaskInput,
    RecordFindingInput,
    RecordReconArtifactInput,
    add_hunt_task,
    record_finding,
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


# -----------------------------------------------------------------------------
# record_finding cases (v0.3) — per docs/specs/2026-06-02-v0.3-hunt-plumbing-design.md
# § Testing strategy.
# -----------------------------------------------------------------------------


@pytest.fixture()
def fresh_db_with_task(
    fresh_db: str, tmp_path: Path
) -> Iterator[tuple[str, str, Path]]:
    """Reuse fresh_db; seed one hunt_task and return (run_id, task_id, repo_root)."""
    repo_root = tmp_path / "repo"
    (repo_root / "src").mkdir(parents=True)
    (repo_root / "src" / "exec.py").write_text(
        "def run(name):\n    return name\n",
        encoding="utf-8",
    )
    out = add_hunt_task(
        AddHuntTaskInput(
            attack_class="command_injection",
            scope_hint="src/exec.py",
            rationale="user input flows to shell",
        ),
        run_id=fresh_db,
        source="recon",
        budget_total=20,
    )
    assert out.accepted
    yield fresh_db, out.task_id, repo_root


def _base_input(file: str = "src/exec.py") -> RecordFindingInput:
    return RecordFindingInput(
        attack_class="command_injection",
        file=file,
        function="run",
        line_start=3,
        line_end=3,
        severity="high",
        confidence="likely",
        title="user-controlled string flows to shell sink",
        description=(
            "The `name` parameter reaches the shell-invoking subprocess API "
            "without escaping; a caller can inject arbitrary commands."
        ),
        poc_code="run('; touch /tmp/pwn ;')",
        suggested_fix="Pass argv list instead of building a shell string.",
    )


def test_record_finding_happy_path_likely(
    fresh_db_with_task: tuple[str, str, Path],
) -> None:
    run_id, task_id, repo_root = fresh_db_with_task
    out = record_finding(_base_input(), run_id=run_id, hunt_task_id=task_id, repo_root=repo_root)
    assert out.finding_id
    assert out.duplicate_of is None
    with st_session.session_scope() as s:
        rows = s.query(Finding).all()
        assert len(rows) == 1
        assert rows[0].confidence == "likely"
        assert rows[0].hunt_task_id == task_id
        assert rows[0].status == "pending_validation"


def test_record_finding_happy_path_speculative(
    fresh_db_with_task: tuple[str, str, Path],
) -> None:
    run_id, task_id, repo_root = fresh_db_with_task
    inp = _base_input().model_copy(update={"confidence": "speculative"})
    out = record_finding(inp, run_id=run_id, hunt_task_id=task_id, repo_root=repo_root)
    assert out.finding_id
    with st_session.session_scope() as s:
        assert s.query(Finding).count() == 1


def test_record_finding_invalid_attack_class(
    fresh_db_with_task: tuple[str, str, Path],
) -> None:
    run_id, task_id, repo_root = fresh_db_with_task
    inp = _base_input().model_copy(update={"attack_class": "not_a_real_class"})
    with pytest.raises(InvalidAttackClassError):
        record_finding(inp, run_id=run_id, hunt_task_id=task_id, repo_root=repo_root)


def test_record_finding_path_not_in_repo(
    fresh_db_with_task: tuple[str, str, Path],
) -> None:
    run_id, task_id, repo_root = fresh_db_with_task
    inp = _base_input().model_copy(update={"file": "../escape.py"})
    with pytest.raises(FlosswingError) as exc:
        record_finding(inp, run_id=run_id, hunt_task_id=task_id, repo_root=repo_root)
    assert exc.value.code == "path_not_in_repo"


def test_record_finding_line_range_invalid_start_zero(
    fresh_db_with_task: tuple[str, str, Path],
) -> None:
    run_id, task_id, repo_root = fresh_db_with_task
    inp = _base_input().model_copy(update={"line_start": 0, "line_end": 1})
    with pytest.raises(FlosswingError) as exc:
        record_finding(inp, run_id=run_id, hunt_task_id=task_id, repo_root=repo_root)
    assert exc.value.code == "line_range_invalid"


def test_record_finding_line_range_invalid_end_before_start(
    fresh_db_with_task: tuple[str, str, Path],
) -> None:
    run_id, task_id, repo_root = fresh_db_with_task
    inp = _base_input().model_copy(update={"line_start": 10, "line_end": 5})
    with pytest.raises(FlosswingError) as exc:
        record_finding(inp, run_id=run_id, hunt_task_id=task_id, repo_root=repo_root)
    assert exc.value.code == "line_range_invalid"


def test_record_finding_confirmed_without_evidence_raises(
    fresh_db_with_task: tuple[str, str, Path],
) -> None:
    run_id, task_id, repo_root = fresh_db_with_task
    inp = _base_input().model_copy(
        update={
            "confidence": "confirmed",
            "description": "",
            "poc_code": None,
        }
    )
    with pytest.raises(FlosswingError) as exc:
        record_finding(inp, run_id=run_id, hunt_task_id=task_id, repo_root=repo_root)
    assert exc.value.code == "description_required_for_confirmed"


def test_record_finding_increments_hunt_task_findings_count(
    fresh_db_with_task: tuple[str, str, Path],
) -> None:
    run_id, task_id, repo_root = fresh_db_with_task
    for i in range(3):
        inp = _base_input().model_copy(update={"title": f"finding {i}"})
        record_finding(inp, run_id=run_id, hunt_task_id=task_id, repo_root=repo_root)
    with st_session.session_scope() as s:
        task = s.get(HuntTask, task_id)
        assert task is not None
        assert task.findings_count == 3


def test_record_finding_description_too_large(
    fresh_db_with_task: tuple[str, str, Path],
) -> None:
    run_id, task_id, repo_root = fresh_db_with_task
    big = "x" * (65 * 1024)
    inp = _base_input().model_copy(update={"description": big})
    with pytest.raises(FlosswingError) as exc:
        record_finding(inp, run_id=run_id, hunt_task_id=task_id, repo_root=repo_root)
    assert exc.value.code == "description_too_large"


def test_record_finding_suggested_fix_too_large(
    fresh_db_with_task: tuple[str, str, Path],
) -> None:
    run_id, task_id, repo_root = fresh_db_with_task
    big = "y" * (65 * 1024)
    inp = _base_input().model_copy(update={"suggested_fix": big})
    with pytest.raises(FlosswingError) as exc:
        record_finding(inp, run_id=run_id, hunt_task_id=task_id, repo_root=repo_root)
    assert exc.value.code == "suggested_fix_too_large"
