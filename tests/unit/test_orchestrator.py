"""orchestrator.run_scan: Recon -> Hunt wiring and finalization.

Stubs stages/recon.run and stages/hunt.run with canned results;
asserts the runs row finalization rules and exit codes per
docs/specs/2026-06-02-v0.3-hunt-plumbing-design.md § Component
responsibilities orchestrator.run_scan extension.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from pathlib import Path

import pytest

from flosswing.config import Config
from flosswing.stages.hunt import HuntStageResult
from flosswing.stages.recon import RunReconResult
from flosswing.state import session as st_session
from flosswing.state.models import Run


@pytest.fixture()
def fresh_db(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("FLOSSWING_DB_URL", "sqlite:///:memory:")
    st_session._cached_engine = None  # type: ignore[attr-defined]
    st_session._cached_session_factory = None  # type: ignore[attr-defined]
    yield
    st_session._cached_engine = None  # type: ignore[attr-defined]
    st_session._cached_session_factory = None  # type: ignore[attr-defined]


def _cfg(tmp_path: Path) -> Config:
    return Config(
        repo_root=tmp_path,
        model="claude-opus-4-7",
        recon_token_budget=200_000,
        hunt_token_budget=200_000,
        auth_env={"ANTHROPIC_API_KEY": "sk-test"},
    )


def _recon(
    *,
    outcome: str = "completed",
    artifact: bool = True,
    tasks_queued: int = 2,
) -> RunReconResult:
    return RunReconResult(
        outcome=outcome,
        recon_artifact_recorded=artifact,
        hunt_tasks_queued=tasks_queued,
        agent_session_id="x",
        input_tokens=1000,
        output_tokens=200,
        cost_usd=0.01,
        refusal_text=None,
        error_text=None,
    )


def _hunt(
    *,
    processed: int = 2,
    succeeded: int = 2,
    refused: int = 0,
    budget: int = 0,
    errored: int = 0,
    findings: int = 1,
) -> HuntStageResult:
    return HuntStageResult(
        tasks_processed=processed,
        tasks_succeeded=succeeded,
        tasks_refused=refused,
        tasks_budget_exceeded=budget,
        tasks_errored=errored,
        findings_total=findings,
    )


def test_recon_errored_short_circuits_no_hunt(
    fresh_db: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from flosswing import orchestrator
    from flosswing.stages import hunt as hunt_stage
    from flosswing.stages import recon as recon_stage

    hunt_called = False

    async def fake_recon(**kwargs: object) -> RunReconResult:
        return _recon(outcome="errored", artifact=False, tasks_queued=0)

    async def fake_hunt(**kwargs: object) -> HuntStageResult:
        nonlocal hunt_called
        hunt_called = True
        return _hunt()

    monkeypatch.setattr(recon_stage, "run", fake_recon)
    monkeypatch.setattr(hunt_stage, "run", fake_hunt)

    result = asyncio.run(orchestrator.run_scan(_cfg(tmp_path)))
    assert result.exit_code == 1
    assert hunt_called is False
    with st_session.session_scope() as s:
        runs = s.query(Run).all()
        assert len(runs) == 1
        assert runs[0].status == "errored"


def test_recon_completed_zero_tasks_queued_short_circuits(
    fresh_db: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from flosswing import orchestrator
    from flosswing.stages import hunt as hunt_stage
    from flosswing.stages import recon as recon_stage

    hunt_called = False

    async def fake_recon(**kwargs: object) -> RunReconResult:
        return _recon(outcome="completed", artifact=True, tasks_queued=0)

    async def fake_hunt(**kwargs: object) -> HuntStageResult:
        nonlocal hunt_called
        hunt_called = True
        return _hunt()

    monkeypatch.setattr(recon_stage, "run", fake_recon)
    monkeypatch.setattr(hunt_stage, "run", fake_hunt)

    result = asyncio.run(orchestrator.run_scan(_cfg(tmp_path)))
    assert result.exit_code == 1
    assert hunt_called is False
    with st_session.session_scope() as s:
        assert s.query(Run).all()[0].status == "errored"


def test_hunt_runs_when_recon_queued_tasks(
    fresh_db: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from flosswing import orchestrator
    from flosswing.stages import hunt as hunt_stage
    from flosswing.stages import recon as recon_stage

    hunt_called = False

    async def fake_recon(**kwargs: object) -> RunReconResult:
        return _recon()

    async def fake_hunt(**kwargs: object) -> HuntStageResult:
        nonlocal hunt_called
        hunt_called = True
        return _hunt(processed=2, succeeded=2, findings=3)

    monkeypatch.setattr(recon_stage, "run", fake_recon)
    monkeypatch.setattr(hunt_stage, "run", fake_hunt)

    result = asyncio.run(orchestrator.run_scan(_cfg(tmp_path)))
    assert hunt_called is True
    assert result.exit_code == 0
    with st_session.session_scope() as s:
        assert s.query(Run).all()[0].status == "completed"


def test_hunt_all_tasks_failed_means_run_errored(
    fresh_db: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from flosswing import orchestrator
    from flosswing.stages import hunt as hunt_stage
    from flosswing.stages import recon as recon_stage

    async def fake_recon(**kwargs: object) -> RunReconResult:
        return _recon()

    async def fake_hunt(**kwargs: object) -> HuntStageResult:
        return _hunt(processed=2, succeeded=0, refused=1, errored=1, findings=0)

    monkeypatch.setattr(recon_stage, "run", fake_recon)
    monkeypatch.setattr(hunt_stage, "run", fake_hunt)

    result = asyncio.run(orchestrator.run_scan(_cfg(tmp_path)))
    assert result.exit_code == 1
    with st_session.session_scope() as s:
        assert s.query(Run).all()[0].status == "errored"


def test_summary_contains_per_task_outcomes(
    fresh_db: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from flosswing import orchestrator
    from flosswing.stages import hunt as hunt_stage
    from flosswing.stages import recon as recon_stage

    async def fake_recon(**kwargs: object) -> RunReconResult:
        return _recon()

    async def fake_hunt(**kwargs: object) -> HuntStageResult:
        return _hunt(processed=2, succeeded=1, refused=1, findings=1)

    monkeypatch.setattr(recon_stage, "run", fake_recon)
    monkeypatch.setattr(hunt_stage, "run", fake_hunt)

    result = asyncio.run(orchestrator.run_scan(_cfg(tmp_path)))
    # Per spec § Success criteria #3: summary mentions Hunt and findings.
    s = result.summary.lower()
    assert "hunt" in s
    assert "findings" in s
    # exit_code 0 because at least one task succeeded.
    assert result.exit_code == 0
