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
    input_tokens_total: int = 0,
    output_tokens_total: int = 0,
) -> HuntStageResult:
    return HuntStageResult(
        tasks_processed=processed,
        tasks_succeeded=succeeded,
        tasks_refused=refused,
        tasks_budget_exceeded=budget,
        tasks_errored=errored,
        findings_total=findings,
        input_tokens_total=input_tokens_total,
        output_tokens_total=output_tokens_total,
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


def test_budget_used_aggregates_recon_and_hunt_tokens(
    fresh_db: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """runs.budget_used must include Hunt tokens (regression for PR #5 review).

    Before the fix, budget_used only summed Recon's input + output tokens,
    silently undercounting every scan that completed Hunt.
    """
    from flosswing import orchestrator
    from flosswing.stages import hunt as hunt_stage
    from flosswing.stages import recon as recon_stage

    async def fake_recon(**kwargs: object) -> RunReconResult:
        return _recon()  # input=1000, output=200

    async def fake_hunt(**kwargs: object) -> HuntStageResult:
        return _hunt(
            processed=2,
            succeeded=2,
            input_tokens_total=5000,
            output_tokens_total=400,
        )

    monkeypatch.setattr(recon_stage, "run", fake_recon)
    monkeypatch.setattr(hunt_stage, "run", fake_hunt)

    asyncio.run(orchestrator.run_scan(_cfg(tmp_path)))

    with st_session.session_scope() as s:
        runs = s.query(Run).all()
        assert len(runs) == 1
        # 1000 + 200 (recon) + 5000 + 400 (hunt) = 6600
        assert runs[0].budget_used == 6600


# ---------------------------------------------------------------------------
# v0.5 IndexBuild wiring — orchestrator must call stages.index_build.run
# between Recon and Hunt when Recon completes with a recorded artifact and
# >=1 queued task. Empty index (symbols == 0) finalizes the run as `errored`
# and Hunt does NOT start. Per
# docs/specs/2026-06-02-v0.5-symbol-index-design.md § IndexBuild placement.
# ---------------------------------------------------------------------------


def _recon_with_index(
    *,
    artifact_id: str = "01ARTIFACT",
    languages: set[str] | None = None,
) -> RunReconResult:
    """Recon result shaped for v0.5: carries artifact_id + languages."""
    return RunReconResult(
        outcome="completed",
        recon_artifact_recorded=True,
        hunt_tasks_queued=1,
        agent_session_id="x",
        input_tokens=0,
        output_tokens=0,
        cost_usd=0.0,
        refusal_text=None,
        error_text=None,
        recon_artifact_id=artifact_id,
        languages=languages if languages is not None else {"python"},
    )


def test_orchestrator_runs_index_build_between_recon_and_hunt(
    fresh_db: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """IndexBuild must run after Recon and before Hunt when artifact_id set."""
    from flosswing import orchestrator
    from flosswing.index.build import IndexBuildResult
    from flosswing.stages import hunt as hunt_stage
    from flosswing.stages import index_build as index_build_stage
    from flosswing.stages import recon as recon_stage

    call_order: list[str] = []

    async def fake_recon(**kwargs: object) -> RunReconResult:
        call_order.append("recon")
        return _recon_with_index()

    async def fake_index_build(**kwargs: object) -> IndexBuildResult:
        call_order.append("index_build")
        return IndexBuildResult(
            symbols=4,
            call_sites=2,
            entry_points=1,
            files_parsed=1,
            files_skipped=0,
            duration_ms=10,
            languages=["python"],
        )

    async def fake_hunt(**kwargs: object) -> HuntStageResult:
        call_order.append("hunt")
        return _hunt(processed=1, succeeded=1, findings=1)

    monkeypatch.setattr(recon_stage, "run", fake_recon)
    monkeypatch.setattr(index_build_stage, "run", fake_index_build)
    monkeypatch.setattr(hunt_stage, "run", fake_hunt)

    result = asyncio.run(orchestrator.run_scan(_cfg(tmp_path)))
    assert call_order == ["recon", "index_build", "hunt"]
    assert result.exit_code == 0
    # Summary surfaces the index block (per the spec § Component
    # responsibilities orchestrator.run_scan extension).
    assert "index:" in result.summary
    assert "symbols:" in result.summary


def test_orchestrator_finalizes_errored_on_empty_index(
    fresh_db: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """symbols == 0 finalizes the run as errored; Hunt must NOT start."""
    from flosswing import orchestrator
    from flosswing.index.build import IndexBuildResult
    from flosswing.stages import hunt as hunt_stage
    from flosswing.stages import index_build as index_build_stage
    from flosswing.stages import recon as recon_stage

    hunt_called = False

    async def fake_recon(**kwargs: object) -> RunReconResult:
        return _recon_with_index()

    async def fake_index_build(**kwargs: object) -> IndexBuildResult:
        return IndexBuildResult(
            symbols=0,
            call_sites=0,
            entry_points=0,
            files_parsed=0,
            files_skipped=0,
            duration_ms=5,
            languages=["python"],
        )

    async def fake_hunt(**kwargs: object) -> HuntStageResult:
        nonlocal hunt_called
        hunt_called = True
        return _hunt()

    monkeypatch.setattr(recon_stage, "run", fake_recon)
    monkeypatch.setattr(index_build_stage, "run", fake_index_build)
    monkeypatch.setattr(hunt_stage, "run", fake_hunt)

    result = asyncio.run(orchestrator.run_scan(_cfg(tmp_path)))
    assert result.exit_code == 1
    assert hunt_called is False, "Hunt must NOT start when index empty"
    assert "index_build_empty" in result.summary
    with st_session.session_scope() as s:
        assert s.query(Run).all()[0].status == "errored"


def test_orchestrator_skips_index_build_when_recon_artifact_id_missing(
    fresh_db: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If Recon recorded no artifact_id, IndexBuild is skipped entirely.

    The pre-IndexBuild short-circuit paths (recon errored, zero tasks)
    must not invoke the stage and must not crash the summary's index
    block (which uses `index_result is None` to print zeros).
    """
    from flosswing import orchestrator
    from flosswing.index.build import IndexBuildResult
    from flosswing.stages import hunt as hunt_stage
    from flosswing.stages import index_build as index_build_stage
    from flosswing.stages import recon as recon_stage

    index_called = False

    async def fake_recon(**kwargs: object) -> RunReconResult:
        return _recon(outcome="errored", artifact=False, tasks_queued=0)

    async def fake_index_build(**kwargs: object) -> IndexBuildResult:
        nonlocal index_called
        index_called = True
        return IndexBuildResult()

    async def fake_hunt(**kwargs: object) -> HuntStageResult:
        return _hunt()

    monkeypatch.setattr(recon_stage, "run", fake_recon)
    monkeypatch.setattr(index_build_stage, "run", fake_index_build)
    monkeypatch.setattr(hunt_stage, "run", fake_hunt)

    result = asyncio.run(orchestrator.run_scan(_cfg(tmp_path)))
    assert index_called is False
    assert result.exit_code == 1
    # Summary should still render the index block with zeros.
    assert "index:" in result.summary
    assert "symbols:           0" in result.summary
