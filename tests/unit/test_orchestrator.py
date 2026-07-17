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
from typing import Literal

import pytest

from flosswing.config import Config
from flosswing.stages.gapfill import GapfillStageResult
from flosswing.stages.hunt import HuntStageResult
from flosswing.stages.recon import RunReconResult
from flosswing.stages.validate import ValidateStageResult
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
        validate_token_budget=200_000,
        gapfill_token_budget=1_000_000,
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
    from flosswing.stages import gapfill as gapfill_stage
    from flosswing.stages import hunt as hunt_stage
    from flosswing.stages import recon as recon_stage
    from flosswing.stages import validate as validate_stage

    hunt_called = False

    async def fake_recon(**kwargs: object) -> RunReconResult:
        return _recon()

    async def fake_hunt(**kwargs: object) -> HuntStageResult:
        nonlocal hunt_called
        hunt_called = True
        return _hunt(processed=2, succeeded=2, findings=3)

    async def fake_validate(**kwargs: object) -> ValidateStageResult:
        return _validate(processed=3, confirmed=3)

    async def fake_gapfill(**kwargs: object) -> GapfillStageResult:
        return _gapfill()

    monkeypatch.setattr(recon_stage, "run", fake_recon)
    monkeypatch.setattr(hunt_stage, "run", fake_hunt)
    monkeypatch.setattr(validate_stage, "run", fake_validate)
    monkeypatch.setattr(gapfill_stage, "run", fake_gapfill)

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
    from flosswing.stages import gapfill as gapfill_stage
    from flosswing.stages import hunt as hunt_stage
    from flosswing.stages import recon as recon_stage
    from flosswing.stages import validate as validate_stage

    async def fake_recon(**kwargs: object) -> RunReconResult:
        return _recon()

    async def fake_hunt(**kwargs: object) -> HuntStageResult:
        return _hunt(processed=2, succeeded=1, refused=1, findings=1)

    async def fake_validate(**kwargs: object) -> ValidateStageResult:
        return _validate(processed=1, confirmed=1)

    async def fake_gapfill(**kwargs: object) -> GapfillStageResult:
        return _gapfill()

    monkeypatch.setattr(recon_stage, "run", fake_recon)
    monkeypatch.setattr(hunt_stage, "run", fake_hunt)
    monkeypatch.setattr(validate_stage, "run", fake_validate)
    monkeypatch.setattr(gapfill_stage, "run", fake_gapfill)

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
    from flosswing.stages import gapfill as gapfill_stage
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

    async def fake_gapfill(**kwargs: object) -> GapfillStageResult:
        return _gapfill()

    monkeypatch.setattr(recon_stage, "run", fake_recon)
    monkeypatch.setattr(hunt_stage, "run", fake_hunt)
    monkeypatch.setattr(gapfill_stage, "run", fake_gapfill)

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
    from flosswing.stages import gapfill as gapfill_stage
    from flosswing.stages import hunt as hunt_stage
    from flosswing.stages import index_build as index_build_stage
    from flosswing.stages import recon as recon_stage
    from flosswing.stages import validate as validate_stage

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

    async def fake_validate(**kwargs: object) -> ValidateStageResult:
        call_order.append("validate")
        return _validate(processed=1, confirmed=1)

    async def fake_gapfill(**kwargs: object) -> GapfillStageResult:
        call_order.append("gapfill")
        return _gapfill()

    monkeypatch.setattr(recon_stage, "run", fake_recon)
    monkeypatch.setattr(index_build_stage, "run", fake_index_build)
    monkeypatch.setattr(hunt_stage, "run", fake_hunt)
    monkeypatch.setattr(validate_stage, "run", fake_validate)
    monkeypatch.setattr(gapfill_stage, "run", fake_gapfill)

    result = asyncio.run(orchestrator.run_scan(_cfg(tmp_path)))
    assert call_order == ["recon", "index_build", "hunt", "validate", "gapfill"]
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


# ---------------------------------------------------------------------------
# v0.6 Validate wiring — orchestrator must call stages.validate.run after
# Hunt when hunt_result.findings_total >= 1 (decision #6: even on partial
# Hunt failures, as long as >=1 finding landed). Per
# docs/specs/2026-06-02-v0.6-validate-design.md § orchestrator.run_scan
# extension.
# ---------------------------------------------------------------------------


def _validate(
    *,
    processed: int = 0,
    confirmed: int = 0,
    rejected: int = 0,
    uncertain: int = 0,
    refused: int = 0,
    budget: int = 0,
    errored: int = 0,
    no_verdict: int = 0,
    input_tokens_total: int = 0,
    output_tokens_total: int = 0,
) -> ValidateStageResult:
    return ValidateStageResult(
        findings_processed=processed,
        findings_confirmed=confirmed,
        findings_rejected=rejected,
        findings_uncertain=uncertain,
        findings_refused=refused,
        findings_budget_exceeded=budget,
        findings_errored=errored,
        findings_no_verdict=no_verdict,
        input_tokens_total=input_tokens_total,
        output_tokens_total=output_tokens_total,
    )


def test_orchestrator_runs_validate_when_hunt_produces_findings(
    fresh_db: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Per docs/specs/2026-06-02-v0.6-validate-design.md § orchestrator.run_scan extension."""
    from flosswing import orchestrator
    from flosswing.index.build import IndexBuildResult
    from flosswing.stages import gapfill as gapfill_stage
    from flosswing.stages import hunt as hunt_stage
    from flosswing.stages import index_build as index_build_stage
    from flosswing.stages import recon as recon_stage
    from flosswing.stages import validate as validate_stage

    validate_called = False

    async def fake_recon(**kwargs: object) -> RunReconResult:
        return _recon_with_index()

    async def fake_index_build(**kwargs: object) -> IndexBuildResult:
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
        return _hunt(
            processed=1,
            succeeded=1,
            findings=2,
            input_tokens_total=100,
            output_tokens_total=50,
        )

    async def fake_validate(**kwargs: object) -> ValidateStageResult:
        nonlocal validate_called
        validate_called = True
        return _validate(
            processed=2,
            confirmed=2,
            input_tokens_total=200,
            output_tokens_total=100,
        )

    async def fake_gapfill(**kwargs: object) -> GapfillStageResult:
        return _gapfill()

    monkeypatch.setattr(recon_stage, "run", fake_recon)
    monkeypatch.setattr(index_build_stage, "run", fake_index_build)
    monkeypatch.setattr(hunt_stage, "run", fake_hunt)
    monkeypatch.setattr(validate_stage, "run", fake_validate)
    monkeypatch.setattr(gapfill_stage, "run", fake_gapfill)

    result = asyncio.run(orchestrator.run_scan(_cfg(tmp_path)))
    assert validate_called is True, (
        "Validate must run when Hunt produces >=1 finding"
    )
    assert result.exit_code == 0
    assert "validate:" in result.summary
    assert "confirmed:" in result.summary
    with st_session.session_scope() as s:
        runs = s.query(Run).all()
        assert len(runs) == 1
        assert runs[0].status == "completed"
        # budget_used includes Validate tokens.
        # recon (0+0) + hunt (100+50) + validate (200+100) = 450
        assert runs[0].budget_used == 450


def test_orchestrator_skips_validate_when_hunt_produces_no_findings(
    fresh_db: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Hunt produced 0 findings -> Validate skipped, run completed."""
    from flosswing import orchestrator
    from flosswing.index.build import IndexBuildResult
    from flosswing.stages import gapfill as gapfill_stage
    from flosswing.stages import hunt as hunt_stage
    from flosswing.stages import index_build as index_build_stage
    from flosswing.stages import recon as recon_stage
    from flosswing.stages import validate as validate_stage

    validate_called = False

    async def fake_recon(**kwargs: object) -> RunReconResult:
        return _recon_with_index()

    async def fake_index_build(**kwargs: object) -> IndexBuildResult:
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
        return _hunt(processed=1, succeeded=1, findings=0)

    async def fake_validate(**kwargs: object) -> ValidateStageResult:
        nonlocal validate_called
        validate_called = True
        return _validate()

    async def fake_gapfill(**kwargs: object) -> GapfillStageResult:
        return _gapfill()

    monkeypatch.setattr(recon_stage, "run", fake_recon)
    monkeypatch.setattr(index_build_stage, "run", fake_index_build)
    monkeypatch.setattr(hunt_stage, "run", fake_hunt)
    monkeypatch.setattr(validate_stage, "run", fake_validate)
    monkeypatch.setattr(gapfill_stage, "run", fake_gapfill)

    result = asyncio.run(orchestrator.run_scan(_cfg(tmp_path)))
    assert validate_called is False, (
        "Validate must NOT run when Hunt produced 0 findings"
    )
    # Per spec § orchestrator.run_scan extension: 0 findings -> completed.
    assert result.exit_code == 0
    with st_session.session_scope() as s:
        assert s.query(Run).all()[0].status == "completed"


def test_orchestrator_errored_when_all_validate_sessions_non_terminal(
    fresh_db: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Hunt produced >=1 findings AND every Validate session was
    non-terminal -> errored, exit 1. Per spec § Component
    responsibilities."""
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
            symbols=4,
            call_sites=2,
            entry_points=1,
            files_parsed=1,
            files_skipped=0,
            duration_ms=10,
            languages=["python"],
        )

    async def fake_hunt(**kwargs: object) -> HuntStageResult:
        return _hunt(processed=1, succeeded=1, findings=2)

    async def fake_validate(**kwargs: object) -> ValidateStageResult:
        # All Validate sessions non-terminal: 2 refused, 0 terminal.
        return _validate(processed=2, refused=2)

    async def fake_gapfill(**kwargs: object) -> GapfillStageResult:
        return _gapfill()

    monkeypatch.setattr(recon_stage, "run", fake_recon)
    monkeypatch.setattr(index_build_stage, "run", fake_index_build)
    monkeypatch.setattr(hunt_stage, "run", fake_hunt)
    monkeypatch.setattr(validate_stage, "run", fake_validate)
    monkeypatch.setattr(gapfill_stage, "run", fake_gapfill)

    result = asyncio.run(orchestrator.run_scan(_cfg(tmp_path)))
    assert result.exit_code == 1
    with st_session.session_scope() as s:
        assert s.query(Run).all()[0].status == "errored"


def test_orchestrator_uncertain_counts_as_terminal_verdict(
    fresh_db: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Per plan-time decision #4: UNCERTAIN verdicts count as terminal,
    so the run still finalizes as `completed`."""
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
            symbols=4,
            call_sites=2,
            entry_points=1,
            files_parsed=1,
            files_skipped=0,
            duration_ms=10,
            languages=["python"],
        )

    async def fake_hunt(**kwargs: object) -> HuntStageResult:
        return _hunt(processed=1, succeeded=1, findings=1)

    async def fake_validate(**kwargs: object) -> ValidateStageResult:
        return _validate(processed=1, uncertain=1)

    async def fake_gapfill(**kwargs: object) -> GapfillStageResult:
        return _gapfill()

    monkeypatch.setattr(recon_stage, "run", fake_recon)
    monkeypatch.setattr(index_build_stage, "run", fake_index_build)
    monkeypatch.setattr(hunt_stage, "run", fake_hunt)
    monkeypatch.setattr(validate_stage, "run", fake_validate)
    monkeypatch.setattr(gapfill_stage, "run", fake_gapfill)

    result = asyncio.run(orchestrator.run_scan(_cfg(tmp_path)))
    # uncertain is a terminal verdict per decision #4.
    assert result.exit_code == 0
    with st_session.session_scope() as s:
        assert s.query(Run).all()[0].status == "completed"


# ---------------------------------------------------------------------------
# v0.7 Gapfill wiring — orchestrator must call stages.gapfill.run after
# Validate when hunt_result.tasks_succeeded >= 1 (per design decision #5:
# gate is tasks_succeeded, NOT findings_total, since zero-finding runs are
# precisely when Gapfill is most useful). Gapfill failure is NOT run-fatal —
# only Recon / Hunt / IndexBuild / Validate outcomes drive run.status. Per
# docs/specs/2026-06-02-v0.7-gapfill-design.md § orchestrator.run_scan
# extension and § Architecture.
# ---------------------------------------------------------------------------


_GapfillOutcome = Literal[
    "completed", "refused", "budget_exceeded", "errored", "skipped"
]


def _gapfill(
    *,
    outcome: _GapfillOutcome = "completed",
    tasks_queued: int = 0,
    cap: int = 1,
    input_tokens: int = 0,
    output_tokens: int = 0,
) -> GapfillStageResult:
    return GapfillStageResult(
        outcome=outcome,
        tasks_queued=tasks_queued,
        cap=cap,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
    )


def test_orchestrator_runs_gapfill_when_hunt_tasks_succeeded(
    fresh_db: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Per docs/specs/2026-06-02-v0.7-gapfill-design.md § orchestrator extension."""
    from flosswing import orchestrator
    from flosswing.index.build import IndexBuildResult
    from flosswing.stages import gapfill as gapfill_stage
    from flosswing.stages import hunt as hunt_stage
    from flosswing.stages import index_build as index_build_stage
    from flosswing.stages import recon as recon_stage
    from flosswing.stages import validate as validate_stage

    gapfill_called = False

    async def fake_recon(**kwargs: object) -> RunReconResult:
        return _recon_with_index()

    async def fake_index_build(**kwargs: object) -> IndexBuildResult:
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
        return _hunt(
            processed=1,
            succeeded=1,
            findings=2,
            input_tokens_total=100,
            output_tokens_total=50,
        )

    async def fake_validate(**kwargs: object) -> ValidateStageResult:
        return _validate(
            processed=2,
            confirmed=2,
            input_tokens_total=200,
            output_tokens_total=100,
        )

    async def fake_gapfill(**kwargs: object) -> GapfillStageResult:
        nonlocal gapfill_called
        gapfill_called = True
        return _gapfill(
            outcome="completed",
            tasks_queued=1,
            cap=1,
            input_tokens=300,
            output_tokens=80,
        )

    monkeypatch.setattr(recon_stage, "run", fake_recon)
    monkeypatch.setattr(index_build_stage, "run", fake_index_build)
    monkeypatch.setattr(hunt_stage, "run", fake_hunt)
    monkeypatch.setattr(validate_stage, "run", fake_validate)
    monkeypatch.setattr(gapfill_stage, "run", fake_gapfill)

    result = asyncio.run(orchestrator.run_scan(_cfg(tmp_path)))
    assert gapfill_called is True
    assert result.exit_code == 0
    assert "gapfill:" in result.summary
    # Summary surfaces outcome + tasks queued.
    assert "completed" in result.summary
    assert "tasks queued" in result.summary or "tasks_queued" in result.summary


def test_orchestrator_runs_gapfill_even_with_zero_findings(
    fresh_db: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Per design decision #5: gate on hunt_result.tasks_succeeded >= 1,
    NOT on findings_total. Zero-finding runs are exactly when Gapfill is
    most useful — propose new investigations that might surface what the
    initial Hunt missed."""
    from flosswing import orchestrator
    from flosswing.index.build import IndexBuildResult
    from flosswing.stages import gapfill as gapfill_stage
    from flosswing.stages import hunt as hunt_stage
    from flosswing.stages import index_build as index_build_stage
    from flosswing.stages import recon as recon_stage
    from flosswing.stages import validate as validate_stage

    validate_called = False
    gapfill_called = False

    async def fake_recon(**kwargs: object) -> RunReconResult:
        return _recon_with_index()

    async def fake_index_build(**kwargs: object) -> IndexBuildResult:
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
        # Hunt succeeded but produced ZERO findings.
        return _hunt(
            processed=1,
            succeeded=1,
            findings=0,
            input_tokens_total=80,
            output_tokens_total=40,
        )

    async def fake_validate(**kwargs: object) -> ValidateStageResult:
        nonlocal validate_called
        validate_called = True
        return _validate()

    async def fake_gapfill(**kwargs: object) -> GapfillStageResult:
        nonlocal gapfill_called
        gapfill_called = True
        return _gapfill(
            outcome="completed",
            tasks_queued=0,
            cap=1,
            input_tokens=200,
            output_tokens=20,
        )

    monkeypatch.setattr(recon_stage, "run", fake_recon)
    monkeypatch.setattr(index_build_stage, "run", fake_index_build)
    monkeypatch.setattr(hunt_stage, "run", fake_hunt)
    monkeypatch.setattr(validate_stage, "run", fake_validate)
    monkeypatch.setattr(gapfill_stage, "run", fake_gapfill)

    result = asyncio.run(orchestrator.run_scan(_cfg(tmp_path)))
    # Validate is skipped (0 findings); Gapfill runs anyway.
    assert validate_called is False
    assert gapfill_called is True
    # Run completes because Hunt had >=1 task succeed; Gapfill's
    # zero-tasks_queued outcome is logged but doesn't error the run.
    assert result.exit_code == 0
    with st_session.session_scope() as s:
        assert s.query(Run).all()[0].status == "completed"


def test_orchestrator_skips_gapfill_when_hunt_zero_succeeded(
    fresh_db: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Per design decision #5 the gate is hunt_result.tasks_succeeded >= 1.
    Zero successes -> Gapfill skipped, run errored on the Hunt branch."""
    from flosswing import orchestrator
    from flosswing.index.build import IndexBuildResult
    from flosswing.stages import gapfill as gapfill_stage
    from flosswing.stages import hunt as hunt_stage
    from flosswing.stages import index_build as index_build_stage
    from flosswing.stages import recon as recon_stage

    gapfill_called = False

    async def fake_recon(**kwargs: object) -> RunReconResult:
        return _recon_with_index()

    async def fake_index_build(**kwargs: object) -> IndexBuildResult:
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
        return _hunt(
            processed=1,
            succeeded=0,
            refused=1,
            findings=0,
            input_tokens_total=80,
            output_tokens_total=40,
        )

    async def fake_gapfill(**kwargs: object) -> GapfillStageResult:
        nonlocal gapfill_called
        gapfill_called = True
        return _gapfill()

    monkeypatch.setattr(recon_stage, "run", fake_recon)
    monkeypatch.setattr(index_build_stage, "run", fake_index_build)
    monkeypatch.setattr(hunt_stage, "run", fake_hunt)
    monkeypatch.setattr(gapfill_stage, "run", fake_gapfill)

    result = asyncio.run(orchestrator.run_scan(_cfg(tmp_path)))
    assert gapfill_called is False
    assert result.exit_code == 1
    with st_session.session_scope() as s:
        assert s.query(Run).all()[0].status == "errored"


def test_orchestrator_gapfill_refusal_does_not_error_run(
    fresh_db: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Per spec § Architecture: Gapfill failure is NOT run-fatal —
    Recon + Hunt produced the primary deliverable. A refused Gapfill
    leaves the run as 'completed' (assuming Validate had a terminal
    verdict)."""
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
            symbols=4,
            call_sites=2,
            entry_points=1,
            files_parsed=1,
            files_skipped=0,
            duration_ms=10,
            languages=["python"],
        )

    async def fake_hunt(**kwargs: object) -> HuntStageResult:
        return _hunt(
            processed=1,
            succeeded=1,
            findings=1,
            input_tokens_total=80,
            output_tokens_total=40,
        )

    async def fake_validate(**kwargs: object) -> ValidateStageResult:
        return _validate(
            processed=1,
            confirmed=1,
            input_tokens_total=200,
            output_tokens_total=100,
        )

    async def fake_gapfill(**kwargs: object) -> GapfillStageResult:
        return _gapfill(
            outcome="refused",
            tasks_queued=0,
            cap=1,
            input_tokens=60,
            output_tokens=10,
        )

    monkeypatch.setattr(recon_stage, "run", fake_recon)
    monkeypatch.setattr(index_build_stage, "run", fake_index_build)
    monkeypatch.setattr(hunt_stage, "run", fake_hunt)
    monkeypatch.setattr(validate_stage, "run", fake_validate)
    monkeypatch.setattr(gapfill_stage, "run", fake_gapfill)

    result = asyncio.run(orchestrator.run_scan(_cfg(tmp_path)))
    # NOT 1 — Gapfill refusal is not run-fatal.
    assert result.exit_code == 0
    with st_session.session_scope() as s:
        assert s.query(Run).all()[0].status == "completed"


def test_orchestrator_summary_includes_gapfill_block(
    fresh_db: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Per spec § Success criteria #3: the printed summary includes a
    gapfill block with outcome, cap, tasks_queued, and tokens."""
    from flosswing import orchestrator
    from flosswing.index.build import IndexBuildResult
    from flosswing.stages import gapfill as gapfill_stage
    from flosswing.stages import hunt as hunt_stage
    from flosswing.stages import index_build as index_build_stage
    from flosswing.stages import recon as recon_stage

    async def fake_recon(**kwargs: object) -> RunReconResult:
        return _recon_with_index()

    async def fake_index_build(**kwargs: object) -> IndexBuildResult:
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
        return _hunt(
            processed=1,
            succeeded=1,
            findings=0,
            input_tokens_total=80,
            output_tokens_total=40,
        )

    async def fake_gapfill(**kwargs: object) -> GapfillStageResult:
        return _gapfill(
            outcome="completed",
            tasks_queued=2,
            cap=2,
            input_tokens=350,
            output_tokens=90,
        )

    monkeypatch.setattr(recon_stage, "run", fake_recon)
    monkeypatch.setattr(index_build_stage, "run", fake_index_build)
    monkeypatch.setattr(hunt_stage, "run", fake_hunt)
    monkeypatch.setattr(gapfill_stage, "run", fake_gapfill)

    result = asyncio.run(orchestrator.run_scan(_cfg(tmp_path)))
    assert "gapfill:" in result.summary
    # outcome / cap / tasks_queued / tokens should each appear.
    for needle in ("completed", " 2", "350", "90"):
        assert needle in result.summary


def test_orchestrator_budget_used_includes_gapfill_tokens(
    fresh_db: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """runs.budget_used must include Gapfill tokens — carryover from
    the PR #11 review pattern. Every per-stage budget is summed."""
    from flosswing import orchestrator
    from flosswing.index.build import IndexBuildResult
    from flosswing.stages import gapfill as gapfill_stage
    from flosswing.stages import hunt as hunt_stage
    from flosswing.stages import index_build as index_build_stage
    from flosswing.stages import recon as recon_stage
    from flosswing.stages import validate as validate_stage

    async def fake_recon(**kwargs: object) -> RunReconResult:
        return _recon_with_index()  # input=0, output=0

    async def fake_index_build(**kwargs: object) -> IndexBuildResult:
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
        return _hunt(
            processed=1,
            succeeded=1,
            findings=1,
            input_tokens_total=100,
            output_tokens_total=50,
        )

    async def fake_validate(**kwargs: object) -> ValidateStageResult:
        return _validate(
            processed=1,
            confirmed=1,
            input_tokens_total=200,
            output_tokens_total=100,
        )

    async def fake_gapfill(**kwargs: object) -> GapfillStageResult:
        return _gapfill(
            outcome="completed",
            tasks_queued=1,
            cap=1,
            input_tokens=300,
            output_tokens=80,
        )

    monkeypatch.setattr(recon_stage, "run", fake_recon)
    monkeypatch.setattr(index_build_stage, "run", fake_index_build)
    monkeypatch.setattr(hunt_stage, "run", fake_hunt)
    monkeypatch.setattr(validate_stage, "run", fake_validate)
    monkeypatch.setattr(gapfill_stage, "run", fake_gapfill)

    asyncio.run(orchestrator.run_scan(_cfg(tmp_path)))
    with st_session.session_scope() as s:
        runs = s.query(Run).all()
        assert len(runs) == 1
        # recon (0+0) + hunt (100+50) + validate (200+100) + gapfill (300+80) = 830
        assert runs[0].budget_used == 830


def test_orchestrator_persists_gapfill_token_budget_in_config_json(
    fresh_db: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Per task spec: _config_for_run_row must include gapfill_token_budget
    in the persisted JSON (carryover from PR #11 review pattern — every
    per-stage budget is persisted)."""
    import json as _json

    from flosswing import orchestrator
    from flosswing.stages import hunt as hunt_stage
    from flosswing.stages import recon as recon_stage

    async def fake_recon(**kwargs: object) -> RunReconResult:
        # Short-circuit so the test doesn't need to mock IndexBuild/Hunt/etc.
        return _recon(outcome="errored", artifact=False, tasks_queued=0)

    async def fake_hunt(**kwargs: object) -> HuntStageResult:
        return _hunt()

    monkeypatch.setattr(recon_stage, "run", fake_recon)
    monkeypatch.setattr(hunt_stage, "run", fake_hunt)

    asyncio.run(orchestrator.run_scan(_cfg(tmp_path)))
    with st_session.session_scope() as s:
        row = s.query(Run).all()[0]
        payload = _json.loads(row.config_json)
        assert "gapfill_token_budget" in payload
        assert payload["gapfill_token_budget"] == 1_000_000


def test_config_for_run_row_persists_provider(tmp_path: Path) -> None:
    """The selected model provider must be recorded in the run's config_json
    audit record. Uses a non-default provider value to prove the serializer
    reads cfg.provider rather than hard-coding 'anthropic'."""
    import json as _json
    from dataclasses import replace

    from flosswing.orchestrator import _config_for_run_row

    cfg = replace(_cfg(tmp_path), provider="bedrock")
    payload = _json.loads(_config_for_run_row(cfg))
    assert payload["provider"] == "bedrock"


def _foundry_cfg(tmp_path: Path, **deployment_env: str) -> Config:
    from dataclasses import replace

    return replace(
        _cfg(tmp_path),
        auth_env={
            "CLAUDE_CODE_USE_FOUNDRY": "1",
            "ANTHROPIC_FOUNDRY_RESOURCE": "res",
            "ANTHROPIC_FOUNDRY_API_KEY": "key",
            **deployment_env,
        },
    )


def test_config_for_run_row_records_foundry_deployment(tmp_path: Path) -> None:
    """Under Foundry mode config_json records the resolved deployment, not the
    tier alias cfg.model carries."""
    import json as _json

    from flosswing.orchestrator import _config_for_run_row

    cfg = _foundry_cfg(tmp_path, ANTHROPIC_DEFAULT_OPUS_MODEL="opus-deploy-1")
    payload = _json.loads(_config_for_run_row(cfg))
    assert payload["foundry_deployment"] == "opus-deploy-1"


def test_config_for_run_row_deployment_none_in_direct_mode(tmp_path: Path) -> None:
    import json as _json

    from flosswing.orchestrator import _config_for_run_row

    payload = _json.loads(_config_for_run_row(_cfg(tmp_path)))
    assert payload["foundry_deployment"] is None


def test_foundry_deployment_empty_var_stays_none(tmp_path: Path) -> None:
    """A present-but-empty deployment var normalises to None so the banner
    (orchestrator) and report header agree on suppressing it — the empty-string
    inconsistency guard."""
    from flosswing.orchestrator import _foundry_deployment

    cfg = _foundry_cfg(tmp_path, ANTHROPIC_DEFAULT_OPUS_MODEL="")
    assert _foundry_deployment(cfg) is None


def _stub_completed_pipeline(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stub the stages so run_scan reaches a normal 'completed' finalization."""
    from flosswing.stages import gapfill as gapfill_stage
    from flosswing.stages import hunt as hunt_stage
    from flosswing.stages import recon as recon_stage
    from flosswing.stages import validate as validate_stage

    async def fake_recon(**kwargs: object) -> RunReconResult:
        return _recon()

    async def fake_hunt(**kwargs: object) -> HuntStageResult:
        return _hunt(processed=2, succeeded=2, findings=1)

    async def fake_validate(**kwargs: object) -> ValidateStageResult:
        return _validate(processed=1, confirmed=1)

    async def fake_gapfill(**kwargs: object) -> GapfillStageResult:
        return _gapfill()

    monkeypatch.setattr(recon_stage, "run", fake_recon)
    monkeypatch.setattr(hunt_stage, "run", fake_hunt)
    monkeypatch.setattr(validate_stage, "run", fake_validate)
    monkeypatch.setattr(gapfill_stage, "run", fake_gapfill)


def test_pid_file_present_during_run_and_cleared_after(
    fresh_db: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import dataclasses

    from flosswing import orchestrator, runpid
    from flosswing.stages import recon as recon_stage

    monkeypatch.setenv("HOME", str(tmp_path))
    _stub_completed_pipeline(monkeypatch)

    seen: dict[str, object] = {}

    async def observing_recon(**kwargs: object) -> RunReconResult:
        rid = str(kwargs["run_id"])
        seen["run_id"] = rid
        # Mid-run: the pid file must exist and report the run as live.
        seen["exists_during"] = runpid.run_pid_path(rid).exists()
        seen["live_during"] = runpid.run_is_live(rid)
        return _recon()

    monkeypatch.setattr(recon_stage, "run", observing_recon)

    cfg = dataclasses.replace(_cfg(tmp_path), auto_render=False)
    result = asyncio.run(orchestrator.run_scan(cfg))
    assert result.exit_code == 0
    assert seen["exists_during"] is True
    assert seen["live_during"] is True
    # After the run finishes, the marker is gone.
    assert not runpid.run_pid_path(str(seen["run_id"])).exists()


def test_pid_file_retained_when_a_stage_raises(
    fresh_db: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """On a crash (unhandled exception), the PID file must be LEFT in place.

    The run row stays status='running' (finalization never runs), so the PID
    file — pointing at a now-dead pid — is what lets the TUI read the run as
    'stale' (crashed) rather than the benign 'unknown' it would show if the
    file had been cleared. Only a clean completion clears the marker.
    """
    import dataclasses

    from flosswing import orchestrator, runpid
    from flosswing.stages import recon as recon_stage
    from flosswing.state.models import Run

    monkeypatch.setenv("HOME", str(tmp_path))

    seen: dict[str, str] = {}

    async def boom_recon(**kwargs: object) -> RunReconResult:
        seen["run_id"] = str(kwargs["run_id"])
        raise RuntimeError("kaboom")

    monkeypatch.setattr(recon_stage, "run", boom_recon)

    cfg = dataclasses.replace(_cfg(tmp_path), auto_render=False)
    with pytest.raises(RuntimeError, match="kaboom"):
        asyncio.run(orchestrator.run_scan(cfg))
    rid = seen["run_id"]
    # PID file retained (dead pid) + row still 'running' => TUI reads 'stale'.
    assert runpid.run_pid_path(rid).exists()
    with st_session.session_scope() as s:
        assert s.get(Run, rid).status == "running"


def test_pid_file_written_before_run_row_committed(
    fresh_db: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The PID marker must exist before the Run row is committed 'running', so
    a TUI poll can never observe a running row with no live PID (false-stale)."""
    import dataclasses

    from flosswing import orchestrator, runpid
    from flosswing.state.models import Run

    monkeypatch.setenv("HOME", str(tmp_path))
    _stub_completed_pipeline(monkeypatch)

    real_write = runpid.write_pid_file
    row_absent_at_write: list[bool] = []

    def spy_write(run_id: str) -> None:
        with st_session.session_scope() as s:
            row_absent_at_write.append(s.get(Run, run_id) is None)
        real_write(run_id)

    monkeypatch.setattr(runpid, "write_pid_file", spy_write)

    cfg = dataclasses.replace(_cfg(tmp_path), auto_render=False)
    asyncio.run(orchestrator.run_scan(cfg))
    # The Run row must NOT yet be committed when the PID file is written.
    assert row_absent_at_write == [True]


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


def test_orchestrator_banner_sanitizes_submodule_paths(
    fresh_db: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Submodule paths come from the untrusted target repo; control/escape
    bytes must not reach the operator's terminal verbatim."""
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
            submodules_skipped=["vendor/\x1b[31mevil\nspoof"],
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
    # Raw ESC and newline must not survive into the banner.
    assert "\x1b" not in result.summary
    assert "vendor/\x1b[31mevil\nspoof" not in result.summary
    # The count still reflects the one skipped submodule.
    assert "submodules_skipped: 1" in result.summary


def test_orchestrator_finally_sweeps_orphaned_heartbeat(
    fresh_db: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If a stage crashes mid-session leaving an in-flight heartbeat row, the
    orchestrator's finally sweeps it (clear_run) so no orphan lingers."""
    from datetime import UTC, datetime

    from flosswing import orchestrator
    from flosswing.stages import recon as recon_stage
    from flosswing.state.models import SessionHeartbeat

    def _now() -> str:
        return datetime.now(UTC).isoformat().replace("+00:00", "Z")

    async def fake_recon(**kwargs: object) -> RunReconResult:
        run_id = kwargs["run_id"]
        assert isinstance(run_id, str)
        # Simulate an in-flight heartbeat that never got cleared because the
        # stage then crashed before its finalize transaction.
        with st_session.session_scope() as s:
            s.add(
                SessionHeartbeat(
                    run_id=run_id,
                    stage="recon",
                    model="claude-opus-4-7",
                    input_tokens=10,
                    output_tokens=5,
                    cost_usd=0.01,
                    started_at=_now(),
                    updated_at=_now(),
                )
            )
        raise RuntimeError("recon blew up after writing a heartbeat")

    monkeypatch.setattr(recon_stage, "run", fake_recon)

    with pytest.raises(RuntimeError):
        asyncio.run(orchestrator.run_scan(_cfg(tmp_path)))

    with st_session.session_scope() as s:
        assert s.query(SessionHeartbeat).all() == []  # swept by the finally
