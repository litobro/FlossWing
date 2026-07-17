"""flosswing.stages.dedupe — Dedupe stage orchestration + orchestrator wiring.

Per docs/specs/2026-06-02-v0.8-dedupe-design.md § Component
responsibilities stages/dedupe.py and § orchestrator.run_scan extension.

Two sections:

1. Stage-level wiring tests with a stubbed
   ``flosswing.agent.runtime.run_session`` (mirrors
   ``test_stages_gapfill.py``). Pass 1 is real SQL; Pass 2's per-cluster
   agent session is stubbed.
2. Orchestrator-side wiring tests that exercise ``_config_for_run_row``
   JSON serialization, the budget_used roll-up arithmetic, and the
   ``hunt_result.findings_total`` gate.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import select
from ulid import ULID

from flosswing import orchestrator
from flosswing.agent.runtime import SessionResult
from flosswing.config import Config
from flosswing.stages import dedupe as dedupe_stage
from flosswing.stages.dedupe import DedupeStageResult
from flosswing.stages.gapfill import GapfillStageResult
from flosswing.stages.hunt import HuntStageResult
from flosswing.stages.recon import RunReconResult
from flosswing.stages.validate import ValidateStageResult
from flosswing.state import session as st_session
from flosswing.state.models import (
    AgentSession,
    DedupeCluster,
    Finding,
    FindingLink,
    HuntTask,
    Run,
)

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


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


def _minimal_cfg(repo: Path) -> Config:
    return Config(
        repo_root=repo,
        model="claude-opus-4-7",
        recon_token_budget=200_000,
        hunt_token_budget=200_000,
        validate_token_budget=100_000,
        gapfill_token_budget=50_000,
        dedupe_token_budget=50_000,
        auth_env={"ANTHROPIC_API_KEY": "x"},
    )


def _seed_run(run_id: str) -> None:
    """Insert a single Run row. Caller commits a separate session_scope."""
    with st_session.session_scope() as s:
        s.add(
            Run(
                id=run_id,
                target_repo_path="/tmp/x",
                target_repo_sha=None,
                depth="standard",
                budget_total=20,
                budget_used=0,
                started_at=_now_iso(),
                status="running",
                config_json="{}",
                flosswing_version="0.8.0",
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
    attack_class: str = "command_injection",
    file: str = "src/a.py",
    function: str | None = "some_fn",
    line_start: int = 10,
    line_end: int | None = None,
) -> str:
    """Insert one finding with dedupe_cluster_id IS NULL. Returns id.

    Defaults ``line_end`` to ``line_start + 2`` so the CHECK constraint
    ``ck_findings_lines`` (line_end >= line_start) is always satisfied
    regardless of which line_start the caller picks.
    """
    fid = str(ULID())
    actual_line_end = line_end if line_end is not None else line_start + 2
    with st_session.session_scope() as s:
        s.add(
            Finding(
                id=fid,
                run_id=run_id,
                hunt_task_id=task_id,
                attack_class=attack_class,
                file=file,
                function=function,
                line_start=line_start,
                line_end=actual_line_end,
                severity="high",
                confidence="likely",
                status="pending_validation",
                title=f"{attack_class} in {file}",
                description="A reasonable description, fifty chars or more.",
                poc_code=None,
                poc_result_json=None,
                suggested_fix=None,
                created_at=_now_iso(),
            )
        )
    return fid


def _benign_session_result(
    *,
    outcome: str = "completed",
    input_tokens: int = 100,
    output_tokens: int = 50,
    refusal_text: str | None = None,
    error_text: str | None = None,
) -> SessionResult:
    # outcome is a Literal in SessionResult; the stage's classification
    # only checks string equality so passing through a str via the type
    # system here would require a cast. Use the Literal directly via
    # the four specific outcomes we care about in these tests.
    if outcome == "completed":
        return SessionResult(
            outcome="completed",
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cache_read_tokens=0,
            cache_write_tokens=0,
            duration_ms=1_000,
            tool_calls_count=0,
            refusal_text=None,
            error_text=None,
        )
    if outcome == "refused":
        return SessionResult(
            outcome="refused",
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cache_read_tokens=0,
            cache_write_tokens=0,
            duration_ms=500,
            tool_calls_count=0,
            refusal_text=refusal_text or "I cannot do that",
            error_text=None,
        )
    if outcome == "errored":
        return SessionResult(
            outcome="errored",
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cache_read_tokens=0,
            cache_write_tokens=0,
            duration_ms=100,
            tool_calls_count=0,
            refusal_text=None,
            error_text=error_text or "boom",
        )
    raise AssertionError(f"unsupported outcome {outcome!r} in helper")


# ---------------------------------------------------------------------------
# Section 1 — Stage-level wiring (stubbed runtime)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dedupe_run_pass1_commits_before_pass2(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per spec § Two passes (open question Q#5 resolution: TWO
    transactions). The first run_session call must see dedupe_clusters
    rows already present — Pass 1 committed before Pass 2 started."""
    run_id = str(ULID())
    _seed_run(run_id)
    task_id = _seed_task(run_id)
    # Two findings within ±5 lines, same file/function/attack_class.
    _seed_finding(run_id=run_id, task_id=task_id, line_start=10, line_end=12)
    _seed_finding(run_id=run_id, task_id=task_id, line_start=13, line_end=15)

    observed_clusters: list[int] = []
    from flosswing.agent.providers.base import UsageSnapshot
    from flosswing.state.models import SessionHeartbeat

    async def fake_run_session(**kw: object) -> SessionResult:
        # At session start, Pass 1 should have committed at least one
        # dedupe_clusters row.
        with st_session.session_scope() as s:
            rows = list(
                s.execute(
                    select(DedupeCluster).where(
                        DedupeCluster.run_id == run_id
                    )
                ).scalars().all()
            )
        observed_clusters.append(len(rows))
        on_usage = kw.get("on_usage")
        assert callable(on_usage)
        on_usage(
            UsageSnapshot(
                input_tokens=100,
                output_tokens=50,
                cache_read_tokens=0,
                cache_write_tokens=0,
                tool_calls_count=1,
                cost_usd=None,
            )
        )
        return _benign_session_result()

    monkeypatch.setattr(
        dedupe_stage, "run_session",
        AsyncMock(side_effect=fake_run_session),
    )

    result = await dedupe_stage.run(
        run_id=run_id,
        repo=isolated_db,
        cfg=_minimal_cfg(isolated_db),
        session_factory=st_session.session_factory(),
    )

    # Exactly one multi-member cluster of size 2 produced.
    assert result.outcome == "completed"
    assert result.clusters_total == 1
    assert result.clusters_reviewed == 1
    # The stub saw the committed cluster row before Pass 2's session ran.
    assert observed_clusters == [1]
    with st_session.session_scope() as s:
        assert s.execute(select(SessionHeartbeat)).scalars().all() == []  # cleared


@pytest.mark.asyncio
async def test_dedupe_skips_size_1_clusters(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per spec § Pass 2 step 1: skip singleton clusters. No agent_sessions
    row inserted for them; run_session never called."""
    run_id = str(ULID())
    _seed_run(run_id)
    task_id = _seed_task(run_id)
    # 3 isolated findings — distinct (file, function, attack_class).
    _seed_finding(
        run_id=run_id, task_id=task_id, file="src/a.py", line_start=10,
    )
    _seed_finding(
        run_id=run_id, task_id=task_id, file="src/b.py", line_start=10,
    )
    _seed_finding(
        run_id=run_id, task_id=task_id, file="src/c.py", line_start=10,
    )

    called = False

    async def fake_run_session(**kw: object) -> SessionResult:
        nonlocal called
        called = True
        return _benign_session_result()

    monkeypatch.setattr(
        dedupe_stage, "run_session",
        AsyncMock(side_effect=fake_run_session),
    )

    result = await dedupe_stage.run(
        run_id=run_id,
        repo=isolated_db,
        cfg=_minimal_cfg(isolated_db),
        session_factory=st_session.session_factory(),
    )

    assert result.outcome == "completed"
    assert result.clusters_total == 3
    assert result.clusters_reviewed == 0
    assert called is False

    # No dedupe-stage agent_sessions row was written.
    with st_session.session_scope() as s:
        sessions = list(
            s.execute(
                select(AgentSession).where(
                    AgentSession.run_id == run_id,
                    AgentSession.stage == "dedupe",
                )
            ).scalars().all()
        )
    assert sessions == []


@pytest.mark.asyncio
async def test_dedupe_tool_list_is_4_tools_in_order(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per docs/tool-contracts.md § Tool scope matrix: Dedupe = 4 tools
    (read_file, query_findings, merge_findings, link_variant).

    The stage's _build_dedupe_tools returns SdkMcpTool objects each with
    a .name attribute. Capture the tools kwarg from the runtime stub and
    assert exact contents in declared order.
    """
    run_id = str(ULID())
    _seed_run(run_id)
    task_id = _seed_task(run_id)
    _seed_finding(run_id=run_id, task_id=task_id, line_start=10)
    _seed_finding(run_id=run_id, task_id=task_id, line_start=13)

    captured_tools: list[list[Any]] = []

    async def fake_run_session(**kw: Any) -> SessionResult:
        captured_tools.append(list(kw["tools"]))
        return _benign_session_result()

    monkeypatch.setattr(
        dedupe_stage, "run_session",
        AsyncMock(side_effect=fake_run_session),
    )

    await dedupe_stage.run(
        run_id=run_id,
        repo=isolated_db,
        cfg=_minimal_cfg(isolated_db),
        session_factory=st_session.session_factory(),
    )

    assert len(captured_tools) == 1
    tools = captured_tools[0]
    assert len(tools) == 4
    names = [getattr(t, "name", "") for t in tools]
    assert names == [
        "read_file",
        "query_findings",
        "merge_findings",
        "link_variant",
    ]


@pytest.mark.asyncio
async def test_dedupe_outcome_completed_counts_merges_and_links(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per spec § Component responsibilities stages/dedupe.py:
    variants_linked is the post-session delta of finding_links rows.

    The stub synthesizes a finding_links insert mid-session to mimic
    a successful link_variant call; the stage's delta accounting
    attributes the write to this session."""
    run_id = str(ULID())
    _seed_run(run_id)
    task_id = _seed_task(run_id)
    fid_a = _seed_finding(
        run_id=run_id, task_id=task_id, line_start=10,
    )
    fid_b = _seed_finding(
        run_id=run_id, task_id=task_id, line_start=12,
    )

    async def fake_run_session(**kw: object) -> SessionResult:
        # Fake a successful link_variant write inside the session window.
        # The stage snapshots finding_links counts before/after each
        # session and rolls the delta into variants_linked.
        with st_session.session_scope() as s:
            s.add(
                FindingLink(
                    id=str(ULID()),
                    finding_id_a=fid_a,
                    finding_id_b=fid_b,
                    relationship="same_root_cause",
                    note="stubbed link",
                    created_at=_now_iso(),
                )
            )
        return _benign_session_result(input_tokens=200, output_tokens=100)

    monkeypatch.setattr(
        dedupe_stage, "run_session",
        AsyncMock(side_effect=fake_run_session),
    )

    result = await dedupe_stage.run(
        run_id=run_id,
        repo=isolated_db,
        cfg=_minimal_cfg(isolated_db),
        session_factory=st_session.session_factory(),
    )

    assert result.outcome == "completed"
    assert result.clusters_total == 1
    assert result.clusters_reviewed == 1
    assert result.variants_linked == 1
    assert result.merges_performed == 0
    assert result.input_tokens == 200
    assert result.output_tokens == 100


@pytest.mark.asyncio
async def test_dedupe_refusal_does_not_block_next_cluster(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per spec § Failure modes: per-cluster failures are swallowed and
    counted; the stage as a whole completes regardless. A refused first
    cluster must not stop the second cluster's session from running."""
    run_id = str(ULID())
    _seed_run(run_id)
    task_id = _seed_task(run_id)
    # Cluster 1: two findings in src/a.py near each other.
    _seed_finding(
        run_id=run_id, task_id=task_id, file="src/a.py",
        line_start=10, line_end=12,
    )
    _seed_finding(
        run_id=run_id, task_id=task_id, file="src/a.py",
        line_start=13, line_end=15,
    )
    # Cluster 2: two findings in src/b.py near each other.
    _seed_finding(
        run_id=run_id, task_id=task_id, file="src/b.py",
        line_start=10, line_end=12,
    )
    _seed_finding(
        run_id=run_id, task_id=task_id, file="src/b.py",
        line_start=13, line_end=15,
    )

    call_count = 0

    async def fake_run_session(**kw: object) -> SessionResult:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return _benign_session_result(outcome="refused")
        return _benign_session_result(outcome="completed")

    monkeypatch.setattr(
        dedupe_stage, "run_session",
        AsyncMock(side_effect=fake_run_session),
    )

    result = await dedupe_stage.run(
        run_id=run_id,
        repo=isolated_db,
        cfg=_minimal_cfg(isolated_db),
        session_factory=st_session.session_factory(),
    )

    assert call_count == 2, "second cluster's session must still run"
    assert result.clusters_total == 2
    assert result.clusters_reviewed == 2
    assert result.clusters_refused == 1
    assert result.clusters_errored == 0


@pytest.mark.asyncio
async def test_dedupe_errored_session_counts_as_errored(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per spec § Failure modes: errored sessions are counted in the
    clusters_errored bucket; the stage as a whole completes."""
    run_id = str(ULID())
    _seed_run(run_id)
    task_id = _seed_task(run_id)
    _seed_finding(run_id=run_id, task_id=task_id, line_start=10)
    _seed_finding(run_id=run_id, task_id=task_id, line_start=13)

    async def fake_run_session(**kw: object) -> SessionResult:
        return _benign_session_result(outcome="errored")

    monkeypatch.setattr(
        dedupe_stage, "run_session",
        AsyncMock(side_effect=fake_run_session),
    )

    result = await dedupe_stage.run(
        run_id=run_id,
        repo=isolated_db,
        cfg=_minimal_cfg(isolated_db),
        session_factory=st_session.session_factory(),
    )

    assert result.outcome == "completed"
    assert result.clusters_errored == 1
    assert result.clusters_refused == 0


@pytest.mark.asyncio
async def test_dedupe_agent_sessions_task_id_is_null_and_stage_is_dedupe(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per spec § State writes: agent_sessions rows for Dedupe set
    stage='dedupe', task_id IS NULL, finding_id IS NULL."""
    run_id = str(ULID())
    _seed_run(run_id)
    task_id = _seed_task(run_id)
    _seed_finding(run_id=run_id, task_id=task_id, line_start=10)
    _seed_finding(run_id=run_id, task_id=task_id, line_start=13)

    async def fake_run_session(**kw: object) -> SessionResult:
        return _benign_session_result()

    monkeypatch.setattr(
        dedupe_stage, "run_session",
        AsyncMock(side_effect=fake_run_session),
    )

    await dedupe_stage.run(
        run_id=run_id,
        repo=isolated_db,
        cfg=_minimal_cfg(isolated_db),
        session_factory=st_session.session_factory(),
    )

    # Snapshot the audit fields INSIDE the session scope. SQLAlchemy
    # expires ORM instances when the scope exits, so attribute access
    # outside the with-block triggers DetachedInstanceError.
    snapshots: list[tuple[str | None, str | None, str]] = []
    with st_session.session_scope() as s:
        rows = list(
            s.execute(
                select(AgentSession).where(
                    AgentSession.run_id == run_id,
                    AgentSession.stage == "dedupe",
                )
            ).scalars().all()
        )
        for row in rows:
            snapshots.append((row.task_id, row.finding_id, row.stage))
    assert len(snapshots) >= 1
    for task_id_v, finding_id_v, stage_v in snapshots:
        assert task_id_v is None
        assert finding_id_v is None
        assert stage_v == "dedupe"


@pytest.mark.asyncio
async def test_dedupe_returns_skipped_when_pass1_yields_zero_clusters(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per spec § Pass 1: 0 findings -> 0 clusters -> stage returns
    DedupeStageResult.skipped(). run_session is never called."""
    run_id = str(ULID())
    _seed_run(run_id)
    _seed_task(run_id)  # no findings attached

    called = False

    async def fake_run_session(**kw: object) -> SessionResult:
        nonlocal called
        called = True
        return _benign_session_result()

    monkeypatch.setattr(
        dedupe_stage, "run_session",
        AsyncMock(side_effect=fake_run_session),
    )

    result = await dedupe_stage.run(
        run_id=run_id,
        repo=isolated_db,
        cfg=_minimal_cfg(isolated_db),
        session_factory=st_session.session_factory(),
    )

    assert result.outcome == "skipped"
    assert result.clusters_total == 0
    assert result.clusters_reviewed == 0
    assert called is False


# ---------------------------------------------------------------------------
# Section 2 — Orchestrator-side wiring
# ---------------------------------------------------------------------------


@pytest.fixture()
def fresh_db(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("FLOSSWING_DB_URL", "sqlite:///:memory:")
    monkeypatch.setattr(st_session, "_cached_engine", None, raising=False)
    monkeypatch.setattr(
        st_session, "_cached_session_factory", None, raising=False
    )
    yield
    monkeypatch.setattr(st_session, "_cached_engine", None, raising=False)
    monkeypatch.setattr(
        st_session, "_cached_session_factory", None, raising=False
    )


def _orch_cfg(tmp_path: Path, dedupe_token_budget: int = 50_000) -> Config:
    return Config(
        repo_root=tmp_path,
        model="claude-opus-4-7",
        recon_token_budget=200_000,
        hunt_token_budget=200_000,
        validate_token_budget=100_000,
        gapfill_token_budget=50_000,
        dedupe_token_budget=dedupe_token_budget,
        auth_env={"ANTHROPIC_API_KEY": "sk-test"},
    )


def test_config_for_run_row_includes_dedupe_token_budget(
    tmp_path: Path,
) -> None:
    """Per spec § Component responsibilities orchestrator.run_scan
    extension: dedupe_token_budget is persisted in runs.config_json."""
    cfg = _orch_cfg(tmp_path, dedupe_token_budget=12_345)
    payload = json.loads(orchestrator._config_for_run_row(cfg))
    assert payload["dedupe_token_budget"] == 12_345


def test_budget_used_sums_dedupe_tokens(
    fresh_db: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """runs.budget_used must include Dedupe tokens.

    Mirrors test_orchestrator.test_orchestrator_budget_used_includes_gapfill_tokens
    — the same end-to-end stub-the-stages pattern, asserting the
    arithmetic includes dedupe_result.input_tokens + output_tokens.
    """
    from flosswing.index.build import IndexBuildResult
    from flosswing.stages import gapfill as gapfill_stage
    from flosswing.stages import hunt as hunt_stage
    from flosswing.stages import index_build as index_build_stage
    from flosswing.stages import recon as recon_stage
    from flosswing.stages import validate as validate_stage

    async def fake_recon(**kwargs: object) -> RunReconResult:
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
            recon_artifact_id="01ARTIFACT",
            languages={"python"},
        )

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
        return HuntStageResult(
            tasks_processed=1,
            tasks_succeeded=1,
            tasks_refused=0,
            tasks_budget_exceeded=0,
            tasks_errored=0,
            findings_total=1,
            input_tokens_total=100,
            output_tokens_total=50,
        )

    async def fake_validate(**kwargs: object) -> ValidateStageResult:
        return ValidateStageResult(
            findings_processed=1,
            findings_confirmed=1,
            findings_rejected=0,
            findings_uncertain=0,
            findings_refused=0,
            findings_budget_exceeded=0,
            findings_errored=0,
            findings_no_verdict=0,
            input_tokens_total=200,
            output_tokens_total=100,
        )

    async def fake_gapfill(**kwargs: object) -> GapfillStageResult:
        return GapfillStageResult(
            outcome="completed",
            tasks_queued=1,
            cap=1,
            input_tokens=300,
            output_tokens=80,
        )

    async def fake_dedupe(**kwargs: object) -> DedupeStageResult:
        return DedupeStageResult(
            outcome="completed",
            clusters_total=1,
            clusters_reviewed=1,
            merges_performed=0,
            variants_linked=1,
            input_tokens=400,
            output_tokens=120,
        )

    monkeypatch.setattr(recon_stage, "run", fake_recon)
    monkeypatch.setattr(index_build_stage, "run", fake_index_build)
    monkeypatch.setattr(hunt_stage, "run", fake_hunt)
    monkeypatch.setattr(validate_stage, "run", fake_validate)
    monkeypatch.setattr(gapfill_stage, "run", fake_gapfill)
    monkeypatch.setattr(dedupe_stage, "run", fake_dedupe)

    asyncio.run(orchestrator.run_scan(_orch_cfg(tmp_path)))

    with st_session.session_scope() as s:
        rows = s.query(Run).all()
        assert len(rows) == 1
        # recon (0+0) + hunt (100+50) + validate (200+100) + gapfill (300+80)
        # + dedupe (400+120) = 1350
        assert rows[0].budget_used == 1350


def test_dedupe_gated_on_findings_total(
    fresh_db: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per spec § orchestrator.run_scan extension: Dedupe runs only when
    >= 1 finding exists to consider. hunt_result.findings_total == 0 means
    the orchestrator must skip stages.dedupe.run entirely."""
    from flosswing.index.build import IndexBuildResult
    from flosswing.stages import gapfill as gapfill_stage
    from flosswing.stages import hunt as hunt_stage
    from flosswing.stages import index_build as index_build_stage
    from flosswing.stages import recon as recon_stage
    from flosswing.stages import validate as validate_stage

    dedupe_called = False

    async def fake_recon(**kwargs: object) -> RunReconResult:
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
            recon_artifact_id="01ARTIFACT",
            languages={"python"},
        )

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
        return HuntStageResult(
            tasks_processed=1,
            tasks_succeeded=1,
            tasks_refused=0,
            tasks_budget_exceeded=0,
            tasks_errored=0,
            findings_total=0,
            input_tokens_total=80,
            output_tokens_total=40,
        )

    async def fake_validate(**kwargs: object) -> ValidateStageResult:
        # Should not be called either (findings_total == 0), but stub
        # to be safe.
        return ValidateStageResult(
            findings_processed=0,
            findings_confirmed=0,
            findings_rejected=0,
            findings_uncertain=0,
            findings_refused=0,
            findings_budget_exceeded=0,
            findings_errored=0,
            findings_no_verdict=0,
            input_tokens_total=0,
            output_tokens_total=0,
        )

    async def fake_gapfill(**kwargs: object) -> GapfillStageResult:
        return GapfillStageResult(
            outcome="completed",
            tasks_queued=0,
            cap=1,
            input_tokens=0,
            output_tokens=0,
        )

    async def fake_dedupe(**kwargs: object) -> DedupeStageResult:
        nonlocal dedupe_called
        dedupe_called = True
        return DedupeStageResult(outcome="completed")

    monkeypatch.setattr(recon_stage, "run", fake_recon)
    monkeypatch.setattr(index_build_stage, "run", fake_index_build)
    monkeypatch.setattr(hunt_stage, "run", fake_hunt)
    monkeypatch.setattr(validate_stage, "run", fake_validate)
    monkeypatch.setattr(gapfill_stage, "run", fake_gapfill)
    monkeypatch.setattr(dedupe_stage, "run", fake_dedupe)

    asyncio.run(orchestrator.run_scan(_orch_cfg(tmp_path)))
    assert dedupe_called is False
