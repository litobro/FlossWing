"""flosswing.stages.gapfill — Gapfill stage orchestration.

Per docs/specs/2026-06-02-v0.7-gapfill-design.md § Component
responsibilities stages/gapfill.py.

Stage-level tests with a stubbed runtime.run_session returning canned
completed / refused / budget-exceeded / errored sessions. The "happy
path" stub simulates the agent calling add_hunt_task inside the
in-process tool wrapper that the real SDK would invoke.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import select
from ulid import ULID

from flosswing.agent.runtime import SessionResult
from flosswing.config import Config
from flosswing.stages import gapfill as gapfill_stage
from flosswing.state import session as st_session
from flosswing.state.models import AgentSession, HuntTask, Run
from flosswing.tools.findings import AddHuntTaskInput, add_hunt_task


def _now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


@pytest.fixture()
def isolated_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("FLOSSWING_DB_URL", f"sqlite:///{tmp_path}/state.db")
    monkeypatch.setattr(st_session, "_cached_engine", None, raising=False)
    return tmp_path


def _seed_run_with_recon_tasks(count: int) -> str:
    run_id = str(ULID())
    with st_session.session_scope() as s:
        s.add(
            Run(
                id=run_id, target_repo_path="/tmp/x", target_repo_sha=None,
                depth="standard", budget_total=100, budget_used=0,
                started_at=_now_iso(), status="running",
                config_json="{}", flosswing_version="0.7.0",
            )
        )
        s.flush()
        for _ in range(count):
            s.add(
                HuntTask(
                    id=str(ULID()), run_id=run_id,
                    attack_class="command_injection",
                    scope_hint="src/", rationale="",
                    priority="normal", source="recon",
                    parent_finding_id=None, status="completed",
                    created_at=_now_iso(),
                    started_at=_now_iso(), finished_at=_now_iso(),
                    findings_count=0,
                )
            )
    return run_id


def _minimal_cfg(repo: Path) -> Config:
    return Config(
        repo_root=repo,
        model="claude-opus-4-7",
        recon_token_budget=200_000,
        hunt_token_budget=200_000,
        validate_token_budget=100_000,
        gapfill_token_budget=50_000,
        auth_env={"ANTHROPIC_API_KEY": "x"},
    )


@pytest.mark.asyncio
async def test_gapfill_stage_computes_cap_floor_one(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per design decision #1: cap = max(1, recon_task_count // 5).
    1 Recon task -> cap=1 (the floor wins)."""
    run_id = _seed_run_with_recon_tasks(1)

    async def fake_run_session(**kw: object) -> SessionResult:
        return SessionResult(
            outcome="completed",
            input_tokens=100, output_tokens=50,
            cache_read_tokens=0, cache_write_tokens=0,
            duration_ms=1_000, tool_calls_count=1,
            refusal_text=None, error_text=None,
        )

    monkeypatch.setattr(
        gapfill_stage, "run_session",
        AsyncMock(side_effect=fake_run_session),
    )
    result = await gapfill_stage.run(
        run_id=run_id, repo=isolated_db,
        cfg=_minimal_cfg(isolated_db),
        session_factory=st_session.session_factory(),
    )
    assert result.cap == 1
    assert result.outcome == "completed"


@pytest.mark.asyncio
async def test_gapfill_stage_computes_cap_twenty_percent(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """20 Recon tasks -> cap=4."""
    run_id = _seed_run_with_recon_tasks(20)

    async def fake_run_session(**kw: object) -> SessionResult:
        return SessionResult(
            outcome="completed",
            input_tokens=100, output_tokens=50,
            cache_read_tokens=0, cache_write_tokens=0,
            duration_ms=1_000, tool_calls_count=0,
            refusal_text=None, error_text=None,
        )

    monkeypatch.setattr(
        gapfill_stage, "run_session",
        AsyncMock(side_effect=fake_run_session),
    )
    result = await gapfill_stage.run(
        run_id=run_id, repo=isolated_db,
        cfg=_minimal_cfg(isolated_db),
        session_factory=st_session.session_factory(),
    )
    assert result.cap == 4


@pytest.mark.asyncio
async def test_gapfill_stage_completed_session_with_added_task(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Happy path: stubbed runtime simulates the agent calling
    add_hunt_task; the row is committed; the stage's
    GapfillStageResult.tasks_queued reflects the post-session count."""
    run_id = _seed_run_with_recon_tasks(10)  # cap=2

    async def fake_run_session(**kw: object) -> SessionResult:
        # Simulate the model invoking the in-process add_hunt_task
        # tool. The real SDK would route the call through the
        # MCP tool wrapper; the stub calls the underlying function
        # with the same kwargs the wrapper closes over.
        add_hunt_task(
            AddHuntTaskInput(
                attack_class="ssrf",
                scope_hint="src/network/",
                rationale="recon flagged a deserialization boundary; no ssrf task targets it",
            ),
            run_id=str(kw["run_id"]),
            source="gapfill",
            budget_total=100,
            gapfill_new_task_cap=2,
        )
        return SessionResult(
            outcome="completed",
            input_tokens=400, output_tokens=200,
            cache_read_tokens=0, cache_write_tokens=0,
            duration_ms=3_000, tool_calls_count=2,
            refusal_text=None, error_text=None,
        )

    monkeypatch.setattr(
        gapfill_stage, "run_session",
        AsyncMock(side_effect=fake_run_session),
    )
    result = await gapfill_stage.run(
        run_id=run_id, repo=isolated_db,
        cfg=_minimal_cfg(isolated_db),
        session_factory=st_session.session_factory(),
    )
    assert result.outcome == "completed"
    assert result.tasks_queued == 1
    assert result.cap == 2
    assert result.input_tokens == 400
    assert result.output_tokens == 200

    with st_session.session_scope() as s:
        gapfill_rows = list(
            s.execute(
                select(HuntTask).where(
                    HuntTask.run_id == run_id,
                    HuntTask.source == "gapfill",
                )
            ).scalars().all()
        )
        assert len(gapfill_rows) == 1
        assert gapfill_rows[0].attack_class == "ssrf"
        assert gapfill_rows[0].status == "pending"
        # The agent_sessions audit row was written.
        sess = s.execute(
            select(AgentSession).where(
                AgentSession.run_id == run_id,
                AgentSession.stage == "gapfill",
            )
        ).scalar_one()
        assert sess.outcome == "completed"
        assert sess.input_tokens == 400
        assert sess.task_id is None
        assert sess.finding_id is None


@pytest.mark.asyncio
async def test_gapfill_stage_completed_session_with_zero_added_tasks(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per spec § Success criteria #2 and § Component responsibilities:
    zero new tasks is a valid outcome. The stage records the
    agent_sessions row with outcome='completed' even though
    tasks_queued=0."""
    run_id = _seed_run_with_recon_tasks(5)  # cap=1

    async def fake_run_session(**kw: object) -> SessionResult:
        # Agent called query_run_state, concluded existing coverage
        # adequate, and returned without queueing anything.
        return SessionResult(
            outcome="completed",
            input_tokens=120, output_tokens=20,
            cache_read_tokens=0, cache_write_tokens=0,
            duration_ms=2_000, tool_calls_count=1,
            refusal_text=None, error_text=None,
        )

    monkeypatch.setattr(
        gapfill_stage, "run_session",
        AsyncMock(side_effect=fake_run_session),
    )
    result = await gapfill_stage.run(
        run_id=run_id, repo=isolated_db,
        cfg=_minimal_cfg(isolated_db),
        session_factory=st_session.session_factory(),
    )
    assert result.outcome == "completed"
    assert result.tasks_queued == 0
    assert result.cap == 1


@pytest.mark.asyncio
async def test_gapfill_stage_refused_session(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per spec § Error and refusal handling: refused Gapfill writes
    agent_sessions.outcome='refused' with scrubbed refusal text; no
    new hunt_tasks rows."""
    run_id = _seed_run_with_recon_tasks(5)

    async def fake_run_session(**kw: object) -> SessionResult:
        return SessionResult(
            outcome="refused",
            input_tokens=80, output_tokens=10,
            cache_read_tokens=0, cache_write_tokens=0,
            duration_ms=500, tool_calls_count=0,
            refusal_text="I cannot do that",
            error_text=None,
        )

    monkeypatch.setattr(
        gapfill_stage, "run_session",
        AsyncMock(side_effect=fake_run_session),
    )
    result = await gapfill_stage.run(
        run_id=run_id, repo=isolated_db,
        cfg=_minimal_cfg(isolated_db),
        session_factory=st_session.session_factory(),
    )
    assert result.outcome == "refused"
    assert result.tasks_queued == 0
    with st_session.session_scope() as s:
        sess = s.execute(
            select(AgentSession).where(
                AgentSession.run_id == run_id,
                AgentSession.stage == "gapfill",
            )
        ).scalar_one()
        assert sess.outcome == "refused"
        assert sess.refusal_text == "I cannot do that"
        gapfill_rows = list(
            s.execute(
                select(HuntTask).where(
                    HuntTask.run_id == run_id,
                    HuntTask.source == "gapfill",
                )
            ).scalars().all()
        )
        assert gapfill_rows == []


@pytest.mark.asyncio
async def test_gapfill_stage_budget_exceeded_session(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id = _seed_run_with_recon_tasks(5)

    async def fake_run_session(**kw: object) -> SessionResult:
        return SessionResult(
            outcome="budget_exceeded",
            input_tokens=60_000, output_tokens=2_000,
            cache_read_tokens=0, cache_write_tokens=0,
            duration_ms=10_000, tool_calls_count=3,
            refusal_text=None, error_text=None,
        )

    monkeypatch.setattr(
        gapfill_stage, "run_session",
        AsyncMock(side_effect=fake_run_session),
    )
    result = await gapfill_stage.run(
        run_id=run_id, repo=isolated_db,
        cfg=_minimal_cfg(isolated_db),
        session_factory=st_session.session_factory(),
    )
    assert result.outcome == "budget_exceeded"
    assert result.tasks_queued == 0
    with st_session.session_scope() as s:
        sess = s.execute(
            select(AgentSession).where(
                AgentSession.stage == "gapfill",
                AgentSession.run_id == run_id,
            )
        ).scalar_one()
        assert sess.outcome == "budget_exceeded"


@pytest.mark.asyncio
async def test_gapfill_stage_errored_session(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id = _seed_run_with_recon_tasks(5)

    async def fake_run_session(**kw: object) -> SessionResult:
        return SessionResult(
            outcome="errored",
            input_tokens=50, output_tokens=0,
            cache_read_tokens=0, cache_write_tokens=0,
            duration_ms=100, tool_calls_count=0,
            refusal_text=None, error_text="network unreachable",
        )

    monkeypatch.setattr(
        gapfill_stage, "run_session",
        AsyncMock(side_effect=fake_run_session),
    )
    result = await gapfill_stage.run(
        run_id=run_id, repo=isolated_db,
        cfg=_minimal_cfg(isolated_db),
        session_factory=st_session.session_factory(),
    )
    assert result.outcome == "errored"
    assert result.tasks_queued == 0
    with st_session.session_scope() as s:
        sess = s.execute(
            select(AgentSession).where(
                AgentSession.stage == "gapfill",
                AgentSession.run_id == run_id,
            )
        ).scalar_one()
        assert sess.outcome == "errored"
        assert sess.error_text == "network unreachable"


@pytest.mark.asyncio
async def test_gapfill_stage_tool_layer_caps_excessive_calls(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The agent tries to queue 3 tasks under cap=1. The first call
    succeeds; the second returns accepted=False, reason='gapfill_cap_reached'
    via the tool layer's enforcement. The stage's tasks_queued count
    reflects the actual DB state — 1, not 3."""
    run_id = _seed_run_with_recon_tasks(1)  # cap=1

    async def fake_run_session(**kw: object) -> SessionResult:
        # First call: accepted.
        out1 = add_hunt_task(
            AddHuntTaskInput(
                attack_class="ssrf", scope_hint="src/", rationale="r1",
            ),
            run_id=str(kw["run_id"]),
            source="gapfill",
            budget_total=100,
            gapfill_new_task_cap=1,
        )
        assert out1.accepted is True
        # Second call: rejected by the cap.
        out2 = add_hunt_task(
            AddHuntTaskInput(
                attack_class="path_traversal", scope_hint="src/",
                rationale="r2",
            ),
            run_id=str(kw["run_id"]),
            source="gapfill",
            budget_total=100,
            gapfill_new_task_cap=1,
        )
        assert out2.accepted is False
        assert out2.reason == "gapfill_cap_reached"
        return SessionResult(
            outcome="completed",
            input_tokens=200, output_tokens=100,
            cache_read_tokens=0, cache_write_tokens=0,
            duration_ms=1_500, tool_calls_count=2,
            refusal_text=None, error_text=None,
        )

    monkeypatch.setattr(
        gapfill_stage, "run_session",
        AsyncMock(side_effect=fake_run_session),
    )
    result = await gapfill_stage.run(
        run_id=run_id, repo=isolated_db,
        cfg=_minimal_cfg(isolated_db),
        session_factory=st_session.session_factory(),
    )
    assert result.outcome == "completed"
    assert result.tasks_queued == 1
    assert result.cap == 1


@pytest.mark.asyncio
async def test_gapfill_stage_empty_run_no_recon_tasks_still_caps_at_one(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per design decision #1's floor: max(1, recon_task_count // 5) = 1
    even when recon_task_count == 0. v0.7 still computes cap=1 in this
    edge case; the orchestrator's gate (Task 8) prevents reaching this
    stage when Hunt didn't succeed, but the stage itself does the
    arithmetic defensively."""
    run_id = _seed_run_with_recon_tasks(0)

    async def fake_run_session(**kw: object) -> SessionResult:
        return SessionResult(
            outcome="completed",
            input_tokens=10, output_tokens=10,
            cache_read_tokens=0, cache_write_tokens=0,
            duration_ms=500, tool_calls_count=0,
            refusal_text=None, error_text=None,
        )

    monkeypatch.setattr(
        gapfill_stage, "run_session",
        AsyncMock(side_effect=fake_run_session),
    )
    result = await gapfill_stage.run(
        run_id=run_id, repo=isolated_db,
        cfg=_minimal_cfg(isolated_db),
        session_factory=st_session.session_factory(),
    )
    assert result.cap == 1


@pytest.mark.asyncio
async def test_gapfill_tool_builder_registers_all_six_tools(
    isolated_db: Path,
) -> None:
    """Per docs/tool-contracts.md § Tool scope matrix: Gapfill = 6 tools.
    Per design decision #6 (UPSIZED) query_findings is registered. Tools
    NOT in Gapfill's scope (find_definition, find_callers, compile_and_run,
    record_finding, validate_finding, record_recon_artifact) must NOT
    be in the registered list."""
    tools = gapfill_stage._build_gapfill_tools(
        repo_root=isolated_db,
        run_id="01RUN",
        agent_session_id="01SESS",
        gapfill_new_task_cap=1,
        budget_total=100,
        total_token_budget=300_000,
    )
    assert len(tools) == 6
    tool_names = {
        getattr(t, "name", None) or getattr(t, "__name__", "")
        for t in tools
    }
    assert tool_names == {
        "read_file", "list_dir", "grep",
        "query_findings", "query_run_state", "add_hunt_task",
    }
    for forbidden in (
        "find_definition", "find_callers", "compile_and_run",
        "record_finding", "validate_finding", "record_recon_artifact",
    ):
        assert forbidden not in tool_names


@pytest.mark.asyncio
async def test_gapfill_stage_result_skipped_classmethod() -> None:
    """GapfillStageResult.skipped() returns outcome='skipped',
    tasks_queued=0, cap=0. Used by the orchestrator when the gate
    (hunt_result.tasks_succeeded >= 1) is not satisfied."""
    r = gapfill_stage.GapfillStageResult.skipped()
    assert r.outcome == "skipped"
    assert r.tasks_queued == 0
    assert r.cap == 0
    assert r.input_tokens == 0
    assert r.output_tokens == 0
