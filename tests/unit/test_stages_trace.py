"""flosswing.stages.trace — Trace stage orchestration + orchestrator wiring.

Per docs/specs/2026-06-02-v0.9-trace-design.md § Component responsibilities
``stages/trace.py`` and § orchestrator.run_scan extension.

Two sections:

1. Stage-level wiring tests with a stubbed
   ``flosswing.agent.runtime.run_session`` imported by
   ``flosswing/stages/trace.py``. The pattern mirrors v0.8's
   ``test_stages_dedupe_wiring.py``: patch the name the stage module
   bound at import time, return canned SessionResults, occasionally
   reach back into the DB to mimic side-effects ``record_trace`` would
   have committed.
2. Orchestrator-side wiring tests that exercise ``_config_for_run_row``
   JSON serialization, the ``budget_used`` roll-up (12 token terms now),
   and the trace_eligible_count gate.
"""

from __future__ import annotations

import asyncio
import json
import time
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
from flosswing.stages import trace as trace_stage
from flosswing.stages.dedupe import DedupeStageResult
from flosswing.stages.gapfill import GapfillStageResult
from flosswing.stages.hunt import HuntStageResult
from flosswing.stages.recon import RunReconResult
from flosswing.stages.trace import TraceStageResult
from flosswing.stages.validate import ValidateStageResult
from flosswing.state import session as st_session
from flosswing.state.models import (
    AgentSession,
    Finding,
    HuntTask,
    Run,
    Trace,
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


def _minimal_cfg(repo: Path, *, trace_max_depth: int = 8) -> Config:
    return Config(
        repo_root=repo,
        model="claude-opus-4-7",
        recon_token_budget=200_000,
        hunt_token_budget=200_000,
        validate_token_budget=100_000,
        gapfill_token_budget=50_000,
        dedupe_token_budget=50_000,
        trace_token_budget=50_000,
        trace_max_depth=trace_max_depth,
        auth_env={"ANTHROPIC_API_KEY": "x"},
    )


def _seed_run(run_id: str) -> None:
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
                flosswing_version="0.9.0",
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
    dedupe_role: str | None = None,
    file: str = "src/a.py",
    line_start: int = 10,
    line_end: int | None = None,
) -> str:
    """Insert one finding; return its id.

    Defaults to a trace-eligible row: status='confirmed',
    dedupe_role IS NULL. Callers override either to seed ineligible rows.
    """
    fid = str(ULID())
    actual_line_end = line_end if line_end is not None else line_start + 2
    with st_session.session_scope() as s:
        s.add(
            Finding(
                id=fid,
                run_id=run_id,
                hunt_task_id=task_id,
                attack_class="command_injection",
                file=file,
                function="some_fn",
                line_start=line_start,
                line_end=actual_line_end,
                severity="high",
                confidence="likely",
                status=status,
                title=f"command_injection in {file}",
                description=(
                    "A reasonable description, fifty chars or more."
                ),
                poc_code=None,
                poc_result_json=None,
                suggested_fix=None,
                created_at=_now_iso(),
                dedupe_role=dedupe_role,
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
    # system here would require a cast. Use the four specific outcomes
    # we care about in these tests directly.
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
    if outcome == "budget_exceeded":
        return SessionResult(
            outcome="budget_exceeded",
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cache_read_tokens=0,
            cache_write_tokens=0,
            duration_ms=200,
            tool_calls_count=0,
            refusal_text=None,
            error_text=None,
        )
    raise AssertionError(f"unsupported outcome {outcome!r} in helper")


def _insert_trace_for(*, finding_id: str, reachable: str) -> None:
    """Mimic what record_trace would have written.

    Trace.agent_session_id is FK ON DELETE RESTRICT to agent_sessions;
    the stage pre-inserts that row before awaiting run_session so the
    real tool can satisfy the FK. The stub looks the row up by
    finding_id and reuses its id for the trace's agent_session_id.

    ``ck_traces_reachable_has_entry_point`` requires
    ``reachable='reachable' -> entry_point_symbol IS NOT NULL``; the
    helper supplies a sentinel symbol whenever reachable=='reachable'
    so the row clears the CHECK constraint.
    """
    entry_symbol: str | None = (
        "main" if reachable == "reachable" else None
    )
    with st_session.session_scope() as s:
        sess = s.execute(
            select(AgentSession).where(
                AgentSession.finding_id == finding_id,
                AgentSession.stage == "trace",
            )
        ).scalar_one()
        agent_session_id = sess.id
        s.add(
            Trace(
                id=str(ULID()),
                finding_id=finding_id,
                reachable=reachable,
                entry_point_symbol=entry_symbol,
                entry_point_id=None,
                call_chain_json="[]",
                rationale="stubbed by test",
                agent_session_id=agent_session_id,
                created_at=_now_iso(),
            )
        )


# ---------------------------------------------------------------------------
# Section 1 — Stage-level wiring (stubbed runtime)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_trace_skips_rejected_uncertain_duplicate_variant_superseded(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per spec § Stage selection: only confirmed primaries are eligible.

    Seed every status/role permutation that must NOT match the SELECT
    and confirm run_session is never invoked and the stage short-circuits
    to ``skipped()`` with findings_total == 0.
    """
    run_id = str(ULID())
    _seed_run(run_id)
    task_id = _seed_task(run_id)
    # rejected — not confirmed.
    _seed_finding(
        run_id=run_id, task_id=task_id, status="rejected",
        file="src/r.py",
    )
    # uncertain — not confirmed.
    _seed_finding(
        run_id=run_id, task_id=task_id, status="uncertain",
        file="src/u.py",
    )
    # superseded — not confirmed.
    _seed_finding(
        run_id=run_id, task_id=task_id, status="superseded",
        file="src/s.py",
    )
    # confirmed + dedupe_role='duplicate' — confirmed but not primary.
    _seed_finding(
        run_id=run_id, task_id=task_id, status="confirmed",
        dedupe_role="duplicate", file="src/d.py",
    )
    # confirmed + dedupe_role='variant' — confirmed but not primary.
    _seed_finding(
        run_id=run_id, task_id=task_id, status="confirmed",
        dedupe_role="variant", file="src/v.py",
    )

    called = False

    async def fake_run_session(**kw: object) -> SessionResult:
        nonlocal called
        called = True
        return _benign_session_result()

    monkeypatch.setattr(
        trace_stage, "run_session",
        AsyncMock(side_effect=fake_run_session),
    )

    result = await trace_stage.run(
        run_id=run_id,
        repo=isolated_db,
        cfg=_minimal_cfg(isolated_db),
        session_factory=st_session.session_factory(),
    )

    assert called is False
    assert result.outcome == "skipped"
    assert result.findings_total == 0


@pytest.mark.asyncio
async def test_trace_selects_confirmed_primaries_only(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per spec § Stage selection: eligible == status='confirmed' AND
    (dedupe_role IS NULL OR dedupe_role='primary'). Two of the four
    seeded rows match; the other two confirmed-but-non-primary rows
    must be ignored. Selection is ULID order (= creation order).
    """
    run_id = str(ULID())
    _seed_run(run_id)
    task_id = _seed_task(run_id)
    # Eligible: confirmed + NULL role.
    fid_a = _seed_finding(
        run_id=run_id, task_id=task_id, status="confirmed",
        dedupe_role=None, file="src/a.py",
    )
    # Eligible: confirmed + primary role.
    fid_b = _seed_finding(
        run_id=run_id, task_id=task_id, status="confirmed",
        dedupe_role="primary", file="src/b.py",
    )
    # Not eligible: confirmed + duplicate role.
    _seed_finding(
        run_id=run_id, task_id=task_id, status="confirmed",
        dedupe_role="duplicate", file="src/c.py",
    )
    # Not eligible: confirmed + variant role.
    _seed_finding(
        run_id=run_id, task_id=task_id, status="confirmed",
        dedupe_role="variant", file="src/d.py",
    )

    seen_finding_ids: list[str] = []

    async def fake_run_session(**kw: Any) -> SessionResult:
        seen_finding_ids.append(str(kw.get("finding_id", "")))
        return _benign_session_result()

    monkeypatch.setattr(
        trace_stage, "run_session",
        AsyncMock(side_effect=fake_run_session),
    )

    result = await trace_stage.run(
        run_id=run_id,
        repo=isolated_db,
        cfg=_minimal_cfg(isolated_db),
        session_factory=st_session.session_factory(),
    )

    assert result.findings_total == 2
    assert len(seen_finding_ids) == 2
    # ULID order == creation order; fid_a was seeded before fid_b.
    assert seen_finding_ids == sorted([fid_a, fid_b])


@pytest.mark.asyncio
async def test_trace_empty_selection_returns_skipped(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per spec § Stage selection: zero eligible findings ->
    TraceStageResult.skipped(). run_session is never called and no
    agent_sessions rows are written."""
    run_id = str(ULID())
    _seed_run(run_id)
    task_id = _seed_task(run_id)
    # Only ineligible findings.
    _seed_finding(
        run_id=run_id, task_id=task_id, status="rejected",
        file="src/r.py",
    )
    _seed_finding(
        run_id=run_id, task_id=task_id, status="confirmed",
        dedupe_role="duplicate", file="src/d.py",
    )

    called = False

    async def fake_run_session(**kw: object) -> SessionResult:
        nonlocal called
        called = True
        return _benign_session_result()

    monkeypatch.setattr(
        trace_stage, "run_session",
        AsyncMock(side_effect=fake_run_session),
    )

    result = await trace_stage.run(
        run_id=run_id,
        repo=isolated_db,
        cfg=_minimal_cfg(isolated_db),
        session_factory=st_session.session_factory(),
    )

    assert result.outcome == "skipped"
    assert called is False
    # No trace agent_sessions row written.
    with st_session.session_scope() as s:
        rows = list(
            s.execute(
                select(AgentSession).where(
                    AgentSession.run_id == run_id,
                    AgentSession.stage == "trace",
                )
            ).scalars().all()
        )
    assert rows == []


@pytest.mark.asyncio
async def test_trace_sequential_per_finding(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per spec § Concurrency: sessions run sequentially per finding,
    one at a time. Verify via a stub that tracks call-window start/end
    timestamps and asserts no overlap.
    """
    run_id = str(ULID())
    _seed_run(run_id)
    task_id = _seed_task(run_id)
    _seed_finding(
        run_id=run_id, task_id=task_id, file="src/a.py",
    )
    _seed_finding(
        run_id=run_id, task_id=task_id, file="src/b.py",
    )

    # Each entry is (start_ns, end_ns). Sequential -> entry N's end_ns
    # is <= entry N+1's start_ns.
    windows: list[tuple[int, int]] = []
    from flosswing.agent.providers.base import UsageSnapshot
    from flosswing.state.models import SessionHeartbeat

    async def fake_run_session(**kw: object) -> SessionResult:
        started = time.monotonic_ns()
        # Brief await to give the event loop a chance to interleave if
        # the stage were (incorrectly) gathering concurrently.
        await asyncio.sleep(0.01)
        ended = time.monotonic_ns()
        windows.append((started, ended))
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
        trace_stage, "run_session",
        AsyncMock(side_effect=fake_run_session),
    )

    await trace_stage.run(
        run_id=run_id,
        repo=isolated_db,
        cfg=_minimal_cfg(isolated_db),
        session_factory=st_session.session_factory(),
    )

    assert len(windows) == 2
    # Strict ordering: previous session must have finished before the
    # next started. Equality is acceptable on the boundary.
    assert windows[0][1] <= windows[1][0]
    # Both per-finding finalizes cleared the heartbeat.
    with st_session.session_scope() as s:
        assert s.execute(select(SessionHeartbeat)).scalars().all() == []


@pytest.mark.asyncio
async def test_trace_outcome_completed_with_record_trace(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per spec § Per-finding classification: completed + traces row
    present -> findings_traced += 1 + bucket by reachable. Stub mimics a
    successful record_trace by inserting a traces row mid-session with
    reachable='reachable'.
    """
    run_id = str(ULID())
    _seed_run(run_id)
    task_id = _seed_task(run_id)
    fid = _seed_finding(run_id=run_id, task_id=task_id)

    async def fake_run_session(**kw: object) -> SessionResult:
        _insert_trace_for(finding_id=fid, reachable="reachable")
        return _benign_session_result(input_tokens=200, output_tokens=100)

    monkeypatch.setattr(
        trace_stage, "run_session",
        AsyncMock(side_effect=fake_run_session),
    )

    result = await trace_stage.run(
        run_id=run_id,
        repo=isolated_db,
        cfg=_minimal_cfg(isolated_db),
        session_factory=st_session.session_factory(),
    )

    assert result.outcome == "completed"
    assert result.findings_total == 1
    assert result.findings_traced == 1
    assert result.findings_reachable == 1
    assert result.findings_errored == 0
    assert result.input_tokens == 200
    assert result.output_tokens == 100


@pytest.mark.asyncio
async def test_trace_outcome_completed_without_record_trace(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per spec § Per-finding classification: completed but NO traces
    row -> findings_errored += 1 (the agent didn't follow the prompt).
    """
    run_id = str(ULID())
    _seed_run(run_id)
    task_id = _seed_task(run_id)
    _seed_finding(run_id=run_id, task_id=task_id)

    async def fake_run_session(**kw: object) -> SessionResult:
        # Do NOT insert a traces row.
        return _benign_session_result()

    monkeypatch.setattr(
        trace_stage, "run_session",
        AsyncMock(side_effect=fake_run_session),
    )

    result = await trace_stage.run(
        run_id=run_id,
        repo=isolated_db,
        cfg=_minimal_cfg(isolated_db),
        session_factory=st_session.session_factory(),
    )

    assert result.findings_total == 1
    assert result.findings_traced == 0
    assert result.findings_errored == 1


@pytest.mark.asyncio
async def test_trace_outcome_refused(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per spec § Per-finding classification: outcome='refused' ->
    findings_refused += 1."""
    run_id = str(ULID())
    _seed_run(run_id)
    task_id = _seed_task(run_id)
    _seed_finding(run_id=run_id, task_id=task_id)

    async def fake_run_session(**kw: object) -> SessionResult:
        return _benign_session_result(outcome="refused")

    monkeypatch.setattr(
        trace_stage, "run_session",
        AsyncMock(side_effect=fake_run_session),
    )

    result = await trace_stage.run(
        run_id=run_id,
        repo=isolated_db,
        cfg=_minimal_cfg(isolated_db),
        session_factory=st_session.session_factory(),
    )

    assert result.findings_refused == 1
    assert result.findings_errored == 0
    assert result.findings_traced == 0


@pytest.mark.asyncio
async def test_trace_outcome_errored(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per spec § Per-finding classification: outcome='errored' ->
    findings_errored += 1."""
    run_id = str(ULID())
    _seed_run(run_id)
    task_id = _seed_task(run_id)
    _seed_finding(run_id=run_id, task_id=task_id)

    async def fake_run_session(**kw: object) -> SessionResult:
        return _benign_session_result(outcome="errored")

    monkeypatch.setattr(
        trace_stage, "run_session",
        AsyncMock(side_effect=fake_run_session),
    )

    result = await trace_stage.run(
        run_id=run_id,
        repo=isolated_db,
        cfg=_minimal_cfg(isolated_db),
        session_factory=st_session.session_factory(),
    )

    assert result.findings_errored == 1
    assert result.findings_refused == 0
    assert result.findings_traced == 0


@pytest.mark.asyncio
async def test_trace_outcome_budget_exceeded(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per spec § Per-finding classification: outcome='budget_exceeded'
    -> findings_budget_exceeded += 1."""
    run_id = str(ULID())
    _seed_run(run_id)
    task_id = _seed_task(run_id)
    _seed_finding(run_id=run_id, task_id=task_id)

    async def fake_run_session(**kw: object) -> SessionResult:
        return _benign_session_result(outcome="budget_exceeded")

    monkeypatch.setattr(
        trace_stage, "run_session",
        AsyncMock(side_effect=fake_run_session),
    )

    result = await trace_stage.run(
        run_id=run_id,
        repo=isolated_db,
        cfg=_minimal_cfg(isolated_db),
        session_factory=st_session.session_factory(),
    )

    assert result.findings_budget_exceeded == 1
    assert result.findings_errored == 0
    assert result.findings_traced == 0


@pytest.mark.asyncio
async def test_trace_per_finding_failure_does_not_block_next(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per spec § Failure modes: per-finding failures are swallowed and
    counted; the stage as a whole completes regardless. A first errored
    finding must not stop the second finding's session from running.

    Chose the "no record_trace" path for the second finding so this test
    only exercises the failure-isolation invariant, not the
    classification of completed-with-record_trace (covered by
    test_trace_outcome_completed_with_record_trace).
    """
    run_id = str(ULID())
    _seed_run(run_id)
    task_id = _seed_task(run_id)
    _seed_finding(
        run_id=run_id, task_id=task_id, file="src/a.py",
    )
    fid_b = _seed_finding(
        run_id=run_id, task_id=task_id, file="src/b.py",
    )

    call_count = 0

    async def fake_run_session(**kw: object) -> SessionResult:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return _benign_session_result(outcome="errored")
        # Second call: write a trace row so this is classified as traced.
        _insert_trace_for(finding_id=fid_b, reachable="unreachable")
        return _benign_session_result(outcome="completed")

    monkeypatch.setattr(
        trace_stage, "run_session",
        AsyncMock(side_effect=fake_run_session),
    )

    result = await trace_stage.run(
        run_id=run_id,
        repo=isolated_db,
        cfg=_minimal_cfg(isolated_db),
        session_factory=st_session.session_factory(),
    )

    assert call_count == 2, "second finding's session must still run"
    assert result.findings_total == 2
    assert result.findings_errored == 1
    assert result.findings_traced == 1
    assert result.findings_unreachable == 1


@pytest.mark.asyncio
async def test_trace_tool_list_is_8_tools_in_order(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per docs/tool-contracts.md § Tool scope matrix: Trace = 8 tools
    (read_file, list_dir, grep, find_definition, find_callers,
    query_entry_points, query_findings, record_trace).

    The stage's _build_trace_tools returns SdkMcpTool objects each with
    a .name attribute. Capture the tools kwarg from the runtime stub and
    assert exact contents in declared order.
    """
    run_id = str(ULID())
    _seed_run(run_id)
    task_id = _seed_task(run_id)
    _seed_finding(run_id=run_id, task_id=task_id)

    captured_tools: list[list[Any]] = []

    async def fake_run_session(**kw: Any) -> SessionResult:
        captured_tools.append(list(kw["tools"]))
        return _benign_session_result()

    monkeypatch.setattr(
        trace_stage, "run_session",
        AsyncMock(side_effect=fake_run_session),
    )

    await trace_stage.run(
        run_id=run_id,
        repo=isolated_db,
        cfg=_minimal_cfg(isolated_db),
        session_factory=st_session.session_factory(),
    )

    assert len(captured_tools) == 1
    tools = captured_tools[0]
    assert len(tools) == 8
    names = [getattr(t, "name", "") for t in tools]
    assert names == [
        "read_file",
        "list_dir",
        "grep",
        "find_definition",
        "find_callers",
        "query_entry_points",
        "query_findings",
        "record_trace",
    ]


@pytest.mark.asyncio
async def test_trace_agent_sessions_row_shape(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per spec § State writes: agent_sessions rows for Trace set
    stage='trace', task_id IS NULL, finding_id IS NOT NULL and matches
    the seeded finding's id."""
    run_id = str(ULID())
    _seed_run(run_id)
    task_id = _seed_task(run_id)
    fid = _seed_finding(run_id=run_id, task_id=task_id)

    async def fake_run_session(**kw: object) -> SessionResult:
        return _benign_session_result()

    monkeypatch.setattr(
        trace_stage, "run_session",
        AsyncMock(side_effect=fake_run_session),
    )

    await trace_stage.run(
        run_id=run_id,
        repo=isolated_db,
        cfg=_minimal_cfg(isolated_db),
        session_factory=st_session.session_factory(),
    )

    # Snapshot the audit fields INSIDE the session scope; SQLAlchemy
    # expires ORM instances when the scope exits, so attribute access
    # outside the with-block triggers DetachedInstanceError.
    snapshots: list[tuple[str, str | None, str | None]] = []
    with st_session.session_scope() as s:
        rows = list(
            s.execute(
                select(AgentSession).where(
                    AgentSession.run_id == run_id,
                    AgentSession.stage == "trace",
                )
            ).scalars().all()
        )
        for row in rows:
            snapshots.append((row.stage, row.task_id, row.finding_id))

    assert len(snapshots) >= 1
    for stage_v, task_id_v, finding_id_v in snapshots:
        assert stage_v == "trace"
        assert task_id_v is None
        assert finding_id_v == fid


@pytest.mark.asyncio
async def test_trace_max_depth_substituted_in_prompt(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per spec / Task C: ``<max_depth>`` placeholder in
    prompts/system/trace.md is substituted with ``cfg.trace_max_depth``
    before the prompt is handed to run_session. Capture the
    system_prompt kwarg and assert the placeholder is gone and the
    numeric value is present."""
    run_id = str(ULID())
    _seed_run(run_id)
    task_id = _seed_task(run_id)
    _seed_finding(run_id=run_id, task_id=task_id)

    captured: list[str] = []

    async def fake_run_session(**kw: Any) -> SessionResult:
        captured.append(str(kw["system_prompt"]))
        return _benign_session_result()

    monkeypatch.setattr(
        trace_stage, "run_session",
        AsyncMock(side_effect=fake_run_session),
    )

    await trace_stage.run(
        run_id=run_id,
        repo=isolated_db,
        cfg=_minimal_cfg(isolated_db, trace_max_depth=12),
        session_factory=st_session.session_factory(),
    )

    assert len(captured) == 1
    prompt = captured[0]
    assert "12" in prompt
    assert "<max_depth>" not in prompt


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


def _orch_cfg(
    tmp_path: Path,
    *,
    trace_token_budget: int = 50_000,
    trace_max_depth: int = 8,
) -> Config:
    return Config(
        repo_root=tmp_path,
        model="claude-opus-4-7",
        recon_token_budget=200_000,
        hunt_token_budget=200_000,
        validate_token_budget=100_000,
        gapfill_token_budget=50_000,
        dedupe_token_budget=50_000,
        trace_token_budget=trace_token_budget,
        trace_max_depth=trace_max_depth,
        auth_env={"ANTHROPIC_API_KEY": "sk-test"},
    )


def test_config_for_run_row_includes_trace_token_budget_and_max_depth(
    tmp_path: Path,
) -> None:
    """Per spec § orchestrator.run_scan extension: trace_token_budget and
    trace_max_depth are persisted in runs.config_json."""
    cfg = _orch_cfg(tmp_path, trace_token_budget=12_345, trace_max_depth=15)
    payload = json.loads(orchestrator._config_for_run_row(cfg))
    assert payload["trace_token_budget"] == 12_345
    assert payload["trace_max_depth"] == 15


def test_budget_used_sums_trace_tokens(
    fresh_db: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """runs.budget_used must include Trace tokens.

    Mirrors test_orchestrator.test_orchestrator_budget_used_includes_gapfill_tokens
    and v0.8's test_budget_used_sums_dedupe_tokens — the same end-to-end
    stub-the-stages pattern, asserting the arithmetic includes
    trace_result.input_tokens + output_tokens. With Trace landed there
    are now 12 token terms total (6 stages x in+out).
    """
    from flosswing.index.build import IndexBuildResult
    from flosswing.stages import dedupe as dedupe_stage
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
            input_tokens=10,
            output_tokens=5,
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
        # Insert a confirmed primary finding so the orchestrator's
        # trace_eligible_count gate sees >= 1 row and calls Trace.
        run_id = str(kwargs["run_id"])  # orchestrator passes run_id kwarg
        with st_session.session_scope() as s:
            task = s.execute(
                select(HuntTask).where(HuntTask.run_id == run_id)
            ).scalar_one_or_none()
            if task is None:
                # No hunt_tasks rows are produced by the recon stub; seed
                # one minimal row so the FK on Finding.hunt_task_id holds.
                task_id = str(ULID())
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
                        findings_count=1,
                    )
                )
            else:
                task_id = task.id
        with st_session.session_scope() as s:
            s.add(
                Finding(
                    id=str(ULID()),
                    run_id=run_id,
                    hunt_task_id=task_id,
                    attack_class="command_injection",
                    file="src/a.py",
                    function="some_fn",
                    line_start=10,
                    line_end=12,
                    severity="high",
                    confidence="likely",
                    status="confirmed",
                    title="command_injection in src/a.py",
                    description=(
                        "A reasonable description, fifty chars or more."
                    ),
                    poc_code=None,
                    poc_result_json=None,
                    suggested_fix=None,
                    created_at=_now_iso(),
                    dedupe_role=None,
                )
            )
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
            variants_linked=0,
            input_tokens=400,
            output_tokens=120,
        )

    async def fake_trace(**kwargs: object) -> TraceStageResult:
        return TraceStageResult(
            outcome="completed",
            findings_total=1,
            findings_traced=1,
            findings_reachable=1,
            input_tokens=500,
            output_tokens=130,
        )

    monkeypatch.setattr(recon_stage, "run", fake_recon)
    monkeypatch.setattr(index_build_stage, "run", fake_index_build)
    monkeypatch.setattr(hunt_stage, "run", fake_hunt)
    monkeypatch.setattr(validate_stage, "run", fake_validate)
    monkeypatch.setattr(gapfill_stage, "run", fake_gapfill)
    monkeypatch.setattr(dedupe_stage, "run", fake_dedupe)
    monkeypatch.setattr(trace_stage, "run", fake_trace)

    asyncio.run(orchestrator.run_scan(_orch_cfg(tmp_path)))

    with st_session.session_scope() as s:
        rows = s.query(Run).all()
        assert len(rows) == 1
        # recon (10+5) + hunt (100+50) + validate (200+100)
        # + gapfill (300+80) + dedupe (400+120) + trace (500+130) = 1995
        assert rows[0].budget_used == 1995


def test_trace_gated_on_confirmed_primary_count(
    fresh_db: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per spec § orchestrator.run_scan extension: Trace runs only when
    >=1 confirmed primary finding exists. With zero such findings the
    orchestrator skips stages.trace.run entirely; with >=1 it calls it.

    Two scenarios in one test: monkeypatch stages.trace.run to record
    invocation; flip a per-scenario state insertion.
    """
    from flosswing.index.build import IndexBuildResult
    from flosswing.stages import dedupe as dedupe_stage
    from flosswing.stages import gapfill as gapfill_stage
    from flosswing.stages import hunt as hunt_stage
    from flosswing.stages import index_build as index_build_stage
    from flosswing.stages import recon as recon_stage
    from flosswing.stages import validate as validate_stage

    # Shared stubs for every scenario.
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

    # Per-scenario findings-seeding switch.
    seed_confirmed_primary = {"enabled": False}

    async def fake_hunt(**kwargs: object) -> HuntStageResult:
        # Hunt produces a finding count >=1 so Validate runs and the
        # orchestrator's trace-eligible query has something to look at.
        return HuntStageResult(
            tasks_processed=1,
            tasks_succeeded=1,
            tasks_refused=0,
            tasks_budget_exceeded=0,
            tasks_errored=0,
            findings_total=1,
            input_tokens_total=0,
            output_tokens_total=0,
        )

    async def fake_validate(**kwargs: object) -> ValidateStageResult:
        # Optionally seed a confirmed primary finding so the trace gate
        # query returns >= 1. Either way, return a stub ValidateResult.
        if seed_confirmed_primary["enabled"]:
            run_id = str(kwargs["run_id"])
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
                        findings_count=1,
                    )
                )
            with st_session.session_scope() as s:
                s.add(
                    Finding(
                        id=str(ULID()),
                        run_id=run_id,
                        hunt_task_id=task_id,
                        attack_class="command_injection",
                        file="src/a.py",
                        function="some_fn",
                        line_start=10,
                        line_end=12,
                        severity="high",
                        confidence="likely",
                        status="confirmed",
                        title="command_injection in src/a.py",
                        description=(
                            "A reasonable description, fifty chars or more."
                        ),
                        poc_code=None,
                        poc_result_json=None,
                        suggested_fix=None,
                        created_at=_now_iso(),
                        dedupe_role=None,
                    )
                )
        return ValidateStageResult(
            findings_processed=1,
            findings_confirmed=(
                1 if seed_confirmed_primary["enabled"] else 0
            ),
            findings_rejected=(
                0 if seed_confirmed_primary["enabled"] else 1
            ),
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
        return DedupeStageResult(outcome="completed")

    trace_called: list[bool] = []

    async def fake_trace(**kwargs: object) -> TraceStageResult:
        trace_called.append(True)
        return TraceStageResult(outcome="completed", findings_total=1)

    monkeypatch.setattr(recon_stage, "run", fake_recon)
    monkeypatch.setattr(index_build_stage, "run", fake_index_build)
    monkeypatch.setattr(hunt_stage, "run", fake_hunt)
    monkeypatch.setattr(validate_stage, "run", fake_validate)
    monkeypatch.setattr(gapfill_stage, "run", fake_gapfill)
    monkeypatch.setattr(dedupe_stage, "run", fake_dedupe)
    monkeypatch.setattr(trace_stage, "run", fake_trace)

    # Scenario 1: zero confirmed primaries -> Trace MUST NOT be called.
    seed_confirmed_primary["enabled"] = False
    asyncio.run(orchestrator.run_scan(_orch_cfg(tmp_path)))
    assert trace_called == []

    # Scenario 2: >= 1 confirmed primary -> Trace MUST be called.
    seed_confirmed_primary["enabled"] = True
    asyncio.run(orchestrator.run_scan(_orch_cfg(tmp_path)))
    assert trace_called == [True]


@pytest.mark.asyncio
async def test_trace_session_crash_clears_heartbeat(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A per-finding session that raises mid-flight must still clear the live
    heartbeat (exercises trace.py's crash-recovery except path)."""
    from flosswing.agent.providers.base import UsageSnapshot
    from flosswing.state.models import SessionHeartbeat

    run_id = str(ULID())
    _seed_run(run_id)
    task_id = _seed_task(run_id)
    _seed_finding(run_id=run_id, task_id=task_id)

    async def fake_run_session(**kw: object) -> SessionResult:
        on_usage = kw["on_usage"]
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
        raise RuntimeError("session blew up mid-flight")

    monkeypatch.setattr(
        trace_stage, "run_session", AsyncMock(side_effect=fake_run_session)
    )

    result = await trace_stage.run(
        run_id=run_id,
        repo=isolated_db,
        cfg=_minimal_cfg(isolated_db),
        session_factory=st_session.session_factory(),
    )
    assert result.findings_errored == 1
    with st_session.session_scope() as s:
        assert s.execute(select(SessionHeartbeat)).scalars().all() == []
