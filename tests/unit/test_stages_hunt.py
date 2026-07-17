"""stages/hunt.py: per-task orchestration with stubbed runtime.

Stubs runtime.run_session to canned (completed | refused |
budget_exceeded | errored) sessions and asserts:
  - pending tasks for the run are processed in priority/order
  - per-task agent_sessions rows are inserted with correct fields
  - per-task hunt_tasks status transitions are correct
  - HuntStageResult totals are correct

Per docs/specs/2026-06-02-v0.3-hunt-plumbing-design.md § Testing
strategy.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import select
from ulid import ULID

from flosswing.agent.runtime import SessionResult
from flosswing.config import Config
from flosswing.prompts import load_attack_class_fragment
from flosswing.stages import hunt
from flosswing.state import session as st_session
from flosswing.state.models import AgentSession, Finding, HuntTask, Run


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def test_shared_loader_returns_authored_fragment() -> None:
    from flosswing.prompts import load_attack_class_fragment

    assert "Attack class: command_injection" in load_attack_class_fragment(
        "command_injection"
    )


def test_shared_loader_falls_back_for_unauthored_class() -> None:
    from flosswing.prompts import load_attack_class_fragment

    # Every *registered* class now ships an authored fragment (see
    # test_attack_classes.test_every_registry_class_has_authored_fragment),
    # so the fallback only fires for a well-formed but unknown class name.
    assert "No attack-class-specific guidance" in load_attack_class_fragment(
        "some_unauthored_future_class"
    )


def test_shared_loader_rejects_path_traversal() -> None:
    from flosswing.prompts import load_attack_class_fragment

    # attack_class is free-text DB input; a traversal payload must not read
    # an out-of-tree file — it falls back to the generic fragment instead.
    for evil in ("../../etc/passwd", "..", "a/b", "command_injection/../x"):
        assert "No attack-class-specific guidance" in load_attack_class_fragment(evil)


@pytest.fixture()
def fresh_db_with_tasks(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> Iterator[tuple[str, list[str], Path]]:
    """Seed a run with three pending hunt_tasks of varying priority."""
    monkeypatch.setenv("FLOSSWING_DB_URL", "sqlite:///:memory:")
    st_session._cached_engine = None  # type: ignore[attr-defined]
    st_session._cached_session_factory = None  # type: ignore[attr-defined]
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "x.py").write_text("pass\n", encoding="utf-8")

    run_id = str(ULID())
    task_ids: list[str] = []
    with st_session.session_scope() as s:
        s.add(
            Run(
                id=run_id,
                target_repo_path=str(repo),
                depth="standard",
                budget_total=20,
                started_at=_now(),
                config_json="{}",
                flosswing_version="0.3.0",
            )
        )
        # Flush the Run before inserting child HuntTask rows so SQLite's
        # FK enforcement (pragma is ON) doesn't reject the executemany
        # batch when the unit-of-work orders inserts unpredictably.
        s.flush()
        for ac, scope, priority in [
            ("command_injection", "src/x.py", "high"),
            ("sqli", "src/", "normal"),
            ("xss", "src/", "low"),
        ]:
            tid = str(ULID())
            task_ids.append(tid)
            s.add(
                HuntTask(
                    id=tid,
                    run_id=run_id,
                    attack_class=ac,
                    scope_hint=scope,
                    rationale="seeded by test",
                    priority=priority,
                    source="recon",
                    status="pending",
                    created_at=_now(),
                    findings_count=0,
                )
            )
    yield run_id, task_ids, repo
    st_session._cached_engine = None  # type: ignore[attr-defined]
    st_session._cached_session_factory = None  # type: ignore[attr-defined]


def _cfg(repo: Path) -> Config:
    return Config(
        repo_root=repo,
        model="claude-opus-4-7",
        recon_token_budget=200_000,
        hunt_token_budget=200_000,
        validate_token_budget=200_000,
        gapfill_token_budget=1_000_000,
        auth_env={"ANTHROPIC_API_KEY": "sk-test"},
    )


@pytest.mark.asyncio
async def test_hunt_processes_all_pending_tasks_in_priority_order(
    fresh_db_with_tasks: tuple[str, list[str], Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id, _task_ids, repo = fresh_db_with_tasks
    seen_order: list[str] = []

    async def fake_run_session(**kwargs: object) -> SessionResult:
        user_prompt = str(kwargs.get("user_prompt", ""))
        for line in user_prompt.splitlines():
            if line.startswith("Attack class:"):
                seen_order.append(line.split(":", 1)[1].strip())
                break
        return SessionResult(
            outcome="completed",
            input_tokens=500,
            output_tokens=100,
            cache_read_tokens=0,
            cache_write_tokens=0,
            duration_ms=10,
            tool_calls_count=0,
            refusal_text=None,
            error_text=None,
        )

    monkeypatch.setattr(hunt, "run_session", fake_run_session)
    result = await hunt.run(
        run_id=run_id,
        repo=repo,
        cfg=_cfg(repo),
        session_factory=st_session.session_factory(),
    )

    assert result.tasks_processed == 3
    assert result.tasks_succeeded == 3
    assert seen_order == ["command_injection", "sqli", "xss"]


@pytest.mark.asyncio
async def test_hunt_records_one_agent_session_per_task(
    fresh_db_with_tasks: tuple[str, list[str], Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id, _task_ids, repo = fresh_db_with_tasks
    from flosswing.agent.providers.base import UsageSnapshot
    from flosswing.state.models import SessionHeartbeat

    async def fake_run_session(**kwargs: object) -> SessionResult:
        # The stage must pass a usable on_usage callback; invoke it to write
        # the in-flight heartbeat, which finalize must then clear.
        on_usage = kwargs.get("on_usage")
        assert callable(on_usage)
        on_usage(
            UsageSnapshot(
                input_tokens=1234,
                output_tokens=56,
                cache_read_tokens=0,
                cache_write_tokens=0,
                tool_calls_count=2,
                cost_usd=None,
            )
        )
        return SessionResult(
            outcome="completed",
            input_tokens=1234,
            output_tokens=56,
            cache_read_tokens=0,
            cache_write_tokens=0,
            duration_ms=99,
            tool_calls_count=2,
            refusal_text=None,
            error_text=None,
        )

    monkeypatch.setattr(hunt, "run_session", fake_run_session)
    await hunt.run(
        run_id=run_id,
        repo=repo,
        cfg=_cfg(repo),
        session_factory=st_session.session_factory(),
    )

    with st_session.session_scope() as s:
        sessions = (
            s.execute(select(AgentSession).where(AgentSession.stage == "hunt"))
            .scalars()
            .all()
        )
        assert len(sessions) == 3
        for sess in sessions:
            assert sess.task_id is not None
            assert sess.outcome == "completed"
            assert sess.input_tokens == 1234
        # Every task's finalize cleared the heartbeat — none linger.
        assert s.execute(select(SessionHeartbeat)).scalars().all() == []


@pytest.mark.asyncio
async def test_hunt_task_status_transitions_completed(
    fresh_db_with_tasks: tuple[str, list[str], Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id, task_ids, repo = fresh_db_with_tasks

    async def fake_run_session(**kwargs: object) -> SessionResult:
        return SessionResult(
            outcome="completed",
            input_tokens=100,
            output_tokens=10,
            cache_read_tokens=0,
            cache_write_tokens=0,
            duration_ms=1,
            tool_calls_count=0,
            refusal_text=None,
            error_text=None,
        )

    monkeypatch.setattr(hunt, "run_session", fake_run_session)
    await hunt.run(
        run_id=run_id,
        repo=repo,
        cfg=_cfg(repo),
        session_factory=st_session.session_factory(),
    )

    with st_session.session_scope() as s:
        for tid in task_ids:
            row = s.get(HuntTask, tid)
            assert row is not None
            assert row.status == "completed"
            assert row.started_at is not None
            assert row.finished_at is not None


@pytest.mark.asyncio
async def test_hunt_task_status_refused_per_task(
    fresh_db_with_tasks: tuple[str, list[str], Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id, task_ids, repo = fresh_db_with_tasks

    async def fake_run_session(**kwargs: object) -> SessionResult:
        return SessionResult(
            outcome="refused",
            input_tokens=10,
            output_tokens=5,
            cache_read_tokens=0,
            cache_write_tokens=0,
            duration_ms=1,
            tool_calls_count=0,
            refusal_text="I can't help with that.",
            error_text=None,
        )

    monkeypatch.setattr(hunt, "run_session", fake_run_session)
    result = await hunt.run(
        run_id=run_id,
        repo=repo,
        cfg=_cfg(repo),
        session_factory=st_session.session_factory(),
    )
    assert result.tasks_refused == 3
    assert result.tasks_succeeded == 0

    with st_session.session_scope() as s:
        for tid in task_ids:
            t = s.get(HuntTask, tid)
            assert t is not None
            assert t.status == "refused"
        sess = (
            s.execute(select(AgentSession).where(AgentSession.stage == "hunt"))
            .scalars()
            .all()
        )
        for row in sess:
            assert row.outcome == "refused"
            assert row.refusal_text == "I can't help with that."


@pytest.mark.asyncio
async def test_hunt_task_status_budget_exceeded(
    fresh_db_with_tasks: tuple[str, list[str], Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id, task_ids, repo = fresh_db_with_tasks

    async def fake_run_session(**kwargs: object) -> SessionResult:
        return SessionResult(
            outcome="budget_exceeded",
            input_tokens=300_000,
            output_tokens=0,
            cache_read_tokens=0,
            cache_write_tokens=0,
            duration_ms=1,
            tool_calls_count=0,
            refusal_text=None,
            error_text=None,
        )

    monkeypatch.setattr(hunt, "run_session", fake_run_session)
    result = await hunt.run(
        run_id=run_id,
        repo=repo,
        cfg=_cfg(repo),
        session_factory=st_session.session_factory(),
    )
    assert result.tasks_budget_exceeded == 3
    with st_session.session_scope() as s:
        for tid in task_ids:
            row = s.get(HuntTask, tid)
            assert row is not None
            assert row.status == "budget_exceeded"


@pytest.mark.asyncio
async def test_hunt_task_status_errored(
    fresh_db_with_tasks: tuple[str, list[str], Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id, task_ids, repo = fresh_db_with_tasks

    async def fake_run_session(**kwargs: object) -> SessionResult:
        return SessionResult(
            outcome="errored",
            input_tokens=0,
            output_tokens=0,
            cache_read_tokens=0,
            cache_write_tokens=0,
            duration_ms=1,
            tool_calls_count=0,
            refusal_text=None,
            error_text="API 500",
        )

    monkeypatch.setattr(hunt, "run_session", fake_run_session)
    result = await hunt.run(
        run_id=run_id,
        repo=repo,
        cfg=_cfg(repo),
        session_factory=st_session.session_factory(),
    )
    assert result.tasks_errored == 3
    with st_session.session_scope() as s:
        for tid in task_ids:
            row = s.get(HuntTask, tid)
            assert row is not None
            assert row.status == "errored"


@pytest.mark.asyncio
async def test_hunt_findings_total_in_result(
    fresh_db_with_tasks: tuple[str, list[str], Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sessions that write findings rows feed the HuntStageResult total."""
    run_id, task_ids, repo = fresh_db_with_tasks

    async def fake_run_session(**kwargs: object) -> SessionResult:
        # Simulate the agent writing one finding through the registry.
        with st_session.session_scope() as s:
            s.add(
                Finding(
                    id=str(ULID()),
                    run_id=run_id,
                    hunt_task_id=task_ids[0],  # all credited to the first task
                    attack_class="command_injection",
                    file="src/x.py",
                    line_start=1,
                    line_end=1,
                    severity="high",
                    confidence="likely",
                    title="t",
                    description="d",
                    created_at=_now(),
                )
            )
        return SessionResult(
            outcome="completed",
            input_tokens=10,
            output_tokens=5,
            cache_read_tokens=0,
            cache_write_tokens=0,
            duration_ms=1,
            tool_calls_count=1,
            refusal_text=None,
            error_text=None,
        )

    monkeypatch.setattr(hunt, "run_session", fake_run_session)
    result = await hunt.run(
        run_id=run_id,
        repo=repo,
        cfg=_cfg(repo),
        session_factory=st_session.session_factory(),
    )
    assert result.findings_total == 3  # one per task, all credited via fake


def test_attack_class_fragment_loader_returns_seeded_class() -> None:
    text = load_attack_class_fragment("command_injection")
    assert "command_injection" in text.lower() or "shell" in text.lower()


def test_attack_class_fragment_loader_falls_back_for_unknown() -> None:
    text = load_attack_class_fragment("buffer_overflow")
    assert "speculative" in text.lower()


def test_hunt_tool_registration_includes_symbol_tools(tmp_path: Path) -> None:
    """Per docs/specs/2026-06-02-v0.5-symbol-index-design.md § Tool scoping:
    Hunt's tool list gains find_definition + find_callers in v0.5.
    """
    from flosswing.stages.hunt import _build_hunt_tools

    tools = _build_hunt_tools(
        repo_root=tmp_path, run_id="01RUN", hunt_task_id="01TASK"
    )
    tool_names = {getattr(t, "name", None) or t.__name__ for t in tools}
    assert "read_file" in tool_names
    assert "list_dir" in tool_names
    assert "grep" in tool_names
    assert "record_finding" in tool_names
    assert "find_definition" in tool_names
    assert "find_callers" in tool_names
    # query_entry_points is Trace-only — NOT registered in Hunt.
    assert "query_entry_points" not in tool_names
    assert len(tools) == 6


@pytest.mark.asyncio
async def test_hunt_find_definition_tool_returns_ok_for_known_symbol(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from flosswing.stages.hunt import _build_hunt_tools
    from flosswing.state.models import Symbol

    monkeypatch.setenv("FLOSSWING_DB_URL", f"sqlite:///{tmp_path}/state.db")
    st_session._cached_engine = None  # type: ignore[attr-defined]
    st_session._cached_session_factory = None  # type: ignore[attr-defined]

    run_id = str(ULID())
    with st_session.session_scope() as s:
        s.add(
            Run(
                id=run_id,
                target_repo_path=str(tmp_path),
                target_repo_sha=None,
                depth="standard",
                budget_total=20,
                budget_used=0,
                started_at="2026-06-02T00:00:00Z",
                status="running",
                config_json="{}",
                flosswing_version="0.5.0",
            )
        )
        s.flush()
        s.add(
            Symbol(
                id=str(ULID()),
                run_id=run_id,
                symbol="greet",
                fully_qualified_name="src.cli.greet",
                file="src/cli.py",
                line_start=10,
                line_end=12,
                kind="function",
                language="python",
            )
        )

    tools = _build_hunt_tools(
        repo_root=tmp_path, run_id=run_id, hunt_task_id="01TASK"
    )
    find_def_tool = next(
        t
        for t in tools
        if (getattr(t, "name", None) or getattr(t, "__name__", ""))
        == "find_definition"
    )
    out = await find_def_tool.handler({"symbol": "greet"})
    assert out.get("is_error") is not True
    text = out["content"][0]["text"]
    assert "greet" in text
    assert "src/cli.py" in text

    st_session._cached_engine = None  # type: ignore[attr-defined]
    st_session._cached_session_factory = None  # type: ignore[attr-defined]
