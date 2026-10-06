# FlossWing — local-CLI vulnerability research harness.
# Copyright (C) 2026  FlossWing contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""OpenAICodexProvider.run_session — stage->scope + ctx assembly + event
reduction, with the subprocess/app-server I/O boundary (``_drive_turn``)
mocked. ``_drive_turn`` itself is exercised only by the gated Task 9
integration test; it is never launched here.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from ulid import ULID

from flosswing.agent.providers import openai_codex as oc
from flosswing.state import session as st_session
from flosswing.state.models import HuntTask, Run

FIX = Path(__file__).parent.parent / "fixtures" / "codex"


def _sc_events(name: str) -> list[dict[str, Any]]:
    """Replay the server->client messages of a committed app-server fixture."""
    out: list[dict[str, Any]] = []
    for line in (FIX / name).read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
        if rec.get("dir") == "S->C":
            out.append(rec["msg"])
    return out


# -----------------------------------------------------------------------------
# run_session: event reduction with _drive_turn mocked
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_session_completes(monkeypatch: pytest.MonkeyPatch) -> None:
    events = _sc_events("round_trip.jsonl")

    async def fake_drive(**kw: Any) -> list[dict[str, Any]]:
        return events

    monkeypatch.setattr(oc, "_drive_turn", fake_drive)
    monkeypatch.setattr(
        oc, "_build_server_args", lambda **kw: ["--run-id", "r", "--repo-root", "/repo"]
    )
    r = await oc.OpenAICodexProvider().run_session(
        model="gpt-daybreak-blue-latest",
        system_prompt="",
        tools=[],
        user_prompt="",
        token_budget=10_000_000,
        auth_env={},
        run_id="r",
        stage="recon",
    )
    assert r.outcome == "completed"
    assert r.cost_usd is None
    assert r.tool_calls_count >= 1
    assert r.duration_ms >= 0


@pytest.mark.asyncio
async def test_run_session_emits_usage(monkeypatch: pytest.MonkeyPatch) -> None:
    events = _sc_events("round_trip.jsonl")

    async def fake_drive(**kw: Any) -> list[dict[str, Any]]:
        return events

    monkeypatch.setattr(oc, "_drive_turn", fake_drive)
    monkeypatch.setattr(
        oc, "_build_server_args", lambda **kw: ["--run-id", "r", "--repo-root", "/repo"]
    )
    snaps: list[Any] = []
    await oc.OpenAICodexProvider().run_session(
        model="gpt-daybreak-blue-latest",
        system_prompt="",
        tools=[],
        user_prompt="",
        token_budget=10_000_000,
        auth_env={},
        run_id="r",
        stage="recon",
        on_usage=snaps.append,
    )
    assert snaps and snaps[-1].input_tokens > 0
    assert snaps[-1].cost_usd is None


@pytest.mark.asyncio
async def test_run_session_refusal_maps_to_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events = _sc_events("refusal.jsonl")

    async def fake_drive(**kw: Any) -> list[dict[str, Any]]:
        return events

    monkeypatch.setattr(oc, "_drive_turn", fake_drive)
    monkeypatch.setattr(
        oc, "_build_server_args", lambda **kw: ["--run-id", "r", "--repo-root", "/repo"]
    )
    r = await oc.OpenAICodexProvider().run_session(
        model="gpt-daybreak-blue-latest",
        system_prompt="",
        tools=[],
        user_prompt="",
        token_budget=10_000_000,
        auth_env={},
        run_id="r",
        stage="recon",
    )
    assert r.outcome == "refused"
    assert r.refusal_text


@pytest.mark.asyncio
async def test_run_session_passes_scope_and_ctx_to_drive_turn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    async def fake_drive(**kw: Any) -> list[dict[str, Any]]:
        captured.update(kw)
        return _sc_events("round_trip.jsonl")

    monkeypatch.setattr(oc, "_drive_turn", fake_drive)
    monkeypatch.setattr(
        oc,
        "_build_server_args",
        lambda **kw: ["--run-id", kw["run_id"], "--repo-root", "/repo",
                      "--hunt-task-id", kw["task_id"]],
    )
    await oc.OpenAICodexProvider().run_session(
        model="gpt-daybreak-blue-latest",
        system_prompt="SYS",
        tools=[object()],
        user_prompt="go",
        token_budget=10_000,
        auth_env={"ANTHROPIC_API_KEY": "x"},
        run_id="run1",
        stage="hunt",
        task_id="task1",
    )
    assert captured["scope"] == "hunt"
    assert captured["model"] == "gpt-daybreak-blue-latest"
    assert captured["system_prompt"] == "SYS"
    assert captured["user_prompt"] == "go"
    assert captured["ctx"] == [
        "--run-id", "run1", "--repo-root", "/repo", "--hunt-task-id", "task1",
    ]


# -----------------------------------------------------------------------------
# stage -> scope mapping (pure)
# -----------------------------------------------------------------------------


def test_stage_to_scope_identity() -> None:
    for s in ("recon", "hunt", "validate", "dedupe", "trace", "gapfill"):
        assert oc._stage_to_scope(s) == s


def test_stage_to_scope_rejects_unknown() -> None:
    with pytest.raises(ValueError):
        oc._stage_to_scope("index_build")


# -----------------------------------------------------------------------------
# OP-1: ctx assembly from the state DB by run_id
# -----------------------------------------------------------------------------


@pytest.fixture()
def fresh_db(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("FLOSSWING_DB_URL", "sqlite:///:memory:")
    st_session._cached_engine = None  # type: ignore[attr-defined]
    st_session._cached_session_factory = None  # type: ignore[attr-defined]
    yield
    st_session._cached_engine = None  # type: ignore[attr-defined]
    st_session._cached_session_factory = None  # type: ignore[attr-defined]


def _seed_run(run_id: str, *, config_json: str = "{}") -> None:
    with st_session.session_scope() as s:
        s.add(
            Run(
                id=run_id,
                target_repo_path="/tmp/target-repo",
                depth="standard",
                budget_total=20,
                started_at="2026-10-06T00:00:00Z",
                config_json=config_json,
                flosswing_version="0.0.0",
            )
        )


def _seed_recon_tasks(run_id: str, n: int) -> None:
    with st_session.session_scope() as s:
        for _ in range(n):
            s.add(
                HuntTask(
                    id=str(ULID()),
                    run_id=run_id,
                    attack_class="command_injection",
                    scope_hint="src/",
                    rationale="",
                    priority="normal",
                    source="recon",
                    parent_finding_id=None,
                    status="pending",
                    created_at="2026-10-06T00:00:00Z",
                    findings_count=0,
                )
            )


def test_build_server_args_recon(fresh_db: None) -> None:
    rid = str(ULID())
    _seed_run(rid)
    args = oc._build_server_args(
        scope="recon", run_id=rid, task_id=None, agent_session_id=None
    )
    assert args == [
        "--run-id", rid, "--repo-root", "/tmp/target-repo", "--budget-total", "20",
    ]


def test_build_server_args_hunt(fresh_db: None) -> None:
    rid = str(ULID())
    _seed_run(rid)
    args = oc._build_server_args(
        scope="hunt", run_id=rid, task_id="t42", agent_session_id=None
    )
    assert args == [
        "--run-id", rid, "--repo-root", "/tmp/target-repo", "--hunt-task-id", "t42",
    ]


def test_build_server_args_validate_and_trace(fresh_db: None) -> None:
    rid = str(ULID())
    _seed_run(rid)
    for scope in ("validate", "trace"):
        args = oc._build_server_args(
            scope=scope, run_id=rid, task_id=None, agent_session_id="sess9"
        )
        assert args == [
            "--run-id", rid, "--repo-root", "/tmp/target-repo",
            "--agent-session-id", "sess9",
        ]


def test_build_server_args_dedupe_has_no_extras(fresh_db: None) -> None:
    rid = str(ULID())
    _seed_run(rid)
    args = oc._build_server_args(
        scope="dedupe", run_id=rid, task_id=None, agent_session_id=None
    )
    assert args == ["--run-id", rid, "--repo-root", "/tmp/target-repo"]


def test_build_server_args_gapfill(fresh_db: None) -> None:
    rid = str(ULID())
    # Mirrors orchestrator config_json: four per-stage token budgets present.
    cfg = json.dumps(
        {
            "recon_token_budget": 200_000,
            "hunt_token_budget": 200_000,
            "validate_token_budget": 100_000,
            "gapfill_token_budget": 50_000,
        }
    )
    _seed_run(rid, config_json=cfg)
    _seed_recon_tasks(rid, 12)  # cap = max(1, 12 // 5) = 2
    args = oc._build_server_args(
        scope="gapfill", run_id=rid, task_id=None, agent_session_id=None
    )
    assert args == [
        "--run-id", rid, "--repo-root", "/tmp/target-repo",
        "--gapfill-new-task-cap", "2",
        "--budget-total", "20",
        "--total-token-budget", "550000",
    ]


def test_build_server_args_missing_run_raises(fresh_db: None) -> None:
    with pytest.raises(RuntimeError, match="not found"):
        oc._build_server_args(
            scope="recon", run_id="nope", task_id=None, agent_session_id=None
        )


def test_build_server_args_gapfill_unrecoverable_total_raises(fresh_db: None) -> None:
    rid = str(ULID())
    _seed_run(rid, config_json="{}")  # no token-budget keys
    with pytest.raises(RuntimeError, match="total_token_budget"):
        oc._build_server_args(
            scope="gapfill", run_id=rid, task_id=None, agent_session_id=None
        )


@pytest.mark.asyncio
async def test_run_session_assembles_ctx_from_db(
    fresh_db: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    rid = str(ULID())
    _seed_run(rid)
    captured: dict[str, Any] = {}

    async def fake_drive(**kw: Any) -> list[dict[str, Any]]:
        captured.update(kw)
        return _sc_events("round_trip.jsonl")

    monkeypatch.setattr(oc, "_drive_turn", fake_drive)
    r = await oc.OpenAICodexProvider().run_session(
        model="gpt-daybreak-blue-latest",
        system_prompt="",
        tools=[],
        user_prompt="",
        token_budget=10_000_000,
        auth_env={},
        run_id=rid,
        stage="hunt",
        task_id="the-task",
    )
    assert r.outcome == "completed"
    assert captured["scope"] == "hunt"
    assert captured["ctx"] == [
        "--run-id", rid, "--repo-root", "/tmp/target-repo", "--hunt-task-id", "the-task",
    ]
