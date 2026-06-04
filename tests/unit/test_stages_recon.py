"""stages/recon.py: orchestrator wiring with stubbed runtime."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import select
from ulid import ULID

from flosswing.agent.runtime import SessionResult
from flosswing.config import Config
from flosswing.stages import recon
from flosswing.state import session as st_session
from flosswing.state.models import AgentSession, HuntTask, ReconArtifact, Run


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


@pytest.mark.asyncio
async def test_recon_stage_records_session_and_returns_summary(
    fresh_db: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Stub the runtime to simulate a successful session that "wrote"
    # one recon artifact and one hunt task to the DB during its run.
    async def fake_run_session(**kwargs: object) -> SessionResult:
        from flosswing.tools.findings import (
            AddHuntTaskInput,
            RecordReconArtifactInput,
            add_hunt_task,
            record_recon_artifact,
        )

        record_recon_artifact(
            RecordReconArtifactInput(
                languages=["python"],
                build_commands={"primary": "pip install ."},
                entry_points=[],
                trust_boundaries=[],
                subsystems=[],
                notes="stub",
            ),
            run_id=fresh_db,
        )
        add_hunt_task(
            AddHuntTaskInput(
                attack_class="command_injection",
                scope_hint="src/",
                rationale="stub",
            ),
            run_id=fresh_db,
            source="recon",
            budget_total=20,
        )
        return SessionResult(
            outcome="completed",
            input_tokens=1000,
            output_tokens=200,
            cache_read_tokens=0,
            cache_write_tokens=0,
            duration_ms=42,
            tool_calls_count=2,
            refusal_text=None,
            error_text=None,
        )

    monkeypatch.setattr(recon, "run_session", fake_run_session)

    cfg = Config(
        repo_root=tmp_path,
        model="claude-opus-4-7",
        recon_token_budget=200_000,
        hunt_token_budget=200_000,
        validate_token_budget=200_000,
        auth_env={"ANTHROPIC_API_KEY": "sk-test"},
    )

    result = await recon.run(run_id=fresh_db, cfg=cfg)

    assert result.outcome == "completed"
    assert result.recon_artifact_recorded is True
    assert result.hunt_tasks_queued >= 1

    with st_session.session_scope() as s:
        rows = s.execute(select(AgentSession)).scalars().all()
        assert len(rows) == 1
        assert rows[0].stage == "recon"
        assert rows[0].outcome == "completed"
        assert rows[0].input_tokens == 1000
        assert s.query(ReconArtifact).count() == 1
        assert s.query(HuntTask).count() == 1
