"""flosswing.stages.index_build — orchestrator-stage wrapper for IndexBuild.

Per docs/specs/2026-06-02-v0.5-symbol-index-design.md § Component
responsibilities flosswing/stages/index_build.py.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from ulid import ULID

from flosswing.config import Config
from flosswing.stages import index_build as ib_stage
from flosswing.state import session as st_session
from flosswing.state.models import ReconArtifact, Run


@pytest.fixture()
def isolated_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("FLOSSWING_DB_URL", f"sqlite:///{tmp_path}/state.db")
    monkeypatch.setattr(st_session, "_cached_engine", None, raising=False)
    monkeypatch.setattr(
        st_session, "_cached_session_factory", None, raising=False
    )
    return tmp_path


def _seed(repo_root: Path) -> tuple[str, str]:
    run_id = str(ULID())
    artifact_id = str(ULID())
    # Two separate transactions so the runs row is committed before the
    # recon_artifacts row references it. SQLAlchemy's UoW can't infer the
    # FK ordering here (no relationship() defined on the model).
    with st_session.session_scope() as s:
        s.add(
            Run(
                id=run_id,
                target_repo_path=str(repo_root),
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
    with st_session.session_scope() as s:
        s.add(
            ReconArtifact(
                id=artifact_id,
                run_id=run_id,
                languages_json=json.dumps(["python"]),
                build_commands_json="[]",
                trust_boundaries_json="[]",
                subsystems_json="[]",
                notes="",
                recorded_at="2026-06-02T00:00:00Z",
            )
        )
    return run_id, artifact_id


@pytest.mark.asyncio
async def test_index_build_stage_run_builds_index(isolated_db: Path) -> None:
    repo = isolated_db / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "x.py").write_text("def f(): pass\n", encoding="utf-8")
    run_id, artifact_id = _seed(repo)
    cfg = Config(
        repo_root=repo,
        model="claude-sonnet-4-5",
        recon_token_budget=1_000_000,
        hunt_token_budget=1_000_000,
        auth_env={"ANTHROPIC_API_KEY": "x"},
    )

    result = await ib_stage.run(
        run_id=run_id,
        recon_artifact_id=artifact_id,
        repo=repo,
        languages={"python"},
        cfg=cfg,
        session_factory=st_session.session_factory(),
    )
    assert result.symbols >= 1
    assert result.languages == ["python"]


@pytest.mark.asyncio
async def test_index_build_stage_zero_symbols_returns_empty_result(
    isolated_db: Path,
) -> None:
    """An empty repo yields IndexBuildResult.symbols == 0; stage does not raise."""
    repo = isolated_db / "repo"
    repo.mkdir()
    run_id, artifact_id = _seed(repo)
    cfg = Config(
        repo_root=repo,
        model="claude-sonnet-4-5",
        recon_token_budget=1_000_000,
        hunt_token_budget=1_000_000,
        auth_env={"ANTHROPIC_API_KEY": "x"},
    )
    result = await ib_stage.run(
        run_id=run_id,
        recon_artifact_id=artifact_id,
        repo=repo,
        languages={"python"},
        cfg=cfg,
        session_factory=st_session.session_factory(),
    )
    assert result.symbols == 0
