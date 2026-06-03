"""Integration smoke test for v0.2 Recon plumbing.

Gated by FLOSSWING_INTEGRATION=1 — NOT run in normal CI. Uses whichever
auth env vars are present (direct Anthropic, Foundry API key, or Entra
ID via az login).
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import pytest
from sqlalchemy import select

from flosswing.config import resolve
from flosswing.orchestrator import run_scan
from flosswing.state import session as st_session
from flosswing.state.models import AgentSession, HuntTask, ReconArtifact, Run

pytestmark = pytest.mark.skipif(
    os.environ.get("FLOSSWING_INTEGRATION") != "1",
    reason="integration tests gated by FLOSSWING_INTEGRATION=1",
)


def test_recon_smoke_against_v02_corpus(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Fresh DB for this run.
    monkeypatch.setenv("FLOSSWING_DB_URL", f"sqlite:///{tmp_path / 'state.db'}")
    st_session._cached_engine = None  # type: ignore[attr-defined]
    st_session._cached_session_factory = None  # type: ignore[attr-defined]

    corpus = Path(__file__).resolve().parents[1] / "corpus" / "v02_smoke"
    assert corpus.exists(), f"corpus missing: {corpus}"

    cfg = resolve(repo_root=corpus, model=None, token_budget=None)
    result = asyncio.run(run_scan(cfg))

    assert result.exit_code == 0, result.summary

    with st_session.session_scope() as s:
        runs = s.execute(select(Run)).scalars().all()
        assert len(runs) == 1
        assert runs[0].status == "completed"

        artifacts = s.execute(select(ReconArtifact)).scalars().all()
        assert len(artifacts) == 1
        assert "python" in artifacts[0].languages_json

        tasks = s.execute(select(HuntTask)).scalars().all()
        assert len(tasks) >= 1

        sessions = s.execute(select(AgentSession)).scalars().all()
        assert len(sessions) == 1
        assert sessions[0].outcome == "completed"
        assert sessions[0].input_tokens > 0
