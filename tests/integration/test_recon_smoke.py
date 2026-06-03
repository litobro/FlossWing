"""Integration smoke test for Recon -> Hunt plumbing.

Gated by FLOSSWING_INTEGRATION=1 — NOT run in normal CI. Uses
whichever auth env vars are present (direct Anthropic, Foundry API
key, or Entra ID via az login).

Per docs/specs/2026-06-02-v0.3-hunt-plumbing-design.md § Testing
strategy / § Design decisions #4: a single gated invocation that
exercises Recon and Hunt against tests/corpus/v02_smoke/.
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
from flosswing.state.models import (
    AgentSession,
    Finding,
    HuntTask,
    ReconArtifact,
    Run,
)

pytestmark = pytest.mark.skipif(
    os.environ.get("FLOSSWING_INTEGRATION") != "1",
    reason="integration tests gated by FLOSSWING_INTEGRATION=1",
)


def test_recon_to_hunt_smoke_against_v02_corpus(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Fresh DB for this run.
    monkeypatch.setenv("FLOSSWING_DB_URL", f"sqlite:///{tmp_path / 'state.db'}")
    st_session._cached_engine = None  # type: ignore[attr-defined]
    st_session._cached_session_factory = None  # type: ignore[attr-defined]

    corpus = Path(__file__).resolve().parents[1] / "corpus" / "v02_smoke"
    assert corpus.exists(), f"corpus missing: {corpus}"

    cfg = resolve(
        repo_root=corpus,
        model=None,
        recon_token_budget=None,
        hunt_token_budget=None,
    )
    result = asyncio.run(run_scan(cfg))
    assert result.exit_code == 0, result.summary

    # ---- v0.2 assertions (Recon side, unchanged) ----------------------------

    with st_session.session_scope() as s:
        runs = s.execute(select(Run)).scalars().all()
        assert len(runs) == 1
        assert runs[0].status == "completed"

        artifacts = s.execute(select(ReconArtifact)).scalars().all()
        assert len(artifacts) == 1
        assert "python" in artifacts[0].languages_json

        tasks = s.execute(select(HuntTask)).scalars().all()
        assert len(tasks) >= 1

        recon_sessions = (
            s.execute(select(AgentSession).where(AgentSession.stage == "recon"))
            .scalars()
            .all()
        )
        assert len(recon_sessions) == 1
        assert recon_sessions[0].outcome == "completed"
        assert recon_sessions[0].input_tokens > 0

    # ---- v0.3 assertions (Hunt side, new) -----------------------------------

    with st_session.session_scope() as s:
        # Every task has a terminal status — no pending / running leftover.
        terminal = {"completed", "refused", "budget_exceeded", "errored"}
        for t in s.execute(select(HuntTask)).scalars().all():
            assert t.status in terminal, (
                f"task {t.id} left in non-terminal status {t.status!r}"
            )

        # At least one Hunt agent session.
        hunt_sessions = (
            s.execute(select(AgentSession).where(AgentSession.stage == "hunt"))
            .scalars()
            .all()
        )
        assert len(hunt_sessions) >= 1
        for sess in hunt_sessions:
            assert sess.task_id is not None
            assert sess.outcome in terminal

        # At least one finding overall.
        all_findings = s.execute(select(Finding)).scalars().all()
        assert len(all_findings) >= 1, "expected >=1 finding total"

        # The command_injection task on the deliberate shell-passthrough sink
        # in src/example/cli.py specifically should produce >=1 finding.
        ci_tasks = (
            s.execute(
                select(HuntTask).where(HuntTask.attack_class == "command_injection")
            )
            .scalars()
            .all()
        )
        assert ci_tasks, "Recon did not queue a command_injection task"
        ci_findings_total = 0
        for ci in ci_tasks:
            ci_findings_total += ci.findings_count
            # findings_count on the task must equal COUNT(*) on the actual
            # findings rows with that hunt_task_id.
            actual = (
                s.execute(select(Finding).where(Finding.hunt_task_id == ci.id))
                .scalars()
                .all()
            )
            assert ci.findings_count == len(actual), (
                f"task {ci.id} findings_count={ci.findings_count} but actual "
                f"COUNT(findings)={len(actual)}"
            )
        assert ci_findings_total >= 1, (
            "expected the command_injection task on the deliberate sink in "
            "tests/corpus/v02_smoke/src/example/cli.py to produce at least one "
            "finding"
        )
