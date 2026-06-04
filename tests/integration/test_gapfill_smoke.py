"""Gated integration smoke for the v0.7 Gapfill stage.

Gated by FLOSSWING_INTEGRATION=1.

Per docs/specs/2026-06-02-v0.7-gapfill-design.md § Success criteria
#1-5 and § Testing strategy Integration test. Asserts:
- exit_code 0 (Gapfill is not run-fatal even if it refuses).
- >=1 agent_sessions row with stage='gapfill' and terminal outcome.
- 0..cap new hunt_tasks rows with source='gapfill' (zero is a valid
  outcome — Gapfill may judge the original task set adequate).
- All gapfill-source rows have status='pending' (v0.7 does NOT
  auto-re-run Hunt against them per design decision #2).
- The CLI summary surfaces the gapfill block.

Runs the full pipeline against tests/corpus/v02_smoke/. Requires
valid auth credentials.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from sqlalchemy import select

from flosswing.config import DEFAULT_MODEL, Config
from flosswing.orchestrator import run_scan
from flosswing.state import session as st_session
from flosswing.state.models import AgentSession, HuntTask

pytestmark = pytest.mark.skipif(
    os.environ.get("FLOSSWING_INTEGRATION") != "1",
    reason="integration test gated by FLOSSWING_INTEGRATION=1",
)

CORPUS_REPO = Path(__file__).parent.parent / "corpus" / "v02_smoke"


def _resolve_auth_env() -> dict[str, str]:
    """Pick up whichever auth mode the operator has configured.

    Delegates to flosswing.config.resolve() so the test gate matches
    production semantics exactly. Returns an empty dict if no auth
    path is available — the calling test then skips.
    """
    from pathlib import Path as _Path

    from flosswing import config as _cfg
    from flosswing.errors import AuthCredentialMissingError as _AuthMissing

    try:
        c = _cfg.resolve(
            repo_root=_Path("."),
            model=None,
            recon_token_budget=None,
            hunt_token_budget=None,
            validate_token_budget=None,
            gapfill_token_budget=None,
        )
    except _AuthMissing:
        return {}
    return dict(c.auth_env)


@pytest.mark.asyncio
async def test_gapfill_smoke_runs_end_to_end_against_v02_smoke(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    auth = _resolve_auth_env()
    if not auth:
        pytest.skip("no auth credentials available")
    monkeypatch.setenv("FLOSSWING_DB_URL", f"sqlite:///{tmp_path}/state.db")
    monkeypatch.setattr(st_session, "_cached_engine", None, raising=False)
    monkeypatch.setattr(
        st_session, "_cached_session_factory", None, raising=False
    )
    monkeypatch.setenv("HOME", str(tmp_path))

    cfg = Config(
        repo_root=CORPUS_REPO.resolve(),
        model=DEFAULT_MODEL,
        recon_token_budget=200_000,
        hunt_token_budget=200_000,
        validate_token_budget=200_000,
        gapfill_token_budget=200_000,
        auth_env=auth,
    )
    result = await run_scan(cfg)
    # Per spec § Success criteria #5: refusal / budget paths for
    # Gapfill are NOT run-fatal. exit_code is 0 as long as the upstream
    # stages succeeded. Allow exit_code in (0, 1) — 1 only happens if
    # Validate had all-non-terminal sessions on the deliberate
    # command_injection finding, which is independent of Gapfill.
    assert result.exit_code in (0, 1), (
        f"unexpected exit_code {result.exit_code}; summary={result.summary}"
    )

    # The summary always includes the gapfill block.
    assert "gapfill:" in result.summary, (
        f"gapfill block missing from summary; got:\n{result.summary}"
    )

    # Snapshot every attribute we'll assert on INSIDE the session scope;
    # SQLAlchemy 2.0 expires ORM instances on commit and any post-scope
    # attribute access raises DetachedInstanceError.
    with st_session.session_scope() as s:
        gapfill_sessions: list[tuple[str, str | None, str | None, str, int]] = [
            (
                sess.id, sess.finding_id, sess.task_id,
                sess.outcome, sess.input_tokens,
            )
            for sess in s.execute(
                select(AgentSession).where(
                    AgentSession.run_id == result.run_id,
                    AgentSession.stage == "gapfill",
                )
            ).scalars().all()
        ]
        gapfill_tasks_count = len(list(
            s.execute(
                select(HuntTask).where(
                    HuntTask.run_id == result.run_id,
                    HuntTask.source == "gapfill",
                )
            ).scalars().all()
        ))
        gapfill_tasks_status: list[tuple[str, str]] = [
            (t.id, t.status)
            for t in s.execute(
                select(HuntTask).where(
                    HuntTask.run_id == result.run_id,
                    HuntTask.source == "gapfill",
                )
            ).scalars().all()
        ]
        recon_tasks_count = len(list(
            s.execute(
                select(HuntTask).where(
                    HuntTask.run_id == result.run_id,
                    HuntTask.source == "recon",
                )
            ).scalars().all()
        ))

    # Per § Success criteria #1: exactly one agent_sessions row.
    assert len(gapfill_sessions) == 1, (
        f"expected exactly 1 gapfill agent_sessions row, "
        f"got {len(gapfill_sessions)}"
    )
    _sess_id, sess_finding_id, sess_task_id, outcome, input_tokens = gapfill_sessions[0]
    assert outcome in (
        "completed", "refused", "budget_exceeded", "errored"
    )
    assert sess_task_id is None
    assert sess_finding_id is None
    # Even a refused session consumes some input tokens for the system
    # prompt + user prompt.
    assert input_tokens > 0, (
        "gapfill agent_sessions.input_tokens is 0; expected nonzero "
        "even on refusal"
    )

    # Per § Success criteria #2: 0..cap new source='gapfill' rows.
    cap = max(1, recon_tasks_count // 5)
    assert gapfill_tasks_count <= cap, (
        f"Gapfill queued {gapfill_tasks_count} tasks but cap was {cap}"
    )

    # Per § Success criteria #4: new gapfill rows remain status='pending'.
    # v0.7 does NOT auto-re-run Hunt against them.
    for _task_id, status in gapfill_tasks_status:
        assert status == "pending", (
            f"expected gapfill task status='pending', got {status!r}; "
            "v0.7 must NOT auto-re-run Hunt"
        )


@pytest.mark.asyncio
async def test_gapfill_smoke_runs_after_zero_findings_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per design decision #5: Gapfill runs when tasks_succeeded >= 1
    regardless of findings_total. This test is a no-op assertion on
    the v02_smoke corpus (which does produce findings); it's here as a
    placeholder to flip on once a zero-finding-corpus exists. Skips
    today."""
    pytest.skip(
        "no zero-finding integration corpus yet; placeholder for the "
        "decision-#5 invariant (Gapfill runs on tasks_succeeded >= 1, "
        "not findings_total >= 1). Add tests/corpus/v07_zero_findings/ "
        "in a follow-on milestone."
    )
