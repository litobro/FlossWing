"""Gated integration smoke for the v0.8 Dedupe stage.

Gated by FLOSSWING_INTEGRATION=1.

Per docs/specs/2026-06-02-v0.8-dedupe-design.md § Success criteria
and docs/plans/2026-06-03-v0.8-dedupe.md § Task J. Asserts the full
Recon -> Hunt -> Validate -> Gapfill -> Dedupe pipeline lands at
least one multi-member cluster on the v08_dedupe_smoke corpus and
that Pass 1 + Pass 2 invariants hold.

Runs against tests/corpus/v08_dedupe_smoke/ which contains two
deliberate command_injection sinks in the same function within ±5
lines so Pass 1's deterministic clustering produces a member_count
>= 2 cluster regardless of Pass 2's outcome.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from sqlalchemy import select

from flosswing.config import DEFAULT_MODEL, Config
from flosswing.orchestrator import run_scan
from flosswing.state import session as st_session
from flosswing.state.models import AgentSession, DedupeCluster, Finding, Run

pytestmark = pytest.mark.skipif(
    os.environ.get("FLOSSWING_INTEGRATION") != "1",
    reason="integration test gated by FLOSSWING_INTEGRATION=1",
)

CORPUS_REPO = Path(__file__).parent.parent / "corpus" / "v08_dedupe_smoke"


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
            dedupe_token_budget=None,
        )
    except _AuthMissing:
        return {}
    return dict(c.auth_env)


@pytest.mark.asyncio
async def test_dedupe_smoke_runs_end_to_end_against_v08_dedupe_smoke(
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

    # Modest budgets — this test consumes API credit. Matches the
    # 200_000-per-stage shape used by test_gapfill_smoke.py.
    cfg = Config(
        repo_root=CORPUS_REPO.resolve(),
        model=DEFAULT_MODEL,
        recon_token_budget=200_000,
        hunt_token_budget=200_000,
        validate_token_budget=200_000,
        gapfill_token_budget=200_000,
        dedupe_token_budget=200_000,
        auth_env=auth,
    )
    result = await run_scan(cfg)

    # Snapshot every attribute we'll assert on INSIDE the session scope;
    # SQLAlchemy 2.0 expires ORM instances on commit and any post-scope
    # attribute access raises DetachedInstanceError. See v0.5/v0.6/v0.7
    # smoke tests for the same pattern.
    with st_session.session_scope() as s:
        run_rows: list[tuple[str, str, int, str]] = [
            (r.id, r.status, r.budget_used, r.config_json)
            for r in s.execute(
                select(Run).where(Run.id == result.run_id)
            ).scalars().all()
        ]
        finding_rows: list[tuple[str, str | None]] = [
            (f.id, f.dedupe_cluster_id)
            for f in s.execute(
                select(Finding).where(Finding.run_id == result.run_id)
            ).scalars().all()
        ]
        finding_roles: list[str | None] = [
            f.dedupe_role
            for f in s.execute(
                select(Finding).where(Finding.run_id == result.run_id)
            ).scalars().all()
        ]
        cluster_rows: list[tuple[str, int]] = [
            (c.id, c.member_count)
            for c in s.execute(
                select(DedupeCluster).where(
                    DedupeCluster.run_id == result.run_id
                )
            ).scalars().all()
        ]
        dedupe_sessions: list[tuple[str, str, str | None, str | None]] = [
            (sess.id, sess.outcome, sess.task_id, sess.finding_id)
            for sess in s.execute(
                select(AgentSession).where(
                    AgentSession.run_id == result.run_id,
                    AgentSession.stage == "dedupe",
                )
            ).scalars().all()
        ]

    # Per § Success criteria #1: exactly one runs row, status='completed',
    # budget_used > 0.
    assert len(run_rows) == 1, (
        f"expected exactly 1 runs row, got {len(run_rows)}"
    )
    _run_id, run_status, budget_used, config_json = run_rows[0]
    assert run_status == "completed", (
        f"expected runs.status='completed', got {run_status!r}; "
        f"summary={result.summary}"
    )
    assert budget_used > 0, (
        f"expected runs.budget_used > 0, got {budget_used}"
    )

    # Per § Success criteria #8: runs.config_json includes
    # dedupe_token_budget.
    config = json.loads(config_json)
    assert "dedupe_token_budget" in config, (
        f"runs.config_json missing dedupe_token_budget; got keys "
        f"{sorted(config.keys())}"
    )

    # Per § Success criteria #2: >= 1 findings row.
    assert len(finding_rows) >= 1, (
        f"expected >= 1 findings row, got {len(finding_rows)}"
    )

    # Per § Success criteria #3: >= 1 dedupe_clusters row.
    assert len(cluster_rows) >= 1, (
        f"expected >= 1 dedupe_clusters row, got {len(cluster_rows)}"
    )

    # Per § Success criteria #4: >= 1 dedupe_clusters row with
    # member_count >= 2. This is the deterministic cluster Pass 1
    # must produce from the corpus's two ±5-line command_injection
    # sinks.
    multi_member_clusters = [
        cid for cid, mc in cluster_rows if mc >= 2
    ]
    assert len(multi_member_clusters) >= 1, (
        f"expected >= 1 multi-member cluster (member_count >= 2); "
        f"got clusters={cluster_rows}"
    )

    # Per § Success criteria #5: every findings row has a non-NULL
    # dedupe_cluster_id (Q#3 resolution: singleton-cluster rows are
    # created so the dedupe_cluster_id column is universally
    # populated for the run).
    for fid, cluster_id in finding_rows:
        assert cluster_id is not None, (
            f"finding {fid} has NULL dedupe_cluster_id; expected "
            "every finding to belong to a cluster (singletons get "
            "their own row per Q#3)"
        )

    # Per § Success criteria #6: >= 1 agent_sessions row with
    # stage='dedupe' and a terminal outcome.
    assert len(dedupe_sessions) >= 1, (
        f"expected >= 1 dedupe agent_sessions row, got "
        f"{len(dedupe_sessions)}"
    )
    valid_outcomes = {
        "completed", "refused", "errored", "budget_exceeded"
    }
    for sess_id, outcome, task_id, finding_id in dedupe_sessions:
        assert outcome in valid_outcomes, (
            f"dedupe session {sess_id} has unexpected outcome "
            f"{outcome!r}; expected one of {sorted(valid_outcomes)}"
        )
        # Per spec § Pass 2: task_id is NULL for dedupe sessions
        # (cluster id is not stored on agent_sessions in v0.8).
        assert task_id is None, (
            f"dedupe session {sess_id} has non-NULL task_id "
            f"{task_id!r}; expected NULL"
        )
        assert finding_id is None, (
            f"dedupe session {sess_id} has non-NULL finding_id "
            f"{finding_id!r}; expected NULL"
        )

    # Per § Success criteria #7: if a dedupe session completed, the
    # model MAY have set dedupe_role on some findings via
    # merge_findings / link_variant. The "do nothing" path is also
    # valid per the dedupe system prompt, so we soft-assert: if any
    # session completed AND any finding has a role, that's fine; if
    # none do, we just note it. We do NOT fail the test on the
    # "completed but did nothing" path.
    any_completed = any(
        outcome == "completed"
        for _sid, outcome, _tid, _fid in dedupe_sessions
    )
    any_role_set = any(role is not None for role in finding_roles)
    if any_completed and not any_role_set:
        # Valid per spec: agent may judge the cluster coincidental
        # and decline to act. Surface it as a note via the summary
        # rather than failing.
        print(
            "note: dedupe session completed but no findings have "
            "dedupe_role set; model chose 'do nothing' per the "
            "spec's decision tree."
        )
