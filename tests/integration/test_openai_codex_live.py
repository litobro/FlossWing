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

"""Gated live test: one Recon turn through the OpenAI Codex/Daybreak backend.

Gated by FLOSSWING_INTEGRATION=1 — NOT run in normal CI (collected, skipped).
Requires a logged-in ``codex`` CLI (``codex login``). Operator-run only: it
spends Daybreak quota.

What a live run VALIDATES that the unit tests (fixture-replayed) cannot:

* the real ``codex app-server`` JSON-RPC wire protocol end to end (initialize,
  thread/start, turn/start, streamed notifications, token-usage reporting);
* the elicitation-accept shape (scoped auto-approve of FlossWing's own MCP
  tools) and the fail-closed *decline* responses. NOTE: the exact decline
  response for ``item/permissions/requestApproval`` and the v1 legacy approval
  methods are UNCONFIRMED live — a live run should check them (e.g. that a
  non-FlossWing approval request is refused rather than hanging the turn);
* ``stderr=DEVNULL`` on the child (no pipe back-pressure / hang);
* the two documented choices: ``thread/start`` ``command=sys.executable`` for
  the stdio MCP server, and the system prompt delivered via
  ``developerInstructions``.

``run_session`` recovers the stdio-server ctx from the state DB by ``run_id``
(OP-1), so this test seeds a ``runs`` row first.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest
from ulid import ULID

from flosswing import __version__
from flosswing.agent.providers.openai_codex import OpenAICodexProvider
from flosswing.agent.tool_descriptors import build_recon_descriptors, to_sdk_tool
from flosswing.state import session as st_session
from flosswing.state.models import Run

pytestmark = pytest.mark.skipif(
    os.environ.get("FLOSSWING_INTEGRATION") != "1",
    reason="integration tests gated by FLOSSWING_INTEGRATION=1",
)

_BUDGET_TOTAL = 20
_TOKEN_BUDGET = 100_000


@pytest.mark.asyncio
async def test_recon_one_turn_live_daybreak(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Fresh DB for this run.
    monkeypatch.setenv("FLOSSWING_DB_URL", f"sqlite:///{tmp_path / 'state.db'}")
    st_session._cached_engine = None  # type: ignore[attr-defined]
    st_session._cached_session_factory = None  # type: ignore[attr-defined]

    corpus = Path(__file__).resolve().parents[1] / "corpus" / "v02_smoke"
    assert corpus.exists(), f"corpus missing: {corpus}"

    run_id = str(ULID())
    now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    # config_json carries the four per-stage token budgets so the provider can
    # recover total_token_budget (OP-1); repo path + budget_total come from
    # the row's own columns.
    config = {
        "repo_root": str(corpus),
        "provider": "openai",
        "recon_token_budget": _TOKEN_BUDGET,
        "hunt_token_budget": _TOKEN_BUDGET,
        "validate_token_budget": _TOKEN_BUDGET,
        "gapfill_token_budget": _TOKEN_BUDGET,
    }
    with st_session.session_scope() as s:
        s.add(
            Run(
                id=run_id,
                target_repo_path=str(corpus),
                target_repo_sha=None,
                depth="standard",
                budget_total=_BUDGET_TOTAL,
                budget_used=0,
                started_at=now,
                status="running",
                config_json=json.dumps(config, sort_keys=True),
                flosswing_version=__version__,
            )
        )

    # Passed for interface parity only; the Codex provider ignores `tools` and
    # serves the same descriptors over its stdio MCP server.
    tools = [
        to_sdk_tool(d)
        for d in build_recon_descriptors(
            repo_root=corpus, run_id=run_id, budget_total=_BUDGET_TOTAL
        )
    ]

    result = await OpenAICodexProvider().run_session(
        model="gpt-daybreak-blue-latest",
        system_prompt="You are a recon agent.",
        tools=tools,
        # FORCING tool-use instruction (drives the >=1 gate below). History:
        # a decline-probe clause ("...also read /etc/hostname via shell")
        # poisoned the turn into a refusal; removing it, a SOFT prompt ("list
        # the languages") was still flaky — the live model is non-deterministic
        # about tool use and sometimes answers from assumption with zero calls
        # (observed: outcome=completed, 0 tool calls). So the prompt now demands
        # output the model cannot produce without a tool call: report list_dir's
        # exact entries. A working MCP seam reliably yields >=1 call; a broken
        # seam still can't (the gate's purpose). The fail-closed shell-approval
        # decline is exercised incidentally and covered by the Task 0 fixtures
        # (tests/fixtures/codex/round_trip.jsonl, NOTES.md).
        user_prompt=(
            "Use the provided tools only; do not answer from assumptions. "
            "Call the list_dir tool on path '.' and report back the exact "
            "top-level file and directory names it returns."
        ),
        token_budget=_TOKEN_BUDGET,
        auth_env={},
        run_id=run_id,
        stage="recon",
    )

    assert result.outcome in {"completed", "refused"}, result
    assert result.input_tokens > 0
    # CRIT#1 live gate: the prompt tells the model to use the tools, so a working
    # MCP seam (package importable in the app-server-spawned stdio child) MUST
    # produce at least one tool call. A broken seam (the child can't import
    # flosswing) yields zero — which this assertion catches.
    assert result.tool_calls_count >= 1, result
