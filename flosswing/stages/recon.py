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

"""Recon stage orchestration.

Loads the system prompt, builds the 5 Recon tools, opens an
agent_sessions row, drives one runtime session, closes the row with
the terminal fields, returns a structured RunReconResult.

Per docs/specs/2026-05-25-v0.2-recon-plumbing-design.md § Component
responsibilities.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select
from ulid import ULID

from flosswing.agent import pricing
from flosswing.agent.runtime import run_session
from flosswing.agent.tool_registry import RegistryContext, build_recon_tools
from flosswing.config import Config
from flosswing.state import heartbeat as st_heartbeat
from flosswing.state import session as st_session
from flosswing.state.models import AgentSession, HuntTask, ReconArtifact

_PROMPT_PATH = (
    Path(__file__).resolve().parent.parent / "prompts" / "system" / "recon.md"
)

_USER_PROMPT = (
    "Analyze the repository at /repo and produce a Recon artifact "
    "plus an initial Hunt task queue per your system instructions."
)


@dataclass
class RunReconResult:
    outcome: str
    recon_artifact_recorded: bool
    hunt_tasks_queued: int
    agent_session_id: str
    input_tokens: int
    output_tokens: int
    cost_usd: float
    refusal_text: str | None
    error_text: str | None
    # v0.5: surfaced for IndexBuild wiring. `recon_artifact_id` is the row
    # id of the just-recorded recon_artifacts row (None if Recon did not
    # record one); `languages` is the set parsed from that row's
    # `languages_json`. Both are consumed by the orchestrator to drive the
    # IndexBuild stage between Recon and Hunt.
    recon_artifact_id: str | None = None
    languages: set[str] = field(default_factory=set)


def _now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


async def run(*, run_id: str, cfg: Config) -> RunReconResult:
    system_prompt = _PROMPT_PATH.read_text(encoding="utf-8")
    prompt_hash = hashlib.sha256(system_prompt.encode("utf-8")).hexdigest()

    tools = build_recon_tools(
        RegistryContext(
            repo_root=cfg.repo_root,
            run_id=run_id,
            budget_total=20,
        )
    )

    session_id = str(ULID())
    started_at = _now_iso()

    result = await run_session(
        model=cfg.model,
        provider=cfg.provider,
        system_prompt=system_prompt,
        tools=tools,
        user_prompt=_USER_PROMPT,
        token_budget=cfg.recon_token_budget,
        auth_env=cfg.auth_env,
        run_id=run_id,
        stage="recon",
        on_usage=st_heartbeat.make_on_usage(
            run_id=run_id, stage="recon", model=cfg.model
        ),
    )

    finished_at = _now_iso()
    cost = pricing.resolve_cost_usd(
        model=cfg.model,
        input_tokens=result.input_tokens,
        output_tokens=result.output_tokens,
        cache_read_tokens=result.cache_read_tokens,
        cache_write_tokens=result.cache_write_tokens,
        authoritative=result.cost_usd,
    )
    # INSERT the audit row after the session completes so we can write the
    # final outcome directly. The schema's ck_agent_sessions_outcome CHECK
    # constraint only allows terminal values; there is no "running" state.
    # Clearing the live heartbeat in the SAME transaction makes the swap from
    # "in-flight ticker" to "committed audit row" atomic for the TUI.
    with st_session.session_scope() as s:
        s.add(
            AgentSession(
                id=session_id,
                run_id=run_id,
                stage="recon",
                model=cfg.model,
                system_prompt_hash=prompt_hash,
                input_tokens=result.input_tokens,
                output_tokens=result.output_tokens,
                cache_read_tokens=result.cache_read_tokens,
                cache_write_tokens=result.cache_write_tokens,
                cost_usd=cost,
                duration_ms=result.duration_ms,
                outcome=result.outcome,
                refusal_text=result.refusal_text,
                error_text=result.error_text,
                tool_calls_count=result.tool_calls_count,
                started_at=started_at,
                finished_at=finished_at,
            )
        )
        st_heartbeat.clear(s, run_id)

    # v0.5: pull artifact_id + languages so the orchestrator can drive
    # IndexBuild without re-querying. Recon may record zero or one
    # artifact in v0.2; we surface the first (and warn nothing about
    # the rest because the contract guarantees ≤1). All ORM attribute
    # reads must happen inside the session scope to avoid
    # DetachedInstanceError after the scope closes.
    artifact_id: str | None = None
    languages: set[str] = set()
    artifact_count = 0
    with st_session.session_scope() as s:
        artifact_rows = list(
            s.execute(select(ReconArtifact).where(ReconArtifact.run_id == run_id))
            .scalars()
            .all()
        )
        artifact_count = len(artifact_rows)
        if artifact_rows:
            artifact_id = artifact_rows[0].id
            langs_json = artifact_rows[0].languages_json
            try:
                parsed = json.loads(langs_json)
            except (json.JSONDecodeError, TypeError):
                parsed = []
            if isinstance(parsed, list):
                languages = {str(x) for x in parsed if isinstance(x, str)}
        tasks_count = len(
            list(
                s.execute(select(HuntTask).where(HuntTask.run_id == run_id))
                .scalars()
                .all()
            )
        )

    return RunReconResult(
        outcome=result.outcome,
        recon_artifact_recorded=artifact_count >= 1,
        hunt_tasks_queued=tasks_count,
        agent_session_id=session_id,
        input_tokens=result.input_tokens,
        output_tokens=result.output_tokens,
        cost_usd=cost,
        refusal_text=result.refusal_text,
        error_text=result.error_text,
        recon_artifact_id=artifact_id,
        languages=languages,
    )


__all__ = ["RunReconResult", "run", "run_session"]
