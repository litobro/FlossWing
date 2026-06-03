"""Recon stage orchestration.

Loads the system prompt, builds the 5 Recon tools, opens an
agent_sessions row, drives one runtime session, closes the row with
the terminal fields, returns a structured RunReconResult.

Per docs/specs/2026-05-25-v0.2-recon-plumbing-design.md § Component
responsibilities.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select
from ulid import ULID

from flosswing.agent.runtime import run_session
from flosswing.agent.tool_registry import RegistryContext, build_recon_tools
from flosswing.config import Config
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


def _now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _estimate_cost_usd(
    *, model: str, input_tokens: int, output_tokens: int
) -> float:
    """Rough cost estimate. Updated when authoritative pricing wired in."""
    # Per-million-token USD rates; placeholder, see Anthropic pricing.
    rates = {
        "claude-opus-4-7": (15.0, 75.0),
        "claude-sonnet-4-6": (3.0, 15.0),
        "claude-haiku-4-5": (0.80, 4.00),
    }
    in_rate, out_rate = rates.get(model, (15.0, 75.0))
    return (input_tokens / 1_000_000) * in_rate + (output_tokens / 1_000_000) * out_rate


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
        system_prompt=system_prompt,
        tools=tools,
        user_prompt=_USER_PROMPT,
        token_budget=cfg.token_budget,
        auth_env=cfg.auth_env,
        run_id=run_id,
        stage="recon",
    )

    finished_at = _now_iso()
    cost = _estimate_cost_usd(
        model=cfg.model,
        input_tokens=result.input_tokens,
        output_tokens=result.output_tokens,
    )
    # INSERT the audit row after the session completes so we can write the
    # final outcome directly. The schema's ck_agent_sessions_outcome CHECK
    # constraint only allows terminal values; there is no "running" state.
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

    with st_session.session_scope() as s:
        artifact_count = (
            s.execute(select(ReconArtifact).where(ReconArtifact.run_id == run_id))
            .scalars()
            .all()
        )
        tasks_count = (
            s.execute(select(HuntTask).where(HuntTask.run_id == run_id))
            .scalars()
            .all()
        )

    return RunReconResult(
        outcome=result.outcome,
        recon_artifact_recorded=len(artifact_count) >= 1,
        hunt_tasks_queued=len(tasks_count),
        agent_session_id=session_id,
        input_tokens=result.input_tokens,
        output_tokens=result.output_tokens,
        cost_usd=cost,
        refusal_text=result.refusal_text,
        error_text=result.error_text,
    )


__all__ = ["RunReconResult", "run", "run_session"]
