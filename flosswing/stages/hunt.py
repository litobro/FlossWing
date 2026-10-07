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

"""Hunt stage orchestration.

Sequentially walks every `pending` hunt_task for the current run,
spawns one agent session per task with the four v0.3-scoped tools,
audits the session in `agent_sessions`, and transitions
`hunt_tasks.status` to a terminal value. Returns a HuntStageResult
summarizing the stage.

Per docs/specs/2026-06-02-v0.3-hunt-plumbing-design.md § Component
responsibilities stages/hunt.py.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker
from ulid import ULID

from flosswing.agent import pricing
from flosswing.agent.runtime import run_session
from flosswing.agent.tool_descriptors import (
    build_hunt_descriptors,
    to_sdk_tool,
)
from flosswing.config import Config
from flosswing.prompts import load_attack_class_fragment
from flosswing.state import heartbeat as st_heartbeat
from flosswing.state import session as st_session
from flosswing.state.models import AgentSession, Finding, HuntTask

_PROMPTS_ROOT = Path(__file__).resolve().parent.parent / "prompts"
_HUNT_SYSTEM_PROMPT_PATH = _PROMPTS_ROOT / "system" / "hunt.md"

SessionFactory = sessionmaker[Session]


@dataclass(frozen=True)
class HuntStageResult:
    tasks_processed: int
    tasks_succeeded: int
    tasks_refused: int
    tasks_budget_exceeded: int
    tasks_errored: int
    findings_total: int
    # Token totals across all Hunt agent sessions in this stage run.
    # Aggregated so the orchestrator can record the full scan's
    # budget_used without re-querying agent_sessions.
    input_tokens_total: int = 0
    output_tokens_total: int = 0

    @classmethod
    def skipped(cls) -> HuntStageResult:
        return cls(0, 0, 0, 0, 0, 0, 0, 0)


# -----------------------------------------------------------------------------
# Private helpers
# -----------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _compose_user_prompt(task: HuntTask) -> str:
    fragment = load_attack_class_fragment(task.attack_class)
    return (
        f"Attack class: {task.attack_class}\n"
        f"Scope hint:   {task.scope_hint}\n"
        f"Rationale:    {task.rationale}\n"
        "\n"
        "---\n"
        f"{fragment}\n"
    )


# -----------------------------------------------------------------------------
# Tool builder — Hunt-scoped (6 tools in v0.5: read_file, list_dir, grep,
# record_finding, find_definition, find_callers). Descriptors live in
# agent.tool_descriptors; this wrapper adapts them to SDK tools.
# -----------------------------------------------------------------------------


def _build_hunt_tools(
    *,
    repo_root: Path,
    run_id: str,
    hunt_task_id: str,
) -> list[Any]:
    """Build the 4 Hunt-scoped tool callables for ClaudeAgentOptions."""
    return [
        to_sdk_tool(d)
        for d in build_hunt_descriptors(
            repo_root=repo_root, run_id=run_id, hunt_task_id=hunt_task_id
        )
    ]


# -----------------------------------------------------------------------------
# Main entry point
# -----------------------------------------------------------------------------


async def run(
    *,
    run_id: str,
    repo: Path,
    cfg: Config,
    session_factory: SessionFactory,
) -> HuntStageResult:
    """Process every pending hunt_task for run_id sequentially."""
    system_prompt = _HUNT_SYSTEM_PROMPT_PATH.read_text(encoding="utf-8")
    prompt_hash = hashlib.sha256(system_prompt.encode("utf-8")).hexdigest()

    # Priority ordering: high > normal > low, then by created_at asc.
    priority_rank = {"high": 0, "normal": 1, "low": 2}

    with st_session.session_scope() as s:
        pending = (
            s.execute(
                select(HuntTask).where(
                    HuntTask.run_id == run_id, HuntTask.status == "pending"
                )
            )
            .scalars()
            .all()
        )
        snapshot = sorted(
            [(priority_rank.get(t.priority, 1), t.created_at, t.id) for t in pending]
        )
        task_ids_in_order = [tid for _, _, tid in snapshot]

    tasks_succeeded = 0
    tasks_refused = 0
    tasks_budget_exceeded = 0
    tasks_errored = 0
    input_tokens_total = 0
    output_tokens_total = 0

    for task_id in task_ids_in_order:
        # Re-fetch each task fresh; mark it running and compose its prompt.
        with st_session.session_scope() as s:
            task = s.get(HuntTask, task_id)
            if task is None or task.status != "pending":
                # Another writer claimed it (shouldn't happen — single-writer
                # invariant — but be defensive).
                continue
            task.status = "running"
            task.started_at = _now_iso()
            user_prompt = _compose_user_prompt(task)

        tools = _build_hunt_tools(
            repo_root=repo, run_id=run_id, hunt_task_id=task_id
        )

        started_at = _now_iso()
        session_result = await run_session(
            model=cfg.model,
            provider=cfg.provider,
            system_prompt=system_prompt,
            tools=tools,
            user_prompt=user_prompt,
            token_budget=cfg.hunt_token_budget,
            auth_env=cfg.auth_env,
            run_id=run_id,
            stage="hunt",
            task_id=task_id,
            on_usage=st_heartbeat.make_on_usage(
                run_id=run_id, stage="hunt", model=cfg.model, task_id=task_id
            ),
        )
        finished_at = _now_iso()
        cost = pricing.resolve_cost_usd(
            model=cfg.model,
            input_tokens=session_result.input_tokens,
            output_tokens=session_result.output_tokens,
            cache_read_tokens=session_result.cache_read_tokens,
            cache_write_tokens=session_result.cache_write_tokens,
            authoritative=session_result.cost_usd,
        )
        input_tokens_total += session_result.input_tokens
        output_tokens_total += session_result.output_tokens

        # INSERT the audit row after the session — same shape as Recon does
        # (the ck_agent_sessions_outcome CHECK only allows terminal values).
        # Clear the live heartbeat in the same transaction (atomic swap).
        with st_session.session_scope() as s:
            s.add(
                AgentSession(
                    id=str(ULID()),
                    run_id=run_id,
                    stage="hunt",
                    task_id=task_id,
                    model=cfg.model,
                    system_prompt_hash=prompt_hash,
                    input_tokens=session_result.input_tokens,
                    output_tokens=session_result.output_tokens,
                    cache_read_tokens=session_result.cache_read_tokens,
                    cache_write_tokens=session_result.cache_write_tokens,
                    cost_usd=cost,
                    duration_ms=session_result.duration_ms,
                    outcome=session_result.outcome,
                    refusal_text=session_result.refusal_text,
                    error_text=session_result.error_text,
                    tool_calls_count=session_result.tool_calls_count,
                    started_at=started_at,
                    finished_at=finished_at,
                )
            )
            st_heartbeat.clear(s, run_id)

        # Transition the task to its terminal status and refresh findings_count.
        terminal_status = session_result.outcome
        with st_session.session_scope() as s:
            t = s.get(HuntTask, task_id)
            if t is None:
                continue
            t.status = terminal_status
            t.finished_at = finished_at
            count = (
                s.execute(
                    select(Finding).where(Finding.hunt_task_id == task_id)
                )
                .scalars()
                .all()
            )
            t.findings_count = len(count)

        if terminal_status == "completed":
            tasks_succeeded += 1
        elif terminal_status == "refused":
            tasks_refused += 1
        elif terminal_status == "budget_exceeded":
            tasks_budget_exceeded += 1
        else:
            tasks_errored += 1

    with st_session.session_scope() as s:
        findings_total = len(
            s.execute(select(Finding).where(Finding.run_id == run_id))
            .scalars()
            .all()
        )

    return HuntStageResult(
        tasks_processed=len(task_ids_in_order),
        tasks_succeeded=tasks_succeeded,
        tasks_refused=tasks_refused,
        tasks_budget_exceeded=tasks_budget_exceeded,
        tasks_errored=tasks_errored,
        findings_total=findings_total,
        input_tokens_total=input_tokens_total,
        output_tokens_total=output_tokens_total,
    )


__all__ = ["HuntStageResult", "run", "run_session"]
