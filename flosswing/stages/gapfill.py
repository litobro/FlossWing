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

"""Gapfill stage orchestration.

One agent session per run. Reads the existing Recon artifact + Hunt
task summaries + finding details via the six-tool scope (read_file,
list_dir, grep, query_findings, query_run_state, add_hunt_task),
proposes 0..cap new hunt_tasks rows with source='gapfill', and stops.
v0.7 does NOT auto-re-run Hunt against the new tasks — they sit
status='pending' for the operator's next invocation.

Per docs/specs/2026-06-02-v0.7-gapfill-design.md § Component
responsibilities stages/gapfill.py and ARCHITECTURE.md § Stage 4.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from claude_agent_sdk import tool
from pydantic import BaseModel, ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker
from ulid import ULID

from flosswing.agent.runtime import run_session
from flosswing.config import Config
from flosswing.errors import FlosswingError, ToolValidationError
from flosswing.state import session as st_session
from flosswing.state.models import AgentSession, HuntTask
from flosswing.tools import findings as t_findings
from flosswing.tools import fs as t_fs
from flosswing.tools import run_state as t_run_state
from flosswing.tools import search as t_search

_PROMPTS_ROOT = Path(__file__).resolve().parent.parent / "prompts"
_GAPFILL_SYSTEM_PROMPT_PATH = _PROMPTS_ROOT / "system" / "gapfill.md"

SessionFactory = sessionmaker[Session]

# Per docs/tool-contracts.md § Tool scope matrix: Gapfill = 6 tools.
# Per design decision #6 (UPSIZED) query_findings is registered. Keep
# the constant alongside the builder so the count is auditable.
_GAPFILL_TOOL_COUNT: int = 6


@dataclass(frozen=True)
class GapfillStageResult:
    outcome: Literal[
        "completed", "refused", "budget_exceeded", "errored", "skipped"
    ]
    tasks_queued: int
    cap: int
    input_tokens: int = 0
    output_tokens: int = 0

    @classmethod
    def skipped(cls) -> GapfillStageResult:
        return cls(
            outcome="skipped",
            tasks_queued=0,
            cap=0,
            input_tokens=0,
            output_tokens=0,
        )


# -----------------------------------------------------------------------------
# Private helpers
# -----------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _estimate_cost_usd(
    *, model: str, input_tokens: int, output_tokens: int
) -> float:
    rates = {
        "claude-opus-4-7": (15.0, 75.0),
        "claude-sonnet-4-6": (3.0, 15.0),
        "claude-haiku-4-5": (0.80, 4.00),
    }
    in_rate, out_rate = rates.get(model, (15.0, 75.0))
    return (input_tokens / 1_000_000) * in_rate + (
        output_tokens / 1_000_000
    ) * out_rate


# -----------------------------------------------------------------------------
# Tool builder — Gapfill-scoped (6 tools per docs/tool-contracts.md § Tool
# scope matrix). Mirrors stages/validate.py shape; kept inline because
# Gapfill is the only consumer of this combination.
# -----------------------------------------------------------------------------


class _ToolError(BaseModel):
    error: str
    message: str
    retryable: bool


def _ok(payload: BaseModel) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": payload.model_dump_json()}]}


def _err(code: str, message: str, retryable: bool) -> dict[str, Any]:
    return {
        "content": [
            {
                "type": "text",
                "text": _ToolError(
                    error=code, message=message, retryable=retryable
                ).model_dump_json(),
            }
        ],
        "is_error": True,
    }


def _wrap_call(
    fn: Callable[..., BaseModel],
    *,
    input_model: type[BaseModel],
    args: dict[str, Any],
    **kwargs: Any,
) -> dict[str, Any]:
    try:
        inp = input_model.model_validate(args)
    except ValidationError as e:
        return _err(ToolValidationError.code, str(e), retryable=False)
    try:
        out = fn(inp, **kwargs)
    except FlosswingError as e:
        return _err(e.code, e.message, retryable=e.retryable)
    return _ok(out)


def _build_gapfill_tools(
    *,
    repo_root: Path,
    run_id: str,
    agent_session_id: str,
    gapfill_new_task_cap: int,
    budget_total: int,
    total_token_budget: int,
) -> list[Any]:
    """Build the 6 Gapfill-scoped tool callables for ClaudeAgentOptions.

    Per docs/tool-contracts.md § Tool scope matrix: read_file, list_dir,
    grep, query_findings, query_run_state, add_hunt_task. The
    add_hunt_task wrapper closes over ``gapfill_new_task_cap`` so the
    tool layer can enforce the 20% cap on top of the prompt-side
    message.
    """
    del agent_session_id  # reserved for future per-tool telemetry tagging

    @tool(
        "read_file",
        "Read a file (or line range) from the target repository (read-only).",
        t_fs.ReadFileInput.model_json_schema(),
    )
    async def _read_file(args: dict[str, Any]) -> dict[str, Any]:
        return _wrap_call(
            t_fs.read_file,
            input_model=t_fs.ReadFileInput,
            args=args,
            repo_root=repo_root,
        )

    @tool(
        "list_dir",
        "List immediate children of a directory in the target repository.",
        t_fs.ListDirInput.model_json_schema(),
    )
    async def _list_dir(args: dict[str, Any]) -> dict[str, Any]:
        return _wrap_call(
            t_fs.list_dir,
            input_model=t_fs.ListDirInput,
            args=args,
            repo_root=repo_root,
        )

    @tool(
        "grep",
        "Regex search the target repository via ripgrep.",
        t_search.GrepInput.model_json_schema(),
    )
    async def _grep(args: dict[str, Any]) -> dict[str, Any]:
        return _wrap_call(
            t_search.grep,
            input_model=t_search.GrepInput,
            args=args,
            repo_root=repo_root,
        )

    @tool(
        "query_findings",
        (
            "Read findings from the current run with optional filters on"
            " finding_id, attack_class, file, status, min_severity."
            " Useful for judging whether an attack class is"
            " under-represented in the finding pool, not just in the"
            " task pool."
        ),
        t_findings.QueryFindingsInput.model_json_schema(),
    )
    async def _query_findings(args: dict[str, Any]) -> dict[str, Any]:
        return _wrap_call(
            t_findings.query_findings,
            input_model=t_findings.QueryFindingsInput,
            args=args,
            run_id=run_id,
        )

    @tool(
        "query_run_state",
        (
            "Read aggregate run state: the recorded Recon architecture,"
            " the list of hunt_tasks with status and findings_count,"
            " budget_used and budget_remaining. Call once first; it is"
            " the source of truth for what Recon proposed and what Hunt"
            " did with it."
        ),
        t_run_state.QueryRunStateInput.model_json_schema(),
    )
    async def _query_run_state(args: dict[str, Any]) -> dict[str, Any]:
        return _wrap_call(
            t_run_state.query_run_state,
            input_model=t_run_state.QueryRunStateInput,
            args=args,
            run_id=run_id,
            total_token_budget=total_token_budget,
        )

    @tool(
        "add_hunt_task",
        (
            "Enqueue a new Hunt task. Returns accepted=False with"
            " reason='gapfill_cap_reached' once the 20% cap is hit, or"
            " reason='budget exhausted (...)' if the global budget cap"
            " is hit. Treat either as a stop signal."
        ),
        t_findings.AddHuntTaskInput.model_json_schema(),
    )
    async def _add_hunt_task(args: dict[str, Any]) -> dict[str, Any]:
        return _wrap_call(
            t_findings.add_hunt_task,
            input_model=t_findings.AddHuntTaskInput,
            args=args,
            run_id=run_id,
            source="gapfill",
            budget_total=budget_total,
            gapfill_new_task_cap=gapfill_new_task_cap,
        )

    return [
        _read_file,
        _list_dir,
        _grep,
        _query_findings,
        _query_run_state,
        _add_hunt_task,
    ]


# -----------------------------------------------------------------------------
# Main entry point
# -----------------------------------------------------------------------------


def _compute_cap(*, recon_task_count: int) -> int:
    """Per design decision #1: max(1, recon_task_count // 5).

    The floor of 1 is binding even when recon_task_count == 0 — Gapfill
    should always be able to propose at least one task if it judges
    coverage incomplete. The orchestrator's gate
    (hunt_result.tasks_succeeded >= 1) prevents reaching this stage
    when Hunt didn't succeed, but the arithmetic is defensive.
    """
    return max(1, recon_task_count // 5)


def _load_prompt(*, cap: int) -> tuple[str, str]:
    """Load gapfill.md and substitute ``<cap>`` with the computed literal.

    Returns ``(system_prompt_text, sha256_hex)``. The hash is computed
    over the post-substitution text so two runs with different
    Recon-task counts hash differently — the prompt content actually
    differs.
    """
    raw = _GAPFILL_SYSTEM_PROMPT_PATH.read_text(encoding="utf-8")
    text = raw.replace("<cap>", str(cap))
    sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return text, sha


def _compose_user_prompt() -> str:
    """Brief user prompt — the agent does the real work via the tools.

    The Recon architecture, the Hunt task log, and the finding details
    all come in via query_run_state / query_findings rather than via
    the user message. Per spec § Gapfill system prompt, the system
    prompt tells the agent which tools to call and in what order; the
    user prompt is a thin trigger.
    """
    return (
        "You are running as the Gapfill stage. The Recon and Hunt "
        "stages have completed. Call query_run_state() to read the "
        "current state, then propose any additional hunt tasks you "
        "judge necessary via add_hunt_task() — up to the cap stated "
        "in your system prompt. Zero new tasks is a valid outcome."
    )


async def run(
    *,
    run_id: str,
    repo: Path,
    cfg: Config,
    session_factory: SessionFactory,
) -> GapfillStageResult:
    """Run Gapfill exactly once for ``run_id``.

    Per ARCHITECTURE.md § Stage 4 ("Gapfill runs **once** per run; no
    recursive expansion in v1") and design decision #2 of the spec
    (queue-and-stop; no auto-re-pass within the same run). The new
    hunt_tasks rows stay status='pending' for the operator's next
    invocation.

    Per plan-time decision #4 the stage does NOT take a hunt_result
    parameter — the recon-task count comes from the DB directly. The
    orchestrator gates the stage on ``hunt_result.tasks_succeeded >= 1``
    upstream.
    """
    del session_factory  # st_session module provides its own session_factory

    # Snapshot the recon-task count for the cap arithmetic. Per plan-
    # time decision #1, read from the DB rather than from any in-memory
    # HuntStageResult shape — independent of orchestrator state.
    with st_session.session_scope() as s:
        recon_task_count = len(
            s.execute(
                select(HuntTask).where(
                    HuntTask.run_id == run_id,
                    HuntTask.source == "recon",
                )
            ).scalars().all()
        )
    cap = _compute_cap(recon_task_count=recon_task_count)

    system_prompt, prompt_hash = _load_prompt(cap=cap)
    user_prompt = _compose_user_prompt()

    # Pre-allocate the agent_session_id; the audit row is INSERTed
    # *after* the session returns (matches v0.3 Hunt; satisfies the
    # ck_agent_sessions_outcome CHECK with a terminal value). Per
    # plan-time decision #3 the Gapfill stage uses the v0.3 Hunt
    # "INSERT after" pattern rather than v0.6 Validate's partial-INSERT
    # pattern — Gapfill has no tool that FKs back to agent_sessions
    # during the session (unlike validate_finding), so the partial
    # INSERT is unnecessary.
    agent_session_id = str(ULID())

    # The total_token_budget passed to query_run_state is the sum of
    # the four per-stage caps in cfg — it's a best-effort estimate the
    # agent uses to decide how aggressive to be. Per the contract:
    # "best-effort against any total estimate the config carries."
    total_token_budget = (
        cfg.recon_token_budget
        + cfg.hunt_token_budget
        + cfg.validate_token_budget
        + cfg.gapfill_token_budget
    )

    tools = _build_gapfill_tools(
        repo_root=repo,
        run_id=run_id,
        agent_session_id=agent_session_id,
        gapfill_new_task_cap=cap,
        # The global cap on total hunt_tasks for this run. v0.3's
        # Recon-side default is 20 (see Run.budget_total at row insert
        # time in orchestrator.py); we mirror that here. A future
        # milestone may expose this as a CLI flag.
        budget_total=20,
        total_token_budget=total_token_budget,
    )

    started_at = _now_iso()
    session_result = await run_session(
        model=cfg.model,
        provider=cfg.provider,
        system_prompt=system_prompt,
        tools=tools,
        user_prompt=user_prompt,
        token_budget=cfg.gapfill_token_budget,
        auth_env=cfg.auth_env,
        run_id=run_id,
        stage="gapfill",
        agent_session_id=agent_session_id,
    )
    finished_at = _now_iso()
    cost = _estimate_cost_usd(
        model=cfg.model,
        input_tokens=session_result.input_tokens,
        output_tokens=session_result.output_tokens,
    )

    # INSERT the audit row after the session — matches v0.3 Hunt's pattern.
    with st_session.session_scope() as s:
        s.add(
            AgentSession(
                id=agent_session_id,
                run_id=run_id,
                stage="gapfill",
                task_id=None,
                finding_id=None,
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

    # Count new source='gapfill' rows for the result. Read the DB
    # post-session — this is the authoritative count, independent of
    # whatever the agent claims to have queued.
    with st_session.session_scope() as s:
        tasks_queued = len(
            s.execute(
                select(HuntTask).where(
                    HuntTask.run_id == run_id,
                    HuntTask.source == "gapfill",
                )
            ).scalars().all()
        )

    # Map runtime outcome -> GapfillStageResult outcome. The runtime's
    # ``timed_out`` is folded into ``errored`` for the result (we don't
    # surface a separate timed_out bucket at the stage level).
    outcome_map: dict[
        str,
        Literal["completed", "refused", "budget_exceeded", "errored"],
    ] = {
        "completed": "completed",
        "refused": "refused",
        "budget_exceeded": "budget_exceeded",
        "errored": "errored",
        "timed_out": "errored",
    }
    stage_outcome = outcome_map.get(session_result.outcome, "errored")

    return GapfillStageResult(
        outcome=stage_outcome,
        tasks_queued=tasks_queued,
        cap=cap,
        input_tokens=session_result.input_tokens,
        output_tokens=session_result.output_tokens,
    )


__all__ = ["GapfillStageResult", "run"]
