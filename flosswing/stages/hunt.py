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
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from claude_agent_sdk import tool
from pydantic import BaseModel, ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker
from ulid import ULID

from flosswing.agent.runtime import run_session
from flosswing.config import Config
from flosswing.errors import FlosswingError, ToolValidationError
from flosswing.state import session as st_session
from flosswing.state.models import AgentSession, Finding, HuntTask
from flosswing.tools import findings as t_findings
from flosswing.tools import fs as t_fs
from flosswing.tools import search as t_search

_PROMPTS_ROOT = Path(__file__).resolve().parent.parent / "prompts"
_HUNT_SYSTEM_PROMPT_PATH = _PROMPTS_ROOT / "system" / "hunt.md"
_ATTACK_CLASS_DIR = _PROMPTS_ROOT / "attack_classes"

_GENERIC_FRAGMENT_FALLBACK = (
    "No attack-class-specific guidance has been authored for "
    "`{attack_class}` yet. Apply general code-review principles for "
    "this class, lean toward `confidence='speculative'`, and stop "
    "after a single pass through the scope hint."
)

SessionFactory = sessionmaker[Session]


@dataclass(frozen=True)
class HuntStageResult:
    tasks_processed: int
    tasks_succeeded: int
    tasks_refused: int
    tasks_budget_exceeded: int
    tasks_errored: int
    findings_total: int

    @classmethod
    def skipped(cls) -> HuntStageResult:
        return cls(0, 0, 0, 0, 0, 0)


# -----------------------------------------------------------------------------
# Private helpers
# -----------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _load_attack_class_fragment(attack_class: str) -> str:
    """Load the per-attack-class prompt fragment, or a generic fallback.

    Per design decision #3, this lives as a private helper here in
    stages/hunt.py rather than in prompts/__init__.py — single consumer.
    Lift to a shared API only when Validate / Gapfill need it.
    """
    p = _ATTACK_CLASS_DIR / f"{attack_class}.md"
    if p.exists():
        return p.read_text(encoding="utf-8")
    return _GENERIC_FRAGMENT_FALLBACK.format(attack_class=attack_class)


def _compose_user_prompt(task: HuntTask) -> str:
    fragment = _load_attack_class_fragment(task.attack_class)
    return (
        f"Attack class: {task.attack_class}\n"
        f"Scope hint:   {task.scope_hint}\n"
        f"Rationale:    {task.rationale}\n"
        "\n"
        "---\n"
        f"{fragment}\n"
    )


def _estimate_cost_usd(
    *, model: str, input_tokens: int, output_tokens: int
) -> float:
    rates = {
        "claude-opus-4-7": (15.0, 75.0),
        "claude-sonnet-4-6": (3.0, 15.0),
        "claude-haiku-4-5": (0.80, 4.00),
    }
    in_rate, out_rate = rates.get(model, (15.0, 75.0))
    return (input_tokens / 1_000_000) * in_rate + (output_tokens / 1_000_000) * out_rate


# -----------------------------------------------------------------------------
# Tool builder — Hunt-scoped (4 tools: read_file, list_dir, grep,
# record_finding). Mirrors agent.tool_registry.build_recon_tools shape;
# kept inline in this file rather than expanded in tool_registry because
# it's the only Hunt consumer in v0.3.
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


def _build_hunt_tools(
    *,
    repo_root: Path,
    run_id: str,
    hunt_task_id: str,
) -> list[Any]:
    """Build the 4 Hunt-scoped tool callables for ClaudeAgentOptions."""

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
        "record_finding",
        (
            "Record a vulnerability finding. confidence='likely' or "
            "'speculative' only in v0.3 (no compile_and_run yet)."
        ),
        t_findings.RecordFindingInput.model_json_schema(),
    )
    async def _record_finding(args: dict[str, Any]) -> dict[str, Any]:
        return _wrap_call(
            t_findings.record_finding,
            input_model=t_findings.RecordFindingInput,
            args=args,
            run_id=run_id,
            hunt_task_id=hunt_task_id,
            repo_root=repo_root,
        )

    return [_read_file, _list_dir, _grep, _record_finding]


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
            system_prompt=system_prompt,
            tools=tools,
            user_prompt=user_prompt,
            token_budget=cfg.hunt_token_budget,
            auth_env=cfg.auth_env,
            run_id=run_id,
            stage="hunt",
            task_id=task_id,
        )
        finished_at = _now_iso()
        cost = _estimate_cost_usd(
            model=cfg.model,
            input_tokens=session_result.input_tokens,
            output_tokens=session_result.output_tokens,
        )

        # INSERT the audit row after the session — same shape as Recon does
        # (the ck_agent_sessions_outcome CHECK only allows terminal values).
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
    )


__all__ = ["HuntStageResult", "run", "run_session"]
