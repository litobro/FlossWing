"""SDK tool registration helper.

Each Recon tool becomes a claude_agent_sdk @tool callable whose body
validates input, calls the pure tool implementation, and returns a
text-content payload. FlosswingError subclasses are converted to
structured ToolError payloads (is_error=True) so the agent sees the
error code and can recover.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from claude_agent_sdk import tool
from pydantic import BaseModel, ValidationError

from flosswing.errors import FlosswingError, ToolValidationError
from flosswing.tools import findings as t_findings
from flosswing.tools import fs as t_fs
from flosswing.tools import search as t_search


@dataclass
class RegistryContext:
    repo_root: Path
    run_id: str
    budget_total: int


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


def build_recon_tools(ctx: RegistryContext) -> list[Any]:
    """Build the 5 Recon-scoped tool callables for ClaudeAgentOptions."""

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
            repo_root=ctx.repo_root,
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
            repo_root=ctx.repo_root,
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
            repo_root=ctx.repo_root,
        )

    @tool(
        "record_recon_artifact",
        (
            "Save Recon's architecture analysis (languages, build commands,"
            " entry points, trust boundaries, subsystems)."
        ),
        t_findings.RecordReconArtifactInput.model_json_schema(),
    )
    async def _record_artifact(args: dict[str, Any]) -> dict[str, Any]:
        return _wrap_call(
            t_findings.record_recon_artifact,
            input_model=t_findings.RecordReconArtifactInput,
            args=args,
            run_id=ctx.run_id,
        )

    @tool(
        "add_hunt_task",
        "Enqueue a Hunt task. Returns accepted=False if budget exhausted.",
        t_findings.AddHuntTaskInput.model_json_schema(),
    )
    async def _add_task(args: dict[str, Any]) -> dict[str, Any]:
        return _wrap_call(
            t_findings.add_hunt_task,
            input_model=t_findings.AddHuntTaskInput,
            args=args,
            run_id=ctx.run_id,
            source="recon",
            budget_total=ctx.budget_total,
        )

    return [_read_file, _list_dir, _grep, _record_artifact, _add_task]
