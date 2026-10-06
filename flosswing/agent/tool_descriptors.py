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


"""Transport-neutral tool descriptors.

A ToolDescriptor carries a tool's name, description, input model and a bound
``call`` that validates args, invokes the pure implementation and returns the
MCP content / ToolError payload. Both the claude-agent-sdk adapter
(``to_sdk_tool``) and a future stdio MCP server build from these.
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


def _invoke(
    fn: Callable[..., BaseModel],
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


@dataclass(frozen=True)
class ToolDescriptor:
    name: str
    description: str
    input_model: type[BaseModel]
    call: Callable[[dict[str, Any]], dict[str, Any]]


def _desc(
    name: str,
    description: str,
    input_model: type[BaseModel],
    fn: Callable[..., BaseModel],
    **bound: Any,
) -> ToolDescriptor:
    return ToolDescriptor(
        name,
        description,
        input_model,
        lambda args: _invoke(fn, input_model, args, **bound),
    )


def to_sdk_tool(d: ToolDescriptor) -> Any:
    """Wrap a descriptor as a claude_agent_sdk ``@tool`` callable."""

    @tool(d.name, d.description, d.input_model.model_json_schema())
    async def _t(args: dict[str, Any]) -> dict[str, Any]:
        return d.call(args)

    return _t


def build_recon_descriptors(
    *, repo_root: Path, run_id: str, budget_total: int
) -> list[ToolDescriptor]:
    """The 5 Recon-scoped tools."""
    return [
        _desc(
            "read_file",
            "Read a file (or line range) from the target repository (read-only).",
            t_fs.ReadFileInput,
            t_fs.read_file,
            repo_root=repo_root,
        ),
        _desc(
            "list_dir",
            "List immediate children of a directory in the target repository.",
            t_fs.ListDirInput,
            t_fs.list_dir,
            repo_root=repo_root,
        ),
        _desc(
            "grep",
            "Regex search the target repository via ripgrep.",
            t_search.GrepInput,
            t_search.grep,
            repo_root=repo_root,
        ),
        _desc(
            "record_recon_artifact",
            (
                "Save Recon's architecture analysis (languages, build commands,"
                " entry points, trust boundaries, subsystems)."
            ),
            t_findings.RecordReconArtifactInput,
            t_findings.record_recon_artifact,
            run_id=run_id,
        ),
        _desc(
            "add_hunt_task",
            "Enqueue a Hunt task. Returns accepted=False if budget exhausted.",
            t_findings.AddHuntTaskInput,
            t_findings.add_hunt_task,
            run_id=run_id,
            source="recon",
            budget_total=budget_total,
        ),
    ]
