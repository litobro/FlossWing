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

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from claude_agent_sdk import tool
from pydantic import BaseModel, ValidationError

from flosswing.errors import FlosswingError, ToolValidationError
from flosswing.sandbox.base import CompileAndRunInput
from flosswing.tools import execution as t_execution
from flosswing.tools import findings as t_findings
from flosswing.tools import fs as t_fs
from flosswing.tools import run_state as t_run_state
from flosswing.tools import search as t_search
from flosswing.tools import symbols as t_symbols


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


async def _invoke_async(
    fn: Callable[..., Awaitable[BaseModel]],
    input_model: type[BaseModel],
    args: dict[str, Any],
    **kwargs: Any,
) -> dict[str, Any]:
    try:
        inp = input_model.model_validate(args)
    except ValidationError as e:
        return _err(ToolValidationError.code, str(e), retryable=False)
    try:
        out = await fn(inp, **kwargs)
    except FlosswingError as e:
        return _err(e.code, e.message, retryable=e.retryable)
    return _ok(out)


@dataclass(frozen=True)
class ToolDescriptor:
    """``call`` returns a dict, or an awaitable of one when ``is_async``."""

    name: str
    description: str
    input_model: type[BaseModel]
    call: Callable[[dict[str, Any]], Any]
    is_async: bool = False


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


def _desc_async(
    name: str,
    description: str,
    input_model: type[BaseModel],
    fn: Callable[..., Awaitable[BaseModel]],
    **bound: Any,
) -> ToolDescriptor:
    return ToolDescriptor(
        name,
        description,
        input_model,
        lambda args: _invoke_async(fn, input_model, args, **bound),
        is_async=True,
    )


def to_sdk_tool(d: ToolDescriptor) -> Any:
    """Wrap a descriptor as a claude_agent_sdk ``@tool`` callable."""

    @tool(d.name, d.description, d.input_model.model_json_schema())
    async def _t(args: dict[str, Any]) -> dict[str, Any]:
        if d.is_async:
            out: dict[str, Any] = await d.call(args)
            return out
        out_sync: dict[str, Any] = d.call(args)
        return out_sync

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


def _fs_search(repo_root: Path, *, with_list_dir: bool = True) -> list[ToolDescriptor]:
    ds = [
        _desc(
            "read_file",
            "Read a file (or line range) from the target repository (read-only).",
            t_fs.ReadFileInput,
            t_fs.read_file,
            repo_root=repo_root,
        )
    ]
    if with_list_dir:
        ds.append(
            _desc(
                "list_dir",
                "List immediate children of a directory in the target repository.",
                t_fs.ListDirInput,
                t_fs.list_dir,
                repo_root=repo_root,
            )
        )
        ds.append(
            _desc(
                "grep",
                "Regex search the target repository via ripgrep.",
                t_search.GrepInput,
                t_search.grep,
                repo_root=repo_root,
            )
        )
    return ds


def _symbol_descriptors(run_id: str) -> list[ToolDescriptor]:
    return [
        _desc(
            "find_definition",
            (
                "Locate the definition of a symbol in the indexed target"
                " repository. Optional file_hint or language narrows the"
                " search."
            ),
            t_symbols.FindDefinitionInput,
            t_symbols.find_definition,
            run_id=run_id,
        ),
        _desc(
            "find_callers",
            (
                "List call sites for a symbol. Returns symbol_not_found if"
                " no definition exists; ambiguous_symbol with candidates if"
                " >1 match (retry with file_hint to disambiguate)."
            ),
            t_symbols.FindCallersInput,
            t_symbols.find_callers,
            run_id=run_id,
        ),
    ]


def _query_findings(run_id: str, tail: str) -> ToolDescriptor:
    return _desc(
        "query_findings",
        (
            "Read findings from the current run with optional filters on"
            " finding_id, attack_class, file, status, min_severity."
            + tail
        ),
        t_findings.QueryFindingsInput,
        t_findings.query_findings,
        run_id=run_id,
    )


def build_hunt_descriptors(
    *, repo_root: Path, run_id: str, hunt_task_id: str
) -> list[ToolDescriptor]:
    """The 6 Hunt-scoped tools."""
    return [
        *_fs_search(repo_root),
        _desc(
            "record_finding",
            (
                "Record a vulnerability finding. confidence='likely' or "
                "'speculative' only in v0.3 (no compile_and_run yet)."
            ),
            t_findings.RecordFindingInput,
            t_findings.record_finding,
            run_id=run_id,
            hunt_task_id=hunt_task_id,
            repo_root=repo_root,
        ),
        *_symbol_descriptors(run_id),
    ]


def build_validate_descriptors(
    *, repo_root: Path, run_id: str, agent_session_id: str
) -> list[ToolDescriptor]:
    """The 8 Validate-scoped tools (compile_and_run is the only async one)."""
    return [
        *_fs_search(repo_root),
        *_symbol_descriptors(run_id),
        _desc_async(
            "compile_and_run",
            (
                "Build and execute attacker-supplied PoC code in an isolated"
                " sandbox. Returns exit code, stdout, stderr, duration, and"
                " resource usage. Use this to confirm or reject a finding by"
                " observing the bug's expected side effect."
            ),
            CompileAndRunInput,
            t_execution.compile_and_run,
            run_id=run_id,
            repo_root=repo_root,
        ),
        _query_findings(
            run_id,
            " Useful for pulling the full row of the finding under review.",
        ),
        _desc(
            "validate_finding",
            (
                "Record your adversarial-review verdict for the assigned"
                " finding. Call exactly once with verdict ('confirmed',"
                " 'rejected', or 'uncertain'), rationale (>=50 chars), and"
                " an optional evidence_files list."
            ),
            t_findings.ValidateFindingInput,
            t_findings.validate_finding,
            run_id=run_id,
            agent_session_id=agent_session_id,
        ),
    ]


def build_dedupe_descriptors(*, repo_root: Path, run_id: str) -> list[ToolDescriptor]:
    """The 4 Dedupe-scoped tools."""
    return [
        *_fs_search(repo_root, with_list_dir=False),
        _query_findings(
            run_id, " Use this to fetch the full body of each cluster member."
        ),
        _desc(
            "merge_findings",
            (
                "Collapse N duplicate findings into a single primary. Pass"
                " ALL duplicate IDs in one call; root_cause_summary must be"
                " >= 50 chars of substantive prose. Duplicates become"
                " status='superseded' — irreversible within the run."
            ),
            t_findings.MergeFindingsInput,
            t_findings.merge_findings,
            run_id=run_id,
        ),
        _desc(
            "link_variant",
            (
                "Flag a relationship between two findings without merging."
                " Both findings must share a dedupe_cluster_id. relationship"
                " is one of: same_root_cause, exploit_chain, preconditions."
            ),
            t_findings.LinkVariantInput,
            t_findings.link_variant,
            run_id=run_id,
        ),
    ]


def build_trace_descriptors(
    *, repo_root: Path, run_id: str, agent_session_id: str
) -> list[ToolDescriptor]:
    """The 8 Trace-scoped tools."""
    return [
        *_fs_search(repo_root),
        *_symbol_descriptors(run_id),
        _desc(
            "query_entry_points",
            (
                "List Recon-identified entry points for the current run."
                " Call once at the start of the backward walk and cache the"
                " set; an entry-point match terminates the trace as"
                " reachable."
            ),
            t_symbols.QueryEntryPointsInput,
            t_symbols.query_entry_points,
            run_id=run_id,
        ),
        _query_findings(
            run_id, " Use to fetch the full body of the finding under trace."
        ),
        _desc(
            "record_trace",
            (
                "Record the reachability trace for the assigned confirmed"
                " primary finding. Call exactly once with reachable"
                " ('reachable', 'unreachable', or 'uncertain'),"
                " entry_point_symbol (required when reachable='reachable'),"
                " call_chain (entry-first, bug-last), and a non-empty"
                " rationale."
            ),
            t_findings.RecordTraceInput,
            t_findings.record_trace,
            run_id=run_id,
            agent_session_id=agent_session_id,
        ),
    ]


def build_gapfill_descriptors(
    *,
    repo_root: Path,
    run_id: str,
    gapfill_new_task_cap: int,
    budget_total: int,
    total_token_budget: int,
) -> list[ToolDescriptor]:
    """The 6 Gapfill-scoped tools."""
    return [
        *_fs_search(repo_root),
        _query_findings(
            run_id,
            " Useful for judging whether an attack class is"
            " under-represented in the finding pool, not just in the"
            " task pool.",
        ),
        _desc(
            "query_run_state",
            (
                "Read aggregate run state: the recorded Recon architecture,"
                " the list of hunt_tasks with status and findings_count,"
                " budget_used and budget_remaining. Call once first; it is"
                " the source of truth for what Recon proposed and what Hunt"
                " did with it."
            ),
            t_run_state.QueryRunStateInput,
            t_run_state.query_run_state,
            run_id=run_id,
            total_token_budget=total_token_budget,
        ),
        _desc(
            "add_hunt_task",
            (
                "Enqueue a new Hunt task. Returns accepted=False with"
                " reason='gapfill_cap_reached' once the 20% cap is hit, or"
                " reason='budget exhausted (...)' if the global budget cap"
                " is hit. Treat either as a stop signal."
            ),
            t_findings.AddHuntTaskInput,
            t_findings.add_hunt_task,
            run_id=run_id,
            source="gapfill",
            budget_total=budget_total,
            gapfill_new_task_cap=gapfill_new_task_cap,
        ),
    ]
