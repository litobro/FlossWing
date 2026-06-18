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

"""Trace stage orchestration.

Sequentially walks every confirmed primary finding for the current run,
spawns one Tracer session per finding with the eight v0.9-scoped tools
(``read_file``, ``list_dir``, ``grep``, ``find_definition``,
``find_callers``, ``query_entry_points``, ``query_findings``,
``record_trace``), audits the session in ``agent_sessions``, and lets
``record_trace`` write the ``traces`` row plus ``findings.reachable``.
Returns a TraceStageResult summarising the stage.

Per docs/specs/2026-06-02-v0.9-trace-design.md § Component
responsibilities ``stages/trace.py``.
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
from sqlalchemy import or_, select
from sqlalchemy.orm import Session, sessionmaker
from ulid import ULID

from flosswing.agent.runtime import run_session
from flosswing.config import Config
from flosswing.errors import FlosswingError, ToolValidationError
from flosswing.state import session as st_session
from flosswing.state.models import AgentSession, Finding, Trace
from flosswing.tools import findings as t_findings
from flosswing.tools import fs as t_fs
from flosswing.tools import search as t_search
from flosswing.tools import symbols as t_symbols

_PROMPTS_ROOT = Path(__file__).resolve().parent.parent / "prompts"
_TRACE_SYSTEM_PROMPT_PATH = _PROMPTS_ROOT / "system" / "trace.md"

SessionFactory = sessionmaker[Session]

# Per docs/tool-contracts.md § Tool scope matrix: Trace = 8 tools
# (read_file, list_dir, grep, find_definition, find_callers,
# query_entry_points, query_findings, record_trace). Kept alongside the
# builder so the count is auditable.
_TRACE_TOOL_COUNT: int = 8


@dataclass(frozen=True)
class TraceStageResult:
    outcome: Literal["completed", "skipped"]
    # Confirmed primary findings selected for tracing.
    findings_total: int = 0
    # Sessions that successfully wrote a ``traces`` row.
    findings_traced: int = 0
    findings_reachable: int = 0
    findings_unreachable: int = 0
    findings_uncertain: int = 0
    findings_refused: int = 0
    findings_errored: int = 0
    findings_budget_exceeded: int = 0
    input_tokens: int = 0
    output_tokens: int = 0

    @classmethod
    def skipped(cls) -> TraceStageResult:
        return cls(outcome="skipped")


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


def _load_prompt(*, max_depth: int) -> tuple[str, str]:
    """Load trace.md and substitute the ``<max_depth>`` placeholder.

    The placeholder is substituted via plain ``str.replace`` per Task C;
    we hash the *substituted* prompt so two runs with different
    ``trace_max_depth`` values get distinct ``system_prompt_hash``
    values in ``agent_sessions``.
    """
    raw = _TRACE_SYSTEM_PROMPT_PATH.read_text(encoding="utf-8")
    text = raw.replace("<max_depth>", str(max_depth))
    sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return text, sha


@dataclass(frozen=True)
class _FindingSnapshot:
    """Plain-Python snapshot of the ORM finding row.

    ``session_scope()`` commits on exit and expires loaded attributes,
    so any ORM field touched outside the ``with`` block would trigger a
    refresh against a closed session. We materialise the per-finding
    fields the user prompt needs into a frozen tuple inside the
    selection scope and only read snapshots in the agent loop.
    """

    id: str
    file: str
    function: str | None
    line_start: int
    line_end: int
    attack_class: str
    title: str
    description: str


# -----------------------------------------------------------------------------
# Tool builder — Trace-scoped (8 tools per docs/tool-contracts.md § Tool
# scope matrix). Mirrors stages/validate.py shape; kept inline since
# Trace is the only consumer.
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


def _build_trace_tools(
    *,
    repo_root: Path,
    run_id: str,
    agent_session_id: str,
) -> list[Any]:
    """Build the 8 Trace-scoped tool callables for ClaudeAgentOptions.

    Per docs/tool-contracts.md § Tool scope matrix: read_file, list_dir,
    grep, find_definition, find_callers, query_entry_points,
    query_findings, record_trace. Order matches the matrix row.

    ``agent_session_id`` is closed over by the record_trace wrapper so
    the inserted ``traces`` row's ``agent_session_id`` FK resolves to
    the agent_sessions row the stage pre-inserted (the FK is
    ``ON DELETE RESTRICT``).
    """

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
        "find_definition",
        (
            "Locate the definition of a symbol in the indexed target"
            " repository. Optional file_hint or language narrows the"
            " search."
        ),
        t_symbols.FindDefinitionInput.model_json_schema(),
    )
    async def _find_definition(args: dict[str, Any]) -> dict[str, Any]:
        return _wrap_call(
            t_symbols.find_definition,
            input_model=t_symbols.FindDefinitionInput,
            args=args,
            run_id=run_id,
        )

    @tool(
        "find_callers",
        (
            "List call sites for a symbol. Returns symbol_not_found if"
            " no definition exists; ambiguous_symbol with candidates if"
            " >1 match (retry with file_hint to disambiguate)."
        ),
        t_symbols.FindCallersInput.model_json_schema(),
    )
    async def _find_callers(args: dict[str, Any]) -> dict[str, Any]:
        return _wrap_call(
            t_symbols.find_callers,
            input_model=t_symbols.FindCallersInput,
            args=args,
            run_id=run_id,
        )

    @tool(
        "query_entry_points",
        (
            "List Recon-identified entry points for the current run."
            " Call once at the start of the backward walk and cache the"
            " set; an entry-point match terminates the trace as"
            " reachable."
        ),
        t_symbols.QueryEntryPointsInput.model_json_schema(),
    )
    async def _query_entry_points(args: dict[str, Any]) -> dict[str, Any]:
        return _wrap_call(
            t_symbols.query_entry_points,
            input_model=t_symbols.QueryEntryPointsInput,
            args=args,
            run_id=run_id,
        )

    @tool(
        "query_findings",
        (
            "Read findings from the current run with optional filters on"
            " finding_id, attack_class, file, status, min_severity."
            " Use to fetch the full body of the finding under trace."
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
        "record_trace",
        (
            "Record the reachability trace for the assigned confirmed"
            " primary finding. Call exactly once with reachable"
            " ('reachable', 'unreachable', or 'uncertain'),"
            " entry_point_symbol (required when reachable='reachable'),"
            " call_chain (entry-first, bug-last), and a non-empty"
            " rationale."
        ),
        t_findings.RecordTraceInput.model_json_schema(),
    )
    async def _record_trace(args: dict[str, Any]) -> dict[str, Any]:
        return _wrap_call(
            t_findings.record_trace,
            input_model=t_findings.RecordTraceInput,
            args=args,
            run_id=run_id,
            agent_session_id=agent_session_id,
        )

    return [
        _read_file,
        _list_dir,
        _grep,
        _find_definition,
        _find_callers,
        _query_entry_points,
        _query_findings,
        _record_trace,
    ]


# -----------------------------------------------------------------------------
# Main entry point
# -----------------------------------------------------------------------------


def _compose_user_prompt(finding: _FindingSnapshot) -> str:
    """Per-finding header passed to the Tracer session.

    Spec § Trace agent contract: the Tracer needs the (file, function,
    line_start) tuple to anchor the backward walk; we include the
    title and description as context so the agent can sanity-check the
    finding before walking. ``query_findings`` is available for the
    full row.
    """
    return (
        f"Finding under trace:\n"
        f"  finding_id:   {finding.id}\n"
        f"  attack_class: {finding.attack_class}\n"
        f"  file:         {finding.file}\n"
        f"  function:     {finding.function or '<unknown>'}\n"
        f"  lines:        {finding.line_start}-{finding.line_end}\n"
        f"  title:        {finding.title}\n"
        "\n"
        "Description:\n"
        f"{finding.description}\n"
        "\n"
        "Walk backwards from "
        f"({finding.file}, {finding.function or '<unknown>'}, "
        f"line {finding.line_start}) via find_callers until you reach a"
        " Recon entry point (reachable), exhaust callers (unreachable),"
        " or hit something unresolvable in-repo (uncertain). Emit"
        " exactly one record_trace."
    )


async def run(
    *,
    run_id: str,
    repo: Path,
    cfg: Config,
    session_factory: SessionFactory,
) -> TraceStageResult:
    """Process every confirmed primary finding for ``run_id`` sequentially.

    Per spec § Component responsibilities ``stages/trace.py``: one
    Tracer session at a time, ULID order, per-finding failures are
    swallowed and counted in ``findings_errored``. Selection-query
    failures and prompt-loading failures propagate to the orchestrator.
    """
    del session_factory  # st_session.session_scope provides the factory

    system_prompt, prompt_hash = _load_prompt(
        max_depth=cfg.trace_max_depth
    )

    # Snapshot eligible findings inside the selection scope so we don't
    # touch ORM attributes after the session closes. Selection criteria
    # per spec § Stage selection: status='confirmed' AND (dedupe_role IS
    # NULL OR dedupe_role='primary'), ULID order (= creation order).
    snapshots: list[_FindingSnapshot] = []
    with st_session.session_scope() as s:
        rows = (
            s.execute(
                select(Finding)
                .where(
                    Finding.run_id == run_id,
                    Finding.status == "confirmed",
                    or_(
                        Finding.dedupe_role.is_(None),
                        Finding.dedupe_role == "primary",
                    ),
                )
                .order_by(Finding.id)
            )
            .scalars()
            .all()
        )
        for r in rows:
            snapshots.append(
                _FindingSnapshot(
                    id=r.id,
                    file=r.file,
                    function=r.function,
                    line_start=r.line_start,
                    line_end=r.line_end,
                    attack_class=r.attack_class,
                    title=r.title,
                    description=r.description,
                )
            )

    if not snapshots:
        return TraceStageResult.skipped()

    findings_traced = 0
    findings_reachable = 0
    findings_unreachable = 0
    findings_uncertain = 0
    findings_refused = 0
    findings_errored = 0
    findings_budget_exceeded = 0
    input_tokens_total = 0
    output_tokens_total = 0

    for snap in snapshots:
        agent_session_id = str(ULID())
        started_at = _now_iso()

        # Pre-allocate the agent_session_id and INSERT a partial
        # agent_sessions row *before* awaiting the session so that the
        # record_trace tool's FK to agent_sessions(id) can resolve when
        # the agent calls it mid-session. The FK is ON DELETE RESTRICT
        # (per docs/schema.sql traces table), so the row MUST exist by
        # the time record_trace runs. Mirrors v0.6 Validate's partial-
        # INSERT pattern; the placeholder terminal-outcome 'completed'
        # satisfies ck_agent_sessions_outcome and is overwritten by the
        # post-session UPDATE.
        try:
            with st_session.session_scope() as s:
                s.add(
                    AgentSession(
                        id=agent_session_id,
                        run_id=run_id,
                        stage="trace",
                        task_id=None,
                        finding_id=snap.id,
                        model=cfg.model,
                        system_prompt_hash=prompt_hash,
                        input_tokens=0,
                        output_tokens=0,
                        cache_read_tokens=0,
                        cache_write_tokens=0,
                        cost_usd=0.0,
                        duration_ms=0,
                        # Placeholder terminal value; overwritten below.
                        outcome="completed",
                        refusal_text=None,
                        error_text=None,
                        tool_calls_count=0,
                        started_at=started_at,
                        # Placeholder; finished_at is NOT NULL in the
                        # schema, overwritten below.
                        finished_at=started_at,
                    )
                )
        except Exception:
            # Pre-INSERT failed (FK violation, disk full, etc.). Count
            # the finding as errored and continue — the stage as a
            # whole must complete regardless of per-finding faults.
            findings_errored += 1
            continue

        user_prompt = _compose_user_prompt(snap)
        tools = _build_trace_tools(
            repo_root=repo,
            run_id=run_id,
            agent_session_id=agent_session_id,
        )

        try:
            session_result = await run_session(
                model=cfg.model,
                provider=cfg.provider,
                system_prompt=system_prompt,
                tools=tools,
                user_prompt=user_prompt,
                token_budget=cfg.trace_token_budget,
                auth_env=cfg.auth_env,
                run_id=run_id,
                stage="trace",
                finding_id=snap.id,
                agent_session_id=agent_session_id,
            )
        except Exception:
            # Per spec § Failure modes: per-finding session crashes are
            # swallowed and counted; the stage continues. UPDATE the
            # pre-inserted agent_sessions row so it doesn't linger with
            # placeholder counters.
            findings_errored += 1
            finished_at = _now_iso()
            try:
                with st_session.session_scope() as s:
                    sess = s.get(AgentSession, agent_session_id)
                    if sess is not None:
                        sess.outcome = "errored"
                        sess.finished_at = finished_at
            except Exception:
                # Best-effort cleanup; if the UPDATE also fails the
                # row stays with the placeholder values.
                pass
            continue

        finished_at = _now_iso()
        cost = _estimate_cost_usd(
            model=cfg.model,
            input_tokens=session_result.input_tokens,
            output_tokens=session_result.output_tokens,
        )
        input_tokens_total += session_result.input_tokens
        output_tokens_total += session_result.output_tokens

        # UPDATE the audit row with real outcome / usage / timestamps.
        with st_session.session_scope() as s:
            sess = s.get(AgentSession, agent_session_id)
            if sess is not None:
                sess.input_tokens = session_result.input_tokens
                sess.output_tokens = session_result.output_tokens
                sess.cache_read_tokens = session_result.cache_read_tokens
                sess.cache_write_tokens = session_result.cache_write_tokens
                sess.cost_usd = cost
                sess.duration_ms = session_result.duration_ms
                sess.outcome = session_result.outcome
                sess.refusal_text = session_result.refusal_text
                sess.error_text = session_result.error_text
                sess.tool_calls_count = session_result.tool_calls_count
                sess.finished_at = finished_at

        # Classify per-finding outcome.
        if session_result.outcome == "refused":
            findings_refused += 1
        elif session_result.outcome == "budget_exceeded":
            findings_budget_exceeded += 1
        elif session_result.outcome == "completed":
            # Check whether the agent actually wrote a traces row. Per
            # the contract, record_trace updates findings.reachable in
            # the same transaction, so the traces row is the canonical
            # signal that the trace landed.
            with st_session.session_scope() as s:
                trace_row = s.execute(
                    select(Trace).where(Trace.finding_id == snap.id)
                ).scalar_one_or_none()
                reachable_value: str | None = (
                    trace_row.reachable if trace_row is not None else None
                )

            if reachable_value is None:
                # Completed cleanly without calling record_trace. Treat
                # as a prompt-not-followed signal per Task E step 8.
                findings_errored += 1
            else:
                findings_traced += 1
                if reachable_value == "reachable":
                    findings_reachable += 1
                elif reachable_value == "unreachable":
                    findings_unreachable += 1
                elif reachable_value == "uncertain":
                    findings_uncertain += 1
                else:
                    # ck_traces_reachable would have prevented this,
                    # but be defensive — count as errored so the
                    # operator notices.
                    findings_errored += 1
        else:
            # 'errored', 'timed_out', or any other terminal literal
            # outside the three buckets above → errored bucket.
            findings_errored += 1

    return TraceStageResult(
        outcome="completed",
        findings_total=len(snapshots),
        findings_traced=findings_traced,
        findings_reachable=findings_reachable,
        findings_unreachable=findings_unreachable,
        findings_uncertain=findings_uncertain,
        findings_refused=findings_refused,
        findings_errored=findings_errored,
        findings_budget_exceeded=findings_budget_exceeded,
        input_tokens=input_tokens_total,
        output_tokens=output_tokens_total,
    )


__all__ = ["TraceStageResult", "run"]
