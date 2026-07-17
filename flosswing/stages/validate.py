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

"""Validate stage orchestration.

Sequentially walks every `pending_validation` finding for the current
run, spawns one agent session per finding with the eight v0.6-scoped
tools (per design decision #1 UPSIZED), audits the session in
`agent_sessions`, and transitions `findings.status` and
`findings.validated_at` based on the outcome. Returns a
ValidateStageResult summarizing the stage.

Per docs/specs/2026-06-02-v0.6-validate-design.md § Component
responsibilities stages/validate.py.
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
from flosswing.prompts import load_attack_class_fragment
from flosswing.sandbox.base import CompileAndRunInput
from flosswing.state import session as st_session
from flosswing.state.models import AgentSession, Finding, Validation
from flosswing.tools import execution as t_execution
from flosswing.tools import findings as t_findings
from flosswing.tools import fs as t_fs
from flosswing.tools import search as t_search
from flosswing.tools import symbols as t_symbols

_PROMPTS_ROOT = Path(__file__).resolve().parent.parent / "prompts"
_VALIDATE_SYSTEM_PROMPT_PATH = _PROMPTS_ROOT / "system" / "validate.md"

SessionFactory = sessionmaker[Session]

# Per design decision #1 (UPSIZED) the full per-matrix Validate scope is
# 8 tools. Keep the constant alongside the builder so the count is
# auditable.
_VALIDATE_TOOL_COUNT: int = 8

_SEVERITY_RANK: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


@dataclass(frozen=True)
class ValidateStageResult:
    findings_processed: int
    findings_confirmed: int
    findings_rejected: int
    findings_uncertain: int
    findings_refused: int
    findings_budget_exceeded: int
    findings_errored: int
    # Session completed cleanly but the agent never called validate_finding.
    # Per design decision #5, the finding stays pending_validation; this
    # bucket exists so the operator can see the count distinctly from the
    # other non-terminal outcomes.
    findings_no_verdict: int
    input_tokens_total: int = 0
    output_tokens_total: int = 0

    @classmethod
    def skipped(cls) -> ValidateStageResult:
        return cls(0, 0, 0, 0, 0, 0, 0, 0, 0, 0)


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
# Tool builder — Validate-scoped (8 tools per design decision #1 UPSIZED).
# Mirrors stages/hunt.py shape; kept inline since Validate is the only consumer.
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


async def _wrap_async_call(
    fn: Callable[..., Any],
    *,
    input_model: type[BaseModel],
    args: dict[str, Any],
    **kwargs: Any,
) -> dict[str, Any]:
    """Async variant for compile_and_run (the only async tool in Validate)."""
    try:
        inp = input_model.model_validate(args)
    except ValidationError as e:
        return _err(ToolValidationError.code, str(e), retryable=False)
    try:
        out = await fn(inp, **kwargs)
    except FlosswingError as e:
        return _err(e.code, e.message, retryable=e.retryable)
    return _ok(out)


def _build_validate_tools(
    *,
    repo_root: Path,
    run_id: str,
    finding_id: str,
    agent_session_id: str,
) -> list[Any]:
    """Build the 8 Validate-scoped tool callables for ClaudeAgentOptions.

    Per docs/specs/2026-06-02-v0.6-validate-design.md § Tool list per design
    decision #1 (UPSIZED): full per-matrix scope = 8 tools.

    Per plan-time decision #5, ``finding_id`` and ``agent_session_id`` are
    closed over by the validate_finding wrapper — the agent does not pick
    which finding to validate; the stage decides.
    """
    # ``finding_id`` is intentionally captured by the validate_finding
    # wrapper only via the closure; the wrapper does NOT inject it into
    # the input model (the agent passes its own finding_id in the input,
    # which the contract requires). The closure exists so that future
    # tightening — e.g. server-side rejection if the agent supplies a
    # different finding_id — has the per-session binding available.
    del finding_id

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
        "compile_and_run",
        (
            "Build and execute attacker-supplied PoC code in an isolated"
            " sandbox. Returns exit code, stdout, stderr, duration, and"
            " resource usage. Use this to confirm or reject a finding by"
            " observing the bug's expected side effect."
        ),
        CompileAndRunInput.model_json_schema(),
    )
    async def _compile_and_run(args: dict[str, Any]) -> dict[str, Any]:
        return await _wrap_async_call(
            t_execution.compile_and_run,
            input_model=CompileAndRunInput,
            args=args,
            run_id=run_id,
            repo_root=repo_root,
        )

    @tool(
        "query_findings",
        (
            "Read findings from the current run with optional filters on"
            " finding_id, attack_class, file, status, min_severity."
            " Useful for pulling the full row of the finding under review."
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
        "validate_finding",
        (
            "Record your adversarial-review verdict for the assigned"
            " finding. Call exactly once with verdict ('confirmed',"
            " 'rejected', or 'uncertain'), rationale (>=50 chars), and"
            " an optional evidence_files list."
        ),
        t_findings.ValidateFindingInput.model_json_schema(),
    )
    async def _validate_finding(args: dict[str, Any]) -> dict[str, Any]:
        return _wrap_call(
            t_findings.validate_finding,
            input_model=t_findings.ValidateFindingInput,
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
        _compile_and_run,
        _query_findings,
        _validate_finding,
    ]


# -----------------------------------------------------------------------------
# Main entry point
# -----------------------------------------------------------------------------


def _compose_user_prompt(finding: Finding) -> str:
    """Per-finding header passed to the Validator session.

    Per spec § Component responsibilities: the Validator has
    query_findings available if it wants the full row; this is a
    convenience header.
    """
    fragment = load_attack_class_fragment(finding.attack_class)
    return (
        f"Finding under review:\n"
        f"  finding_id:   {finding.id}\n"
        f"  attack_class: {finding.attack_class}\n"
        f"  file:         {finding.file}\n"
        f"  function:     {finding.function or '<unknown>'}\n"
        f"  lines:        {finding.line_start}-{finding.line_end}\n"
        f"  severity:     {finding.severity}\n"
        f"  confidence:   {finding.confidence}\n"
        f"  title:        {finding.title}\n"
        "\n"
        "Description:\n"
        f"{finding.description}\n"
        "\n"
        f"PoC code (if any):\n"
        f"{finding.poc_code or '<none>'}\n"
        "\n"
        "---\n"
        "Attack-class guidance:\n"
        f"{fragment}\n"
    )


async def run(
    *,
    run_id: str,
    repo: Path,
    cfg: Config,
    session_factory: SessionFactory,
) -> ValidateStageResult:
    """Process every pending_validation finding for run_id sequentially.

    Per design decision #2: sequential per-finding execution. One Validator
    session at a time. No asyncio.gather, no Semaphore.
    """
    del session_factory  # accepted for stage-API parity; we use st_session.

    system_prompt = _VALIDATE_SYSTEM_PROMPT_PATH.read_text(encoding="utf-8")
    prompt_hash = hashlib.sha256(system_prompt.encode("utf-8")).hexdigest()

    # Snapshot pending findings, ordered by severity DESC, created_at ASC.
    with st_session.session_scope() as s:
        pending = (
            s.execute(
                select(Finding).where(
                    Finding.run_id == run_id,
                    Finding.status == "pending_validation",
                )
            )
            .scalars()
            .all()
        )
        snapshot = sorted(
            [
                (_SEVERITY_RANK.get(f.severity, 99), f.created_at, f.id)
                for f in pending
            ]
        )
        finding_ids_in_order = [fid for _, _, fid in snapshot]

    findings_confirmed = 0
    findings_rejected = 0
    findings_uncertain = 0
    findings_refused = 0
    findings_budget_exceeded = 0
    findings_errored = 0
    findings_no_verdict = 0
    input_tokens_total = 0
    output_tokens_total = 0

    for finding_id in finding_ids_in_order:
        # Re-fetch each finding fresh; defensive re-check that status hasn't
        # changed (single-writer invariant — shouldn't happen, but be safe).
        with st_session.session_scope() as s:
            finding = s.get(Finding, finding_id)
            if finding is None or finding.status != "pending_validation":
                continue
            user_prompt = _compose_user_prompt(finding)

        # Pre-allocate the agent_session_id and INSERT the audit row
        # *before* awaiting the session so that the validate_finding tool's
        # FK to agent_sessions(id) can resolve when the agent calls it
        # mid-session. Per docs/specs/2026-06-02-v0.6-validate-design.md
        # § Component responsibilities steps (c)→(f): INSERT partial row,
        # await session, UPDATE final fields.
        #
        # NOTE: this diverges from plan-time decision #1 (which inherited
        # v0.3 Hunt's "INSERT after" pattern). v0.3 Hunt doesn't have this
        # problem because record_finding has no FK to agent_sessions. The
        # design spec wins per CLAUDE.md "spec and code disagree → spec
        # wins"; the schema CHECK on outcome forces a placeholder terminal
        # value during the in-flight window, which is then overwritten by
        # the post-session UPDATE.
        agent_session_id = str(ULID())
        started_at = _now_iso()

        with st_session.session_scope() as s:
            s.add(
                AgentSession(
                    id=agent_session_id,
                    run_id=run_id,
                    stage="validate",
                    task_id=None,
                    finding_id=finding_id,
                    model=cfg.model,
                    system_prompt_hash=prompt_hash,
                    input_tokens=0,
                    output_tokens=0,
                    cache_read_tokens=0,
                    cache_write_tokens=0,
                    cost_usd=0.0,
                    duration_ms=0,
                    # Placeholder terminal value to satisfy
                    # ck_agent_sessions_outcome; overwritten below.
                    outcome="completed",
                    refusal_text=None,
                    error_text=None,
                    tool_calls_count=0,
                    started_at=started_at,
                    # Placeholder; finished_at is NOT NULL in the schema,
                    # overwritten below with the real timestamp.
                    finished_at=started_at,
                )
            )

        tools = _build_validate_tools(
            repo_root=repo,
            run_id=run_id,
            finding_id=finding_id,
            agent_session_id=agent_session_id,
        )

        session_result = await run_session(
            model=cfg.model,
            provider=cfg.provider,
            system_prompt=system_prompt,
            tools=tools,
            user_prompt=user_prompt,
            token_budget=cfg.validate_token_budget,
            auth_env=cfg.auth_env,
            run_id=run_id,
            stage="validate",
            finding_id=finding_id,
            # The runtime accepts but does not consume agent_session_id;
            # it's reserved for future per-session telemetry tagging and
            # lets test stubs read the same pre-allocated id the real
            # validate_finding tool wrapper closes over.
            agent_session_id=agent_session_id,
        )
        finished_at = _now_iso()
        cost = _estimate_cost_usd(
            model=cfg.model,
            input_tokens=session_result.input_tokens,
            output_tokens=session_result.output_tokens,
        )
        input_tokens_total += session_result.input_tokens
        output_tokens_total += session_result.output_tokens

        # UPDATE the audit row with the real outcome / usage / timestamps.
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

        # Classify finding outcome. If the agent called validate_finding,
        # a validations row exists and the finding's status is one of
        # confirmed/rejected/uncertain.
        with st_session.session_scope() as s:
            v = s.execute(
                select(Validation).where(Validation.finding_id == finding_id)
            ).scalar_one_or_none()
            verdict = v.verdict if v is not None else None

        if session_result.outcome == "refused":
            findings_refused += 1
        elif session_result.outcome == "budget_exceeded":
            findings_budget_exceeded += 1
        elif session_result.outcome == "errored":
            findings_errored += 1
        elif session_result.outcome == "completed":
            if verdict is None:
                # Completed cleanly without calling validate_finding.
                findings_no_verdict += 1
            elif verdict == "confirmed":
                findings_confirmed += 1
            elif verdict == "rejected":
                findings_rejected += 1
            elif verdict == "uncertain":
                findings_uncertain += 1
            else:
                # ck_validations_verdict would have prevented this,
                # but be defensive.
                findings_no_verdict += 1
        else:
            # Any other outcome literal (timed_out etc.) -> errored bucket.
            findings_errored += 1

    return ValidateStageResult(
        findings_processed=len(finding_ids_in_order),
        findings_confirmed=findings_confirmed,
        findings_rejected=findings_rejected,
        findings_uncertain=findings_uncertain,
        findings_refused=findings_refused,
        findings_budget_exceeded=findings_budget_exceeded,
        findings_errored=findings_errored,
        findings_no_verdict=findings_no_verdict,
        input_tokens_total=input_tokens_total,
        output_tokens_total=output_tokens_total,
    )


__all__ = ["ValidateStageResult", "run"]
