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

"""Wrapper around claude-agent-sdk.

Spawns the `claude` CLI subprocess via ClaudeAgentOptions, drives one
session, returns a structured SessionResult. Outcome classification is
factored out as _classify() for direct unit testing without mocking
the entire SDK transport.

Per docs/specs/2026-05-25-v0.2-recon-plumbing-design.md § Component
responsibilities: no retry on refusal, best-effort token-budget
enforcement (may overshoot by one round).

SDK shape notes (verified against installed claude-agent-sdk):
- `ClaudeAgentOptions.mcp_servers` is a dict of name->config, where the
  config for in-process Python tools is an `McpSdkServerConfig` built
  via `create_sdk_mcp_server(name, tools=[...])`. We accept the raw
  list returned by `tool_registry.build_recon_tools(...)` and wrap it.
- `query()` yields `UserMessage | AssistantMessage | SystemMessage |
  ResultMessage | StreamEvent | RateLimitEvent`. `ResultMessage` carries
  the terminal fields we care about: `stop_reason`, `usage`, `is_error`,
  `subtype`, `errors`, `result`. `subtype` distinguishes the SDK's
  spurious-error case (`is_error=True`, `subtype="success"`) from real
  errors (`error_max_turns`, `error_during_execution`) — see
  `_api_error_from_result`. `AssistantMessage` carries per-turn `usage`
  and `stop_reason` which we also harvest as a fallback / running tally.
"""

from __future__ import annotations

import time
from typing import Any

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ResultMessage,
    create_sdk_mcp_server,
    query,
)

from flosswing.agent.providers.base import (  # re-exported for callers/tests
    OutcomeLiteral,
    Provider,
    SessionResult,
    _classify,
)

__all__ = ["OutcomeLiteral", "Provider", "SessionResult", "_classify", "run_session"]


def _api_error_from_result(
    *,
    is_error: bool,
    subtype: str,
    errors: list[str] | None,
) -> str | None:
    """Translate ResultMessage error fields into our ``api_error`` string.

    Returns ``None`` when no error should be propagated.

    Carve-out for the SDK's "spurious is_error" pattern (issue #22):
    ``is_error=True`` co-existing with ``subtype="success"`` is how
    ``claude_agent_sdk`` signals "the agent's session ran to
    completion, but the underlying HTTP call had a transient blip
    (rate limit, 5xx, etc.)". The ``ResultMessage.api_error_status``
    field carries the HTTP code in that case. The agent's output is
    intact and tool calls already landed in the DB; classifying the
    session as ``errored`` here would mis-bucket a clean run. Return
    ``None`` instead so the orchestrator finalizes as ``completed``.

    Non-success subtypes (``error_max_turns``, ``error_during_execution``,
    or anything else) DO propagate as real errors — the ``errors``
    list is preferred when populated, falling back to a structured
    ``result_is_error:<subtype>`` sentinel.
    """
    if not is_error:
        return None
    if subtype == "success":
        return None
    errs = errors or []
    return "; ".join(str(e) for e in errs) or f"result_is_error:{subtype}"


_SPURIOUS_SDK_EXIT_ERROR_TEXT = (
    "Claude Code returned an error result: success"
)


def _is_spurious_sdk_exit_error(exc: BaseException) -> bool:
    """Detect the SDK exception that follows a ``is_error=True`` /
    ``subtype="success"`` ResultMessage.

    The CLI exits non-zero after emitting that ResultMessage (for
    shell-script consumers); the SDK wraps the resulting
    ``ProcessError`` as exactly ``"Claude Code returned an error
    result: success"`` (see ``_internal/query.py`` in
    claude_agent_sdk). The agent already finalized cleanly via the
    ResultMessage we processed; the follow-on exception here is
    noise.

    We anchor on the full canonical string including the ``Claude
    Code`` prefix so attacker-controlled content (e.g., a finding
    description, refusal text) that happens to contain the loose
    substring ``returned an error result: success`` doesn't trigger
    a false positive and suppress a real exception. Per CLAUDE.md
    "the target repo is untrusted input". Issue #22.
    """
    return _SPURIOUS_SDK_EXIT_ERROR_TEXT in str(exc)


def _harvest_usage(raw: dict[str, Any] | None) -> dict[str, int]:
    """Coerce SDK usage payload to the int-valued dict _classify expects.

    The SDK reports `cache_read_input_tokens` / `cache_creation_input_tokens`
    in the underlying Anthropic API shape; we normalize to the shorter
    field names the rest of FlossWing uses (matches the schema columns
    `cache_read_tokens` / `cache_write_tokens`).
    """
    if not raw:
        return {}
    out: dict[str, int] = {}
    for k, v in raw.items():
        if isinstance(v, int):
            out[k] = v
        elif isinstance(v, float):
            out[k] = int(v)
    # Normalize Anthropic-API names to our schema names.
    if "cache_read_input_tokens" in out and "cache_read_tokens" not in out:
        out["cache_read_tokens"] = out["cache_read_input_tokens"]
    if "cache_creation_input_tokens" in out and "cache_write_tokens" not in out:
        out["cache_write_tokens"] = out["cache_creation_input_tokens"]
    return out


async def run_session(
    *,
    model: str,
    system_prompt: str,
    tools: list[Any],
    user_prompt: str,
    token_budget: int,
    auth_env: dict[str, str],
    run_id: str,
    stage: str,
    task_id: str | None = None,
    finding_id: str | None = None,
    agent_session_id: str | None = None,
) -> SessionResult:
    """Drive one claude-agent-sdk session and return a structured result.

    `tools` is the list returned by `tool_registry.build_recon_tools(...)`.
    We wrap it into an in-process SDK MCP server and pass it to
    ClaudeAgentOptions.mcp_servers under a single namespace.

    `run_id`, `stage`, `task_id`, `finding_id`, `agent_session_id` are
    accepted for parity with the stage-side caller (so callers can pass
    them unconditionally) but are not yet plumbed into the SDK options —
    they'll be used by later milestones for per-session telemetry tagging.
    The Validate stage pre-allocates `agent_session_id` so the
    validate_finding tool wrapper can close over it and write it to the
    validations row in the same transaction as the verdict.
    """
    del run_id, stage, task_id, finding_id, agent_session_id

    server_config = create_sdk_mcp_server(name="flosswing", tools=tools) if tools else None
    mcp_servers: dict[str, Any] = {"flosswing": server_config} if server_config else {}

    # Pre-authorize the MCP tools we registered. Without this, the SDK
    # treats every tool call as needing interactive permission and denies
    # them in a non-interactive context — surfacing as "Claude requested
    # permissions to use mcp__flosswing__X, but you haven't granted it yet"
    # in the tool_result stream. We also pass `tools=[]` to strip Claude
    # Code's built-in tools (Read, Bash, Write, etc.) so the agent can
    # only use what we explicitly registered, matching the
    # docs/tool-contracts.md scope-matrix discipline.
    allowed_tools: list[str] = [
        f"mcp__flosswing__{getattr(t, 'name', '')}"
        for t in tools
        if getattr(t, "name", "")
    ]

    options = ClaudeAgentOptions(
        model=model,
        system_prompt=system_prompt,
        env=auth_env,
        mcp_servers=mcp_servers,
        tools=[],
        allowed_tools=allowed_tools,
    )

    started = time.monotonic()
    usage: dict[str, int] = {}
    stop_reason: str | None = None
    refusal_text: str | None = None
    tool_calls = 0
    api_error: str | None = None

    try:
        async for message in query(prompt=user_prompt, options=options):
            if isinstance(message, AssistantMessage):
                # Count tool_use blocks within the assistant turn.
                for block in message.content:
                    if type(block).__name__ in {"ToolUseBlock", "ServerToolUseBlock"}:
                        tool_calls += 1
                # Track rolling usage / stop_reason as a fallback if
                # ResultMessage is never emitted.
                u = _harvest_usage(message.usage)
                if u:
                    usage = u
                if message.stop_reason:
                    stop_reason = message.stop_reason
                # AssistantMessage.error is a Literal of error categories.
                if message.error:
                    api_error = api_error or f"assistant_error: {message.error}"
            elif isinstance(message, ResultMessage):
                if message.stop_reason:
                    stop_reason = message.stop_reason
                u = _harvest_usage(message.usage)
                if u:
                    usage = u
                result_err = _api_error_from_result(
                    is_error=message.is_error,
                    subtype=message.subtype,
                    errors=message.errors,
                )
                if result_err is not None:
                    api_error = api_error or result_err
                # When is_error=True with subtype="success" (the spurious
                # SDK case), _api_error_from_result returns None — we
                # deliberately do NOT promote that to api_error. The CLI
                # will exit non-zero next, raising an exception we catch
                # below via _is_spurious_sdk_exit_error. Issue #22.
                # The SDK surfaces refusal text in `result` when stop_reason
                # indicates a refusal; capture it for the classifier.
                if message.stop_reason == "refusal" and message.result:
                    refusal_text = message.result
            # Best-effort budget check: abort the iterator if we've
            # already overshot.
            if usage.get("input_tokens", 0) > token_budget:
                break
    except Exception as e:
        # Only suppress when the exception text matches the SDK's
        # canonical "Claude Code returned an error result: success"
        # wrap (issue #22). A flag-based suppression (set during the
        # ResultMessage branch) was rejected: it would also swallow
        # unrelated exceptions raised after the spurious ResultMessage
        # (e.g., asyncio.CancelledError, connection drops). Requiring
        # the canonical text keeps the carve-out tightly scoped.
        if _is_spurious_sdk_exit_error(e):
            pass
        else:
            api_error = f"{type(e).__name__}: {e}"

    classified = _classify(
        stop_reason=stop_reason,
        usage=usage,
        refusal_text=refusal_text,
        budget=token_budget,
        api_error=api_error,
    )
    return SessionResult(
        outcome=classified.outcome,
        input_tokens=classified.input_tokens,
        output_tokens=classified.output_tokens,
        cache_read_tokens=classified.cache_read_tokens,
        cache_write_tokens=classified.cache_write_tokens,
        duration_ms=int((time.monotonic() - started) * 1000),
        tool_calls_count=tool_calls,
        refusal_text=classified.refusal_text,
        error_text=classified.error_text,
    )
