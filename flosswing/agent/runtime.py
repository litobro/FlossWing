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
  `errors`, `result`. `AssistantMessage` carries per-turn `usage` and
  `stop_reason` which we also harvest as a fallback / running tally.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Literal

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ResultMessage,
    create_sdk_mcp_server,
    query,
)

from flosswing.errors import scrub

OutcomeLiteral = Literal[
    "completed", "refused", "budget_exceeded", "timed_out", "errored"
]


@dataclass
class SessionResult:
    outcome: OutcomeLiteral
    input_tokens: int
    output_tokens: int
    cache_read_tokens: int
    cache_write_tokens: int
    duration_ms: int
    tool_calls_count: int
    refusal_text: str | None
    error_text: str | None


def _classify(
    *,
    stop_reason: str | None,
    usage: dict[str, int],
    refusal_text: str | None,
    budget: int,
    api_error: str | None,
) -> SessionResult:
    """Map terminal session state to a SessionResult.

    Pure function — no SDK imports needed at call sites. Precedence
    matches the spec: api_error > refusal > budget > completed.
    """
    input_tokens = int(usage.get("input_tokens", 0))
    output_tokens = int(usage.get("output_tokens", 0))
    cache_read = int(usage.get("cache_read_tokens", 0))
    cache_write = int(usage.get("cache_write_tokens", 0))

    if api_error:
        return SessionResult(
            outcome="errored",
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cache_read_tokens=cache_read,
            cache_write_tokens=cache_write,
            duration_ms=0,
            tool_calls_count=0,
            refusal_text=None,
            error_text=scrub(api_error),
        )
    if stop_reason == "refusal" or refusal_text:
        return SessionResult(
            outcome="refused",
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cache_read_tokens=cache_read,
            cache_write_tokens=cache_write,
            duration_ms=0,
            tool_calls_count=0,
            refusal_text=scrub(refusal_text or ""),
            error_text=None,
        )
    if input_tokens > budget:
        return SessionResult(
            outcome="budget_exceeded",
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cache_read_tokens=cache_read,
            cache_write_tokens=cache_write,
            duration_ms=0,
            tool_calls_count=0,
            refusal_text=None,
            error_text=None,
        )
    return SessionResult(
        outcome="completed",
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cache_read_tokens=cache_read,
        cache_write_tokens=cache_write,
        duration_ms=0,
        tool_calls_count=0,
        refusal_text=None,
        error_text=None,
    )


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
) -> SessionResult:
    """Drive one claude-agent-sdk session and return a structured result.

    `tools` is the list returned by `tool_registry.build_recon_tools(...)`.
    We wrap it into an in-process SDK MCP server and pass it to
    ClaudeAgentOptions.mcp_servers under a single namespace.

    `run_id`, `stage`, `task_id`, `finding_id` are accepted for parity
    with the stage-side caller (so callers can pass them unconditionally)
    but are not yet plumbed into the SDK options — they'll be used by
    later milestones for per-session telemetry tagging.
    """
    del run_id, stage, task_id, finding_id  # reserved for future telemetry

    server_config = create_sdk_mcp_server(name="flosswing", tools=tools) if tools else None
    mcp_servers: dict[str, Any] = {"flosswing": server_config} if server_config else {}

    options = ClaudeAgentOptions(
        model=model,
        system_prompt=system_prompt,
        env=auth_env,
        mcp_servers=mcp_servers,
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
                if message.is_error:
                    errs = message.errors or []
                    api_error = api_error or "; ".join(str(e) for e in errs) or "result_is_error"
                # The SDK surfaces refusal text in `result` when stop_reason
                # indicates a refusal; capture it for the classifier.
                if message.stop_reason == "refusal" and message.result:
                    refusal_text = message.result
            # Best-effort budget check: abort the iterator if we've
            # already overshot.
            if usage.get("input_tokens", 0) > token_budget:
                break
    except Exception as e:
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
