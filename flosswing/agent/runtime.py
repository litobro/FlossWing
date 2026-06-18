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

from typing import Any

from flosswing.agent.providers.anthropic_sdk import AnthropicSDKProvider
from flosswing.agent.providers.base import (  # re-exported for callers/tests
    OutcomeLiteral,
    Provider,
    SessionResult,
    _classify,
)

__all__ = ["OutcomeLiteral", "Provider", "SessionResult", "_classify", "run_session"]

_ANTHROPIC = AnthropicSDKProvider()


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
    """Drive one agent session via the default Anthropic provider.

    Provider selection (registry-based) is added in a later task; for now
    this delegates straight to the Anthropic SDK backend.
    """
    return await _ANTHROPIC.run_session(
        model=model,
        system_prompt=system_prompt,
        tools=tools,
        user_prompt=user_prompt,
        token_budget=token_budget,
        auth_env=auth_env,
        run_id=run_id,
        stage=stage,
        task_id=task_id,
        finding_id=finding_id,
        agent_session_id=agent_session_id,
    )
