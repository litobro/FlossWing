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

"""Thin provider facade for agent sessions.

Resolves the requested provider (default ``"anthropic"``) from the
registry and delegates to its ``run_session`` implementation. Session
logic, auth validation, and SDK interaction live in the provider module
(e.g. ``flosswing/agent/providers/anthropic_sdk.py``).
"""

from __future__ import annotations

from typing import Any

from flosswing.agent.providers import registry
from flosswing.agent.providers.base import (  # re-exported for callers/tests
    OnUsage,
    OutcomeLiteral,
    Provider,
    SessionResult,
    UsageSnapshot,
    _classify,
)

__all__ = [
    "OnUsage",
    "OutcomeLiteral",
    "Provider",
    "SessionResult",
    "UsageSnapshot",
    "_classify",
    "run_session",
]


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
    on_usage: OnUsage | None = None,
    provider: str = "anthropic",
) -> SessionResult:
    """Drive one agent session via the selected provider (default anthropic)."""
    prov = registry.get_provider(provider)
    return await prov.run_session(
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
        on_usage=on_usage,
    )
