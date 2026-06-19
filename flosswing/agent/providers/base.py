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

"""Provider contract shared by all model backends.

`SessionResult` is the provider-agnostic return type for one agent
session. `_classify` is the pure mapping from terminal session state to a
`SessionResult` — its outcome taxonomy (completed/refused/budget_exceeded/
timed_out/errored) is FlossWing contract, not Anthropic-specific, so it
lives here and is shared by every provider.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal, Protocol

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

    Pure function. Precedence matches the spec:
    api_error > refusal > budget > completed.
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


class Provider(Protocol):
    """A model backend that can drive one agent session.

    `auth_env_keys` are the env vars this provider reads (alternatives, not
    all-required). `validate_auth` raises `AuthCredentialMissingError` when
    the environment lacks a usable credential path.
    """

    name: str
    auth_env_keys: frozenset[str]

    def validate_auth(
        self, env: Mapping[str, str], *, model: str | None = None
    ) -> None: ...

    async def run_session(
        self,
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
    ) -> SessionResult: ...
