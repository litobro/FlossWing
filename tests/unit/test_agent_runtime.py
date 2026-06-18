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

"""agent/runtime: run_session resolves provider via registry."""

from __future__ import annotations

import asyncio

from flosswing.agent import runtime as rt
from flosswing.agent.providers import registry as reg
from flosswing.agent.providers.base import SessionResult


def test_run_session_routes_to_named_provider(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    sentinel = SessionResult(
        outcome="completed", input_tokens=0, output_tokens=0,
        cache_read_tokens=0, cache_write_tokens=0, duration_ms=0,
        tool_calls_count=0, refusal_text=None, error_text=None,
    )

    class Fake:
        name = "fake"
        auth_env_keys: frozenset[str] = frozenset()

        def validate_auth(self, env: object) -> None:
            return None

        async def run_session(self, **kw: object) -> SessionResult:
            return sentinel

    monkeypatch.setattr(reg, "get_provider", lambda name: Fake())
    out = asyncio.run(
        rt.run_session(
            model="m", system_prompt="s", tools=[], user_prompt="u",
            token_budget=1, auth_env={}, run_id="r", stage="hunt",
            provider="fake",
        )
    )
    assert out is sentinel
