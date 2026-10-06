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

"""OpenAI Codex / Daybreak Blue backend.

Auth is the local ``codex login`` session (no env credential); ``run_session`` is
filled in by later tasks.
"""

from __future__ import annotations

import dataclasses
import shutil
import subprocess
from collections.abc import Mapping
from typing import Any

from flosswing.agent.providers.base import OnUsage, SessionResult, _classify
from flosswing.errors import AuthCredentialMissingError

_MISSING_AUTH_MSG = (
    "No Codex login found. Install the Codex CLI and run `codex login` with a\n"
    "Daybreak-Blue-approved account (credentials live in ~/.codex, not the env)."
)


def _codex_installed() -> bool:
    return shutil.which("codex") is not None


def _codex_logged_in() -> bool:
    # EXACT subcommand confirmed in Task 0 Step 1; default guess `codex login status`.
    try:
        r = subprocess.run(
            ["codex", "login", "status"],
            check=False,
            capture_output=True,
            timeout=10,
        )
    except (subprocess.TimeoutExpired, OSError):
        return False
    return r.returncode == 0


# --- Event-stream parsing (codex app-server protocol; see tests/fixtures/codex/NOTES.md)
#
# BEST-EFFORT REFUSAL HEURISTIC: Daybreak/Codex gives NO refusal signal. A
# refusal is an ordinary final ``agentMessage`` with ``turn/completed``
# status "completed" and no tool call. We therefore detect it from the message
# TEXT only, which can both miss refusals and misfire on benign prose.
_DECLINE_PHRASES: tuple[str, ...] = (
    "i can't",
    "i cannot",
    "i'm unable",
    "i am unable",
    "i won't",
    "can't help with",
    "unable to assist",
)


def _looks_like_decline(text: str) -> bool:
    # Normalise typographic apostrophes (the captured refusal uses U+2019).
    norm = text.replace("\u2019", "'").replace("\u2018", "'").lower()
    return any(p in norm for p in _DECLINE_PHRASES)


def _harvest_usage(token_usage: dict[str, Any]) -> dict[str, int]:
    """Map a ``thread/tokenUsage/updated`` ``tokenUsage`` payload (cumulative
    ``total``) to FlossWing's usage names. Missing keys default to 0."""
    total = token_usage.get("total") or {}
    return {
        "input_tokens": int(total.get("inputTokens") or 0),
        "output_tokens": int(total.get("outputTokens") or 0),
        "cache_read_tokens": int(total.get("cachedInputTokens") or 0),
        "cache_write_tokens": int(total.get("cacheWriteInputTokens") or 0),
    }


def _classify_events(events: list[dict[str, Any]], *, budget: int) -> SessionResult:
    """Reduce received app-server messages to a SessionResult (pure)."""
    usage: dict[str, int] = _harvest_usage({})
    tool_calls = 0
    final_text: str | None = None
    api_error: str | None = None

    for ev in events:
        if ev.get("error") is not None and "method" not in ev:
            err = ev["error"]
            msg = err.get("message") if isinstance(err, dict) else None
            api_error = str(msg or err)
            continue
        method = ev.get("method")
        params = ev.get("params") or {}
        if method == "thread/tokenUsage/updated":
            usage = _harvest_usage(params.get("tokenUsage") or {})
        elif method == "item/completed":
            item = params.get("item") or {}
            if item.get("type") == "mcpToolCall":
                tool_calls += 1
            elif item.get("type") == "agentMessage" and item.get("phase") == "final_answer":
                final_text = str(item.get("text") or "")
        elif method == "turn/completed":
            turn_err = (params.get("turn") or {}).get("error")
            if turn_err is not None:
                msg = turn_err.get("message") if isinstance(turn_err, dict) else None
                api_error = str(msg or turn_err)

    refusal_text: str | None = None
    stop_reason: str | None = None
    if final_text is not None and _looks_like_decline(final_text):
        refusal_text = final_text
        if tool_calls == 0:
            # Terminal refusal: detected BEFORE the error branch so a refusal
            # can never be laundered into ``errored`` (refusal overrides error).
            stop_reason = "refusal"
            api_error = None

    result = _classify(
        stop_reason=stop_reason,
        usage=usage,
        refusal_text=refusal_text,
        budget=budget,
        api_error=api_error,
        cost_usd=None,
    )
    return dataclasses.replace(result, tool_calls_count=tool_calls)


class OpenAICodexProvider:
    name = "openai"
    auth_env_keys: frozenset[str] = frozenset()

    def validate_auth(self, env: Mapping[str, str]) -> None:
        if not (_codex_installed() and _codex_logged_in()):
            raise AuthCredentialMissingError(_MISSING_AUTH_MSG)

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
        on_usage: OnUsage | None = None,
    ) -> SessionResult:
        raise NotImplementedError("filled in by later tasks")
