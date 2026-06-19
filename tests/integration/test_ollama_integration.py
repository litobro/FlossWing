"""Gated real-Ollama integration smoke test.

Runs only when FLOSSWING_OLLAMA_INTEGRATION=1 and a local Ollama server is
serving a tool-calling model (default gemma4, override with
FLOSSWING_OLLAMA_MODEL). Not part of normal CI — mirrors the
FLOSSWING_INTEGRATION discipline. Verifies the native loop completes a
single tool round-trip end-to-end.
"""

from __future__ import annotations

import os
from typing import ClassVar

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("FLOSSWING_OLLAMA_INTEGRATION") != "1",
    reason="set FLOSSWING_OLLAMA_INTEGRATION=1 with a live Ollama server to run",
)


@pytest.mark.asyncio
async def test_ollama_round_trip_completes() -> None:
    from flosswing.agent.providers.ollama_native import OllamaProvider

    calls: list[dict[str, object]] = []

    class _EchoTool:
        name: ClassVar[str] = "echo"
        description: ClassVar[str] = "Echo the given text back."
        input_schema: ClassVar[dict[str, object]] = {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
        }

        async def handler(self, args: dict[str, object]) -> dict[str, object]:
            calls.append(args)
            return {"content": [{"type": "text", "text": f"echoed: {args.get('text')}"}]}

    model = os.environ.get("FLOSSWING_OLLAMA_MODEL", "gemma4")
    prov = OllamaProvider()
    prov.validate_auth(dict(os.environ), model=model)

    result = await prov.run_session(
        model=model,
        system_prompt="You are a tool-using assistant. Use the echo tool when asked.",
        tools=[_EchoTool()],
        user_prompt="Call the echo tool with text='hello'. Then stop.",
        token_budget=200_000,
        auth_env={k: os.environ[k] for k in ("OLLAMA_HOST",) if k in os.environ},
        run_id="integration",
        stage="hunt",
    )

    assert result.outcome in {"completed", "budget_exceeded"}
    assert result.input_tokens > 0
    # A tool-calling model should have invoked echo at least once.
    assert result.tool_calls_count >= 1
