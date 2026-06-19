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

"""Ollama backend: a native in-process agentic tool-use loop.

Unlike the Anthropic provider (which delegates the whole agent loop to the
claude_agent_sdk subprocess), this provider drives the loop itself against
a locally-running Ollama server. It converts each SdkMcpTool to Ollama's
tool spec, calls the chat endpoint, dispatches the model's tool_calls to
the tool handlers, and feeds results back until the model answers without
calling tools (or a guard trips). See
docs/specs/2026-06-18-ollama-provider-design.md.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from typing import Any, cast

from ollama import AsyncClient, ChatResponse, Client

from flosswing.agent.providers.base import SessionResult, _classify
from flosswing.errors import OllamaBackendUnavailableError, scrub

# Safety guards for the native loop (the SDK normally provides these).
# Generous because local inference is slow; both are tunable here.
_MAX_TOOL_ITERATIONS: int = 50
_WALL_CLOCK_DEADLINE_S: float = 1800.0  # 30 minutes per session

_DEFAULT_HOST_LABEL: str = "default host (http://localhost:11434)"


def _to_ollama_tool(tool: Any) -> dict[str, Any]:
    """Convert one SdkMcpTool to Ollama's function-tool spec.

    The real FlossWing tools pass ``Model.model_json_schema()`` as
    ``input_schema`` (already a JSON-Schema dict), used verbatim as
    ``function.parameters``. A non-dict schema (e.g. a TypedDict type)
    falls back to an empty object schema.
    """
    schema = tool.input_schema if isinstance(tool.input_schema, dict) else {}
    return {
        "type": "function",
        "function": {
            "name": tool.name,
            "description": tool.description,
            "parameters": schema,
        },
    }


def _flatten_content(raw: dict[str, Any]) -> str:
    """Flatten a tool handler's ``{"content": [...]}`` payload to text.

    Mirrors the SdkMcpTool return shape: a list of content blocks, each a
    dict with ``type``/``text``. An ``is_error`` flag is surfaced inline so
    the model can react. Returned text is fed back to the model as a
    ``tool``-role message (model-facing data, not stderr/DB output).
    """
    parts: list[str] = []
    for block in raw.get("content", []):
        if isinstance(block, dict) and block.get("type") == "text":
            parts.append(str(block.get("text", "")))
    text = "\n".join(parts)
    if raw.get("is_error"):
        text = f"[tool_error] {text}"
    return text


def _model_is_available(requested: str, available: set[str]) -> bool:
    """True if ``requested`` matches a pulled model name.

    Ollama lists models with explicit tags (e.g. ``gemma4:latest``). A
    tag-less request matches the implicit ``:latest`` (i.e. the base name).
    """
    if requested in available:
        return True
    if ":" not in requested:
        return any(name.split(":", 1)[0] == requested for name in available)
    return False


class OllamaProvider:
    name = "ollama"
    auth_env_keys = frozenset({"OLLAMA_HOST"})

    def validate_auth(
        self, env: Mapping[str, str], *, model: str | None = None
    ) -> None:
        """Preflight: confirm the server is reachable and the model is pulled.

        Repurposes the credential preflight as a backend-reachability check
        (Ollama has no credentials). Raises OllamaBackendUnavailableError
        with an actionable, credential-free (scrubbed) message on failure.
        """
        host = env.get("OLLAMA_HOST") or None
        host_label = host or _DEFAULT_HOST_LABEL
        client = Client(host=host)
        try:
            listed = client.list()
        except Exception as e:  # noqa: BLE001 - any client/transport error == unreachable
            raise OllamaBackendUnavailableError(
                scrub(
                    f"ollama not reachable at {host_label}: {type(e).__name__}: {e}"
                )
            ) from e
        if model is None:
            return
        available = {m.model for m in listed.models if m.model}
        if not _model_is_available(model, available):
            raise OllamaBackendUnavailableError(
                scrub(f"model {model!r} not pulled; run: ollama pull {model}")
            )
