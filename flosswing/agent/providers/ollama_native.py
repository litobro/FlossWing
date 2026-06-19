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

import asyncio
import time
from collections.abc import Mapping
from typing import Any

from ollama import AsyncClient, Client

from flosswing.agent.providers.base import SessionResult as SessionResult
from flosswing.agent.providers.base import _classify
from flosswing.errors import OllamaBackendUnavailableError, scrub

# Safety guards for the native loop (the SDK normally provides these).
# Generous because local inference is slow; both are tunable here.
_MAX_TOOL_ITERATIONS: int = 50
_WALL_CLOCK_DEADLINE_S: float = 1800.0  # 30 minutes per session

# Bound on the preflight reachability probe. The ollama client otherwise has
# no timeout (httpx Timeout=None), so a host that accepts the connection but
# never responds would hang config.resolve() — and the whole CLI — indefinitely.
# Mirrors the Anthropic provider's 5s az-login probe bound.
_PREFLIGHT_TIMEOUT_S: float = 5.0

_DEFAULT_HOST_LABEL: str = "default host (http://localhost:11434)"


def _normalize_schema(schema: Any, defs: dict[str, Any]) -> Any:
    """Flatten a JSON Schema into a form strict Ollama chat templates accept.

    Some model templates (notably gpt-oss) index ``property.type[0]`` while
    rendering the tool list and 500 on any property that lacks a scalar
    ``type`` — exactly what Pydantic emits for optional fields
    (``anyOf: [{type: X}, {type: null}]``) and nested models (``$ref``). This:

    - resolves ``$ref`` against the schema's ``$defs``,
    - collapses an ``anyOf``/``oneOf`` to its first non-null branch (the
      optional/union case), merging sibling keys (``default``/``title``/
      ``description``) onto it,
    - recurses through ``properties`` and array ``items``,

    so every property ends with a concrete ``type``. It is intentionally lossy
    — it keeps the parts a tool-calling model needs (name, type, description,
    enum) and drops only the structural indirection templates choke on.
    """
    if not isinstance(schema, dict):
        return schema

    ref = schema.get("$ref")
    if isinstance(ref, str) and ref.startswith("#/$defs/"):
        target = defs.get(ref.rsplit("/", 1)[-1], {})
        siblings = {k: v for k, v in schema.items() if k != "$ref"}
        return _normalize_schema({**target, **siblings}, defs)

    for combiner in ("anyOf", "oneOf"):
        options = schema.get(combiner)
        if isinstance(options, list):
            non_null = [
                o
                for o in options
                if not (isinstance(o, dict) and o.get("type") == "null")
            ]
            chosen = non_null[0] if non_null else {"type": "string"}
            siblings = {k: v for k, v in schema.items() if k not in (combiner, "$ref")}
            return _normalize_schema({**chosen, **siblings}, defs)

    out: dict[str, Any] = {}
    for key, value in schema.items():
        if key == "$defs":
            continue  # inlined via $ref resolution; drop from the output
        if key == "properties" and isinstance(value, dict):
            out[key] = {k: _normalize_schema(v, defs) for k, v in value.items()}
        elif key == "items":
            out[key] = _normalize_schema(value, defs)
        else:
            out[key] = value
    return out


def _to_ollama_tool(tool: Any) -> dict[str, Any]:
    """Convert one SdkMcpTool to Ollama's function-tool spec.

    The real FlossWing tools pass ``Model.model_json_schema()`` as
    ``input_schema`` (already a JSON-Schema dict). It is normalized (see
    ``_normalize_schema``) so strict model templates can render every property,
    then used as ``function.parameters``. A non-dict schema (e.g. a TypedDict
    type) falls back to an empty object schema.
    """
    raw = tool.input_schema if isinstance(tool.input_schema, dict) else {}
    defs = raw.get("$defs", {}) if isinstance(raw, dict) else {}
    schema = _normalize_schema(raw, defs)
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
    default_model = "gpt-oss:20b"

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
        client = Client(host=host, timeout=_PREFLIGHT_TIMEOUT_S)
        try:
            listed = client.list()
        except Exception as e:  # any client/transport error == unreachable
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
    ) -> SessionResult:
        """Drive one native tool-use loop against Ollama.

        Converts each SdkMcpTool to an Ollama tool spec, calls the chat
        endpoint, dispatches the model's tool_calls to the tool handlers,
        and feeds results back until the model answers without calling a
        tool (completed) or a guard trips (budget/timeout/iteration-cap).
        The run_id/stage/task_id/finding_id/agent_session_id args are
        accepted for stage-side call parity (matching the Anthropic
        provider) and are not yet plumbed into per-session telemetry.
        """
        del run_id, stage, task_id, finding_id, agent_session_id

        host = auth_env.get("OLLAMA_HOST") or None
        client = AsyncClient(host=host)
        tool_specs = [_to_ollama_tool(t) for t in tools]
        handlers = {t.name: t.handler for t in tools}

        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        started = time.monotonic()
        deadline = started + _WALL_CLOCK_DEADLINE_S
        input_tokens = 0
        output_tokens = 0
        tool_calls_count = 0
        api_error: str | None = None
        timed_out = False

        try:
            for _iteration in range(_MAX_TOOL_ITERATIONS):
                now = time.monotonic()
                if now > deadline:
                    timed_out = True
                    break

                # Bound each request by the remaining wall-clock budget. Without
                # this, a single slow/hung generation runs unbounded: the check
                # above only gates *starting* an iteration, and the ollama client
                # has no request timeout of its own (httpx Timeout=None).
                try:
                    response = await asyncio.wait_for(
                        client.chat(
                            model=model,
                            messages=messages,
                            tools=tool_specs or None,
                        ),
                        timeout=deadline - now,
                    )
                except TimeoutError:
                    timed_out = True
                    break

                input_tokens += int(response.prompt_eval_count or 0)
                output_tokens += int(response.eval_count or 0)
                msg = response.message

                assistant_entry: dict[str, Any] = {
                    "role": "assistant",
                    "content": msg.content or "",
                }
                if msg.tool_calls:
                    assistant_entry["tool_calls"] = msg.tool_calls
                messages.append(assistant_entry)

                # Count the tool calls the model requested this turn, even if the
                # budget cut-off below skips dispatching them — the telemetry
                # should reflect what the model asked for.
                tool_calls = msg.tool_calls or []
                tool_calls_count += len(tool_calls)

                # Best-effort budget check: stop before doing more work once
                # we've overshot. _classify then buckets this as
                # budget_exceeded (input_tokens > budget).
                if input_tokens > token_budget:
                    break

                if not tool_calls:
                    break  # final answer -> completed

                for call in tool_calls:
                    name = call.function.name
                    args = dict(call.function.arguments or {})
                    handler = handlers.get(name)
                    if handler is None:
                        messages.append({
                            "role": "tool",
                            "tool_name": name,
                            "content": f"error: unknown tool {name!r}",
                        })
                        continue
                    try:
                        raw = await handler(args)
                        content = _flatten_content(raw)
                    except Exception as e:  # tool errors feed back to the model
                        messages.append({
                            "role": "tool",
                            "tool_name": name,
                            "content": scrub(
                                f"tool {name} raised {type(e).__name__}: {e}"
                            ),
                        })
                        continue
                    messages.append({
                        "role": "tool",
                        "tool_name": name,
                        "content": content,
                    })
            else:
                # Loop exhausted range() without breaking -> stuck calling tools.
                api_error = api_error or "max_tool_iterations_exceeded"
        except Exception as e:  # any transport/model error -> errored
            api_error = f"{type(e).__name__}: {e}"

        duration_ms = int((time.monotonic() - started) * 1000)

        classified = _classify(
            stop_reason=None,
            usage={"input_tokens": input_tokens, "output_tokens": output_tokens},
            refusal_text=None,
            budget=token_budget,
            api_error=api_error,
            timed_out=timed_out,
        )
        return SessionResult(
            outcome=classified.outcome,
            input_tokens=classified.input_tokens,
            output_tokens=classified.output_tokens,
            cache_read_tokens=0,
            cache_write_tokens=0,
            duration_ms=duration_ms,
            tool_calls_count=tool_calls_count,
            refusal_text=None,
            error_text=classified.error_text,
        )
