"""OllamaProvider: preflight, helpers, and the native tool-use loop.

The ollama client is mocked at the package boundary (the module-level
`Client` / `AsyncClient` names), never at HTTP.
"""

from __future__ import annotations

import asyncio
from typing import Any, ClassVar

import pytest

from flosswing.agent.providers import ollama_native as on
from flosswing.errors import OllamaBackendUnavailableError

# --- fakes -------------------------------------------------------------------

class _FakeModel:
    def __init__(self, name: str) -> None:
        self.model = name


class _FakeListResponse:
    def __init__(self, names: list[str]) -> None:
        self.models = [_FakeModel(n) for n in names]


class _FakeSyncClient:
    """Stands in for ollama.Client in validate_auth tests."""

    def __init__(
        self,
        names: list[str] | None,
        exc: Exception | None = None,
        *,
        host: Any = None,
        timeout: Any = None,
    ) -> None:
        self._names = names or []
        self._exc = exc
        self.host = host
        self.timeout = timeout

    def list(self) -> _FakeListResponse:
        if self._exc is not None:
            raise self._exc
        return _FakeListResponse(self._names)


def _sync_client_factory(names: list[str] | None = None, exc: Exception | None = None):  # type: ignore[no-untyped-def]  # returns an untyped client-factory closure for tests
    # Accept **kwargs so the factory tolerates the timeout= the preflight passes.
    def factory(host: Any = None, **kwargs: Any) -> _FakeSyncClient:
        return _FakeSyncClient(names, exc, host=host, timeout=kwargs.get("timeout"))
    return factory


# --- helpers -----------------------------------------------------------------

def test_to_ollama_tool_shape() -> None:
    class _T:
        name = "grep"
        description = "search the repo"
        input_schema: ClassVar[dict[str, Any]] = {
            "type": "object",
            "properties": {"pattern": {"type": "string"}},
        }

    spec = on._to_ollama_tool(_T())
    assert spec == {
        "type": "function",
        "function": {
            "name": "grep",
            "description": "search the repo",
            "parameters": {"type": "object", "properties": {"pattern": {"type": "string"}}},
        },
    }


def test_to_ollama_tool_non_dict_schema_falls_back_to_empty() -> None:
    class _T:
        name = "x"
        description = "y"
        input_schema = dict  # a type, not a dict instance

    spec = on._to_ollama_tool(_T())
    assert spec["function"]["parameters"] == {}


def test_flatten_content_joins_text_blocks() -> None:
    raw = {"content": [{"type": "text", "text": "a"}, {"type": "text", "text": "b"}]}
    assert on._flatten_content(raw) == "a\nb"


def test_flatten_content_marks_errors() -> None:
    raw = {"content": [{"type": "text", "text": "boom"}], "is_error": True}
    assert on._flatten_content(raw) == "[tool_error] boom"


def test_model_is_available_matches_latest_tag() -> None:
    assert on._model_is_available("gemma4", {"gemma4:latest"}) is True
    assert on._model_is_available("gemma4:7b", {"gemma4:7b"}) is True
    assert on._model_is_available("zzz", {"gemma4:latest"}) is False


# --- validate_auth -----------------------------------------------------------

def test_validate_auth_ok_when_reachable_and_model_present(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(on, "Client", _sync_client_factory(names=["gemma4:latest"]))
    prov = on.OllamaProvider()
    prov.validate_auth({}, model="gemma4")  # no raise


def test_validate_auth_ok_when_model_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(on, "Client", _sync_client_factory(names=[]))
    prov = on.OllamaProvider()
    prov.validate_auth({})  # reachable, model check skipped -> no raise


def test_validate_auth_raises_when_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(on, "Client", _sync_client_factory(exc=ConnectionError("refused")))
    prov = on.OllamaProvider()
    with pytest.raises(OllamaBackendUnavailableError) as ei:
        prov.validate_auth({"OLLAMA_HOST": "http://localhost:11434"}, model="gemma4")
    assert "not reachable" in ei.value.message


def test_validate_auth_raises_when_model_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(on, "Client", _sync_client_factory(names=["other:latest"]))
    prov = on.OllamaProvider()
    with pytest.raises(OllamaBackendUnavailableError) as ei:
        prov.validate_auth({}, model="gemma4")
    assert "ollama pull gemma4" in ei.value.message


def test_validate_auth_passes_a_timeout_to_the_client(monkeypatch: pytest.MonkeyPatch) -> None:
    # The preflight probe must be bounded; otherwise a hung host stalls the CLI.
    captured: dict[str, Any] = {}

    def factory(host: Any = None, **kwargs: Any) -> _FakeSyncClient:
        captured["timeout"] = kwargs.get("timeout")
        return _FakeSyncClient(["gpt-oss:20b"], host=host)

    monkeypatch.setattr(on, "Client", factory)
    on.OllamaProvider().validate_auth({}, model="gpt-oss:20b")
    assert captured["timeout"] == on._PREFLIGHT_TIMEOUT_S
    assert captured["timeout"] is not None


def test_name_and_auth_env_keys() -> None:
    prov = on.OllamaProvider()
    assert prov.name == "ollama"
    assert prov.auth_env_keys == frozenset({"OLLAMA_HOST"})
    assert prov.default_model == "gpt-oss:20b"


# --- run_session fakes -------------------------------------------------------

class _FakeFunction:
    def __init__(self, name: str, arguments: dict[str, Any]) -> None:
        self.name = name
        self.arguments = arguments


class _FakeToolCall:
    def __init__(self, name: str, arguments: dict[str, Any]) -> None:
        self.function = _FakeFunction(name, arguments)


class _FakeMessage:
    def __init__(self, content: str = "", tool_calls: list[_FakeToolCall] | None = None) -> None:
        self.role = "assistant"
        self.content = content
        self.tool_calls = tool_calls


class _FakeChatResponse:
    def __init__(
        self,
        message: _FakeMessage,
        prompt_eval_count: int = 0,
        eval_count: int = 0,
    ) -> None:
        self.message = message
        self.prompt_eval_count = prompt_eval_count
        self.eval_count = eval_count


class _ScriptedAsyncClient:
    """Returns queued responses in order; records each chat() call."""

    def __init__(self, responses: list[_FakeChatResponse], *, host: Any = None) -> None:
        self._responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    async def chat(
        self, *, model: str, messages: Any, tools: Any = None, **kw: Any
    ) -> _FakeChatResponse:
        self.calls.append({"model": model, "messages": list(messages), "tools": tools})
        return self._responses.pop(0)


class _LoopingAsyncClient:
    """Always returns a tool-call response (drives the iteration cap)."""

    def __init__(self, *, host: Any = None) -> None:
        self.count = 0

    async def chat(
        self, *, model: str, messages: Any, tools: Any = None, **kw: Any
    ) -> _FakeChatResponse:
        self.count += 1
        return _FakeChatResponse(
            _FakeMessage(tool_calls=[_FakeToolCall("grep", {"pattern": "x"})]),
            prompt_eval_count=1,
            eval_count=1,
        )


class _RaisingAsyncClient:
    def __init__(self, exc: Exception, *, host: Any = None) -> None:
        self._exc = exc

    async def chat(
        self, *, model: str, messages: Any, tools: Any = None, **kw: Any
    ) -> _FakeChatResponse:
        raise self._exc


def _async_factory(client: Any):  # type: ignore[no-untyped-def]  # returns an untyped client-factory closure for tests
    def factory(host: Any = None) -> Any:
        return client
    return factory


class _FakeTool:
    # result is typed Any so tests can also model a contract-violating return
    # (e.g. None) and exercise the malformed-result path.
    def __init__(self, name: str, result: Any) -> None:
        self.name = name
        self.description = f"{name} tool"
        self.input_schema = {"type": "object"}
        self._result = result

    async def handler(self, args: dict[str, Any]) -> Any:
        return self._result


def _run(prov: on.OllamaProvider, **kw: Any) -> on.SessionResult:
    base = dict(
        model="gemma4", system_prompt="sys", tools=[], user_prompt="go",
        token_budget=200_000, auth_env={}, run_id="r", stage="hunt",
    )
    base.update(kw)
    return asyncio.run(prov.run_session(**base))  # type: ignore[arg-type]  # **base is a heterogeneous dict; kwargs types are exercised at runtime


# --- run_session tests -------------------------------------------------------

def test_run_session_completes_with_no_tool_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _ScriptedAsyncClient([
        _FakeChatResponse(_FakeMessage(content="done"), prompt_eval_count=10, eval_count=3),
    ])
    monkeypatch.setattr(on, "AsyncClient", _async_factory(client))
    res = _run(on.OllamaProvider())
    assert res.outcome == "completed"
    assert res.input_tokens == 10
    assert res.output_tokens == 3
    assert res.tool_calls_count == 0
    assert res.refusal_text is None
    assert res.cache_read_tokens == 0
    assert res.cache_write_tokens == 0


def test_run_session_dispatches_tool_then_completes(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _ScriptedAsyncClient([
        _FakeChatResponse(
            _FakeMessage(tool_calls=[_FakeToolCall("grep", {"pattern": "x"})]),
            prompt_eval_count=5, eval_count=2,
        ),
        _FakeChatResponse(_FakeMessage(content="final"), prompt_eval_count=4, eval_count=1),
    ])
    monkeypatch.setattr(on, "AsyncClient", _async_factory(client))
    tool = _FakeTool("grep", {"content": [{"type": "text", "text": "match"}]})
    res = _run(on.OllamaProvider(), tools=[tool])
    assert res.outcome == "completed"
    assert res.tool_calls_count == 1
    assert res.input_tokens == 9  # 5 + 4 accumulated
    # The second chat call must include the tool result as a tool-role message.
    second_call_messages = client.calls[1]["messages"]
    assert any(
        m.get("role") == "tool" and "match" in m.get("content", "")
        for m in second_call_messages
    )


def test_run_session_propagates_tool_is_error(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _ScriptedAsyncClient([
        _FakeChatResponse(_FakeMessage(tool_calls=[_FakeToolCall("grep", {})])),
        _FakeChatResponse(_FakeMessage(content="ok")),
    ])
    monkeypatch.setattr(on, "AsyncClient", _async_factory(client))
    tool = _FakeTool("grep", {"content": [{"type": "text", "text": "bad"}], "is_error": True})
    res = _run(on.OllamaProvider(), tools=[tool])
    assert res.outcome == "completed"
    tool_msgs = [m for m in client.calls[1]["messages"] if m.get("role") == "tool"]
    assert tool_msgs and "[tool_error] bad" in tool_msgs[0]["content"]


def test_run_session_recovers_from_unknown_tool(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _ScriptedAsyncClient([
        _FakeChatResponse(_FakeMessage(tool_calls=[_FakeToolCall("nope", {})])),
        _FakeChatResponse(_FakeMessage(content="ok")),
    ])
    monkeypatch.setattr(on, "AsyncClient", _async_factory(client))
    res = _run(on.OllamaProvider(), tools=[])
    assert res.outcome == "completed"
    tool_msgs = [m for m in client.calls[1]["messages"] if m.get("role") == "tool"]
    assert tool_msgs and "unknown tool" in tool_msgs[0]["content"]


def test_run_session_budget_exceeded(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _ScriptedAsyncClient([
        _FakeChatResponse(
            _FakeMessage(tool_calls=[_FakeToolCall("grep", {})]),
            prompt_eval_count=999, eval_count=1,
        ),
    ])
    monkeypatch.setattr(on, "AsyncClient", _async_factory(client))
    res = _run(on.OllamaProvider(), token_budget=100)
    assert res.outcome == "budget_exceeded"
    # The over-budget response requested one tool; it is counted even though
    # the budget cut-off skips dispatching it.
    assert res.tool_calls_count == 1


def test_run_session_times_out(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(on, "_WALL_CLOCK_DEADLINE_S", -1.0)
    client = _ScriptedAsyncClient([_FakeChatResponse(_FakeMessage(content="never"))])
    monkeypatch.setattr(on, "AsyncClient", _async_factory(client))
    res = _run(on.OllamaProvider())
    assert res.outcome == "timed_out"
    assert res.tool_calls_count == 0


def test_run_session_times_out_on_slow_chat(monkeypatch: pytest.MonkeyPatch) -> None:
    # A single chat() that runs longer than the remaining wall-clock budget is
    # cut off by asyncio.wait_for -> timed_out (the deadline must bound an
    # in-flight request, not just gate the start of the next iteration).
    monkeypatch.setattr(on, "_WALL_CLOCK_DEADLINE_S", 0.05)

    class _SlowAsyncClient:
        def __init__(self, *, host: Any = None) -> None:
            self.host = host

        async def chat(self, **_kw: Any) -> _FakeChatResponse:
            await asyncio.sleep(10)  # far longer than the 0.05s deadline
            return _FakeChatResponse(_FakeMessage(content="too late"))

    monkeypatch.setattr(on, "AsyncClient", _async_factory(_SlowAsyncClient()))
    res = _run(on.OllamaProvider())
    assert res.outcome == "timed_out"


def test_run_session_handles_malformed_tool_result(monkeypatch: pytest.MonkeyPatch) -> None:
    # A handler that returns a non-dict (contract violation) must degrade to a
    # single tool-error message fed back to the model, not crash the session.
    client = _ScriptedAsyncClient([
        _FakeChatResponse(_FakeMessage(tool_calls=[_FakeToolCall("grep", {})])),
        _FakeChatResponse(_FakeMessage(content="ok")),
    ])
    monkeypatch.setattr(on, "AsyncClient", _async_factory(client))
    tool = _FakeTool("grep", None)  # handler returns None -> _flatten_content fails
    res = _run(on.OllamaProvider(), tools=[tool])
    assert res.outcome == "completed"
    tool_msgs = [m for m in client.calls[1]["messages"] if m.get("role") == "tool"]
    assert tool_msgs and "raised" in tool_msgs[0]["content"]


def test_run_session_iteration_cap_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(on, "_MAX_TOOL_ITERATIONS", 2)
    client = _LoopingAsyncClient()
    monkeypatch.setattr(on, "AsyncClient", _async_factory(client))
    tool = _FakeTool("grep", {"content": [{"type": "text", "text": "again"}]})
    res = _run(on.OllamaProvider(), tools=[tool])
    assert res.outcome == "errored"
    assert "max_tool_iterations_exceeded" in (res.error_text or "")
    assert client.count == 2


def test_run_session_client_error_is_errored_and_scrubbed(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _RaisingAsyncClient(RuntimeError("boom Authorization: Bearer eyJabc.def.ghi"))
    monkeypatch.setattr(on, "AsyncClient", _async_factory(client))
    res = _run(on.OllamaProvider())
    assert res.outcome == "errored"
    assert "eyJabc.def.ghi" not in (res.error_text or "")
    assert "[REDACTED]" in (res.error_text or "")


def test_run_session_never_synthesizes_refusal(monkeypatch: pytest.MonkeyPatch) -> None:
    # Refusal-sounding prose with no tool calls must classify as completed.
    client = _ScriptedAsyncClient([
        _FakeChatResponse(_FakeMessage(content="I can't help with that."), prompt_eval_count=1),
    ])
    monkeypatch.setattr(on, "AsyncClient", _async_factory(client))
    res = _run(on.OllamaProvider())
    assert res.outcome == "completed"
    assert res.refusal_text is None
