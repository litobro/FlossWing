"""OllamaProvider: preflight, helpers, and the native tool-use loop.

The ollama client is mocked at the package boundary (the module-level
`Client` / `AsyncClient` names), never at HTTP.
"""

from __future__ import annotations

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
        self, names: list[str] | None, exc: Exception | None = None, *, host: Any = None
    ) -> None:
        self._names = names or []
        self._exc = exc
        self.host = host

    def list(self) -> _FakeListResponse:
        if self._exc is not None:
            raise self._exc
        return _FakeListResponse(self._names)


def _sync_client_factory(names: list[str] | None = None, exc: Exception | None = None):  # type: ignore[no-untyped-def]  # returns an untyped client-factory closure for tests
    def factory(host: Any = None) -> _FakeSyncClient:
        return _FakeSyncClient(names, exc, host=host)
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


def test_name_and_auth_env_keys() -> None:
    prov = on.OllamaProvider()
    assert prov.name == "ollama"
    assert prov.auth_env_keys == frozenset({"OLLAMA_HOST"})
