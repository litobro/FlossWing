# Ollama Provider Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the `ollama` provider stub with a working native backend so `flosswing scan <repo> --provider ollama --model <m>` runs the full pipeline against a locally-running Ollama model with no Anthropic credentials.

**Architecture:** A new `OllamaProvider` implements the existing `Provider` Protocol. Instead of delegating to the `claude_agent_sdk` subprocess (the Anthropic path), it drives its own in-process agentic tool-use loop: it converts each `SdkMcpTool` to Ollama's tool format, calls the Ollama HTTP API via the `ollama` package's `AsyncClient`, dispatches the model's `tool_calls` to each tool's `.handler`, feeds results back, and classifies the terminal state through the shared `_classify`.

**Tech Stack:** Python 3.11+, `ollama` package (new dependency), `pytest` + `pytest-asyncio`, `ruff`, `mypy --strict`.

**Reference spec:** `docs/specs/2026-06-18-ollama-provider-design.md`

## Global Constraints

- Python 3.11+, full type hints; `ruff check` and `mypy --strict` must pass (config in `pyproject.toml`). Add `# type: ignore` only with an inline reason comment.
- Provider Protocol is internal (introduced in #32); it is NOT a frozen agent-facing tool contract. `docs/tool-contracts.md` must not change.
- All strings bound for stderr / state DB / report output pass through `errors.scrub()`.
- No credential value is ever logged, persisted, or placed in an error message. (Ollama has no credentials; `OLLAMA_HOST` is config, not a secret.)
- Adding the `ollama` top-level dependency is operator-approved (2026-06-18). No other new dependency.
- `DEFAULT_OLLAMA_MODEL = "gemma4"` (operator-confirmed tool-calling capable, 2026-06-18).
- The Ollama provider never returns the `refused` outcome (no reliable structured refusal signal; heuristic matching rejected).
- All commits end with the trailer: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.
- Run all commands from the worktree root: `/home/tdang/projects/personal/FlossWing/.claude/worktrees/ollama-provider`. The venv is `.venv/` there; use `.venv/bin/python -m pytest …`, `.venv/bin/ruff`, `.venv/bin/mypy`.

---

## File Structure

**New files:**
- `flosswing/agent/providers/ollama_native.py` — the `OllamaProvider` class, its preflight, the native tool-use loop, and the three pure helpers (`_to_ollama_tool`, `_flatten_content`, `_model_is_available`).
- `tests/unit/test_providers_ollama.py` — unit tests for the provider (mock the `ollama` client at the package boundary).
- `tests/integration/test_ollama_integration.py` — gated real-Ollama end-to-end check.

**Modified files:**
- `flosswing/errors.py` — add `OllamaBackendUnavailableError`.
- `flosswing/agent/providers/base.py` — widen `Provider.validate_auth` with a keyword-only `model`.
- `flosswing/agent/providers/anthropic_sdk.py` — accept (and ignore) the new `model` kwarg.
- `flosswing/agent/providers/registry.py` — move `ollama` to implemented; add `implemented_providers()`.
- `flosswing/config.py` — resolve model before preflight; Ollama default model; widen `AUTH_ENV_KEYS` to the union of implemented providers.
- `flosswing/cli.py` — update `--provider` / `--model` help text.
- `tests/unit/test_providers_registry.py`, `tests/unit/test_config.py`, `tests/unit/test_cli.py` — update the assertions that assume `ollama` is unimplemented.

**Proposed diff (approval-gated, NOT applied in this plan):**
- `CLAUDE.md` (dependency-list line), `ARCHITECTURE.md` (ollama no longer a stub).

---

## Task 1: Declare the `ollama` dependency

**Files:**
- Modify: `pyproject.toml` (the `[project]` `dependencies` array)

**Interfaces:**
- Produces: the `ollama` package as a declared runtime dependency (already installed in the worktree venv as `ollama==0.6.2`).

- [ ] **Step 1: Add the dependency**

In `pyproject.toml`, add `"ollama"` to the `dependencies` array, immediately after the `"python-ulid"` line:

```toml
    "python-ulid",
    "ollama",
    "tomli; python_version < '3.11'",
```

(If the line following `"python-ulid"` differs, just insert `"ollama",` as its own line within the `dependencies` array — alphabetical order is not enforced in this file.)

- [ ] **Step 2: Verify it resolves and imports**

Run: `.venv/bin/python -c "import ollama; print('ok', ollama.__name__)"`
Expected: `ok ollama`

Run: `.venv/bin/python -c "import tomllib; tomllib.load(open('pyproject.toml','rb')); print('toml ok')"`
Expected: `toml ok`

- [ ] **Step 3: Commit**

```bash
git add pyproject.toml
git commit -m "Add ollama runtime dependency (operator-approved 2026-06-18)

Per docs/specs/2026-06-18-ollama-provider-design.md § Dependency.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: Add `OllamaBackendUnavailableError`

**Files:**
- Modify: `flosswing/errors.py` (insert after `ProviderNotImplementedError`, around line 129)
- Test: `tests/unit/test_errors.py`

**Interfaces:**
- Produces: `flosswing.errors.OllamaBackendUnavailableError(FlosswingError)` with `code = "ollama_backend_unavailable"`, `retryable = False`. Raised by the Ollama preflight; subclasses `FlosswingError` so `cli.py`'s existing `except FlosswingError` catches it and exits 2.

- [ ] **Step 1: Write the failing test**

Append to `tests/unit/test_errors.py`:

```python
def test_ollama_backend_unavailable_is_flosswing_error() -> None:
    from flosswing.errors import FlosswingError, OllamaBackendUnavailableError

    err = OllamaBackendUnavailableError("ollama not reachable at default host")
    assert isinstance(err, FlosswingError)
    assert err.code == "ollama_backend_unavailable"
    assert err.retryable is False
    assert err.message == "ollama not reachable at default host"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/unit/test_errors.py::test_ollama_backend_unavailable_is_flosswing_error -v`
Expected: FAIL with `ImportError: cannot import name 'OllamaBackendUnavailableError'`

- [ ] **Step 3: Add the error class**

In `flosswing/errors.py`, directly after the `ProviderNotImplementedError` class (after line 129), insert:

```python


class OllamaBackendUnavailableError(FlosswingError):
    """The Ollama backend could not be used at preflight or mid-session.

    Raised by OllamaProvider.validate_auth when the Ollama server is
    unreachable at the configured host, or when the requested model is
    not pulled. Subclasses FlosswingError so the CLI's `except
    FlosswingError` maps it to a clean exit 2. Ollama has no credentials,
    so the message carries only host/model info (still run through
    errors.scrub() defensively at the raise site).
    """

    code = "ollama_backend_unavailable"
    retryable = False
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/unit/test_errors.py -v`
Expected: PASS (all tests in file)

- [ ] **Step 5: Commit**

```bash
git add flosswing/errors.py tests/unit/test_errors.py
git commit -m "Add OllamaBackendUnavailableError per ollama-provider design § Error handling

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Widen `Provider.validate_auth` with a keyword-only `model`

**Files:**
- Modify: `flosswing/agent/providers/base.py:130` (the Protocol method)
- Modify: `flosswing/agent/providers/anthropic_sdk.py:195` (`AnthropicSDKProvider.validate_auth`)
- Modify: `flosswing/agent/providers/registry.py:41` (`UnimplementedProvider.validate_auth`)
- Test: `tests/unit/test_providers_anthropic.py`

**Interfaces:**
- Produces: `Provider.validate_auth(self, env: Mapping[str, str], *, model: str | None = None) -> None`. Backward compatible — existing callers passing only `env` keep working; the Anthropic and stub impls ignore `model`.

- [ ] **Step 1: Write the failing test**

Append to `tests/unit/test_providers_anthropic.py`:

```python
def test_validate_auth_accepts_model_kwarg() -> None:
    # The model kwarg was added for the Ollama preflight; Anthropic ignores it.
    prov = a.AnthropicSDKProvider()
    prov.validate_auth({"ANTHROPIC_API_KEY": "sk-ant"}, model="claude-opus-4-7")
    # No raise == pass; also callable positionally-env, kw-model.
```

(Confirm the module is imported as `a` at the top of that test file; it is — existing tests reference `a._has_az_session`.)

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/unit/test_providers_anthropic.py::test_validate_auth_accepts_model_kwarg -v`
Expected: FAIL with `TypeError: validate_auth() got an unexpected keyword argument 'model'`

- [ ] **Step 3: Update the three signatures**

In `flosswing/agent/providers/base.py`, change the Protocol method (line 130) from:

```python
    def validate_auth(self, env: Mapping[str, str]) -> None: ...
```

to:

```python
    def validate_auth(
        self, env: Mapping[str, str], *, model: str | None = None
    ) -> None: ...
```

In `flosswing/agent/providers/anthropic_sdk.py`, change `AnthropicSDKProvider.validate_auth` (line 195) from:

```python
    def validate_auth(self, env: Mapping[str, str]) -> None:
        """Raise AuthCredentialMissingError unless a usable auth path exists.

        Same logic previously inlined in config.resolve().
        """
```

to:

```python
    def validate_auth(
        self, env: Mapping[str, str], *, model: str | None = None
    ) -> None:
        """Raise AuthCredentialMissingError unless a usable auth path exists.

        Same logic previously inlined in config.resolve(). `model` is
        accepted for Provider-Protocol parity with the Ollama backend
        (which preflights model availability) and is unused here.
        """
        del model
```

In `flosswing/agent/providers/registry.py`, change `UnimplementedProvider.validate_auth` (line 41) from:

```python
    def validate_auth(self, env: Any) -> None:  # no-op by design
        return None
```

to:

```python
    def validate_auth(
        self, env: Any, *, model: str | None = None
    ) -> None:  # no-op by design
        del model
        return None
```

- [ ] **Step 4: Run tests + type check to verify pass**

Run: `.venv/bin/python -m pytest tests/unit/test_providers_anthropic.py tests/unit/test_providers_base.py tests/unit/test_providers_registry.py -v`
Expected: PASS (all)

Run: `.venv/bin/mypy flosswing/agent/providers`
Expected: `Success: no issues found`

- [ ] **Step 5: Commit**

```bash
git add flosswing/agent/providers/base.py flosswing/agent/providers/anthropic_sdk.py flosswing/agent/providers/registry.py tests/unit/test_providers_anthropic.py
git commit -m "Add keyword-only model arg to Provider.validate_auth (seam change for Ollama preflight)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: `OllamaProvider` — preflight + pure helpers

**Files:**
- Create: `flosswing/agent/providers/ollama_native.py`
- Test: `tests/unit/test_providers_ollama.py`

**Interfaces:**
- Consumes: `flosswing.agent.providers.base.SessionResult` / `_classify`; `flosswing.errors.OllamaBackendUnavailableError` / `scrub`; `ollama.Client`, `ollama.AsyncClient`, `ollama.ChatResponse`.
- Produces:
  - `OllamaProvider` with `name = "ollama"`, `auth_env_keys = frozenset({"OLLAMA_HOST"})`, and `validate_auth(self, env, *, model=None) -> None`.
  - module-level helpers: `_to_ollama_tool(tool: Any) -> dict[str, Any]`, `_flatten_content(raw: dict[str, Any]) -> str`, `_model_is_available(requested: str, available: set[str]) -> bool`.
  - module-level names `Client`, `AsyncClient`, `ChatResponse` (imported), monkeypatch-able by tests.
  - module constants `_MAX_TOOL_ITERATIONS: int`, `_WALL_CLOCK_DEADLINE_S: float` (used by Task 5).

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_providers_ollama.py`:

```python
"""OllamaProvider: preflight, helpers, and the native tool-use loop.

The ollama client is mocked at the package boundary (the module-level
`Client` / `AsyncClient` names), never at HTTP.
"""

from __future__ import annotations

import asyncio
from typing import Any

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

    def __init__(self, names: list[str] | None, exc: Exception | None = None, *, host: Any = None) -> None:
        self._names = names or []
        self._exc = exc
        self.host = host

    def list(self) -> _FakeListResponse:
        if self._exc is not None:
            raise self._exc
        return _FakeListResponse(self._names)


def _sync_client_factory(names: list[str] | None = None, exc: Exception | None = None):  # type: ignore[no-untyped-def]
    def factory(host: Any = None) -> _FakeSyncClient:
        return _FakeSyncClient(names, exc, host=host)
    return factory


# --- helpers -----------------------------------------------------------------

def test_to_ollama_tool_shape() -> None:
    class _T:
        name = "grep"
        description = "search the repo"
        input_schema = {"type": "object", "properties": {"pattern": {"type": "string"}}}

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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/unit/test_providers_ollama.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'flosswing.agent.providers.ollama_native'`

- [ ] **Step 3: Create the module (preflight + helpers + constants)**

Create `flosswing/agent/providers/ollama_native.py`:

```python
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
```

(Task 5 appends the `run_session` method to this same class.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/unit/test_providers_ollama.py -v`
Expected: PASS (helpers + validate_auth + name tests; no run_session tests yet)

Run: `.venv/bin/mypy flosswing/agent/providers/ollama_native.py`
Expected: `Success: no issues found`
(If mypy reports errors originating inside the `ollama` package itself, add the contingency override in Task 8 Step 4 and re-run.)

- [ ] **Step 5: Commit**

```bash
git add flosswing/agent/providers/ollama_native.py tests/unit/test_providers_ollama.py
git commit -m "Implement OllamaProvider preflight + tool/content helpers

Per docs/specs/2026-06-18-ollama-provider-design.md § validate_auth and
§ run_session (helpers). run_session loop follows in the next commit.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: `OllamaProvider.run_session` — the native tool-use loop

**Files:**
- Modify: `flosswing/agent/providers/ollama_native.py` (append `run_session` to `OllamaProvider`)
- Test: `tests/unit/test_providers_ollama.py` (append loop tests)

**Interfaces:**
- Consumes: the `OllamaProvider`, `AsyncClient`, `ChatResponse`, `_classify`, `SessionResult` from Task 4.
- Produces: `async OllamaProvider.run_session(self, *, model, system_prompt, tools, user_prompt, token_budget, auth_env, run_id, stage, task_id=None, finding_id=None, agent_session_id=None) -> SessionResult` — matches the `Provider` Protocol signature exactly. Outcomes: `completed` (final message, no tool calls), `budget_exceeded` (accumulated input tokens > budget), `timed_out` (wall-clock deadline), `errored` (iteration cap / client exception); never `refused`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_providers_ollama.py`:

```python
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

    async def chat(self, *, model: str, messages: Any, tools: Any = None, **kw: Any) -> _FakeChatResponse:
        self.calls.append({"model": model, "messages": list(messages), "tools": tools})
        return self._responses.pop(0)


class _LoopingAsyncClient:
    """Always returns a tool-call response (drives the iteration cap)."""

    def __init__(self, *, host: Any = None) -> None:
        self.count = 0

    async def chat(self, *, model: str, messages: Any, tools: Any = None, **kw: Any) -> _FakeChatResponse:
        self.count += 1
        return _FakeChatResponse(
            _FakeMessage(tool_calls=[_FakeToolCall("grep", {"pattern": "x"})]),
            prompt_eval_count=1,
            eval_count=1,
        )


class _RaisingAsyncClient:
    def __init__(self, exc: Exception, *, host: Any = None) -> None:
        self._exc = exc

    async def chat(self, *, model: str, messages: Any, tools: Any = None, **kw: Any) -> _FakeChatResponse:
        raise self._exc


def _async_factory(client: Any):  # type: ignore[no-untyped-def]
    def factory(host: Any = None) -> Any:
        return client
    return factory


class _FakeTool:
    def __init__(self, name: str, result: dict[str, Any]) -> None:
        self.name = name
        self.description = f"{name} tool"
        self.input_schema = {"type": "object"}
        self._result = result

    async def handler(self, args: dict[str, Any]) -> dict[str, Any]:
        return self._result


def _run(prov: on.OllamaProvider, **kw: Any) -> on.SessionResult:
    base = dict(
        model="gemma4", system_prompt="sys", tools=[], user_prompt="go",
        token_budget=200_000, auth_env={}, run_id="r", stage="hunt",
    )
    base.update(kw)
    return asyncio.run(prov.run_session(**base))  # type: ignore[arg-type]


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


def test_run_session_times_out(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(on, "_WALL_CLOCK_DEADLINE_S", -1.0)
    client = _ScriptedAsyncClient([_FakeChatResponse(_FakeMessage(content="never"))])
    monkeypatch.setattr(on, "AsyncClient", _async_factory(client))
    res = _run(on.OllamaProvider())
    assert res.outcome == "timed_out"
    assert res.tool_calls_count == 0


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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/unit/test_providers_ollama.py -k run_session -v`
Expected: FAIL with `AttributeError: 'OllamaProvider' object has no attribute 'run_session'`

- [ ] **Step 3: Append `run_session` to `OllamaProvider`**

Append this method inside the `OllamaProvider` class in `flosswing/agent/providers/ollama_native.py` (after `validate_auth`):

```python
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
                if time.monotonic() > deadline:
                    timed_out = True
                    break

                response = cast(
                    ChatResponse,
                    await client.chat(
                        model=model,
                        messages=messages,
                        tools=tool_specs or None,
                    ),
                )
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

                # Best-effort budget check: stop before doing more work once
                # we've overshot. _classify then buckets this as
                # budget_exceeded (input_tokens > budget).
                if input_tokens > token_budget:
                    break

                tool_calls = msg.tool_calls or []
                if not tool_calls:
                    break  # final answer -> completed

                for call in tool_calls:
                    tool_calls_count += 1
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
                    except Exception as e:  # noqa: BLE001 - tool errors feed back to the model
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
                        "content": _flatten_content(raw),
                    })
            else:
                # Loop exhausted range() without breaking -> stuck calling tools.
                api_error = api_error or "max_tool_iterations_exceeded"
        except Exception as e:  # noqa: BLE001 - any transport/model error -> errored
            api_error = f"{type(e).__name__}: {e}"

        duration_ms = int((time.monotonic() - started) * 1000)

        if timed_out:
            return SessionResult(
                outcome="timed_out",
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                cache_read_tokens=0,
                cache_write_tokens=0,
                duration_ms=duration_ms,
                tool_calls_count=tool_calls_count,
                refusal_text=None,
                error_text=None,
            )

        classified = _classify(
            stop_reason=None,
            usage={"input_tokens": input_tokens, "output_tokens": output_tokens},
            refusal_text=None,
            budget=token_budget,
            api_error=api_error,
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
```

- [ ] **Step 4: Run tests + type check to verify pass**

Run: `.venv/bin/python -m pytest tests/unit/test_providers_ollama.py -v`
Expected: PASS (all preflight, helper, and run_session tests)

Run: `.venv/bin/mypy flosswing/agent/providers/ollama_native.py`
Expected: `Success: no issues found`

- [ ] **Step 5: Commit**

```bash
git add flosswing/agent/providers/ollama_native.py tests/unit/test_providers_ollama.py
git commit -m "Implement OllamaProvider.run_session native tool-use loop

Per docs/specs/2026-06-18-ollama-provider-design.md § run_session +
§ Outcome mapping. Outcomes: completed/budget_exceeded/timed_out/errored;
never refused. Guards: wall-clock deadline and max tool-iteration cap.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: Activate ollama — registry + config + CLI

This is the atomic "flip the switch" task: the moment `ollama` becomes implemented, the existing tests that assert it is a stub must be updated in the same commit to keep the suite green.

**Files:**
- Modify: `flosswing/agent/providers/registry.py` (move ollama to implemented; add `implemented_providers()`)
- Modify: `flosswing/config.py` (model-first resolution; Ollama default; `AUTH_ENV_KEYS` union)
- Modify: `flosswing/cli.py` (`--provider` / `--model` help text)
- Modify: `tests/unit/test_providers_registry.py`, `tests/unit/test_config.py`, `tests/unit/test_cli.py`

**Interfaces:**
- Consumes: `OllamaProvider` (Tasks 4-5).
- Produces:
  - `registry.is_implemented("ollama") is True`; `registry.get_provider("ollama")` returns an `OllamaProvider`.
  - `registry.implemented_providers() -> tuple[Provider, ...]`.
  - `config.DEFAULT_OLLAMA_MODEL = "gemma4"`.
  - `config.AUTH_ENV_KEYS` is the union of every implemented provider's `auth_env_keys` (now includes `OLLAMA_HOST`); still excludes `FLOSSWING_PROVIDER`.
  - `config.resolve` resolves the model before preflight and passes it to `validate_auth(env, model=...)`; uses `DEFAULT_OLLAMA_MODEL` when `provider == "ollama"` and no `--model`.

- [ ] **Step 1: Write/update the failing tests**

In `tests/unit/test_providers_registry.py`:

Change the stub parametrize list (line 19) to drop `ollama`:

```python
@pytest.mark.parametrize("name", ["openai", "bedrock", "cloudflare"])
def test_stubs_registered_but_not_implemented(name: str) -> None:
    assert name in reg.registered_names()
    assert reg.is_implemented(name) is False
    prov = reg.get_provider(name)
    assert prov.name == name
```

Change `test_stub_run_session_raises` (line 33) to use a still-stub provider:

```python
def test_stub_run_session_raises() -> None:
    prov = reg.get_provider("openai")
    with pytest.raises(ProviderNotImplementedError):
        asyncio.run(
            prov.run_session(
                model="x", system_prompt="s", tools=[], user_prompt="u",
                token_budget=1, auth_env={}, run_id="r", stage="hunt",
            )
        )
```

Append two new tests:

```python
def test_ollama_is_implemented() -> None:
    from flosswing.agent.providers.ollama_native import OllamaProvider

    assert reg.is_implemented("ollama") is True
    assert isinstance(reg.get_provider("ollama"), OllamaProvider)


def test_implemented_providers_includes_anthropic_and_ollama() -> None:
    names = {p.name for p in reg.implemented_providers()}
    assert {"anthropic", "ollama"} <= names
```

In `tests/unit/test_config.py`:

Replace `test_env_selects_provider_when_no_flag` (lines 582-593) — it must use a still-unimplemented provider:

```python
def test_env_selects_provider_when_no_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _strip_all_auth(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("FLOSSWING_PROVIDER", "openai")
    with pytest.raises(ProviderNotImplementedError):
        resolve(
            repo_root=tmp_path, model=None, recon_token_budget=None,
            hunt_token_budget=None, validate_token_budget=None,
            gapfill_token_budget=None,
        )
```

Replace `test_auth_env_keys_match_anthropic_provider` (lines 609-613) — `AUTH_ENV_KEYS` is now a union:

```python
def test_auth_env_keys_is_union_of_implemented_providers() -> None:
    from flosswing.agent.providers.anthropic_sdk import AnthropicSDKProvider
    from flosswing.agent.providers.ollama_native import OllamaProvider

    assert AnthropicSDKProvider.auth_env_keys <= cfg_mod.AUTH_ENV_KEYS
    assert OllamaProvider.auth_env_keys <= cfg_mod.AUTH_ENV_KEYS
    assert "OLLAMA_HOST" in cfg_mod.AUTH_ENV_KEYS
    assert "FLOSSWING_PROVIDER" not in cfg_mod.AUTH_ENV_KEYS
```

Append a new test for the Ollama default model (uses a fake provider so no server is needed):

```python
def test_ollama_provider_defaults_model_to_gemma4(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _strip_all_auth(monkeypatch)
    # Stub the Ollama preflight so resolve() doesn't need a live server.
    from flosswing.agent.providers import ollama_native
    seen: dict[str, object] = {}

    def _fake_validate(self: object, env: object, *, model: object = None) -> None:
        seen["model"] = model

    monkeypatch.setattr(ollama_native.OllamaProvider, "validate_auth", _fake_validate)
    cfg = resolve(
        repo_root=tmp_path, model=None, recon_token_budget=None,
        hunt_token_budget=None, validate_token_budget=None,
        gapfill_token_budget=None, provider="ollama",
    )
    assert cfg.provider == "ollama"
    assert cfg.model == "gemma4"
    assert seen["model"] == "gemma4"  # preflight saw the resolved model


def test_ollama_provider_respects_explicit_model(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _strip_all_auth(monkeypatch)
    from flosswing.agent.providers import ollama_native
    monkeypatch.setattr(
        ollama_native.OllamaProvider, "validate_auth",
        lambda self, env, *, model=None: None,
    )
    cfg = resolve(
        repo_root=tmp_path, model="qwen2.5-coder:7b", recon_token_budget=None,
        hunt_token_budget=None, validate_token_budget=None,
        gapfill_token_budget=None, provider="ollama",
    )
    assert cfg.model == "qwen2.5-coder:7b"
```

In `tests/unit/test_cli.py`, change `test_scan_rejects_unimplemented_provider` (line 33) to use a still-unimplemented provider:

```python
    result = runner.invoke(
        main, ["scan", str(tmp_path), "--provider", "openai"]
    )
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/unit/test_providers_registry.py tests/unit/test_config.py::test_ollama_is_implemented tests/unit/test_config.py::test_ollama_provider_defaults_model_to_gemma4 -v`
Expected: FAIL — `implemented_providers` missing / `is_implemented("ollama")` is False / `DEFAULT_OLLAMA_MODEL` not applied. (Some collection errors are expected until Step 3.)

- [ ] **Step 3a: Register ollama as implemented**

In `flosswing/agent/providers/registry.py`:

Add the import near the top (after the anthropic import, line 23):

```python
from flosswing.agent.providers.anthropic_sdk import AnthropicSDKProvider
from flosswing.agent.providers.ollama_native import OllamaProvider
```

Change the stub-names tuple (line 27) to drop ollama:

```python
_STUB_NAMES: tuple[str, ...] = ("openai", "bedrock", "cloudflare")
```

Change the implemented map (line 50) to add ollama:

```python
_IMPLEMENTED: dict[str, Provider] = {
    "anthropic": AnthropicSDKProvider(),
    "ollama": OllamaProvider(),
}
```

Add an accessor after `get_provider` (end of file):

```python


def implemented_providers() -> tuple[Provider, ...]:
    """All providers with a working backend (not stubs).

    Used by config to build the .env auto-load allowlist (AUTH_ENV_KEYS)
    from the union of every implemented provider's declared auth keys.
    """
    return tuple(_IMPLEMENTED.values())
```

- [ ] **Step 3b: Wire config.resolve**

In `flosswing/config.py`:

Add the Ollama default constant after `DEFAULT_MODEL` (line 57):

```python
DEFAULT_MODEL: str = "claude-opus-4-7"
DEFAULT_OLLAMA_MODEL: str = "gemma4"
```

Replace the `AUTH_ENV_KEYS` assignment (lines 72-77) with the union form:

```python
# The default `.env` auto-load (flosswing/cli.py) is restricted to this
# allowlist: the union of every implemented provider's declared auth keys
# (Anthropic's credential set + Ollama's OLLAMA_HOST). A future real
# provider extends it just by declaring auth_env_keys. FLOSSWING_PROVIDER is
# intentionally NOT here: provider selection is not a credential and must not
# be settable by an auto-loaded .env.
AUTH_ENV_KEYS: frozenset[str] = frozenset().union(
    *(p.auth_env_keys for p in registry.implemented_providers())
)
```

(The unused-import `AnthropicSDKProvider` at line 54 is now only referenced by nothing in config — leave the import in place ONLY if still used elsewhere; if `ruff check` flags it as unused (F401) in Step 4, delete the `from flosswing.agent.providers.anthropic_sdk import AnthropicSDKProvider` line.)

In `resolve()` (lines 117-126), resolve the model before the preflight and pass it in. Replace:

```python
    provider_name = provider or os.environ.get(PROVIDER_ENV_VAR) or DEFAULT_PROVIDER
    prov = registry.get_provider(provider_name)  # UnknownProviderError if bogus
    if not registry.is_implemented(provider_name):
        raise ProviderNotImplementedError(
            f"{provider_name} provider is not yet implemented; see ARCHITECTURE.md"
        )
    prov.validate_auth(os.environ)  # AuthCredentialMissingError if no usable path
    auth_env: dict[str, str] = {
        k: os.environ[k] for k in prov.auth_env_keys if k in os.environ
    }
```

with:

```python
    provider_name = provider or os.environ.get(PROVIDER_ENV_VAR) or DEFAULT_PROVIDER
    prov = registry.get_provider(provider_name)  # UnknownProviderError if bogus
    if not registry.is_implemented(provider_name):
        raise ProviderNotImplementedError(
            f"{provider_name} provider is not yet implemented; see ARCHITECTURE.md"
        )
    # Resolve the model before preflight so providers that verify model
    # availability (Ollama) can check the concrete model name.
    default_model = (
        DEFAULT_OLLAMA_MODEL if provider_name == "ollama" else DEFAULT_MODEL
    )
    resolved_model = model or default_model
    # AuthCredentialMissingError / OllamaBackendUnavailableError if unusable.
    prov.validate_auth(os.environ, model=resolved_model)
    auth_env: dict[str, str] = {
        k: os.environ[k] for k in prov.auth_env_keys if k in os.environ
    }
```

Then change the `Config(...)` construction's `model=` line (line 130) from:

```python
        model=model or DEFAULT_MODEL,
```

to:

```python
        model=resolved_model,
```

- [ ] **Step 3c: Update CLI help text**

In `flosswing/cli.py`, update the two help strings (lines 110-118):

```python
@click.option(
    "--model",
    default=None,
    help="Override the agent model (default claude-opus-4-7; gemma4 for --provider ollama).",
)
@click.option(
    "--provider",
    default=None,
    help="Model provider backend: anthropic (default) or ollama. openai/bedrock/cloudflare are reserved/unimplemented.",
)
```

- [ ] **Step 4: Run the full unit suite + lint + type check**

Run: `.venv/bin/python -m pytest tests/unit -q`
Expected: all pass (the previously-stub assertions now updated)

Run: `.venv/bin/ruff check flosswing tests`
Expected: `All checks passed!` (if `AnthropicSDKProvider` import in config.py is now unused, delete that line per Step 3b note and re-run)

Run: `.venv/bin/mypy flosswing`
Expected: `Success: no issues found`

- [ ] **Step 5: Commit**

```bash
git add flosswing/agent/providers/registry.py flosswing/config.py flosswing/cli.py tests/unit/test_providers_registry.py tests/unit/test_config.py tests/unit/test_cli.py
git commit -m "Activate ollama provider: registry + config model-first resolve + CLI

Moves ollama from stub to implemented; adds registry.implemented_providers();
resolves the model before validate_auth so the Ollama preflight can check it;
defaults to gemma4 for --provider ollama; widens AUTH_ENV_KEYS to the union of
implemented providers' auth keys (adds OLLAMA_HOST). Updates the tests that
assumed ollama was unimplemented to use openai instead.

Per docs/specs/2026-06-18-ollama-provider-design.md § Seam changes.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: Gated integration test

**Files:**
- Create: `tests/integration/test_ollama_integration.py`

**Interfaces:**
- Consumes: a real local Ollama server + a pulled tool-calling model. Gated on `FLOSSWING_OLLAMA_INTEGRATION=1`; skipped otherwise (so normal CI is unaffected, mirroring the `FLOSSWING_INTEGRATION` pattern).
- Produces: a smoke test that `OllamaProvider.run_session` completes a one-tool round-trip against the real backend.

- [ ] **Step 1: Write the test**

Create `tests/integration/test_ollama_integration.py`:

```python
"""Gated real-Ollama integration smoke test.

Runs only when FLOSSWING_OLLAMA_INTEGRATION=1 and a local Ollama server is
serving a tool-calling model (default gemma4, override with
FLOSSWING_OLLAMA_MODEL). Not part of normal CI — mirrors the
FLOSSWING_INTEGRATION discipline. Verifies the native loop completes a
single tool round-trip end-to-end.
"""

from __future__ import annotations

import os

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
        name = "echo"
        description = "Echo the given text back."
        input_schema = {
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
```

- [ ] **Step 2: Verify it skips cleanly without the gate**

Run: `.venv/bin/python -m pytest tests/integration/test_ollama_integration.py -v`
Expected: `1 skipped` (no `FLOSSWING_OLLAMA_INTEGRATION`)

- [ ] **Step 3: (Optional, requires a live server) run it for real**

Only if Ollama is installed and serving:
```bash
ollama pull gemma4
FLOSSWING_OLLAMA_INTEGRATION=1 .venv/bin/python -m pytest tests/integration/test_ollama_integration.py -v
```
Expected: PASS (or a clear, actionable skip/fail if the model isn't pulled).
If `gemma4` does not emit `tool_calls`, this is where it surfaces (`tool_calls_count == 0`); rerun with `FLOSSWING_OLLAMA_MODEL=qwen2.5-coder:7b` to confirm the loop itself is correct.

- [ ] **Step 4: Commit**

```bash
git add tests/integration/test_ollama_integration.py
git commit -m "Add gated FLOSSWING_OLLAMA_INTEGRATION round-trip smoke test

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: Final verification + operator-curated doc proposals

**Files:**
- No code changes. Verification only, plus two *proposed* diffs surfaced for operator approval (NOT applied).

- [ ] **Step 1: Full suite**

Run: `.venv/bin/python -m pytest tests/unit -q`
Expected: all pass (baseline was 580; this adds the ollama/error/anthropic tests).

- [ ] **Step 2: Lint**

Run: `.venv/bin/ruff check flosswing tests`
Expected: `All checks passed!`

- [ ] **Step 3: Type check**

Run: `.venv/bin/mypy flosswing`
Expected: `Success: no issues found`

- [ ] **Step 4: mypy contingency for the `ollama` package**

If Step 3 reported strict-mode errors originating *inside* the `ollama` package (not our code), add an override in `pyproject.toml` under the existing `[[tool.mypy.overrides]]` blocks:

```toml
[[tool.mypy.overrides]]
module = ["ollama", "ollama.*"]
ignore_missing_imports = true
follow_imports = "skip"
```

Re-run `.venv/bin/mypy flosswing` → `Success`. If Step 3 already passed, skip this step. (Commit `pyproject.toml` with the message `Silence mypy on third-party ollama internals` if changed.)

- [ ] **Step 5: Surface the operator-curated doc diffs (do NOT apply)**

These two files are operator-curated; per `CLAUDE.md` they must not be edited without explicit instruction. Present these exact proposed diffs in chat and wait for approval:

Proposed `CLAUDE.md` dependency-list addition (under "## Dependency policy", in the `Current stack` list):
```
- `ollama` — local-model backend client (OllamaProvider native tool-use loop)
```

Proposed `ARCHITECTURE.md` change: locate the sentence/line describing `ollama` as an unimplemented stub (alongside `openai`/`bedrock`/`cloudflare`) and update it to state that `ollama` is an implemented v1 backend (native in-process tool-use loop), with `openai`/`bedrock`/`cloudflare` remaining stubs. (Run `grep -n "ollama" ARCHITECTURE.md` to find the exact line before drafting the diff.)

- [ ] **Step 6: Report completion**

Summarize: tests passing (count), ruff/mypy clean, the manual end-to-end runbook (`ollama pull gemma4` → `flosswing scan tests/corpus/<repo> --provider ollama`), and the two pending operator-approval doc diffs. Then use the `superpowers:finishing-a-development-branch` skill to decide how to integrate the worktree branch.

---

## Self-Review

**1. Spec coverage**

| Spec section | Task |
| --- | --- |
| Goal: working `--provider ollama` end-to-end | Tasks 4-6 + runbook (8) |
| Native loop (decision 1) | Task 5 |
| `ollama` package (decision 2) | Task 1 |
| Preflight ping + model check (decision 3) | Task 4 (+ signature in 3) |
| No synthesized refusals (decision 4) | Task 5 (`test_run_session_never_synthesizes_refusal`) |
| Ollama default model gemma4 (decision 5) | Task 6 |
| Model tool-calling requirement | Task 7 (integration surfaces it) |
| `OllamaProvider` name/auth_env_keys | Task 4 |
| `validate_auth` reachable/unreachable/model-missing | Task 4 |
| `run_session` loop + usage + classify | Task 5 |
| Safety guards (wall-clock, iteration cap) | Task 5 |
| Outcome mapping table | Task 5 (one test per row) |
| `OllamaBackendUnavailableError` | Task 2 |
| Seam: validate_auth `model` kwarg | Task 3 |
| Seam: config model-first + default + AUTH_ENV_KEYS union | Task 6 |
| Seam: registry ollama → implemented | Task 6 |
| Dependency + pyproject | Task 1 |
| CLAUDE.md / ARCHITECTURE.md proposals | Task 8 |
| errors.scrub() over operator-facing strings | Tasks 4-5 (scrub at raise + in api_error path) |
| Unit tests (mock at package boundary) | Tasks 4-5 |
| Gated integration test | Task 7 |
| Manual runbook | Task 8 |

No spec requirement is left without a task.

**2. Placeholder scan:** No TBD/TODO/"handle edge cases"/"similar to" — every code and test step contains the literal code. The only conditional step (Task 8 Step 4) is a guarded contingency with the exact TOML to add.

**3. Type consistency:** `OllamaProvider`, `validate_auth(env, *, model=None)`, `run_session(...)`, `implemented_providers()`, `_to_ollama_tool`/`_flatten_content`/`_model_is_available`, `_MAX_TOOL_ITERATIONS`/`_WALL_CLOCK_DEADLINE_S`, `DEFAULT_OLLAMA_MODEL`, `OllamaBackendUnavailableError`, and `AUTH_ENV_KEYS` are named identically across the tasks that define and consume them. The module-level `Client`/`AsyncClient`/`ChatResponse` imports are the exact names the tests monkeypatch.
