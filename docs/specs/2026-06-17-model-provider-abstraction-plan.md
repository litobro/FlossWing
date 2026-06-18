# Model-Provider Abstraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Introduce a `Provider` seam at `run_session()` so non-Anthropic model backends can be added later, with the existing Claude Agent SDK path refactored behind it as the default and Ollama/OpenAI/Bedrock/Cloudflare registered as unimplemented stubs.

**Architecture:** A new `flosswing/agent/providers/` package (mirroring `flosswing/sandbox/`) holds a `Provider` Protocol + shared `SessionResult`/`_classify` in `base.py`, the relocated Agent-SDK logic in `anthropic_sdk.py`, and a name→provider `registry.py`. `runtime.run_session()` becomes a thin facade that resolves a provider and delegates. `config.resolve()` selects the provider (flag → `FLOSSWING_PROVIDER` env → default `anthropic`), rejects unimplemented providers early, and delegates auth validation to the provider.

**Tech Stack:** Python 3.11+, `claude-agent-sdk`, `click`, `pydantic` (unaffected), `pytest`/`pytest-asyncio`. No new dependencies.

## Global Constraints

- Python 3.11+, full type hints. `ruff check` and `mypy --strict` must pass (config in `pyproject.toml`). `# type: ignore` only with an inline reason.
- Frozen contracts unchanged: do **not** modify any signature in `docs/tool-contracts.md`. `run_session` is internal and not covered by it.
- No state-DB schema change → no Alembic migration, `docs/schema.sql` untouched.
- No credential value is ever logged, persisted to the state DB, or placed in an error message/trace. All strings bound for stderr/DB/report pass through `errors.scrub()`.
- `FLOSSWING_PROVIDER` must **not** be added to `AUTH_ENV_KEYS` (provider selection is not a credential; a planted `.env` must not flip it).
- Unit tests mock the SDK at the `query()`/`tool()` boundary, never HTTP.
- Default provider is `"anthropic"`; Anthropic behavior (auth modes, error messages, `SessionResult` shape) must be byte-for-byte unchanged for callers.
- `ARCHITECTURE.md` is operator-curated: the Task 8 diff is **proposed and committed only after explicit operator approval**.

---

### Task 1: Provider base module (`SessionResult`, `Provider` Protocol, shared `_classify`)

Relocate the provider-agnostic contract (`SessionResult`, `_classify`) into a new `base.py`; have `runtime.py` import + re-export them so all existing import paths keep working.

**Files:**
- Create: `flosswing/agent/providers/__init__.py`
- Create: `flosswing/agent/providers/base.py`
- Modify: `flosswing/agent/runtime.py` (import `SessionResult`/`_classify` from base; delete the local copies; keep re-export)
- Create: `tests/unit/test_providers_base.py`
- Modify: `tests/unit/test_agent_runtime.py` (move the four `_classify` tests out)

**Interfaces:**
- Produces: `flosswing.agent.providers.base.SessionResult` (dataclass, fields exactly as today), `flosswing.agent.providers.base._classify(*, stop_reason, usage, refusal_text, budget, api_error) -> SessionResult`, `flosswing.agent.providers.base.OutcomeLiteral`, and `flosswing.agent.providers.base.Provider` (Protocol).
- Produces: `flosswing.agent.runtime.SessionResult` and `flosswing.agent.runtime._classify` remain importable (re-exported).

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_providers_base.py`:

```python
"""providers.base: SessionResult contract + pure _classify mapping."""

from __future__ import annotations

from flosswing.agent.providers import base


def test_classify_completed() -> None:
    result = base._classify(
        stop_reason="end_turn",
        usage={"input_tokens": 1234, "output_tokens": 567},
        refusal_text=None,
        budget=200_000,
        api_error=None,
    )
    assert result.outcome == "completed"
    assert result.input_tokens == 1234
    assert result.output_tokens == 567


def test_classify_refused() -> None:
    result = base._classify(
        stop_reason="refusal",
        usage={"input_tokens": 100, "output_tokens": 20},
        refusal_text="I can't help with that.",
        budget=200_000,
        api_error=None,
    )
    assert result.outcome == "refused"
    assert result.refusal_text == "I can't help with that."


def test_classify_budget_exceeded() -> None:
    result = base._classify(
        stop_reason="end_turn",
        usage={"input_tokens": 300_000, "output_tokens": 5},
        refusal_text=None,
        budget=200_000,
        api_error=None,
    )
    assert result.outcome == "budget_exceeded"


def test_classify_errored_scrubs_credentials() -> None:
    result = base._classify(
        stop_reason="error",
        usage={"input_tokens": 0, "output_tokens": 0},
        refusal_text=None,
        budget=200_000,
        api_error="500 with Authorization: Bearer eyJsecret.payload.sig in headers",
    )
    assert result.outcome == "errored"
    assert "eyJsecret.payload.sig" not in (result.error_text or "")
    assert "[REDACTED]" in (result.error_text or "")


def test_session_result_reexported_from_runtime() -> None:
    from flosswing.agent.runtime import SessionResult as RuntimeSR

    assert RuntimeSR is base.SessionResult
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_providers_base.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'flosswing.agent.providers'`

- [ ] **Step 3: Create the package and base module**

Create `flosswing/agent/providers/__init__.py` (license header + empty body):

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

"""Model-provider abstraction. See docs/specs/2026-06-17-model-provider-abstraction-design.md."""
```

Create `flosswing/agent/providers/base.py` (same license header, then):

```python
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

    def validate_auth(self, env: Mapping[str, str]) -> None: ...

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
```

- [ ] **Step 4: Point runtime at base and delete its local copies**

In `flosswing/agent/runtime.py`: remove the local `OutcomeLiteral`, `SessionResult`, and `_classify` definitions, and add an import + re-export near the top (after the existing `from flosswing.errors import scrub`):

```python
from flosswing.agent.providers.base import (  # re-exported for callers/tests
    OutcomeLiteral,
    Provider,
    SessionResult,
    _classify,
)

__all__ = ["OutcomeLiteral", "Provider", "SessionResult", "_classify", "run_session"]
```

Leave the rest of `runtime.py` (the `query()` loop, `_harvest_usage`, `_api_error_from_result`, `_is_spurious_sdk_exit_error`, `run_session`) untouched in this task — they still reference the now-imported `SessionResult`/`_classify`.

- [ ] **Step 5: Move the `_classify` tests out of test_agent_runtime.py**

In `tests/unit/test_agent_runtime.py`, delete the four functions `test_classify_completed`, `test_classify_refused`, `test_classify_budget_exceeded`, `test_classify_errored_scrubs_credentials` (now living in `test_providers_base.py`). Leave the issue-#22 `_api_error_from_result` / `_is_spurious_sdk_exit_error` tests in place.

- [ ] **Step 6: Run tests to verify they pass**

Run: `pytest tests/unit/test_providers_base.py tests/unit/test_agent_runtime.py -v`
Expected: PASS (all). Then `mypy --strict flosswing/agent/providers/base.py flosswing/agent/runtime.py` and `ruff check flosswing/agent`.

- [ ] **Step 7: Commit**

```bash
git add flosswing/agent/providers/__init__.py flosswing/agent/providers/base.py \
        flosswing/agent/runtime.py tests/unit/test_providers_base.py \
        tests/unit/test_agent_runtime.py
git commit -m "Add providers.base with SessionResult + _classify per docs/specs/2026-06-17-model-provider-abstraction-design.md § Architecture"
```

---

### Task 2: AnthropicSDKProvider (relocate the Agent-SDK session body + auth)

Move all Anthropic/Agent-SDK-specific logic — the `query()` loop, SDK parsing helpers, the auth key sets, the `az` probe, and the auth-path check — into `anthropic_sdk.py` as `AnthropicSDKProvider`. Make `runtime.run_session` delegate to it directly (registry comes in Task 5). This keeps `config.resolve` working (it still has its own inline auth check until Task 6).

**Files:**
- Create: `flosswing/agent/providers/anthropic_sdk.py`
- Modify: `flosswing/agent/runtime.py` (replace body of `run_session` with a direct call to `AnthropicSDKProvider().run_session`; remove the now-moved helpers)
- Create: `tests/unit/test_providers_anthropic.py`
- Modify: `tests/unit/test_agent_runtime.py` (move the issue-#22 helper tests to the new file; convert to a delegation test)

**Interfaces:**
- Consumes: `flosswing.agent.providers.base.{SessionResult, _classify}`.
- Produces: class `AnthropicSDKProvider` with `name = "anthropic"`, `auth_env_keys: frozenset[str]` (direct + Foundry routing + Foundry key + Entra SP triple + Foundry model names), `validate_auth(env: Mapping[str, str]) -> None`, and `async run_session(...) -> SessionResult` (signature identical to today's module-level `run_session` minus `provider`).
- Produces: module-level `_has_az_session() -> bool` (monkeypatchable).

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_providers_anthropic.py` (license header omitted for brevity in the plan — include it):

```python
"""providers.anthropic_sdk: auth validation + SDK error parsing."""

from __future__ import annotations

from collections.abc import Mapping

import pytest

from flosswing.agent.providers import anthropic_sdk as a
from flosswing.errors import AuthCredentialMissingError


def _provider() -> a.AnthropicSDKProvider:
    return a.AnthropicSDKProvider()


def test_name_and_auth_env_keys() -> None:
    p = _provider()
    assert p.name == "anthropic"
    assert "ANTHROPIC_API_KEY" in p.auth_env_keys
    assert "CLAUDE_CODE_USE_FOUNDRY" in p.auth_env_keys
    assert "AZURE_CLIENT_SECRET" in p.auth_env_keys
    assert "ANTHROPIC_DEFAULT_OPUS_MODEL" in p.auth_env_keys


def test_validate_auth_accepts_direct_key() -> None:
    _provider().validate_auth({"ANTHROPIC_API_KEY": "sk-ant-test"})  # no raise


def test_validate_auth_accepts_foundry_key() -> None:
    env: Mapping[str, str] = {
        "CLAUDE_CODE_USE_FOUNDRY": "1",
        "ANTHROPIC_FOUNDRY_RESOURCE": "res",
        "ANTHROPIC_FOUNDRY_API_KEY": "key",
    }
    _provider().validate_auth(env)  # no raise


def test_validate_auth_rejects_empty_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(a, "_has_az_session", lambda: False)
    with pytest.raises(AuthCredentialMissingError):
        _provider().validate_auth({})


def test_api_error_from_result_clean_run_returns_none() -> None:
    assert a._api_error_from_result(
        is_error=False, subtype="success", errors=None
    ) is None


def test_api_error_from_result_spurious_success_returns_none() -> None:
    assert a._api_error_from_result(
        is_error=True, subtype="success", errors=None
    ) is None


def test_api_error_from_result_real_error_propagates() -> None:
    msg = a._api_error_from_result(
        is_error=True, subtype="error_max_turns", errors=["boom"]
    )
    assert msg == "boom"


def test_is_spurious_sdk_exit_error_anchors_full_string() -> None:
    assert a._is_spurious_sdk_exit_error(
        RuntimeError("Claude Code returned an error result: success")
    )
    assert not a._is_spurious_sdk_exit_error(
        RuntimeError("returned an error result: success")
    )
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/unit/test_providers_anthropic.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'flosswing.agent.providers.anthropic_sdk'`

- [ ] **Step 3: Create `anthropic_sdk.py`**

Create `flosswing/agent/providers/anthropic_sdk.py` (license header, then). The `run_session`/`_harvest_usage`/`_api_error_from_result`/`_is_spurious_sdk_exit_error` bodies are moved **verbatim** from the current `runtime.py` (lines 144–225 and 228–364), wrapped as a class method. The auth key tuples and `_has_az_session` are moved **verbatim** from the current `config.py` (lines 69–108 and 134–152).

```python
"""Anthropic backend: drives a session via the Claude Agent SDK subprocess.

Faithful relocation of the previous flosswing/agent/runtime.py body plus
the Anthropic/Foundry/Entra auth knowledge previously inlined in
flosswing/config.py. Keeping that knowledge here (not in config) lets
config import auth metadata FROM the provider without a circular import.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from collections.abc import Mapping
from typing import Any

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ResultMessage,
    create_sdk_mcp_server,
    query,
)

from flosswing.agent.providers.base import SessionResult, _classify
from flosswing.errors import AuthCredentialMissingError

# --- Auth key sets (moved verbatim from config.py) -------------------------

_DIRECT_KEYS: tuple[str, ...] = ("ANTHROPIC_API_KEY",)
_FOUNDRY_ROUTING_KEYS: tuple[str, ...] = (
    "CLAUDE_CODE_USE_FOUNDRY",
    "ANTHROPIC_FOUNDRY_RESOURCE",
)
_FOUNDRY_API_KEY: str = "ANTHROPIC_FOUNDRY_API_KEY"
_ENTRA_SP_KEYS: tuple[str, ...] = (
    "AZURE_CLIENT_ID",
    "AZURE_TENANT_ID",
    "AZURE_CLIENT_SECRET",
)
_FOUNDRY_MODEL_KEYS: tuple[str, ...] = (
    "ANTHROPIC_DEFAULT_OPUS_MODEL",
    "ANTHROPIC_DEFAULT_SONNET_MODEL",
    "ANTHROPIC_DEFAULT_HAIKU_MODEL",
)

_AUTH_ENV_KEYS: frozenset[str] = frozenset(
    (
        *_DIRECT_KEYS,
        *_FOUNDRY_ROUTING_KEYS,
        _FOUNDRY_API_KEY,
        *_ENTRA_SP_KEYS,
        *_FOUNDRY_MODEL_KEYS,
    )
)

_MISSING_AUTH_MSG = (
    "No auth credential found. Set one of:\n"
    "  - ANTHROPIC_API_KEY (direct Anthropic API), OR\n"
    "  - Foundry routing: CLAUDE_CODE_USE_FOUNDRY=1 +\n"
    "    ANTHROPIC_FOUNDRY_RESOURCE=<name>, plus one of:\n"
    "      ANTHROPIC_FOUNDRY_API_KEY=<key>, OR\n"
    "      an active az-login session, OR\n"
    "      AZURE_CLIENT_ID + AZURE_TENANT_ID + AZURE_CLIENT_SECRET\n"
    "      (Entra ID service principal)."
)


def _has_az_session() -> bool:
    """Return True iff `az account show` succeeds (plain az-login active).

    Moved verbatim from config.py. Bounded by a 5-second timeout.
    """
    if shutil.which("az") is None:
        return False
    try:
        r = subprocess.run(
            ["az", "account", "show"],
            check=False,
            capture_output=True,
            timeout=5,
        )
    except (subprocess.TimeoutExpired, OSError):
        return False
    return r.returncode == 0


# --- SDK parsing helpers (moved verbatim from runtime.py) -------------------
# NOTE: copy _api_error_from_result, _is_spurious_sdk_exit_error,
# _SPURIOUS_SDK_EXIT_ERROR_TEXT, and _harvest_usage EXACTLY as they appear
# in the current flosswing/agent/runtime.py (lines 144–225). They are
# omitted here only to keep the plan readable; reproduce them byte-for-byte.


class AnthropicSDKProvider:
    name = "anthropic"
    auth_env_keys = _AUTH_ENV_KEYS

    def validate_auth(self, env: Mapping[str, str]) -> None:
        """Raise AuthCredentialMissingError unless a usable auth path exists.

        Same logic previously inlined in config.resolve().
        """
        has_direct = "ANTHROPIC_API_KEY" in env
        foundry_routing_enabled = (
            env.get("CLAUDE_CODE_USE_FOUNDRY") == "1"
            and "ANTHROPIC_FOUNDRY_RESOURCE" in env
        )
        has_foundry_key = _FOUNDRY_API_KEY in env
        has_entra_sp = all(k in env for k in _ENTRA_SP_KEYS)
        has_az_login = (
            foundry_routing_enabled
            and not has_foundry_key
            and not has_entra_sp
            and _has_az_session()
        )
        has_foundry = foundry_routing_enabled and (
            has_foundry_key or has_entra_sp or has_az_login
        )
        if not (has_direct or has_foundry):
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
    ) -> SessionResult:
        # MOVE the entire body of the current runtime.run_session here
        # VERBATIM (lines 256–364), including the `del run_id, ...` line and
        # the create_sdk_mcp_server / ClaudeAgentOptions / query() loop.
        ...
```

> Implementer note: replace the two `...`/NOTE placeholders by copying the exact existing code from `runtime.py` — do not paraphrase. The `del run_id, stage, task_id, finding_id, agent_session_id` line stays (parity with current behavior).

- [ ] **Step 4: Make runtime delegate to the provider directly**

Replace the body of `run_session` in `flosswing/agent/runtime.py` and drop the moved helpers. After this task `runtime.py` contains only the re-export block (from Task 1) plus:

```python
from flosswing.agent.providers.anthropic_sdk import AnthropicSDKProvider

_ANTHROPIC = AnthropicSDKProvider()


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
) -> SessionResult:
    """Drive one agent session via the default Anthropic provider.

    Provider selection (registry-based) is added in a later task; for now
    this delegates straight to the Anthropic SDK backend.
    """
    return await _ANTHROPIC.run_session(
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
    )
```

Remove the now-unused imports (`time`, `AssistantMessage`, `ClaudeAgentOptions`, `ResultMessage`, `create_sdk_mcp_server`, `query`) from `runtime.py`.

- [ ] **Step 5: Move issue-#22 helper tests; convert test_agent_runtime to a delegation test**

In `tests/unit/test_agent_runtime.py`: delete the `_api_error_from_result` / `_is_spurious_sdk_exit_error` tests (now in `test_providers_anthropic.py`). Replace the file body with a delegation test that monkeypatches the provider and asserts `run_session` forwards kwargs:

```python
"""agent/runtime: run_session delegates to the Anthropic provider."""

from __future__ import annotations

import asyncio

from flosswing.agent import runtime as rt
from flosswing.agent.providers.base import SessionResult


def test_run_session_delegates_to_anthropic(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    captured: dict[str, object] = {}
    sentinel = SessionResult(
        outcome="completed", input_tokens=1, output_tokens=2,
        cache_read_tokens=0, cache_write_tokens=0, duration_ms=0,
        tool_calls_count=0, refusal_text=None, error_text=None,
    )

    async def fake(**kw: object) -> SessionResult:
        captured.update(kw)
        return sentinel

    monkeypatch.setattr(rt._ANTHROPIC, "run_session", fake)
    result = asyncio.run(
        rt.run_session(
            model="claude-opus-4-7", system_prompt="s", tools=[],
            user_prompt="u", token_budget=10, auth_env={}, run_id="r",
            stage="recon",
        )
    )
    assert result is sentinel
    assert captured["model"] == "claude-opus-4-7"
    assert captured["stage"] == "recon"
```

- [ ] **Step 6: Run tests + typecheck**

Run: `pytest tests/unit/test_providers_anthropic.py tests/unit/test_agent_runtime.py tests/unit/test_config.py -v`
Expected: PASS. (`test_config.py` still passes — `config.resolve` is unchanged in this task.)
Run: `mypy --strict flosswing/agent` and `ruff check flosswing/agent tests/unit/test_providers_anthropic.py`

- [ ] **Step 7: Commit**

```bash
git add flosswing/agent/providers/anthropic_sdk.py flosswing/agent/runtime.py \
        tests/unit/test_providers_anthropic.py tests/unit/test_agent_runtime.py
git commit -m "Relocate Agent-SDK session + Anthropic auth into AnthropicSDKProvider per design § AnthropicSDKProvider"
```

---

### Task 3: Provider errors

Add the two scrubbed error types the registry and config will raise.

**Files:**
- Modify: `flosswing/errors.py` (add two classes)
- Modify: `tests/unit/test_errors.py` (add cases; create the file if it doesn't exist)

**Interfaces:**
- Produces: `flosswing.errors.UnknownProviderError(FlosswingError)` with `code = "unknown_provider"`, `retryable = False`; `flosswing.errors.ProviderNotImplementedError(FlosswingError)` with `code = "provider_not_implemented"`, `retryable = False`.

- [ ] **Step 1: Write the failing test**

Add to `tests/unit/test_errors.py` (create with a license header if absent):

```python
from flosswing.errors import (
    FlosswingError,
    ProviderNotImplementedError,
    UnknownProviderError,
)


def test_provider_error_types_are_flosswing_errors() -> None:
    assert issubclass(UnknownProviderError, FlosswingError)
    assert issubclass(ProviderNotImplementedError, FlosswingError)
    assert UnknownProviderError("x").code == "unknown_provider"
    assert ProviderNotImplementedError("x").code == "provider_not_implemented"
    assert UnknownProviderError("x").retryable is False
    assert ProviderNotImplementedError("x").retryable is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_errors.py::test_provider_error_types_are_flosswing_errors -v`
Expected: FAIL — `ImportError: cannot import name 'ProviderNotImplementedError'`

- [ ] **Step 3: Add the classes**

In `flosswing/errors.py`, after `class AuthCredentialMissingError(...)` (line ~116):

```python
class UnknownProviderError(FlosswingError):
    code = "unknown_provider"
    retryable = False


class ProviderNotImplementedError(FlosswingError):
    code = "provider_not_implemented"
    retryable = False
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/unit/test_errors.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add flosswing/errors.py tests/unit/test_errors.py
git commit -m "Add UnknownProviderError + ProviderNotImplementedError per design § Error handling"
```

---

### Task 4: Provider registry

Map provider names to instances; register Anthropic + four unimplemented stubs.

**Files:**
- Create: `flosswing/agent/providers/registry.py`
- Create: `tests/unit/test_providers_registry.py`

**Interfaces:**
- Consumes: `AnthropicSDKProvider`, `flosswing.errors.{UnknownProviderError, ProviderNotImplementedError}`, `flosswing.agent.providers.base.{Provider, SessionResult}`.
- Produces: `get_provider(name: str) -> Provider` (raises `UnknownProviderError` listing registered names); `is_implemented(name: str) -> bool`; `registered_names() -> tuple[str, ...]`; `class UnimplementedProvider` with `name`, `auth_env_keys = frozenset()`, no-op `validate_auth`, and `run_session` that raises `ProviderNotImplementedError`.

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_providers_registry.py`:

```python
"""providers.registry: lookup, implemented-flag, stub behavior."""

from __future__ import annotations

import asyncio

import pytest

from flosswing.agent.providers import registry as reg
from flosswing.agent.providers.anthropic_sdk import AnthropicSDKProvider
from flosswing.errors import ProviderNotImplementedError, UnknownProviderError


def test_anthropic_is_implemented_and_returned() -> None:
    assert reg.is_implemented("anthropic") is True
    assert isinstance(reg.get_provider("anthropic"), AnthropicSDKProvider)


@pytest.mark.parametrize("name", ["ollama", "openai", "bedrock", "cloudflare"])
def test_stubs_registered_but_not_implemented(name: str) -> None:
    assert name in reg.registered_names()
    assert reg.is_implemented(name) is False
    prov = reg.get_provider(name)
    assert prov.name == name


def test_unknown_provider_raises_listing_names() -> None:
    with pytest.raises(UnknownProviderError) as ei:
        reg.get_provider("gpt5")
    assert "anthropic" in ei.value.message


def test_stub_run_session_raises() -> None:
    prov = reg.get_provider("ollama")
    with pytest.raises(ProviderNotImplementedError):
        asyncio.run(
            prov.run_session(
                model="x", system_prompt="s", tools=[], user_prompt="u",
                token_budget=1, auth_env={}, run_id="r", stage="hunt",
            )
        )
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/unit/test_providers_registry.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'flosswing.agent.providers.registry'`

- [ ] **Step 3: Create `registry.py`**

```python
# (license header)
"""Provider registry: name -> Provider, with unimplemented stubs."""

from __future__ import annotations

from typing import Any

from flosswing.agent.providers.anthropic_sdk import AnthropicSDKProvider
from flosswing.agent.providers.base import Provider, SessionResult
from flosswing.errors import ProviderNotImplementedError, UnknownProviderError

_STUB_NAMES: tuple[str, ...] = ("ollama", "openai", "bedrock", "cloudflare")


class UnimplementedProvider:
    """Registered placeholder for a backend not yet built.

    Selecting it is rejected early at config.resolve(); this class's
    run_session raise is a defense-in-depth backstop.
    """

    def __init__(self, name: str) -> None:
        self.name = name
        self.auth_env_keys: frozenset[str] = frozenset()

    def validate_auth(self, env: Any) -> None:  # noqa: ARG002 - no-op by design
        return None

    async def run_session(self, **_kwargs: Any) -> SessionResult:
        raise ProviderNotImplementedError(
            f"{self.name} provider is not yet implemented; see ARCHITECTURE.md"
        )


_IMPLEMENTED: dict[str, Provider] = {"anthropic": AnthropicSDKProvider()}
_STUBS: dict[str, Provider] = {n: UnimplementedProvider(n) for n in _STUB_NAMES}
_REGISTRY: dict[str, Provider] = {**_IMPLEMENTED, **_STUBS}


def registered_names() -> tuple[str, ...]:
    return tuple(_REGISTRY)


def is_implemented(name: str) -> bool:
    return name in _IMPLEMENTED


def get_provider(name: str) -> Provider:
    try:
        return _REGISTRY[name]
    except KeyError:
        raise UnknownProviderError(
            f"Unknown provider {name!r}. Registered: "
            f"{', '.join(sorted(_REGISTRY))}."
        ) from None
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/unit/test_providers_registry.py -v`
Expected: PASS
Run: `mypy --strict flosswing/agent/providers/registry.py`

- [ ] **Step 5: Commit**

```bash
git add flosswing/agent/providers/registry.py tests/unit/test_providers_registry.py
git commit -m "Add provider registry with anthropic default + unimplemented stubs per design § Registry"
```

---

### Task 5: runtime facade resolves provider via registry

Add the `provider` parameter to `run_session` and route through the registry.

**Files:**
- Modify: `flosswing/agent/runtime.py`
- Modify: `tests/unit/test_agent_runtime.py`

**Interfaces:**
- Produces: `run_session(*, ..., provider: str = "anthropic") -> SessionResult` — looks up `registry.get_provider(provider)` and delegates.

- [ ] **Step 1: Write the failing test**

Add to `tests/unit/test_agent_runtime.py`:

```python
def test_run_session_routes_to_named_provider(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import asyncio

    from flosswing.agent import runtime as rt
    from flosswing.agent.providers import registry as reg
    from flosswing.agent.providers.base import SessionResult

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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_agent_runtime.py::test_run_session_routes_to_named_provider -v`
Expected: FAIL — `TypeError: run_session() got an unexpected keyword argument 'provider'`

- [ ] **Step 3: Update the facade**

Replace the Task-2 facade in `flosswing/agent/runtime.py` with registry resolution:

```python
from flosswing.agent.providers import registry


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
    )
```

Delete the `_ANTHROPIC = AnthropicSDKProvider()` module global and the direct-import of `AnthropicSDKProvider` from runtime (now reached via the registry). Update the Task-2 delegation test (`test_run_session_delegates_to_anthropic`) to monkeypatch `reg.get_provider` instead of `rt._ANTHROPIC`, or delete it in favor of the new routing test.

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/unit/test_agent_runtime.py -v`
Expected: PASS
Run: `mypy --strict flosswing/agent` and `ruff check flosswing/agent`

- [ ] **Step 5: Commit**

```bash
git add flosswing/agent/runtime.py tests/unit/test_agent_runtime.py
git commit -m "run_session resolves provider via registry (default anthropic) per design § Architecture"
```

---

### Task 6: Config — provider selection, delegated auth, derived allowlist

Add `Config.provider`, select it (flag → `FLOSSWING_PROVIDER` → default), reject unimplemented providers early, delegate auth + `auth_env` collection to the provider, and derive `AUTH_ENV_KEYS` from the Anthropic provider.

**Files:**
- Modify: `flosswing/config.py`
- Modify: `tests/unit/test_config.py`

**Interfaces:**
- Consumes: `registry.{get_provider, is_implemented}`, `AnthropicSDKProvider.auth_env_keys`, `flosswing.errors.ProviderNotImplementedError`.
- Produces: `Config.provider: str` (default `"anthropic"`); `resolve(*, ..., provider: str | None = None) -> Config`; module constants `DEFAULT_PROVIDER = "anthropic"`, `PROVIDER_ENV_VAR = "FLOSSWING_PROVIDER"`, and `AUTH_ENV_KEYS: frozenset[str]` (== `AnthropicSDKProvider.auth_env_keys`).

- [ ] **Step 1: Write the failing tests**

Add to `tests/unit/test_config.py` (and update `_strip_all_auth` to patch the new az-probe location — see Step 3):

```python
def test_default_provider_is_anthropic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _strip_all_auth(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.delenv("FLOSSWING_PROVIDER", raising=False)
    cfg = resolve(
        repo_root=tmp_path, model=None, recon_token_budget=None,
        hunt_token_budget=None, validate_token_budget=None,
        gapfill_token_budget=None,
    )
    assert cfg.provider == "anthropic"


def test_flag_beats_env_for_provider(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _strip_all_auth(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("FLOSSWING_PROVIDER", "ollama")
    # flag says anthropic -> wins; resolve succeeds
    cfg = resolve(
        repo_root=tmp_path, model=None, recon_token_budget=None,
        hunt_token_budget=None, validate_token_budget=None,
        gapfill_token_budget=None, provider="anthropic",
    )
    assert cfg.provider == "anthropic"


def test_env_selects_provider_when_no_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _strip_all_auth(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("FLOSSWING_PROVIDER", "ollama")
    with pytest.raises(ProviderNotImplementedError):
        resolve(
            repo_root=tmp_path, model=None, recon_token_budget=None,
            hunt_token_budget=None, validate_token_budget=None,
            gapfill_token_budget=None,
        )


def test_unknown_provider_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _strip_all_auth(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    with pytest.raises(UnknownProviderError):
        resolve(
            repo_root=tmp_path, model=None, recon_token_budget=None,
            hunt_token_budget=None, validate_token_budget=None,
            gapfill_token_budget=None, provider="gpt5",
        )


def test_auth_env_keys_match_anthropic_provider() -> None:
    from flosswing.agent.providers.anthropic_sdk import AnthropicSDKProvider

    assert cfg_mod.AUTH_ENV_KEYS == AnthropicSDKProvider.auth_env_keys
    assert "FLOSSWING_PROVIDER" not in cfg_mod.AUTH_ENV_KEYS
```

Add imports to the test module: `from flosswing.errors import ProviderNotImplementedError, UnknownProviderError`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/unit/test_config.py -v`
Expected: FAIL — `resolve()` has no `provider` kwarg / `Config` has no `provider` attribute.

- [ ] **Step 3: Rewrite the auth/provider portion of `config.py`**

1. Delete the moved auth knowledge from `config.py`: `_DIRECT_KEYS`, `_FOUNDRY_ROUTING_KEYS`, `_FOUNDRY_API_KEY`, `_ENTRA_SP_KEYS`, `_FOUNDRY_MODEL_KEYS`, the literal `AUTH_ENV_KEYS`, `_collect_present`, and `_has_az_session` (all now in `anthropic_sdk.py`).
2. Add near the top:

```python
from flosswing.agent.providers import registry
from flosswing.agent.providers.anthropic_sdk import AnthropicSDKProvider
from flosswing.errors import ProviderNotImplementedError

DEFAULT_PROVIDER: str = "anthropic"
PROVIDER_ENV_VAR: str = "FLOSSWING_PROVIDER"

# The default `.env` auto-load (flosswing/cli.py) is restricted to this
# allowlist. Derived from the Anthropic provider's declared keys so a future
# real provider extends it just by declaring auth_env_keys. FLOSSWING_PROVIDER
# is intentionally NOT here: provider selection is not a credential and must
# not be settable by an auto-loaded .env.
AUTH_ENV_KEYS: frozenset[str] = AnthropicSDKProvider.auth_env_keys
```

> Remove the old `from flosswing.errors import AuthCredentialMissingError` import — `config.resolve` no longer raises it (the provider's `validate_auth` does). `UnknownProviderError` is raised inside `registry.get_provider` and simply propagates, so `config.py` does not import it either. `_has_az_session` references in `config.py` are gone.

3. Add `provider: str = DEFAULT_PROVIDER` to the `Config` dataclass (in the defaulted-fields region, e.g. directly after `auth_env`).
4. Add `provider: str | None = None` to `resolve(...)` signature.
5. Replace the inline auth block (current lines 171–209) with provider resolution + delegation:

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

6. Pass `provider=provider_name` into the returned `Config(...)`.

- [ ] **Step 4: Update `_strip_all_auth` az-probe patch target**

In `tests/unit/test_config.py`, change the az-probe patch from `cfg_mod._has_az_session` to the provider module:

```python
def _strip_all_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    for k in _ALL_AUTH_ENV:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.delenv("FLOSSWING_PROVIDER", raising=False)
    from flosswing.agent.providers import anthropic_sdk
    monkeypatch.setattr(anthropic_sdk, "_has_az_session", lambda: False)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/unit/test_config.py tests/unit/test_providers_anthropic.py -v`
Expected: PASS (existing auth-mode tests still pass — the logic moved, not changed).
Run: `mypy --strict flosswing/config.py` and `ruff check flosswing/config.py`

- [ ] **Step 6: Commit**

```bash
git add flosswing/config.py tests/unit/test_config.py
git commit -m "Config: provider selection + delegated auth + derived AUTH_ENV_KEYS per design § Config & selection"
```

---

### Task 7: Wire `--provider` through CLI, stages, and eval

Expose the flag and thread `cfg.provider` into every `run_session` call.

**Files:**
- Modify: `flosswing/cli.py` (add `--provider` option to `scan`; pass to `resolve`)
- Modify: `flosswing/eval/runner.py` (pass `provider=None` to `resolve` for parity)
- Modify: `flosswing/stages/recon.py:107`, `flosswing/stages/hunt.py:350`, `flosswing/stages/validate.py:492`, `flosswing/stages/gapfill.py:410`, `flosswing/stages/dedupe.py:631`, `flosswing/stages/trace.py:515` (add `provider=cfg.provider`)
- Modify: `tests/unit/test_cli.py` (add a `--provider` test; create if absent)

**Interfaces:**
- Consumes: `Config.provider`, `resolve(provider=...)`.
- Produces: `flosswing scan --provider NAME`; each stage's `run_session(...)` call carries `provider=cfg.provider`.

- [ ] **Step 1: Write the failing test**

Add to `tests/unit/test_cli.py` (uses Click's `CliRunner`; mirror existing CLI-test style in the repo):

```python
def test_scan_rejects_unimplemented_provider(monkeypatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    from click.testing import CliRunner

    from flosswing.cli import cli

    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    runner = CliRunner()
    result = runner.invoke(
        cli, ["scan", str(tmp_path), "--provider", "ollama"]
    )
    assert result.exit_code == 2
    assert "not yet implemented" in result.output
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_cli.py::test_scan_rejects_unimplemented_provider -v`
Expected: FAIL — `--provider` is not a known option (Click exits 2 with "no such option", but the message assertion fails).

- [ ] **Step 3: Add the `--provider` option to `scan`**

In `flosswing/cli.py`, add an option decorator alongside `--model` (after the `--model` block, before `--recon-token-budget`):

```python
@click.option(
    "--provider",
    default=None,
    help="Model provider backend (default anthropic). Others are reserved/unimplemented.",
)
```

Add `provider: str | None,` to the `scan(...)` signature (next to `model: str | None,`) and pass it into the `fcfg.resolve(...)` call:

```python
        cfg = fcfg.resolve(
            repo_root=Path(path),
            model=model,
            provider=provider,
            recon_token_budget=recon_token_budget,
            ...
        )
```

(The existing `except FlosswingError` handler already maps `ProviderNotImplementedError` / `UnknownProviderError` to `echo(e.message)` + `exit(2)`.)

- [ ] **Step 4: Thread `provider=cfg.provider` into the six stages**

In each of the six stage files, add `provider=cfg.provider,` to the `run_session(...)` keyword call (alongside `model=cfg.model`):

- `flosswing/stages/recon.py` (the `run_session` at ~line 107)
- `flosswing/stages/hunt.py` (~line 350)
- `flosswing/stages/validate.py` (~line 492)
- `flosswing/stages/gapfill.py` (~line 410)
- `flosswing/stages/dedupe.py` (~line 631)
- `flosswing/stages/trace.py` (~line 515)

Example (recon):

```python
    result = await run_session(
        model=cfg.model,
        provider=cfg.provider,
        system_prompt=system_prompt,
        tools=tools,
        user_prompt=_USER_PROMPT,
        token_budget=cfg.recon_token_budget,
        auth_env=cfg.auth_env,
        run_id=run_id,
        stage="recon",
    )
```

- [ ] **Step 5: Add `provider` to the eval resolve call**

In `flosswing/eval/runner.py` `run_and_score`, add `provider=None,` to the `fcfg.resolve(...)` call (keeps eval on the default backend):

```python
    cfg = fcfg.resolve(
        repo_root=repo_root, model=None, provider=None,
        recon_token_budget=None, hunt_token_budget=None,
        ...
    )
```

- [ ] **Step 6: Run the full unit suite + typecheck + lint**

Run: `pytest tests/unit -q`
Expected: PASS (all). The existing stage tests pass unchanged because they mock `run_session` with `**kwargs`.
Run: `mypy --strict flosswing` and `ruff check flosswing tests`

- [ ] **Step 7: Commit**

```bash
git add flosswing/cli.py flosswing/eval/runner.py flosswing/stages/*.py tests/unit/test_cli.py
git commit -m "Wire --provider through CLI, stages, and eval per design § Config & selection"
```

---

### Task 8: ARCHITECTURE.md edits (OPERATOR-APPROVAL-GATED)

`ARCHITECTURE.md` is operator-curated. **Do not commit this task until the operator approves the diff.** Present the exact diff in chat first.

**Files:**
- Modify: `ARCHITECTURE.md` (three edits)

- [ ] **Step 1: Present the proposed diff in chat and wait for approval**

Proposed edits:

1. **Remove the v2 line** `- Non-Anthropic model providers` from the "Deferred to v2" list (`:529`).
2. **Add a "Model providers" subsection** under § *Agent runtime* (after the `Model defaults` block, before § *Tool contracts*):

   > **Model providers.** Model invocation goes through a `Provider` seam at
   > `flosswing/agent/providers/` (`base.py` Protocol + shared `SessionResult`/
   > `_classify`, `anthropic_sdk.py` default backend, `registry.py`). `run_session`
   > resolves the provider selected by `--provider` / `FLOSSWING_PROVIDER` (default
   > `anthropic`). `ollama`, `openai`, `bedrock`, and `cloudflare` are registered as
   > unimplemented stubs — selecting one fails early at config resolution. Adding a
   > real backend means implementing the `Provider` protocol and registering it; no
   > pipeline stage changes.
3. **Update the v1 scope summary**: change the `BYO ANTHROPIC_API_KEY` bullet to note the provider abstraction ships with Anthropic as the sole working backend, e.g. `- Model-provider abstraction (Anthropic Agent SDK is the only working backend; BYO ANTHROPIC_API_KEY)`.

- [ ] **Step 2: After approval, apply the edits and verify the repo is consistent**

Run: `grep -n "Non-Anthropic model providers" ARCHITECTURE.md` → expect no match.
Run: `pytest tests/unit -q` → PASS (doc-only change, sanity check).

- [ ] **Step 3: Commit (only after approval)**

```bash
git add ARCHITECTURE.md
git commit -m "ARCHITECTURE: promote model-provider abstraction to v1 per operator decision 2026-06-17"
```

---

## Final verification

- [ ] Run `pytest tests/unit -q` — all green.
- [ ] Run `mypy --strict flosswing` — clean.
- [ ] Run `ruff check flosswing tests` — clean.
- [ ] Manual smoke: `flosswing scan --help` shows `--provider`; `flosswing scan <path> --provider ollama` (with `ANTHROPIC_API_KEY` set) exits 2 with "not yet implemented"; a normal `--provider anthropic` (or no flag) resolves as before.
- [ ] Confirm no credential value appears in any new log/error path (provider errors carry only provider names, never env values).

## Self-review notes (coverage vs. spec)

- Seam at `run_session` → Tasks 1–5. Registry + stubs → Task 4. Early stub rejection → Task 6. Flag→env→default selection + `FLOSSWING_PROVIDER` exclusion from `AUTH_ENV_KEYS` → Task 6. `SessionResult` re-export → Task 1. `auth_env_keys` rename → Task 2. CLI/stages/eval wiring → Task 7. Doc edits (gated) → Task 8. Errors → Task 3. No schema/migration, no frozen-contract change — verified, no task needed.
