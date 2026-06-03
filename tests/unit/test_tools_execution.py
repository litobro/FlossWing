"""tools/execution.compile_and_run — frozen-contract wrapper.

Per docs/tool-contracts.md § Scope: execution and
docs/specs/2026-06-02-v0.4-sandbox-design.md § Component responsibilities
tools/execution.py. All sandbox backends are mocked; this layer is
validation + routing only.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from flosswing.errors import (
    LanguageNotSupportedError,
    NetworkNotPermittedError,
    ResourceLimitExceededError,
)
from flosswing.sandbox.base import (
    CompileAndRunOutput,
    ExecResult,
    SourceFile,
)
from flosswing.tools.execution import CompileAndRunInput, compile_and_run


def _ok_run() -> ExecResult:
    return ExecResult(
        exit_code=0,
        signal=None,
        stdout="hi\n",
        stdout_truncated=False,
        stderr="",
        stderr_truncated=False,
        duration_ms=42,
        oom_killed=False,
        timed_out=False,
        network_used=False,
        sandbox_backend="docker",
    )


def _ok_output(scratch: str) -> CompileAndRunOutput:
    return CompileAndRunOutput(build=None, run=_ok_run(), scratch_path=scratch)


def _good_input(**overrides: object) -> CompileAndRunInput:
    base: dict[str, object] = dict(
        language="python",
        files=[SourceFile(relative_path="x.py", content="print(1)")],
        run_command="python x.py",
        attack_class="command_injection",
    )
    base.update(overrides)
    return CompileAndRunInput(**base)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_compile_and_run_happy_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = MagicMock()
    backend.backend_name = "docker"
    backend.execute = AsyncMock(return_value=_ok_output(str(tmp_path)))
    monkeypatch.setattr(
        "flosswing.tools.execution.select_backend",
        AsyncMock(return_value=backend),
    )
    out = await compile_and_run(
        _good_input(), run_id="01RUN", repo_root=tmp_path
    )
    assert out.run.exit_code == 0
    assert out.scratch_path == str(tmp_path)
    backend.execute.assert_awaited_once()


@pytest.mark.asyncio
async def test_compile_and_run_rejects_timeout_above_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(ResourceLimitExceededError):
        await compile_and_run(
            _good_input(timeout_seconds=400),
            run_id="01RUN",
            repo_root=tmp_path,
        )


@pytest.mark.asyncio
async def test_compile_and_run_rejects_timeout_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(ResourceLimitExceededError):
        await compile_and_run(
            _good_input(timeout_seconds=0),
            run_id="01RUN",
            repo_root=tmp_path,
        )


@pytest.mark.asyncio
async def test_compile_and_run_rejects_unknown_language(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Pydantic catches this at model construction; we test the bypass
    # path via model_construct.
    bad = CompileAndRunInput.model_construct(
        language="scheme",  # not in the literal
        files=[SourceFile(relative_path="x.scm", content="")],
        run_command="scheme x.scm",
        attack_class="command_injection",
        timeout_seconds=60,
        network=False,
        env={},
        args=[],
        build_command=None,
        stdin=None,
    )
    with pytest.raises(LanguageNotSupportedError):
        await compile_and_run(bad, run_id="01RUN", repo_root=tmp_path)


@pytest.mark.asyncio
async def test_compile_and_run_network_true_for_class_not_permitting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(NetworkNotPermittedError):
        await compile_and_run(
            _good_input(network=True),
            run_id="01RUN",
            repo_root=tmp_path,
        )


@pytest.mark.asyncio
async def test_compile_and_run_network_true_for_ssrf_passes_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = MagicMock()
    backend.backend_name = "docker"
    backend.execute = AsyncMock(return_value=_ok_output(str(tmp_path)))
    monkeypatch.setattr(
        "flosswing.tools.execution.select_backend",
        AsyncMock(return_value=backend),
    )
    out = await compile_and_run(
        _good_input(attack_class="ssrf", network=True),
        run_id="01RUN",
        repo_root=tmp_path,
    )
    assert out.run.exit_code == 0
    backend.execute.assert_awaited_once()


@pytest.mark.asyncio
async def test_compile_and_run_filters_env_before_backend(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = MagicMock()
    backend.backend_name = "docker"
    backend.execute = AsyncMock(return_value=_ok_output(str(tmp_path)))
    monkeypatch.setattr(
        "flosswing.tools.execution.select_backend",
        AsyncMock(return_value=backend),
    )
    await compile_and_run(
        _good_input(
            env={"ANTHROPIC_API_KEY": "sk-secret", "LANG": "C.UTF-8"},
        ),
        run_id="01RUN",
        repo_root=tmp_path,
    )
    inv = backend.execute.call_args[0][0]
    assert "ANTHROPIC_API_KEY" not in inv.env
    assert inv.env.get("LANG") == "C.UTF-8"


@pytest.mark.asyncio
async def test_compile_and_run_generates_ulid_invocation_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = MagicMock()
    backend.backend_name = "docker"
    backend.execute = AsyncMock(return_value=_ok_output(str(tmp_path)))
    monkeypatch.setattr(
        "flosswing.tools.execution.select_backend",
        AsyncMock(return_value=backend),
    )
    await compile_and_run(
        _good_input(), run_id="01RUN", repo_root=tmp_path
    )
    inv = backend.execute.call_args[0][0]
    assert isinstance(inv.invocation_id, str)
    assert len(inv.invocation_id) == 26  # ULID canonical length


@pytest.mark.asyncio
async def test_compile_and_run_passes_repo_root_to_backend(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = MagicMock()
    backend.backend_name = "docker"
    backend.execute = AsyncMock(return_value=_ok_output(str(tmp_path)))
    monkeypatch.setattr(
        "flosswing.tools.execution.select_backend",
        AsyncMock(return_value=backend),
    )
    await compile_and_run(
        _good_input(), run_id="01RUN", repo_root=tmp_path
    )
    _, kwargs = backend.execute.call_args
    assert kwargs.get("repo_root") == tmp_path
