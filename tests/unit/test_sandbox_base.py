"""sandbox/base.py — Protocol shape and Pydantic-model wire compat.

Models on the frozen-contract boundary (SourceFile, CompileAndRunInput,
ExecResult, CompileAndRunOutput) MUST match docs/tool-contracts.md
§ Scope: execution exactly. These tests pin the field names and types
so any future drift fails loudly.
"""

from __future__ import annotations

from typing import get_args

import pytest
from pydantic import ValidationError

from flosswing.sandbox.base import (
    CompileAndRunInput,
    CompileAndRunOutput,
    ExecResult,
    Sandbox,
    SandboxBackend,
    SandboxInvocation,
    SourceFile,
)


def test_source_file_minimal() -> None:
    sf = SourceFile(relative_path="exploit.py", content="print('x')")
    assert sf.relative_path == "exploit.py"
    assert sf.content == "print('x')"


def test_source_file_requires_both_fields() -> None:
    with pytest.raises(ValidationError):
        SourceFile()  # type: ignore[call-arg]


def test_compile_and_run_input_field_names_match_contract() -> None:
    """Wire compatibility: any rename or drop here is a contract break."""
    fields = set(CompileAndRunInput.model_fields.keys())
    expected = {
        "language",
        "files",
        "build_command",
        "run_command",
        "stdin",
        "args",
        "env",
        "timeout_seconds",
        "network",
        "attack_class",
    }
    assert fields == expected, f"contract drift: {fields ^ expected}"


def test_language_literal_has_eight_values() -> None:
    """Per docs/tool-contracts.md § Scope: execution: 8 languages exactly."""
    ann = CompileAndRunInput.model_fields["language"].annotation
    values = set(get_args(ann))
    assert values == {
        "c",
        "cpp",
        "rust",
        "go",
        "python",
        "javascript",
        "typescript",
        "java",
    }


def test_compile_and_run_input_defaults() -> None:
    inp = CompileAndRunInput(
        language="python",
        files=[SourceFile(relative_path="x.py", content="")],
        run_command="python x.py",
        attack_class="command_injection",
    )
    assert inp.build_command is None
    assert inp.stdin is None
    assert inp.args == []
    assert inp.env == {}
    assert inp.timeout_seconds == 60
    assert inp.network is False


def test_exec_result_field_names_match_contract() -> None:
    fields = set(ExecResult.model_fields.keys())
    expected = {
        "exit_code",
        "signal",
        "stdout",
        "stdout_truncated",
        "stderr",
        "stderr_truncated",
        "duration_ms",
        "oom_killed",
        "timed_out",
        "network_used",
        "sandbox_backend",
    }
    assert fields == expected, f"contract drift: {fields ^ expected}"


def test_exec_result_sandbox_backend_literal() -> None:
    ann = ExecResult.model_fields["sandbox_backend"].annotation
    assert set(get_args(ann)) == {"docker", "firejail"}


def test_compile_and_run_output_field_names_match_contract() -> None:
    fields = set(CompileAndRunOutput.model_fields.keys())
    assert fields == {"build", "run", "scratch_path"}


def test_sandbox_backend_enum_values() -> None:
    assert SandboxBackend.DOCKER.value == "docker"
    assert SandboxBackend.FIREJAIL.value == "firejail"


def test_sandbox_invocation_minimal() -> None:
    inv = SandboxInvocation(
        invocation_id="01ABC",
        run_id="01XYZ",
        attack_class="command_injection",
        language="python",
        files=[SourceFile(relative_path="x.py", content="")],
        build_command=None,
        run_command="python x.py",
        stdin=None,
        args=[],
        env={},
        timeout_seconds=60,
        network=False,
    )
    assert inv.invocation_id == "01ABC"
    assert inv.run_id == "01XYZ"


def test_sandbox_protocol_runtime_check_smoke() -> None:
    """Protocol smoke test: a class that defines the attrs satisfies it."""

    class _Fake:
        backend_name = "docker"

        async def is_available(self) -> bool:
            return True

        async def execute(
            self, invocation: SandboxInvocation, repo_root: object
        ) -> CompileAndRunOutput:
            raise NotImplementedError

    fake: Sandbox = _Fake()  # noqa: F841  # structural check only
