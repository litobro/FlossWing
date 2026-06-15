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

"""Sandbox base module — Protocol, dataclasses, frozen-contract models.

Per docs/tool-contracts.md § Scope: execution and
docs/specs/2026-06-02-v0.4-sandbox-design.md § Component responsibilities.

The Pydantic models on the frozen-contract boundary (SourceFile,
CompileAndRunInput, ExecResult, CompileAndRunOutput) are copied
verbatim from the contract. Any change here is a contract break.

SandboxInvocation is FlossWing-internal: it bundles the contract input
with the resolved invocation_id, run_id, attack_class, and the
already-validated env/timeout/network fields.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Literal, Protocol, runtime_checkable

from pydantic import BaseModel

# -----------------------------------------------------------------------------
# Frozen-contract models  (copied verbatim from docs/tool-contracts.md
# § Scope: execution — do NOT change without operator approval)
# -----------------------------------------------------------------------------


class SourceFile(BaseModel):
    """One source file to materialize inside /scratch/src.

    relative_path is POSIX, within /scratch, e.g. "exploit.c".
    Path segments containing ".." raise PathEscapesScratchError
    (mapped to input_validation_failed at the tool layer per design
    decision #6).
    """

    relative_path: str
    content: str


class CompileAndRunInput(BaseModel):
    """Input to the compile_and_run tool — see docs/tool-contracts.md."""

    language: Literal[
        "c",
        "cpp",
        "rust",
        "go",
        "python",
        "javascript",
        "typescript",
        "java",
    ]
    files: list[SourceFile]
    build_command: str | None = None
    run_command: str
    stdin: str | None = None
    args: list[str] = []
    env: dict[str, str] = {}  # filtered against an allowlist
    timeout_seconds: int = 60  # hard cap 300
    network: bool = False
    attack_class: str  # for sandbox policy lookup and audit


class ExecResult(BaseModel):
    """One executed step's structured result — build OR run."""

    exit_code: int  # -1 if killed by signal/timeout
    signal: str | None
    stdout: str
    stdout_truncated: bool
    stderr: str
    stderr_truncated: bool
    duration_ms: int
    oom_killed: bool
    timed_out: bool
    network_used: bool
    sandbox_backend: Literal["docker", "firejail"]


class CompileAndRunOutput(BaseModel):
    """Full compile_and_run output: optional build step + mandatory run step."""

    build: ExecResult | None
    run: ExecResult
    scratch_path: str  # host path; for record_finding to reference


# -----------------------------------------------------------------------------
# FlossWing-internal types
# -----------------------------------------------------------------------------


class SandboxBackend(StrEnum):
    """Enum mirror of the ExecResult.sandbox_backend literal."""

    DOCKER = "docker"
    FIREJAIL = "firejail"


class SandboxInvocation(BaseModel):
    """Internal carrier: contract input + resolved run/invocation metadata.

    The tool wrapper builds this once per call, after validating
    timeout / language / network policy / env allowlist. Backends
    receive an invocation that has already been vetted.
    """

    invocation_id: str  # ULID; matches scratch dir name
    run_id: str
    attack_class: str
    language: str
    files: list[SourceFile]
    build_command: str | None
    run_command: str
    stdin: str | None
    args: list[str]
    env: dict[str, str]
    timeout_seconds: int
    network: bool


@runtime_checkable
class Sandbox(Protocol):
    """The Protocol every backend implements.

    Intentionally does NOT include cleanup in v0.4 — scratch dirs
    persist until the operator removes them. A `flosswing prune`
    subcommand is v2 (per design decision in the spec § Scope).
    """

    backend_name: str  # "docker" | "firejail"

    async def is_available(self) -> bool: ...

    async def execute(
        self,
        invocation: SandboxInvocation,
        repo_root: Path,
    ) -> CompileAndRunOutput: ...


__all__ = [
    "CompileAndRunInput",
    "CompileAndRunOutput",
    "ExecResult",
    "Sandbox",
    "SandboxBackend",
    "SandboxInvocation",
    "SourceFile",
]
