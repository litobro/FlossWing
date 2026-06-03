"""flosswing.sandbox — sandbox protocol, backends, selection.

Public surface re-exported here so callers can write:

    from flosswing.sandbox import select_backend, Sandbox, CompileAndRunInput

Per docs/specs/2026-06-02-v0.4-sandbox-design.md § Component
responsibilities sandbox/__init__.py.
"""

from __future__ import annotations

from flosswing.sandbox.base import (
    CompileAndRunInput,
    CompileAndRunOutput,
    ExecResult,
    Sandbox,
    SandboxBackend,
    SandboxInvocation,
    SourceFile,
)
from flosswing.sandbox.select import select_backend

__all__ = [
    "CompileAndRunInput",
    "CompileAndRunOutput",
    "ExecResult",
    "Sandbox",
    "SandboxBackend",
    "SandboxInvocation",
    "SourceFile",
    "select_backend",
]
