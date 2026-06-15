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
