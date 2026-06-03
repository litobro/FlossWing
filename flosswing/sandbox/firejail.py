"""FirejailSandbox stub — full implementation lands in Task 8."""

from __future__ import annotations

from pathlib import Path

from flosswing.sandbox.base import (
    CompileAndRunOutput,
    SandboxInvocation,
)


class FirejailSandbox:
    """Firejail-backed fallback sandbox."""

    backend_name: str = "firejail"

    async def is_available(self) -> bool:
        # Replaced with `firejail --version` exit-0 probe in Task 8.
        return False

    async def execute(
        self,
        invocation: SandboxInvocation,
        repo_root: Path,
    ) -> CompileAndRunOutput:
        raise NotImplementedError("Task 8 implements FirejailSandbox.execute")


__all__ = ["FirejailSandbox"]
