"""DockerSandbox stub — full implementation lands in Task 7."""

from __future__ import annotations

from pathlib import Path

from flosswing.sandbox.base import (
    CompileAndRunOutput,
    SandboxInvocation,
)


class DockerSandbox:
    """Docker-backed sandbox. See docs/specs/2026-06-02-v0.4-sandbox-design.md."""

    backend_name: str = "docker"

    async def is_available(self) -> bool:
        # Replaced with docker.from_env().ping() in Task 7.
        return False

    async def execute(
        self,
        invocation: SandboxInvocation,
        repo_root: Path,
    ) -> CompileAndRunOutput:
        raise NotImplementedError("Task 7 implements DockerSandbox.execute")


__all__ = ["DockerSandbox"]
