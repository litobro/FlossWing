"""Backend selection — Docker -> Firejail -> sandbox_unavailable.

Per docs/specs/2026-06-02-v0.4-sandbox-design.md § Component
responsibilities sandbox/__init__.py. Selection is cached for the
process lifetime — long Hunt / Validate runs do not re-probe.

Per design decision #2, Firejail availability is a plain
`firejail --version` exit-0 check. Caps-drop failures at run time
surface as a clear sandbox_unavailable from the first compile_and_run
invocation.
"""

from __future__ import annotations

from typing import Literal

from flosswing.errors import SandboxUnavailableError
from flosswing.sandbox.base import Sandbox
from flosswing.sandbox.docker import DockerSandbox
from flosswing.sandbox.firejail import FirejailSandbox

_cached_backend: Sandbox | None = None


async def select_backend(
    preferred: Literal["docker", "firejail", None] = None,
) -> Sandbox:
    """Return a Sandbox instance, honoring the preferred backend if any.

    preferred="docker"    -> DockerSandbox or SandboxUnavailableError
                             (does NOT fall back to Firejail)
    preferred="firejail"  -> FirejailSandbox or SandboxUnavailableError
    preferred=None (auto) -> Docker if available, else Firejail, else raise.
    """
    global _cached_backend
    if _cached_backend is not None:
        return _cached_backend

    if preferred == "docker":
        d = DockerSandbox()
        if await d.is_available():
            _cached_backend = d
            return d
        raise SandboxUnavailableError(
            "preferred='docker' but Docker is not available"
        )

    if preferred == "firejail":
        f = FirejailSandbox()
        if await f.is_available():
            _cached_backend = f
            return f
        raise SandboxUnavailableError(
            "preferred='firejail' but Firejail is not available"
        )

    # auto: Docker first
    d = DockerSandbox()
    if await d.is_available():
        _cached_backend = d
        return d
    f = FirejailSandbox()
    if await f.is_available():
        _cached_backend = f
        return f
    raise SandboxUnavailableError(
        "neither Docker nor Firejail is available — install one to enable "
        "compile_and_run"
    )


__all__ = ["select_backend"]
