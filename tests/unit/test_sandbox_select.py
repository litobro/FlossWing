"""sandbox.select_backend: Docker -> Firejail -> sandbox_unavailable.

Per docs/specs/2026-06-02-v0.4-sandbox-design.md § Component
responsibilities sandbox/__init__.py and § Testing strategy
test_sandbox_select.py. Tests stub DockerSandbox.is_available and
FirejailSandbox.is_available — never touches real docker or firejail.
"""

from __future__ import annotations

import pytest

from flosswing.errors import SandboxUnavailableError
from flosswing.sandbox import select as sel
from flosswing.sandbox.docker import DockerSandbox
from flosswing.sandbox.firejail import FirejailSandbox


@pytest.fixture(autouse=True)
def _reset_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sel, "_cached_backend", None, raising=False)


@pytest.mark.asyncio
async def test_select_returns_docker_when_available(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def yes(self: object) -> bool:
        return True

    async def no(self: object) -> bool:
        return False

    monkeypatch.setattr(DockerSandbox, "is_available", yes)
    monkeypatch.setattr(FirejailSandbox, "is_available", no)
    backend = await sel.select_backend()
    assert isinstance(backend, DockerSandbox)
    assert backend.backend_name == "docker"


@pytest.mark.asyncio
async def test_select_falls_back_to_firejail_when_docker_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def no(self: object) -> bool:
        return False

    async def yes(self: object) -> bool:
        return True

    monkeypatch.setattr(DockerSandbox, "is_available", no)
    monkeypatch.setattr(FirejailSandbox, "is_available", yes)
    backend = await sel.select_backend()
    assert isinstance(backend, FirejailSandbox)
    assert backend.backend_name == "firejail"


@pytest.mark.asyncio
async def test_select_raises_when_neither_available(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def no(self: object) -> bool:
        return False

    monkeypatch.setattr(DockerSandbox, "is_available", no)
    monkeypatch.setattr(FirejailSandbox, "is_available", no)
    with pytest.raises(SandboxUnavailableError) as exc:
        await sel.select_backend()
    assert exc.value.code == "sandbox_unavailable"
    assert exc.value.retryable is False


@pytest.mark.asyncio
async def test_select_preferred_docker_does_not_fall_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """preferred='docker' is strict — no Firejail fallback even if available."""

    async def no(self: object) -> bool:
        return False

    async def yes(self: object) -> bool:
        return True

    monkeypatch.setattr(DockerSandbox, "is_available", no)
    monkeypatch.setattr(FirejailSandbox, "is_available", yes)
    with pytest.raises(SandboxUnavailableError):
        await sel.select_backend(preferred="docker")


@pytest.mark.asyncio
async def test_select_preferred_firejail_does_not_use_docker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """preferred='firejail' is strict — uses Firejail even if Docker available."""

    async def yes(self: object) -> bool:
        return True

    monkeypatch.setattr(DockerSandbox, "is_available", yes)
    monkeypatch.setattr(FirejailSandbox, "is_available", yes)
    backend = await sel.select_backend(preferred="firejail")
    assert isinstance(backend, FirejailSandbox)


@pytest.mark.asyncio
async def test_select_caches_result_across_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Second call must not re-probe."""
    calls = {"docker": 0, "firejail": 0}

    async def docker_probe(self: object) -> bool:
        calls["docker"] += 1
        return True

    async def firejail_probe(self: object) -> bool:
        calls["firejail"] += 1
        return False

    monkeypatch.setattr(DockerSandbox, "is_available", docker_probe)
    monkeypatch.setattr(FirejailSandbox, "is_available", firejail_probe)
    a = await sel.select_backend()
    b = await sel.select_backend()
    assert a is b  # same instance
    assert calls["docker"] == 1
    assert calls["firejail"] == 0


@pytest.mark.asyncio
async def test_select_preferred_does_not_pollute_cache(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """preferred='firejail' caches the firejail instance; later None call honors cache."""

    async def yes(self: object) -> bool:
        return True

    monkeypatch.setattr(DockerSandbox, "is_available", yes)
    monkeypatch.setattr(FirejailSandbox, "is_available", yes)
    a = await sel.select_backend(preferred="firejail")
    b = await sel.select_backend()  # auto: would normally pick Docker
    assert a is b  # cache wins
    assert isinstance(b, FirejailSandbox)
