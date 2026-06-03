"""FirejailSandbox: argv shape and result-mapping. No real firejail invocation.

Per docs/specs/2026-06-02-v0.4-sandbox-design.md § Component
responsibilities sandbox/firejail.py.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from flosswing.sandbox.base import SandboxInvocation, SourceFile
from flosswing.sandbox.firejail import FirejailSandbox


def _inv(tmp_path: Path) -> tuple[SandboxInvocation, Path]:
    inv = SandboxInvocation(
        invocation_id="01FIRE",
        run_id="01RUN",
        attack_class="command_injection",
        language="python",
        files=[SourceFile(relative_path="exploit.py", content="print(1)")],
        build_command=None,
        run_command="python3 exploit.py",
        stdin=None,
        args=[],
        env={},
        timeout_seconds=60,
        network=False,
    )
    return inv, tmp_path


@pytest.mark.asyncio
async def test_firejail_is_available_via_version_exit_zero(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_proc = MagicMock()
    fake_proc.returncode = 0
    fake_proc.stdout = "firejail version 0.9.72\n"
    with (
        patch(
            "flosswing.sandbox.firejail.shutil.which",
            return_value="/usr/bin/firejail",
        ),
        patch(
            "flosswing.sandbox.firejail.subprocess.run", return_value=fake_proc
        ),
    ):
        sb = FirejailSandbox()
        assert await sb.is_available() is True


@pytest.mark.asyncio
async def test_firejail_is_available_returns_false_when_not_installed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with (
        patch(
            "flosswing.sandbox.firejail.shutil.which",
            return_value=None,
        ),
        patch(
            "flosswing.sandbox.firejail.subprocess.run",
            side_effect=FileNotFoundError("firejail"),
        ),
    ):
        sb = FirejailSandbox()
        assert await sb.is_available() is False


@pytest.mark.asyncio
async def test_firejail_execute_passes_arch_flags_in_argv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    inv, repo = _inv(tmp_path)
    fake_proc = MagicMock()
    fake_proc.returncode = 0
    fake_proc.stdout = b""
    fake_proc.stderr = b""
    captured: dict[str, list[str]] = {}

    def fake_run(argv: list[str], **kw: object) -> MagicMock:
        captured["argv"] = argv
        return fake_proc

    with (
        patch(
            "flosswing.sandbox.firejail.shutil.which",
            return_value="/usr/bin/firejail",
        ),
        patch(
            "flosswing.sandbox.firejail.subprocess.run",
            side_effect=fake_run,
        ),
    ):
        sb = FirejailSandbox()
        await sb.execute(inv, repo_root=repo)

    argv = captured["argv"]
    assert argv[0].endswith("firejail")
    # Mandatory hardening flags.
    assert "--net=none" in argv
    assert "--quiet" in argv
    assert "--noprofile" in argv
    assert "--private-tmp" in argv
    assert "--caps.drop=all" in argv
    # Timeout — firejail's own enforcement (belt-and-suspenders).
    assert any(a.startswith("--timeout=") for a in argv)
    # Resource limits.
    assert any(a.startswith("--rlimit-as=") for a in argv)
    assert any(a.startswith("--rlimit-nproc=") for a in argv)


@pytest.mark.asyncio
async def test_firejail_execute_writes_meta_and_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    inv, repo = _inv(tmp_path)
    fake_proc = MagicMock()
    fake_proc.returncode = 0
    fake_proc.stdout = b"hi\n"
    fake_proc.stderr = b""
    with (
        patch(
            "flosswing.sandbox.firejail.shutil.which",
            return_value="/usr/bin/firejail",
        ),
        patch(
            "flosswing.sandbox.firejail.subprocess.run",
            return_value=fake_proc,
        ),
    ):
        sb = FirejailSandbox()
        out = await sb.execute(inv, repo_root=repo)
    base = Path(out.scratch_path)
    assert (base / "meta.json").exists()
    assert (base / "result.json").exists()
    assert (base / "src" / "exploit.py").read_text() == "print(1)"


@pytest.mark.asyncio
async def test_firejail_execute_timeout_maps_to_timed_out_true(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    inv, repo = _inv(tmp_path)
    with (
        patch(
            "flosswing.sandbox.firejail.shutil.which",
            return_value="/usr/bin/firejail",
        ),
        patch(
            "flosswing.sandbox.firejail.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="firejail", timeout=60),
        ),
    ):
        sb = FirejailSandbox()
        out = await sb.execute(inv, repo_root=repo)
    assert out.run.timed_out is True
    assert out.run.exit_code == -1
    assert out.run.signal == "SIGKILL"


@pytest.mark.asyncio
async def test_firejail_execute_truncates_stdout_at_10mb(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    inv, repo = _inv(tmp_path)
    big = b"y" * (11 * 1024 * 1024)
    fake_proc = MagicMock()
    fake_proc.returncode = 0
    fake_proc.stdout = big
    fake_proc.stderr = b""
    with (
        patch(
            "flosswing.sandbox.firejail.shutil.which",
            return_value="/usr/bin/firejail",
        ),
        patch(
            "flosswing.sandbox.firejail.subprocess.run",
            return_value=fake_proc,
        ),
    ):
        sb = FirejailSandbox()
        out = await sb.execute(inv, repo_root=repo)
    assert out.run.stdout_truncated is True
    assert len(out.run.stdout.encode("utf-8")) <= 10 * 1024 * 1024


@pytest.mark.asyncio
async def test_firejail_execute_path_escape_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    _, repo = _inv(tmp_path)
    bad = SandboxInvocation(
        invocation_id="01F",
        run_id="01R",
        attack_class="command_injection",
        language="python",
        files=[SourceFile(relative_path="../escape.py", content="x")],
        build_command=None,
        run_command="true",
        stdin=None,
        args=[],
        env={},
        timeout_seconds=10,
        network=False,
    )
    fake_proc = MagicMock()
    fake_proc.returncode = 0
    fake_proc.stdout = b""
    fake_proc.stderr = b""
    with (
        patch(
            "flosswing.sandbox.firejail.shutil.which",
            return_value="/usr/bin/firejail",
        ),
        patch(
            "flosswing.sandbox.firejail.subprocess.run",
            return_value=fake_proc,
        ),
    ):
        sb = FirejailSandbox()
        with pytest.raises(Exception) as exc:
            await sb.execute(bad, repo_root=repo)
    assert getattr(exc.value, "code", None) == "input_validation_failed"
