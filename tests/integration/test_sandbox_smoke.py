"""Gated integration smoke test for compile_and_run.

Gated by FLOSSWING_INTEGRATION=1 AND FLOSSWING_SANDBOX_INTEGRATION=1
(so existing Recon/Hunt gated tests that only set the first env var
do NOT trigger this file on machines without Docker installed).

Per docs/specs/2026-06-02-v0.4-sandbox-design.md § Testing strategy:
runs the four PoCs from § Success criteria 3-6 against the real
Docker daemon (or Firejail if FLOSSWING_SANDBOX_BACKEND=firejail is
set).
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from flosswing.sandbox import policy
from flosswing.sandbox.base import (
    CompileAndRunInput,
    SourceFile,
)
from flosswing.tools.execution import compile_and_run

pytestmark = pytest.mark.skipif(
    os.environ.get("FLOSSWING_INTEGRATION") != "1"
    or os.environ.get("FLOSSWING_SANDBOX_INTEGRATION") != "1",
    reason=(
        "sandbox integration gated by both FLOSSWING_INTEGRATION=1 "
        "and FLOSSWING_SANDBOX_INTEGRATION=1"
    ),
)


@pytest.fixture()
def repo_root(tmp_path: Path) -> Path:
    """Tiny fake repo for the sandbox to mount read-only."""
    r = tmp_path / "repo"
    r.mkdir()
    (r / "README.md").write_text("test repo\n", encoding="utf-8")
    return r


@pytest.mark.asyncio
async def test_sandbox_happy_path_compiles_and_runs(repo_root: Path) -> None:
    """Per § Success criteria #3: a deliberate PoC runs to completion."""
    inp = CompileAndRunInput(
        language="python",
        files=[
            SourceFile(
                relative_path="hello.py",
                content="print('flosswing sandbox v0.4 ok')\n",
            )
        ],
        run_command="python hello.py",
        attack_class="command_injection",
        timeout_seconds=30,
    )
    out = await compile_and_run(
        inp, run_id="integ_happy", repo_root=repo_root
    )
    assert out.run.exit_code == 0, out.run.stderr
    assert out.run.duration_ms > 0
    assert out.run.network_used is False
    assert out.run.sandbox_backend in {"docker", "firejail"}
    assert "flosswing sandbox v0.4 ok" in out.run.stdout
    assert Path(out.scratch_path).exists()
    assert (Path(out.scratch_path) / "meta.json").exists()
    assert (Path(out.scratch_path) / "result.json").exists()


@pytest.mark.asyncio
async def test_sandbox_network_blocked(repo_root: Path) -> None:
    """Per § Success criteria #4: TCP attempt fails; network_used recorded."""
    poc = (
        "import socket\n"
        "s = socket.socket()\n"
        "s.settimeout(2)\n"
        "try:\n"
        "    s.connect(('1.1.1.1', 80))\n"
        "    print('CONNECTED (unexpected)')\n"
        "except Exception as e:\n"
        "    print('blocked:', e)\n"
        "    raise SystemExit(1)\n"
    )
    inp = CompileAndRunInput(
        language="python",
        files=[SourceFile(relative_path="net.py", content=poc)],
        run_command="python net.py",
        attack_class="command_injection",  # does not permit network
        timeout_seconds=15,
        network=False,
    )
    out = await compile_and_run(
        inp, run_id="integ_net", repo_root=repo_root
    )
    assert out.run.exit_code != 0
    assert out.run.network_used is True


@pytest.mark.asyncio
async def test_sandbox_timeout_kills_long_sleep(repo_root: Path) -> None:
    """Per § Success criteria #5: time.sleep(120) with timeout_seconds=2."""
    poc = "import time; time.sleep(120)\n"
    inp = CompileAndRunInput(
        language="python",
        files=[SourceFile(relative_path="sleeper.py", content=poc)],
        run_command="python sleeper.py",
        attack_class="command_injection",
        timeout_seconds=2,
    )
    out = await compile_and_run(
        inp, run_id="integ_timeout", repo_root=repo_root
    )
    assert out.run.timed_out is True
    assert out.run.exit_code == -1
    assert out.run.signal == "SIGKILL"
    # Wall-clock under ~5 seconds (operator-visible).
    assert out.run.duration_ms < 10_000


@pytest.mark.asyncio
async def test_sandbox_oom_killed_on_3gb_alloc(repo_root: Path) -> None:
    """Per § Success criteria #6: allocate 3 GB; container OOM-killed.

    Skipped on Firejail (oom_killed always False — kernel-level OOM
    isn't surfaced by firejail in v0.4; documented in the ARCH amendment).
    """
    if os.environ.get("FLOSSWING_SANDBOX_BACKEND") == "firejail":
        pytest.skip("Firejail backend does not surface OOMKilled in v0.4")

    poc = "x = bytearray(3 * 1024 * 1024 * 1024)\nprint('alloc ok')\n"
    inp = CompileAndRunInput(
        language="python",
        files=[SourceFile(relative_path="oom.py", content=poc)],
        run_command="python oom.py",
        attack_class="command_injection",
        timeout_seconds=30,
    )
    out = await compile_and_run(
        inp, run_id="integ_oom", repo_root=repo_root
    )
    assert out.run.oom_killed is True
    assert out.run.exit_code == -1
    assert out.run.signal == "SIGKILL"


@pytest.mark.asyncio
async def test_sandbox_policy_smoke_only_ssrf_permits(repo_root: Path) -> None:
    """Quick policy smoke wired through the real lookup."""
    assert policy.lookup("ssrf").network_permitted is True
    assert policy.lookup("command_injection").network_permitted is False
