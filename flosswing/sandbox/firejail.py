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

"""FirejailSandbox — fallback backend for compile_and_run.

Per docs/specs/2026-06-02-v0.4-sandbox-design.md § Component
responsibilities sandbox/firejail.py.

Translates a SandboxInvocation into a firejail argv. Wall-clock
timeout is enforced via the subprocess timeout= kwarg (outer guard)
plus firejail's own --timeout= (inner guard).

Firejail does NOT provide per-language filesystem images. The host
must have the required language toolchain installed when Firejail is
the active backend. Deliberate trade-off — documented in the
ARCHITECTURE.md amendment landed alongside this milestone.
"""

from __future__ import annotations

import asyncio
import json
import re
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from flosswing.errors import PathEscapesScratchError
from flosswing.sandbox.base import (
    CompileAndRunOutput,
    ExecResult,
    SandboxInvocation,
)

_STDIO_CAP_BYTES: Final[int] = 10 * 1024 * 1024
# Match the Docker network-pattern set so backends agree on inference.
_NETWORK_PATTERNS: Final[list[re.Pattern[str]]] = [
    re.compile(r"\bEPERM\b"),
    re.compile(r"\bENETUNREACH\b"),
    re.compile(r"\bnetwork is unreachable\b", re.IGNORECASE),
    re.compile(r"\bgetaddrinfo\b"),
    re.compile(r"\bsocket\.gaierror\b"),
    re.compile(r"\bConnection refused\b"),
]

_ENV_ALLOWLIST: Final[frozenset[str]] = frozenset({
    "LANG",
    "LC_ALL",
    "PYTHONUNBUFFERED",
    "RUSTFLAGS",
    "CARGO_HOME",
    "GOFLAGS",
    "GOPATH",
    "NODE_OPTIONS",
})


def _filter_env(env: dict[str, str]) -> dict[str, str]:
    return {k: v for k, v in env.items() if k in _ENV_ALLOWLIST}


def _now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _scratch_root(run_id: str, invocation_id: str) -> Path:
    return (
        Path.home() / ".flosswing" / "runs" / run_id / "sandbox" / invocation_id
    )


def _validate_relative_path(rel: str) -> None:
    if Path(rel).is_absolute():
        raise PathEscapesScratchError(rel)
    if any(p == ".." for p in Path(rel).parts):
        raise PathEscapesScratchError(rel)


def _truncate(buf: bytes, cap: int) -> tuple[str, bool]:
    if len(buf) > cap:
        return buf[:cap].decode("utf-8", errors="replace"), True
    return buf.decode("utf-8", errors="replace"), False


def _infer_network_used(stdout_text: str, stderr_text: str) -> bool:
    """Scan both stdout and stderr — user code may print the diagnostic
    to stdout via an explicit exception handler."""
    combined = stdout_text + "\n" + stderr_text
    return any(p.search(combined) for p in _NETWORK_PATTERNS)


def _materialize_sources(
    invocation: SandboxInvocation, scratch: Path
) -> None:
    src_root = scratch / "src"
    src_root.mkdir(parents=True, exist_ok=True)
    for sf in invocation.files:
        _validate_relative_path(sf.relative_path)
        target = (src_root / sf.relative_path).resolve()
        try:
            target.relative_to(src_root.resolve())
        except ValueError as e:
            raise PathEscapesScratchError(sf.relative_path) from e
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(sf.content, encoding="utf-8")


def _entrypoint_script(invocation: SandboxInvocation) -> str:
    parts: list[str] = [
        "set -eu",
        "cp -r /tmp/scratch_src/. /tmp/scratch_work/",
        "cd /tmp/scratch_work",
    ]
    if invocation.build_command:
        parts.append(invocation.build_command)
    if invocation.args:
        quoted = " ".join(
            "'" + a.replace("'", "'\\''") + "'" for a in invocation.args
        )
        parts.append(f"{invocation.run_command} {quoted}")
    else:
        parts.append(invocation.run_command)
    return "\n".join(parts)


def _format_timeout(seconds: int) -> str:
    """firejail wants HH:MM:SS for --timeout=."""
    hh = seconds // 3600
    mm = (seconds % 3600) // 60
    ss = seconds % 60
    return f"{hh:02d}:{mm:02d}:{ss:02d}"


class FirejailSandbox:
    """Firejail-backed fallback. Implements flosswing.sandbox.base.Sandbox."""

    backend_name: str = "firejail"

    def __init__(self) -> None:
        self._available: bool | None = None

    async def is_available(self) -> bool:
        """Plain --version exit-0 probe per design decision #2."""
        if self._available is not None:
            return self._available
        firejail = shutil.which("firejail")
        if firejail is None:
            self._available = False
            return False
        try:
            proc = await asyncio.to_thread(
                subprocess.run,
                [firejail, "--version"],
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
            self._available = proc.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            self._available = False
        return self._available

    async def execute(
        self,
        invocation: SandboxInvocation,
        repo_root: Path,
    ) -> CompileAndRunOutput:
        scratch = _scratch_root(invocation.run_id, invocation.invocation_id)
        scratch.mkdir(parents=True, exist_ok=True)
        _materialize_sources(invocation, scratch)

        meta = {
            "invocation_id": invocation.invocation_id,
            "run_id": invocation.run_id,
            "attack_class": invocation.attack_class,
            "language": invocation.language,
            "build_command": invocation.build_command,
            "run_command": invocation.run_command,
            "started_at": _now_iso(),
            # Firejail-only metadata: no image / digest / SBOM available.
            "image": None,
            "image_digest": None,
            "sbom": "firejail backend — host toolchain in use; no per-image SBOM",
            "sandbox_backend": "firejail",
        }
        (scratch / "meta.json").write_text(
            json.dumps(meta, indent=2, sort_keys=True), encoding="utf-8"
        )

        firejail = shutil.which("firejail")
        if firejail is None:
            # Should not happen (select_backend already gated), but handle defensively.
            from flosswing.errors import SandboxBackendUnavailableError

            raise SandboxBackendUnavailableError(
                "firejail binary disappeared between selection and execute"
            )

        argv: list[str] = [
            firejail,
            "--quiet",
            "--noprofile",
            "--private-tmp",
            "--caps.drop=all",
            ("--net=none" if not invocation.network else "--net=auto"),
            f"--timeout={_format_timeout(invocation.timeout_seconds)}",
            "--rlimit-as=2000000000",       # ~2 GB virtual address space
            "--rlimit-nproc=256",
            f"--whitelist={(scratch / 'src').resolve()}",
            f"--read-only={repo_root.resolve()}",
            "/bin/sh",
            "-lc",
            _entrypoint_script(invocation),
        ]

        env = _filter_env(invocation.env)

        started = datetime.now(UTC)
        timed_out = False
        signal: str | None = None
        exit_code = -1
        stdout_bytes = b""
        stderr_bytes = b""

        try:
            proc = await asyncio.to_thread(
                subprocess.run,
                argv,
                capture_output=True,
                env=env,
                check=False,
                timeout=invocation.timeout_seconds + 5,
            )
            exit_code = proc.returncode
            stdout_bytes = (
                proc.stdout if isinstance(proc.stdout, bytes) else b""
            )
            stderr_bytes = (
                proc.stderr if isinstance(proc.stderr, bytes) else b""
            )
            # firejail signals timeout with non-zero exit; we already
            # consider timed_out true only when subprocess.TimeoutExpired
            # fired. Mirror Docker's signal handling for negative exit
            # codes (POSIX shells report 128+N for signal-N kills).
            if exit_code < 0:
                signal = "SIGKILL"
                exit_code = -1
        except subprocess.TimeoutExpired:
            timed_out = True
            exit_code = -1
            signal = "SIGKILL"

        finished = datetime.now(UTC)
        duration_ms = int((finished - started).total_seconds() * 1000)

        stdout_text, stdout_truncated = _truncate(stdout_bytes, _STDIO_CAP_BYTES)
        stderr_text, stderr_truncated = _truncate(stderr_bytes, _STDIO_CAP_BYTES)
        network_used = _infer_network_used(stdout_text, stderr_text)

        (scratch / "stdout").write_text(stdout_text, encoding="utf-8")
        (scratch / "stderr").write_text(stderr_text, encoding="utf-8")

        # Firejail cannot detect kernel-level OOM the way Docker can; we set
        # oom_killed=False unconditionally. Operators on Firejail-only hosts
        # see signal='SIGKILL' / exit_code=-1 in OOM cases and can
        # distinguish from timed_out via the boolean flag.
        run_result = ExecResult(
            exit_code=exit_code,
            signal=signal,
            stdout=stdout_text,
            stdout_truncated=stdout_truncated,
            stderr=stderr_text,
            stderr_truncated=stderr_truncated,
            duration_ms=duration_ms,
            oom_killed=False,
            timed_out=timed_out,
            network_used=network_used,
            sandbox_backend="firejail",
        )

        output = CompileAndRunOutput(
            build=None,
            run=run_result,
            scratch_path=str(scratch.resolve()),
        )

        (scratch / "result.json").write_text(
            output.model_dump_json(indent=2), encoding="utf-8"
        )
        return output


__all__ = ["FirejailSandbox"]
