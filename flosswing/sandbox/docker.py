"""DockerSandbox — primary backend for compile_and_run.

Per docs/specs/2026-06-02-v0.4-sandbox-design.md § Component
responsibilities sandbox/docker.py and § Data flow.

Container flags are set explicitly via the Docker SDK
`containers.run(...)` call. Wall-clock timeout is enforced OUTSIDE the
container by the driver (asyncio.wait_for); the timeout(1) baked into
the language Dockerfiles is a belt-and-suspenders second guard.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

import docker
import docker.errors

from flosswing.errors import (
    PathEscapesScratchError,
    SandboxBackendUnavailableError,
    SandboxImageBuildError,
)
from flosswing.sandbox.base import (
    CompileAndRunOutput,
    ExecResult,
    SandboxInvocation,
)

# -----------------------------------------------------------------------------
# Constants — ARCH-mandated. Do not weaken without operator approval.
# -----------------------------------------------------------------------------

_IMAGE_TAG_FMT: Final[str] = "flosswing-sandbox-{language}:v0.4"
_IMAGES_DIR: Final[Path] = Path(__file__).resolve().parent / "images"
_STDIO_CAP_BYTES: Final[int] = 10 * 1024 * 1024  # 10 MB per ARCH § Sandbox
_TMPFS_WORK_SIZE: Final[str] = "size=128m"  # per design decision #3

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

# Network-attempt signatures in stderr. Best-effort inference per spec.
# TODO(v0.4-hardening): replace with dmesg/audit parsing.
_NETWORK_PATTERNS: Final[list[re.Pattern[str]]] = [
    re.compile(r"\bEPERM\b"),
    re.compile(r"\bENETUNREACH\b"),
    re.compile(r"\bnetwork is unreachable\b", re.IGNORECASE),
    re.compile(r"\bgetaddrinfo\b"),
    re.compile(r"\bsocket\.gaierror\b"),
    re.compile(r"\bConnection refused\b"),
]


def _filter_env(env: dict[str, str]) -> dict[str, str]:
    """Drop everything not in the allowlist. Anything else is silently removed."""
    return {k: v for k, v in env.items() if k in _ENV_ALLOWLIST}


def _now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _scratch_root(run_id: str, invocation_id: str) -> Path:
    return (
        Path.home() / ".flosswing" / "runs" / run_id / "sandbox" / invocation_id
    )


def _validate_relative_path(rel: str) -> None:
    """Reject absolute paths and any segment that escapes /scratch/src."""
    if Path(rel).is_absolute():
        raise PathEscapesScratchError(rel)
    parts = Path(rel).parts
    if any(p == ".." for p in parts):
        raise PathEscapesScratchError(rel)


def _truncate(buf: bytes, cap: int) -> tuple[str, bool]:
    """Truncate `buf` to `cap` bytes; return (text, truncated_flag).

    UTF-8 decoding is lenient — repo-controlled output may not be valid UTF-8.
    """
    if len(buf) > cap:
        return buf[:cap].decode("utf-8", errors="replace"), True
    return buf.decode("utf-8", errors="replace"), False


def _infer_network_used(stdout_text: str, stderr_text: str) -> bool:
    """Scan both stdout and stderr — user code may catch the exception and
    print the diagnostic to stdout (e.g. `print('blocked:', e)`)."""
    combined = stdout_text + "\n" + stderr_text
    return any(p.search(combined) for p in _NETWORK_PATTERNS)


def _materialize_sources(
    invocation: SandboxInvocation, scratch: Path
) -> None:
    """Write each SourceFile under <scratch>/src/. Reject path escapes."""
    src_root = scratch / "src"
    src_root.mkdir(parents=True, exist_ok=True)
    for sf in invocation.files:
        _validate_relative_path(sf.relative_path)
        target = (src_root / sf.relative_path).resolve()
        # Double-check resolution stays inside src_root (catches symlinks
        # snuck in via the relative_path).
        try:
            target.relative_to(src_root.resolve())
        except ValueError as e:
            raise PathEscapesScratchError(sf.relative_path) from e
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(sf.content, encoding="utf-8")


def _entrypoint_script(invocation: SandboxInvocation) -> str:
    """Compose the /bin/sh -lc script: copy src into work, build, run.

    The container's working_dir is /scratch/work (tmpfs). /scratch/src is
    mounted rw but the container shouldn't write to it; copying to work
    lets the toolchain spit out build artifacts to tmpfs.
    """
    parts: list[str] = [
        "set -eu",
        "cp -r /scratch/src/. /scratch/work/",
    ]
    if invocation.build_command:
        parts.append(invocation.build_command)
    # Quote args defensively.
    if invocation.args:
        # Use shell-quoted args; runtime is /bin/sh which does word splitting.
        # Caller-controlled list — wrap each token in single quotes after
        # escaping any embedded single quotes.
        quoted = " ".join(
            "'" + a.replace("'", "'\\''") + "'" for a in invocation.args
        )
        parts.append(f"{invocation.run_command} {quoted}")
    else:
        parts.append(invocation.run_command)
    return "\n".join(parts)


def _build_log_tail(err: docker.errors.BuildError) -> str:
    """Extract the last few kB of an aborted build's log stream."""
    lines: list[str] = []
    try:
        build_log = getattr(err, "build_log", None)
        if build_log is not None:
            for chunk in build_log:
                stream = chunk.get("stream") if isinstance(chunk, dict) else None
                if stream:
                    lines.append(stream)
    except Exception:  # build_log is best-effort already
        pass
    text = "".join(lines)
    return text[-4 * 1024:] if len(text) > 4 * 1024 else text


class DockerSandbox:
    """Docker-backed sandbox. Implements flosswing.sandbox.base.Sandbox."""

    backend_name: str = "docker"

    def __init__(self) -> None:
        self._client: docker.DockerClient | None = None
        self._available: bool | None = None

    def _get_client(self) -> docker.DockerClient:
        if self._client is None:
            self._client = docker.from_env()
        return self._client

    async def is_available(self) -> bool:
        if self._available is not None:
            return self._available
        try:
            client = await asyncio.to_thread(docker.from_env)
            await asyncio.to_thread(client.ping)
            self._client = client
            self._available = True
        except Exception:  # any failure means "not available"
            self._available = False
        return self._available

    async def ensure_image(self, language: str) -> str:
        """Return the image tag, building it from the language Dockerfile if missing."""
        tag = _IMAGE_TAG_FMT.format(language=language)
        client = self._get_client()
        try:
            await asyncio.to_thread(client.images.get, tag)
            return tag
        except docker.errors.ImageNotFound:
            pass
        dockerfile = _IMAGES_DIR / f"{language}.Dockerfile"
        if not dockerfile.exists():
            raise SandboxImageBuildError(
                language=language,
                log_tail=f"missing Dockerfile: {dockerfile}",
            )
        try:
            await asyncio.to_thread(
                client.images.build,
                path=str(_IMAGES_DIR),
                dockerfile=str(dockerfile),
                tag=tag,
                rm=True,
                forcerm=True,
                pull=False,
            )
        except docker.errors.BuildError as e:
            raise SandboxImageBuildError(
                language=language,
                log_tail=_build_log_tail(e),
            ) from e
        except docker.errors.APIError as e:
            raise SandboxImageBuildError(
                language=language,
                log_tail=str(e),
            ) from e
        return tag

    async def execute(
        self,
        invocation: SandboxInvocation,
        repo_root: Path,
    ) -> CompileAndRunOutput:
        scratch = _scratch_root(invocation.run_id, invocation.invocation_id)
        scratch.mkdir(parents=True, exist_ok=True)
        _materialize_sources(invocation, scratch)

        # Write meta.json BEFORE launching the container.
        image_tag = await self.ensure_image(invocation.language)
        image_digest = await self._image_digest(image_tag)
        sbom = await self._read_sbom(image_tag)
        meta = {
            "invocation_id": invocation.invocation_id,
            "run_id": invocation.run_id,
            "attack_class": invocation.attack_class,
            "language": invocation.language,
            "build_command": invocation.build_command,
            "run_command": invocation.run_command,
            "started_at": _now_iso(),
            "image": image_tag,
            "image_digest": image_digest,
            "sbom": sbom,
            "sandbox_backend": "docker",
        }
        (scratch / "meta.json").write_text(
            json.dumps(meta, indent=2, sort_keys=True), encoding="utf-8"
        )

        # Compose the entrypoint script. /bin/sh inside the container.
        script = _entrypoint_script(invocation)

        client = self._get_client()
        run_kwargs: dict[str, Any] = dict(
            image=image_tag,
            network_mode="none" if not invocation.network else "bridge",
            read_only=True,
            # mode=1777 (world-writable + sticky) lets the unprivileged
            # container user (nobody:nogroup) write into the tmpfs. Without
            # it the cp from /scratch/src to /scratch/work fails with EACCES
            # because tmpfs mounts default to root:root 0755.
            tmpfs={"/scratch/work": f"{_TMPFS_WORK_SIZE},mode=1777"},
            volumes={
                str((scratch / "src").resolve()): {
                    "bind": "/scratch/src",
                    "mode": "rw",
                },
                str(repo_root.resolve()): {"bind": "/repo", "mode": "ro"},
            },
            mem_limit="2g",
            nano_cpus=2_000_000_000,
            pids_limit=256,
            cap_drop=["ALL"],
            user="65534:65534",
            working_dir="/scratch/work",
            environment=_filter_env(invocation.env),
            entrypoint=["/bin/sh", "-lc"],
            # Wrap in a list so the SDK doesn't shlex.split a multi-line
            # str command into separate args (which would degrade the
            # script to `sh -lc set` followed by positional args, dumping
            # shell vars to stdout and skipping the cp + run).
            command=[script],
            detach=True,
            stdin_open=False,
            stderr=True,
            stdout=True,
            remove=False,
        )

        started = datetime.now(UTC)
        timed_out = False
        oom_killed = False
        signal: str | None = None
        exit_code = -1
        stdout_bytes = b""
        stderr_bytes = b""

        container = None
        try:
            # detach=True returns a Container handle near-instantly after the
            # container starts. We then block on container.wait() with our own
            # timeout so we can observe attrs/logs/OOM separately. The bare
            # containers.run path returns bytes, not a Container — fatal for
            # this code, which relies on attrs["State"] and .logs().
            container = await asyncio.to_thread(
                client.containers.run, **run_kwargs
            )
            try:
                wait_result = await asyncio.to_thread(
                    container.wait, timeout=invocation.timeout_seconds
                )
                exit_code = int(wait_result.get("StatusCode", 0))
            except Exception:
                # container.wait() raises an HTTP ReadTimeout when the
                # container is still running at the deadline. Kill it.
                timed_out = True
                exit_code = -1
                signal = "SIGKILL"
                with contextlib.suppress(Exception):
                    await asyncio.to_thread(container.kill, signal="SIGKILL")
                # Give the daemon a moment to reap; ignore further failure.
                with contextlib.suppress(Exception):
                    await asyncio.to_thread(
                        container.wait, timeout=5
                    )

            # Re-read attrs after the container has fully exited so OOMKilled
            # and ExitCode reflect the terminal state, not the launch state.
            with contextlib.suppress(Exception):
                await asyncio.to_thread(container.reload)
            attrs = getattr(container, "attrs", {}) or {}
            state = attrs.get("State", {}) if isinstance(attrs, dict) else {}
            oom_killed = bool(state.get("OOMKilled", False))
            if not timed_out:
                # On the timeout path we keep exit_code=-1; otherwise prefer
                # the daemon's final ExitCode over wait()'s status.
                exit_code = int(state.get("ExitCode", exit_code))

            with contextlib.suppress(Exception):
                stdout_bytes = await asyncio.to_thread(
                    container.logs, stdout=True, stderr=False, stream=False
                )
                stderr_bytes = await asyncio.to_thread(
                    container.logs, stdout=False, stderr=True, stream=False
                )
            if oom_killed:
                exit_code = -1
                signal = "SIGKILL"
        except docker.errors.APIError as e:
            raise SandboxBackendUnavailableError(
                f"docker API error during execute: {e}"
            ) from e
        finally:
            # Always clean up the container; logs were already captured above.
            if container is not None:
                with contextlib.suppress(Exception):
                    await asyncio.to_thread(container.remove, force=True)

        finished = datetime.now(UTC)
        duration_ms = int((finished - started).total_seconds() * 1000)

        stdout_text, stdout_truncated = _truncate(stdout_bytes, _STDIO_CAP_BYTES)
        stderr_text, stderr_truncated = _truncate(stderr_bytes, _STDIO_CAP_BYTES)
        network_used = _infer_network_used(stdout_text, stderr_text)

        (scratch / "stdout").write_text(stdout_text, encoding="utf-8")
        (scratch / "stderr").write_text(stderr_text, encoding="utf-8")

        run_result = ExecResult(
            exit_code=exit_code,
            signal=signal,
            stdout=stdout_text,
            stdout_truncated=stdout_truncated,
            stderr=stderr_text,
            stderr_truncated=stderr_truncated,
            duration_ms=duration_ms,
            oom_killed=oom_killed,
            timed_out=timed_out,
            network_used=network_used,
            sandbox_backend="docker",
        )

        output = CompileAndRunOutput(
            build=None,  # v0.4 collapses build + run into one container call;
                         # ExecResult for a separate build is a v0.5+ refinement.
            run=run_result,
            scratch_path=str(scratch.resolve()),
        )

        (scratch / "result.json").write_text(
            output.model_dump_json(indent=2), encoding="utf-8"
        )
        return output

    async def _image_digest(self, tag: str) -> str | None:
        """Return the sha256 digest of the local image, or None if unknown."""
        try:
            client = self._get_client()
            image = await asyncio.to_thread(client.images.get, tag)
            return getattr(image, "id", None)
        except Exception:
            return None

    async def _read_sbom(self, tag: str) -> str:
        """Read /sbom.txt from the image layer via a one-shot container.

        Per design decision #4. Best-effort; failures return an empty SBOM
        rather than raising — the SBOM is observability metadata, not a
        gate.
        """
        try:
            client = self._get_client()
            out = await asyncio.to_thread(
                client.containers.run,
                image=tag,
                command=["cat", "/sbom.txt"],
                entrypoint=[],
                network_mode="none",
                read_only=True,
                cap_drop=["ALL"],
                user="65534:65534",
                detach=False,
                stdout=True,
                stderr=False,
                remove=True,
                mem_limit="128m",
                nano_cpus=500_000_000,
                pids_limit=32,
            )
            return out.decode("utf-8", errors="replace") if isinstance(out, bytes) else str(out)
        except Exception:
            return ""


__all__ = ["DockerSandbox"]
