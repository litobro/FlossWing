"""DockerSandbox: verify the Docker SDK kwargs match the ARCH constraints.

This is the test that catches accidental cap relaxation. Mocks
docker.from_env() at the boundary; never launches a real container.

Per docs/specs/2026-06-02-v0.4-sandbox-design.md § Testing strategy
test_sandbox_docker_args.py and § Data flow.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from flosswing.sandbox.base import SandboxInvocation, SourceFile
from flosswing.sandbox.docker import DockerSandbox


def _invocation(tmp_path: Path) -> tuple[SandboxInvocation, Path]:
    inv = SandboxInvocation(
        invocation_id="01TEST",
        run_id="01RUN",
        attack_class="command_injection",
        language="python",
        files=[SourceFile(relative_path="exploit.py", content="print('hi')")],
        build_command=None,
        run_command="python exploit.py",
        stdin=None,
        args=[],
        env={"PYTHONUNBUFFERED": "1"},
        timeout_seconds=60,
        network=False,
    )
    return inv, tmp_path


def _wire_mock_client() -> tuple[MagicMock, MagicMock]:
    """Return (client, run_call_target) wired to deliver a successful container."""
    client = MagicMock()
    container = MagicMock()
    container.attrs = {"State": {"OOMKilled": False, "ExitCode": 0}}
    container.logs.side_effect = lambda **kw: (
        b"stdout-bytes" if kw.get("stdout") and not kw.get("stderr") else b"stderr-bytes"
    )
    container.wait.return_value = {"StatusCode": 0}
    client.containers.run.return_value = container
    client.images.get.return_value = MagicMock(id="sha256:fake")
    client.ping.return_value = True
    return client, container


@pytest.mark.asyncio
async def test_docker_sandbox_run_passes_arch_mandated_flags(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    inv, repo = _invocation(tmp_path)
    client, _container = _wire_mock_client()
    with patch("flosswing.sandbox.docker.docker.from_env", return_value=client):
        sb = DockerSandbox()
        await sb.execute(inv, repo_root=repo)

    assert client.containers.run.called, "containers.run was not invoked"
    # The execute() call invokes containers.run once for the main exec and
    # may invoke it again for the SBOM read. Look at the main exec call,
    # which is the one with our entrypoint script.
    main_call = None
    for call in client.containers.run.call_args_list:
        _, kwargs = call
        if kwargs.get("entrypoint") == ["/bin/sh", "-lc"]:
            main_call = call
            break
    assert main_call is not None, "main containers.run call not found"
    _, kwargs = main_call
    # Hard-coded checks: any drift here is an ARCH-constraint relaxation.
    assert kwargs["network_mode"] == "none"
    assert kwargs["read_only"] is True
    # mode=1777 lets the unprivileged container user write to the tmpfs.
    assert kwargs["tmpfs"] == {"/scratch/work": "size=128m,mode=1777"}
    assert kwargs["mem_limit"] == "2g"
    assert kwargs["nano_cpus"] == 2_000_000_000
    assert kwargs["pids_limit"] == 256
    assert kwargs["cap_drop"] == ["ALL"]
    assert "cap_add" not in kwargs or not kwargs["cap_add"]
    assert kwargs["user"] == "65534:65534"
    assert kwargs["working_dir"] == "/scratch/work"
    # detach=True is required: containers.run(detach=False) returns bytes
    # rather than a Container object, which breaks attrs/logs/OOM observation.
    assert kwargs["detach"] is True
    assert kwargs["entrypoint"] == ["/bin/sh", "-lc"]


@pytest.mark.asyncio
async def test_docker_sandbox_passes_scratch_and_repo_volumes_with_correct_modes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    inv, repo = _invocation(tmp_path)
    client, _container = _wire_mock_client()
    with patch("flosswing.sandbox.docker.docker.from_env", return_value=client):
        sb = DockerSandbox()
        await sb.execute(inv, repo_root=repo)

    # Look at the main exec call (the one with the entrypoint).
    main_call = None
    for call in client.containers.run.call_args_list:
        _, kwargs = call
        if kwargs.get("entrypoint") == ["/bin/sh", "-lc"]:
            main_call = call
            break
    assert main_call is not None
    _, kwargs = main_call
    vols = kwargs["volumes"]
    # /scratch/src is rw (the container writes nothing to /scratch/src directly,
    # but the entrypoint copies into /scratch/work; rw kept for symmetry with
    # the spec's data-flow block).
    src_mounts = [v for v in vols.values() if v["bind"] == "/scratch/src"]
    repo_mounts = [v for v in vols.values() if v["bind"] == "/repo"]
    assert len(src_mounts) == 1
    assert len(repo_mounts) == 1
    assert src_mounts[0]["mode"] == "rw"
    assert repo_mounts[0]["mode"] == "ro"


@pytest.mark.asyncio
async def test_docker_sandbox_image_tag_matches_language(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    inv, repo = _invocation(tmp_path)
    client, _container = _wire_mock_client()
    with patch("flosswing.sandbox.docker.docker.from_env", return_value=client):
        sb = DockerSandbox()
        await sb.execute(inv, repo_root=repo)
    main_call = None
    for call in client.containers.run.call_args_list:
        _, kwargs = call
        if kwargs.get("entrypoint") == ["/bin/sh", "-lc"]:
            main_call = call
            break
    assert main_call is not None
    _, kwargs = main_call
    assert kwargs["image"] == "flosswing-sandbox-python:v0.4"


@pytest.mark.asyncio
async def test_docker_sandbox_materializes_source_files_into_scratch_src(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    inv, repo = _invocation(tmp_path)
    client, _container = _wire_mock_client()
    with patch("flosswing.sandbox.docker.docker.from_env", return_value=client):
        sb = DockerSandbox()
        out = await sb.execute(inv, repo_root=repo)
    materialized = Path(out.scratch_path) / "src" / "exploit.py"
    assert materialized.exists()
    assert materialized.read_text() == "print('hi')"


@pytest.mark.asyncio
async def test_docker_sandbox_path_escape_rejects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    _, repo = _invocation(tmp_path)
    bad_inv = SandboxInvocation(
        invocation_id="01TEST",
        run_id="01RUN",
        attack_class="command_injection",
        language="python",
        files=[SourceFile(relative_path="../escape.py", content="x")],
        build_command=None,
        run_command="python -c ''",
        stdin=None,
        args=[],
        env={},
        timeout_seconds=60,
        network=False,
    )
    client, _container = _wire_mock_client()
    with patch("flosswing.sandbox.docker.docker.from_env", return_value=client):
        sb = DockerSandbox()
        with pytest.raises(Exception) as exc:  # PathEscapesScratchError
            await sb.execute(bad_inv, repo_root=repo)
    # Code maps to input_validation_failed per design decision #6.
    assert getattr(exc.value, "code", None) == "input_validation_failed"


@pytest.mark.asyncio
async def test_docker_sandbox_writes_meta_and_result_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    inv, repo = _invocation(tmp_path)
    client, _container = _wire_mock_client()
    with patch("flosswing.sandbox.docker.docker.from_env", return_value=client):
        sb = DockerSandbox()
        out = await sb.execute(inv, repo_root=repo)
    base = Path(out.scratch_path)
    assert (base / "meta.json").exists()
    assert (base / "result.json").exists()
    assert (base / "stdout").exists()
    assert (base / "stderr").exists()


@pytest.mark.asyncio
async def test_docker_sandbox_oom_killed_surfaces_in_exec_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    inv, repo = _invocation(tmp_path)
    client, container = _wire_mock_client()
    container.attrs = {"State": {"OOMKilled": True, "ExitCode": 137}}
    container.wait.return_value = {"StatusCode": 137}
    with patch("flosswing.sandbox.docker.docker.from_env", return_value=client):
        sb = DockerSandbox()
        out = await sb.execute(inv, repo_root=repo)
    assert out.run.oom_killed is True
    assert out.run.exit_code == -1
    assert out.run.signal == "SIGKILL"


@pytest.mark.asyncio
async def test_docker_sandbox_truncates_stdout_at_10mb(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    inv, repo = _invocation(tmp_path)
    client, container = _wire_mock_client()
    big = b"x" * (11 * 1024 * 1024)  # 11 MB
    container.logs.side_effect = lambda **kw: (
        big if kw.get("stdout") and not kw.get("stderr") else b""
    )
    with patch("flosswing.sandbox.docker.docker.from_env", return_value=client):
        sb = DockerSandbox()
        out = await sb.execute(inv, repo_root=repo)
    assert out.run.stdout_truncated is True
    assert len(out.run.stdout.encode("utf-8")) <= 10 * 1024 * 1024


@pytest.mark.asyncio
async def test_docker_sandbox_network_used_inferred_from_stderr(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    inv, repo = _invocation(tmp_path)
    client, container = _wire_mock_client()
    container.logs.side_effect = lambda **kw: (
        b"" if kw.get("stdout") and not kw.get("stderr") else
        b"socket.gaierror: [Errno -2] Name or service not known\n"
    )
    with patch("flosswing.sandbox.docker.docker.from_env", return_value=client):
        sb = DockerSandbox()
        out = await sb.execute(inv, repo_root=repo)
    assert out.run.network_used is True


@pytest.mark.asyncio
async def test_docker_sandbox_image_build_on_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """images.get -> ImageNotFound triggers images.build with the right Dockerfile."""
    import docker.errors

    monkeypatch.setenv("HOME", str(tmp_path))
    inv, repo = _invocation(tmp_path)
    client, _container = _wire_mock_client()
    client.images.get.side_effect = docker.errors.ImageNotFound("not found")
    client.images.build.return_value = (MagicMock(id="sha256:built"), iter([]))
    with patch("flosswing.sandbox.docker.docker.from_env", return_value=client):
        sb = DockerSandbox()
        await sb.execute(inv, repo_root=repo)
    assert client.images.build.called
    _, build_kwargs = client.images.build.call_args
    assert build_kwargs["tag"] == "flosswing-sandbox-python:v0.4"
    assert build_kwargs["dockerfile"].endswith("python.Dockerfile")


@pytest.mark.asyncio
async def test_docker_sandbox_image_build_failure_raises_sandbox_image_build_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import docker.errors

    from flosswing.errors import SandboxImageBuildError

    monkeypatch.setenv("HOME", str(tmp_path))
    inv, repo = _invocation(tmp_path)
    client, _container = _wire_mock_client()
    client.images.get.side_effect = docker.errors.ImageNotFound("not found")
    client.images.build.side_effect = docker.errors.BuildError(
        reason="layer 3: package not found",
        build_log=iter([{"stream": "Step 1/4\n"}, {"stream": "ERROR: package\n"}]),
    )
    with patch("flosswing.sandbox.docker.docker.from_env", return_value=client):
        sb = DockerSandbox()
        with pytest.raises(SandboxImageBuildError) as exc:
            await sb.execute(inv, repo_root=repo)
    assert exc.value.language == "python"
    assert "package" in exc.value.log_tail.lower() or "step" in exc.value.log_tail.lower()
