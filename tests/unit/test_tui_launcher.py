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

"""flosswing.tui.launcher — scan/report child process management."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

import pytest

from flosswing.tui import launcher


def test_build_scan_argv_minimal() -> None:
    argv = launcher.build_scan_argv(
        Path("/tmp/repo"),
        formats=["md", "json"],
        hunt_token_budget=None,
    )
    assert argv[:4] == [sys.executable, "-m", "flosswing.cli", "scan"]
    assert "/tmp/repo" in argv
    assert "--depth" not in argv
    assert "--format" in argv and "md,json" in argv
    assert "--hunt-token-budget" not in argv


def test_build_scan_argv_with_budget() -> None:
    argv = launcher.build_scan_argv(
        Path("/tmp/repo"),
        formats=["md"],
        hunt_token_budget=150000,
    )
    assert "--hunt-token-budget" in argv
    assert "150000" in argv


def test_build_report_argv() -> None:
    argv = launcher.build_report_argv("run-123")
    assert argv == [sys.executable, "-m", "flosswing.cli", "report", "run-123"]


def test_spawn_scan_starts_process_and_tracks_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(launcher, "_RUNS_DIR", tmp_path)
    fake = mock.MagicMock()
    fake.poll.return_value = None  # alive
    with mock.patch("flosswing.tui.launcher.subprocess.Popen", return_value=fake) as popen:
        proc = launcher.spawn_scan(
            tmp_path, formats=["md"], hunt_token_budget=None
        )
    popen.assert_called_once()
    assert proc.is_alive() is True
    # log path is under the flosswing runs dir
    assert proc.log_path.name == "tui-scan.log"
    # the log file handle was wired to the child's stdout, stderr merged in
    assert popen.call_args.kwargs["stdout"] is not None
    assert popen.call_args.kwargs["stderr"] is launcher.subprocess.STDOUT


def test_spawn_report_starts_process_and_tracks_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(launcher, "_RUNS_DIR", tmp_path)
    fake = mock.MagicMock()
    fake.poll.return_value = None  # alive
    with mock.patch("flosswing.tui.launcher.subprocess.Popen", return_value=fake) as popen:
        proc = launcher.spawn_report("run-42")
    popen.assert_called_once()
    assert proc.is_alive() is True
    assert proc.log_path.name == "tui-report.log"


def test_proc_is_alive_false_after_exit() -> None:
    fake = mock.MagicMock()
    fake.poll.return_value = 0
    proc = launcher.ChildProcess(popen=fake, log_path=Path("/tmp/x.log"), kind="scan")
    assert proc.is_alive() is False
    assert proc.returncode == 0


def test_terminate_escalates_to_kill() -> None:
    fake = mock.MagicMock()
    fake.poll.return_value = None  # alive, so terminate() proceeds
    # Still alive after SIGTERM (wait raises TimeoutExpired), then killed.
    import subprocess as _sp

    fake.wait.side_effect = [_sp.TimeoutExpired(cmd="scan", timeout=5), 0]
    proc = launcher.ChildProcess(popen=fake, log_path=Path("/tmp/x.log"), kind="scan")
    proc.terminate(grace_seconds=5)
    fake.terminate.assert_called_once()
    fake.kill.assert_called_once()
    assert fake.wait.call_count == 2  # post-SIGTERM wait + post-SIGKILL wait


def test_terminate_early_returns_when_already_dead() -> None:
    fake = mock.MagicMock()
    fake.poll.return_value = 0  # already exited
    proc = launcher.ChildProcess(popen=fake, log_path=Path("/tmp/x.log"), kind="scan")
    proc.terminate()
    fake.terminate.assert_not_called()
    fake.kill.assert_not_called()
