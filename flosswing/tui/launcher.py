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

"""Spawn and track `flosswing scan` / `flosswing report` child processes.

This is the only TUI module that starts subprocesses. It never touches the
state DB; progress is read separately via `flosswing.tui.data`. Children are
launched as `python -m flosswing.cli …` so they work regardless of whether a
`flosswing` console script is on PATH.
"""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

_RUNS_DIR = Path.home() / ".flosswing" / "runs"


def build_scan_argv(
    path: Path,
    *,
    depth: str,
    formats: list[str],
    hunt_token_budget: int | None,
) -> list[str]:
    """Construct argv for a scan child process."""
    argv = [
        sys.executable,
        "-m",
        "flosswing.cli",
        "scan",
        str(path),
        "--depth",
        depth,
        "--format",
        ",".join(formats),
    ]
    if hunt_token_budget is not None:
        argv += ["--hunt-token-budget", str(hunt_token_budget)]
    return argv


def build_report_argv(run_id: str) -> list[str]:
    """Construct argv for a report re-render child process."""
    return [sys.executable, "-m", "flosswing.cli", "report", run_id]


@dataclass(frozen=True)
class ChildProcess:
    """A spawned child plus its captured-output log path."""

    popen: subprocess.Popen[bytes]
    log_path: Path
    kind: Literal["scan", "report"]

    def is_alive(self) -> bool:
        return self.popen.poll() is None

    @property
    def returncode(self) -> int | None:
        return self.popen.poll()

    def terminate(self, grace_seconds: float = 5.0) -> None:
        """SIGTERM, then SIGKILL if the child does not exit within the grace."""
        if not self.is_alive():
            return
        self.popen.terminate()
        try:
            self.popen.wait(timeout=grace_seconds)
        except subprocess.TimeoutExpired:
            self.popen.kill()
            self.popen.wait(timeout=grace_seconds)


def _open_log(kind: str) -> Path:
    """A timestamp-free, kind-specific log path under the runs dir.

    The scan child generates its own run_id, so we cannot name the log after
    it up front; a single rolling log per launch is sufficient for post-hoc
    inspection. Existing content is truncated on each launch.
    """
    _RUNS_DIR.mkdir(parents=True, exist_ok=True)
    return _RUNS_DIR / f"tui-{kind}.log"


def spawn_scan(
    path: Path,
    *,
    depth: str,
    formats: list[str],
    hunt_token_budget: int | None,
) -> ChildProcess:
    argv = build_scan_argv(
        path, depth=depth, formats=formats, hunt_token_budget=hunt_token_budget
    )
    log_path = _open_log("scan")
    with open(log_path, "wb") as log:
        popen = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT)
    # parent's fd closed here; the child already holds its own copy
    return ChildProcess(popen=popen, log_path=log_path, kind="scan")


def spawn_report(run_id: str) -> ChildProcess:
    argv = build_report_argv(run_id)
    log_path = _open_log("report")
    with open(log_path, "wb") as log:
        popen = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT)
    # parent's fd closed here; the child already holds its own copy
    return ChildProcess(popen=popen, log_path=log_path, kind="report")
