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

"""flosswing.runpid — per-run PID-file liveness marker."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from flosswing import runpid


@pytest.fixture(autouse=True)
def _home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # runpid derives the runs dir from Path.home(), which honours $HOME.
    monkeypatch.setenv("HOME", str(tmp_path))


_HAVE_PROC = Path("/proc/self/cmdline").exists()


def test_run_pid_path_under_runs_dir(tmp_path: Path) -> None:
    p = runpid.run_pid_path("run-1")
    assert p == tmp_path / ".flosswing" / "runs" / "run-1" / "run.pid"


def test_write_then_read_pid_roundtrip() -> None:
    runpid.write_pid_file("run-1")
    assert runpid.run_pid_path("run-1").exists()
    assert runpid.read_pid("run-1") == os.getpid()


def test_run_is_live_true_for_current_process() -> None:
    runpid.write_pid_file("run-1")
    assert runpid.run_is_live("run-1") is True


def test_clear_removes_file_and_liveness() -> None:
    runpid.write_pid_file("run-1")
    runpid.clear_pid_file("run-1")
    assert not runpid.run_pid_path("run-1").exists()
    assert runpid.read_pid("run-1") is None
    assert runpid.run_is_live("run-1") is False


def test_clear_missing_is_noop() -> None:
    # Never raises even if the file was never written.
    runpid.clear_pid_file("never")


def test_read_pid_absent_is_none() -> None:
    assert runpid.read_pid("ghost") is None


def test_run_is_live_absent_is_false() -> None:
    assert runpid.run_is_live("ghost") is False


def _write_record(run_id: str, record: object) -> None:
    p = runpid.run_pid_path(run_id)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(record), encoding="utf-8")


def test_corrupt_file_is_not_live() -> None:
    p = runpid.run_pid_path("bad")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("}{ not json", encoding="utf-8")
    assert runpid.read_pid("bad") is None
    assert runpid.run_is_live("bad") is False


def test_dead_pid_is_not_live() -> None:
    # A pid that is (almost certainly) not running. Guard: if it happens to
    # be alive on this machine, the test is meaningless — assert the premise.
    dead = 2_000_000_000
    try:
        os.kill(dead, 0)
        alive = True
    except (ProcessLookupError, OverflowError):
        alive = False
    except PermissionError:
        alive = True
    if alive:  # pragma: no cover - environment-dependent
        pytest.skip("chosen 'dead' pid is actually alive here")
    _write_record("d", {"pid": dead, "created_at": "x", "cmdline": ["python"]})
    assert runpid.run_is_live("d") is False


@pytest.mark.skipif(not _HAVE_PROC, reason="needs /proc for cmdline reuse guard")
def test_alive_pid_with_mismatched_cmdline_is_not_live() -> None:
    # Same pid as us (alive) but a stored cmdline that cannot match ours:
    # simulates PID reuse by an unrelated process.
    _write_record(
        "reuse",
        {"pid": os.getpid(), "created_at": "x", "cmdline": ["/nonexistent/other"]},
    )
    assert runpid.run_is_live("reuse") is False


def test_alive_pid_without_stored_cmdline_trusts_liveness() -> None:
    # Legacy/degraded record with no cmdline: fall back to existence only.
    _write_record("nocmd", {"pid": os.getpid(), "created_at": "x"})
    assert runpid.run_is_live("nocmd") is True


@pytest.mark.skipif(not _HAVE_PROC, reason="needs /proc for starttime reuse guard")
def test_write_records_starttime() -> None:
    runpid.write_pid_file("st")
    import json as _json

    rec = _json.loads(runpid.run_pid_path("st").read_text())
    assert isinstance(rec.get("starttime"), int)


@pytest.mark.skipif(not _HAVE_PROC, reason="needs /proc for starttime reuse guard")
def test_alive_pid_with_mismatched_starttime_is_not_live() -> None:
    # Same live pid and matching argv, but a different process *instance*
    # (simulated via a wrong starttime): a reused PID running an identical
    # command line must NOT be reported live.
    cmd = runpid._proc_cmdline(os.getpid())
    _write_record(
        "reuse-st",
        {
            "pid": os.getpid(),
            "created_at": "x",
            "cmdline": cmd,
            "starttime": 1,  # cannot match our real starttime
        },
    )
    assert runpid.run_is_live("reuse-st") is False


@pytest.mark.skipif(not _HAVE_PROC, reason="needs /proc for starttime reuse guard")
def test_matching_starttime_is_live() -> None:
    # A full, self-consistent record (pid + cmdline + real starttime) is live.
    runpid.write_pid_file("st-ok")
    assert runpid.run_is_live("st-ok") is True


def test_record_without_starttime_still_trusts_cmdline() -> None:
    # Legacy record predating the starttime field: fall back to the cmdline
    # guard (or plain liveness) rather than rejecting outright.
    cmd = runpid._proc_cmdline(os.getpid())
    _write_record("legacy-st", {"pid": os.getpid(), "created_at": "x", "cmdline": cmd})
    assert runpid.run_is_live("legacy-st") is True
