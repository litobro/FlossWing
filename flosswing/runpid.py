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

"""Per-run PID-file liveness marker.

A running scan writes ``~/.flosswing/runs/<run_id>/run.pid`` at start and
removes it at finish. The read-only TUI uses this file to tell whether a run
whose DB ``status`` is ``running`` is *actually* alive, or whether the process
crashed / was killed and left the row stuck.

This is a liveness marker for a **foreground** process — not a daemon, not a
lock, not a background service. The file holds only a PID, a timestamp, and the
writer's own command line (used purely to guard against PID reuse); it never
holds a credential, repo contents, or any secret.

Pure stdlib, no SQLAlchemy and no Textual imports, so both the producer
(``flosswing.orchestrator``) and the consumer (``flosswing.tui.data``) can
import it without a layering violation. No function here ever raises to its
caller: a liveness check must never crash the dashboard or the scan.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def _now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _runs_base() -> Path:
    return Path.home() / ".flosswing" / "runs"


def run_pid_path(run_id: str) -> Path:
    """Path to the PID file for ``run_id`` (inside its scratch dir)."""
    return _runs_base() / run_id / "run.pid"


def _proc_cmdline(pid: int) -> list[str] | None:
    """Argv of ``pid`` from ``/proc``, or ``None`` if it can't be read.

    ``None`` means "can't verify" (no ``/proc`` on this platform, the process
    is gone, or it isn't readable) — callers treat that as "don't use the
    reuse guard", not "dead".
    """
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return None
    if not raw:
        return None
    # /proc/<pid>/cmdline is NUL-separated; drop the trailing empty field.
    return [part.decode("utf-8", "replace") for part in raw.split(b"\x00") if part]


def _self_cmdline() -> list[str] | None:
    return _proc_cmdline(os.getpid())


def _proc_starttime(pid: int) -> int | None:
    """Process start time (clock ticks since boot) from ``/proc/<pid>/stat``.

    This uniquely identifies a *process instance*: unlike the PID or the
    command line, it does not repeat when the kernel reuses a PID for a new
    process — even one launched with byte-identical argv. ``None`` if it can't
    be read (no ``/proc``, process gone), so callers fall back to the cmdline
    guard rather than mis-rejecting.
    """
    try:
        data = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    # Fields: "pid (comm) state ppid ...". comm may contain spaces or ')', so
    # split after the final ')'. starttime is field 22 overall, i.e. index 19
    # of the fields that follow comm (which start at field 3, 'state').
    _, _, rest = data.rpartition(")")
    parts = rest.split()
    if len(parts) < 20:
        return None
    try:
        return int(parts[19])
    except ValueError:
        return None


def write_pid_file(run_id: str) -> None:
    """Record the current process as the owner of ``run_id``.

    Best-effort: any I/O failure is swallowed. A missing PID file simply makes
    the run look stale to the TUI, which is the safe direction.
    """
    payload: dict[str, Any] = {
        "pid": os.getpid(),
        "created_at": _now_iso(),
        "cmdline": _self_cmdline(),
        "starttime": _proc_starttime(os.getpid()),
    }
    try:
        p = run_pid_path(run_id)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(payload), encoding="utf-8")
    except OSError:
        return


def clear_pid_file(run_id: str) -> None:
    """Remove ``run_id``'s PID file. Never raises (missing file is fine)."""
    try:
        run_pid_path(run_id).unlink()
    except OSError:
        return


def _read_record(run_id: str) -> dict[str, Any] | None:
    try:
        raw = run_pid_path(run_id).read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        rec = json.loads(raw)
    except (ValueError, TypeError):
        return None
    if not isinstance(rec, dict) or not isinstance(rec.get("pid"), int):
        return None
    return rec


def read_pid(run_id: str) -> int | None:
    """The PID recorded for ``run_id``, or ``None`` if absent/corrupt."""
    rec = _read_record(run_id)
    return rec["pid"] if rec is not None else None


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # Exists but owned by another user — the reuse guard decides.
        return True
    except OSError:
        return False
    return True


def liveness(run_id: str) -> str:
    """Classify ``run_id`` from a single PID-file read.

    Returns one of:

    - ``"absent"`` — no usable PID file (never written, or corrupt).
    - ``"dead"``   — a PID file exists but its recorded process is gone.
    - ``"live"``   — the recorded process is still running.

    Guards against PID reuse: if the record stored the writer's start time (or,
    failing that, its command line) and ``/proc`` is available, the live
    process must match. When neither comparison can be made (no ``/proc``, or a
    legacy record), plain liveness is trusted.
    """
    rec = _read_record(run_id)
    if rec is None:
        return "absent"
    pid = rec["pid"]
    if not _pid_alive(pid):
        return "dead"
    # Strongest reuse guard: process start time. It survives PID reuse even by
    # a second scan with identical argv (which defeats the cmdline check). When
    # both the stored and the live start time are available, the comparison is
    # conclusive either way.
    stored_start = rec.get("starttime")
    if isinstance(stored_start, int):
        current_start = _proc_starttime(pid)
        if current_start is not None:
            return "live" if current_start == stored_start else "dead"
        # start time unreadable — fall through to the cmdline guard
    stored = rec.get("cmdline")
    if not isinstance(stored, list):
        return "live"  # legacy/degraded record — can't apply the guard
    current = _proc_cmdline(pid)
    if current is None:
        return "live"  # no /proc (non-Linux) — can't apply the guard
    return "live" if current == stored else "dead"


def run_is_live(run_id: str) -> bool:
    """True iff ``run_id``'s recorded process is still running."""
    return liveness(run_id) == "live"
