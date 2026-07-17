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

"""Runs list — the initial screen."""

from __future__ import annotations

from typing import ClassVar, cast

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding, BindingType
from textual.screen import Screen
from textual.timer import Timer
from textual.widgets import DataTable, Footer, Header, Static

from flosswing import errors
from flosswing.tui import data
from flosswing.tui.widgets import SelectableDataTable

# Live-status glyphs. Kept as a named map so tests and the header stay in sync.
# 'unknown' = a running row with no usable PID file: we can't confirm liveness,
# so it gets a neutral marker rather than the alarming 'stale' warning.
_LIVE_GLYPH = {"live": "●", "stale": "⚠", "unknown": "?", "done": "·"}
_LIVE_STYLE = {"live": "green", "stale": "yellow", "unknown": "dim", "done": "dim"}


def _format_elapsed(started_at: str) -> str:
    """Humanised elapsed time since an ISO8601 timestamp, e.g. '3m12s'.

    Returns '' if the timestamp can't be parsed — never raises into the poll.
    """
    from datetime import UTC, datetime

    try:
        start = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
        # A timezone-naive timestamp (no offset/'Z') makes the subtraction
        # below raise TypeError; catch it here so the poll never sees it.
        delta = datetime.now(UTC) - start
    except (ValueError, AttributeError, TypeError):
        return ""
    secs = int(delta.total_seconds())
    if secs < 0:
        return ""
    if secs < 60:
        return f"{secs}s"
    if secs < 3600:
        return f"{secs // 60}m{secs % 60:02d}s"
    hours, rem = divmod(secs, 3600)
    return f"{hours}h{rem // 60:02d}m"


class RunsScreen(Screen[None]):
    BINDINGS: ClassVar[list[BindingType]] = [
        # priority=True: DataTable also binds enter (select_cursor); the screen
        # must win so that enter opens the run detail rather than DataTable eating it.
        Binding("enter", "open_run", "Open", priority=True),
        ("n", "new_scan", "New scan"),
        ("r", "render_report", "Re-render report"),
        ("q", "request_quit", "Quit"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._poll: Timer | None = None

    def compose(self) -> ComposeResult:
        yield Header()
        yield SelectableDataTable(id="runs-table", cursor_type="row")
        yield Static("", id="runs-empty")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#runs-table", DataTable)
        table.add_columns(
            "Run", "Repo", "Status", "Live", "Stage", "Findings", "Tokens",
            "Cost", "Elapsed", "Started",
        )
        self.refresh_rows()
        self._poll = self.set_interval(data.POLL_INTERVAL_SECONDS, self.refresh_rows)

    def refresh_rows(self) -> None:
        table = self.query_one("#runs-table", DataTable)
        try:
            rows = data.list_runs()
        except Exception as e:  # DB unreadable — show guidance, stop poll, never crash
            empty = self.query_one("#runs-empty", Static)
            # Text(...) renders literally — the scrubbed error is untrusted and
            # may contain Rich-markup-like sequences.
            empty.update(Text(f"Cannot read state.db: {errors.scrub(str(e))}"))
            table.clear()
            if self._poll is not None:
                self._poll.stop()
                self._poll = None
            return
        cursor = table.cursor_row
        table.clear()
        for r in rows:
            live_glyph = Text(
                _LIVE_GLYPH.get(r.liveness, "?"),
                style=_LIVE_STYLE.get(r.liveness, ""),
            )
            # Only live runs get an elapsed value: a stale (crashed) run keeps
            # DB status 'running', so gating on status would grow its Elapsed
            # unbounded and present a dead scan as if still working.
            elapsed = _format_elapsed(r.started_at) if r.liveness == "live" else ""
            table.add_row(
                r.short_id,
                # repo path is operator/DB-derived — render literally so it
                # can't be interpreted as Rich markup.
                Text(r.target_repo_path),
                r.status,
                live_glyph,
                r.active_stage or "",
                str(r.findings_count),
                f"{r.tokens_used:,}",
                f"${r.cost_usd:.2f}",
                elapsed,
                r.started_at,
                key=r.id,
            )
        empty = self.query_one("#runs-empty", Static)
        empty.update(
            "No runs yet — press [b]n[/b] to start a scan." if not rows else ""
        )
        if rows and 0 <= cursor < len(rows):
            table.move_cursor(row=cursor)

    def _selected_run_id(self) -> str | None:
        table = self.query_one("#runs-table", DataTable)
        if table.row_count == 0:
            return None
        row_key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key
        return row_key.value

    def action_open_run(self) -> None:
        run_id = self._selected_run_id()
        if run_id is not None:
            from flosswing.tui.app import FlosswingTUI
            from flosswing.tui.screens.run_detail import RunDetailScreen

            app = cast(FlosswingTUI, self.app)
            app.push_screen(RunDetailScreen(run_id))

    def action_new_scan(self) -> None:
        from flosswing.tui.app import FlosswingTUI
        from flosswing.tui.screens.new_scan import NewScanScreen

        app = cast(FlosswingTUI, self.app)
        app.push_screen(NewScanScreen())

    def action_render_report(self) -> None:
        run_id = self._selected_run_id()
        if run_id is None:
            return
        from flosswing.tui import launcher
        from flosswing.tui.app import FlosswingTUI

        app = cast(FlosswingTUI, self.app)
        try:
            app.track_child(launcher.spawn_report(run_id))
            self.notify(f"Re-rendering report for {run_id[-8:]}…")
        except Exception as e:  # surface error in the UI, never crash the dashboard
            from flosswing import errors

            self.notify(f"report failed: {errors.scrub(str(e))}", severity="error", markup=False)

    def action_request_quit(self) -> None:
        from flosswing.tui.app import FlosswingTUI

        app = cast(FlosswingTUI, self.app)
        app.action_request_quit()
