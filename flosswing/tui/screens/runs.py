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

from textual.app import ComposeResult
from textual.binding import BindingType
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Static

from flosswing.tui import data


class RunsScreen(Screen[None]):
    BINDINGS: ClassVar[list[BindingType]] = [
        ("enter", "open_run", "Open"),
        ("n", "new_scan", "New scan"),
        ("r", "render_report", "Re-render report"),
        ("q", "request_quit", "Quit"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        yield DataTable(id="runs-table", cursor_type="row")
        yield Static("", id="runs-empty")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#runs-table", DataTable)
        table.add_columns("Run", "Repo", "Status", "Findings", "Started")
        self.refresh_rows()
        self.set_interval(2.0, self.refresh_rows)

    def refresh_rows(self) -> None:
        table = self.query_one("#runs-table", DataTable)
        rows = data.list_runs()
        cursor = table.cursor_row
        table.clear()
        for r in rows:
            badge = "running" if r.status == "running" else r.status
            table.add_row(
                r.short_id,
                r.target_repo_path,
                badge,
                str(r.findings_count),
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

            self.notify(f"report failed: {errors.scrub(str(e))}", severity="error")

    def action_request_quit(self) -> None:
        from flosswing.tui.app import FlosswingTUI

        app = cast(FlosswingTUI, self.app)
        app.action_request_quit()
