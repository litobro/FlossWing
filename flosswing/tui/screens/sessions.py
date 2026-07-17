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

"""Agent sessions for a run."""

from __future__ import annotations

from typing import ClassVar

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import BindingType
from textual.screen import Screen
from textual.timer import Timer
from textual.widgets import DataTable, Footer, Header

from flosswing.tui import data
from flosswing.tui.widgets import SelectableDataTable


class SessionsScreen(Screen[None]):
    BINDINGS: ClassVar[list[BindingType]] = [("escape", "app.pop_screen", "Back")]

    def __init__(self, run_id: str) -> None:
        super().__init__()
        self._run_id = run_id
        self._poll: Timer | None = None

    def compose(self) -> ComposeResult:
        yield Header()
        yield SelectableDataTable(id="sessions-table", cursor_type="row")
        yield Footer()

    def on_mount(self) -> None:
        self.sub_title = "agent sessions"
        table = self.query_one("#sessions-table", DataTable)
        table.add_columns("Stage", "Model", "In", "Out", "Cost", "Outcome", "Note")
        self.refresh_rows()
        # Poll like run_detail so completed sessions and the in-flight one
        # appear live as a scan runs, instead of a one-shot snapshot on mount.
        self._poll = self.set_interval(data.POLL_INTERVAL_SECONDS, self.refresh_rows)

    def refresh_rows(self) -> None:
        table = self.query_one("#sessions-table", DataTable)
        try:
            # One transaction: the live line and the session list always agree.
            live, sessions = data.activity(self._run_id)
        except Exception:
            # A transient read error (e.g. a momentary SQLite lock while the
            # scan writes heartbeats) must not permanently freeze the view:
            # skip this tick, keep the timer armed, and retry on the next poll.
            return
        cursor = table.cursor_row
        table.clear()
        for r in sessions:
            note = ""
            if r.outcome == "refused" and r.refusal_text:
                note = f"refused: {r.refusal_text[:40]}"
            elif r.error_text:
                note = f"error: {r.error_text[:40]}"
            # The note carries untrusted refusal/error text; wrap it in
            # rich.text.Text so DataTable renders it literally rather than
            # parsing embedded Rich markup (CLAUDE.md: repo is untrusted).
            table.add_row(
                r.stage,
                r.model,
                str(r.input_tokens),
                str(r.output_tokens),
                f"${r.cost_usd:.2f}",
                r.outcome,
                Text(note),
            )
        # The in-flight session, if any, is appended as a distinct live row.
        # Its "● live" outcome is synthetic display state — never written to the
        # DB, so it doesn't touch the frozen ck_agent_sessions_outcome vocabulary.
        if live is not None:
            table.add_row(
                live.stage,
                live.model,
                str(live.input_tokens),
                str(live.output_tokens),
                f"~${live.cost_usd:.2f}",
                Text("● live", style="green"),
                Text("in flight…"),
            )
        if 0 <= cursor < table.row_count:
            table.move_cursor(row=cursor)
