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

"""Run detail — stage progress, budget, Hunt task table."""

from __future__ import annotations

from typing import ClassVar

from textual.app import ComposeResult
from textual.binding import BindingType
from textual.screen import Screen
from textual.timer import Timer
from textual.widgets import DataTable, Footer, Header, Static

from flosswing.tui import data

_GLYPH = {"done": "✓", "active": "▶", "pending": "…", "n/a": "·"}
# Must stay in sync with the state values emitted by data._derive_stages;
# a new state there needs a new entry here (falls back to "?" otherwise).


class RunDetailScreen(Screen[None]):
    BINDINGS: ClassVar[list[BindingType]] = [
        ("f", "findings", "Findings"),
        ("s", "sessions", "Sessions"),
        ("escape", "app.pop_screen", "Back"),
    ]

    def __init__(self, run_id: str) -> None:
        super().__init__()
        self._run_id = run_id
        self._poll: Timer | None = None

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("", id="stage-strip")
        yield Static("", id="run-meta")
        yield DataTable(id="hunt-table", cursor_type="row")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#hunt-table", DataTable)
        table.add_columns("Attack class", "Scope", "Status", "Findings")
        self._poll = self.set_interval(2.0, self.refresh_view)
        self.refresh_view()

    def refresh_view(self) -> None:
        p = data.run_progress(self._run_id)
        strip = self.query_one("#stage-strip", Static)
        meta = self.query_one("#run-meta", Static)
        if p is None:
            strip.update("run not found")
            meta.update("")
            return
        self.sub_title = f"{p.short_id}  {p.target_repo_path}  [{p.status}]"
        strip.update(
            "  ".join(f"{_GLYPH.get(st.state, '?')} {st.name}" for st in p.stages)
        )
        meta.update(
            f"Hunt {p.hunt_done}/{p.hunt_total}   "
            f"findings {p.findings_total}   "
            f"tokens {p.tokens_used:,}   "
            f"cost ${p.cost_usd:.2f}"
        )
        table = self.query_one("#hunt-table", DataTable)
        cursor = table.cursor_row
        table.clear()
        for t in p.hunt_tasks:
            table.add_row(t.attack_class, t.scope_hint, t.status, str(t.findings_count))
        if p.hunt_tasks and 0 <= cursor < len(p.hunt_tasks):
            table.move_cursor(row=cursor)
        if p.status != "running" and self._poll is not None:
            self._poll.stop()
            self._poll = None

    def action_findings(self) -> None:
        from flosswing.tui.screens.findings import FindingsScreen

        self.app.push_screen(FindingsScreen(self._run_id))

    def action_sessions(self) -> None:
        from flosswing.tui.screens.sessions import SessionsScreen

        self.app.push_screen(SessionsScreen(self._run_id))
