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

"""Findings list for a run."""

from __future__ import annotations

from typing import ClassVar

from textual.app import ComposeResult
from textual.binding import BindingType
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header

from flosswing.tui import data


class FindingsScreen(Screen[None]):
    BINDINGS: ClassVar[list[BindingType]] = [
        ("enter", "open_finding", "Open"),
        ("escape", "app.pop_screen", "Back"),
    ]

    def __init__(self, run_id: str) -> None:
        super().__init__()
        self._run_id = run_id

    def compose(self) -> ComposeResult:
        yield Header()
        yield DataTable(id="findings-table", cursor_type="row")
        yield Footer()

    def on_mount(self) -> None:
        self.sub_title = "findings"
        table = self.query_one("#findings-table", DataTable)
        table.add_columns("Severity", "Conf.", "Status", "Reach", "Class", "Title")
        for f in data.findings_list(self._run_id):
            table.add_row(
                f.severity,
                f.confidence,
                f.status,
                f.reachable or "-",
                f.attack_class,
                f.title,
                key=f.id,
            )

    def action_open_finding(self) -> None:
        table = self.query_one("#findings-table", DataTable)
        if table.row_count == 0:
            return
        finding_id = table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
        if finding_id is None:
            return
        from flosswing.tui.screens.finding_detail import FindingDetailScreen

        self.app.push_screen(FindingDetailScreen(self._run_id, finding_id))
