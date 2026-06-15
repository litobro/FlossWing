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

"""Single finding detail — PoC, validation, trace, suggested fix."""

from __future__ import annotations

from typing import ClassVar

from textual.app import ComposeResult
from textual.binding import BindingType
from textual.containers import VerticalScroll
from textual.screen import Screen
from textual.widgets import Footer, Header, Static

from flosswing.tui import data
from flosswing.tui.data import FindingDetail


def _render(d: FindingDetail) -> str:
    lines: list[str] = []
    lines.append(f"# {d.title}")
    lines.append(f"{d.attack_class}  ·  {d.severity}/{d.confidence}  ·  {d.status}")
    lines.append(f"location: {d.location}")
    if d.reachable:
        lines.append(f"reachability: {d.reachable}")
    lines.append("")
    lines.append("## Description")
    lines.append(d.description or "(none)")
    if d.poc_code:
        lines.append("")
        lines.append("## PoC")
        lines.append(d.poc_code)
    if d.poc_result:
        lines.append("")
        lines.append("## PoC result")
        lines.append(d.poc_result)
    if d.verdict:
        lines.append("")
        lines.append(f"## Validation: {d.verdict}")
        lines.append(d.verdict_rationale or "")
    if d.call_chain:
        lines.append("")
        lines.append("## Trace")
        if d.trace_rationale:
            lines.append(d.trace_rationale)
        for i, hop in enumerate(d.call_chain):
            lines.append(f"  {i}. {hop}")
    if d.suggested_fix:
        lines.append("")
        lines.append("## Suggested fix")
        lines.append(d.suggested_fix)
    return "\n".join(lines)


class FindingDetailScreen(Screen[None]):
    BINDINGS: ClassVar[list[BindingType]] = [("escape", "app.pop_screen", "Back")]

    def __init__(self, run_id: str, finding_id: str) -> None:
        super().__init__()
        self._run_id = run_id
        self._finding_id = finding_id

    def compose(self) -> ComposeResult:
        yield Header()
        with VerticalScroll():
            yield Static("", id="finding-body")
        yield Footer()

    def on_mount(self) -> None:
        self.sub_title = "finding"
        d = data.finding_detail(self._run_id, self._finding_id)
        body = self.query_one("#finding-body", Static)
        body.update(_render(d) if d is not None else "finding not found")
