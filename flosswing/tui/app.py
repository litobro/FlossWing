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

"""Textual application entry point for the FlossWing dashboard."""

from __future__ import annotations

from textual.app import App

from flosswing.tui.launcher import ChildProcess


class FlosswingTUI(App[None]):
    """Read-only dashboard over state.db plus a scan/report launcher."""

    TITLE = "FlossWing"
    SUB_TITLE = "vulnerability research dashboard"

    def __init__(self) -> None:
        super().__init__()
        self._children: list[ChildProcess] = []

    def on_mount(self) -> None:
        from flosswing.tui.screens.runs import RunsScreen

        self.push_screen(RunsScreen())

    def track_child(self, child: ChildProcess) -> None:
        """Register a spawned child so the quit guard can manage it."""
        self._children.append(child)

    def live_children(self) -> list[ChildProcess]:
        """Return live children, pruning any that have exited."""
        alive = [c for c in self._children if c.is_alive()]
        self._children = alive
        return alive

    def action_request_quit(self) -> None:
        """Quit, but guard against killing a live scan we launched."""
        live = [c for c in self.live_children() if c.kind == "scan"]
        if not live:
            self.exit()
            return
        from flosswing.tui.screens.new_scan import QuitGuard

        self.push_screen(QuitGuard(live))


def run() -> None:
    """Launch the dashboard (called by `flosswing tui`)."""
    FlosswingTUI().run()
