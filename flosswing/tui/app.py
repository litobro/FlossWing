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

from typing import ClassVar


def run() -> None:
    """Launch the dashboard. Fleshed out in a later task."""
    from textual.app import App, ComposeResult
    from textual.binding import BindingType
    from textual.widgets import Footer, Static

    class _Placeholder(App[None]):
        BINDINGS: ClassVar[list[BindingType]] = [("q", "quit", "Quit")]

        def compose(self) -> ComposeResult:
            yield Static("FlossWing TUI — under construction")
            yield Footer()

    _Placeholder().run()
