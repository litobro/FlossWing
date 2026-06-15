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

"""New-scan form and the quit-guard, both modal screens."""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar, cast

from textual.app import ComposeResult
from textual.binding import BindingType
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, Static

from flosswing.tui import launcher
from flosswing.tui.launcher import ChildProcess

_FORMATS: list[str] = ["md", "json", "sarif"]


class NewScanScreen(ModalScreen[None]):
    """Modal form for launching a new scan."""

    BINDINGS: ClassVar[list[BindingType]] = [
        ("enter", "submit", "Start"),
        ("escape", "app.pop_screen", "Cancel"),
    ]

    def compose(self) -> ComposeResult:
        with Vertical(id="new-scan-box"):
            yield Label("New scan")
            yield Input(value=str(Path.cwd()), placeholder="repo path", id="scan-path")
            yield Input(value="md,json", placeholder="formats (comma sep)", id="scan-formats")
            yield Input(placeholder="hunt token budget (optional)", id="scan-budget")
            yield Static("", id="scan-error")
            with Horizontal():
                yield Button("Start", variant="primary", id="scan-start")
                yield Button("Cancel", id="scan-cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "scan-start":
            self.action_submit()
        else:
            self.app.pop_screen()

    def action_submit(self) -> None:
        err = self.query_one("#scan-error", Static)
        path_str = self.query_one("#scan-path", Input).value.strip()
        if not path_str:
            err.update("repo path is required")
            return
        path = Path(path_str)
        if not path.is_dir():
            err.update(f"not a directory: {path_str}")
            return

        formats = [
            f.strip()
            for f in self.query_one("#scan-formats", Input).value.split(",")
            if f.strip()
        ]
        bad = [f for f in formats if f not in _FORMATS]
        if not formats or bad:
            err.update(f"invalid format(s): {', '.join(bad) or '(empty)'}")
            return

        budget_str = self.query_one("#scan-budget", Input).value.strip()
        budget: int | None = None
        if budget_str:
            try:
                budget = int(budget_str)
            except ValueError:
                err.update("token budget must be an integer")
                return
            if budget <= 0:
                err.update("token budget must be a positive integer")
                return

        try:
            child = launcher.spawn_scan(
                path, formats=formats, hunt_token_budget=budget
            )
        except Exception as e:  # surface, never crash the UI
            from flosswing import errors

            err.update(f"failed to start scan: {errors.scrub(str(e))}")
            return

        from flosswing.tui.app import FlosswingTUI

        app = cast(FlosswingTUI, self.app)
        app.track_child(child)
        app.pop_screen()
        self.notify("Scan started — watch the runs list for progress.")


class QuitGuard(ModalScreen[None]):
    """Shown when quitting with a live scan child the TUI launched."""

    BINDINGS: ClassVar[list[BindingType]] = [
        ("d", "detach", "Detach"),
        ("k", "kill", "Kill"),
        ("escape", "app.pop_screen", "Cancel"),
    ]

    def __init__(self, live: list[ChildProcess]) -> None:
        super().__init__()
        self._live = live

    def compose(self) -> ComposeResult:
        with Vertical(id="quit-guard-box"):
            yield Label(f"{len(self._live)} scan(s) still running.")
            with Horizontal():
                yield Button("Detach (leave running)", variant="primary", id="qg-detach")
                yield Button("Kill", variant="error", id="qg-kill")
                yield Button("Cancel", id="qg-cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "qg-detach":
            self.action_detach()
        elif event.button.id == "qg-kill":
            self.action_kill()
        else:
            self.app.pop_screen()

    def action_detach(self) -> None:
        # Leave children running; just exit the UI.
        self.app.exit()

    def action_kill(self) -> None:
        for child in self._live:
            child.terminate()
        self.app.exit()
