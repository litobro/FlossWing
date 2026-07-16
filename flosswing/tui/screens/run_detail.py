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

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import BindingType
from textual.screen import Screen
from textual.timer import Timer
from textual.widgets import DataTable, Footer, Header, Static

from flosswing.tui import data
from flosswing.tui.screens.runs import _LIVE_GLYPH

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
        yield Static("", id="liveness-banner")
        yield Static("", id="stage-strip")
        yield Static("", id="run-meta")
        yield Static("", id="recent-activity")
        yield DataTable(id="hunt-table", cursor_type="row")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#hunt-table", DataTable)
        table.add_columns("Attack class", "Scope", "Status", "Findings")
        self._poll = self.set_interval(2.0, self.refresh_view)
        self.refresh_view()

    def refresh_view(self) -> None:
        p = data.run_progress(self._run_id)
        banner = self.query_one("#liveness-banner", Static)
        strip = self.query_one("#stage-strip", Static)
        meta = self.query_one("#run-meta", Static)
        activity = self.query_one("#recent-activity", Static)
        if p is None:
            banner.update("")
            strip.update("run not found")
            meta.update("")
            activity.update("")
            return
        self.sub_title = f"{p.short_id}  {p.target_repo_path}  [{p.status}]"
        banner.update(self._banner_text(p))
        strip.update(
            "  ".join(f"{_GLYPH.get(st.state, '?')} {st.name}" for st in p.stages)
        )
        meta.update(
            f"Hunt {p.hunt_done}/{p.hunt_total}   "
            f"findings {p.findings_total}   "
            f"tokens {p.tokens_used:,}   "
            f"cost ${p.cost_usd:.2f}"
        )
        activity.update(self._activity_text())
        table = self.query_one("#hunt-table", DataTable)
        cursor = table.cursor_row
        table.clear()
        for t in p.hunt_tasks:
            # Wrap untrusted, repo-derived strings (attack_class, scope_hint)
            # in rich.text.Text so DataTable renders them literally instead of
            # parsing embedded Rich markup (CLAUDE.md: repo is untrusted input).
            table.add_row(
                Text(t.attack_class),
                Text(t.scope_hint),
                t.status,
                str(t.findings_count),
            )
        if p.hunt_tasks and 0 <= cursor < len(p.hunt_tasks):
            table.move_cursor(row=cursor)
        # Stop polling once the run is terminal OR stale: a stale run's process
        # is gone, so its DB rows will never change again.
        if (p.status != "running" or p.liveness == "stale") and self._poll is not None:
            self._poll.stop()
            self._poll = None

    def _banner_text(self, p: data.RunProgress) -> Text:
        """Liveness banner: empty for terminal runs, live/stale for running."""
        if p.status != "running":
            return Text("")
        if p.liveness == "live":
            return Text(f"{_LIVE_GLYPH['live']} live", style="green")
        return Text(
            f"{_LIVE_GLYPH['stale']} process not found — the scan appears to have "
            "stopped (crashed or killed); the state DB still shows 'running'. "
            f"Re-run the scan or 'flosswing report {p.short_id}' to recover.",
            style="yellow",
        )

    def _activity_text(self) -> Text:
        """Tail of the agent-session feed — the DB-derived 'what happened' view.

        Sessions land as each stage/task finishes, so this grows live. Rendered
        as literal Text: refusal/error snippets are credential-scrubbed upstream
        but may still contain markup-like characters.
        """
        sessions = data.list_sessions(self._run_id)
        if not sessions:
            return Text("no agent activity yet")
        lines: list[str] = []
        for sr in sessions[-5:]:
            line = (
                f"{sr.stage}  {sr.outcome}  "
                f"{sr.input_tokens:,}/{sr.output_tokens:,} tok  ${sr.cost_usd:.2f}"
            )
            extra = sr.refusal_text or sr.error_text
            if extra:
                snippet = extra if len(extra) <= 80 else extra[:77] + "…"
                line += f"  — {snippet}"
            lines.append(line)
        return Text("\n".join(lines))

    def action_findings(self) -> None:
        from flosswing.tui.screens.findings import FindingsScreen

        self.app.push_screen(FindingsScreen(self._run_id))

    def action_sessions(self) -> None:
        from flosswing.tui.screens.sessions import SessionsScreen

        self.app.push_screen(SessionsScreen(self._run_id))
