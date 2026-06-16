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
from textual.widgets import Footer, Header, Markdown

from flosswing.tui import data
from flosswing.tui.data import FindingDetail


def _fence(content: str, lang: str = "") -> str:
    """Wrap content in a code fence long enough that the content cannot
    break out (CommonMark: a fence is closed only by a line of >= as many
    backticks). Uses one more backtick than the longest backtick run inside."""
    longest = 0
    run = 0
    for ch in content:
        if ch == "`":
            run += 1
            longest = max(longest, run)
        else:
            run = 0
    fence = "`" * max(3, longest + 1)
    return f"{fence}{lang}\n{content}\n{fence}"


def _render(d: FindingDetail) -> str:
    sections: list[str] = []

    # Title
    sections.append(f"# {d.title}")

    # Metadata
    meta = f"**{d.attack_class}** · {d.severity}/{d.confidence} · {d.status}"
    location_line = f"*location:* {d.location}"
    if d.reachable:
        meta_block = f"{meta}\n\n{location_line}\n\n*reachability:* {d.reachable}"
    else:
        meta_block = f"{meta}\n\n{location_line}"
    sections.append(meta_block)

    # Description
    desc_text = d.description if d.description else "_(none)_"
    sections.append(f"## Description\n\n{desc_text}")

    # PoC
    if d.poc_code:
        sections.append(f"## PoC\n\n{_fence(d.poc_code)}")

    # PoC result
    if d.poc_result:
        sections.append(f"## PoC result\n\n{_fence(d.poc_result)}")

    # Validation
    if d.verdict:
        validation_section = f"## Validation: {d.verdict}"
        if d.verdict_rationale:
            validation_section += f"\n\n{d.verdict_rationale}"
        sections.append(validation_section)

    # Trace
    if d.call_chain:
        trace_section = "## Trace"
        if d.trace_rationale:
            trace_section += f"\n\n{d.trace_rationale}"
        numbered = "\n".join(f"{i + 1}. {hop}" for i, hop in enumerate(d.call_chain))
        trace_section += f"\n\n{numbered}"
        sections.append(trace_section)

    # Suggested fix
    if d.suggested_fix:
        sections.append(f"## Suggested fix\n\n{d.suggested_fix}")

    return "\n\n".join(sections)


class FindingDetailScreen(Screen[None]):
    BINDINGS: ClassVar[list[BindingType]] = [("escape", "app.pop_screen", "Back")]

    def __init__(self, run_id: str, finding_id: str) -> None:
        super().__init__()
        self._run_id = run_id
        self._finding_id = finding_id
        try:
            d = data.finding_detail(run_id, finding_id)
            self._md: str = _render(d) if d is not None else "_finding not found_"
        except Exception as e:  # DB unreadable — show guidance, never crash the push
            from flosswing import errors

            self._md = f"Cannot load finding: {errors.scrub(str(e))}"

    def compose(self) -> ComposeResult:
        yield Header()
        with VerticalScroll():
            yield Markdown(self._md, id="finding-body", open_links=False)
        yield Footer()

    def on_mount(self) -> None:
        self.sub_title = "finding"
