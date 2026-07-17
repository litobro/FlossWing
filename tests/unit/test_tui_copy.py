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

"""Copy (mouse-drag) and paste behaviour for the TUI.

These tests drive *real* mouse events (down / move-with-button / up) so they
exercise the actual event pipeline. Fabricating ``Selection`` offsets by hand
would bypass the pipeline that a DataTable can never satisfy (its strips carry
no per-cell offset metadata), which is exactly how an earlier, broken version
of this feature passed its tests while copying the whole table on any drag.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from rich.text import Text
from textual.app import App, ComposeResult
from textual.events import MouseMove
from textual.screen import Screen
from textual.widgets import DataTable, Input

from flosswing.tui.widgets import SelectableDataTable

# The run_id column is narrow but the values are long; on screen they render
# truncated (``01J8ZK…``). Copy must yield the *full* value.
_ROWS = [
    ("01J8ZKQ9ABCDEF0000FULLID", "/repo/foo"),
    ("01J8ZKQ9GHIJKL1111FULLID", "/repo/bar"),
    ("01J8ZKQ9MNOPQR2222FULLID", "/repo/baz"),
    ("01J8ZKQ9STUVWX3333FULLID", "/repo/qux"),
]


def _line(i: int) -> str:
    return f"{_ROWS[i][0]} {_ROWS[i][1]}"


class _TableApp(App[None]):
    def compose(self) -> ComposeResult:
        yield SelectableDataTable(id="t", cursor_type="row")

    def on_mount(self) -> None:
        t = self.query_one(SelectableDataTable)
        t.add_columns("run_id", "path")
        for run_id, path in _ROWS:
            t.add_row(Text(run_id), path)


async def _drag(pilot: object, table: SelectableDataTable, y_from: int, y_to: int) -> None:
    """Simulate a real mouse drag over the table from widget-row y_from to y_to.

    y is a widget-relative row line: 0 = header, 1 = data row 0, etc.
    """
    app = table.app
    await pilot.mouse_down(table, offset=(1, y_from))  # type: ignore[attr-defined]
    step = 1 if y_to >= y_from else -1
    for y in range(y_from, y_to + step, step):
        region = table.region
        sx, sy = region.x + 1, region.y + y
        move = MouseMove(
            widget=table,
            x=1,
            y=y,
            delta_x=0,
            delta_y=step,
            button=1,
            shift=False,
            meta=False,
            ctrl=False,
            screen_x=sx,
            screen_y=sy,
            style=app.screen.get_style_at(sx, sy),
        )
        table.post_message(move)
        await pilot.pause()  # type: ignore[attr-defined]
    await pilot.mouse_up(table, offset=(1, y_to))  # type: ignore[attr-defined]
    await pilot.pause()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_drag_over_rows_copies_only_those_rows_full_values() -> None:
    app = _TableApp()
    async with app.run_test(size=(30, 12)) as pilot:
        await pilot.pause()
        t = app.query_one(SelectableDataTable)
        # Drag over data rows 0..2 (widget y 1..3); row 3 must NOT be included.
        await _drag(pilot, t, 1, 3)
        assert app._clipboard == f"{_line(0)}\n{_line(1)}\n{_line(2)}"


@pytest.mark.asyncio
async def test_drag_within_single_row_copies_that_row() -> None:
    app = _TableApp()
    async with app.run_test(size=(30, 12)) as pilot:
        await pilot.pause()
        t = app.query_one(SelectableDataTable)
        await _drag(pilot, t, 2, 2)  # row 1 only
        assert app._clipboard == _line(1)


@pytest.mark.asyncio
async def test_upward_drag_copies_the_same_span() -> None:
    app = _TableApp()
    async with app.run_test(size=(30, 12)) as pilot:
        await pilot.pause()
        t = app.query_one(SelectableDataTable)
        await _drag(pilot, t, 3, 1)  # drag upward over rows 2..0
        assert app._clipboard == f"{_line(0)}\n{_line(1)}\n{_line(2)}"


@pytest.mark.asyncio
async def test_ctrl_c_recopies_the_dragged_rows() -> None:
    app = _TableApp()
    async with app.run_test(size=(30, 12)) as pilot:
        await pilot.pause()
        t = app.query_one(SelectableDataTable)
        await _drag(pilot, t, 1, 2)
        app._clipboard = ""  # clear, then re-copy via keyboard
        await pilot.press("ctrl+c")
        await pilot.pause()
        assert app._clipboard == f"{_line(0)}\n{_line(1)}"


@pytest.mark.asyncio
async def test_plain_click_moves_cursor_and_copies_nothing() -> None:
    app = _TableApp()
    async with app.run_test(size=(30, 12)) as pilot:
        await pilot.pause()
        t = app.query_one(SelectableDataTable)
        assert t.cursor_row == 0
        await pilot.click(t, offset=(1, 3))  # click data row 2
        await pilot.pause()
        assert t.cursor_row == 2
        assert app._clipboard == ""  # a click is not a drag -> nothing copied


@pytest.mark.asyncio
async def test_input_accepts_pasted_text() -> None:
    class _InputApp(App[None]):
        def compose(self) -> ComposeResult:
            yield Input(id="i")

    app = _InputApp()
    async with app.run_test(size=(40, 6)) as pilot:
        await pilot.pause()
        inp = app.query_one(Input)
        inp.focus()
        await pilot.pause()
        from textual.events import Paste

        inp.post_message(Paste("/home/user/repos/target"))
        await pilot.pause()
        assert inp.value == "/home/user/repos/target"


def test_selectable_datatable_is_a_datatable() -> None:
    # Selection is owned by the widget (see widgets.py), so Textual's own
    # selection machine must stay OFF for it — otherwise a drag collapses to
    # whole-table SELECT_ALL.
    assert issubclass(SelectableDataTable, DataTable)
    assert SelectableDataTable.ALLOW_SELECT is False


# --- ctrl+shift+c binding on the real app (DB-isolated) ----------------------


class _CopyProbeScreen(Screen[None]):
    def compose(self) -> ComposeResult:
        yield SelectableDataTable(id="probe", cursor_type="row")

    def on_mount(self) -> None:
        t = self.query_one(SelectableDataTable)
        t.add_columns("run_id")
        for run_id, _ in _ROWS:
            t.add_row(Text(run_id))


@pytest.fixture()
def _isolated_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from flosswing.state import session as st_session

    monkeypatch.setenv("FLOSSWING_DB_URL", f"sqlite:///{tmp_path}/state.db")
    monkeypatch.setattr(st_session, "_cached_engine", None, raising=False)
    monkeypatch.setattr(st_session, "_cached_session_factory", None, raising=False)


async def _drag_probe(pilot: object, table: SelectableDataTable, y_from: int, y_to: int) -> None:
    await _drag(pilot, table, y_from, y_to)


@pytest.mark.asyncio
async def test_ctrl_shift_c_copies_dragged_rows(_isolated_db: None) -> None:
    from flosswing.tui.app import FlosswingTUI

    app = FlosswingTUI()
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        app.push_screen(_CopyProbeScreen())
        await pilot.pause()
        table = app.screen.query_one("#probe", SelectableDataTable)
        await _drag_probe(pilot, table, 1, 1)  # first data row
        app._clipboard = ""
        await pilot.press("ctrl+shift+c")
        await pilot.pause()
        assert app._clipboard == _ROWS[0][0]


@pytest.mark.asyncio
async def test_ctrl_shift_c_with_no_selection_is_a_noop(_isolated_db: None) -> None:
    from flosswing.tui.app import FlosswingTUI

    app = FlosswingTUI()
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        app.push_screen(_CopyProbeScreen())
        await pilot.pause()
        assert app._clipboard == ""
        await pilot.press("ctrl+shift+c")
        await pilot.pause()
        assert app._clipboard == ""
