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

"""Copy (mouse-select) and paste behaviour for the TUI."""

from __future__ import annotations

from pathlib import Path

import pytest
from rich.text import Text
from textual.app import App, ComposeResult
from textual.geometry import Offset
from textual.screen import Screen
from textual.selection import Selection
from textual.widgets import DataTable, Input

from flosswing.tui.widgets import SelectableDataTable

# The run_id column is 6 cells wide but the value is much longer; on screen it
# renders truncated (``01J8ZK…``). Copy must yield the *full* value.
_FULL_ID_0 = "01J8ZKQ9ABCDEF0000FULLID"
_FULL_ID_1 = "01J8ZKQ9GHIJKL1111FULLID"
_FULL_ID_2 = "01J8ZKQ9MNOPQR2222FULLID"


class _TableApp(App[None]):
    def compose(self) -> ComposeResult:
        yield SelectableDataTable(id="t", cursor_type="row")

    def on_mount(self) -> None:
        t = self.query_one(SelectableDataTable)
        t.add_columns("run_id", "path")
        t.add_row(Text(_FULL_ID_0), "/repo/foo")
        t.add_row(Text(_FULL_ID_1), "/repo/bar")
        t.add_row(Text(_FULL_ID_2), "/repo/baz")


def _select(
    app: App[None],
    table: SelectableDataTable,
    start: Offset | None,
    end: Offset | None,
) -> str | None:
    app.screen.selections = {table: Selection(start, end)}
    return app.screen.get_selected_text()


@pytest.mark.asyncio
async def test_selecting_data_rows_copies_full_untruncated_values() -> None:
    app = _TableApp()
    async with app.run_test(size=(30, 12)) as pilot:
        await pilot.pause()
        t = app.query_one(SelectableDataTable)
        # Content line 0 = header, line 1 = row0, line 2 = row1, line 3 = row2.
        text = _select(app, t, Offset(0, 1), Offset(3, 2))
        assert text == f"{_FULL_ID_0} /repo/foo\n{_FULL_ID_1} /repo/bar"


@pytest.mark.asyncio
async def test_selection_touching_a_single_row_returns_the_whole_row() -> None:
    app = _TableApp()
    async with app.run_test(size=(30, 12)) as pilot:
        await pilot.pause()
        t = app.query_one(SelectableDataTable)
        # An x-partial selection on row1 still yields the whole row (row-granular).
        text = _select(app, t, Offset(2, 2), Offset(3, 2))
        assert text == f"{_FULL_ID_1} /repo/bar"


@pytest.mark.asyncio
async def test_selection_including_header_row() -> None:
    app = _TableApp()
    async with app.run_test(size=(30, 12)) as pilot:
        await pilot.pause()
        t = app.query_one(SelectableDataTable)
        text = _select(app, t, Offset(0, 0), Offset(3, 1))
        assert text == f"run_id path\n{_FULL_ID_0} /repo/foo"


@pytest.mark.asyncio
async def test_whole_widget_selection_returns_all_lines() -> None:
    # A drag that spans the entire widget is delivered as Selection(None, None).
    app = _TableApp()
    async with app.run_test(size=(30, 12)) as pilot:
        await pilot.pause()
        t = app.query_one(SelectableDataTable)
        text = _select(app, t, None, None)
        assert text == (
            "run_id path\n"
            f"{_FULL_ID_0} /repo/foo\n"
            f"{_FULL_ID_1} /repo/bar\n"
            f"{_FULL_ID_2} /repo/baz"
        )


@pytest.mark.asyncio
async def test_empty_table_selection_is_none() -> None:
    class _EmptyApp(App[None]):
        def compose(self) -> ComposeResult:
            yield SelectableDataTable(id="t")

    app = _EmptyApp()
    async with app.run_test(size=(30, 12)) as pilot:
        await pilot.pause()
        t = app.query_one(SelectableDataTable)
        # No columns, no rows: nothing to extract.
        assert t.get_selection(Selection(None, None)) is None


@pytest.mark.asyncio
async def test_plain_click_still_moves_row_cursor_and_does_not_select() -> None:
    app = _TableApp()
    async with app.run_test(size=(30, 12)) as pilot:
        await pilot.pause()
        t = app.query_one(SelectableDataTable)
        assert t.cursor_row == 0
        # Click the second data row (widget y: header=0, row0=1, row1=2).
        await pilot.click(t, offset=(1, 2))
        await pilot.pause()
        assert t.cursor_row == 1
        assert app.screen.get_selected_text() is None


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
        # Bracketed paste arrives as a Paste event; Input inserts it.
        from textual.events import Paste

        inp.post_message(Paste("/home/user/repos/target"))
        await pilot.pause()
        assert inp.value == "/home/user/repos/target"


def test_selectable_datatable_is_a_datatable() -> None:
    assert issubclass(SelectableDataTable, DataTable)
    assert SelectableDataTable.ALLOW_SELECT is True


class _CopyProbeScreen(Screen[None]):
    """A throwaway screen with one selectable table, pushed onto the real app
    so the app-level ctrl+shift+c binding is exercised without RunsScreen's DB
    polling re-populating the table underneath us."""

    def compose(self) -> ComposeResult:
        yield SelectableDataTable(id="probe")


@pytest.fixture()
def _isolated_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Point the state DB at an empty temp file so the real RunsScreen mounts
    # cleanly (and deterministically) instead of reading the operator's DB.
    from flosswing.state import session as st_session

    monkeypatch.setenv("FLOSSWING_DB_URL", f"sqlite:///{tmp_path}/state.db")
    monkeypatch.setattr(st_session, "_cached_engine", None, raising=False)
    monkeypatch.setattr(st_session, "_cached_session_factory", None, raising=False)


@pytest.mark.asyncio
async def test_ctrl_shift_c_copies_selection_to_clipboard(_isolated_db: None) -> None:
    from flosswing.tui.app import FlosswingTUI

    app = FlosswingTUI()
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        app.push_screen(_CopyProbeScreen())
        await pilot.pause()
        table = app.screen.query_one("#probe", SelectableDataTable)
        table.add_columns("run_id")
        table.add_row(Text(_FULL_ID_0))
        await pilot.pause()
        app.screen.selections = {table: Selection(Offset(0, 1), Offset(5, 1))}
        await pilot.press("ctrl+shift+c")
        await pilot.pause()
        # copy_to_clipboard records the last-copied text on the app.
        assert app._clipboard == _FULL_ID_0


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
        assert app._clipboard == ""  # no selection -> nothing copied, no crash
