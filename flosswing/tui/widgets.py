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

"""Shared TUI widgets."""

from __future__ import annotations

from typing import Any, ClassVar

from rich.text import Text
from textual import events
from textual.geometry import Offset
from textual.selection import Selection
from textual.widgets import DataTable

_COLUMN_DELIM = " "


def _cell_text(value: Any) -> str:
    """Flatten a stored cell value to plain text for the clipboard.

    Cells carrying untrusted repo text are stored as ``rich.text.Text`` (see the
    screen modules); ``.plain`` drops the styling. Everything else is stringified.
    """
    if isinstance(value, Text):
        return value.plain
    return str(value)


class SelectableDataTable(DataTable[Any]):
    """A ``DataTable`` whose rows can be mouse-dragged to copy their contents.

    Textual's built-in text selection cannot work here: a ``DataTable`` renders
    via strips that carry no per-character offset metadata, so the compositor
    resolves every point over the table to a ``None`` offset and any real drag
    collapses to a whole-table SELECT_ALL. So we keep Textual's selection
    machine off (``ALLOW_SELECT = False``) and own the drag ourselves.

    On mouse-down over a data row we capture the mouse and remember the row; each
    drag move extends the span (rows are identified by the ``row``/``column``
    metadata Textual already embeds in cell segments — the same data the hover
    cursor uses, so it is scroll-independent). On release we copy the touched
    rows' **full, untruncated** values (on-screen cells are often truncated,
    e.g. ``01J8ZK…``) to the clipboard and record the selection so ``ctrl+c`` /
    ``ctrl+shift+c`` re-copy it. A plain click (no movement) is left untouched,
    so row-cursor navigation still works.
    """

    ALLOW_SELECT: ClassVar[bool] = False

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._drag_from_row: int | None = None
        self._drag_to_row: int = 0
        self._dragged: bool = False

    # -- text model -----------------------------------------------------------

    def _has_header(self) -> bool:
        return bool(self.show_header and self.ordered_columns)

    def _content_lines(self) -> list[str]:
        """One text line per selectable content line: an optional single header
        line followed by one line per data row (in display order). This is our
        own coordinate space — deliberately independent of rendered row heights."""
        lines: list[str] = []
        if self._has_header():
            lines.append(_COLUMN_DELIM.join(_cell_text(c.label) for c in self.ordered_columns))
        for row in self.ordered_rows:
            values = self.get_row(row.key)
            lines.append(_COLUMN_DELIM.join(_cell_text(v) for v in values))
        return lines

    def get_selection(self, selection: Selection) -> tuple[str, str] | None:
        """Return the text under a selection previously set by our own drag.

        Used by ``ctrl+c`` / ``ctrl+shift+c`` (Textual's copy action reads
        ``screen.selections`` and calls this)."""
        lines = self._content_lines()
        if not lines:
            return None
        last = len(lines) - 1
        start = selection.start
        end = selection.end
        y0 = 0 if start is None else start.y
        y1 = last if end is None else end.y
        y0 = max(0, min(y0, last))
        y1 = max(0, min(y1, last))
        if y1 < y0:
            y0, y1 = y1, y0
        return "\n".join(lines[y0 : y1 + 1]), "\n"

    # -- drag handling --------------------------------------------------------

    def _event_row(self, event: events.MouseEvent) -> int | None:
        """Data-row index under the mouse, ``-1`` for the header, ``None`` if the
        pointer is not over a cell."""
        style = event.style
        meta = style.meta if style is not None else {}
        row = meta.get("row")
        return row if isinstance(row, int) else None

    async def _on_mouse_down(self, event: events.MouseDown) -> None:
        await super()._on_mouse_down(event)
        row = self._event_row(event)
        if row is None or row < 0:
            return  # header / outside a data row — leave click & cursor alone
        self.capture_mouse()
        self._drag_from_row = row
        self._drag_to_row = row
        self._dragged = False

    def _on_mouse_move(self, event: events.MouseMove) -> None:
        super()._on_mouse_move(event)  # preserve the hover cursor
        if self._drag_from_row is None or not event.button:
            return
        row = self._event_row(event)
        if row is None:
            return
        self._dragged = True
        self._drag_to_row = max(row, 0)  # clamp a drag into the header to row 0

    async def _on_mouse_up(self, event: events.MouseUp) -> None:
        await super()._on_mouse_up(event)
        if self._drag_from_row is None:
            return
        self.capture_mouse(False)
        from_row, self._drag_from_row = self._drag_from_row, None
        if not self._dragged:
            return  # a click, not a drag — nothing to copy
        lo, hi = sorted((from_row, self._drag_to_row))
        offset = 1 if self._has_header() else 0
        text = "\n".join(self._content_lines()[offset + lo : offset + hi + 1])
        if not text:
            return
        self.app.copy_to_clipboard(text)
        self.screen.selections = {
            self: Selection(Offset(0, offset + lo), Offset(2**31, offset + hi))
        }
        n = hi - lo + 1
        self.notify(f"Copied {n} row{'s' if n != 1 else ''} to clipboard")
