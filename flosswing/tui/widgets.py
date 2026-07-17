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
    """A ``DataTable`` whose rows can be mouse-selected and copied.

    Textual disables selection on ``DataTable`` (``ALLOW_SELECT = False``) because
    its generic text extraction only handles widgets that render to plain text,
    not strip-rendered grids. We re-enable it and extract text ourselves.

    Selection is **row-granular**: a drag that touches any part of a row yields
    that row's full, *untruncated* cell values (on-screen cells are often
    truncated, e.g. ``01J8ZK…``, which would be useless to copy). Content line 0
    is the header; each height-1 data row follows.
    """

    ALLOW_SELECT: ClassVar[bool] = True

    def _content_lines(self) -> list[str]:
        lines: list[str] = []
        if self.show_header and self.ordered_columns:
            header = _COLUMN_DELIM.join(_cell_text(c.label) for c in self.ordered_columns)
            lines.extend([header] * self.header_height)
        for row in self.ordered_rows:
            values = self.get_row(row.key)
            lines.append(_COLUMN_DELIM.join(_cell_text(v) for v in values))
        return lines

    def get_selection(self, selection: Selection) -> tuple[str, str] | None:
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
