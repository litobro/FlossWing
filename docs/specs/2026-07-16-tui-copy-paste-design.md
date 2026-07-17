# TUI copy & paste — design

**Date:** 2026-07-16
**Status:** approved (scope confirmed with operator)
**Scope:** `flosswing/tui/` only. No tool-contract, schema, or sandbox surface is touched. No new dependencies.

## Problem

Users want to copy text out of the FlossWing TUI (run IDs, finding IDs, repo
paths, PoC bodies) and paste into the New-Scan input fields. The reported
friction is muscle-memory `Ctrl+Shift+C`, which is a *terminal-emulator*
shortcut: it copies the terminal's own selection. A Textual app captures the
mouse, so a normal drag never produces a terminal selection, and most
terminals never forward `Ctrl+Shift+C` to the app — so it cannot be rebound
inside FlossWing.

## What already works (no code)

Textual 8.2 provides the whole mechanism:

- `Screen` binds `Ctrl+C` / `⌘+C` → `copy_text`, which OSC-52-copies the
  current selection (works over SSH) and *falls through to the existing quit
  hint* when nothing is selected.
- `Markdown`, `Static`, and `Label` are `ALLOW_SELECT = True`, so the
  **finding-detail** screen (a `Markdown`) and **run-detail**'s `Static`
  blocks are already drag-selectable and copyable.
- `Input` widgets accept paste natively (bracketed paste / `Ctrl+V`), so paste
  into New-Scan's repo-path / formats / budget fields already works.

## The one real gap: DataTable

`runs`, `findings`, `sessions`, and the `run_detail` hunt-table are
`DataTable`, which ships `ALLOW_SELECT = False`. That is deliberate: Textual's
generic `Widget.get_selection` only extracts text from widgets that render to
plain `Text`/`Content`, and `DataTable` renders via strips. Simply flipping the
flag copies an empty string. And because table cells are visually truncated
(`01J8ZK…`), even a hypothetical char-precise selection would copy a broken ID.

## Approach: `SelectableDataTable`

A small `DataTable` subclass (`flosswing/tui/widgets.py`):

- `ALLOW_SELECT = True`.
- Overrides `get_selection(selection)` to return `(text, "\n")`:
  - Builds a plain-text, one-line-per-content-line view of the table:
    `header_height` header lines (column labels) followed by one line per data
    row, using each row's **full, untruncated** cell values from `get_row`
    (cells stored as `rich.text.Text` are flattened via `.plain`), columns
    joined by a single space.
  - Maps the selection's **vertical span** (`start.y … end.y`, `None` meaning
    the open end) onto those content lines and returns the touched lines.
- **Row-granular, not char-granular by design.** For a data grid the useful
  gesture is "drag over these rows → copy their real IDs/paths." This copies
  the full value rather than the truncated on-screen text. Content line 0 is
  the header (confirmed empirically against Textual's selection coordinate
  space); rows are height 1 in all four tables.

The four `DataTable(...)` construction sites are swapped to
`SelectableDataTable(...)`. Existing `query_one("#id", DataTable)` calls are
unchanged — the subclass satisfies the `DataTable` isinstance check.

Row-cursor click navigation is unaffected: text selection only activates on a
drag; a plain click still moves the cursor and `enter` still opens the detail.

### Alternatives considered

- **Text-widgets only** (free): leaves the IDs in tables uncopyable —
  under-delivers.
- **Char-precise cell selection**: brittle over a virtualized / truncated /
  scrolling grid and copies truncated text; Textual itself punted on it.

## Terminal fallback (documented, no code)

For users who prefer their terminal's native copy: hold **Shift** while
dragging to bypass the app's mouse capture and make a real terminal selection,
then `Ctrl+Shift+C` as usual. Caveat: copies raw on-screen text, so truncated
cells copy truncated. This is added to the TUI docs, not implemented.

## Testing

Pilot-driven unit tests in `tests/unit/test_tui_copy.py`:

1. `SelectableDataTable.get_selection` with constructed `Selection` offsets
   returns full untruncated row values for a partial row span, the header for a
   header-spanning selection, and all lines for a whole-widget (`None`/`None`)
   selection — driven through `screen.get_selected_text()` so the real code
   path is exercised.
2. A plain click still moves the row cursor and does not start a selection
   (cursor navigation regression guard).
3. The four screens instantiate `SelectableDataTable` (smoke: mount + query).
4. Paste into a New-Scan `Input` sets the field value (native-paste guard).

`ruff check` and `mypy --strict` must pass over the new module.
