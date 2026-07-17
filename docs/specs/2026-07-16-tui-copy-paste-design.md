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

## Why Textual's built-in selection cannot be reused

Textual's text selection resolves the character under the mouse from a per-cell
`offset` tag embedded in each rendered segment's style (`Compositor.
get_widget_and_offset_at`). `DataTable` renders via strips that carry **no**
such tag, so the compositor returns a `None` offset for every point over the
table, and any real drag is delivered as `Selection(None, None)` — a whole-table
SELECT_ALL. This is exactly why Textual ships `DataTable.ALLOW_SELECT = False`.
Merely flipping the flag and overriding `get_selection` does **not** work: the
override is never fed a per-row span by real mouse input (only fabricated
offsets in a test can reach it). Verified empirically with a real
MouseDown/MouseMove/MouseUp drag.

## Approach: `SelectableDataTable` owns the drag

A small `DataTable` subclass (`flosswing/tui/widgets.py`) that keeps Textual's
selection machine **off** (`ALLOW_SELECT = False`, so the Screen never engages
SELECT_ALL over the table) and implements the drag itself:

- **Row identity** comes from the `row`/`column` metadata Textual already
  embeds in cell segments (`event.style.meta["row"]`) — the same data the hover
  cursor uses, so it is scroll-independent.
- `_on_mouse_down` over a data row captures the mouse and records the anchor
  row. `_on_mouse_move` (with the button held) extends the span and marks the
  drag as real. `_on_mouse_up` releases the mouse and, **only if the pointer
  actually moved**, copies the touched rows.
- **Copy on release + selection record.** On release it builds one line per
  touched row from each row's **full, untruncated** cell values (`get_row`;
  `rich.text.Text` cells flattened via `.plain`), `copy_to_clipboard`s it (OSC
  52), shows a "Copied N row(s)" notification, and records the span in
  `screen.selections` so `ctrl+c` / `ctrl+shift+c` re-copy the same text. The
  recorded selection uses the widget's own content-line coordinate space
  (optional single header line + one line per row) — deliberately independent
  of rendered row heights, so multi-line rows cannot desync the mapping.
- **Row-granular by design.** For a data grid the useful gesture is "drag over
  these rows → copy their real IDs/paths," and this copies the full value
  rather than the truncated on-screen text.

The four `DataTable(...)` construction sites are swapped to
`SelectableDataTable(...)`. Existing `query_one("#id", DataTable)` calls are
unchanged — the subclass satisfies the `DataTable` isinstance check.

Row-cursor click navigation is unaffected: a plain click (no movement) never
starts a copy, so it still moves the cursor and `enter` still opens the detail.

### Alternatives considered

- **Flip `ALLOW_SELECT` + `get_selection`** (the first attempt): does not work —
  real drags collapse to SELECT_ALL (see above).
- **Text-widgets only** (free): leaves the IDs in tables uncopyable —
  under-delivers.
- **Click row + `ctrl+c`**: simplest and robust, but not the drag gesture the
  operator asked for.

## `Ctrl+Shift+C` binding

To honour the terminal-copy muscle memory, `FlosswingTUI` binds
`ctrl+shift+c` → `screen.copy_text` (app-level, active on every screen),
mirroring the built-in `ctrl+c`. Whether the key reaches the app depends on the
terminal: emulators using the Kitty keyboard protocol (kitty, ghostty, foot,
WezTerm, recent Alacritty) forward it and it copies the app selection via OSC
52; terminals that intercept `Ctrl+Shift+C` as their own copy are unaffected
(their native copy fires instead). With no selection the action is a no-op
(`SkipAction`). `ctrl+c` remains the always-works path.

## Terminal fallback (documented, no code)

For users whose terminal intercepts `Ctrl+Shift+C`: hold **Shift** while
dragging to bypass the app's mouse capture and make a real terminal selection,
then `Ctrl+Shift+C` as usual. Caveat: copies raw on-screen text, so truncated
cells copy truncated. Documented in the README.

## Testing

Pilot-driven unit tests in `tests/unit/test_tui_copy.py` drive **real** mouse
events (down → move-with-button → up), never fabricated `Selection` offsets —
fabricated offsets bypass the pipeline a DataTable can't satisfy, which is how
the first, broken version passed its tests:

1. A drag over rows 0–2 copies exactly those rows' full, untruncated values and
   **not** the untouched row 3; a same-row drag copies just that row; an upward
   drag copies the same span.
2. After a drag, `ctrl+c` / `ctrl+shift+c` re-copy the dragged rows.
3. A plain click moves the row cursor and copies **nothing** (click-vs-drag +
   cursor-navigation regression guard).
4. The four screens instantiate `SelectableDataTable` (smoke: mount + query).
5. Paste into a New-Scan `Input` sets the field value (native-paste guard).

`ruff check` and `mypy --strict` must pass over the new module.
