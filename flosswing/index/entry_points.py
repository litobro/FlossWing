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

"""Deterministic entry-point post-pass.

Per docs/specs/2026-06-02-v0.5-symbol-index-design.md § Component
responsibilities flosswing/index/entry_points.py and design decision #3.

Runs after IndexBuild has collected all symbols + call sites for a run.
Heuristics are deliberately simple — no agent involved, no contract
change.

v0.5 ships:
- cli: a symbol named `main` (any v1 language).
- http: Python decorator scan for Flask/FastAPI-style routes (regex over
  file contents — placeholder coverage; framework-specific tightening
  is future work).
- deserializer: callers of known unsafe Python loader names per the
  call-site list.
- exported and ipc: not implemented in v0.5; the schema's CHECK
  constraint already permits the kinds so adding them later requires
  no migration.
"""

from __future__ import annotations

import re
from typing import Final

from pydantic import BaseModel

from flosswing.index.extractor import CallSiteRow, SymbolRow


class EntryPointRow(BaseModel):
    symbol: str
    file: str
    line: int
    kind: str  # 'cli' | 'http' | 'exported' | 'deserializer' | 'ipc'
    attacker_controlled_input: bool
    notes: str


# Python unsafe-deserializer callee names. These are the rightmost
# identifier in attribute calls (e.g. yaml.load -> 'load',
# marshal.loads -> 'loads'). The list intentionally stays short — the
# heuristic is a hint, not a complete taxonomy.
_PY_UNSAFE_DESERIALIZER_NAMES: Final[frozenset[str]] = frozenset({
    "load",      # yaml.load (unsafe loader default)
    "loads",     # marshal.loads, the binary-object loader's loads
    "Unpickler", # the binary-object loader's Unpickler class
})

_CLI_MAIN_LANGUAGES: Final[frozenset[str]] = frozenset({
    "python", "go", "rust", "java", "c", "cpp",
})

_HTTP_DECORATOR_REGEX: Final[re.Pattern[str]] = re.compile(
    r"^\s*@\s*\w+\s*\.\s*(?:route|get|post|put|patch|delete|head|options)\s*\(",
    re.MULTILINE,
)


def detect(
    *,
    symbols: list[SymbolRow],
    call_sites: list[CallSiteRow],
    file_contents: dict[str, str],
) -> list[EntryPointRow]:
    """Run all v0.5 heuristics, return EntryPointRows.

    `file_contents` maps repo-relative-file -> decoded utf-8 text; the
    caller (build.py) populates it on demand for files that contain a
    symbol the http heuristic wants to inspect. Empty dict is fine.
    """
    rows: list[EntryPointRow] = []
    rows.extend(_detect_cli_main(symbols))
    rows.extend(_detect_http_flask_decorator(symbols, file_contents))
    rows.extend(_detect_deserializer(symbols, call_sites))
    return rows


def _detect_cli_main(symbols: list[SymbolRow]) -> list[EntryPointRow]:
    out: list[EntryPointRow] = []
    for s in symbols:
        if s.symbol == "main" and s.language in _CLI_MAIN_LANGUAGES:
            out.append(EntryPointRow(
                symbol=s.symbol,
                file=s.file,
                line=s.line_start,
                kind="cli",
                attacker_controlled_input=True,
                notes=f"`main` in {s.language}",
            ))
    return out


def _detect_http_flask_decorator(
    symbols: list[SymbolRow],
    file_contents: dict[str, str],
) -> list[EntryPointRow]:
    """Flag any Python function whose preceding lines have a route decorator."""
    out: list[EntryPointRow] = []
    for s in symbols:
        if s.language != "python":
            continue
        if s.kind not in ("function", "method"):
            continue
        text = file_contents.get(s.file)
        if text is None:
            continue
        lines = text.splitlines()
        # Include up to three preceding lines plus line_start itself. The
        # slice is `[start_idx : s.line_start]` (not `- 1`) so we catch
        # both possible extractor behaviours: tree-sitter-python may
        # report `line_start` at the `def` keyword (decorator strictly
        # above) or at the `decorated_definition` (decorator co-located
        # with `line_start`). Deviation from the plan-spec's slice noted
        # in the Task 7 report.
        start_idx = max(0, s.line_start - 4)
        prologue = "\n".join(lines[start_idx:s.line_start])
        if _HTTP_DECORATOR_REGEX.search(prologue):
            out.append(EntryPointRow(
                symbol=s.symbol,
                file=s.file,
                line=s.line_start,
                kind="http",
                attacker_controlled_input=True,
                notes="route decorator detected above def",
            ))
    return out


def _detect_deserializer(
    symbols: list[SymbolRow],
    call_sites: list[CallSiteRow],
) -> list[EntryPointRow]:
    """Flag callers of known unsafe Python deserializer names."""
    out: list[EntryPointRow] = []
    sym_by_fqn = {s.fully_qualified_name: s for s in symbols}
    seen: set[tuple[str, str]] = set()
    for cs in call_sites:
        if cs.callee_text not in _PY_UNSAFE_DESERIALIZER_NAMES:
            continue
        caller = sym_by_fqn.get(cs.caller_fqn)
        if caller is None:
            continue
        key = (caller.fully_qualified_name, cs.callee_text)
        if key in seen:
            continue
        seen.add(key)
        out.append(EntryPointRow(
            symbol=caller.symbol,
            file=caller.file,
            line=caller.line_start,
            kind="deserializer",
            attacker_controlled_input=True,
            notes=f"calls unsafe loader {cs.callee_text!r} at line {cs.line}",
        ))
    return out


__all__ = ["EntryPointRow", "detect"]
