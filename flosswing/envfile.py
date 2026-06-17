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

"""Optional ``.env`` loading for operator convenience.

This is an explicit, operator-opt-in convenience (the credential policy in
``CLAUDE.md`` / ``ARCHITECTURE.md`` was amended to permit a local ``.env``).
Two invariants keep it safe:

- **The real process environment always wins.** Values from the file are applied
  with ``setdefault`` semantics, so a ``.env`` can never override a variable that
  is already set — explicit ``export``/CI environment is never shadowed.
- **No value is ever logged, returned, or persisted.** The loader only mutates
  ``os.environ`` and returns a *count* of variables newly set. The file must stay
  out of version control (it is ``.gitignore``d).
"""

from __future__ import annotations

import os
import re
from pathlib import Path

# An inline comment on an unquoted value is a ``#`` introduced by whitespace
# (a bare ``#`` with no preceding space is kept, e.g. ``pass#word``).
_INLINE_COMMENT = re.compile(r"\s#")


def _parse_value(raw: str) -> str:
    """Parse the right-hand side of a ``KEY=`` line into its value.

    Strips a single layer of matching surrounding quotes; for a quoted value,
    anything after the closing quote (e.g. an inline comment) is dropped. For an
    unquoted value, an inline ``#`` comment introduced by whitespace is dropped.
    """
    value = raw.strip()
    if value[:1] in ("'", '"'):
        quote = value[0]
        end = value.find(quote, 1)
        return value[1:end] if end != -1 else value[1:]
    match = _INLINE_COMMENT.search(value)
    if match is not None:
        value = value[: match.start()]
    return value.strip()


def load_env_file(path: Path, allowed_keys: frozenset[str] | None = None) -> int:
    """Apply ``KEY=VALUE`` lines from ``path`` to ``os.environ`` (setdefault).

    Skips blank lines, full-line and inline ``#`` comments, an optional leading
    ``export``, and any malformed line (no ``=`` or a non-identifier key). A
    single layer of matching surrounding quotes is stripped from values. If
    ``allowed_keys`` is given, only those variable names are applied (everything
    else is ignored) — used to restrict the default ``.env`` auto-load to known
    credential/config keys. A missing or unreadable file is a no-op. Returns the
    number of variables newly set (those not already present in the environment);
    never logs or returns any variable name or value.
    """
    if not path.is_file():
        return 0
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return 0

    set_count = 0
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        key, sep, raw_value = line.partition("=")
        if not sep:
            continue  # malformed: no '='
        key = key.strip()
        if not key.isidentifier():
            continue
        if allowed_keys is not None and key not in allowed_keys:
            continue
        if key not in os.environ:
            os.environ[key] = _parse_value(raw_value)
            set_count += 1
    return set_count
