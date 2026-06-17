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
from pathlib import Path


def load_env_file(path: Path) -> int:
    """Apply ``KEY=VALUE`` lines from ``path`` to ``os.environ`` (setdefault).

    Skips blank lines, ``#`` comments, an optional leading ``export``, and any
    malformed line (no ``=`` or a non-identifier key). A single layer of matching
    surrounding single/double quotes is stripped from values. A missing or
    unreadable file is a no-op. Returns the number of variables newly set (those
    not already present in the environment); never logs or returns any value.
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
        key, sep, value = line.partition("=")
        if not sep:
            continue  # malformed: no '='
        key = key.strip()
        if not key.isidentifier():
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        if key not in os.environ:
            os.environ[key] = value
            set_count += 1
    return set_count
