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

"""Prompt-asset loading shared across pipeline stages."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final

_PROMPTS_ROOT: Final[Path] = Path(__file__).resolve().parent
_ATTACK_CLASS_DIR: Final[Path] = _PROMPTS_ROOT / "attack_classes"

# Attack-class names are lowercase snake_case (see flosswing/attack_classes.py).
# `attack_class` reaches here from a free-text DB column, so validate against a
# strict allowlist before building a filesystem path — otherwise a value like
# `../../etc/passwd` would traverse out of the attack_classes dir.
_SAFE_ATTACK_CLASS_RE: Final[re.Pattern[str]] = re.compile(r"[a-z0-9_]+")

_GENERIC_FRAGMENT_FALLBACK: Final[str] = (
    "No attack-class-specific guidance has been authored for "
    "`{attack_class}` yet. Apply general code-review principles for "
    "this class, lean toward `confidence='speculative'`, and stop "
    "after a single pass through the scope hint."
)


def load_attack_class_fragment(attack_class: str) -> str:
    """Load the per-attack-class prompt fragment, or a generic fallback.

    `attack_class` is untrusted free text; names that aren't a plain
    snake_case token fall back rather than touching an unexpected path.
    """
    if _SAFE_ATTACK_CLASS_RE.fullmatch(attack_class):
        p = _ATTACK_CLASS_DIR / f"{attack_class}.md"
        if p.is_file():
            return p.read_text(encoding="utf-8")
    return _GENERIC_FRAGMENT_FALLBACK.format(attack_class=attack_class)


__all__ = ["load_attack_class_fragment"]
