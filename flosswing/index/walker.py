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

"""Repo walker for the symbol-index build.

Per docs/specs/2026-06-02-v0.5-symbol-index-design.md § Component
responsibilities flosswing/index/walker.py and design decision #5:

- If <repo>/.git/ exists, shell out to `git ls-files -z` and use that.
  Honours the target repo's .gitignore for free; git is already required
  to clone any target.
- Otherwise, fall back to a manual walk with a small built-in ignore list.

The walker yields (path: Path, language: str) tuples filtered by the
languages_allowlist. Binary detection / size caps are NOT here — the
extractor handles those at parse time.
"""

from __future__ import annotations

import logging
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import Final

from flosswing.index.grammars import language_for_path

logger = logging.getLogger(__name__)

_GIT_LS_FILES_TIMEOUT_SECONDS: Final[int] = 30

# Per design decision #5: built-in ignore set for the manual-walk fallback.
_MANUAL_IGNORE_DIRS: Final[frozenset[str]] = frozenset({
    ".git",
    "node_modules",
    "target",
    "build",
    "dist",
    "__pycache__",
    ".venv",
    "venv",
    ".tox",
    ".mypy_cache",
})


def walk(
    repo_root: Path,
    *,
    languages_allowlist: set[str],
) -> Iterator[tuple[Path, str]]:
    """Yield (absolute_path, language) tuples for in-scope files.

    Filters out files whose extension does not map to a language in
    `languages_allowlist`. The allowlist is the v0.5 contract surface —
    callers (typically `build.build_index`) pass the language set from
    Recon's `recon_artifacts.languages_json`.
    """
    if not languages_allowlist:
        return
    use_git = (repo_root / ".git").exists()
    if use_git:
        yield from _walk_git(repo_root, languages_allowlist)
    else:
        yield from _walk_manual(repo_root, languages_allowlist)


def _walk_git(
    repo_root: Path, languages_allowlist: set[str]
) -> Iterator[tuple[Path, str]]:
    """git ls-files -z mode."""
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo_root), "ls-files", "-z"],
            capture_output=True,
            timeout=_GIT_LS_FILES_TIMEOUT_SECONDS,
            check=False,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as e:
        logger.warning(
            "git ls-files unavailable (%s); falling back to manual walk", e
        )
        yield from _walk_manual(repo_root, languages_allowlist)
        return
    if proc.returncode != 0:
        logger.warning(
            "git ls-files returned %d; falling back to manual walk",
            proc.returncode,
        )
        yield from _walk_manual(repo_root, languages_allowlist)
        return

    repo_resolved = repo_root.resolve()
    for entry in proc.stdout.split(b"\x00"):
        if not entry:
            continue
        try:
            rel = entry.decode("utf-8")
        except UnicodeDecodeError:
            logger.warning("skipping non-utf-8 path entry from git ls-files")
            continue
        abs_path = repo_root / rel
        try:
            resolved = abs_path.resolve()
        except (OSError, RuntimeError):
            continue
        if not str(resolved).startswith(str(repo_resolved)):
            logger.warning("skipping out-of-tree path %r", rel)
            continue
        if not abs_path.is_file():
            continue
        lang = language_for_path(rel)
        if lang is None or lang not in languages_allowlist:
            continue
        yield abs_path, lang


def _walk_manual(
    repo_root: Path, languages_allowlist: set[str]
) -> Iterator[tuple[Path, str]]:
    """Manual walk with the built-in ignore set."""
    repo_resolved = repo_root.resolve()
    stack: list[Path] = [repo_root]
    while stack:
        current = stack.pop()
        try:
            children = list(current.iterdir())
        except (PermissionError, OSError):
            continue
        for child in children:
            if child.is_dir():
                if child.name in _MANUAL_IGNORE_DIRS:
                    continue
                try:
                    resolved = child.resolve()
                except (OSError, RuntimeError):
                    continue
                if not str(resolved).startswith(str(repo_resolved)):
                    continue
                stack.append(child)
                continue
            if not child.is_file():
                continue
            try:
                rel = str(child.relative_to(repo_root))
            except ValueError:
                continue
            lang = language_for_path(rel)
            if lang is None or lang not in languages_allowlist:
                continue
            yield child, lang


__all__ = ["walk"]
