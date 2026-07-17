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


def _git_ls_files(repo_root: Path, *, recurse: bool) -> bytes | None:
    """Run `git ls-files -z` (optionally recursing into submodules).

    Returns stdout bytes on success, or None on any failure so the caller can
    fall back. Either form honours the target repo's `.gitignore`.
    """
    argv = ["git", "-C", str(repo_root), "ls-files", "-z"]
    if recurse:
        argv.append("--recurse-submodules")
    label = "git ls-files --recurse-submodules" if recurse else "git ls-files"
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            timeout=_GIT_LS_FILES_TIMEOUT_SECONDS,
            check=False,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as e:
        logger.warning("%s unavailable (%s)", label, e)
        return None
    if proc.returncode != 0:
        logger.warning("%s returned %d", label, proc.returncode)
        return None
    return proc.stdout


def _walk_git(
    repo_root: Path, languages_allowlist: set[str]
) -> Iterator[tuple[Path, str]]:
    """git ls-files -z mode.

    Prefers ``--recurse-submodules`` so initialized submodule files are
    indexed. If that fails (git too old to know the flag, or a timeout on a
    large submodule tree), retries plain ``git ls-files -z`` — which still
    honours ``.gitignore`` — before dropping to the manual walk, which does
    not. This keeps a recurse failure from silently pulling in vendored /
    generated files the operator's `.gitignore` meant to exclude.
    """
    stdout = _git_ls_files(repo_root, recurse=True)
    if stdout is None:
        logger.warning("retrying git ls-files without --recurse-submodules")
        stdout = _git_ls_files(repo_root, recurse=False)
    if stdout is None:
        logger.warning("git ls-files failed; falling back to manual walk")
        yield from _walk_manual(repo_root, languages_allowlist)
        return

    repo_resolved = repo_root.resolve()
    for entry in stdout.split(b"\x00"):
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
        if not resolved.is_relative_to(repo_resolved):
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
                if not resolved.is_relative_to(repo_resolved):
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


def find_uninitialized_submodules(repo_root: Path) -> list[str]:
    """Repo-relative paths of submodules declared in the index but not
    checked out.

    `git ls-files --recurse-submodules` silently omits submodules that have
    no working tree, which would under-cover the scan without warning. This
    surfaces them so the caller can warn the operator.

    Enumerates gitlink entries (mode 160000) via `git ls-files --stage` and
    returns those whose working tree lacks a `.git` entry. Returns [] in
    non-git mode, on any git failure, or when there are no submodules.

    Gating on `.gitmodules` existence is deliberately avoided: gitlink entries
    can be present in the index without a tracked `.gitmodules` (sparse/partial
    checkouts, malformed repos), and skipping the scan there would reintroduce
    the silent under-coverage this helper exists to prevent. The scan runs
    whenever git mode is enabled.
    """
    if not (repo_root / ".git").exists():
        return []
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo_root), "ls-files", "-z", "--stage"],
            capture_output=True,
            timeout=_GIT_LS_FILES_TIMEOUT_SECONDS,
            check=False,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as e:
        logger.warning("git ls-files --stage unavailable (%s)", e)
        return []
    if proc.returncode != 0:
        logger.warning(
            "git ls-files --stage returned %d", proc.returncode
        )
        return []

    skipped: list[str] = []
    for entry in proc.stdout.split(b"\x00"):
        if not entry:
            continue
        # Record layout: "<mode> <object> <stage>\t<path>".
        meta, _tab, path_bytes = entry.partition(b"\t")
        if not path_bytes:
            continue
        if meta.split(b" ", 1)[0] != b"160000":  # not a gitlink
            continue
        try:
            rel = path_bytes.decode("utf-8")
        except UnicodeDecodeError:
            # Can't reliably resolve a non-utf-8 path on disk, but silently
            # dropping it would re-introduce the exact under-coverage this
            # function exists to surface. Report it (display-safe) instead.
            display = path_bytes.decode("utf-8", errors="replace")
            logger.warning(
                "submodule path is not valid utf-8; reporting as skipped: %r",
                display,
            )
            skipped.append(display)
            continue
        # A checked-out submodule work-tree has a `.git` file (or dir).
        if not (repo_root / rel / ".git").exists():
            skipped.append(rel)
    return skipped


__all__ = ["find_uninitialized_submodules", "walk"]
