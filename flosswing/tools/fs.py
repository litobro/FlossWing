"""Filesystem read tools: read_file, list_dir.

Pydantic input/output models match docs/tool-contracts.md
§ filesystem (read). Implementations raise FlosswingError subclasses;
the tool_registry wrapper converts them to structured ToolError
payloads for the agent.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Literal

from pydantic import BaseModel

from flosswing.errors import (
    BinaryFileError,
    FileNotFoundInRepoError,
    PathEscapesRepoError,
    PathIsDirectoryError,
    PathNotDirectoryError,
    PathNotFoundError,
)

_SIZE_CAP_BYTES: int = 256 * 1024
_BINARY_SNIFF_BYTES: int = 8 * 1024


class ReadFileInput(BaseModel):
    path: str
    start_line: int | None = None
    end_line: int | None = None


class ReadFileOutput(BaseModel):
    path: str
    content: str
    total_lines: int
    returned_lines: tuple[int, int] | None
    truncated: bool
    sha256: str


class DirEntry(BaseModel):
    name: str
    kind: Literal["file", "dir", "symlink"]
    size_bytes: int | None
    symlink_target: str | None


class ListDirInput(BaseModel):
    path: str = "."
    include_hidden: bool = False


class ListDirOutput(BaseModel):
    path: str
    entries: list[DirEntry]
    truncated: bool


def _resolve_inside_repo(rel: str, repo_root: Path) -> Path:
    """Resolve rel against repo_root; raise PathEscapesRepoError on escape.

    Rejects: absolute paths, paths with `..` segments that escape root,
    symlinks that resolve outside root.
    """
    if Path(rel).is_absolute():
        raise PathEscapesRepoError(rel)
    candidate = (repo_root / rel).resolve(strict=False)
    try:
        candidate.relative_to(repo_root.resolve(strict=False))
    except ValueError as e:
        raise PathEscapesRepoError(rel) from e
    return candidate


def _looks_binary(data: bytes) -> bool:
    return b"\x00" in data[:_BINARY_SNIFF_BYTES]


def read_file(inp: ReadFileInput, *, repo_root: Path) -> ReadFileOutput:
    p = _resolve_inside_repo(inp.path, repo_root)
    if not p.exists():
        raise FileNotFoundInRepoError(f"no such file in repo: {inp.path}")
    if p.is_dir():
        raise PathIsDirectoryError(f"path is a directory: {inp.path}")

    raw = p.read_bytes()
    if _looks_binary(raw):
        raise BinaryFileError(f"binary file refused: {inp.path}")

    text = raw.decode("utf-8", errors="replace")
    lines = text.splitlines(keepends=True)
    total = len(lines)

    if inp.start_line is not None or inp.end_line is not None:
        s = (inp.start_line or 1) - 1
        e = inp.end_line if inp.end_line is not None else total
        s = max(0, s)
        e = min(total, e)
        selected = "".join(lines[s:e])
        returned: tuple[int, int] | None = (s + 1, e) if e > s else None
    else:
        selected = text
        returned = (1, total) if total else None

    truncated = False
    encoded = selected.encode("utf-8")
    if len(encoded) > _SIZE_CAP_BYTES:
        encoded = encoded[:_SIZE_CAP_BYTES]
        selected = encoded.decode("utf-8", errors="replace")
        truncated = True

    return ReadFileOutput(
        path=inp.path,
        content=selected,
        total_lines=total,
        returned_lines=returned,
        truncated=truncated,
        sha256=hashlib.sha256(raw).hexdigest(),
    )


def list_dir(inp: ListDirInput, *, repo_root: Path) -> ListDirOutput:
    p = _resolve_inside_repo(inp.path, repo_root)
    if not p.exists():
        raise PathNotFoundError(f"not found: {inp.path}")
    if not p.is_dir():
        raise PathNotDirectoryError(f"not a directory: {inp.path}")

    entries: list[DirEntry] = []
    repo_root_resolved = repo_root.resolve(strict=False)
    for child in sorted(p.iterdir(), key=lambda c: c.name):
        if not inp.include_hidden and child.name.startswith("."):
            continue
        if child.is_symlink():
            target = child.readlink()
            try:
                resolved_target = (child.parent / target).resolve(strict=False)
                rel = resolved_target.relative_to(repo_root_resolved)
                target_str: str | None = str(rel)
            except (OSError, ValueError):
                target_str = None
            entries.append(
                DirEntry(
                    name=child.name,
                    kind="symlink",
                    size_bytes=None,
                    symlink_target=target_str,
                )
            )
        elif child.is_dir():
            entries.append(
                DirEntry(name=child.name, kind="dir", size_bytes=None, symlink_target=None)
            )
        else:
            entries.append(
                DirEntry(
                    name=child.name,
                    kind="file",
                    size_bytes=child.stat().st_size,
                    symlink_target=None,
                )
            )

    truncated = len(entries) > 1000
    if truncated:
        entries = entries[:1000]

    return ListDirOutput(path=inp.path, entries=entries, truncated=truncated)
