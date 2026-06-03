"""grep tool backed by ripgrep (system binary).

Per docs/tool-contracts.md § search: regex pattern, optional path glob,
case-insensitive flag, max_results (hard ceiling 500), context_lines.
Returns structured matches; truncates at max_results.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from pydantic import BaseModel

from flosswing.errors import (
    FlosswingError,
    InvalidRegexError,
    PatternTooBroadError,
)

_HARD_RESULT_CEILING: int = 500


class GrepInput(BaseModel):
    pattern: str
    path_glob: str | None = None
    case_insensitive: bool = False
    max_results: int = 50
    context_lines: int = 0


class GrepMatch(BaseModel):
    path: str
    line_number: int
    line: str
    context_before: list[str]
    context_after: list[str]


class GrepOutput(BaseModel):
    matches: list[GrepMatch]
    truncated: bool
    files_searched: int


class RipgrepMissingError(FlosswingError):
    code = "ripgrep_unavailable"
    retryable = False


def _is_pattern_too_broad(pattern: str, has_glob: bool) -> bool:
    # Mirrors the contract: refuse a bare ".*" with no glob to protect
    # the token budget. Other broad patterns flow through.
    stripped = pattern.strip()
    if has_glob:
        return False
    return stripped in {".*", "^.*$", ".+", "^.+$"}


def grep(inp: GrepInput, *, repo_root: Path) -> GrepOutput:
    if _is_pattern_too_broad(inp.pattern, inp.path_glob is not None):
        raise PatternTooBroadError(
            f"pattern {inp.pattern!r} is too broad without a path_glob"
        )

    cap = min(max(1, inp.max_results), _HARD_RESULT_CEILING)
    rg = shutil.which("rg")
    if rg is None:
        raise RipgrepMissingError("`rg` (ripgrep) not found on PATH")

    cmd: list[str] = [
        rg,
        "--json",
        "--no-heading",
        "--color=never",
        f"--max-count={cap}",
    ]
    if inp.case_insensitive:
        cmd.append("-i")
    if inp.context_lines > 0:
        cmd.extend(["-C", str(inp.context_lines)])
    if inp.path_glob:
        cmd.extend(["-g", inp.path_glob])
    cmd.extend(["-e", inp.pattern, "."])

    proc = subprocess.run(
        cmd,
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode == 2:
        # ripgrep returns 2 on usage / regex errors.
        raise InvalidRegexError(proc.stderr.strip() or "invalid regex")

    matches: list[GrepMatch] = []
    files_searched = 0
    truncated = False

    pending_before: dict[str, list[str]] = {}
    last_match_per_file: dict[str, GrepMatch] = {}

    for raw_line in proc.stdout.splitlines():
        if not raw_line:
            continue
        try:
            event = json.loads(raw_line)
        except json.JSONDecodeError:
            continue
        etype = event.get("type")
        data = event.get("data", {})
        if etype == "begin":
            files_searched += 1
            continue
        if etype == "context":
            path = data.get("path", {}).get("text", "")
            line_text = data.get("lines", {}).get("text", "").rstrip("\n")
            line_no = data.get("line_number", 0)
            last = last_match_per_file.get(path)
            if last is not None and line_no > last.line_number:
                last.context_after.append(line_text)
            else:
                pending_before.setdefault(path, []).append(line_text)
            continue
        if etype == "match":
            if len(matches) >= cap:
                truncated = True
                continue
            path = data.get("path", {}).get("text", "")
            line_text = data.get("lines", {}).get("text", "").rstrip("\n")
            line_no = data.get("line_number", 0)
            before = pending_before.pop(path, [])
            m = GrepMatch(
                # removeprefix not lstrip: "./.github/x" must stay ".github/x"
                # (lstrip("./") is a character-set strip that would eat the dot).
                path=path.removeprefix("./"),
                line_number=line_no,
                line=line_text[:500],
                context_before=before[-inp.context_lines :] if inp.context_lines else [],
                context_after=[],
            )
            matches.append(m)
            last_match_per_file[path] = m

    return GrepOutput(matches=matches, truncated=truncated, files_searched=files_searched)
