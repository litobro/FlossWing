"""tools/search.py: grep behavior + error paths.

Skipped if `rg` (ripgrep) is not installed.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from flosswing.errors import InvalidRegexError, PatternTooBroadError
from flosswing.tools.search import GrepInput, grep

pytestmark = pytest.mark.skipif(
    shutil.which("rg") is None, reason="ripgrep not installed"
)


@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    (tmp_path / "a.py").write_text("def alpha():\n    pass\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("def beta():\n    return 1\n", encoding="utf-8")
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "c.go").write_text("func gamma() {}\n", encoding="utf-8")
    return tmp_path


def test_grep_finds_matches(repo: Path) -> None:
    out = grep(GrepInput(pattern=r"def \w+"), repo_root=repo)
    paths = sorted({m.path for m in out.matches})
    assert paths == ["a.py", "b.py"]
    assert out.truncated is False


def test_grep_path_glob_filters(repo: Path) -> None:
    out = grep(GrepInput(pattern=r"\w+", path_glob="**/*.go"), repo_root=repo)
    paths = {m.path for m in out.matches}
    assert paths == {"sub/c.go"}


def test_grep_context_lines(repo: Path) -> None:
    out = grep(
        GrepInput(pattern=r"def alpha", context_lines=1),
        repo_root=repo,
    )
    assert any("pass" in c for m in out.matches for c in m.context_after)


def test_grep_invalid_regex(repo: Path) -> None:
    with pytest.raises(InvalidRegexError):
        grep(GrepInput(pattern=r"["), repo_root=repo)


def test_grep_pattern_too_broad(repo: Path) -> None:
    with pytest.raises(PatternTooBroadError):
        grep(GrepInput(pattern=r".*"), repo_root=repo)


def test_grep_max_results_cap(repo: Path) -> None:
    out = grep(GrepInput(pattern=r"def \w+", max_results=1), repo_root=repo)
    assert len(out.matches) == 1
    assert out.truncated is True
