"""flosswing.index.walker — dual-mode repo walker.

Per docs/specs/2026-06-02-v0.5-symbol-index-design.md § Component
responsibilities flosswing/index/walker.py and design decision #5.

Both walk modes (git ls-files, manual fallback) are exercised. Path
escape and ignore-set behaviour are pinned.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

from flosswing.index import walker


def _make_repo(tmp_path: Path, files: dict[str, str]) -> Path:
    """Materialize a tiny fake repo under tmp_path. Returns repo root."""
    root = tmp_path / "repo"
    root.mkdir()
    for relpath, content in files.items():
        p = root / relpath
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return root


def _make_git_repo(tmp_path: Path, files: dict[str, str]) -> Path:
    root = _make_repo(tmp_path, files)
    (root / ".git").mkdir()
    return root


def test_walker_manual_mode_yields_python_files(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path, {
        "src/example/cli.py": "def f(): pass\n",
        "README.md": "# readme\n",
    })
    files = list(walker.walk(repo, languages_allowlist={"python"}))
    paths = sorted(str(p.relative_to(repo)) for p, _ in files)
    assert paths == ["src/example/cli.py"]
    assert files[0][1] == "python"


def test_walker_manual_mode_filters_by_language_allowlist(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path, {
        "src/main.go": "package main\n",
        "src/main.py": "pass\n",
        "src/main.c": "int main(){return 0;}\n",
    })
    py_only = sorted(
        str(p.relative_to(repo)) for p, _ in walker.walk(
            repo, languages_allowlist={"python"}
        )
    )
    assert py_only == ["src/main.py"]


def test_walker_manual_mode_skips_built_in_ignore_set(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path, {
        "src/keep.py": "pass\n",
        "node_modules/foo/index.js": "module.exports = {};\n",
        "__pycache__/keep.cpython-311.pyc": "binary\n",
        ".venv/lib/site-packages/x.py": "pass\n",
        "target/release/debug.rs": "fn main(){}\n",
    })
    files = sorted(
        str(p.relative_to(repo)) for p, _ in walker.walk(
            repo,
            languages_allowlist={
                "python", "javascript", "rust",
            },
        )
    )
    assert files == ["src/keep.py"]


def test_walker_git_mode_used_when_dot_git_exists(tmp_path: Path) -> None:
    repo = _make_git_repo(tmp_path, {
        "src/example/cli.py": "def f(): pass\n",
        "src/example/util.py": "def g(): pass\n",
        "node_modules/foo/index.js": "x;\n",
    })
    fake_output = b"src/example/cli.py\x00src/example/util.py\x00"
    fake_proc = MagicMock(returncode=0, stdout=fake_output, stderr=b"")
    with patch.object(subprocess, "run", return_value=fake_proc) as m:
        files = sorted(
            str(p.relative_to(repo)) for p, _ in walker.walk(
                repo, languages_allowlist={"python"}
            )
        )
    assert m.called
    args, _ = m.call_args
    cmd = args[0]
    assert cmd[0] == "git"
    assert "ls-files" in cmd
    assert "-z" in cmd
    assert "--recurse-submodules" in cmd
    assert files == ["src/example/cli.py", "src/example/util.py"]


def test_walker_git_mode_falls_back_on_nonzero(tmp_path: Path) -> None:
    """git ls-files non-zero exit → walker falls back to manual walk."""
    repo = _make_git_repo(tmp_path, {
        "src/example/cli.py": "def f(): pass\n",
    })
    fake_proc = MagicMock(returncode=128, stdout=b"", stderr=b"fatal: not a git repo")
    with patch.object(subprocess, "run", return_value=fake_proc):
        files = sorted(
            str(p.relative_to(repo)) for p, _ in walker.walk(
                repo, languages_allowlist={"python"}
            )
        )
    assert files == ["src/example/cli.py"]


def test_walker_git_mode_falls_back_on_timeout(tmp_path: Path) -> None:
    repo = _make_git_repo(tmp_path, {
        "src/example/cli.py": "def f(): pass\n",
    })
    with patch.object(
        subprocess, "run",
        side_effect=subprocess.TimeoutExpired(cmd="git", timeout=30),
    ):
        files = sorted(
            str(p.relative_to(repo)) for p, _ in walker.walk(
                repo, languages_allowlist={"python"}
            )
        )
    assert files == ["src/example/cli.py"]


def test_walker_git_mode_falls_back_on_missing_git_binary(tmp_path: Path) -> None:
    repo = _make_git_repo(tmp_path, {
        "src/example/cli.py": "def f(): pass\n",
    })
    with patch.object(
        subprocess, "run", side_effect=FileNotFoundError("git not on PATH")
    ):
        files = sorted(
            str(p.relative_to(repo)) for p, _ in walker.walk(
                repo, languages_allowlist={"python"}
            )
        )
    assert files == ["src/example/cli.py"]


def test_walker_ignores_paths_outside_repo(tmp_path: Path) -> None:
    """Defensive: even if git lied, we never yield paths outside repo_root."""
    repo = _make_git_repo(tmp_path, {"keep.py": "pass\n"})
    fake_output = b"keep.py\x00../escape.py\x00"
    fake_proc = MagicMock(returncode=0, stdout=fake_output, stderr=b"")
    with patch.object(subprocess, "run", return_value=fake_proc):
        files = sorted(
            str(p.resolve()) for p, _ in walker.walk(
                repo, languages_allowlist={"python"}
            )
        )
    for f in files:
        assert f.startswith(str(repo.resolve()))


def test_walker_handles_empty_allowlist(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path, {"src/main.py": "pass\n"})
    files = list(walker.walk(repo, languages_allowlist=set()))
    assert files == []


def test_walker_git_mode_recurses_submodules(tmp_path: Path) -> None:
    """--recurse-submodules is passed and submodule files are yielded."""
    repo = _make_git_repo(tmp_path, {
        "glue.py": "pass\n",
        "vendor/lib/mod.py": "def f(): pass\n",  # inside a submodule work-tree
    })
    fake_output = b"glue.py\x00vendor/lib/mod.py\x00"
    fake_proc = MagicMock(returncode=0, stdout=fake_output, stderr=b"")
    with patch.object(subprocess, "run", return_value=fake_proc) as m:
        files = sorted(
            str(p.relative_to(repo)) for p, _ in walker.walk(
                repo, languages_allowlist={"python"}
            )
        )
    args, _ = m.call_args
    assert "--recurse-submodules" in args[0]
    assert files == ["glue.py", "vendor/lib/mod.py"]


def test_find_uninitialized_submodules_reports_unchecked_out(
    tmp_path: Path,
) -> None:
    repo = _make_git_repo(tmp_path, {"src/keep.py": "pass\n"})
    (repo / ".gitmodules").write_text("")  # submodules declared
    # ext/bar is a checked-out submodule (has a .git marker file);
    # vendor/foo is declared but never initialized (no working tree).
    (repo / "ext" / "bar").mkdir(parents=True)
    (repo / "ext" / "bar" / ".git").write_text("gitdir: ../.git/modules/bar\n")
    stage_output = (
        b"100644 1111111111111111111111111111111111111111 0\tsrc/keep.py\x00"
        b"160000 2222222222222222222222222222222222222222 0\tvendor/foo\x00"
        b"160000 3333333333333333333333333333333333333333 0\text/bar\x00"
    )
    fake_proc = MagicMock(returncode=0, stdout=stage_output, stderr=b"")
    with patch.object(subprocess, "run", return_value=fake_proc):
        result = walker.find_uninitialized_submodules(repo)
    assert result == ["vendor/foo"]


def test_find_uninitialized_submodules_empty_without_submodules(
    tmp_path: Path,
) -> None:
    repo = _make_git_repo(tmp_path, {"src/keep.py": "pass\n"})
    (repo / ".gitmodules").write_text("")
    stage_output = (
        b"100644 1111111111111111111111111111111111111111 0\tsrc/keep.py\x00"
    )
    fake_proc = MagicMock(returncode=0, stdout=stage_output, stderr=b"")
    with patch.object(subprocess, "run", return_value=fake_proc):
        assert walker.find_uninitialized_submodules(repo) == []


def test_find_uninitialized_submodules_empty_in_non_git_mode(
    tmp_path: Path,
) -> None:
    repo = _make_repo(tmp_path, {"src/keep.py": "pass\n"})  # no .git
    with patch.object(subprocess, "run") as m:
        assert walker.find_uninitialized_submodules(repo) == []
    assert not m.called  # short-circuits before shelling out


def test_find_uninitialized_submodules_empty_on_git_failure(
    tmp_path: Path,
) -> None:
    repo = _make_git_repo(tmp_path, {"src/keep.py": "pass\n"})
    (repo / ".gitmodules").write_text("")
    fake_proc = MagicMock(returncode=128, stdout=b"", stderr=b"fatal")
    with patch.object(subprocess, "run", return_value=fake_proc):
        assert walker.find_uninitialized_submodules(repo) == []


def test_walker_git_mode_excludes_sibling_prefix_escape(
    tmp_path: Path,
) -> None:
    """A symlink resolving into a sibling dir with a shared path prefix
    (repo vs repo-x) must be treated as out-of-tree, not indexed."""
    repo = _make_git_repo(tmp_path, {"keep.py": "pass\n"})
    sibling = tmp_path / "repo-x"  # shares the "repo" string prefix
    sibling.mkdir()
    (sibling / "secret.py").write_text("SECRET = 1\n")
    (repo / "link.py").symlink_to(sibling / "secret.py")
    fake_output = b"keep.py\x00link.py\x00"
    fake_proc = MagicMock(returncode=0, stdout=fake_output, stderr=b"")
    with patch.object(subprocess, "run", return_value=fake_proc):
        resolved = [
            str(p.resolve())
            for p, _ in walker.walk(repo, languages_allowlist={"python"})
        ]
    assert str((sibling / "secret.py").resolve()) not in resolved
    assert resolved == [str((repo / "keep.py").resolve())]


def test_walker_git_mode_retries_without_recurse_on_flag_failure(
    tmp_path: Path,
) -> None:
    """If --recurse-submodules fails, retry plain git ls-files (which still
    honours .gitignore) before dropping to the manual walk."""
    repo = _make_git_repo(tmp_path, {
        "tracked.py": "pass\n",
        "generated.py": "pass\n",  # a manual walk would wrongly include this
    })
    fail = MagicMock(returncode=129, stdout=b"", stderr=b"error: unknown option")
    ok = MagicMock(returncode=0, stdout=b"tracked.py\x00", stderr=b"")
    with patch.object(subprocess, "run", side_effect=[fail, ok]) as m:
        files = sorted(
            str(p.relative_to(repo)) for p, _ in walker.walk(
                repo, languages_allowlist={"python"}
            )
        )
    assert m.call_count == 2
    assert "--recurse-submodules" not in m.call_args_list[1].args[0]
    # git-mode result honoured (generated.py excluded); NOT the manual walk.
    assert files == ["tracked.py"]


def test_find_uninitialized_submodules_skips_without_gitmodules(
    tmp_path: Path,
) -> None:
    """No .gitmodules → no submodules declared → skip the git subprocess."""
    repo = _make_git_repo(tmp_path, {"src/keep.py": "pass\n"})  # no .gitmodules
    with patch.object(subprocess, "run") as m:
        assert walker.find_uninitialized_submodules(repo) == []
    assert not m.called


def test_find_uninitialized_submodules_reports_non_utf8_path(
    tmp_path: Path,
) -> None:
    """A non-utf-8 gitlink path must still surface (display-safe), never be
    silently dropped — that is the exact under-coverage this helper exists
    to prevent."""
    repo = _make_git_repo(tmp_path, {"src/keep.py": "pass\n"})
    (repo / ".gitmodules").write_text("")
    stage_output = (
        b"100644 1111111111111111111111111111111111111111 0\tsrc/keep.py\x00"
        b"160000 2222222222222222222222222222222222222222 0\tvendor/\xff\xfe\x00"
    )
    fake_proc = MagicMock(returncode=0, stdout=stage_output, stderr=b"")
    with patch.object(subprocess, "run", return_value=fake_proc):
        result = walker.find_uninitialized_submodules(repo)
    assert len(result) == 1
    assert "�" in result[0]  # undecodable bytes shown as replacement char
