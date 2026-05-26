"""tools/fs.py: read_file and list_dir behavior + error paths."""

from __future__ import annotations

from pathlib import Path

import pytest

from flosswing.errors import (
    BinaryFileError,
    FileNotFoundInRepoError,
    PathEscapesRepoError,
    PathIsDirectoryError,
    PathNotDirectoryError,
    PathNotFoundError,
)
from flosswing.tools.fs import (
    ListDirInput,
    ReadFileInput,
    list_dir,
    read_file,
)


@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "hello.py").write_text("print('hi')\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("# title\n" * 5, encoding="utf-8")
    (tmp_path / "binary.bin").write_bytes(b"\x00\x01\x02\x03" * 32)
    return tmp_path


def test_read_file_happy_path(repo: Path) -> None:
    out = read_file(ReadFileInput(path="src/hello.py"), repo_root=repo)
    assert out.content == "print('hi')\n"
    assert out.total_lines == 1
    assert out.truncated is False


def test_read_file_with_line_range(repo: Path) -> None:
    out = read_file(
        ReadFileInput(path="README.md", start_line=2, end_line=4),
        repo_root=repo,
    )
    assert out.content.count("\n") == 3
    assert out.returned_lines == (2, 4)


def test_read_file_rejects_path_escape(repo: Path) -> None:
    with pytest.raises(PathEscapesRepoError):
        read_file(ReadFileInput(path="../etc/passwd"), repo_root=repo)


def test_read_file_rejects_absolute_path(repo: Path) -> None:
    with pytest.raises(PathEscapesRepoError):
        read_file(ReadFileInput(path="/etc/passwd"), repo_root=repo)


def test_read_file_rejects_binary(repo: Path) -> None:
    with pytest.raises(BinaryFileError):
        read_file(ReadFileInput(path="binary.bin"), repo_root=repo)


def test_read_file_missing(repo: Path) -> None:
    with pytest.raises(FileNotFoundInRepoError):
        read_file(ReadFileInput(path="src/nope.py"), repo_root=repo)


def test_read_file_is_directory(repo: Path) -> None:
    with pytest.raises(PathIsDirectoryError):
        read_file(ReadFileInput(path="src"), repo_root=repo)


def test_read_file_size_cap_truncates(repo: Path) -> None:
    big = repo / "big.txt"
    big.write_text("x" * (300 * 1024), encoding="utf-8")
    out = read_file(ReadFileInput(path="big.txt"), repo_root=repo)
    assert out.truncated is True
    assert len(out.content.encode("utf-8")) <= 256 * 1024


def test_list_dir_happy(repo: Path) -> None:
    out = list_dir(ListDirInput(path="src"), repo_root=repo)
    assert [e.name for e in out.entries] == ["hello.py"]
    assert out.entries[0].kind == "file"


def test_list_dir_default_root(repo: Path) -> None:
    out = list_dir(ListDirInput(), repo_root=repo)
    names = sorted(e.name for e in out.entries)
    assert names == ["README.md", "binary.bin", "src"]


def test_list_dir_rejects_path_escape(repo: Path) -> None:
    with pytest.raises(PathEscapesRepoError):
        list_dir(ListDirInput(path="../"), repo_root=repo)


def test_list_dir_not_found(repo: Path) -> None:
    with pytest.raises(PathNotFoundError):
        list_dir(ListDirInput(path="nope"), repo_root=repo)


def test_list_dir_not_a_directory(repo: Path) -> None:
    with pytest.raises(PathNotDirectoryError):
        list_dir(ListDirInput(path="README.md"), repo_root=repo)
