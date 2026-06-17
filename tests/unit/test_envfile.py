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

"""Unit tests for the optional .env loader (flosswing.envfile)."""

from __future__ import annotations

from pathlib import Path

import pytest

from flosswing.envfile import load_env_file


def _write(tmp_path: Path, body: str) -> Path:
    p = tmp_path / ".env"
    p.write_text(body, encoding="utf-8")
    return p


def test_loads_basic_pairs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FW_A", raising=False)
    monkeypatch.delenv("FW_B", raising=False)
    n = load_env_file(_write(tmp_path, "FW_A=one\nFW_B=two\n"))
    import os

    assert n == 2
    assert os.environ["FW_A"] == "one"
    assert os.environ["FW_B"] == "two"


def test_existing_env_takes_precedence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FW_KEEP", "real")
    n = load_env_file(_write(tmp_path, "FW_KEEP=fromfile\n"))
    import os

    assert n == 0  # not overridden, so not counted
    assert os.environ["FW_KEEP"] == "real"


def test_skips_comments_blanks_and_export(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("FW_C", raising=False)
    body = "# a comment\n\n   \nexport FW_C=three\n"
    n = load_env_file(_write(tmp_path, body))
    import os

    assert n == 1
    assert os.environ["FW_C"] == "three"


def test_strips_matching_quotes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("FW_Q1", raising=False)
    monkeypatch.delenv("FW_Q2", raising=False)
    load_env_file(_write(tmp_path, "FW_Q1='single'\nFW_Q2=\"double\"\n"))
    import os

    assert os.environ["FW_Q1"] == "single"
    assert os.environ["FW_Q2"] == "double"


def test_skips_malformed_lines(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("FW_OK", raising=False)
    # no '=' (malformed), and a non-identifier key — both skipped.
    n = load_env_file(_write(tmp_path, "NOEQUALS\n1BAD=x\nFW_OK=fine\n"))
    import os

    assert n == 1
    assert os.environ["FW_OK"] == "fine"
    assert "1BAD" not in os.environ


def test_missing_file_is_noop(tmp_path: Path) -> None:
    assert load_env_file(tmp_path / "does-not-exist.env") == 0


def test_strips_inline_comment_unquoted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("FW_IC", raising=False)
    load_env_file(_write(tmp_path, "FW_IC=value  # trailing comment\n"))
    import os

    assert os.environ["FW_IC"] == "value"


def test_strips_inline_comment_after_quoted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("FW_ICQ", raising=False)
    load_env_file(_write(tmp_path, 'FW_ICQ="sk-secret"  # main key\n'))
    import os

    assert os.environ["FW_ICQ"] == "sk-secret"


def test_bare_hash_without_space_is_kept(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("FW_HASH", raising=False)
    load_env_file(_write(tmp_path, "FW_HASH=pa#ss\n"))
    import os

    assert os.environ["FW_HASH"] == "pa#ss"


def test_allowed_keys_filters(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("FW_KEEP_ME", raising=False)
    monkeypatch.delenv("FW_DROP_ME", raising=False)
    n = load_env_file(
        _write(tmp_path, "FW_KEEP_ME=yes\nFW_DROP_ME=no\n"),
        allowed_keys=frozenset({"FW_KEEP_ME"}),
    )
    import os

    assert n == 1
    assert os.environ["FW_KEEP_ME"] == "yes"
    assert "FW_DROP_ME" not in os.environ
