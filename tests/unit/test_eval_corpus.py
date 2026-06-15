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

from __future__ import annotations

from pathlib import Path

import pytest

from flosswing.errors import EvalConfigError
from flosswing.eval import corpus


def _write(tmp_path: Path, name: str, body: str) -> Path:
    p = tmp_path / f"{name}.toml"
    p.write_text(body, encoding="utf-8")
    return p


_VALID = """
name = "demo"
repo = "demo"
description = "a demo"

[[vuln]]
id = "v1"
file = "src/a.py"
line_start = 10
line_end = 12
attack_class = "command_injection"
"""


def test_load_manifest_valid(tmp_path: Path) -> None:
    entry = corpus.load_manifest(_write(tmp_path, "demo", _VALID))
    assert entry.name == "demo"
    assert entry.repo == "demo"
    assert len(entry.vulns) == 1
    v = entry.vulns[0]
    assert v.id == "v1"
    assert v.attack_class == "command_injection"
    assert v.tolerance == corpus.DEFAULT_TOLERANCE  # default applied


def test_load_manifest_name_must_match_stem(tmp_path: Path) -> None:
    body = _VALID.replace('name = "demo"', 'name = "other"')
    with pytest.raises(EvalConfigError) as e:
        corpus.load_manifest(_write(tmp_path, "demo", body))
    assert "demo.toml" in str(e.value)


def test_load_manifest_line_end_before_start(tmp_path: Path) -> None:
    body = _VALID.replace("line_end = 12", "line_end = 9")
    with pytest.raises(EvalConfigError):
        corpus.load_manifest(_write(tmp_path, "demo", body))


def test_load_manifest_duplicate_vuln_id(tmp_path: Path) -> None:
    body = _VALID + """
[[vuln]]
id = "v1"
file = "src/b.py"
line_start = 1
line_end = 1
attack_class = "path_traversal"
"""
    with pytest.raises(EvalConfigError) as e:
        corpus.load_manifest(_write(tmp_path, "demo", body))
    assert "duplicate" in str(e.value).lower()


def test_load_manifest_missing_required_field(tmp_path: Path) -> None:
    body = _VALID.replace('attack_class = "command_injection"', "")
    with pytest.raises(EvalConfigError):
        corpus.load_manifest(_write(tmp_path, "demo", body))


def test_load_manifest_malformed_toml(tmp_path: Path) -> None:
    with pytest.raises(EvalConfigError):
        corpus.load_manifest(_write(tmp_path, "demo", "this is = = not toml"))


def test_load_corpus_sorted_and_empty(tmp_path: Path) -> None:
    assert corpus.load_corpus(tmp_path) == []
    bbb_body = (
        _VALID.replace('name = "demo"', 'name = "bbb"')
        .replace('repo = "demo"', 'repo = "bbb"')
    )
    aaa_body = (
        _VALID.replace('name = "demo"', 'name = "aaa"')
        .replace('repo = "demo"', 'repo = "aaa"')
    )
    _write(tmp_path, "bbb", bbb_body)
    _write(tmp_path, "aaa", aaa_body)
    names = [e.name for e in corpus.load_corpus(tmp_path)]
    assert names == ["aaa", "bbb"]


def test_find_entry_valid(tmp_path: Path) -> None:
    _write(tmp_path, "demo", _VALID)
    entry = corpus.find_entry("demo", manifest_dir=tmp_path)
    assert entry.name == "demo"
    assert len(entry.vulns) == 1


def test_find_entry_missing_raises(tmp_path: Path) -> None:
    with pytest.raises(EvalConfigError):
        corpus.find_entry("nope", manifest_dir=tmp_path)
