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

"""The `flosswing` CLI group auto-loads a local .env into the environment."""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from click.testing import CliRunner

from flosswing.cli import main


@pytest.fixture()
def _clean_var() -> Iterator[None]:
    # The code under test writes directly to os.environ; ensure the probe var is
    # absent before and removed after so the test stays hermetic.
    for v in ("FW_CLI_ENV_PROBE",):
        os.environ.pop(v, None)
    yield
    for v in ("FW_CLI_ENV_PROBE",):
        os.environ.pop(v, None)


def _write_env(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("FW_CLI_ENV_PROBE=loaded\n", encoding="utf-8")


def test_dotenv_autoloaded_from_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, _clean_var: None
) -> None:
    monkeypatch.delenv("FLOSSWING_DISABLE_DOTENV", raising=False)  # undo conftest guard
    monkeypatch.chdir(tmp_path)
    _write_env(tmp_path)

    res = CliRunner().invoke(main, ["eval", "--help"])
    assert res.exit_code == 0, res.output
    assert os.environ.get("FW_CLI_ENV_PROBE") == "loaded"


def test_no_env_file_flag_disables_load(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, _clean_var: None
) -> None:
    monkeypatch.delenv("FLOSSWING_DISABLE_DOTENV", raising=False)
    monkeypatch.chdir(tmp_path)
    _write_env(tmp_path)

    res = CliRunner().invoke(main, ["--no-env-file", "eval", "--help"])
    assert res.exit_code == 0, res.output
    assert "FW_CLI_ENV_PROBE" not in os.environ


def test_disable_guard_blocks_load(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, _clean_var: None
) -> None:
    # Guard left in place (as the conftest sets it) → no auto-load.
    monkeypatch.setenv("FLOSSWING_DISABLE_DOTENV", "1")
    monkeypatch.chdir(tmp_path)
    _write_env(tmp_path)

    res = CliRunner().invoke(main, ["eval", "--help"])
    assert res.exit_code == 0, res.output
    assert "FW_CLI_ENV_PROBE" not in os.environ
