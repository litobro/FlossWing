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

"""flosswing.cli `tui` command wiring."""

from __future__ import annotations

from unittest import mock

from click.testing import CliRunner

from flosswing import cli


def test_tui_command_registered() -> None:
    runner = CliRunner()
    result = runner.invoke(cli.main, ["tui", "--help"])
    assert result.exit_code == 0
    assert "dashboard" in result.output.lower()


def test_tui_command_invokes_app_run() -> None:
    runner = CliRunner()
    with mock.patch("flosswing.tui.app.run") as run_mock:
        result = runner.invoke(cli.main, ["tui"])
    assert result.exit_code == 0
    run_mock.assert_called_once_with()
