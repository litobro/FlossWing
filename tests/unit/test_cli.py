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

"""CLI tests: --provider option wiring.

Per docs/specs/2026-06-15-provider-abstraction § Task 7.
"""

from __future__ import annotations


def test_scan_rejects_unimplemented_provider(monkeypatch, tmp_path) -> None:  # type: ignore[no-untyped-def]  # pytest monkeypatch/tmp_path fixtures are untyped
    from click.testing import CliRunner

    from flosswing.cli import main

    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    runner = CliRunner()
    result = runner.invoke(
        main, ["scan", str(tmp_path), "--provider", "openai"]
    )
    assert result.exit_code == 2
    assert "not yet implemented" in result.output
