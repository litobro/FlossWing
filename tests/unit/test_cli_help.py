"""Smoke test: the CLI entry point loads and `--help` exits cleanly."""

from __future__ import annotations

from click.testing import CliRunner

from flosswing.cli import main


def test_help_exits_zero() -> None:
    result = CliRunner().invoke(main, ["--help"])
    assert result.exit_code == 0, result.output
    assert "scan" in result.output
    assert "report" in result.output
    assert "eval" in result.output
