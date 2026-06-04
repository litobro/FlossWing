"""Smoke tests: the CLI entry point loads and `--help` exits cleanly.

Asserts per-stage budget flags exist and the old --token-budget flag
does not (per docs/specs/2026-06-02-v0.3-hunt-plumbing-design.md
§ Design decisions #1).
"""

from __future__ import annotations

from click.testing import CliRunner

from flosswing.cli import main


def test_help_exits_zero() -> None:
    result = CliRunner().invoke(main, ["--help"])
    assert result.exit_code == 0, result.output
    assert "scan" in result.output
    assert "report" in result.output
    assert "eval" in result.output


def test_scan_help_lists_per_stage_budget_flags() -> None:
    result = CliRunner().invoke(main, ["scan", "--help"])
    assert result.exit_code == 0, result.output
    assert "--recon-token-budget" in result.output
    assert "--hunt-token-budget" in result.output


def test_scan_help_lists_validate_token_budget_flag() -> None:
    """Per docs/specs/2026-06-02-v0.6-validate-design.md § cli.py extension."""
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--validate-token-budget" in result.output


def test_scan_help_lists_gapfill_token_budget_flag() -> None:
    """Per docs/specs/2026-06-02-v0.7-gapfill-design.md § cli.py extension."""
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--gapfill-token-budget" in result.output


def test_scan_help_lists_dedupe_token_budget_flag() -> None:
    """Per docs/specs/2026-06-02-v0.8-dedupe-design.md § cli.py extension."""
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--dedupe-token-budget" in result.output


def test_scan_help_lists_trace_token_budget_flag() -> None:
    """Per docs/plans/2026-06-04-v0.9-trace.md § Task B."""
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--trace-token-budget" in result.output
    assert "50000" in result.output


def test_scan_help_lists_trace_max_depth_flag() -> None:
    """Per docs/plans/2026-06-04-v0.9-trace.md § Task B."""
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--trace-max-depth" in result.output
    assert "default 8" in result.output


def test_scan_help_no_longer_offers_legacy_token_budget() -> None:
    result = CliRunner().invoke(main, ["scan", "--help"])
    assert result.exit_code == 0, result.output
    # Hard line: the old flag must not appear anywhere in --help. The
    # per-stage flags use it as a substring, so check whole-flag match.
    assert " --token-budget " not in result.output
    assert result.output.find("--token-budget\n") == -1


def test_scan_rejects_legacy_token_budget_flag() -> None:
    """Old flag must error out, not silently no-op."""
    result = CliRunner().invoke(main, ["scan", "--token-budget", "1", "."])
    assert result.exit_code != 0
    assert (
        "no such option" in result.output.lower()
        or "unrecognized" in result.output.lower()
    )
