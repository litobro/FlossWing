"""FlossWing command-line interface."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import click

from flosswing import config as fcfg
from flosswing import orchestrator
from flosswing.errors import FlosswingError


@click.group()
@click.version_option(package_name="flosswing")
def main() -> None:
    """FlossWing: local-CLI vulnerability research harness."""


@main.command()
@click.argument(
    "path",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, resolve_path=True),
)
@click.option(
    "--model",
    default=None,
    help="Override the Recon model (default claude-opus-4-7).",
)
@click.option(
    "--token-budget",
    type=int,
    default=None,
    help="Override the Recon token budget (default 200000).",
)
def scan(path: str, model: str | None, token_budget: int | None) -> None:
    """Scan a cloned target repository at PATH (v0.2: Recon-only)."""
    try:
        cfg = fcfg.resolve(
            repo_root=Path(path),
            model=model,
            token_budget=token_budget,
        )
    except FlosswingError as e:
        click.echo(e.message, err=True)
        sys.exit(2)

    result = asyncio.run(orchestrator.run_scan(cfg))
    click.echo(result.summary)
    sys.exit(result.exit_code)


@main.command()
@click.argument("run_id")
def report(run_id: str) -> None:
    """Render the report for an existing RUN_ID."""
    click.echo("not implemented")


@main.command(name="eval")
def eval_() -> None:
    """Run the eval corpus and score against known-CVE ground truth."""
    click.echo("not implemented")


if __name__ == "__main__":
    main()
