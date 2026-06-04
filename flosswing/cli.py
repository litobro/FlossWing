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
    help="Override the agent model (default claude-opus-4-7).",
)
@click.option(
    "--recon-token-budget",
    type=int,
    default=None,
    help="Override the Recon-stage token budget (default 200000).",
)
@click.option(
    "--hunt-token-budget",
    type=int,
    default=None,
    help="Override the per-task Hunt token budget (default 200000).",
)
@click.option(
    "--validate-token-budget",
    type=int,
    default=None,
    help="Override the per-finding Validate token budget (default 100000).",
)
@click.option(
    "--gapfill-token-budget",
    type=int,
    default=None,
    help="Override the Gapfill token budget (default 50000).",
)
@click.option(
    "--dedupe-token-budget",
    type=int,
    default=None,
    help="Per-cluster Dedupe session token cap (default 50000).",
)
@click.option(
    "--trace-token-budget",
    type=int,
    default=None,
    help="Per-finding Trace session token cap (default 50000).",
)
@click.option(
    "--trace-max-depth",
    type=int,
    default=None,
    help="Maximum find_callers walk depth for Trace (default 8).",
)
def scan(
    path: str,
    model: str | None,
    recon_token_budget: int | None,
    hunt_token_budget: int | None,
    validate_token_budget: int | None,
    gapfill_token_budget: int | None,
    dedupe_token_budget: int | None,
    trace_token_budget: int | None,
    trace_max_depth: int | None,
) -> None:
    """Scan a cloned target repository at PATH (Recon -> Hunt -> Validate -> Gapfill)."""
    try:
        cfg = fcfg.resolve(
            repo_root=Path(path),
            model=model,
            recon_token_budget=recon_token_budget,
            hunt_token_budget=hunt_token_budget,
            validate_token_budget=validate_token_budget,
            gapfill_token_budget=gapfill_token_budget,
            dedupe_token_budget=dedupe_token_budget,
            trace_token_budget=trace_token_budget,
            trace_max_depth=trace_max_depth,
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
