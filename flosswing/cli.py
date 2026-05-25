"""FlossWing command-line interface.

v0.1 ships subcommand stubs only. Real pipeline wiring lands in later
milestones (v0.2 tools, v0.3 sandbox + runtime, v0.4+ stages).
"""

from __future__ import annotations

import click


@click.group()
@click.version_option(package_name="flosswing")
def main() -> None:
    """FlossWing: local-CLI vulnerability research harness."""


@main.command()
@click.argument("path", type=click.Path(exists=True, file_okay=False, dir_okay=True))
def scan(path: str) -> None:
    """Scan a cloned target repository at PATH."""
    click.echo("not implemented")


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
