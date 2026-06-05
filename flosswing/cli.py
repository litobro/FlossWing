"""FlossWing command-line interface."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import click

from flosswing import config as fcfg
from flosswing import orchestrator
from flosswing.errors import FlosswingError
from flosswing.stages import report as report_stage

_VALID_OUTPUT_FORMATS: frozenset[str] = frozenset({"md", "json", "sarif"})


def _parse_formats(value: str) -> list[str]:
    """Parse a comma-separated format list. Raises click.BadParameter on invalid."""
    parts = [p.strip() for p in value.split(",") if p.strip()]
    if not parts:
        raise click.BadParameter(
            "must be a comma-separated subset of md, json, sarif (got empty)"
        )
    bad = [p for p in parts if p not in _VALID_OUTPUT_FORMATS]
    if bad:
        raise click.BadParameter(
            f"unknown format(s): {', '.join(bad)}. "
            "Valid values: md, json, sarif."
        )
    return parts


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
@click.option(
    "--no-report",
    "no_report",
    is_flag=True,
    default=False,
    help="Skip auto-rendering the report at end of scan.",
)
@click.option(
    "--format",
    "format_",
    type=str,
    default="md,json",
    help=(
        "Comma-separated output formats for the report "
        "(default md,json; valid: md, json, sarif)."
    ),
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
    no_report: bool,
    format_: str,
) -> None:
    """Scan a cloned target repository at PATH (Recon -> Hunt -> Validate -> Gapfill)."""
    formats = _parse_formats(format_)
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
            auto_render=not no_report,
            output_formats=formats,
        )
    except FlosswingError as e:
        click.echo(e.message, err=True)
        sys.exit(2)

    result = asyncio.run(orchestrator.run_scan(cfg))
    click.echo(result.summary)
    sys.exit(result.exit_code)


@main.command()
@click.argument("run_id")
@click.option(
    "--format",
    "format_",
    type=str,
    default="md,json",
    help=(
        "Comma-separated output formats for the report "
        "(default md,json; valid: md, json, sarif)."
    ),
)
@click.option(
    "--output-dir",
    "output_dir",
    type=click.Path(file_okay=False, dir_okay=True, resolve_path=True),
    default=None,
    help=(
        "Directory to write report outputs to "
        "(default ~/.flosswing/runs/<run_id>/output/)."
    ),
)
def report(run_id: str, format_: str, output_dir: str | None) -> None:
    """Render the report for an existing RUN_ID."""
    formats = _parse_formats(format_)
    resolved_output_dir: Path | None = (
        Path(output_dir) if output_dir is not None else None
    )
    try:
        cfg = fcfg.resolve(
            repo_root=Path.cwd(),
            model=None,
            recon_token_budget=None,
            hunt_token_budget=None,
            validate_token_budget=None,
            gapfill_token_budget=None,
            dedupe_token_budget=None,
            trace_token_budget=None,
            trace_max_depth=None,
            auto_render=True,
            output_formats=formats,
            output_dir=resolved_output_dir,
        )
    except FlosswingError as e:
        click.echo(e.message, err=True)
        sys.exit(2)

    # Verify run_id exists in the runs table before invoking the renderer.
    # Imported lazily to keep CLI startup time off the import graph.
    from flosswing.state import session as st_session
    from flosswing.state.models import Run

    with st_session.session_scope() as s:
        if s.get(Run, run_id) is None:
            click.echo(f"unknown run_id: {run_id}", err=True)
            sys.exit(1)

    resolved_dir = cfg.output_dir or (
        Path.home() / ".flosswing" / "runs" / run_id / "output"
    )
    result = report_stage.render(
        run_id=run_id,
        session_factory=st_session.session_factory(),
        output_dir=resolved_dir,
        formats=cfg.output_formats,
    )
    click.echo(
        f"Wrote {len(result.formats_written)} format(s) to {result.output_dir}"
    )


@main.command(name="eval")
def eval_() -> None:
    """Run the eval corpus and score against known-CVE ground truth."""
    click.echo("not implemented")


if __name__ == "__main__":
    main()
