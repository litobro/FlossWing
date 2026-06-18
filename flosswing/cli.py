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

"""FlossWing command-line interface."""

from __future__ import annotations

import asyncio
import os
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
@click.option(
    "--env-file",
    "env_file",
    type=click.Path(dir_okay=False),
    default=None,
    help=(
        "Explicitly load ALL variables from this file into the environment before "
        "running (you are trusting this file). Without it, a local .env is loaded "
        "but restricted to known credential/config keys. --no-env-file disables both."
    ),
)
@click.option(
    "--no-env-file",
    "no_env_file",
    is_flag=True,
    default=False,
    help="Do not load any .env file.",
)
def main(env_file: str | None, no_env_file: bool) -> None:
    """FlossWing: local-CLI vulnerability research harness."""
    # Operator convenience: load a local .env into the environment so commands
    # (and TUI-spawned `flosswing scan` children) pick up credentials without a
    # manual `source`. The real environment always takes precedence (setdefault),
    # and only a COUNT is ever printed (never names/values). FLOSSWING_DISABLE_DOTENV
    # is a hermeticity escape hatch (the test suite sets it so it never slurps a
    # real .env).
    if no_env_file or os.environ.get("FLOSSWING_DISABLE_DOTENV"):
        return
    from flosswing import envfile

    if env_file is None:
        # Default convenience load: restricted to known credential/config keys so
        # a stray .env (e.g. inside an untrusted target repo the operator runs
        # from) cannot inject arbitrary environment variables.
        from flosswing.config import AUTH_ENV_KEYS

        source = ".env"
        loaded = envfile.load_env_file(Path(source), allowed_keys=AUTH_ENV_KEYS)
    else:
        # Explicit file: the operator is deliberately trusting it; load everything.
        source = env_file
        loaded = envfile.load_env_file(Path(source))
    if loaded:
        click.echo(
            f"Loaded {loaded} variable(s) from {source} "
            "(existing environment takes precedence).",
            err=True,
        )


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
    "--provider",
    default=None,
    help="Model provider backend (default anthropic). Others are reserved/unimplemented.",
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
    provider: str | None,
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
            provider=provider,
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
            # Spec § Error handling (and RunNotFoundError docstring) require
            # exit 2 + the canonical message here. Distinguishes "no such
            # run" from generic render failures (exit 1).
            click.echo(f"no run with id {run_id} in state.db", err=True)
            sys.exit(2)

    resolved_dir = cfg.output_dir or (
        Path.home() / ".flosswing" / "runs" / run_id / "output"
    )
    try:
        result = report_stage.render(
            run_id=run_id,
            session_factory=st_session.session_factory(),
            output_dir=resolved_dir,
            formats=cfg.output_formats,
        )
    except Exception as e:
        # Per CLAUDE.md hard rule + spec § Error handling: scrub before
        # writing to stderr. Mirrors the orchestrator's auto-render
        # error-handling path.
        from flosswing import errors as _errors

        click.echo(f"report render failed: {_errors.scrub(str(e))}", err=True)
        sys.exit(1)
    click.echo(
        f"Wrote {len(result.formats_written)} format(s) to {result.output_dir}"
    )


@main.command(name="eval")
@click.option("--from-run", "from_run", default=None,
              help="Score an existing run instead of scanning (no API). Requires --corpus.")
@click.option("--corpus", "corpus_name", default=None,
              help="Corpus entry name (manifest stem).")
@click.option("--manifest-dir", "manifest_dir", default=None,
              type=click.Path(file_okay=False, dir_okay=True, resolve_path=True),
              help="Ground-truth dir (default: packaged flosswing/eval/ground_truth).")
@click.option("--corpus-root", "corpus_root", default="tests/corpus",
              type=click.Path(file_okay=False, dir_okay=True, resolve_path=True),
              help="Root for resolving a manifest's repo dir on the scan path.")
@click.option("--include-uncertain", "include_uncertain", is_flag=True, default=False,
              help="Also score findings with status 'uncertain'.")
@click.option("--json", "json_out", default=None,
              type=click.Path(dir_okay=False),
              help="Write the scorecard JSON to this path.")
@click.option("--min-recall", "min_recall", type=click.FloatRange(0.0, 1.0),
              default=None,
              help="Exit non-zero if aggregate recall < value (0.0-1.0).")
@click.option("--min-precision", "min_precision", type=click.FloatRange(0.0, 1.0),
              default=None,
              help="Exit non-zero if aggregate precision < value (0.0-1.0).")
def eval_(
    from_run: str | None,
    corpus_name: str | None,
    manifest_dir: str | None,
    corpus_root: str,
    include_uncertain: bool,
    json_out: str | None,
    min_recall: float | None,
    min_precision: float | None,
) -> None:
    """Run the eval corpus and score against known-CVE ground truth."""
    import json as _json

    from flosswing import errors as _errors
    from flosswing.eval import corpus as _corpus
    from flosswing.eval import runner as _runner

    if from_run is not None and corpus_name is None:
        click.echo("--from-run requires --corpus", err=True)
        sys.exit(2)

    mdir = Path(manifest_dir) if manifest_dir else _corpus.DEFAULT_MANIFEST_DIR
    try:
        result = _runner.run_evaluation(
            manifest_dir=mdir,
            corpus_root=Path(corpus_root),
            from_run=from_run,
            corpus_name=corpus_name,
            include_uncertain=include_uncertain,
        )
    except (_errors.EvalConfigError, _errors.RunNotFoundError) as e:
        click.echo(_errors.scrub(e.message), err=True)
        sys.exit(2)

    click.echo(_runner.render_scorecard(result))
    if json_out is not None:
        Path(json_out).write_text(
            _json.dumps(result.model_dump(), indent=2, sort_keys=True),
            encoding="utf-8",
        )

    agg = result.aggregate
    if min_recall is not None and (agg.recall is None or agg.recall < min_recall):
        sys.exit(1)
    if min_precision is not None and (
        agg.precision is None or agg.precision < min_precision
    ):
        sys.exit(1)


@main.command(name="tui")
def tui() -> None:
    """Launch the interactive terminal dashboard for browsing runs and findings."""
    # Lazy import: keep textual + the TUI import graph off the startup path
    # of scan/report/eval (mirrors the lazy state import in `report`).
    from flosswing.tui import app as tui_app

    tui_app.run()


if __name__ == "__main__":
    main()
