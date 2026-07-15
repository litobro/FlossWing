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

"""Top-level scan entry: creates the run row, drives Recon -> Hunt, finalizes."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import func, or_, select
from ulid import ULID

from flosswing import __version__, errors
from flosswing.config import Config
from flosswing.index.build import IndexBuildResult
from flosswing.stages import dedupe as dedupe_stage
from flosswing.stages import gapfill as gapfill_stage
from flosswing.stages import hunt as hunt_stage
from flosswing.stages import index_build as index_build_stage
from flosswing.stages import recon as recon_stage
from flosswing.stages import report as report_stage
from flosswing.stages import trace as trace_stage
from flosswing.stages import validate as validate_stage
from flosswing.stages.dedupe import DedupeStageResult
from flosswing.stages.report import ReportRenderResult
from flosswing.stages.trace import TraceStageResult
from flosswing.state import session as st_session
from flosswing.state.models import Finding, HuntTask, Run, Validation


@dataclass
class ScanResult:
    run_id: str
    exit_code: int
    summary: str


def _now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _git_sha(repo_root: Path) -> str | None:
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode == 0:
            return proc.stdout.strip()
    except (FileNotFoundError, OSError):
        return None
    return None


def _ensure_run_dir(run_id: str) -> Path:
    base = Path.home() / ".flosswing" / "runs" / run_id
    (base / "recon").mkdir(parents=True, exist_ok=True)
    (base / "hunt").mkdir(parents=True, exist_ok=True)
    # v0.7: Gapfill scratch dir alongside recon/ and hunt/ for symmetry.
    # Per docs/specs/2026-06-02-v0.7-gapfill-design.md § Component
    # responsibilities stages/gapfill.py — v0.7 does not write here yet,
    # but the layout matches the other stages so a future enhancement
    # (e.g. cached query_run_state JSON) has somewhere to put files.
    (base / "gapfill").mkdir(parents=True, exist_ok=True)
    return base


# Foundry mode routes a tier alias (opus/sonnet/haiku) to a named deployment via
# ANTHROPIC_DEFAULT_<TIER>_MODEL; the request only carries the alias. cfg.model
# records that alias, not the deployment inference actually ran on — resolve the
# deployment so run provenance reflects reality instead of a misleading "opus".
_FOUNDRY_TIER_ENV: dict[str, str] = {
    "opus": "ANTHROPIC_DEFAULT_OPUS_MODEL",
    "sonnet": "ANTHROPIC_DEFAULT_SONNET_MODEL",
    "haiku": "ANTHROPIC_DEFAULT_HAIKU_MODEL",
}


def _foundry_deployment(cfg: Config) -> str | None:
    """Deployment ``cfg.model`` routes to under Foundry mode, else ``None``.

    Returns ``None`` outside Foundry mode, when ``cfg.model``'s tier can't be
    identified, or when that tier has no configured deployment. Reads only the
    non-sensitive routing/deployment vars already collected into ``auth_env``.
    """
    if cfg.auth_env.get("CLAUDE_CODE_USE_FOUNDRY") != "1":
        return None
    if "ANTHROPIC_FOUNDRY_RESOURCE" not in cfg.auth_env:
        return None
    model_lower = cfg.model.lower()
    for tier, env_key in _FOUNDRY_TIER_ENV.items():
        if tier in model_lower:
            return cfg.auth_env.get(env_key)
    return None


def _config_for_run_row(cfg: Config) -> str:
    # Persist non-sensitive config only. auth_env stays out of the DB.
    payload = {
        "repo_root": str(cfg.repo_root),
        "model": cfg.model,
        # Deployment name only (already non-sensitive; never an API key).
        "foundry_deployment": _foundry_deployment(cfg),
        "provider": cfg.provider,
        "recon_token_budget": cfg.recon_token_budget,
        "hunt_token_budget": cfg.hunt_token_budget,
        "validate_token_budget": cfg.validate_token_budget,
        "gapfill_token_budget": cfg.gapfill_token_budget,
        "dedupe_token_budget": cfg.dedupe_token_budget,
        "trace_token_budget": cfg.trace_token_budget,
        "trace_max_depth": cfg.trace_max_depth,
        "auto_render": cfg.auto_render,
        "output_formats": list(cfg.output_formats),
        "output_dir": str(cfg.output_dir) if cfg.output_dir is not None else None,
        "auth_modes": sorted(cfg.auth_env.keys()),  # KEY NAMES only, never values
    }
    return json.dumps(payload, sort_keys=True)


async def run_scan(cfg: Config) -> ScanResult:
    run_id = str(ULID())
    _ensure_run_dir(run_id)

    with st_session.session_scope() as s:
        s.add(
            Run(
                id=run_id,
                target_repo_path=str(cfg.repo_root.resolve()),
                target_repo_sha=_git_sha(cfg.repo_root),
                depth="standard",
                budget_total=20,
                budget_used=0,
                started_at=_now_iso(),
                status="running",
                config_json=_config_for_run_row(cfg),
                flosswing_version=__version__,
            )
        )

    recon_result = await recon_stage.run(run_id=run_id, cfg=cfg)

    # Hunt runs only if Recon completed AND queued >=1 task.
    recon_ok = (
        recon_result.outcome == "completed"
        and recon_result.recon_artifact_recorded
        and recon_result.hunt_tasks_queued >= 1
    )

    # v0.5: IndexBuild phase runs between Recon and Hunt. Per
    # docs/specs/2026-06-02-v0.5-symbol-index-design.md § IndexBuild
    # placement. The phase is deterministic — no agent_sessions row.
    # On empty result (symbols == 0) the run finalizes as `errored`
    # and Hunt does NOT start (design decision #7).
    index_result: IndexBuildResult | None = None
    index_empty = False
    if recon_ok and recon_result.recon_artifact_id is not None:
        index_result = await index_build_stage.run(
            run_id=run_id,
            recon_artifact_id=recon_result.recon_artifact_id,
            repo=cfg.repo_root,
            languages=set(recon_result.languages),
            cfg=cfg,
            session_factory=st_session.session_factory(),
        )
        if index_result.symbols == 0:
            index_empty = True
            recon_ok = False  # short-circuit Hunt below

    if recon_ok:
        hunt_result = await hunt_stage.run(
            run_id=run_id,
            repo=cfg.repo_root,
            cfg=cfg,
            session_factory=st_session.session_factory(),
        )
    else:
        hunt_result = hunt_stage.HuntStageResult.skipped()

    # v0.6: Validate runs after Hunt when Hunt produced >=1 finding.
    # Per docs/specs/2026-06-02-v0.6-validate-design.md § orchestrator
    # extension. Plan-time decision #6: Validate runs even if Hunt had
    # partial failures, as long as >=1 finding landed.
    if recon_ok and hunt_result.findings_total >= 1:
        validate_result = await validate_stage.run(
            run_id=run_id,
            repo=cfg.repo_root,
            cfg=cfg,
            session_factory=st_session.session_factory(),
        )
    else:
        validate_result = validate_stage.ValidateStageResult.skipped()

    # v0.8: Dedupe runs after Validate when Hunt produced >=1 finding.
    # Per docs/specs/2026-06-02-v0.8-dedupe-design.md § orchestrator.run_scan
    # extension: "Dedupe runs only when >= 1 finding exists to consider"
    # AND "The orchestrator runs Dedupe regardless of Validate's outcome
    # (Dedupe doesn't require any `confirmed` verdicts to be useful)".
    # The spec's pseudocode references `validate_result.outcome != "fatal"`,
    # but ValidateStageResult has no `outcome` field; the canonical
    # "did Validate produce usable state" predicate is satisfied whenever
    # Validate did not raise (a raise would have already propagated past
    # this point), so we gate purely on findings_total > 0 here.
    if recon_ok and hunt_result.findings_total > 0:
        dedupe_result = await dedupe_stage.run(
            run_id=run_id,
            repo=cfg.repo_root,
            cfg=cfg,
            session_factory=st_session.session_factory(),
        )
    else:
        dedupe_result = DedupeStageResult.skipped()

    # v0.7: Gapfill runs after Validate when Hunt succeeded at least
    # one task — regardless of findings_total. Per design decision #5
    # of docs/specs/2026-06-02-v0.7-gapfill-design.md: zero-finding
    # runs are when Gapfill is most useful, so the gate is
    # tasks_succeeded >= 1 (not findings_total >= 1).
    if recon_ok and hunt_result.tasks_succeeded >= 1:
        gapfill_result = await gapfill_stage.run(
            run_id=run_id,
            repo=cfg.repo_root,
            cfg=cfg,
            session_factory=st_session.session_factory(),
        )
    else:
        gapfill_result = gapfill_stage.GapfillStageResult.skipped()

    # v0.9: Trace runs after Dedupe over confirmed primaries (status =
    # 'confirmed' AND (dedupe_role IS NULL OR dedupe_role='primary')).
    # Per docs/specs/2026-06-02-v0.9-trace-design.md § orchestrator
    # extension. Per-finding failures do NOT promote the run to errored
    # — Trace is "best effort" coverage data.
    with st_session.session_scope() as s:
        trace_eligible_count = int(
            s.execute(
                select(func.count())
                .select_from(Finding)
                .where(
                    Finding.run_id == run_id,
                    Finding.status == "confirmed",
                    or_(
                        Finding.dedupe_role.is_(None),
                        Finding.dedupe_role == "primary",
                    ),
                )
            ).scalar_one()
        )

    if trace_eligible_count > 0:
        trace_result = await trace_stage.run(
            run_id=run_id,
            repo=cfg.repo_root,
            cfg=cfg,
            session_factory=st_session.session_factory(),
        )
    else:
        trace_result = TraceStageResult.skipped()

    # Run finalization (per spec § Component responsibilities
    # orchestrator.run_scan extension):
    #   recon failed                                        -> errored, exit 1
    #   recon completed, 0 tasks queued                     -> errored, exit 1
    #   IndexBuild empty (symbols==0)                       -> errored, exit 1
    #   hunt processed >=1 AND zero succeeded               -> errored, exit 1
    #   hunt produced 0 findings                            -> completed (skip Validate)
    #   hunt findings >=1 AND >=1 terminal Validate verdict -> completed, exit 0
    #   hunt findings >=1 AND every Validate non-terminal   -> errored, exit 1
    if not recon_ok:
        final_status = "errored"
    elif hunt_result.tasks_succeeded < 1:
        # Kept separate from `not recon_ok` for the spec's
        # "hunt processed >=1 AND zero succeeded" branch to remain
        # legible alongside Validate's terminal-verdict check below.
        final_status = "errored"
    elif hunt_result.findings_total == 0:
        # No findings -> Validate was skipped -> the run did its job.
        final_status = "completed"
    elif (
        validate_result.findings_confirmed
        + validate_result.findings_rejected
        + validate_result.findings_uncertain
        >= 1
    ):
        # Hunt produced findings AND >=1 Validate session reached a
        # terminal verdict -> completed.
        final_status = "completed"
    else:
        # Hunt produced findings but every Validate session was
        # non-terminal -> errored. Per plan-time decision #5, findings
        # that stay pending_validation don't fail individually, but if
        # NONE reach a verdict the run as a whole errors.
        final_status = "errored"
    exit_code = 0 if final_status == "completed" else 1
    finished_at = _now_iso()

    with st_session.session_scope() as s:
        row = s.get(Run, run_id)
        # assert is erased under `python -O`; use an explicit guard.
        if row is None:
            raise RuntimeError(
                f"runs row missing for run_id={run_id!r}; "
                "this is a bug in flosswing.orchestrator"
            )
        row.finished_at = finished_at
        row.status = final_status
        row.budget_used = (
            recon_result.input_tokens
            + recon_result.output_tokens
            + hunt_result.input_tokens_total
            + hunt_result.output_tokens_total
            + validate_result.input_tokens_total
            + validate_result.output_tokens_total
            + gapfill_result.input_tokens
            + gapfill_result.output_tokens
            + dedupe_result.input_tokens
            + dedupe_result.output_tokens
            + trace_result.input_tokens
            + trace_result.output_tokens
        )

    # v1.0: Report rendering. Runs after the runs row is committed so the
    # renderer sees final status / budget_used. Per
    # docs/specs/2026-06-02-v1.0-report-design.md § orchestrator wiring and
    # docs/plans/2026-06-04-v1.0-report.md Task C: a render failure does
    # NOT propagate or change final_status — the state DB is the canonical
    # record; the report is a derived view. Errors are surfaced in the
    # printed summary (scrubbed) so the operator can re-run
    # ``flosswing report <run_id>`` to inspect.
    report_result: ReportRenderResult | None = None
    report_error_text: str | None = None
    if cfg.auto_render:
        output_dir = cfg.output_dir or (
            Path.home() / ".flosswing" / "runs" / run_id / "output"
        )
        try:
            report_result = report_stage.render(
                run_id=run_id,
                session_factory=st_session.session_factory(),
                output_dir=output_dir,
                formats=cfg.output_formats,
            )
        except Exception as e:
            # Render failure must NOT fail the run. The state DB is the
            # canonical record; the report is a derived view. Catch broad
            # here on purpose — any unexpected exception (DB blip, IO,
            # programmer error) should leave the run intact and surface
            # in the printed summary instead.
            #
            # Per spec § Error handling: surface as exit 1 even though
            # final_status stays 'completed' (don't retro-mark the run).
            # Tells the operator to run `flosswing report <run_id>` to
            # recover.
            report_result = None
            report_error_text = errors.scrub(str(e))
            exit_code = 1

    # Build the summary string. Per spec § Success criteria #3:
    # per-task lines from hunt_tasks + a roll-up footer.
    # Snapshot row attributes inside the session scope; ORM instances
    # are expired once session_scope() commits and exits.
    task_lines: list[str] = []
    with st_session.session_scope() as s:
        task_rows = list(
            s.execute(select(HuntTask).where(HuntTask.run_id == run_id))
            .scalars()
            .all()
        )
        for t in task_rows:
            task_lines.append(
                f"  - {t.attack_class} {t.scope_hint} -> {t.status}, "
                f"{t.findings_count} findings"
            )

    # Per-finding verdict lines (one per Hunt-produced finding). Findings
    # without a validations row stay `pending_validation` in the summary
    # per plan-time decision #5.
    finding_lines: list[str] = []
    if validate_result.findings_processed >= 1:
        with st_session.session_scope() as s:
            finding_rows = list(
                s.execute(
                    select(Finding).where(Finding.run_id == run_id)
                )
                .scalars()
                .all()
            )
            for f in finding_rows:
                v = s.execute(
                    select(Validation).where(
                        Validation.finding_id == f.id
                    )
                ).scalar_one_or_none()
                verdict = (
                    v.verdict if v is not None else "pending_validation"
                )
                finding_lines.append(
                    f"    - {f.attack_class} {f.file}:{f.line_start} "
                    f"-> {verdict}"
                )

    total_in_tokens = (
        recon_result.input_tokens
        + hunt_result.input_tokens_total
        + validate_result.input_tokens_total
        + gapfill_result.input_tokens
        + dedupe_result.input_tokens
        + trace_result.input_tokens
    )
    total_out_tokens = (
        recon_result.output_tokens
        + hunt_result.output_tokens_total
        + validate_result.output_tokens_total
        + gapfill_result.output_tokens
        + dedupe_result.output_tokens
        + trace_result.output_tokens
    )

    # v0.8: Dedupe section, printed after Hunt/Validate/Gapfill per
    # docs/specs/2026-06-02-v0.8-dedupe-design.md § Success criteria #3.
    # If the stage was skipped (no findings to cluster), emit a single
    # explanatory line; otherwise emit the full breakdown.
    if dedupe_result.outcome == "skipped":
        dedupe_lines: list[str] = [
            "  dedupe: skipped (no findings to cluster)",
        ]
    else:
        singletons = dedupe_result.clusters_total - dedupe_result.clusters_reviewed
        dedupe_lines = [
            "  dedupe:",
            (
                f"    clusters_total:     {dedupe_result.clusters_total} "
                f"(singletons: {singletons}, multi-member: "
                f"{dedupe_result.clusters_reviewed})"
            ),
            f"    clusters_reviewed:  {dedupe_result.clusters_reviewed}",
            f"    merges_performed:   {dedupe_result.merges_performed}",
            f"    variants_linked:    {dedupe_result.variants_linked}",
        ]
        if dedupe_result.clusters_refused:
            dedupe_lines.append(
                f"    clusters_refused:   {dedupe_result.clusters_refused}"
            )
        if dedupe_result.clusters_errored:
            dedupe_lines.append(
                f"    clusters_errored:   {dedupe_result.clusters_errored}"
            )
        dedupe_lines.extend(
            [
                (
                    f"    findings_superseded: "
                    f"{dedupe_result.findings_superseded} / "
                    f"{dedupe_result.findings_total}"
                ),
                f"    tokens in/out:      "
                f"{dedupe_result.input_tokens} / {dedupe_result.output_tokens}",
            ]
        )

    # v1.0: Report section, printed after Trace per
    # docs/specs/2026-06-02-v1.0-report-design.md § orchestrator wiring and
    # docs/plans/2026-06-04-v1.0-report.md Task C. Three shapes:
    #   - auto_render disabled       -> single "skipped (--no-report)" line
    #   - render succeeded           -> full breakdown
    #   - render raised (tolerated)  -> single "errored — see logs" line
    if not cfg.auto_render:
        report_lines: list[str] = ["  report: skipped (--no-report)"]
    elif report_result is not None:
        report_lines = [
            "  report:",
            f"    output dir:        {report_result.output_dir}",
            f"    formats:           {','.join(report_result.formats_written)}",
            f"    findings dirs:     {report_result.findings_dirs_written}",
            f"    bytes written:     {report_result.bytes_written}",
        ]
        if report_result.sarif_skipped:
            report_lines.append(
                "    sarif: not yet implemented; tracked in v1.1"
            )
    else:
        # Render raised; scrubbed error captured above. Stay in 'errored —
        # see logs' shape per Task C even when we have a message to show,
        # so the summary structure is grep-stable.
        report_lines = ["  report: errored — see logs"]
        if report_error_text:
            report_lines.append(f"    error: {report_error_text}")

    # v0.9: Trace section, printed after Dedupe per
    # docs/specs/2026-06-02-v0.9-trace-design.md § Success criteria.
    # If the stage was skipped (no confirmed primaries), emit a single
    # explanatory line; otherwise emit the full breakdown.
    if trace_result.outcome == "skipped":
        trace_lines: list[str] = [
            "  trace: skipped (no confirmed primaries)",
        ]
    else:
        trace_lines = [
            "  trace:",
            f"    findings_total:      {trace_result.findings_total}",
            f"    findings_traced:     {trace_result.findings_traced}",
            f"    reachable:           {trace_result.findings_reachable}",
            f"    unreachable:         {trace_result.findings_unreachable}",
            f"    uncertain:           {trace_result.findings_uncertain}",
        ]
        if trace_result.findings_refused:
            trace_lines.append(
                f"    refused:             {trace_result.findings_refused}"
            )
        if trace_result.findings_errored:
            trace_lines.append(
                f"    errored:             {trace_result.findings_errored}"
            )
        if trace_result.findings_budget_exceeded:
            trace_lines.append(
                f"    budget_exceeded:     "
                f"{trace_result.findings_budget_exceeded}"
            )
        trace_lines.append(
            f"    tokens in/out:       "
            f"{trace_result.input_tokens} / {trace_result.output_tokens}"
        )

    _deployment = _foundry_deployment(cfg)
    _model_line = f"  model:         {cfg.model}"
    if _deployment is not None:
        _model_line += f" -> foundry deployment: {_deployment}"

    summary_lines = [
        f"Run {run_id} {final_status}.",
        _model_line,
        "  recon:",
        f"    outcome:     {recon_result.outcome}",
        (
            f"    artifact:    "
            f"{'recorded' if recon_result.recon_artifact_recorded else 'NOT recorded'}"
        ),
        f"    tasks queued: {recon_result.hunt_tasks_queued}",
        "  index:",
        f"    symbols:           {index_result.symbols if index_result else 0}",
        f"    call_sites:        {index_result.call_sites if index_result else 0}",
        f"    entry_points:      {index_result.entry_points if index_result else 0}",
        f"    files_parsed:      {index_result.files_parsed if index_result else 0}",
        f"    files_skipped:     {index_result.files_skipped if index_result else 0}",
        f"    duration_ms:       {index_result.duration_ms if index_result else 0}",
        "  hunt:",
        f"    tasks processed:    {hunt_result.tasks_processed}",
        f"    succeeded:          {hunt_result.tasks_succeeded}",
        f"    refused:            {hunt_result.tasks_refused}",
        f"    budget_exceeded:    {hunt_result.tasks_budget_exceeded}",
        f"    errored:            {hunt_result.tasks_errored}",
        f"    findings recorded:  {hunt_result.findings_total}",
        f"    tokens in/out:      "
        f"{hunt_result.input_tokens_total} / {hunt_result.output_tokens_total}",
        *task_lines,
        "  validate:",
        f"    findings processed: {validate_result.findings_processed}",
        f"    confirmed:          {validate_result.findings_confirmed}",
        f"    rejected:           {validate_result.findings_rejected}",
        f"    uncertain:          {validate_result.findings_uncertain}",
        f"    refused:            {validate_result.findings_refused}",
        f"    budget_exceeded:    {validate_result.findings_budget_exceeded}",
        f"    errored:            {validate_result.findings_errored}",
        f"    no_verdict:         {validate_result.findings_no_verdict}",
        f"    tokens in/out:      "
        f"{validate_result.input_tokens_total} / "
        f"{validate_result.output_tokens_total}",
        *finding_lines,
        "  gapfill:",
        f"    outcome:            {gapfill_result.outcome}",
        f"    cap (20% rule):     {gapfill_result.cap}",
        f"    tasks queued:       {gapfill_result.tasks_queued}",
        f"    tokens in/out:      "
        f"{gapfill_result.input_tokens} / {gapfill_result.output_tokens}",
        *dedupe_lines,
        *trace_lines,
        *report_lines,
        f"  total tokens in/out: {total_in_tokens} / {total_out_tokens}",
        f"  est. cost USD (recon only): {recon_result.cost_usd:.4f}",
    ]
    if recon_result.refusal_text:
        summary_lines.append(f"  recon refusal: {recon_result.refusal_text}")
    if recon_result.error_text:
        summary_lines.append(f"  recon error:   {recon_result.error_text}")
    if index_empty:
        summary_lines.append(
            "  index_build_empty: no symbols extracted; Hunt did not start"
        )

    return ScanResult(
        run_id=run_id, exit_code=exit_code, summary="\n".join(summary_lines)
    )
