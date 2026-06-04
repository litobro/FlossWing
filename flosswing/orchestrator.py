"""Top-level scan entry: creates the run row, drives Recon -> Hunt, finalizes."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select
from ulid import ULID

from flosswing import __version__
from flosswing.config import Config
from flosswing.index.build import IndexBuildResult
from flosswing.stages import gapfill as gapfill_stage
from flosswing.stages import hunt as hunt_stage
from flosswing.stages import index_build as index_build_stage
from flosswing.stages import recon as recon_stage
from flosswing.stages import validate as validate_stage
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


def _config_for_run_row(cfg: Config) -> str:
    # Persist non-sensitive config only. auth_env stays out of the DB.
    payload = {
        "repo_root": str(cfg.repo_root),
        "model": cfg.model,
        "recon_token_budget": cfg.recon_token_budget,
        "hunt_token_budget": cfg.hunt_token_budget,
        "validate_token_budget": cfg.validate_token_budget,
        "gapfill_token_budget": cfg.gapfill_token_budget,
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
        )

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
    )
    total_out_tokens = (
        recon_result.output_tokens
        + hunt_result.output_tokens_total
        + validate_result.output_tokens_total
        + gapfill_result.output_tokens
    )

    summary_lines = [
        f"Run {run_id} {final_status}.",
        f"  model:         {cfg.model}",
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
