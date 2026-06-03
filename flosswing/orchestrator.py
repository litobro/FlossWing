"""Top-level scan entry: creates the run row, drives Recon, finalizes."""

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
from flosswing.stages import recon as recon_stage
from flosswing.state import session as st_session
from flosswing.state.models import HuntTask, Run


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
    base = Path.home() / ".flosswing" / "runs" / run_id / "recon"
    base.mkdir(parents=True, exist_ok=True)
    return base


def _config_for_run_row(cfg: Config) -> str:
    # Persist non-sensitive config only. auth_env stays out of the DB.
    payload = {
        "repo_root": str(cfg.repo_root),
        "model": cfg.model,
        "recon_token_budget": cfg.recon_token_budget,
        "hunt_token_budget": cfg.hunt_token_budget,
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

    happy = (
        recon_result.outcome == "completed"
        and recon_result.recon_artifact_recorded
        and recon_result.hunt_tasks_queued >= 1
    )
    final_status = "completed" if happy else "errored"
    exit_code = 0 if happy else 1
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
        row.budget_used = recon_result.input_tokens + recon_result.output_tokens

    with st_session.session_scope() as s:
        task_titles = [
            f"  • {t.attack_class}: {t.scope_hint}"
            for t in s.execute(select(HuntTask).where(HuntTask.run_id == run_id))
            .scalars()
            .all()
        ]

    summary_lines = [
        f"Run {run_id} {final_status}.",
        f"  model:         {cfg.model}",
        f"  outcome:       {recon_result.outcome}",
        f"  artifact:      "
        f"{'recorded' if recon_result.recon_artifact_recorded else 'NOT recorded'}",
        f"  hunt tasks:    {recon_result.hunt_tasks_queued}",
        *task_titles,
        f"  tokens in/out: {recon_result.input_tokens} / {recon_result.output_tokens}",
        f"  est. cost USD: {recon_result.cost_usd:.4f}",
    ]
    if recon_result.refusal_text:
        summary_lines.append(f"  refusal:       {recon_result.refusal_text}")
    if recon_result.error_text:
        summary_lines.append(f"  error:         {recon_result.error_text}")

    return ScanResult(
        run_id=run_id, exit_code=exit_code, summary="\n".join(summary_lines)
    )
