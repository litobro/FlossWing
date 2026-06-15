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

"""Read-only query layer for the FlossWing TUI.

This is the ONLY TUI module that touches SQLAlchemy. Every function opens a
read session, snapshots rows into frozen dataclasses before the scope
closes, and returns those dataclasses. No ORM entity escapes this module.

Display text is shown as-is: finding/title/description text is already
credential-scrubbed by the upstream stage that wrote it (see
flosswing.stages.report module docstring). Only error/stderr text elsewhere
in the TUI is run through flosswing.errors.scrub.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import func, select

from flosswing.state import session as st_session
from flosswing.state.models import (
    AgentSession,
    DedupeCluster,
    Finding,
    HuntTask,
    ReconArtifact,
    Run,
    Symbol,
    Trace,
    Validation,
)


def _short_id(run_id: str) -> str:
    """Last 8 chars of a ULID — enough to disambiguate in a list."""
    return run_id[-8:] if len(run_id) > 8 else run_id


@dataclass(frozen=True)
class RunRow:
    id: str
    short_id: str
    target_repo_path: str
    status: str
    started_at: str
    finished_at: str | None
    findings_count: int


def list_runs() -> list[RunRow]:
    """All runs, newest started_at first, with finding counts."""
    with st_session.session_scope() as s:
        counts: dict[str, int] = {
            row[0]: row[1]
            for row in s.execute(
                select(Finding.run_id, func.count(Finding.id)).group_by(Finding.run_id)
            ).all()
        }
        runs = (
            s.execute(select(Run).order_by(Run.started_at.desc()))
            .scalars()
            .all()
        )
        return [
            RunRow(
                id=r.id,
                short_id=_short_id(r.id),
                target_repo_path=r.target_repo_path,
                status=r.status,
                started_at=r.started_at,
                finished_at=r.finished_at,
                findings_count=int(counts.get(r.id, 0)),
            )
            for r in runs
        ]


@dataclass(frozen=True)
class StageState:
    name: str
    state: str  # "done" | "active" | "pending" | "n/a"


@dataclass(frozen=True)
class HuntTaskRow:
    attack_class: str
    scope_hint: str
    status: str
    findings_count: int


@dataclass(frozen=True)
class RunProgress:
    run_id: str
    short_id: str
    target_repo_path: str
    status: str
    started_at: str
    finished_at: str | None
    stages: list[StageState]
    hunt_done: int
    hunt_total: int
    tokens_used: int
    cost_usd: float
    findings_total: int
    findings_by_status: dict[str, int]
    hunt_tasks: list[HuntTaskRow]


def _stage(name: str, done: bool, *, active_if_running: bool, run_running: bool) -> StageState:
    """Generic stage state: done if `done`; else active when the run is still
    running and this stage could plausibly be the active one; else pending."""
    if done:
        return StageState(name, "done")
    if run_running and active_if_running:
        return StageState(name, "active")
    return StageState(name, "pending" if run_running else "n/a")


def _derive_stages(
    *,
    run_running: bool,
    recon_done: bool,
    index_done: bool,
    hunt_total: int,
    hunt_done: int,
    gapfill_done: bool,
    n_validations: int,
    n_clusters: int,
    n_traces: int,
    findings_total: int,
) -> list[StageState]:
    """Infer per-stage state purely from which rows exist.

    The state DB has no 'current stage' column, so each stage's state is
    derived from its own evidence. A stage with no evidence is 'pending'
    while the run is still running and 'n/a' once it has stopped.
    """
    hunt_finished = hunt_total > 0 and hunt_done == hunt_total
    hunt_active = hunt_total > 0 and not hunt_finished
    if hunt_finished:
        hunt_state = "done"
    elif hunt_active:
        hunt_state = "active"
    elif run_running:
        hunt_state = "pending"
    else:
        hunt_state = "n/a"
    return [
        _stage("Recon", recon_done, active_if_running=not recon_done, run_running=run_running),
        _stage(
            "Index",
            index_done,
            active_if_running=recon_done and not index_done,
            run_running=run_running,
        ),
        StageState("Hunt", hunt_state),
        _stage("Validate", n_validations > 0, active_if_running=False, run_running=run_running),
        _stage("Gapfill", gapfill_done, active_if_running=False, run_running=run_running),
        _stage("Dedupe", n_clusters > 0, active_if_running=False, run_running=run_running),
        _stage("Trace", n_traces > 0, active_if_running=False, run_running=run_running),
        # Report leaves no DB row; we cannot confirm it ran. Show n/a always.
        StageState("Report", "n/a"),
    ]


def run_progress(run_id: str) -> RunProgress | None:
    """Live progress for one run, or None if the run does not exist."""
    with st_session.session_scope() as s:
        run = s.get(Run, run_id)
        if run is None:
            return None
        run_running = run.status == "running"

        recon_done = (
            s.execute(
                select(ReconArtifact.id).where(ReconArtifact.run_id == run_id).limit(1)
            ).first()
            is not None
        )
        index_done = (
            s.execute(
                select(Symbol.id).where(Symbol.run_id == run_id).limit(1)
            ).first()
            is not None
        )

        tasks = (
            s.execute(select(HuntTask).where(HuntTask.run_id == run_id))
            .scalars()
            .all()
        )
        hunt_total = len(tasks)
        hunt_done = sum(1 for t in tasks if t.status not in ("pending", "running"))
        gapfill_done = any(t.source == "gapfill" for t in tasks)
        hunt_tasks = [
            HuntTaskRow(t.attack_class, t.scope_hint, t.status, t.findings_count)
            for t in tasks
        ]

        findings = (
            s.execute(select(Finding).where(Finding.run_id == run_id))
            .scalars()
            .all()
        )
        findings_total = len(findings)
        by_status: dict[str, int] = {}
        for f in findings:
            by_status[f.status] = by_status.get(f.status, 0) + 1

        n_validations = int(
            s.execute(
                select(func.count())
                .select_from(Validation)
                .join(Finding, Validation.finding_id == Finding.id)
                .where(Finding.run_id == run_id)
            ).scalar()
            or 0
        )
        n_traces = int(
            s.execute(
                select(func.count())
                .select_from(Trace)
                .join(Finding, Trace.finding_id == Finding.id)
                .where(Finding.run_id == run_id)
            ).scalar()
            or 0
        )
        n_clusters = int(
            s.execute(
                select(func.count())
                .select_from(DedupeCluster)
                .where(DedupeCluster.run_id == run_id)
            ).scalar()
            or 0
        )

        tokens_used = int(
            s.execute(
                select(
                    func.coalesce(
                        func.sum(AgentSession.input_tokens + AgentSession.output_tokens),
                        0,
                    )
                ).where(AgentSession.run_id == run_id)
            ).scalar()
            or 0
        )
        cost_usd = float(
            s.execute(
                select(func.coalesce(func.sum(AgentSession.cost_usd), 0.0)).where(
                    AgentSession.run_id == run_id
                )
            ).scalar()
            or 0.0
        )

        stages = _derive_stages(
            run_running=run_running,
            recon_done=recon_done,
            index_done=index_done,
            hunt_total=hunt_total,
            hunt_done=hunt_done,
            gapfill_done=gapfill_done,
            n_validations=n_validations,
            n_clusters=n_clusters,
            n_traces=n_traces,
            findings_total=findings_total,
        )

        return RunProgress(
            run_id=run.id,
            short_id=_short_id(run.id),
            target_repo_path=run.target_repo_path,
            status=run.status,
            started_at=run.started_at,
            finished_at=run.finished_at,
            stages=stages,
            hunt_done=hunt_done,
            hunt_total=hunt_total,
            tokens_used=tokens_used,
            cost_usd=cost_usd,
            findings_total=findings_total,
            findings_by_status=by_status,
            hunt_tasks=hunt_tasks,
        )
