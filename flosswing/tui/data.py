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

import json
from dataclasses import dataclass
from typing import Any

from sqlalchemy import func, select

from flosswing import runpid
from flosswing.stages import report as report_stage
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


def _liveness(run_id: str, status: str) -> str:
    """Reconcile a run's DB status against real process liveness.

    Display-only: the TUI never writes a corrected status back (that would
    race a still-alive run). Returns, for a 'running' row:

    - 'live'    — the PID file points at a live flosswing process.
    - 'stale'   — a PID file exists but its process is gone: a genuine crash.
    - 'unknown' — no usable PID file at all. We cannot conclude the run
                  crashed: it may predate liveness tracking, have been started
                  by another build, or the write may have failed. Absence of
                  evidence is not evidence of death.

    Any terminal status returns 'done'.
    """
    if status != "running":
        return "done"
    # One PID-file read classifies all three running cases.
    return {"live": "live", "dead": "stale", "absent": "unknown"}[
        runpid.liveness(run_id)
    ]


@dataclass(frozen=True)
class RunRow:
    id: str
    short_id: str
    target_repo_path: str
    status: str
    started_at: str
    finished_at: str | None
    findings_count: int
    liveness: str  # "live" | "stale" | "unknown" | "done"
    tokens_used: int
    active_stage: str | None  # derived stage name for running rows, else None


def list_runs() -> list[RunRow]:
    """All runs, newest started_at first, with finding counts, live tokens,
    liveness, and (for running rows) the derived active stage."""
    with st_session.session_scope() as s:
        counts: dict[str, int] = {
            row[0]: row[1]
            for row in s.execute(
                select(Finding.run_id, func.count(Finding.id)).group_by(Finding.run_id)
            ).all()
        }
        token_sums: dict[str, int] = {
            row[0]: int(row[1] or 0)
            for row in s.execute(
                select(
                    AgentSession.run_id,
                    func.coalesce(
                        func.sum(
                            AgentSession.input_tokens + AgentSession.output_tokens
                        ),
                        0,
                    ),
                ).group_by(AgentSession.run_id)
            ).all()
        }
        # Stage-derivation evidence for the *active* stage only, gathered once
        # via grouped/DISTINCT queries (a fixed query count regardless of run
        # count). We collect just Recon/Index/Hunt evidence: the active stage is
        # always one of these three, because Validate/Gapfill/Dedupe/Trace pass
        # active_if_running=False in _derive_stages and so can never be the
        # active stage. The post-Hunt evidence is therefore left as 0/False
        # below — it would only affect those stages' 'done' state, which
        # list_runs does not surface (unlike run_progress, which shows it).
        recon_ids = {
            row[0] for row in s.execute(select(ReconArtifact.run_id).distinct()).all()
        }
        index_ids = {
            row[0] for row in s.execute(select(Symbol.run_id).distinct()).all()
        }
        hunt_total: dict[str, int] = {}
        hunt_done: dict[str, int] = {}
        for run_id, status in s.execute(
            select(HuntTask.run_id, HuntTask.status)
        ).all():
            hunt_total[run_id] = hunt_total.get(run_id, 0) + 1
            if status not in ("pending", "running"):
                hunt_done[run_id] = hunt_done.get(run_id, 0) + 1

        runs = (
            s.execute(select(Run).order_by(Run.started_at.desc()))
            .scalars()
            .all()
        )
        rows: list[RunRow] = []
        for r in runs:
            active_stage: str | None = None
            if r.status == "running":
                # Post-Hunt evidence is passed as 0/False on purpose: those
                # stages are never the 'active' one, so their inputs can't
                # change which stage this extracts (see the comment above).
                stages = _derive_stages(
                    run_running=True,
                    recon_done=r.id in recon_ids,
                    index_done=r.id in index_ids,
                    hunt_total=hunt_total.get(r.id, 0),
                    hunt_done=hunt_done.get(r.id, 0),
                    gapfill_done=False,
                    n_validations=0,
                    n_clusters=0,
                    n_traces=0,
                )
                active_stage = next(
                    (st.name for st in stages if st.state == "active"), None
                )
            rows.append(
                RunRow(
                    id=r.id,
                    short_id=_short_id(r.id),
                    target_repo_path=r.target_repo_path,
                    status=r.status,
                    started_at=r.started_at,
                    finished_at=r.finished_at,
                    findings_count=int(counts.get(r.id, 0)),
                    liveness=_liveness(r.id, r.status),
                    tokens_used=int(token_sums.get(r.id, 0)),
                    active_stage=active_stage,
                )
            )
        return rows


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
    liveness: str  # "live" | "stale" | "unknown" | "done"
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
) -> list[StageState]:
    """Infer per-stage state purely from which rows exist.

    The state DB has no 'current stage' column, so each stage's state is
    derived from its own evidence. A stage with no evidence is 'pending'
    while the run is still running and 'n/a' once it has stopped.
    """
    return [
        _stage("Recon", recon_done, active_if_running=not recon_done, run_running=run_running),
        _stage(
            "Index",
            index_done,
            active_if_running=recon_done and not index_done,
            run_running=run_running,
        ),
        _stage(
            "Hunt",
            hunt_total > 0 and hunt_done == hunt_total,
            active_if_running=hunt_total > 0 and hunt_done < hunt_total,
            run_running=run_running,
        ),
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
        )

        return RunProgress(
            run_id=run.id,
            short_id=_short_id(run.id),
            target_repo_path=run.target_repo_path,
            status=run.status,
            liveness=_liveness(run.id, run.status),
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


@dataclass(frozen=True)
class FindingListRow:
    id: str
    title: str
    attack_class: str
    file: str
    severity: str
    confidence: str
    status: str
    reachable: str | None


@dataclass(frozen=True)
class FindingDetail:
    id: str
    title: str
    attack_class: str
    location: str
    severity: str
    confidence: str
    status: str
    description: str
    poc_code: str | None
    poc_result: str | None
    suggested_fix: str | None
    verdict: str | None
    verdict_rationale: str | None
    reachable: str | None
    trace_rationale: str | None
    call_chain: list[str]


def _run_exists(run_id: str) -> bool:
    """Return True if a Run row for run_id exists."""
    with st_session.session_scope() as s:
        return s.get(Run, run_id) is not None


def findings_list(run_id: str) -> list[FindingListRow]:
    """Findings for a run in report display order, or [] if the run is absent."""
    if not _run_exists(run_id):
        return []
    report = report_stage.load_report(run_id, st_session.session_factory())
    return [
        FindingListRow(
            id=f.id,
            title=f.title,
            attack_class=f.attack_class,
            file=f.file,
            severity=f.severity,
            confidence=f.confidence,
            status=f.status,
            reachable=f.reachable,
        )
        for f in report.findings
    ]


def _format_poc_result(raw: str | None) -> str | None:
    if raw is None:
        return None
    try:
        return json.dumps(json.loads(raw), indent=2)
    except (ValueError, TypeError):
        return raw


def _format_call_chain(chain: list[dict[str, Any]]) -> list[str]:
    hops: list[str] = []
    for hop in chain:
        sym = hop.get("symbol") or hop.get("function") or "?"
        hop_file = hop.get("file") or ""
        line = hop.get("line")
        loc = f"{hop_file}:{line}" if line is not None else str(hop_file)
        hops.append(f"{sym}  ({loc})" if loc else str(sym))
    return hops


def finding_detail(run_id: str, finding_id: str) -> FindingDetail | None:
    """Full detail for one finding, or None if run/finding absent."""
    if not _run_exists(run_id):
        return None
    report = report_stage.load_report(run_id, st_session.session_factory())
    match = next((f for f in report.findings if f.id == finding_id), None)
    if match is None:
        return None

    # poc_result is not on ReportFinding; read it directly.
    with st_session.session_scope() as s:
        row = s.get(Finding, finding_id)
        poc_result_raw = row.poc_result_json if row is not None else None

    fn = f" ({match.function})" if match.function else ""
    location = f"{match.file}:{match.line_start}-{match.line_end}{fn}"
    return FindingDetail(
        id=match.id,
        title=match.title,
        attack_class=match.attack_class,
        location=location,
        severity=match.severity,
        confidence=match.confidence,
        status=match.status,
        description=match.description,
        poc_code=match.poc_code,
        poc_result=_format_poc_result(poc_result_raw),
        suggested_fix=match.suggested_fix,
        verdict=match.validation.verdict if match.validation else None,
        verdict_rationale=match.validation.rationale if match.validation else None,
        reachable=match.trace.reachable if match.trace else match.reachable,
        trace_rationale=match.trace.rationale if match.trace else None,
        call_chain=_format_call_chain(match.trace.call_chain) if match.trace else [],
    )


@dataclass(frozen=True)
class SessionRow:
    stage: str
    model: str
    input_tokens: int
    output_tokens: int
    cost_usd: float
    outcome: str
    refusal_text: str | None
    error_text: str | None


def list_sessions(run_id: str) -> list[SessionRow]:
    """Agent sessions for a run, ordered by start time."""
    with st_session.session_scope() as s:
        rows = (
            s.execute(
                select(AgentSession)
                .where(AgentSession.run_id == run_id)
                .order_by(AgentSession.started_at.asc())
            )
            .scalars()
            .all()
        )
        return [
            SessionRow(
                stage=r.stage,
                model=r.model,
                input_tokens=r.input_tokens,
                output_tokens=r.output_tokens,
                cost_usd=r.cost_usd,
                outcome=r.outcome,
                refusal_text=r.refusal_text,
                error_text=r.error_text,
            )
            for r in rows
        ]
