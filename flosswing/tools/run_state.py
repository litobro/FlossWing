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

"""query_run_state: read-only aggregation across runs, recon_artifacts,
hunt_tasks, and agent_sessions.

Per docs/tool-contracts.md § Scope: run state (read-only). Frozen
contract — the Pydantic Input/Output models are copied verbatim from
the contract.

Per plan-time decision #1 of docs/plans/2026-06-04-v0.7-gapfill.md the
function reads the DB directly (no in-memory result-object shortcut),
which makes the aggregation deterministic from DB state alone. Per
plan-time decision #6 no new error classes — recon_artifact is None
when there is no row, and budget_remaining clamps to >=0.
"""

from __future__ import annotations

import json
from typing import Literal

from pydantic import BaseModel
from sqlalchemy import select

from flosswing.state import session as st_session
from flosswing.state.models import AgentSession, HuntTask, ReconArtifact
from flosswing.tools.findings import (
    EntryPoint,
    RecordReconArtifactInput,
    Subsystem,
    TrustBoundary,
)

# -----------------------------------------------------------------------------
# Frozen contract (copied from docs/tool-contracts.md § Scope: run state)
# -----------------------------------------------------------------------------


class QueryRunStateInput(BaseModel):
    """No parameters; returns the current run summary."""

    # Pydantic v2 accepts empty BaseModel; explicit `pass` makes the
    # "no fields" intent visible to readers of the source.
    pass


class HuntTaskSummary(BaseModel):
    task_id: str
    attack_class: str
    scope_hint: str
    status: Literal[
        "pending", "running", "completed",
        "refused", "budget_exceeded", "errored",
    ]
    findings_count: int


class QueryRunStateOutput(BaseModel):
    run_id: str
    recon_artifact: RecordReconArtifactInput | None
    hunt_tasks: list[HuntTaskSummary]
    budget_used: int
    budget_remaining: int


# -----------------------------------------------------------------------------
# Implementation
# -----------------------------------------------------------------------------


def _project_recon_artifact(row: ReconArtifact) -> RecordReconArtifactInput:
    """Re-project a stored recon_artifacts row back into the contract shape.

    The Recon writer stores the four nested fields as JSON columns
    (languages_json, build_commands_json, trust_boundaries_json,
    subsystems_json); read-back is the inverse transformation. The
    `entry_points` column does not yet exist in the schema (v0.2's
    ReconArtifact model maps the JSON columns listed above; entry_points
    is captured as part of subsystems' notes today — to be normalized
    in a later milestone). v0.7 returns an empty list for entry_points
    so the Pydantic shape is satisfied.
    """
    languages = json.loads(row.languages_json)
    build_commands = json.loads(row.build_commands_json)
    trust_boundaries_raw = json.loads(row.trust_boundaries_json)
    subsystems_raw = json.loads(row.subsystems_json)
    # v0.7: entry_points is not yet a stored column (see docstring); pass an
    # empty list to satisfy the Pydantic shape. Annotated to keep mypy strict
    # happy without a `# type: ignore`.
    entry_points: list[EntryPoint] = []
    return RecordReconArtifactInput(
        languages=languages,
        build_commands=build_commands,
        entry_points=entry_points,
        trust_boundaries=[
            TrustBoundary(**tb) for tb in trust_boundaries_raw
        ],
        subsystems=[Subsystem(**s_) for s_ in subsystems_raw],
        notes=row.notes,
    )


def query_run_state(
    inp: QueryRunStateInput,
    *,
    run_id: str,
    total_token_budget: int,
) -> QueryRunStateOutput:
    """Read aggregate state for the current run.

    Per docs/tool-contracts.md § Scope: run state. Run scoping is
    enforced server-side; the agent cannot leak across runs.

    `total_token_budget` is passed by the caller (the Gapfill stage
    computes it from cfg). Per the contract: "best-effort against any
    total estimate the config carries (else 0)" — passing 0 yields
    budget_remaining=0 unambiguously.
    """
    del inp  # contract requires no input parameters
    with st_session.session_scope() as s:
        recon_row = s.execute(
            select(ReconArtifact).where(ReconArtifact.run_id == run_id)
        ).scalar_one_or_none()
        recon_artifact = (
            _project_recon_artifact(recon_row)
            if recon_row is not None
            else None
        )

        hunt_rows = list(
            s.execute(
                select(HuntTask).where(HuntTask.run_id == run_id)
            ).scalars().all()
        )
        hunt_tasks = [
            HuntTaskSummary(
                task_id=t.id,
                attack_class=t.attack_class,
                scope_hint=t.scope_hint,
                # SQLAlchemy Mapped[str] doesn't narrow to the contract's
                # Literal[...]; the schema's ck_hunt_tasks_status check
                # guarantees the value is always one of the literals.
                status=t.status,  # type: ignore[arg-type]
                findings_count=t.findings_count or 0,
            )
            for t in hunt_rows
        ]

        session_rows = list(
            s.execute(
                select(AgentSession).where(AgentSession.run_id == run_id)
            ).scalars().all()
        )
        budget_used = sum(
            (r.input_tokens or 0) + (r.output_tokens or 0)
            for r in session_rows
        )

    budget_remaining = max(0, total_token_budget - budget_used)
    return QueryRunStateOutput(
        run_id=run_id,
        recon_artifact=recon_artifact,
        hunt_tasks=hunt_tasks,
        budget_used=budget_used,
        budget_remaining=budget_remaining,
    )


__all__ = [
    "HuntTaskSummary",
    "QueryRunStateInput",
    "QueryRunStateOutput",
    "query_run_state",
]
