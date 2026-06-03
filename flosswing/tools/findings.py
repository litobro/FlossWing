"""record_recon_artifact, add_hunt_task: state-writing tools.

Per docs/tool-contracts.md § recon artifacts and § task management.
Validation happens server-side: attack_class is checked against
attack_classes.REGISTRY; recon artifact uniqueness is enforced by
the schema's uq_recon_artifacts_run_id constraint plus an explicit
pre-check for a friendlier error.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel
from sqlalchemy import select
from ulid import ULID

from flosswing import attack_classes
from flosswing.errors import ReconAlreadyRecordedError
from flosswing.state import session as st_session
from flosswing.state.models import HuntTask, ReconArtifact

# -----------------------------------------------------------------------------
# record_recon_artifact
# -----------------------------------------------------------------------------


class EntryPoint(BaseModel):
    symbol: str
    file: str
    line: int
    kind: Literal["http", "cli", "exported", "deserializer", "ipc"]
    attacker_controlled_input: bool
    notes: str = ""


class TrustBoundary(BaseModel):
    kind: Literal["network", "file", "ipc", "deserialization", "subprocess", "other"]
    description: str
    files: list[str]


class Subsystem(BaseModel):
    name: str
    description: str
    paths: list[str]
    languages: list[str]
    notes: str


class RecordReconArtifactInput(BaseModel):
    languages: list[str]
    build_commands: dict[str, str]
    entry_points: list[EntryPoint]
    trust_boundaries: list[TrustBoundary]
    subsystems: list[Subsystem]
    notes: str


class RecordReconArtifactOutput(BaseModel):
    artifact_id: str


def record_recon_artifact(
    inp: RecordReconArtifactInput, *, run_id: str
) -> RecordReconArtifactOutput:
    with st_session.session_scope() as s:
        existing = s.execute(
            select(ReconArtifact).where(ReconArtifact.run_id == run_id)
        ).scalar_one_or_none()
        if existing is not None:
            raise ReconAlreadyRecordedError(
                f"recon_artifact already recorded for run {run_id}"
            )

        artifact_id = str(ULID())
        s.add(
            ReconArtifact(
                id=artifact_id,
                run_id=run_id,
                languages_json=json.dumps(inp.languages),
                build_commands_json=json.dumps(inp.build_commands, sort_keys=True),
                trust_boundaries_json=json.dumps(
                    [tb.model_dump() for tb in inp.trust_boundaries]
                ),
                subsystems_json=json.dumps(
                    [s_.model_dump() for s_ in inp.subsystems]
                ),
                notes=inp.notes,
                recorded_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            )
        )

    return RecordReconArtifactOutput(artifact_id=artifact_id)


# -----------------------------------------------------------------------------
# add_hunt_task
# -----------------------------------------------------------------------------


class AddHuntTaskInput(BaseModel):
    attack_class: str
    scope_hint: str
    rationale: str = ""
    priority: Literal["high", "normal", "low"] = "normal"
    parent_finding_id: str | None = None


class AddHuntTaskOutput(BaseModel):
    task_id: str
    accepted: bool
    reason: str | None = None


def add_hunt_task(
    inp: AddHuntTaskInput,
    *,
    run_id: str,
    source: Literal["recon", "gapfill"],
    budget_total: int,
) -> AddHuntTaskOutput:
    attack_classes.validate(inp.attack_class)

    with st_session.session_scope() as s:
        current = (
            s.execute(select(HuntTask).where(HuntTask.run_id == run_id))
            .scalars()
            .all()
        )
        if len(current) >= budget_total:
            return AddHuntTaskOutput(
                task_id="",
                accepted=False,
                reason=f"budget exhausted ({budget_total} tasks already queued)",
            )

        task_id = str(ULID())
        s.add(
            HuntTask(
                id=task_id,
                run_id=run_id,
                attack_class=inp.attack_class,
                scope_hint=inp.scope_hint,
                rationale=inp.rationale,
                priority=inp.priority,
                source=source,
                parent_finding_id=inp.parent_finding_id,
                status="pending",
                created_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                findings_count=0,
            )
        )

    return AddHuntTaskOutput(task_id=task_id, accepted=True, reason=None)
