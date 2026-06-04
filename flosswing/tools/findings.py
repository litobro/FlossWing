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
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel
from sqlalchemy import select
from ulid import ULID

from flosswing import attack_classes
from flosswing.errors import (
    DescriptionRequiredForConfirmedError,
    DescriptionTooLargeError,
    EvidenceFilesTooManyError,
    FindingAlreadyValidatedError,
    FindingNotFoundError,
    LineRangeInvalidError,
    PathNotInRepoError,
    RationaleTooShortError,
    ReconAlreadyRecordedError,
    SuggestedFixTooLargeError,
)
from flosswing.state import session as st_session
from flosswing.state.models import Finding, HuntTask, ReconArtifact, Validation

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
    gapfill_new_task_cap: int | None = None,
) -> AddHuntTaskOutput:
    """Enqueue a Hunt task.

    Per docs/tool-contracts.md § Scope: task management. The Pydantic
    contract surface (AddHuntTaskInput / AddHuntTaskOutput) is unchanged;
    v0.7 adds a keyword-only Python parameter ``gapfill_new_task_cap``
    that, when set, enforces the 20%-rule cap on rows with
    ``source='gapfill'`` for this run.

    Per design decision #1 of docs/specs/2026-06-02-v0.7-gapfill-design.md
    the cap is ``max(1, recon_task_count // 5)``, computed by the Gapfill
    stage and passed through. Per plan-time decision #2 of
    docs/plans/2026-06-04-v0.7-gapfill.md the cap is enforced at the tool
    layer (in addition to the prompt-side hard cap message). Per plan-time
    decision #5 the Gapfill cap check precedes the ``budget_total`` check
    so the operator-facing reason string is the more specific one.
    """
    attack_classes.validate(inp.attack_class)

    with st_session.session_scope() as s:
        # Gapfill cap: count existing source='gapfill' rows for this run.
        # Decision #5: this check precedes the budget_total check so the
        # operator-facing reason is the more specific one when both fire.
        if gapfill_new_task_cap is not None:
            existing_gapfill = (
                s.execute(
                    select(HuntTask).where(
                        HuntTask.run_id == run_id,
                        HuntTask.source == "gapfill",
                    )
                )
                .scalars()
                .all()
            )
            if len(existing_gapfill) >= gapfill_new_task_cap:
                return AddHuntTaskOutput(
                    task_id="",
                    accepted=False,
                    reason="gapfill_cap_reached",
                )

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


# -----------------------------------------------------------------------------
# record_finding  (per docs/tool-contracts.md § findings (Hunt-side))
# -----------------------------------------------------------------------------


# Application-layer size caps (the findings table has no column-side cap;
# we mirror the fs.py read-size shape — 64 KB per blob).
_FINDING_TEXT_CAP_BYTES: int = 64 * 1024


class RecordFindingInput(BaseModel):
    attack_class: str
    file: str
    function: str | None = None
    line_start: int
    line_end: int
    severity: Literal["critical", "high", "medium", "low", "info"]
    confidence: Literal["confirmed", "likely", "speculative"]
    title: str
    description: str
    poc_code: str | None = None
    # poc_result is part of the contract signature but unreachable in v0.3
    # (no compile_and_run yet). Accept it as opaque dict so the contract
    # stays frozen; we serialize to JSON if present.
    poc_result: dict[str, Any] | None = None
    suggested_fix: str | None = None
    related_findings: list[str] = []


class RecordFindingOutput(BaseModel):
    finding_id: str
    duplicate_of: str | None = None


def _resolve_inside_repo_str(rel: str, repo_root: Path) -> None:
    """Raise PathNotInRepoError if rel doesn't resolve inside repo_root."""
    if Path(rel).is_absolute():
        raise PathNotInRepoError(f"path escapes repo root: {rel}")
    candidate = (repo_root / rel).resolve(strict=False)
    try:
        candidate.relative_to(repo_root.resolve(strict=False))
    except ValueError as e:
        raise PathNotInRepoError(f"path escapes repo root: {rel}") from e


def record_finding(
    inp: RecordFindingInput,
    *,
    run_id: str,
    hunt_task_id: str,
    repo_root: Path,
) -> RecordFindingOutput:
    """Record a Hunt finding. See docs/tool-contracts.md § findings (Hunt-side)."""
    attack_classes.validate(inp.attack_class)
    _resolve_inside_repo_str(inp.file, repo_root)

    if inp.line_start < 1 or inp.line_end < inp.line_start:
        raise LineRangeInvalidError(
            f"line_range_invalid: start={inp.line_start} end={inp.line_end}"
        )

    if inp.confidence == "confirmed" and (
        not inp.description.strip()
        or (inp.poc_code is None and inp.poc_result is None)
    ):
        raise DescriptionRequiredForConfirmedError(
            "confidence='confirmed' requires a non-empty description AND "
            "either a poc_code or a poc_result. In v0.3, compile_and_run "
            "is not yet available, so use confidence='likely' or "
            "'speculative' instead."
        )

    if len(inp.description.encode("utf-8")) > _FINDING_TEXT_CAP_BYTES:
        raise DescriptionTooLargeError(
            f"description exceeds {_FINDING_TEXT_CAP_BYTES} bytes"
        )
    if (
        inp.suggested_fix is not None
        and len(inp.suggested_fix.encode("utf-8")) > _FINDING_TEXT_CAP_BYTES
    ):
        raise SuggestedFixTooLargeError(
            f"suggested_fix exceeds {_FINDING_TEXT_CAP_BYTES} bytes"
        )

    finding_id = str(ULID())
    with st_session.session_scope() as s:
        s.add(
            Finding(
                id=finding_id,
                run_id=run_id,
                hunt_task_id=hunt_task_id,
                attack_class=inp.attack_class,
                file=inp.file,
                function=inp.function,
                line_start=inp.line_start,
                line_end=inp.line_end,
                severity=inp.severity,
                confidence=inp.confidence,
                status="pending_validation",
                title=inp.title,
                description=inp.description,
                poc_code=inp.poc_code,
                poc_result_json=(
                    json.dumps(inp.poc_result, sort_keys=True)
                    if inp.poc_result is not None
                    else None
                ),
                suggested_fix=inp.suggested_fix,
                created_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            )
        )
        task = s.get(HuntTask, hunt_task_id)
        if task is not None:
            task.findings_count = (task.findings_count or 0) + 1

    return RecordFindingOutput(finding_id=finding_id, duplicate_of=None)


# -----------------------------------------------------------------------------
# query_findings  (per docs/tool-contracts.md § findings (Validate-side))
#
# Read access to the current run's findings, with optional filters. Available
# to Validate, Dedupe (agent pass), and Trace per the tool-scope matrix.
# -----------------------------------------------------------------------------

# Plan-time decision #4 of docs/plans/2026-06-02-v0.6-validate.md.
_QUERY_FINDINGS_CAP: int = 100

# Severity ordering for the min_severity filter. Lower rank == more severe.
_SEVERITY_RANK: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


class QueryFindingsInput(BaseModel):
    finding_id: str | None = None
    attack_class: str | None = None
    file: str | None = None
    status: Literal[
        "pending_validation", "confirmed", "rejected", "uncertain", "any"
    ] = "any"
    min_severity: (
        Literal["critical", "high", "medium", "low", "info"] | None
    ) = None


class _FindingRow(BaseModel):
    """The Finding shape returned to the agent.

    Matches docs/tool-contracts.md § findings (Validate-side) `Finding`
    verbatim. Aliased to a private name in this module because the
    SQLAlchemy ORM class also named `Finding` is imported here; the
    public surface is exposed via QueryFindingsOutput.findings.

    Note has_poc_result is a derived boolean over poc_result_json IS NOT
    NULL — the full JSON blob never leaves the DB through this tool.
    """

    finding_id: str
    attack_class: str
    file: str
    function: str | None
    line_start: int
    line_end: int
    severity: Literal["critical", "high", "medium", "low", "info"]
    confidence: Literal["confirmed", "likely", "speculative"]
    status: Literal[
        "pending_validation", "confirmed", "rejected", "uncertain"
    ]
    title: str
    description: str
    poc_code: str | None
    has_poc_result: bool
    suggested_fix: str | None


class QueryFindingsOutput(BaseModel):
    findings: list[_FindingRow]
    truncated: bool


def query_findings(
    inp: QueryFindingsInput, *, run_id: str
) -> QueryFindingsOutput:
    """Read findings from the current run, with optional filters.

    Per docs/tool-contracts.md § findings (Validate-side) query_findings.
    Run scoping is enforced server-side; an agent cannot leak across runs
    even if it supplies a foreign finding_id.

    Truncation: rows are capped at _QUERY_FINDINGS_CAP (plan-time decision
    #4). We SELECT cap+1 rows so we can detect overflow without a second
    COUNT query, then clip and set truncated accordingly.
    """
    with st_session.session_scope() as s:
        stmt = select(Finding).where(Finding.run_id == run_id)
        if inp.finding_id is not None:
            stmt = stmt.where(Finding.id == inp.finding_id)
        if inp.attack_class is not None:
            stmt = stmt.where(Finding.attack_class == inp.attack_class)
        if inp.file is not None:
            stmt = stmt.where(Finding.file == inp.file)
        if inp.status != "any":
            stmt = stmt.where(Finding.status == inp.status)
        rows = (
            s.execute(stmt.limit(_QUERY_FINDINGS_CAP + 1)).scalars().all()
        )
        truncated = len(rows) > _QUERY_FINDINGS_CAP
        rows = rows[:_QUERY_FINDINGS_CAP]
        if inp.min_severity is not None:
            min_rank = _SEVERITY_RANK[inp.min_severity]
            rows = [
                r for r in rows
                if _SEVERITY_RANK.get(r.severity, 99) <= min_rank
            ]
        # Materialize inside the session scope; ORM rows expire on exit.
        out_rows = [
            _FindingRow(
                finding_id=r.id,
                attack_class=r.attack_class,
                file=r.file,
                function=r.function,
                line_start=r.line_start,
                line_end=r.line_end,
                # SQLAlchemy Mapped[str] doesn't narrow to the contract's
                # Literal[...]; insertion-side validation guarantees the
                # value is always one of the documented literal options.
                severity=r.severity,  # type: ignore[arg-type]
                confidence=r.confidence,  # type: ignore[arg-type]
                status=r.status,  # type: ignore[arg-type]
                title=r.title,
                description=r.description,
                poc_code=r.poc_code,
                has_poc_result=r.poc_result_json is not None,
                suggested_fix=r.suggested_fix,
            )
            for r in rows
        ]
    return QueryFindingsOutput(findings=out_rows, truncated=truncated)


# -----------------------------------------------------------------------------
# validate_finding  (per docs/tool-contracts.md § findings (Validate-side))
#
# Per plan preamble decision #3 (operator override on 2026-06-03), the 64 KB
# byte-level cap on evidence_files_json is NOT implemented. Only the spec's
# 100-entry list cap (EvidenceFilesTooManyError) ships.
# -----------------------------------------------------------------------------

_RATIONALE_MIN_CHARS: int = 50
_EVIDENCE_FILES_MAX_COUNT: int = 100


class ValidateFindingInput(BaseModel):
    finding_id: str
    verdict: Literal["confirmed", "rejected", "uncertain"]
    rationale: str
    evidence_files: list[str] = []


class ValidateFindingOutput(BaseModel):
    finding_id: str
    new_status: Literal["confirmed", "rejected", "uncertain"]


def validate_finding(
    inp: ValidateFindingInput,
    *,
    run_id: str,
    agent_session_id: str,
) -> ValidateFindingOutput:
    """Record an adversarial-review verdict for an existing finding.

    Per docs/tool-contracts.md § findings (Validate-side) validate_finding.
    Run scoping is enforced server-side; an agent cannot validate findings
    in other runs even if it hallucinates a foreign finding_id.

    Three-stage validation, in order: (1) input shape (rationale length,
    evidence_files length); (2) target row exists in this run; (3) no prior
    validation row exists for this finding. The DB-level UNIQUE on
    uq_validations_finding_id is belt-and-suspenders against a future
    parallel-Validate race; for v0.6 sequential it's unreachable on the
    happy path.

    Per plan-time decision #5, agent_session_id and the binding to one
    finding flow via wrapper kwargs (and the closed-over finding_id on
    the input model) — the stage decides which finding gets validated,
    not the agent.
    """
    # Stage 1: input-shape checks.
    if len(inp.rationale) < _RATIONALE_MIN_CHARS:
        raise RationaleTooShortError(
            f"rationale must be >= {_RATIONALE_MIN_CHARS} chars; "
            f"got {len(inp.rationale)}"
        )
    if len(inp.evidence_files) > _EVIDENCE_FILES_MAX_COUNT:
        raise EvidenceFilesTooManyError(
            f"evidence_files has {len(inp.evidence_files)} entries "
            f"(cap={_EVIDENCE_FILES_MAX_COUNT})"
        )
    evidence_json = json.dumps(inp.evidence_files)

    now = datetime.now(UTC).isoformat().replace("+00:00", "Z")

    # Stages 2 + 3 + write: one transaction.
    with st_session.session_scope() as s:
        finding = s.execute(
            select(Finding).where(
                Finding.id == inp.finding_id,
                Finding.run_id == run_id,
            )
        ).scalar_one_or_none()
        if finding is None:
            raise FindingNotFoundError(
                f"finding_id={inp.finding_id!r} not found in run "
                f"{run_id!r}"
            )

        existing_validation = s.execute(
            select(Validation).where(Validation.finding_id == inp.finding_id)
        ).scalar_one_or_none()
        if existing_validation is not None:
            raise FindingAlreadyValidatedError(
                f"finding_id={inp.finding_id!r} already has a "
                "validations row"
            )

        validation_id = str(ULID())
        s.add(
            Validation(
                id=validation_id,
                finding_id=inp.finding_id,
                verdict=inp.verdict,
                rationale=inp.rationale,
                evidence_files_json=evidence_json,
                agent_session_id=agent_session_id,
                created_at=now,
            )
        )
        finding.status = inp.verdict
        finding.validated_at = now

    return ValidateFindingOutput(
        finding_id=inp.finding_id, new_status=inp.verdict
    )
