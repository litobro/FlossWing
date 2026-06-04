"""SQLAlchemy 2.0 declarative models for v0.2.

Only the four tables Recon touches in v0.2 are modeled here. The other
nine tables in docs/schema.sql get models when the milestone that
consumes them lands. The shared MetaData (with the naming convention)
lives in flosswing.state.db.
"""

from __future__ import annotations

from sqlalchemy import REAL, ForeignKey, Integer, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from flosswing.state.db import metadata as _metadata


class Base(DeclarativeBase):
    metadata = _metadata


class Run(Base):
    __tablename__ = "runs"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    target_repo_path: Mapped[str] = mapped_column(Text)
    target_repo_sha: Mapped[str | None] = mapped_column(Text)
    depth: Mapped[str] = mapped_column(Text)
    budget_total: Mapped[int] = mapped_column(Integer)
    budget_used: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[str] = mapped_column(Text)
    finished_at: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text, default="running")
    config_json: Mapped[str] = mapped_column(Text)
    flosswing_version: Mapped[str] = mapped_column(Text)


class ReconArtifact(Base):
    __tablename__ = "recon_artifacts"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    run_id: Mapped[str] = mapped_column(
        Text, ForeignKey("runs.id", ondelete="CASCADE")
    )
    languages_json: Mapped[str] = mapped_column(Text)
    build_commands_json: Mapped[str] = mapped_column(Text)
    trust_boundaries_json: Mapped[str] = mapped_column(Text)
    subsystems_json: Mapped[str] = mapped_column(Text)
    notes: Mapped[str] = mapped_column(Text, default="")
    recorded_at: Mapped[str] = mapped_column(Text)


class HuntTask(Base):
    __tablename__ = "hunt_tasks"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    run_id: Mapped[str] = mapped_column(
        Text, ForeignKey("runs.id", ondelete="CASCADE")
    )
    attack_class: Mapped[str] = mapped_column(Text)
    scope_hint: Mapped[str] = mapped_column(Text)
    rationale: Mapped[str] = mapped_column(Text, default="")
    priority: Mapped[str] = mapped_column(Text, default="normal")
    source: Mapped[str] = mapped_column(Text)
    parent_finding_id: Mapped[str | None] = mapped_column(Text)
    # parent_finding_id intentionally NOT FK'd; see docs/schema.sql:280-282.
    # Add FK to findings.id when the Findings model lands (v0.3+).
    status: Mapped[str] = mapped_column(Text, default="pending")
    created_at: Mapped[str] = mapped_column(Text)
    started_at: Mapped[str | None] = mapped_column(Text)
    finished_at: Mapped[str | None] = mapped_column(Text)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)


class AgentSession(Base):
    __tablename__ = "agent_sessions"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    run_id: Mapped[str] = mapped_column(
        Text, ForeignKey("runs.id", ondelete="CASCADE")
    )
    stage: Mapped[str] = mapped_column(Text)
    task_id: Mapped[str | None] = mapped_column(Text)
    finding_id: Mapped[str | None] = mapped_column(Text)
    model: Mapped[str] = mapped_column(Text)
    system_prompt_hash: Mapped[str] = mapped_column(Text)
    input_tokens: Mapped[int] = mapped_column(Integer)
    output_tokens: Mapped[int] = mapped_column(Integer)
    cache_read_tokens: Mapped[int] = mapped_column(Integer, default=0)
    cache_write_tokens: Mapped[int] = mapped_column(Integer, default=0)
    cost_usd: Mapped[float] = mapped_column(REAL)
    duration_ms: Mapped[int] = mapped_column(Integer)
    outcome: Mapped[str] = mapped_column(Text)
    refusal_text: Mapped[str | None] = mapped_column(Text)
    error_text: Mapped[str | None] = mapped_column(Text)
    tool_calls_count: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[str] = mapped_column(Text)
    finished_at: Mapped[str] = mapped_column(Text)


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    run_id: Mapped[str] = mapped_column(
        Text, ForeignKey("runs.id", ondelete="CASCADE")
    )
    hunt_task_id: Mapped[str] = mapped_column(
        Text, ForeignKey("hunt_tasks.id", ondelete="CASCADE")
    )
    attack_class: Mapped[str] = mapped_column(Text)
    file: Mapped[str] = mapped_column(Text)
    function: Mapped[str | None] = mapped_column(Text)
    line_start: Mapped[int] = mapped_column(Integer)
    line_end: Mapped[int] = mapped_column(Integer)
    severity: Mapped[str] = mapped_column(Text)
    confidence: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text, default="pending_validation")
    title: Mapped[str] = mapped_column(Text)
    description: Mapped[str] = mapped_column(Text)
    poc_code: Mapped[str | None] = mapped_column(Text)
    poc_result_json: Mapped[str | None] = mapped_column(Text)
    suggested_fix: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[str] = mapped_column(Text)
    # Validate-managed (added in v0.6):
    validated_at: Mapped[str | None] = mapped_column(Text, default=None)
    # Dedupe-managed columns (primary_finding_id, dedupe_cluster_id,
    # dedupe_role, root_cause_summary, superseded_at) and Trace-managed
    # (reachable) exist in the schema but are intentionally not mapped
    # here — Hunt does not read or write them in v0.3.


# -----------------------------------------------------------------------------
# v0.5 symbol-index models (per docs/specs/2026-06-02-v0.5-symbol-index-design.md
# § SQLAlchemy models). Tables already exist in 001_initial; v0.5 only adds
# models. CHECK constraints (ck_symbols_kind, ck_symbols_lines,
# ck_call_sites_line, ck_entry_points_kind, ck_entry_points_attacker_input,
# ck_entry_points_line) are enforced server-side by SQLite and not duplicated
# in Python.
# -----------------------------------------------------------------------------


class Symbol(Base):
    __tablename__ = "symbols"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    run_id: Mapped[str] = mapped_column(
        Text, ForeignKey("runs.id", ondelete="CASCADE")
    )
    symbol: Mapped[str] = mapped_column(Text)
    fully_qualified_name: Mapped[str] = mapped_column(Text)
    file: Mapped[str] = mapped_column(Text)
    line_start: Mapped[int] = mapped_column(Integer)
    line_end: Mapped[int] = mapped_column(Integer)
    kind: Mapped[str] = mapped_column(Text)
    language: Mapped[str] = mapped_column(Text)


class CallSite(Base):
    __tablename__ = "call_sites"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    run_id: Mapped[str] = mapped_column(
        Text, ForeignKey("runs.id", ondelete="CASCADE")
    )
    caller_symbol_id: Mapped[str] = mapped_column(
        Text, ForeignKey("symbols.id", ondelete="CASCADE")
    )
    callee_symbol_id: Mapped[str | None] = mapped_column(
        Text, ForeignKey("symbols.id", ondelete="SET NULL"), nullable=True
    )
    callee_text: Mapped[str] = mapped_column(Text)
    file: Mapped[str] = mapped_column(Text)
    line: Mapped[int] = mapped_column(Integer)
    snippet: Mapped[str] = mapped_column(Text)


class EntryPoint(Base):
    __tablename__ = "entry_points"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    recon_artifact_id: Mapped[str] = mapped_column(
        Text, ForeignKey("recon_artifacts.id", ondelete="CASCADE")
    )
    run_id: Mapped[str] = mapped_column(
        Text, ForeignKey("runs.id", ondelete="CASCADE")
    )
    symbol: Mapped[str] = mapped_column(Text)
    file: Mapped[str] = mapped_column(Text)
    line: Mapped[int] = mapped_column(Integer)
    kind: Mapped[str] = mapped_column(Text)
    # 0 | 1 — cast to bool in the tool layer per § Component responsibilities.
    attacker_controlled_input: Mapped[int] = mapped_column(Integer)
    notes: Mapped[str] = mapped_column(Text, default="")


# -----------------------------------------------------------------------------
# v0.6 Validate model (per docs/specs/2026-06-02-v0.6-validate-design.md
# § SQLAlchemy models). Table already exists in 001_initial; v0.6 only adds
# the model. CHECK constraints (ck_validations_verdict,
# ck_validations_evidence_valid) and the UNIQUE constraint
# (uq_validations_finding_id) are enforced server-side by SQLite and not
# duplicated in Python.
# -----------------------------------------------------------------------------


class Validation(Base):
    __tablename__ = "validations"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    finding_id: Mapped[str] = mapped_column(
        Text, ForeignKey("findings.id", ondelete="CASCADE")
    )
    verdict: Mapped[str] = mapped_column(Text)
    rationale: Mapped[str] = mapped_column(Text)
    evidence_files_json: Mapped[str] = mapped_column(Text, default="[]")
    agent_session_id: Mapped[str] = mapped_column(
        Text, ForeignKey("agent_sessions.id", ondelete="RESTRICT")
    )
    created_at: Mapped[str] = mapped_column(Text)
