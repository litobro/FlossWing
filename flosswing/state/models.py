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
    # Dedupe-managed columns (primary_finding_id, dedupe_cluster_id,
    # dedupe_role, root_cause_summary, superseded_at) and Trace-managed
    # (reachable) exist in the schema but are intentionally not mapped
    # here — Hunt does not read or write them in v0.3.
