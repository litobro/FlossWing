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
    target_repo_path: Mapped[str] = mapped_column(Text, nullable=False)
    target_repo_sha: Mapped[str | None] = mapped_column(Text, nullable=True)
    depth: Mapped[str] = mapped_column(Text, nullable=False)
    budget_total: Mapped[int] = mapped_column(Integer, nullable=False)
    budget_used: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    started_at: Mapped[str] = mapped_column(Text, nullable=False)
    finished_at: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="running")
    config_json: Mapped[str] = mapped_column(Text, nullable=False)
    flosswing_version: Mapped[str] = mapped_column(Text, nullable=False)


class ReconArtifact(Base):
    __tablename__ = "recon_artifacts"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    run_id: Mapped[str] = mapped_column(
        Text, ForeignKey("runs.id", ondelete="CASCADE"), nullable=False
    )
    languages_json: Mapped[str] = mapped_column(Text, nullable=False)
    build_commands_json: Mapped[str] = mapped_column(Text, nullable=False)
    trust_boundaries_json: Mapped[str] = mapped_column(Text, nullable=False)
    subsystems_json: Mapped[str] = mapped_column(Text, nullable=False)
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    recorded_at: Mapped[str] = mapped_column(Text, nullable=False)


class HuntTask(Base):
    __tablename__ = "hunt_tasks"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    run_id: Mapped[str] = mapped_column(
        Text, ForeignKey("runs.id", ondelete="CASCADE"), nullable=False
    )
    attack_class: Mapped[str] = mapped_column(Text, nullable=False)
    scope_hint: Mapped[str] = mapped_column(Text, nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False, default="")
    priority: Mapped[str] = mapped_column(Text, nullable=False, default="normal")
    source: Mapped[str] = mapped_column(Text, nullable=False)
    parent_finding_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="pending")
    created_at: Mapped[str] = mapped_column(Text, nullable=False)
    started_at: Mapped[str | None] = mapped_column(Text, nullable=True)
    finished_at: Mapped[str | None] = mapped_column(Text, nullable=True)
    findings_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class AgentSession(Base):
    __tablename__ = "agent_sessions"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    run_id: Mapped[str] = mapped_column(
        Text, ForeignKey("runs.id", ondelete="CASCADE"), nullable=False
    )
    stage: Mapped[str] = mapped_column(Text, nullable=False)
    task_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    finding_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    model: Mapped[str] = mapped_column(Text, nullable=False)
    system_prompt_hash: Mapped[str] = mapped_column(Text, nullable=False)
    input_tokens: Mapped[int] = mapped_column(Integer, nullable=False)
    output_tokens: Mapped[int] = mapped_column(Integer, nullable=False)
    cache_read_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    cache_write_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    cost_usd: Mapped[float] = mapped_column(REAL, nullable=False)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    outcome: Mapped[str] = mapped_column(Text, nullable=False)
    refusal_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    tool_calls_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    started_at: Mapped[str] = mapped_column(Text, nullable=False)
    finished_at: Mapped[str] = mapped_column(Text, nullable=False)
