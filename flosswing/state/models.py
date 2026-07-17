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


class SessionHeartbeat(Base):
    """Ephemeral in-flight-session ticker (one row per run_id).

    Written while an agent session streams, deleted in the same transaction as
    the terminal agent_sessions write. Backs the TUI's live token/cost counter.
    CHECK constraints (ck_session_heartbeats_stage/_tokens/_cost/_tool_calls)
    are enforced server-side and not duplicated in Python. See
    docs/specs/2026-07-16-tui-live-token-cost-design.md.
    """

    __tablename__ = "session_heartbeats"

    run_id: Mapped[str] = mapped_column(
        Text, ForeignKey("runs.id", ondelete="CASCADE"), primary_key=True
    )
    stage: Mapped[str] = mapped_column(Text)
    task_id: Mapped[str | None] = mapped_column(Text, default=None)
    finding_id: Mapped[str | None] = mapped_column(Text, default=None)
    agent_session_id: Mapped[str | None] = mapped_column(Text, default=None)
    model: Mapped[str] = mapped_column(Text)
    input_tokens: Mapped[int] = mapped_column(Integer, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, default=0)
    cache_read_tokens: Mapped[int] = mapped_column(Integer, default=0)
    cache_write_tokens: Mapped[int] = mapped_column(Integer, default=0)
    cost_usd: Mapped[float] = mapped_column(REAL, default=0.0)
    tool_calls_count: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[str] = mapped_column(Text)
    updated_at: Mapped[str] = mapped_column(Text)


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
    # Dedupe-managed (added in v0.8). The columns already exist in the
    # schema (001_initial); v0.8 only adds the Python mappings. CHECK
    # constraint ck_findings_dedupe_role is enforced server-side and not
    # duplicated in Python. The FK from primary_finding_id back to
    # findings.id is named fk_findings_primary_findings (ON DELETE
    # SET NULL); dedupe_cluster_id's FK to dedupe_clusters.id is
    # fk_findings_dedupe_cluster_id_dedupe_clusters (see 001_initial).
    primary_finding_id: Mapped[str | None] = mapped_column(
        Text, ForeignKey("findings.id", ondelete="SET NULL"), default=None
    )
    dedupe_cluster_id: Mapped[str | None] = mapped_column(
        Text,
        ForeignKey("dedupe_clusters.id", ondelete="SET NULL"),
        default=None,
    )
    dedupe_role: Mapped[str | None] = mapped_column(Text, default=None)
    root_cause_summary: Mapped[str | None] = mapped_column(Text, default=None)
    superseded_at: Mapped[str | None] = mapped_column(Text, default=None)
    # Trace-managed (added in v0.9). The column already exists in the
    # schema (001_initial); v0.9 only adds the Python mapping. CHECK
    # constraint ck_findings_reachable is enforced server-side and not
    # duplicated in Python.
    reachable: Mapped[str | None] = mapped_column(Text, default=None)


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


# -----------------------------------------------------------------------------
# v0.8 Dedupe models (per docs/specs/2026-06-02-v0.8-dedupe-design.md
# § SQLAlchemy models). Tables already exist in 001_initial; v0.8 only adds
# the models. CHECK constraints (ck_dedupe_clusters_member_count,
# ck_finding_links_relationship, ck_finding_links_distinct) and the UNIQUE
# constraint (uq_finding_links_ordered) are enforced server-side by SQLite
# and not duplicated in Python.
# -----------------------------------------------------------------------------


class DedupeCluster(Base):
    __tablename__ = "dedupe_clusters"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    run_id: Mapped[str] = mapped_column(
        Text, ForeignKey("runs.id", ondelete="CASCADE")
    )
    primary_finding_id: Mapped[str] = mapped_column(
        Text, ForeignKey("findings.id", ondelete="CASCADE")
    )
    root_cause_summary: Mapped[str] = mapped_column(Text)
    created_at: Mapped[str] = mapped_column(Text)
    member_count: Mapped[int] = mapped_column(Integer)


class FindingLink(Base):
    __tablename__ = "finding_links"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    finding_id_a: Mapped[str] = mapped_column(
        Text, ForeignKey("findings.id", ondelete="CASCADE")
    )
    finding_id_b: Mapped[str] = mapped_column(
        Text, ForeignKey("findings.id", ondelete="CASCADE")
    )
    relationship: Mapped[str] = mapped_column(Text)
    note: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[str] = mapped_column(Text)


# -----------------------------------------------------------------------------
# v0.9 Trace model (per docs/specs/2026-06-02-v0.9-trace-design.md
# § SQLAlchemy models). Table already exists in 001_initial; v0.9 only adds
# the model. CHECK constraints (ck_traces_reachable, ck_traces_call_chain_valid,
# ck_traces_reachable_has_entry_point) and the UNIQUE constraint
# (uq_traces_finding_id) are enforced server-side by SQLite and not duplicated
# in Python.
# -----------------------------------------------------------------------------


class Trace(Base):
    __tablename__ = "traces"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    finding_id: Mapped[str] = mapped_column(
        Text, ForeignKey("findings.id", ondelete="CASCADE")
    )
    reachable: Mapped[str] = mapped_column(Text)
    entry_point_symbol: Mapped[str | None] = mapped_column(Text, default=None)
    entry_point_id: Mapped[str | None] = mapped_column(
        Text,
        ForeignKey("entry_points.id", ondelete="SET NULL"),
        default=None,
    )
    call_chain_json: Mapped[str] = mapped_column(Text)
    rationale: Mapped[str] = mapped_column(Text)
    agent_session_id: Mapped[str] = mapped_column(
        Text, ForeignKey("agent_sessions.id", ondelete="RESTRICT")
    )
    created_at: Mapped[str] = mapped_column(Text)
