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

"""initial schema

Revision ID: 001_initial
Revises:
Create Date: 2026-05-25

Creates all 13 tables defined in docs/schema.sql. Every constraint is
explicitly named per the conventions in the schema header. Tables are
created in foreign-key dependency order; downgrade drops in reverse.

Note on findings.dedupe_cluster_id: the schema comment refers to a link
table that does not exist; we declare the FK directly here as
ON DELETE SET NULL. Flag for schema reconciliation.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "001_initial"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # ------------------------------------------------------------------- runs
    op.create_table(
        "runs",
        sa.Column("id", sa.Text(), nullable=False),
        sa.Column("target_repo_path", sa.Text(), nullable=False),
        sa.Column("target_repo_sha", sa.Text(), nullable=True),
        sa.Column("depth", sa.Text(), nullable=False),
        sa.Column("budget_total", sa.Integer(), nullable=False),
        sa.Column("budget_used", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("started_at", sa.Text(), nullable=False),
        sa.Column("finished_at", sa.Text(), nullable=True),
        sa.Column(
            "status",
            sa.Text(),
            nullable=False,
            server_default=sa.text("'running'"),
        ),
        sa.Column("config_json", sa.Text(), nullable=False),
        sa.Column("flosswing_version", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_runs"),
        sa.CheckConstraint(
            "depth IN ('quick', 'standard', 'deep')",
            name="ck_runs_depth",
        ),
        sa.CheckConstraint(
            "status IN ('running', 'completed', 'errored', 'aborted')",
            name="ck_runs_status",
        ),
        sa.CheckConstraint(
            "budget_total >= 0 AND budget_used >= 0",
            name="ck_runs_budget",
        ),
        sa.CheckConstraint(
            "json_valid(config_json)",
            name="ck_runs_config_json_valid",
        ),
    )
    op.create_index("ix_runs_started_at", "runs", ["started_at"])
    op.create_index("ix_runs_status", "runs", ["status"])

    # ------------------------------------------------------- recon_artifacts
    op.create_table(
        "recon_artifacts",
        sa.Column("id", sa.Text(), nullable=False),
        sa.Column("run_id", sa.Text(), nullable=False),
        sa.Column("languages_json", sa.Text(), nullable=False),
        sa.Column("build_commands_json", sa.Text(), nullable=False),
        sa.Column("trust_boundaries_json", sa.Text(), nullable=False),
        sa.Column("subsystems_json", sa.Text(), nullable=False),
        sa.Column("notes", sa.Text(), nullable=False, server_default=sa.text("''")),
        sa.Column("recorded_at", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_recon_artifacts"),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["runs.id"],
            name="fk_recon_artifacts_run_id_runs",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("run_id", name="uq_recon_artifacts_run_id"),
        sa.CheckConstraint(
            "json_valid(languages_json)",
            name="ck_recon_artifacts_languages_valid",
        ),
        sa.CheckConstraint(
            "json_valid(build_commands_json)",
            name="ck_recon_artifacts_builds_valid",
        ),
        sa.CheckConstraint(
            "json_valid(trust_boundaries_json)",
            name="ck_recon_artifacts_trust_valid",
        ),
        sa.CheckConstraint(
            "json_valid(subsystems_json)",
            name="ck_recon_artifacts_subsystems_valid",
        ),
    )

    # ----------------------------------------------------------- entry_points
    op.create_table(
        "entry_points",
        sa.Column("id", sa.Text(), nullable=False),
        sa.Column("recon_artifact_id", sa.Text(), nullable=False),
        sa.Column("run_id", sa.Text(), nullable=False),
        sa.Column("symbol", sa.Text(), nullable=False),
        sa.Column("file", sa.Text(), nullable=False),
        sa.Column("line", sa.Integer(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("attacker_controlled_input", sa.Integer(), nullable=False),
        sa.Column("notes", sa.Text(), nullable=False, server_default=sa.text("''")),
        sa.PrimaryKeyConstraint("id", name="pk_entry_points"),
        sa.ForeignKeyConstraint(
            ["recon_artifact_id"],
            ["recon_artifacts.id"],
            name="fk_entry_points_recon_artifact_id_recon_artifacts",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["runs.id"],
            name="fk_entry_points_run_id_runs",
            ondelete="CASCADE",
        ),
        sa.CheckConstraint(
            "kind IN ('http', 'cli', 'exported', 'deserializer', 'ipc')",
            name="ck_entry_points_kind",
        ),
        sa.CheckConstraint(
            "attacker_controlled_input IN (0, 1)",
            name="ck_entry_points_attacker_input",
        ),
        sa.CheckConstraint("line >= 1", name="ck_entry_points_line"),
    )
    op.create_index("ix_entry_points_run_id", "entry_points", ["run_id"])
    op.create_index("ix_entry_points_kind", "entry_points", ["kind"])

    # ---------------------------------------------------------------- symbols
    op.create_table(
        "symbols",
        sa.Column("id", sa.Text(), nullable=False),
        sa.Column("run_id", sa.Text(), nullable=False),
        sa.Column("symbol", sa.Text(), nullable=False),
        sa.Column("fully_qualified_name", sa.Text(), nullable=False),
        sa.Column("file", sa.Text(), nullable=False),
        sa.Column("line_start", sa.Integer(), nullable=False),
        sa.Column("line_end", sa.Integer(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("language", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_symbols"),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["runs.id"],
            name="fk_symbols_run_id_runs",
            ondelete="CASCADE",
        ),
        sa.CheckConstraint(
            "kind IN ('function', 'method', 'class', 'struct', 'enum', 'macro', 'type')",
            name="ck_symbols_kind",
        ),
        sa.CheckConstraint(
            "line_start >= 1 AND line_end >= line_start",
            name="ck_symbols_lines",
        ),
    )
    op.create_index("ix_symbols_run_id_symbol", "symbols", ["run_id", "symbol"])
    op.create_index("ix_symbols_run_id_fqn", "symbols", ["run_id", "fully_qualified_name"])
    op.create_index("ix_symbols_run_id_file", "symbols", ["run_id", "file"])

    # ------------------------------------------------------------- call_sites
    op.create_table(
        "call_sites",
        sa.Column("id", sa.Text(), nullable=False),
        sa.Column("run_id", sa.Text(), nullable=False),
        sa.Column("caller_symbol_id", sa.Text(), nullable=False),
        sa.Column("callee_symbol_id", sa.Text(), nullable=True),
        sa.Column("callee_text", sa.Text(), nullable=False),
        sa.Column("file", sa.Text(), nullable=False),
        sa.Column("line", sa.Integer(), nullable=False),
        sa.Column("snippet", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_call_sites"),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["runs.id"],
            name="fk_call_sites_run_id_runs",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["caller_symbol_id"],
            ["symbols.id"],
            name="fk_call_sites_caller_symbols",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["callee_symbol_id"],
            ["symbols.id"],
            name="fk_call_sites_callee_symbols",
            ondelete="SET NULL",
        ),
        sa.CheckConstraint("line >= 1", name="ck_call_sites_line"),
    )
    op.create_index(
        "ix_call_sites_run_id_callee", "call_sites", ["run_id", "callee_symbol_id"]
    )
    op.create_index(
        "ix_call_sites_run_id_caller", "call_sites", ["run_id", "caller_symbol_id"]
    )
    op.create_index(
        "ix_call_sites_run_id_callee_text",
        "call_sites",
        ["run_id", "callee_text"],
    )

    # ------------------------------------------------------------- hunt_tasks
    op.create_table(
        "hunt_tasks",
        sa.Column("id", sa.Text(), nullable=False),
        sa.Column("run_id", sa.Text(), nullable=False),
        sa.Column("attack_class", sa.Text(), nullable=False),
        sa.Column("scope_hint", sa.Text(), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False, server_default=sa.text("''")),
        sa.Column(
            "priority",
            sa.Text(),
            nullable=False,
            server_default=sa.text("'normal'"),
        ),
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("parent_finding_id", sa.Text(), nullable=True),
        sa.Column(
            "status",
            sa.Text(),
            nullable=False,
            server_default=sa.text("'pending'"),
        ),
        sa.Column("created_at", sa.Text(), nullable=False),
        sa.Column("started_at", sa.Text(), nullable=True),
        sa.Column("finished_at", sa.Text(), nullable=True),
        sa.Column("findings_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.PrimaryKeyConstraint("id", name="pk_hunt_tasks"),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["runs.id"],
            name="fk_hunt_tasks_run_id_runs",
            ondelete="CASCADE",
        ),
        sa.CheckConstraint(
            "priority IN ('high', 'normal', 'low')",
            name="ck_hunt_tasks_priority",
        ),
        sa.CheckConstraint(
            "source IN ('recon', 'gapfill')",
            name="ck_hunt_tasks_source",
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'running', 'completed', 'refused', "
            "'budget_exceeded', 'errored')",
            name="ck_hunt_tasks_status",
        ),
        sa.CheckConstraint(
            "findings_count >= 0",
            name="ck_hunt_tasks_findings_count",
        ),
    )
    op.create_index("ix_hunt_tasks_run_id_status", "hunt_tasks", ["run_id", "status"])
    op.create_index("ix_hunt_tasks_attack_class", "hunt_tasks", ["attack_class"])

    # --------------------------------------------------------------- findings
    # findings.dedupe_cluster_id references dedupe_clusters, which itself
    # references findings via primary_finding_id. SQLite enforces FKs at
    # modify-time only, so we can create either table first; we create
    # findings first because more tables depend on it.
    op.create_table(
        "findings",
        sa.Column("id", sa.Text(), nullable=False),
        sa.Column("run_id", sa.Text(), nullable=False),
        sa.Column("hunt_task_id", sa.Text(), nullable=False),
        sa.Column("attack_class", sa.Text(), nullable=False),
        sa.Column("file", sa.Text(), nullable=False),
        sa.Column("function", sa.Text(), nullable=True),
        sa.Column("line_start", sa.Integer(), nullable=False),
        sa.Column("line_end", sa.Integer(), nullable=False),
        sa.Column("severity", sa.Text(), nullable=False),
        sa.Column("confidence", sa.Text(), nullable=False),
        sa.Column(
            "status",
            sa.Text(),
            nullable=False,
            server_default=sa.text("'pending_validation'"),
        ),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("poc_code", sa.Text(), nullable=True),
        sa.Column("poc_result_json", sa.Text(), nullable=True),
        sa.Column("suggested_fix", sa.Text(), nullable=True),
        sa.Column("primary_finding_id", sa.Text(), nullable=True),
        sa.Column("dedupe_cluster_id", sa.Text(), nullable=True),
        sa.Column("dedupe_role", sa.Text(), nullable=True),
        sa.Column("root_cause_summary", sa.Text(), nullable=True),
        sa.Column("reachable", sa.Text(), nullable=True),
        sa.Column("created_at", sa.Text(), nullable=False),
        sa.Column("validated_at", sa.Text(), nullable=True),
        sa.Column("superseded_at", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_findings"),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["runs.id"],
            name="fk_findings_run_id_runs",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["hunt_task_id"],
            ["hunt_tasks.id"],
            name="fk_findings_hunt_task_id_hunt_tasks",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["primary_finding_id"],
            ["findings.id"],
            name="fk_findings_primary_findings",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["dedupe_cluster_id"],
            ["dedupe_clusters.id"],
            name="fk_findings_dedupe_cluster_id_dedupe_clusters",
            ondelete="SET NULL",
        ),
        sa.CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low', 'info')",
            name="ck_findings_severity",
        ),
        sa.CheckConstraint(
            "confidence IN ('confirmed', 'likely', 'speculative')",
            name="ck_findings_confidence",
        ),
        sa.CheckConstraint(
            "status IN ('pending_validation', 'confirmed', 'rejected', "
            "'uncertain', 'superseded')",
            name="ck_findings_status",
        ),
        sa.CheckConstraint(
            "dedupe_role IS NULL OR dedupe_role IN ('primary', 'variant', 'duplicate')",
            name="ck_findings_dedupe_role",
        ),
        sa.CheckConstraint(
            "reachable IS NULL OR reachable IN ('reachable', 'unreachable', 'uncertain')",
            name="ck_findings_reachable",
        ),
        sa.CheckConstraint(
            "line_start >= 1 AND line_end >= line_start",
            name="ck_findings_lines",
        ),
        sa.CheckConstraint(
            "poc_result_json IS NULL OR json_valid(poc_result_json)",
            name="ck_findings_poc_result_valid",
        ),
        sa.CheckConstraint(
            "confidence != 'confirmed' OR length(description) >= 50",
            name="ck_findings_confirmed_evidence",
        ),
    )
    op.create_index("ix_findings_run_id_status", "findings", ["run_id", "status"])
    op.create_index("ix_findings_run_id_severity", "findings", ["run_id", "severity"])
    op.create_index("ix_findings_attack_class", "findings", ["attack_class"])
    op.create_index("ix_findings_file", "findings", ["file"])
    op.create_index("ix_findings_primary_finding_id", "findings", ["primary_finding_id"])
    op.create_index("ix_findings_dedupe_cluster_id", "findings", ["dedupe_cluster_id"])

    # --------------------------------------------------------- agent_sessions
    op.create_table(
        "agent_sessions",
        sa.Column("id", sa.Text(), nullable=False),
        sa.Column("run_id", sa.Text(), nullable=False),
        sa.Column("stage", sa.Text(), nullable=False),
        sa.Column("task_id", sa.Text(), nullable=True),
        sa.Column("finding_id", sa.Text(), nullable=True),
        sa.Column("model", sa.Text(), nullable=False),
        sa.Column("system_prompt_hash", sa.Text(), nullable=False),
        sa.Column("input_tokens", sa.Integer(), nullable=False),
        sa.Column("output_tokens", sa.Integer(), nullable=False),
        sa.Column(
            "cache_read_tokens", sa.Integer(), nullable=False, server_default=sa.text("0")
        ),
        sa.Column(
            "cache_write_tokens", sa.Integer(), nullable=False, server_default=sa.text("0")
        ),
        sa.Column("cost_usd", sa.REAL(), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=False),
        sa.Column("outcome", sa.Text(), nullable=False),
        sa.Column("refusal_text", sa.Text(), nullable=True),
        sa.Column("error_text", sa.Text(), nullable=True),
        sa.Column(
            "tool_calls_count", sa.Integer(), nullable=False, server_default=sa.text("0")
        ),
        sa.Column("started_at", sa.Text(), nullable=False),
        sa.Column("finished_at", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_agent_sessions"),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["runs.id"],
            name="fk_agent_sessions_run_id_runs",
            ondelete="CASCADE",
        ),
        sa.CheckConstraint(
            "stage IN ('recon', 'hunt', 'validate', 'gapfill', 'dedupe', 'trace')",
            name="ck_agent_sessions_stage",
        ),
        sa.CheckConstraint(
            "outcome IN ('completed', 'refused', 'budget_exceeded', 'timed_out', 'errored')",
            name="ck_agent_sessions_outcome",
        ),
        sa.CheckConstraint(
            "input_tokens >= 0 AND output_tokens >= 0 "
            "AND cache_read_tokens >= 0 AND cache_write_tokens >= 0",
            name="ck_agent_sessions_tokens",
        ),
        sa.CheckConstraint("cost_usd >= 0", name="ck_agent_sessions_cost"),
    )
    op.create_index("ix_agent_sessions_run_id", "agent_sessions", ["run_id"])
    op.create_index(
        "ix_agent_sessions_run_id_stage", "agent_sessions", ["run_id", "stage"]
    )
    op.create_index("ix_agent_sessions_outcome", "agent_sessions", ["outcome"])

    # ----------------------------------------------------------- validations
    op.create_table(
        "validations",
        sa.Column("id", sa.Text(), nullable=False),
        sa.Column("finding_id", sa.Text(), nullable=False),
        sa.Column("verdict", sa.Text(), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column(
            "evidence_files_json",
            sa.Text(),
            nullable=False,
            server_default=sa.text("'[]'"),
        ),
        sa.Column("agent_session_id", sa.Text(), nullable=False),
        sa.Column("created_at", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_validations"),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["findings.id"],
            name="fk_validations_finding_id_findings",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["agent_session_id"],
            ["agent_sessions.id"],
            name="fk_validations_agent_session_id_agent_sessions",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("finding_id", name="uq_validations_finding_id"),
        sa.CheckConstraint(
            "verdict IN ('confirmed', 'rejected', 'uncertain')",
            name="ck_validations_verdict",
        ),
        sa.CheckConstraint(
            "json_valid(evidence_files_json)",
            name="ck_validations_evidence_valid",
        ),
    )

    # ------------------------------------------------------- dedupe_clusters
    op.create_table(
        "dedupe_clusters",
        sa.Column("id", sa.Text(), nullable=False),
        sa.Column("run_id", sa.Text(), nullable=False),
        sa.Column("primary_finding_id", sa.Text(), nullable=False),
        sa.Column("root_cause_summary", sa.Text(), nullable=False),
        sa.Column("created_at", sa.Text(), nullable=False),
        sa.Column("member_count", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_dedupe_clusters"),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["runs.id"],
            name="fk_dedupe_clusters_run_id_runs",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["primary_finding_id"],
            ["findings.id"],
            name="fk_dedupe_clusters_primary_findings",
            ondelete="CASCADE",
        ),
        sa.CheckConstraint("member_count >= 1", name="ck_dedupe_clusters_member_count"),
    )
    op.create_index("ix_dedupe_clusters_run_id", "dedupe_clusters", ["run_id"])

    # --------------------------------------------------------- finding_links
    op.create_table(
        "finding_links",
        sa.Column("id", sa.Text(), nullable=False),
        sa.Column("finding_id_a", sa.Text(), nullable=False),
        sa.Column("finding_id_b", sa.Text(), nullable=False),
        sa.Column("relationship", sa.Text(), nullable=False),
        sa.Column("note", sa.Text(), nullable=False, server_default=sa.text("''")),
        sa.Column("created_at", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_finding_links"),
        sa.ForeignKeyConstraint(
            ["finding_id_a"],
            ["findings.id"],
            name="fk_finding_links_a_findings",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["finding_id_b"],
            ["findings.id"],
            name="fk_finding_links_b_findings",
            ondelete="CASCADE",
        ),
        sa.CheckConstraint(
            "relationship IN ('same_root_cause', 'exploit_chain', 'preconditions')",
            name="ck_finding_links_relationship",
        ),
        sa.CheckConstraint(
            "finding_id_a != finding_id_b",
            name="ck_finding_links_distinct",
        ),
        sa.UniqueConstraint(
            "finding_id_a",
            "finding_id_b",
            "relationship",
            name="uq_finding_links_ordered",
        ),
    )

    # ----------------------------------------------------------------- traces
    op.create_table(
        "traces",
        sa.Column("id", sa.Text(), nullable=False),
        sa.Column("finding_id", sa.Text(), nullable=False),
        sa.Column("reachable", sa.Text(), nullable=False),
        sa.Column("entry_point_symbol", sa.Text(), nullable=True),
        sa.Column("entry_point_id", sa.Text(), nullable=True),
        sa.Column("call_chain_json", sa.Text(), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("agent_session_id", sa.Text(), nullable=False),
        sa.Column("created_at", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_traces"),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["findings.id"],
            name="fk_traces_finding_id_findings",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["entry_point_id"],
            ["entry_points.id"],
            name="fk_traces_entry_point_id_entry_points",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["agent_session_id"],
            ["agent_sessions.id"],
            name="fk_traces_agent_session_id_agent_sessions",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("finding_id", name="uq_traces_finding_id"),
        sa.CheckConstraint(
            "reachable IN ('reachable', 'unreachable', 'uncertain')",
            name="ck_traces_reachable",
        ),
        sa.CheckConstraint(
            "json_valid(call_chain_json)",
            name="ck_traces_call_chain_valid",
        ),
        sa.CheckConstraint(
            "reachable != 'reachable' OR entry_point_symbol IS NOT NULL",
            name="ck_traces_reachable_has_entry_point",
        ),
    )

    # ---------------------------------------------------------- sandbox_runs
    op.create_table(
        "sandbox_runs",
        sa.Column("id", sa.Text(), nullable=False),
        sa.Column("run_id", sa.Text(), nullable=False),
        sa.Column("agent_session_id", sa.Text(), nullable=False),
        sa.Column("attack_class", sa.Text(), nullable=False),
        sa.Column("language", sa.Text(), nullable=False),
        sa.Column("files_json", sa.Text(), nullable=False),
        sa.Column("build_command", sa.Text(), nullable=True),
        sa.Column("run_command", sa.Text(), nullable=False),
        sa.Column("args_json", sa.Text(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("env_json", sa.Text(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("network_requested", sa.Integer(), nullable=False),
        sa.Column("network_granted", sa.Integer(), nullable=False),
        sa.Column("timeout_seconds", sa.Integer(), nullable=False),
        sa.Column("sandbox_backend", sa.Text(), nullable=False),
        sa.Column("build_result_json", sa.Text(), nullable=True),
        sa.Column("run_result_json", sa.Text(), nullable=False),
        sa.Column("started_at", sa.Text(), nullable=False),
        sa.Column("finished_at", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_sandbox_runs"),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["runs.id"],
            name="fk_sandbox_runs_run_id_runs",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["agent_session_id"],
            ["agent_sessions.id"],
            name="fk_sandbox_runs_agent_session_id_agent_sessions",
            ondelete="CASCADE",
        ),
        sa.CheckConstraint(
            "language IN ('c', 'cpp', 'rust', 'go', 'python', "
            "'javascript', 'typescript', 'java')",
            name="ck_sandbox_runs_language",
        ),
        sa.CheckConstraint(
            "network_requested IN (0, 1) AND network_granted IN (0, 1)",
            name="ck_sandbox_runs_network",
        ),
        sa.CheckConstraint(
            "sandbox_backend IN ('docker', 'firejail')",
            name="ck_sandbox_runs_backend",
        ),
        sa.CheckConstraint(
            "json_valid(files_json)",
            name="ck_sandbox_runs_files_valid",
        ),
        sa.CheckConstraint(
            "json_valid(args_json)",
            name="ck_sandbox_runs_args_valid",
        ),
        sa.CheckConstraint(
            "json_valid(env_json)",
            name="ck_sandbox_runs_env_valid",
        ),
        sa.CheckConstraint(
            "build_result_json IS NULL OR json_valid(build_result_json)",
            name="ck_sandbox_runs_build_result_valid",
        ),
        sa.CheckConstraint(
            "json_valid(run_result_json)",
            name="ck_sandbox_runs_run_result_valid",
        ),
    )
    op.create_index("ix_sandbox_runs_run_id", "sandbox_runs", ["run_id"])
    op.create_index(
        "ix_sandbox_runs_agent_session_id", "sandbox_runs", ["agent_session_id"]
    )


def downgrade() -> None:
    # Drop in reverse creation order to satisfy FK constraints.
    op.drop_index("ix_sandbox_runs_agent_session_id", table_name="sandbox_runs")
    op.drop_index("ix_sandbox_runs_run_id", table_name="sandbox_runs")
    op.drop_table("sandbox_runs")

    op.drop_table("traces")
    op.drop_table("finding_links")

    op.drop_index("ix_dedupe_clusters_run_id", table_name="dedupe_clusters")
    op.drop_table("dedupe_clusters")

    op.drop_table("validations")

    op.drop_index("ix_agent_sessions_outcome", table_name="agent_sessions")
    op.drop_index("ix_agent_sessions_run_id_stage", table_name="agent_sessions")
    op.drop_index("ix_agent_sessions_run_id", table_name="agent_sessions")
    op.drop_table("agent_sessions")

    op.drop_index("ix_findings_dedupe_cluster_id", table_name="findings")
    op.drop_index("ix_findings_primary_finding_id", table_name="findings")
    op.drop_index("ix_findings_file", table_name="findings")
    op.drop_index("ix_findings_attack_class", table_name="findings")
    op.drop_index("ix_findings_run_id_severity", table_name="findings")
    op.drop_index("ix_findings_run_id_status", table_name="findings")
    op.drop_table("findings")

    op.drop_index("ix_hunt_tasks_attack_class", table_name="hunt_tasks")
    op.drop_index("ix_hunt_tasks_run_id_status", table_name="hunt_tasks")
    op.drop_table("hunt_tasks")

    op.drop_index("ix_call_sites_run_id_callee_text", table_name="call_sites")
    op.drop_index("ix_call_sites_run_id_caller", table_name="call_sites")
    op.drop_index("ix_call_sites_run_id_callee", table_name="call_sites")
    op.drop_table("call_sites")

    op.drop_index("ix_symbols_run_id_file", table_name="symbols")
    op.drop_index("ix_symbols_run_id_fqn", table_name="symbols")
    op.drop_index("ix_symbols_run_id_symbol", table_name="symbols")
    op.drop_table("symbols")

    op.drop_index("ix_entry_points_kind", table_name="entry_points")
    op.drop_index("ix_entry_points_run_id", table_name="entry_points")
    op.drop_table("entry_points")

    op.drop_table("recon_artifacts")

    op.drop_index("ix_runs_status", table_name="runs")
    op.drop_index("ix_runs_started_at", table_name="runs")
    op.drop_table("runs")
