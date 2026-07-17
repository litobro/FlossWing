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

"""session_heartbeats table

Revision ID: 002_session_heartbeats
Revises: 001_initial
Create Date: 2026-07-16

Adds the ephemeral `session_heartbeats` table backing the TUI's live
in-flight token/cost ticker (see
docs/specs/2026-07-16-tui-live-token-cost-design.md). Purely additive
CREATE TABLE — no existing table is altered. Every constraint is explicitly
named per the conventions in docs/schema.sql. The CHECK expression strings
are kept character-identical to docs/schema.sql so the schema-sync check
(tests/unit/test_schema_sync.py) passes.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "002_session_heartbeats"
down_revision: str | Sequence[str] | None = "001_initial"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "session_heartbeats",
        sa.Column("run_id", sa.Text(), nullable=False),
        sa.Column("stage", sa.Text(), nullable=False),
        sa.Column("task_id", sa.Text(), nullable=True),
        sa.Column("finding_id", sa.Text(), nullable=True),
        sa.Column("agent_session_id", sa.Text(), nullable=True),
        sa.Column("model", sa.Text(), nullable=False),
        sa.Column(
            "input_tokens", sa.Integer(), nullable=False, server_default=sa.text("0")
        ),
        sa.Column(
            "output_tokens", sa.Integer(), nullable=False, server_default=sa.text("0")
        ),
        sa.Column(
            "cache_read_tokens", sa.Integer(), nullable=False, server_default=sa.text("0")
        ),
        sa.Column(
            "cache_write_tokens", sa.Integer(), nullable=False, server_default=sa.text("0")
        ),
        sa.Column("cost_usd", sa.REAL(), nullable=False, server_default=sa.text("0")),
        sa.Column(
            "tool_calls_count", sa.Integer(), nullable=False, server_default=sa.text("0")
        ),
        sa.Column("started_at", sa.Text(), nullable=False),
        sa.Column("updated_at", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("run_id", name="pk_session_heartbeats"),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["runs.id"],
            name="fk_session_heartbeats_run_id_runs",
            ondelete="CASCADE",
        ),
        sa.CheckConstraint(
            "stage IN ('recon', 'hunt', 'validate', 'gapfill', 'dedupe', 'trace')",
            name="ck_session_heartbeats_stage",
        ),
        sa.CheckConstraint(
            "input_tokens >= 0 AND output_tokens >= 0 "
            "AND cache_read_tokens >= 0 AND cache_write_tokens >= 0",
            name="ck_session_heartbeats_tokens",
        ),
        sa.CheckConstraint("cost_usd >= 0", name="ck_session_heartbeats_cost"),
        sa.CheckConstraint(
            "tool_calls_count >= 0", name="ck_session_heartbeats_tool_calls"
        ),
    )


def downgrade() -> None:
    op.drop_table("session_heartbeats")
