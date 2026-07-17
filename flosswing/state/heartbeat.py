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

"""In-flight-session heartbeat writer (stage/orchestrator side).

This is the DB-writing half of the live token/cost ticker. The provider layer
(``flosswing.agent.providers``) never imports it — it only calls an opaque
``on_usage`` callback, and this module builds that callback. Keeping the write
here preserves the "provider layer has no DB access" boundary.

Lifecycle (see docs/specs/2026-07-16-tui-live-token-cost-design.md):

- ``make_on_usage`` returns a callback that upserts the single
  ``session_heartbeats`` row for a run while its session streams.
- ``clear`` deletes that row inside an already-open session — a stage calls it
  in the SAME ``session_scope()`` block that writes the terminal
  ``agent_sessions`` row, so the swap is atomic and the TUI never double-counts.
- ``clear_run`` is a standalone best-effort sweep for the orchestrator's
  ``finally``; it never raises.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import delete
from sqlalchemy.orm import Session

from flosswing.agent.pricing import estimate_cost_usd
from flosswing.agent.providers.base import OnUsage, UsageSnapshot
from flosswing.state import session as st_session
from flosswing.state.models import SessionHeartbeat


def _now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def make_on_usage(
    *,
    run_id: str,
    stage: str,
    model: str,
    task_id: str | None = None,
    finding_id: str | None = None,
    agent_session_id: str | None = None,
) -> OnUsage:
    """Build an ``on_usage`` callback that upserts ``run_id``'s heartbeat row.

    ``agent_session_id`` is the id of the agent_sessions row the stage
    pre-inserts before the session (validate/dedupe/trace); the TUI uses it to
    hide that committed 0-token placeholder while the live line is shown. Leave
    it None for insert-after stages, which have no committed row mid-session.
    """

    def _on_usage(snap: UsageSnapshot) -> None:
        cost = (
            snap.cost_usd
            if snap.cost_usd is not None
            else estimate_cost_usd(
                model=model,
                input_tokens=snap.input_tokens,
                output_tokens=snap.output_tokens,
                cache_read_tokens=snap.cache_read_tokens,
                cache_write_tokens=snap.cache_write_tokens,
            )
        )
        now = _now_iso()
        with st_session.session_scope() as s:
            row = s.get(SessionHeartbeat, run_id)
            if row is None:
                s.add(
                    SessionHeartbeat(
                        run_id=run_id,
                        stage=stage,
                        task_id=task_id,
                        finding_id=finding_id,
                        agent_session_id=agent_session_id,
                        model=model,
                        input_tokens=snap.input_tokens,
                        output_tokens=snap.output_tokens,
                        cache_read_tokens=snap.cache_read_tokens,
                        cache_write_tokens=snap.cache_write_tokens,
                        cost_usd=cost,
                        tool_calls_count=snap.tool_calls_count,
                        started_at=now,
                        updated_at=now,
                    )
                )
            else:
                row.stage = stage
                row.task_id = task_id
                row.finding_id = finding_id
                row.agent_session_id = agent_session_id
                row.model = model
                row.input_tokens = snap.input_tokens
                row.output_tokens = snap.output_tokens
                row.cache_read_tokens = snap.cache_read_tokens
                row.cache_write_tokens = snap.cache_write_tokens
                row.cost_usd = cost
                row.tool_calls_count = snap.tool_calls_count
                row.updated_at = now

    return _on_usage


def clear(s: Session, run_id: str) -> None:
    """Delete ``run_id``'s heartbeat row inside an ALREADY-OPEN session.

    Call this from the same ``session_scope()`` block that writes the terminal
    ``agent_sessions`` row so both land in one atomic commit.
    """
    s.execute(delete(SessionHeartbeat).where(SessionHeartbeat.run_id == run_id))


def clear_run(run_id: str) -> None:
    """Best-effort standalone delete of ``run_id``'s heartbeat row.

    Never raises — it runs from the orchestrator's ``finally``, where a second
    exception would mask the original. A row left by a hard crash is harmless
    anyway: the TUI ignores heartbeats for runs that aren't PID-file-live.
    """
    try:
        with st_session.session_scope() as s:
            clear(s, run_id)
    except Exception:
        pass
