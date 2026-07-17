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

"""flosswing.state.heartbeat — in-flight-session ticker writer."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from sqlalchemy import delete, select

from flosswing.agent.providers.base import UsageSnapshot
from flosswing.state import heartbeat as st_heartbeat
from flosswing.state import session as st_session
from flosswing.state.models import Run, SessionHeartbeat


def _iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


@pytest.fixture()
def db(monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    monkeypatch.setenv("FLOSSWING_DB_URL", "sqlite:///:memory:")
    monkeypatch.setattr(st_session, "_cached_engine", None, raising=False)
    monkeypatch.setattr(st_session, "_cached_session_factory", None, raising=False)
    run_id = "01JTESTHEARTBEAT0000000000"
    with st_session.session_scope() as s:
        s.add(
            Run(
                id=run_id,
                target_repo_path="/tmp/r",
                target_repo_sha=None,
                depth="standard",
                budget_total=20,
                budget_used=0,
                started_at=_iso(),
                finished_at=None,
                status="running",
                config_json="{}",
                flosswing_version="test",
            )
        )
    yield run_id


def _snap(*, in_tok: int, out_tok: int, cost: float | None) -> UsageSnapshot:
    return UsageSnapshot(
        input_tokens=in_tok,
        output_tokens=out_tok,
        cache_read_tokens=0,
        cache_write_tokens=0,
        tool_calls_count=1,
        cost_usd=cost,
    )


def _get(run_id: str) -> SimpleNamespace | None:
    """Snapshot the heartbeat row's fields inside the session (rows detach on
    scope exit, so we can't return the ORM object itself)."""
    with st_session.session_scope() as s:
        row = s.get(SessionHeartbeat, run_id)
        if row is None:
            return None
        return SimpleNamespace(
            input_tokens=row.input_tokens,
            output_tokens=row.output_tokens,
            cost_usd=row.cost_usd,
            stage=row.stage,
            task_id=row.task_id,
            started_at=row.started_at,
        )


def test_make_on_usage_inserts_then_updates_same_row(db: str) -> None:
    on_usage = st_heartbeat.make_on_usage(run_id=db, stage="hunt", model="m", task_id="t1")

    on_usage(_snap(in_tok=100, out_tok=10, cost=0.5))
    row = _get(db)
    assert row is not None
    assert (row.input_tokens, row.output_tokens, row.cost_usd) == (100, 10, 0.5)
    assert row.stage == "hunt" and row.task_id == "t1"
    first_started = row.started_at

    # A second call updates the SAME primary-key row (no duplicate-PK error),
    # and preserves started_at while advancing the counters.
    on_usage(_snap(in_tok=300, out_tok=40, cost=1.2))
    with st_session.session_scope() as s:
        rows = s.execute(select(SessionHeartbeat)).scalars().all()
        assert len(rows) == 1
        assert (rows[0].input_tokens, rows[0].output_tokens) == (300, 40)
        assert rows[0].started_at == first_started  # started_at preserved


def test_make_on_usage_estimates_cost_when_snapshot_cost_none(db: str) -> None:
    on_usage = st_heartbeat.make_on_usage(run_id=db, stage="recon", model="claude-opus-4-8")
    on_usage(_snap(in_tok=1_000_000, out_tok=0, cost=None))
    row = _get(db)
    assert row is not None
    assert row.cost_usd == 15.0  # estimated from tokens, not left at 0


def test_seed_creates_zeroed_row_at_session_start(db: str) -> None:
    with st_session.session_scope() as s:
        st_heartbeat.seed(
            s,
            run_id=db,
            stage="validate",
            model="claude-opus-4-8",
            agent_session_id="as-1",
            finding_id="f-1",
        )
    row = _get(db)
    assert row is not None
    assert (row.input_tokens, row.output_tokens, row.cost_usd) == (0, 0, 0.0)
    assert row.stage == "validate"
    # A later on_usage upsert updates counters but preserves the seeded start.
    first_started = row.started_at
    st_heartbeat.make_on_usage(
        run_id=db, stage="validate", model="claude-opus-4-8", agent_session_id="as-1"
    )(_snap(in_tok=200, out_tok=50, cost=0.3))
    updated = _get(db)
    assert updated is not None
    assert updated.input_tokens == 200
    assert updated.started_at == first_started


def test_seed_hidden_id_matches_agent_session_id(db: str) -> None:
    # The seeded row carries agent_session_id so the TUI can hide the placeholder.
    with st_session.session_scope() as s:
        st_heartbeat.seed(
            s, run_id=db, stage="dedupe", model="m", agent_session_id="as-xyz"
        )
        row = s.get(SessionHeartbeat, db)
        assert row is not None
        assert row.agent_session_id == "as-xyz"


def test_clear_removes_row_within_open_session(db: str) -> None:
    st_heartbeat.make_on_usage(run_id=db, stage="recon", model="m")(
        _snap(in_tok=1, out_tok=1, cost=0.0)
    )
    assert _get(db) is not None
    with st_session.session_scope() as s:
        st_heartbeat.clear(s, db)
    assert _get(db) is None


def test_clear_run_is_noop_when_absent_and_never_raises(db: str) -> None:
    # No heartbeat exists — clear_run must simply do nothing, no exception.
    st_heartbeat.clear_run(db)
    assert _get(db) is None


def test_heartbeat_cascade_deletes_with_parent_run(db: str) -> None:
    st_heartbeat.make_on_usage(run_id=db, stage="recon", model="m")(
        _snap(in_tok=1, out_tok=1, cost=0.0)
    )
    assert _get(db) is not None
    with st_session.session_scope() as s:
        s.execute(delete(Run).where(Run.id == db))
    assert _get(db) is None  # FK ON DELETE CASCADE removed the heartbeat
