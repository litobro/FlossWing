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

"""flosswing.tui.data — read-only query layer."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from flosswing.state import session as st_session
from flosswing.state.models import (
    AgentSession,
    Finding,
    HuntTask,
    ReconArtifact,
    Run,
    SessionHeartbeat,
)
from flosswing.tui import data


def _iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


@pytest.fixture()
def isolated_db(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[Path]:
    monkeypatch.setenv("FLOSSWING_DB_URL", f"sqlite:///{tmp_path}/state.db")
    monkeypatch.setattr(st_session, "_cached_engine", None, raising=False)
    monkeypatch.setattr(
        st_session, "_cached_session_factory", None, raising=False
    )
    yield tmp_path


def _add_run(
    run_id: str,
    *,
    status: str = "completed",
    path: str = "/tmp/r",
    started_at: str | None = None,
) -> None:
    with st_session.session_scope() as s:
        s.add(
            Run(
                id=run_id,
                target_repo_path=path,
                target_repo_sha=None,
                depth="standard",
                budget_total=20,
                budget_used=0,
                started_at=started_at or _iso(),
                finished_at=_iso() if status != "running" else None,
                status=status,
                config_json="{}",
                flosswing_version="test",
            )
        )


def _add_finding(finding_id: str, run_id: str, *, status: str = "confirmed") -> None:
    with st_session.session_scope() as s:
        s.add(
            HuntTask(
                id=f"task-{finding_id}",
                run_id=run_id,
                attack_class="command_injection",
                scope_hint="src/x.c",
                source="recon",
                status="completed",
                created_at=_iso(),
            )
        )
        s.flush()  # ensure HuntTask row exists before Finding FK is checked
        s.add(
            Finding(
                id=finding_id,
                run_id=run_id,
                hunt_task_id=f"task-{finding_id}",
                attack_class="command_injection",
                file="src/x.c",
                function="parse",
                line_start=10,
                line_end=12,
                severity="high",
                confidence="confirmed",
                status=status,
                title="Command injection in parse()",
                description=(
                    "User-controlled input flows directly to system()"
                    " without sanitisation."
                ),
                poc_code="print('poc')",
                poc_result_json='{"exit_code": 0, "stdout": "pwned"}',
                suggested_fix="Use execve with a fixed argv.",
                created_at=_iso(),
            )
        )


def test_list_runs_orders_newest_first_with_counts(isolated_db: Path) -> None:
    _add_run("run-a", status="completed", started_at="2026-06-15T00:00:01Z")
    _add_run("run-b", status="running", started_at="2026-06-15T00:00:02Z")
    _add_finding("f1", "run-b")
    _add_finding("f2", "run-b")

    rows = data.list_runs()

    assert [r.id for r in rows] == ["run-b", "run-a"]  # newest started_at first
    by_id = {r.id: r for r in rows}
    assert by_id["run-b"].findings_count == 2
    assert by_id["run-a"].findings_count == 0
    assert by_id["run-b"].status == "running"
    assert by_id["run-b"].short_id  # non-empty display id


def test_list_runs_empty(isolated_db: Path) -> None:
    assert data.list_runs() == []


def test_short_id_truncates_to_last_8() -> None:
    assert data._short_id("01JXABCDE12345678901ABCDE") == "901ABCDE"  # last 8 chars
    assert data._short_id("short") == "short"


def _add_recon(run_id: str) -> None:
    with st_session.session_scope() as s:
        s.add(
            ReconArtifact(
                id=f"recon-{run_id}",
                run_id=run_id,
                languages_json="[]",
                build_commands_json="[]",
                trust_boundaries_json="[]",
                subsystems_json="[]",
                notes="",
                recorded_at=_iso(),
            )
        )


def _add_hunt_task(
    task_id: str, run_id: str, *, status: str, source: str = "recon"
) -> None:
    with st_session.session_scope() as s:
        s.add(
            HuntTask(
                id=task_id,
                run_id=run_id,
                attack_class="path_traversal",
                scope_hint="src/y.c",
                source=source,
                status=status,
                created_at=_iso(),
                findings_count=0,
            )
        )


def _add_session(run_id: str, *, stage: str, in_tok: int, out_tok: int, cost: float) -> None:
    with st_session.session_scope() as s:
        s.add(
            AgentSession(
                id=f"sess-{run_id}-{stage}-{in_tok}",
                run_id=run_id,
                stage=stage,
                task_id=None,
                finding_id=None,
                model="claude-sonnet-4-6",
                system_prompt_hash="x",
                input_tokens=in_tok,
                output_tokens=out_tok,
                cost_usd=cost,
                duration_ms=1000,
                outcome="completed",
                started_at=_iso(),
                finished_at=_iso(),
            )
        )


def test_run_progress_none_for_missing_run(isolated_db: Path) -> None:
    _add_run("exists")
    assert data.run_progress("ghost") is None


def test_run_progress_stage_derivation_and_totals(isolated_db: Path) -> None:
    _add_run("run-x", status="running")
    _add_recon("run-x")
    _add_hunt_task("t1", "run-x", status="completed")
    _add_hunt_task("t2", "run-x", status="running")
    _add_hunt_task("t3", "run-x", status="pending")
    _add_finding("f1", "run-x", status="confirmed")
    _add_session("run-x", stage="recon", in_tok=100, out_tok=50, cost=0.01)
    _add_session("run-x", stage="hunt", in_tok=200, out_tok=80, cost=0.02)

    p = data.run_progress("run-x")
    assert p is not None
    assert p.run_id == "run-x"
    assert p.hunt_total == 4  # 3 added here + 1 from _add_finding's task
    # done = not in (pending, running): t1 + _add_finding's "completed" task
    assert p.hunt_done == 2
    assert p.tokens_used == 100 + 50 + 200 + 80
    assert round(p.cost_usd, 4) == 0.03
    assert p.findings_total == 1
    assert p.findings_by_status["confirmed"] == 1

    stages = {st.name: st.state for st in p.stages}
    assert stages["Recon"] == "done"
    assert stages["Hunt"] == "active"  # some done, some not, run running
    # No validations rows -> Validate pending while run is running
    assert stages["Validate"] == "pending"


def test_run_progress_gapfill_detected_from_source(isolated_db: Path) -> None:
    _add_run("run-g", status="completed")
    _add_hunt_task("g1", "run-g", status="completed", source="gapfill")
    p = data.run_progress("run-g")
    assert p is not None
    stages = {st.name: st.state for st in p.stages}
    assert stages["Gapfill"] == "done"


def test_findings_list_maps_rows(isolated_db: Path) -> None:
    _add_run("run-f", status="completed")
    _add_finding("f1", "run-f", status="confirmed")
    rows = data.findings_list("run-f")
    assert len(rows) == 1
    assert rows[0].id == "f1"
    assert rows[0].title == "Command injection in parse()"
    assert rows[0].severity == "high"
    assert rows[0].status == "confirmed"


def test_findings_list_missing_run_is_empty(isolated_db: Path) -> None:
    assert data.findings_list("nope") == []


def test_finding_detail_includes_poc_result(isolated_db: Path) -> None:
    _add_run("run-d", status="completed")
    _add_finding("f1", "run-d", status="confirmed")
    d = data.finding_detail("run-d", "f1")
    assert d is not None
    assert d.id == "f1"
    assert d.poc_code == "print('poc')"
    assert d.poc_result is not None and "pwned" in d.poc_result
    assert d.suggested_fix is not None
    assert "src/x.c" in d.location


def test_finding_detail_missing_returns_none(isolated_db: Path) -> None:
    _add_run("run-d2", status="completed")
    assert data.finding_detail("run-d2", "ghost") is None


def test_finding_detail_missing_run_returns_none(isolated_db: Path) -> None:
    assert data.finding_detail("ghost-run", "ghost-finding") is None


def test_list_sessions(isolated_db: Path) -> None:
    _add_run("run-s", status="completed")
    _add_session("run-s", stage="recon", in_tok=100, out_tok=50, cost=0.01)
    rows = data.list_sessions("run-s")
    assert len(rows) == 1
    assert rows[0].stage == "recon"
    assert rows[0].input_tokens == 100
    assert rows[0].outcome == "completed"


def test_list_sessions_missing_run_is_empty(isolated_db: Path) -> None:
    assert data.list_sessions("nope") == []


def test_list_runs_liveness_live_when_pid_alive(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from flosswing import runpid

    _add_run("run-live", status="running")
    monkeypatch.setattr(runpid, "liveness", lambda rid: "live" if rid == "run-live" else "absent")
    row = {r.id: r for r in data.list_runs()}["run-live"]
    assert row.liveness == "live"


def test_list_runs_liveness_stale_when_pid_recorded_but_dead(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from flosswing import runpid

    _add_run("run-dead", status="running")
    # A PID file exists (read_pid returns a pid) but the process is gone:
    # this is a genuine crash -> 'stale'.
    monkeypatch.setattr(runpid, "liveness", lambda rid: "dead")
    row = {r.id: r for r in data.list_runs()}["run-dead"]
    assert row.liveness == "stale"


def test_list_runs_liveness_unknown_when_no_pid_file(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from flosswing import runpid

    _add_run("run-nopid", status="running")
    # No PID file at all (e.g. a scan started before liveness tracking, an
    # older build, or a swallowed write failure). We cannot conclude 'crashed'
    # -> 'unknown', not 'stale'.
    monkeypatch.setattr(runpid, "liveness", lambda rid: "absent")
    row = {r.id: r for r in data.list_runs()}["run-nopid"]
    assert row.liveness == "unknown"


def test_list_runs_liveness_done_for_terminal_status(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from flosswing import runpid

    _add_run("run-fin", status="completed")
    # Even if a stale pid file somehow lingered, terminal status wins.
    monkeypatch.setattr(runpid, "liveness", lambda rid: "live")
    row = {r.id: r for r in data.list_runs()}["run-fin"]
    assert row.liveness == "done"


def test_list_runs_tokens_used_summed(isolated_db: Path) -> None:
    _add_run("run-tok", status="running")
    _add_session("run-tok", stage="recon", in_tok=100, out_tok=50, cost=0.01)
    _add_session("run-tok", stage="hunt", in_tok=200, out_tok=80, cost=0.02)
    row = {r.id: r for r in data.list_runs()}["run-tok"]
    assert row.tokens_used == 100 + 50 + 200 + 80


def _add_symbol(run_id: str) -> None:
    from flosswing.state.models import Symbol

    with st_session.session_scope() as s:
        s.add(
            Symbol(
                id=f"sym-{run_id}",
                run_id=run_id,
                symbol="f",
                fully_qualified_name="f",
                file="src/x.c",
                line_start=1,
                line_end=2,
                kind="function",
                language="c",
            )
        )


def test_list_runs_active_stage_for_running(isolated_db: Path) -> None:
    _add_run("run-mid", status="running")
    _add_recon("run-mid")
    _add_symbol("run-mid")  # Index done, so Hunt is the frontier stage
    _add_hunt_task("t1", "run-mid", status="completed")
    _add_hunt_task("t2", "run-mid", status="running")
    row = {r.id: r for r in data.list_runs()}["run-mid"]
    # Recon + Index done, Hunt partially done while running -> Hunt is active.
    assert row.active_stage == "Hunt"


def test_list_runs_active_stage_none_for_terminal(isolated_db: Path) -> None:
    _add_run("run-term", status="completed")
    row = {r.id: r for r in data.list_runs()}["run-term"]
    assert row.active_stage is None


def test_run_progress_liveness_live(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from flosswing import runpid

    _add_run("rp-live", status="running")
    monkeypatch.setattr(runpid, "liveness", lambda rid: "live")
    p = data.run_progress("rp-live")
    assert p is not None
    assert p.liveness == "live"


def test_run_progress_liveness_done_for_terminal(isolated_db: Path) -> None:
    _add_run("rp-fin", status="completed")
    p = data.run_progress("rp-fin")
    assert p is not None
    assert p.liveness == "done"


# --- Live in-flight heartbeat contribution (approach B) ----------------------


def _add_heartbeat(
    run_id: str,
    *,
    stage: str = "hunt",
    in_tok: int,
    out_tok: int,
    cost: float,
    started_at: str | None = None,
) -> None:
    with st_session.session_scope() as s:
        s.add(
            SessionHeartbeat(
                run_id=run_id,
                stage=stage,
                task_id=None,
                finding_id=None,
                model="claude-opus-4-8",
                input_tokens=in_tok,
                output_tokens=out_tok,
                cache_read_tokens=0,
                cache_write_tokens=0,
                cost_usd=cost,
                tool_calls_count=1,
                started_at=started_at or _iso(),
                updated_at=_iso(),
            )
        )


def test_run_progress_includes_heartbeat_when_live(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from flosswing import runpid

    _add_run("rp-live", status="running")
    _add_session("rp-live", stage="recon", in_tok=100, out_tok=50, cost=0.10)
    _add_heartbeat("rp-live", in_tok=200, out_tok=80, cost=0.05)
    monkeypatch.setattr(runpid, "liveness", lambda rid: "live")

    p = data.run_progress("rp-live")
    assert p is not None
    # committed (100+50) + heartbeat (200+80)
    assert p.tokens_used == 430
    assert round(p.cost_usd, 6) == round(0.10 + 0.05, 6)


def test_run_progress_excludes_heartbeat_when_stale(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from flosswing import runpid

    _add_run("rp-stale", status="running")
    _add_session("rp-stale", stage="recon", in_tok=100, out_tok=50, cost=0.10)
    _add_heartbeat("rp-stale", in_tok=200, out_tok=80, cost=0.05)
    # A dead PID → the orphaned heartbeat must NOT inflate the totals.
    monkeypatch.setattr(runpid, "liveness", lambda rid: "dead")

    p = data.run_progress("rp-stale")
    assert p is not None
    assert p.tokens_used == 150  # committed only
    assert round(p.cost_usd, 6) == 0.10
    assert p.tokens_per_sec is None and p.cost_per_min is None


def test_run_progress_rates_present_when_live(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from flosswing import runpid

    # started_at well in the past so elapsed > 0 and the rate is finite.
    _add_run("rp-rate", status="running", started_at="2026-01-01T00:00:00Z")
    _add_heartbeat("rp-rate", in_tok=600, out_tok=0, cost=1.0)
    monkeypatch.setattr(runpid, "liveness", lambda rid: "live")

    p = data.run_progress("rp-rate")
    assert p is not None
    assert p.tokens_per_sec is not None and p.tokens_per_sec > 0
    assert p.cost_per_min is not None and p.cost_per_min > 0


def test_run_progress_projected_cost_from_hunt_fraction(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from flosswing import runpid

    _add_run("rp-proj", status="running")
    _add_session("rp-proj", stage="hunt", in_tok=10, out_tok=10, cost=2.0)
    _add_hunt_task("t-done", "rp-proj", status="completed")
    _add_hunt_task("t-pending", "rp-proj", status="pending")
    monkeypatch.setattr(runpid, "liveness", lambda rid: "live")

    p = data.run_progress("rp-proj")
    assert p is not None
    # 1 of 2 hunt tasks done, cost so far 2.0 → projected 4.0
    assert p.projected_cost_usd == pytest.approx(4.0)


def test_run_progress_projected_cost_none_before_any_hunt_done(
    isolated_db: Path,
) -> None:
    _add_run("rp-noproj", status="running")
    _add_hunt_task("t1", "rp-noproj", status="pending")
    p = data.run_progress("rp-noproj")
    assert p is not None
    assert p.projected_cost_usd is None


def test_list_runs_cost_summed_and_live_inclusive(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from flosswing import runpid

    _add_run("lr-cost", status="running")
    _add_session("lr-cost", stage="recon", in_tok=10, out_tok=5, cost=0.10)
    _add_session("lr-cost", stage="hunt", in_tok=20, out_tok=8, cost=0.20)
    _add_heartbeat("lr-cost", in_tok=100, out_tok=0, cost=0.05)
    monkeypatch.setattr(runpid, "liveness", lambda rid: "live")

    row = next(r for r in data.list_runs() if r.id == "lr-cost")
    assert round(row.cost_usd, 6) == round(0.10 + 0.20 + 0.05, 6)
    assert row.tokens_used == 10 + 5 + 20 + 8 + 100


def test_live_session_none_when_not_live(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from flosswing import runpid

    _add_run("ls-x", status="running")
    _add_heartbeat("ls-x", in_tok=1, out_tok=1, cost=0.0)
    monkeypatch.setattr(runpid, "liveness", lambda rid: "dead")
    assert data.live_session("ls-x") is None


def test_live_session_returns_row_when_live(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from flosswing import runpid

    _add_run("ls-y", status="running")
    _add_heartbeat("ls-y", stage="validate", in_tok=42, out_tok=7, cost=0.33)
    monkeypatch.setattr(runpid, "liveness", lambda rid: "live")
    live = data.live_session("ls-y")
    assert live is not None
    assert live.stage == "validate"
    assert live.input_tokens == 42 and live.output_tokens == 7


def test_list_sessions_hides_inflight_placeholder_when_live(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A pre-insert stage's committed 0-token placeholder row is hidden while
    its live heartbeat is shown, so the operator sees no contradictory
    'completed 0/0' entry beside the live line."""
    from flosswing import runpid

    _add_run("ls-live", status="running")
    # A genuinely-finished earlier session — must stay visible.
    _add_session("ls-live", stage="recon", in_tok=100, out_tok=50, cost=0.10)
    # The in-flight placeholder row (0 tokens, placeholder outcome) with a
    # known id, plus a heartbeat that points at it.
    placeholder_id = "sess-ls-live-validate-placeholder"
    with st_session.session_scope() as s:
        s.add(
            AgentSession(
                id=placeholder_id,
                run_id="ls-live",
                stage="validate",
                task_id=None,
                finding_id="find-1",
                model="claude-opus-4-8",
                system_prompt_hash="x",
                input_tokens=0,
                output_tokens=0,
                cost_usd=0.0,
                duration_ms=0,
                outcome="completed",
                started_at=_iso(),
                finished_at=_iso(),
            )
        )
        s.add(
            SessionHeartbeat(
                run_id="ls-live",
                stage="validate",
                task_id=None,
                finding_id="find-1",
                agent_session_id=placeholder_id,
                model="claude-opus-4-8",
                input_tokens=1234,
                output_tokens=567,
                cache_read_tokens=0,
                cache_write_tokens=0,
                cost_usd=0.05,
                tool_calls_count=2,
                started_at=_iso(),
                updated_at=_iso(),
            )
        )
    monkeypatch.setattr(runpid, "liveness", lambda rid: "live")

    stages = [sr.stage for sr in data.list_sessions("ls-live")]
    assert stages == ["recon"]  # validate placeholder hidden while live


def test_list_sessions_shows_placeholder_once_run_not_live(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Once the run is no longer live (finalized/crashed), the (now real,
    finalized) row is shown normally — nothing is hidden."""
    from flosswing import runpid

    _add_run("ls-done", status="completed")
    _add_session("ls-done", stage="validate", in_tok=10, out_tok=5, cost=0.02)
    monkeypatch.setattr(runpid, "liveness", lambda rid: "dead")

    stages = [sr.stage for sr in data.list_sessions("ls-done")]
    assert stages == ["validate"]


def test_run_progress_rate_uses_heartbeat_start_not_run_start(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The live rate is measured over the current session (heartbeat start),
    not the whole run — so a long-idle run still shows the burst's real rate."""
    from datetime import timedelta

    from flosswing import runpid

    # Run started long ago; the in-flight session started ~10s ago.
    _add_run("rp-hbrate", status="running", started_at="2020-01-01T00:00:00Z")
    hb_started = (
        (datetime.now(UTC) - timedelta(seconds=10))
        .isoformat()
        .replace("+00:00", "Z")
    )
    _add_heartbeat("rp-hbrate", in_tok=600, out_tok=0, cost=1.0, started_at=hb_started)
    monkeypatch.setattr(runpid, "liveness", lambda rid: "live")

    p = data.run_progress("rp-hbrate")
    assert p is not None
    # ~600 tokens / ~10s ≈ 60 tok/s. If it used the run's multi-year elapsed it
    # would be ~0. Assert it reflects the session, not the run.
    assert p.tokens_per_sec is not None and p.tokens_per_sec > 10


def test_activity_returns_live_and_sessions_in_one_call(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from flosswing import runpid

    _add_run("act-1", status="running")
    _add_session("act-1", stage="recon", in_tok=10, out_tok=5, cost=0.1)
    _add_heartbeat("act-1", stage="hunt", in_tok=50, out_tok=5, cost=0.02)
    monkeypatch.setattr(runpid, "liveness", lambda rid: "live")

    live, sessions = data.activity("act-1")
    assert live is not None and live.stage == "hunt"
    assert [s.stage for s in sessions] == ["recon"]


def test_activity_missing_run_returns_empty(isolated_db: Path) -> None:
    assert data.activity("ghost") == (None, [])


def test_run_detail_view_bundles_progress_live_sessions(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from flosswing import runpid

    _add_run("rdv-1", status="running")
    _add_recon("rdv-1")
    _add_session("rdv-1", stage="recon", in_tok=100, out_tok=50, cost=0.1)
    _add_heartbeat("rdv-1", stage="hunt", in_tok=200, out_tok=80, cost=0.05)
    monkeypatch.setattr(runpid, "liveness", lambda rid: "live")

    view = data.run_detail_view("rdv-1")
    assert view is not None
    assert view.progress.tokens_used == 100 + 50 + 200 + 80  # live-inclusive
    assert view.live is not None and view.live.stage == "hunt"
    assert [s.stage for s in view.recent_sessions] == ["recon"]


def test_run_detail_view_none_for_missing_run(isolated_db: Path) -> None:
    assert data.run_detail_view("ghost") is None
