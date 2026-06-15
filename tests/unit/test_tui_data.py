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


def test_list_sessions(isolated_db: Path) -> None:
    _add_run("run-s", status="completed")
    _add_session("run-s", stage="recon", in_tok=100, out_tok=50, cost=0.01)
    rows = data.list_sessions("run-s")
    assert len(rows) == 1
    assert rows[0].stage == "recon"
    assert rows[0].input_tokens == 100
    assert rows[0].outcome == "completed"
