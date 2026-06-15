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
    Finding,
    HuntTask,
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


def _add_run(run_id: str, *, status: str = "completed", path: str = "/tmp/r") -> None:
    with st_session.session_scope() as s:
        s.add(
            Run(
                id=run_id,
                target_repo_path=path,
                target_repo_sha=None,
                depth="standard",
                budget_total=20,
                budget_used=0,
                started_at=_iso(),
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
    _add_run("run-a", status="completed")
    _add_run("run-b", status="running")
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
