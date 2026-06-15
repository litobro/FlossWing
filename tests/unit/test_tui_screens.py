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

"""flosswing.tui screen smoke tests via Textual's run_test() pilot."""

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
from flosswing.tui.app import FlosswingTUI


def _iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


@pytest.fixture()
def seeded_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    monkeypatch.setenv("FLOSSWING_DB_URL", f"sqlite:///{tmp_path}/state.db")
    monkeypatch.setattr(st_session, "_cached_engine", None, raising=False)
    monkeypatch.setattr(st_session, "_cached_session_factory", None, raising=False)
    run_id = "01JTESTRUN0000000000000000"
    with st_session.session_scope() as s:
        s.add(
            Run(
                id=run_id,
                target_repo_path="/tmp/curl",
                target_repo_sha=None,
                depth="standard",
                budget_total=20,
                budget_used=0,
                started_at=_iso(),
                finished_at=_iso(),
                status="completed",
                config_json="{}",
                flosswing_version="test",
            )
        )
        s.flush()  # ensure Run row exists before HuntTask FK is checked
        s.add(
            HuntTask(
                id="task-1",
                run_id=run_id,
                attack_class="command_injection",
                scope_hint="src/x.c",
                source="recon",
                status="completed",
                created_at=_iso(),
                findings_count=1,
            )
        )
        s.flush()  # ensure HuntTask row exists before Finding FK is checked
        s.add(
            Finding(
                id="find-1",
                run_id=run_id,
                hunt_task_id="task-1",
                attack_class="command_injection",
                file="src/x.c",
                function="parse",
                line_start=10,
                line_end=12,
                severity="high",
                confidence="confirmed",
                status="confirmed",
                title="Command injection in parse()",
                description=(
                    "User-controlled input flows directly to system()"
                    " without sanitisation."
                ),
                poc_code="print('poc')",
                poc_result_json='{"stdout": "pwned"}',
                suggested_fix="Use execve.",
                created_at=_iso(),
            )
        )
    yield run_id


@pytest.mark.asyncio
async def test_runs_screen_lists_run(seeded_db: str) -> None:
    app = FlosswingTUI()
    async with app.run_test() as pilot:
        await pilot.pause()
        from textual.widgets import DataTable

        table = app.screen.query_one("#runs-table", DataTable)
        assert table.row_count == 1
