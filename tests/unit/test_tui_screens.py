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
    AgentSession,
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
        s.add(
            AgentSession(
                id="sess-1",
                run_id=run_id,
                stage="hunt",
                model="claude-sonnet-4-6",
                system_prompt_hash="x",
                input_tokens=200,
                output_tokens=80,
                cost_usd=0.02,
                duration_ms=1000,
                outcome="completed",
                task_id="task-1",
                finding_id=None,
                started_at=_iso(),
                finished_at=_iso(),
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


@pytest.mark.asyncio
async def test_run_detail_shows_stage_strip(seeded_db: str) -> None:
    from flosswing.tui.screens.run_detail import RunDetailScreen

    app = FlosswingTUI()
    async with app.run_test() as pilot:
        await pilot.pause()
        app.push_screen(RunDetailScreen(seeded_db))
        await pilot.pause()
        from textual.widgets import Static

        strip = app.screen.query_one("#stage-strip", Static)
        rendered = str(strip.content)
        assert "Recon" in rendered and "Hunt" in rendered


@pytest.mark.asyncio
async def test_sessions_screen_lists_session(seeded_db: str) -> None:
    from flosswing.tui.screens.sessions import SessionsScreen

    app = FlosswingTUI()
    async with app.run_test() as pilot:
        await pilot.pause()
        app.push_screen(SessionsScreen(seeded_db))
        await pilot.pause()
        from textual.widgets import DataTable

        table = app.screen.query_one("#sessions-table", DataTable)
        assert table.row_count == 1


@pytest.mark.asyncio
async def test_findings_screen_lists_finding(seeded_db: str) -> None:
    from flosswing.tui.screens.findings import FindingsScreen

    app = FlosswingTUI()
    async with app.run_test() as pilot:
        await pilot.pause()
        app.push_screen(FindingsScreen(seeded_db))
        await pilot.pause()
        from textual.widgets import DataTable

        table = app.screen.query_one("#findings-table", DataTable)
        assert table.row_count == 1


@pytest.mark.asyncio
async def test_finding_detail_renders_poc(seeded_db: str) -> None:
    from flosswing.tui.screens.finding_detail import FindingDetailScreen

    app = FlosswingTUI()
    async with app.run_test() as pilot:
        await pilot.pause()
        app.push_screen(FindingDetailScreen(seeded_db, "find-1"))
        await pilot.pause()
        from textual.widgets import Static

        body = app.screen.query_one("#finding-body", Static)
        rendered = str(body.content)
        assert "Command injection" in rendered
        assert "pwned" in rendered  # poc result rendered


@pytest.mark.asyncio
async def test_findings_table_renders_markup_literally(seeded_db: str) -> None:
    """Untrusted finding titles must not be interpreted as Rich markup.

    DataTable parses Rich markup in plain-str cells; the findings screen
    defends against this by wrapping repo-derived strings in rich.text.Text.
    Seed a title containing markup and assert it survives to the rendered cell.
    """
    from rich.style import Style

    from flosswing.tui.screens.findings import FindingsScreen

    with st_session.session_scope() as s:
        s.add(
            Finding(
                id="find-markup",
                run_id=seeded_db,
                hunt_task_id="task-1",
                attack_class="command_injection",
                file="src/y.c",
                function="g",
                line_start=1,
                line_end=2,
                severity="low",
                confidence="confirmed",
                status="confirmed",
                title="leak at [bold]0x4141[/bold]",
                description="A confirmed finding needs a non-trivial description"
                " of at least fifty characters to satisfy the CHECK constraint.",
                poc_code="print('poc')",
                poc_result_json='{"stdout": "ok"}',
                suggested_fix=None,
                created_at=_iso(),
            )
        )

    app = FlosswingTUI()
    async with app.run_test() as pilot:
        await pilot.pause()
        app.push_screen(FindingsScreen(seeded_db))
        await pilot.pause()
        from textual.widgets import DataTable

        table = app.screen.query_one("#findings-table", DataTable)
        assert table.row_count == 2
        # Render every cell of the Title column (index 5) and confirm the
        # literal markup text survives — i.e. it was NOT parsed away.
        rendered = ""
        for row in range(table.row_count):
            lines = table._render_cell(row, 5, Style(), width=60)
            rendered += "".join(seg.text for line in lines for seg in line)
        assert "[bold]0x4141[/bold]" in rendered


@pytest.mark.asyncio
async def test_new_scan_modal_spawns_scan(
    seeded_db: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from unittest import mock

    from flosswing.tui import launcher
    from flosswing.tui.screens.new_scan import NewScanScreen

    spawned = {}

    def fake_spawn(path, *, depth, formats, hunt_token_budget):  # type: ignore[no-untyped-def]
        spawned["path"] = str(path)
        spawned["depth"] = depth
        child = mock.MagicMock()
        child.is_alive.return_value = False
        child.kind = "scan"
        return child

    monkeypatch.setattr(launcher, "spawn_scan", fake_spawn)

    app = FlosswingTUI()
    async with app.run_test() as pilot:
        await pilot.pause()
        screen = NewScanScreen()
        app.push_screen(screen)
        await pilot.pause()
        # Set the path input to an existing dir and submit.
        from textual.widgets import Input

        path_input = app.screen.query_one("#scan-path", Input)
        path_input.value = str(tmp_path)
        app.screen.action_submit()
        await pilot.pause()
    assert spawned["path"] == str(tmp_path)


@pytest.mark.asyncio
async def test_quit_guard_detach_exits(seeded_db: str) -> None:
    from unittest import mock

    from flosswing.tui.screens.new_scan import QuitGuard

    child = mock.MagicMock()
    child.is_alive.return_value = True
    child.kind = "scan"

    app = FlosswingTUI()
    async with app.run_test() as pilot:
        await pilot.pause()
        guard = QuitGuard([child])
        app.push_screen(guard)
        await pilot.pause()
        app.screen.action_detach()
        await pilot.pause()
    # Detach must NOT terminate the child.
    child.terminate.assert_not_called()
