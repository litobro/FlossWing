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
    from textual.widgets import Markdown

    from flosswing.tui.screens.finding_detail import FindingDetailScreen

    app = FlosswingTUI()
    async with app.run_test() as pilot:
        await pilot.pause()
        app.push_screen(FindingDetailScreen(seeded_db, "find-1"))
        await pilot.pause()
        # Assert against the widget's public markdown source.
        md = app.screen.query_one("#finding-body", Markdown)
        assert "Command injection" in md.source
        assert "pwned" in md.source  # poc result rendered
        # Links must be inert: untrusted content cannot trigger webbrowser.open.
        assert md._open_links is False


def test_render_produces_valid_markdown() -> None:
    """_render builds well-structured Markdown from a FindingDetail."""
    from flosswing.tui.data import FindingDetail
    from flosswing.tui.screens.finding_detail import _render

    d = FindingDetail(
        id="test-1",
        title="SQL injection in login()",
        attack_class="sql_injection",
        location="src/auth.py:42-55 (login)",
        severity="critical",
        confidence="confirmed",
        status="confirmed",
        description="Unsanitised user input is interpolated into a raw SQL query.",
        poc_code="payload = \"' OR 1=1 --\"",
        poc_result='{"stdout": "admin logged in"}',
        suggested_fix="Use parameterised queries.",
        verdict="exploitable",
        verdict_rationale="Confirmed via PoC execution.",
        reachable="yes",
        trace_rationale="Taint flows from HTTP param to cursor.execute.",
        call_chain=["handle_login (src/views.py:10)", "login (src/auth.py:42)"],
    )
    md = _render(d)
    # Starts with H1 title.
    assert md.startswith("# SQL injection in login()")
    # Description prose is present.
    assert "Unsanitised user input" in md
    # PoC code appears inside a fenced block (backticks on a line before it).
    assert "```" in md
    assert "' OR 1=1 --" in md
    # PoC result is present.
    assert "admin logged in" in md
    # Call chain items are present.
    assert "handle_login" in md


def test_fence_guard_prevents_breakout() -> None:
    """_fence uses a longer fence when content contains backtick runs."""
    from flosswing.tui.screens.finding_detail import _fence

    # Content with triple backticks — must produce at least 4-backtick fence.
    out = _fence("```")
    assert out.startswith("````"), f"expected 4-backtick opening fence, got: {out!r}"
    # The literal triple-backtick content must appear inside.
    assert "```" in out

    # Content with no backticks — standard 3-backtick fence is fine.
    plain = _fence("hello world")
    assert plain.startswith("```")

    # Longer run: 5 backticks in content → 6-backtick fence.
    long_run = _fence("`````code`````")
    assert long_run.startswith("``````"), f"expected 6-backtick fence, got: {long_run!r}"

    # Structural breakout attempt: content embeds a closing fence on its own line
    # followed by an injected heading. The whole payload must stay inside the
    # outer fence — the injected heading must NOT escape into a real heading.
    content = "```\ncode\n```\n# INJECTED"
    out2 = _fence(content)
    lines = out2.splitlines()
    open_fence = lines[0]
    close_fence = lines[-1]
    # Outer fence is at least 4 backticks (longer than the embedded 3).
    assert open_fence.startswith("````")
    assert set(open_fence) == {"`"} and len(open_fence) >= 4
    assert close_fence == open_fence
    # The injected heading sits strictly between the outer fences (still fenced).
    body = lines[1:-1]
    assert "# INJECTED" in body
    # And there is no real heading: the only top-level lines outside the fence
    # are the fence lines themselves.
    assert out2.startswith(open_fence) and out2.endswith(close_fence)


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
async def test_runs_table_renders_repo_path_literally(seeded_db: str) -> None:
    """Untrusted repo paths must not be interpreted as Rich markup.

    RunsScreen wraps the repo-path cell in rich.text.Text; seed a run whose
    target_repo_path contains markup and assert it survives to the rendered
    Repo column cell (index 1).
    """
    from rich.style import Style

    with st_session.session_scope() as s:
        s.add(
            Run(
                id="01JTESTRUN0000000000000001",
                target_repo_path="/tmp/[bold]evil[/bold]",
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

    app = FlosswingTUI()
    async with app.run_test() as pilot:
        await pilot.pause()
        from textual.widgets import DataTable

        table = app.screen.query_one("#runs-table", DataTable)
        rendered = ""
        for row in range(table.row_count):
            lines = table._render_cell(row, 1, Style(), width=80)
            rendered += "".join(seg.text for line in lines for seg in line)
        assert "[bold]evil[/bold]" in rendered


@pytest.mark.asyncio
async def test_new_scan_modal_spawns_scan(
    seeded_db: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from unittest import mock

    from flosswing.tui import launcher
    from flosswing.tui.screens.new_scan import NewScanScreen

    spawned = {}

    def fake_spawn(path, *, formats, hunt_token_budget):  # type: ignore[no-untyped-def]
        spawned["path"] = str(path)
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
async def test_new_scan_rejects_empty_path(
    seeded_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from unittest import mock

    from flosswing.tui import launcher
    from flosswing.tui.screens.new_scan import NewScanScreen

    spawn = mock.MagicMock()
    monkeypatch.setattr(launcher, "spawn_scan", spawn)

    app = FlosswingTUI()
    async with app.run_test() as pilot:
        await pilot.pause()
        app.push_screen(NewScanScreen())
        await pilot.pause()
        from textual.widgets import Input, Static

        app.screen.query_one("#scan-path", Input).value = "   "
        app.screen.action_submit()
        await pilot.pause()
        err = app.screen.query_one("#scan-error", Static)
        assert str(err.content) != ""
    spawn.assert_not_called()


@pytest.mark.asyncio
async def test_new_scan_rejects_bad_format(
    seeded_db: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from unittest import mock

    from flosswing.tui import launcher
    from flosswing.tui.screens.new_scan import NewScanScreen

    spawn = mock.MagicMock()
    monkeypatch.setattr(launcher, "spawn_scan", spawn)

    app = FlosswingTUI()
    async with app.run_test() as pilot:
        await pilot.pause()
        app.push_screen(NewScanScreen())
        await pilot.pause()
        from textual.widgets import Input, Static

        app.screen.query_one("#scan-path", Input).value = str(tmp_path)
        app.screen.query_one("#scan-formats", Input).value = "md,bogus"
        app.screen.action_submit()
        await pilot.pause()
        err = app.screen.query_one("#scan-error", Static)
        assert str(err.content) != ""
    spawn.assert_not_called()


@pytest.mark.asyncio
async def test_new_scan_rejects_nonpositive_budget(
    seeded_db: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from unittest import mock

    from flosswing.tui import launcher
    from flosswing.tui.screens.new_scan import NewScanScreen

    spawn = mock.MagicMock()
    monkeypatch.setattr(launcher, "spawn_scan", spawn)

    app = FlosswingTUI()
    async with app.run_test() as pilot:
        await pilot.pause()
        app.push_screen(NewScanScreen())
        await pilot.pause()
        from textual.widgets import Input, Static

        app.screen.query_one("#scan-path", Input).value = str(tmp_path)
        app.screen.query_one("#scan-budget", Input).value = "0"
        app.screen.action_submit()
        await pilot.pause()
        err = app.screen.query_one("#scan-error", Static)
        assert str(err.content) != ""
    spawn.assert_not_called()


@pytest.mark.asyncio
async def test_quit_guard_kill_terminates(seeded_db: str) -> None:
    from unittest import mock

    from flosswing.tui.screens.new_scan import QuitGuard

    child = mock.MagicMock()
    child.is_alive.return_value = True
    child.kind = "scan"

    app = FlosswingTUI()
    async with app.run_test() as pilot:
        await pilot.pause()
        app.push_screen(QuitGuard([child]))
        await pilot.pause()
        app.screen.action_kill()
        await pilot.pause()
    child.terminate.assert_called_once()


@pytest.mark.asyncio
async def test_enter_on_run_opens_detail(seeded_db: str) -> None:
    from flosswing.tui.screens.run_detail import RunDetailScreen

    app = FlosswingTUI()
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        assert isinstance(app.screen, RunDetailScreen)


@pytest.mark.asyncio
async def test_enter_on_finding_opens_detail(seeded_db: str) -> None:
    from flosswing.tui.screens.finding_detail import FindingDetailScreen
    from flosswing.tui.screens.findings import FindingsScreen

    app = FlosswingTUI()
    async with app.run_test() as pilot:
        await pilot.pause()
        app.push_screen(FindingsScreen(seeded_db))
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        assert isinstance(app.screen, FindingDetailScreen)


@pytest.mark.asyncio
async def test_db_error_shows_guidance(monkeypatch: pytest.MonkeyPatch) -> None:
    """RunsScreen must not crash when list_runs raises; #runs-empty shows guidance."""
    from flosswing.tui import data as tui_data

    def boom() -> list[object]:
        raise RuntimeError("boom")

    monkeypatch.setattr(tui_data, "list_runs", boom)

    app = FlosswingTUI()
    async with app.run_test() as pilot:
        await pilot.pause()
        from textual.widgets import Static

        empty = app.screen.query_one("#runs-empty", Static)
        assert "Cannot read" in str(empty.content)


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


def _add_running_run(run_id: str, *, path: str = "/tmp/live") -> None:
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
                finished_at=None,
                status="running",
                config_json="{}",
                flosswing_version="test",
            )
        )


@pytest.mark.asyncio
async def test_runs_screen_shows_stale_marker(
    seeded_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from rich.style import Style

    from flosswing import runpid
    from flosswing.tui.screens.runs import _LIVE_GLYPH

    _add_running_run("01JTESTRUN0000000000000009")
    monkeypatch.setattr(runpid, "run_is_live", lambda rid: False)

    app = FlosswingTUI()
    async with app.run_test() as pilot:
        await pilot.pause()
        from textual.widgets import DataTable

        table = app.screen.query_one("#runs-table", DataTable)
        rendered = ""
        for row in range(table.row_count):
            lines = table._render_cell(row, 3, Style(), width=6)  # Live column
            rendered += "".join(seg.text for line in lines for seg in line)
        assert _LIVE_GLYPH["stale"] in rendered


@pytest.mark.asyncio
async def test_runs_screen_shows_live_marker(
    seeded_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from rich.style import Style

    from flosswing import runpid
    from flosswing.tui.screens.runs import _LIVE_GLYPH

    _add_running_run("01JTESTRUN0000000000000010")
    monkeypatch.setattr(runpid, "run_is_live", lambda rid: True)

    app = FlosswingTUI()
    async with app.run_test() as pilot:
        await pilot.pause()
        from textual.widgets import DataTable

        table = app.screen.query_one("#runs-table", DataTable)
        rendered = ""
        for row in range(table.row_count):
            lines = table._render_cell(row, 3, Style(), width=6)
            rendered += "".join(seg.text for line in lines for seg in line)
        assert _LIVE_GLYPH["live"] in rendered


@pytest.mark.asyncio
async def test_run_detail_stale_banner_and_stops_polling(
    seeded_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from flosswing import runpid
    from flosswing.tui.screens.run_detail import RunDetailScreen

    _add_running_run("01JTESTRUN0000000000000011")
    monkeypatch.setattr(runpid, "run_is_live", lambda rid: False)

    app = FlosswingTUI()
    async with app.run_test() as pilot:
        await pilot.pause()
        screen = RunDetailScreen("01JTESTRUN0000000000000011")
        app.push_screen(screen)
        await pilot.pause()
        from textual.widgets import Static

        banner = app.screen.query_one("#liveness-banner", Static)
        assert "stopped" in str(banner.content).lower()
        # A stale run never changes -> polling must stop.
        assert screen._poll is None


@pytest.mark.asyncio
async def test_run_detail_live_banner(
    seeded_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from flosswing import runpid
    from flosswing.tui.screens.run_detail import RunDetailScreen

    _add_running_run("01JTESTRUN0000000000000012")
    monkeypatch.setattr(runpid, "run_is_live", lambda rid: True)

    app = FlosswingTUI()
    async with app.run_test() as pilot:
        await pilot.pause()
        app.push_screen(RunDetailScreen("01JTESTRUN0000000000000012"))
        await pilot.pause()
        from textual.widgets import Static

        banner = app.screen.query_one("#liveness-banner", Static)
        assert "live" in str(banner.content).lower()


@pytest.mark.asyncio
async def test_run_detail_recent_activity_panel(seeded_db: str) -> None:
    from flosswing.tui.screens.run_detail import RunDetailScreen

    app = FlosswingTUI()
    async with app.run_test() as pilot:
        await pilot.pause()
        app.push_screen(RunDetailScreen(seeded_db))
        await pilot.pause()
        from textual.widgets import Static

        panel = app.screen.query_one("#recent-activity", Static)
        # The seeded run has one 'hunt' agent session.
        assert "hunt" in str(panel.content).lower()
