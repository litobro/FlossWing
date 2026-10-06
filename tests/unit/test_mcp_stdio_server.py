"""flosswing.agent.mcp_stdio_server: JSON-RPC handling + subprocess round-trip."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import create_engine, text
from ulid import ULID

from flosswing.agent import mcp_stdio_server as srv
from flosswing.agent import tool_descriptors as td
from flosswing.tools import fs as t_fs


def _recon_by_name(repo: Path = Path("/repo")) -> dict[str, td.ToolDescriptor]:
    return {
        d.name: d
        for d in td.build_recon_descriptors(repo_root=repo, run_id="r", budget_total=20)
    }


def test_initialize_echoes_protocol_version() -> None:
    out = srv.handle_message(
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2025-06-18"}},
        _recon_by_name(),
    )
    assert out is not None
    assert out["id"] == 1
    assert out["result"]["protocolVersion"] == "2025-06-18"
    assert out["result"]["serverInfo"]["name"] == "flosswing"


def test_tools_list_returns_scope_tools() -> None:
    out = srv.handle_message({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, _recon_by_name())
    assert out is not None
    tools = out["result"]["tools"]
    names = {t["name"] for t in tools}
    assert "read_file" in names and "add_hunt_task" in names
    assert all("inputSchema" in t and "description" in t for t in tools)


def test_initialized_notification_returns_none() -> None:
    assert srv.handle_message(
        {"jsonrpc": "2.0", "method": "notifications/initialized"}, _recon_by_name()
    ) is None


def test_ping_returns_empty_result() -> None:
    out = srv.handle_message({"jsonrpc": "2.0", "id": 4, "method": "ping"}, _recon_by_name())
    assert out == {"jsonrpc": "2.0", "id": 4, "result": {}}


def test_unknown_method_returns_jsonrpc_error() -> None:
    out = srv.handle_message({"jsonrpc": "2.0", "id": 9, "method": "no/such"}, _recon_by_name())
    assert out is not None
    assert out["error"]["code"] == -32601


def test_unknown_method_notification_is_silent() -> None:
    assert srv.handle_message({"jsonrpc": "2.0", "method": "no/such"}, _recon_by_name()) is None


def test_tools_call_validation_error_is_tool_error() -> None:
    out = srv.handle_message(
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
         "params": {"name": "read_file", "arguments": {}}},
        _recon_by_name(),
    )
    assert out is not None
    assert out["result"]["isError"] is True


def test_tools_call_unknown_tool_is_tool_error() -> None:
    out = srv.handle_message(
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
         "params": {"name": "nope", "arguments": {}}},
        _recon_by_name(),
    )
    assert out is not None
    assert out["result"]["isError"] is True


def test_read_file_cap_survives_jsonrpc_boundary(tmp_path: Path) -> None:
    (tmp_path / "big.txt").write_text("a" * (t_fs._SIZE_CAP_BYTES + 1000))
    out = srv.handle_message(
        {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
         "params": {"name": "read_file", "arguments": {"path": "big.txt"}}},
        _recon_by_name(tmp_path),
    )
    assert out is not None
    assert out["result"]["isError"] is False
    payload = json.loads(out["result"]["content"][0]["text"])
    assert payload["truncated"] is True


def test_async_descriptor_is_awaited() -> None:
    async def _co(args: dict[str, Any]) -> dict[str, Any]:
        return {"content": [{"type": "text", "text": "{}"}]}

    d = td.ToolDescriptor("x", "d", td.t_fs.ReadFileInput, _co, is_async=True)
    out = srv.handle_message(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
         "params": {"name": "x", "arguments": {}}},
        {"x": d},
    )
    assert out is not None
    assert out["result"]["isError"] is False


def test_subprocess_round_trip_writes_finding(tmp_path: Path) -> None:
    db = tmp_path / "state.db"
    url = f"sqlite:///{db}"
    env = {**os.environ, "FLOSSWING_DB_URL": url}
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.c").write_text("int main(void){return 0;}\n")
    run_id, task_id = str(ULID()), str(ULID())

    # Seed via a child process so the migration engine cache stays out of this one.
    seed = (
        "from flosswing.state import session as s\n"
        "from flosswing.state.models import Run, HuntTask\n"
        f"with s.session_scope() as x:\n"
        f"    x.add(Run(id={run_id!r}, target_repo_path='/tmp/x', depth='standard',"
        " budget_total=20, started_at='2026-05-25T00:00:00Z', config_json='{}',"
        " flosswing_version='0.2.0'))\n"
        f"    x.flush()\n"
        f"    x.add(HuntTask(id={task_id!r}, run_id={run_id!r}, attack_class='command_injection',"
        " scope_hint='src/', rationale='', priority='normal', source='recon',"
        " parent_finding_id=None, status='pending',"
        " created_at='2026-06-04T00:00:00Z', findings_count=0))\n"
    )
    subprocess.run([sys.executable, "-c", seed], env=env, check=True)

    proc = subprocess.Popen(
        [sys.executable, "-m", "flosswing.agent.mcp_stdio_server", "--scope", "hunt",
         "--run-id", run_id, "--repo-root", str(repo), "--hunt-task-id", task_id],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=env, text=True,
    )
    finding_args = {
        "attack_class": "command_injection", "file": "a.c", "line_start": 1, "line_end": 1,
        "severity": "high", "confidence": "likely", "title": "t", "description": "d",
    }
    msgs = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
         "params": {"name": "record_finding", "arguments": finding_args}},
    ]
    stdout, stderr = proc.communicate("".join(json.dumps(m) + "\n" for m in msgs), timeout=60)
    assert proc.returncode == 0, stderr
    replies = [json.loads(line) for line in stdout.splitlines()]
    assert [r["id"] for r in replies] == [1, 2, 3]
    assert replies[2]["result"]["isError"] is False
    fid = json.loads(replies[2]["result"]["content"][0]["text"])["finding_id"]

    eng = create_engine(url)
    with eng.connect() as c:
        rows = c.execute(
            text("SELECT id, run_id, hunt_task_id FROM findings WHERE id = :i"), {"i": fid}
        ).fetchall()
    assert len(rows) == 1
    assert rows[0][1] == run_id


def test_main_rejects_missing_scope_args() -> None:
    with pytest.raises(SystemExit):
        srv.main(["--scope", "hunt", "--run-id", "r", "--repo-root", "/tmp"])
