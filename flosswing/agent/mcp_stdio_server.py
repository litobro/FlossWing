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

"""Standalone stdio MCP server serving one stage scope's tool descriptors.

Launched by Codex as ``python -m flosswing.agent.mcp_stdio_server --scope ...``.
Newline-delimited JSON-RPC 2.0 over stdin/stdout; no listening socket. The state
DB is selected by the inherited ``FLOSSWING_DB_URL`` env var (see
flosswing/state/session.py), never a flag.
"""

from __future__ import annotations

import argparse
import asyncio
import inspect
import json
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from flosswing.agent import tool_descriptors as td
from flosswing.errors import scrub

_DEFAULT_PROTOCOL = "2025-06-18"
_SCOPES = ("recon", "hunt", "validate", "dedupe", "trace", "gapfill")


def _result(msg_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _error(msg_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


def _tool_error(text: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": text}], "isError": True}


def _call_tool(
    params: dict[str, Any], by_name: dict[str, td.ToolDescriptor]
) -> dict[str, Any]:
    name = params.get("name")
    d = by_name.get(name) if isinstance(name, str) else None
    if d is None:
        return _tool_error(scrub(f"unknown tool: {name!r}"))
    args = params.get("arguments") or {}
    if not isinstance(args, dict):
        return _tool_error("arguments must be an object")
    out = d.call(args)
    if d.is_async or inspect.isawaitable(out):
        out = asyncio.run(out)
    return {
        "content": out.get("content", []),
        "isError": bool(out.get("is_error", False)),
    }


def handle_message(
    msg: dict[str, Any], descriptors_by_name: dict[str, td.ToolDescriptor]
) -> dict[str, Any] | None:
    """Handle one JSON-RPC message; return the response, or None (notification)."""
    method = msg.get("method")
    has_id = "id" in msg
    msg_id = msg.get("id")
    params = msg.get("params")
    if not isinstance(params, dict):
        params = {}

    if method == "initialize":
        version = params.get("protocolVersion")
        return _result(
            msg_id,
            {
                "protocolVersion": version if isinstance(version, str) else _DEFAULT_PROTOCOL,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "flosswing", "version": "1"},
            },
        )
    if method == "ping":
        return _result(msg_id, {})
    if method == "tools/list":
        tools = [
            {
                "name": d.name,
                "description": d.description,
                "inputSchema": d.input_model.model_json_schema(),
            }
            for d in descriptors_by_name.values()
        ]
        return _result(msg_id, {"tools": tools})
    if method == "tools/call":
        return _result(msg_id, _call_tool(params, descriptors_by_name))
    if not has_id:
        return None  # notifications (incl. notifications/initialized) get no reply
    return _error(msg_id, -32601, f"method not found: {method}")


def _build_descriptors(
    args: argparse.Namespace, parser: argparse.ArgumentParser
) -> dict[str, td.ToolDescriptor]:
    repo = Path(args.repo_root)
    builders: dict[str, tuple[Callable[..., list[td.ToolDescriptor]], tuple[str, ...]]] = {
        "recon": (td.build_recon_descriptors, ("budget_total",)),
        "hunt": (td.build_hunt_descriptors, ("hunt_task_id",)),
        "validate": (td.build_validate_descriptors, ("agent_session_id",)),
        "dedupe": (td.build_dedupe_descriptors, ()),
        "trace": (td.build_trace_descriptors, ("agent_session_id",)),
        "gapfill": (
            td.build_gapfill_descriptors,
            ("gapfill_new_task_cap", "budget_total", "total_token_budget"),
        ),
    }
    builder, extra = builders[args.scope]
    kwargs: dict[str, Any] = {"repo_root": repo, "run_id": args.run_id}
    for k in extra:
        v = getattr(args, k)
        if v is None:
            parser.error(f"--{k.replace('_', '-')} is required for --scope {args.scope}")
        kwargs[k] = v
    return {d.name: d for d in builder(**kwargs)}


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="flosswing.agent.mcp_stdio_server")
    p.add_argument("--scope", required=True, choices=_SCOPES)
    p.add_argument("--run-id", required=True)
    p.add_argument("--repo-root", required=True)
    p.add_argument("--hunt-task-id")
    p.add_argument("--agent-session-id")
    p.add_argument("--budget-total", type=int)
    p.add_argument("--gapfill-new-task-cap", type=int)
    p.add_argument("--total-token-budget", type=int)
    return p


def _log(s: str) -> None:
    print(scrub(s), file=sys.stderr, flush=True)


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    by_name = _build_descriptors(args, parser)
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
            if not isinstance(msg, dict):
                raise ValueError("message must be a JSON object")
        except ValueError as e:
            resp: dict[str, Any] | None = _error(None, -32700, scrub(f"parse error: {e}"))
        else:
            try:
                resp = handle_message(msg, by_name)
            except Exception as e:  # keep the server alive on tool bugs
                _log(f"internal error: {type(e).__name__}: {e}")
                resp = _error(msg.get("id"), -32603, "internal error") if "id" in msg else None
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
