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

"""OpenAI Codex / Daybreak Blue backend.

Auth is the local ``codex login`` session (no env credential); ``run_session`` is
filled in by later tasks.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Mapping
from typing import Any

from flosswing.agent.providers.base import (
    OnUsage,
    SessionResult,
    UsageSnapshot,
    _classify,
)
from flosswing.errors import AuthCredentialMissingError

# Scopes the stdio MCP server (flosswing/agent/mcp_stdio_server.py) understands;
# the FlossWing agent ``stage`` names map 1:1 onto them. Index-build and report
# are deterministic (no agent session), so they never reach this provider.
_SCOPES: frozenset[str] = frozenset(
    {"recon", "hunt", "validate", "dedupe", "trace", "gapfill"}
)

# Bounded waits so the driver never hangs on a stuck/dead app-server. Generous:
# a FlossWing stage turn can legitimately run for minutes. Validated live by the
# Task 9 gated integration test.
_REQUEST_TIMEOUT_S: float = 60.0
_TURN_TIMEOUT_S: float = 900.0

_MISSING_AUTH_MSG = (
    "No Codex login found. Install the Codex CLI and run `codex login` with a\n"
    "Daybreak-Blue-approved account (credentials live in ~/.codex, not the env)."
)


def _codex_installed() -> bool:
    return shutil.which("codex") is not None


def _codex_logged_in() -> bool:
    # EXACT subcommand confirmed in Task 0 Step 1; default guess `codex login status`.
    try:
        r = subprocess.run(
            ["codex", "login", "status"],
            check=False,
            capture_output=True,
            timeout=10,
        )
    except (subprocess.TimeoutExpired, OSError):
        return False
    return r.returncode == 0


# --- Event-stream parsing (codex app-server protocol; see tests/fixtures/codex/NOTES.md)
#
# BEST-EFFORT REFUSAL HEURISTIC: Daybreak/Codex gives NO refusal signal. A
# refusal is an ordinary final ``agentMessage`` with ``turn/completed``
# status "completed" and no tool call. We therefore detect it from the message
# TEXT only, which can both miss refusals and misfire on benign prose.
_DECLINE_PHRASES: tuple[str, ...] = (
    "i can't",
    "i cannot",
    "i'm unable",
    "i am unable",
    "i won't",
    "can't help with",
    "unable to assist",
)


def _looks_like_decline(text: str) -> bool:
    # Normalise typographic apostrophes (the captured refusal uses U+2019).
    norm = text.replace("\u2019", "'").replace("\u2018", "'").lower()
    return any(p in norm for p in _DECLINE_PHRASES)


def _harvest_usage(token_usage: dict[str, Any]) -> dict[str, int]:
    """Map a ``thread/tokenUsage/updated`` ``tokenUsage`` payload (cumulative
    ``total``) to FlossWing's usage names. Missing keys default to 0."""
    total = token_usage.get("total") or {}
    return {
        "input_tokens": int(total.get("inputTokens") or 0),
        "output_tokens": int(total.get("outputTokens") or 0),
        "cache_read_tokens": int(total.get("cachedInputTokens") or 0),
        "cache_write_tokens": int(total.get("cacheWriteInputTokens") or 0),
    }


def _classify_events(events: list[dict[str, Any]], *, budget: int) -> SessionResult:
    """Reduce received app-server messages to a SessionResult (pure)."""
    usage: dict[str, int] = _harvest_usage({})
    tool_calls = 0
    final_text: str | None = None
    api_error: str | None = None

    for ev in events:
        if ev.get("error") is not None and "method" not in ev:
            err = ev["error"]
            msg = err.get("message") if isinstance(err, dict) else None
            api_error = str(msg or err)
            continue
        method = ev.get("method")
        params = ev.get("params") or {}
        if method == "thread/tokenUsage/updated":
            usage = _harvest_usage(params.get("tokenUsage") or {})
        elif method == "item/completed":
            item = params.get("item") or {}
            if item.get("type") == "mcpToolCall":
                tool_calls += 1
            elif item.get("type") == "agentMessage" and item.get("phase") == "final_answer":
                final_text = str(item.get("text") or "")
        elif method == "turn/completed":
            turn_err = (params.get("turn") or {}).get("error")
            if turn_err is not None:
                msg = turn_err.get("message") if isinstance(turn_err, dict) else None
                api_error = str(msg or turn_err)

    refusal_text: str | None = None
    stop_reason: str | None = None
    if final_text is not None and _looks_like_decline(final_text):
        refusal_text = final_text
        if tool_calls == 0:
            # Terminal refusal: detected BEFORE the error branch so a refusal
            # can never be laundered into ``errored`` (refusal overrides error).
            stop_reason = "refusal"
            api_error = None

    result = _classify(
        stop_reason=stop_reason,
        usage=usage,
        refusal_text=refusal_text,
        budget=budget,
        api_error=api_error,
        cost_usd=None,
    )
    return dataclasses.replace(result, tool_calls_count=tool_calls)


# --- Stage -> scope + ctx assembly (OP-1) -----------------------------------
#
# OP-1 (plan § checkpoint addenda): the frozen Provider.run_session signature
# carries only run_id/stage/task_id/finding_id/agent_session_id, NOT the
# per-scope ctx the stdio MCP server needs (repo_root for every scope;
# budget_total for recon/gapfill; gapfill_new_task_cap + total_token_budget for
# gapfill). The opaque ``tools`` list does not carry it either (to_sdk_tool does
# not attach the descriptor to the SDK object). Per operator decision (a) we
# recover everything that is not in the signature from the state DB by run_id —
# never by changing the frozen protocol. Every value below is DB-recoverable:
#   repo_root           <- runs.target_repo_path
#   budget_total        <- runs.budget_total (orchestrator writes the literal 20,
#                          which recon.py / gapfill.py also pass as 20)
#   gapfill_new_task_cap <- recomputed exactly as stages/gapfill._compute_cap:
#                          max(1, count(hunt_tasks source='recon') // 5)
#   total_token_budget  <- sum of the four per-stage token budgets in
#                          runs.config_json (stages/gapfill.run sums the same
#                          four cfg fields; orchestrator persists each one).
# task_id -> --hunt-task-id and agent_session_id -> --agent-session-id are
# pass-through from the signature and need no DB read.


def _stage_to_scope(stage: str) -> str:
    """Map a FlossWing stage name to an stdio-server scope (identity today).

    Raises ``ValueError`` for a stage with no agent scope (e.g. index_build),
    which must never be routed to this provider.
    """
    if stage not in _SCOPES:
        raise ValueError(f"no Codex MCP scope for stage {stage!r}")
    return stage


def _total_token_budget_from_config(config_json: str) -> int:
    """Sum the four per-stage token budgets recorded in ``runs.config_json``.

    Mirrors stages/gapfill.run's ``total_token_budget`` (recon + hunt + validate
    + gapfill). Raises ``RuntimeError`` if any is absent — the caller surfaces
    that as DONE_WITH_CONCERNS/BLOCKED rather than inventing a default.
    """
    try:
        data = json.loads(config_json)
    except (ValueError, TypeError) as e:
        raise RuntimeError(f"runs.config_json is not valid JSON: {e}") from e
    keys = (
        "recon_token_budget",
        "hunt_token_budget",
        "validate_token_budget",
        "gapfill_token_budget",
    )
    missing = [k for k in keys if not isinstance(data.get(k), int)]
    if missing:
        raise RuntimeError(
            "total_token_budget not recoverable from runs.config_json; "
            f"missing integer keys: {missing}"
        )
    return sum(int(data[k]) for k in keys)


def _build_server_args(
    *,
    scope: str,
    run_id: str,
    task_id: str | None,
    agent_session_id: str | None,
) -> list[str]:
    """Assemble the mcp_stdio_server CLI args (after ``--scope <scope>``).

    Reads the state DB by ``run_id`` (OP-1). Raises ``RuntimeError`` if a value
    a scope requires cannot be recovered — the frozen protocol stays untouched.
    """
    # Imported lazily so merely importing the provider (e.g. via the registry,
    # imported by config) does not pull in the Alembic/SQLAlchemy stack.
    from sqlalchemy import select

    from flosswing.state import session as st_session
    from flosswing.state.models import HuntTask, Run

    with st_session.session_scope() as s:
        run = s.get(Run, run_id)
        if run is None:
            raise RuntimeError(
                f"run {run_id!r} not found in state DB; cannot assemble Codex MCP ctx"
            )
        repo_root = run.target_repo_path
        budget_total = run.budget_total
        config_json = run.config_json
        recon_task_count = 0
        if scope == "gapfill":
            recon_task_count = len(
                s.execute(
                    select(HuntTask).where(
                        HuntTask.run_id == run_id,
                        HuntTask.source == "recon",
                    )
                )
                .scalars()
                .all()
            )

    args: list[str] = ["--run-id", run_id, "--repo-root", repo_root]
    if scope == "recon":
        args += ["--budget-total", str(budget_total)]
    elif scope == "hunt":
        if task_id is None:
            raise RuntimeError("hunt scope requires task_id (-> --hunt-task-id)")
        args += ["--hunt-task-id", task_id]
    elif scope in ("validate", "trace"):
        if agent_session_id is None:
            raise RuntimeError(
                f"{scope} scope requires agent_session_id (-> --agent-session-id)"
            )
        args += ["--agent-session-id", agent_session_id]
    elif scope == "dedupe":
        pass  # repo_root is the only ctx dedupe needs
    elif scope == "gapfill":
        cap = max(1, recon_task_count // 5)  # == stages/gapfill._compute_cap
        total = _total_token_budget_from_config(config_json)
        args += [
            "--gapfill-new-task-cap", str(cap),
            "--budget-total", str(budget_total),
            "--total-token-budget", str(total),
        ]
    else:  # pragma: no cover - _stage_to_scope already gated the scope
        raise RuntimeError(f"unhandled scope {scope!r}")
    return args


# --- The single patchable subprocess / app-server I/O boundary ---------------


def _augmented_env() -> dict[str, str]:
    """Inherit the process env, ensuring the Codex + node binaries are on PATH.

    ``codex`` installs to ``~/.local/bin`` and is a node CLI, so the node bin
    dir must also be reachable. OP-2: auth is the local ``codex login`` session
    in ``~/.codex`` (never an env credential), so nothing sensitive is added.
    """
    env = dict(os.environ)
    parts = [os.path.expanduser("~/.local/bin")]
    node = shutil.which("node")
    if node:
        parts.append(os.path.dirname(node))
    existing = env.get("PATH", "")
    if existing:
        parts.append(existing)
    env["PATH"] = os.pathsep.join(parts)
    return env


async def _drive_turn(
    *,
    model: str,
    system_prompt: str,
    user_prompt: str,
    scope: str,
    ctx: list[str],
    on_usage: OnUsage | None,
) -> list[dict[str, Any]]:
    """Drive ONE Codex app-server turn and return the server->client messages.

    Spawns ``codex app-server --stdio`` with the FlossWing stdio MCP server
    configured on its command line, speaks newline-delimited JSON-RPC 2.0
    (initialize -> initialized -> thread/start -> turn/start), scope-approves
    only our own ``flosswing`` MCP tool-call elicitations, collects every
    server->client message until ``turn/completed`` (or EOF / timeout), and
    returns them for ``_classify_events``.

    THIS FUNCTION IS NOT UNIT-TESTED. It performs real subprocess I/O against a
    live ``codex`` binary + Daybreak account and is written from the committed
    protocol capture in tests/fixtures/codex/NOTES.md. It is validated by the
    gated Task 9 integration test (FLOSSWING_INTEGRATION=1); unit tests patch
    this symbol wholesale and replay the fixtures.

    OP-2 (security): ``cwd`` is a FRESH EMPTY temp dir — never the target repo —
    so the untrusted repo's AGENTS.md cannot inject instructions, and the
    read-only sandbox's workspace is that empty dir, not ``/repo``. The Codex
    app-server exposes NO switch to disable its built-in shell/read tools
    (confirmed against ``codex app-server generate-ts``: ThreadStartParams /
    TurnStartParams expose only ToolsV2.web_search and AskForApproval's granular
    *approval* toggles, none of which remove the built-ins). So the mitigation
    is layered: empty cwd + sandbox="read-only" + scoped MCP approval mean the
    target repo is reachable only through the flosswing MCP tools (which take
    repo_root out-of-band via the stdio server's CLI args), keeping the
    _SIZE_CAP_BYTES / scrub() guarantees on the only path to ``/repo``.
    """
    del on_usage  # usage is harvested from the returned events in run_session

    work_dir = tempfile.mkdtemp(prefix="flw-codex-")
    env = _augmented_env()
    server_args = [
        "-m",
        "flosswing.agent.mcp_stdio_server",
        "--scope",
        scope,
        *ctx,
    ]
    cmd = [
        "codex",
        "app-server",
        "--stdio",
        "-c",
        f"mcp_servers.flosswing.command={json.dumps(sys.executable)}",
        "-c",
        f"mcp_servers.flosswing.args={json.dumps(server_args)}",
    ]

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
        cwd=work_dir,
    )

    collected: list[dict[str, Any]] = []
    pending: dict[int, asyncio.Future[dict[str, Any]]] = {}
    turn_done = asyncio.Event()
    loop = asyncio.get_running_loop()

    async def _send(obj: dict[str, Any]) -> None:
        assert proc.stdin is not None
        proc.stdin.write((json.dumps(obj) + "\n").encode())
        await proc.stdin.drain()

    async def _handle_server_request(msg: dict[str, Any]) -> None:
        mid = msg.get("id")
        method = msg.get("method")
        params = msg.get("params")
        params = params if isinstance(params, dict) else {}
        if method == "mcpServer/elicitation/request":
            meta = params.get("_meta")
            meta = meta if isinstance(meta, dict) else {}
            kind = meta.get("codex_approval_kind")
            server_name = params.get("serverName")
            # Scoped approval (Task 8 factors this into _should_auto_approve):
            # ACCEPT only our own flosswing MCP tool-call elicitations; DECLINE
            # every other elicitation (a built-in shell/exec approval, another
            # server). Never a blanket approve — that would re-open the hole the
            # sandbox exists to close.
            if kind == "mcp_tool_call" and server_name == "flosswing":
                result: dict[str, Any] = {"action": "accept", "content": {}, "_meta": None}
            else:
                result = {"action": "decline", "content": None, "_meta": None}
            await _send({"jsonrpc": "2.0", "id": mid, "result": result})
        else:
            # Unknown server->client request: empty result so the turn is not
            # blocked. We grant nothing we were not asked to scope.
            await _send({"jsonrpc": "2.0", "id": mid, "result": {}})

    async def _reader() -> None:
        assert proc.stdout is not None
        while True:
            line = await proc.stdout.readline()
            if not line:
                break  # EOF: the app-server closed stdout / exited
            text = line.decode(errors="replace").strip()
            if not text:
                continue
            try:
                msg = json.loads(text)
            except ValueError:
                continue
            if not isinstance(msg, dict):
                continue
            collected.append(msg)
            method = msg.get("method")
            mid = msg.get("id")
            if method is not None and mid is not None:
                await _handle_server_request(msg)  # server->client request
            elif method is None and mid is not None:
                fut = pending.pop(mid, None)  # response to one of our requests
                if fut is not None and not fut.done():
                    fut.set_result(msg)
            elif method == "turn/completed":
                turn_done.set()
        # EOF: unblock the turn wait and fail any outstanding handshake request
        # so the driver never hangs on a dead process.
        turn_done.set()
        for fut in pending.values():
            if not fut.done():
                fut.set_exception(
                    RuntimeError("codex app-server closed before responding")
                )

    async def _request(method: str, params: dict[str, Any], *, req_id: int) -> dict[str, Any]:
        fut: asyncio.Future[dict[str, Any]] = loop.create_future()
        pending[req_id] = fut
        await _send({"jsonrpc": "2.0", "id": req_id, "method": method, "params": params})
        return await asyncio.wait_for(fut, timeout=_REQUEST_TIMEOUT_S)

    reader_task = asyncio.create_task(_reader())
    try:
        await _request(
            "initialize",
            {
                "clientInfo": {"name": "flosswing", "title": "FlossWing", "version": "1"},
                "capabilities": {"experimentalApi": True, "requestAttestation": False},
            },
            req_id=1,
        )
        await _send({"jsonrpc": "2.0", "method": "initialized"})

        thread_params: dict[str, Any] = {
            "model": model,
            "cwd": work_dir,  # OP-2: empty dir, never the target repo
            "approvalPolicy": "untrusted",
            "sandbox": "read-only",
            "ephemeral": True,
        }
        if system_prompt:
            # The stage system prompt rides as developerInstructions (additive,
            # the app-server analogue of ClaudeAgentOptions.system_prompt). This
            # placement is NOT live-validated yet (Task 9).
            thread_params["developerInstructions"] = system_prompt

        ts = await _request("thread/start", thread_params, req_id=2)
        thread = (ts.get("result") or {}).get("thread") or {}
        thread_id = thread.get("id")
        if not isinstance(thread_id, str):
            raise RuntimeError("codex app-server did not return a thread id")

        await _send(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "turn/start",
                "params": {
                    "threadId": thread_id,
                    "input": [
                        {"type": "text", "text": user_prompt, "text_elements": []}
                    ],
                },
            }
        )

        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(turn_done.wait(), timeout=_TURN_TIMEOUT_S)
    finally:
        reader_task.cancel()
        with contextlib.suppress(BaseException):
            await reader_task
        with contextlib.suppress(Exception):
            if proc.stdin is not None:
                proc.stdin.close()
        with contextlib.suppress(ProcessLookupError):
            proc.terminate()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(proc.wait(), timeout=5.0)
        shutil.rmtree(work_dir, ignore_errors=True)

    return collected


class OpenAICodexProvider:
    name = "openai"
    auth_env_keys: frozenset[str] = frozenset()

    def validate_auth(self, env: Mapping[str, str]) -> None:
        if not (_codex_installed() and _codex_logged_in()):
            raise AuthCredentialMissingError(_MISSING_AUTH_MSG)

    async def run_session(
        self,
        *,
        model: str,
        system_prompt: str,
        tools: list[Any],
        user_prompt: str,
        token_budget: int,
        auth_env: dict[str, str],
        run_id: str,
        stage: str,
        task_id: str | None = None,
        finding_id: str | None = None,
        agent_session_id: str | None = None,
        on_usage: OnUsage | None = None,
    ) -> SessionResult:
        """Drive one Codex app-server turn for ``stage`` and classify it.

        Codex serves FlossWing's tools over the stdio MCP server (not the SDK
        ``tools`` list, which this provider ignores) and authenticates via the
        local ``codex login`` session (not ``auth_env``). ``run_id``/``stage``
        plus the pass-through ``task_id``/``agent_session_id`` are resolved into
        the stdio server's CLI ctx via ``_build_server_args`` (OP-1, DB-backed).

        Task 8 adds the scoped-approval guard factor-out and maps a ``_drive_turn``
        crash to ``outcome="errored"``; here a failure propagates.
        """
        del tools, auth_env, finding_id  # see docstring: not consumed by Codex

        scope = _stage_to_scope(stage)
        ctx = _build_server_args(
            scope=scope,
            run_id=run_id,
            task_id=task_id,
            agent_session_id=agent_session_id,
        )

        started = time.monotonic()
        events = await _drive_turn(
            model=model,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            scope=scope,
            ctx=ctx,
            on_usage=on_usage,
        )
        # One app-server thread per session, so the final tokenUsage ``total``
        # (which _classify_events reads) is the cumulative session usage.
        result = _classify_events(events, budget=token_budget)
        result = dataclasses.replace(
            result, duration_ms=int((time.monotonic() - started) * 1000)
        )

        if on_usage is not None:
            # A single terminal snapshot from the last thread/tokenUsage/updated
            # (cost_usd is None — Daybreak via ChatGPT has no per-token price;
            # the caller estimates). Telemetry must never abort the session.
            with contextlib.suppress(Exception):
                on_usage(
                    UsageSnapshot(
                        input_tokens=result.input_tokens,
                        output_tokens=result.output_tokens,
                        cache_read_tokens=result.cache_read_tokens,
                        cache_write_tokens=result.cache_write_tokens,
                        tool_calls_count=result.tool_calls_count,
                        cost_usd=None,
                    )
                )

        return result
