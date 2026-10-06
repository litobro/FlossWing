# OpenAI Codex / Daybreak Blue Provider Backend — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make FlossWing's registered-but-unimplemented `openai` provider a co-equal backend that drives OpenAI Daybreak Blue (`gpt-daybreak-blue-latest`) through the Codex app-server, selectable per-run via `--provider openai`.

**Architecture:** A new `Provider` implementation drives the `codex` app-server subprocess for one agent session, exposing FlossWing's existing tools to Codex through a standalone **stdlib stdio MCP server**. Tool definitions are factored into transport-neutral descriptors consumed by both the existing claude-agent-sdk `@tool` path (unchanged) and the new stdio server. The provider auto-approves only `flosswing` MCP tool calls (scoped; never the `--dangerously` bypass) and maps Codex's JSON event stream onto the shared `base._classify` outcome taxonomy.

**Tech Stack:** Python 3.11+, claude-agent-sdk (existing Anthropic path), SQLAlchemy/SQLite state DB, Pydantic tool contracts, the external `codex` CLI (v0.160.1, account login), pytest + pytest-asyncio, ruff, mypy --strict.

**Spec:** `docs/superpowers/specs/2026-10-06-openai-codex-daybreak-provider-design.md` (read it alongside this plan).

## Global Constraints

- **Python 3.11+, full type hints; `ruff check .` and `mypy --strict flosswing` must pass** after every task. Add `# type: ignore` only with an inline reason.
- **Tool contracts are frozen** (`docs/tool-contracts.md`): re-serve the *same* pure impls over the new transport; no signature/field/error-semantics change.
- **No schema change, no migration**; `docs/schema.sql` untouched.
- **Do not edit** `ARCHITECTURE.md`, `docs/tool-contracts.md`, `docs/schema.sql`, `CLAUDE.md`.
- **No write access to the target repo**; stdio server reads `/repo` read-only, writes only to the state DB / scratch.
- **Transport is stdio, never a listening socket** ("FlossWing serves nothing, listens on nothing").
- **No new top-level dependency without operator approval.** Transport is Python stdlib only. If driving the app-server appears to need a library, **stop and ask** before adding it (spec §15).
- **Credentials never touch env/DB/logs/errors.** Codex login lives in `~/.codex`; `errors.scrub()` runs over all strings bound for stderr, the state DB, or the report. `auth_env_keys = frozenset()` for this provider.
- **Provider protocol unchanged**: match `flosswing/agent/providers/base.py` `Provider` (L166-194) exactly.
- **Model id:** `gpt-daybreak-blue-latest`. **Never** use `--dangerously-bypass-approvals-and-sandbox`.
- **Commit messages reference the spec/section**, e.g. *"Add transport-neutral tool descriptors per docs/superpowers/specs/2026-10-06-…-design.md §5"*.

## Review Focus

Failure modes the spec implies but ordinary task tests may miss — each gets a test in the owning task:

- **Scoped approval leak** — if Codex requests approval for a *non-`flosswing`* tool (e.g. a built-in shell/exec), the provider must **deny/ignore** it, never auto-approve. A blanket approve would re-open the sandbox hole we rejected. → Task 8.
- **App-server/codex process dies mid-session** (crash, non-zero exit, missing binary not caught at `validate_auth`) → outcome `errored` with a scrubbed message, no hang. → Task 8.
- **Recovered vs terminal refusal** — a Daybreak refusal on one turn that then completes must keep `outcome="completed"` with `refusal_text` set; only a terminal refusal is `outcome="refused"` (never laundered to `errored`; commit 892bc7b). → Task 6.
- **Tool impl raises `FlosswingError` inside the subprocess** — the stdio server returns a `ToolError` payload (`is_error=True`) and keeps serving; it does not crash the session. → Task 3.
- **Untrusted tool output** (huge file, binary, control chars from `/repo`) — existing size caps (`_SIZE_CAP_BYTES`, `_FINDING_TEXT_CAP_BYTES`) and `scrub()` hold across the stdio JSON-RPC boundary. → Task 4.

---

## Task 0: Phase 0 feasibility gate (investigation — throwaway, no product code)

**This task is a go/no-go spike, per spec §12. It commits only test fixtures, not product code.** If the round-trip cannot be made to work without `--dangerously-bypass-approvals-and-sandbox`, STOP and report — do not proceed to Task 1.

**Files:**
- Create (committed): `tests/fixtures/codex/round_trip.jsonl`, `tests/fixtures/codex/refusal.jsonl`, `tests/fixtures/codex/NOTES.md`
- Throwaway (scratch, not committed): a one-tool stdio MCP server + driver script

**Prerequisite:** `codex` installed and `codex login` done with a Daybreak-Blue-approved account (operator-side).

- [ ] **Step 1: Pin the login-status command.** Run `codex login --help` and record the exact status subcommand (e.g. `codex login status`) in `tests/fixtures/codex/NOTES.md`. This feeds Task 6's `validate_auth`.

- [ ] **Step 2: Pin the app-server turn/approval protocol.** Using a throwaway one-tool stdio MCP server (the spike's `flw_spike_mcp.py` shape), drive the **codex app-server** for one turn that calls the tool, with **scoped auto-approve** (answer only the `flosswing` approval request). Capture the full event stream. Record in `NOTES.md`: the exact request to start a turn, the approval-request event/method name and its reply shape, and the terminal event. **Do not use `--dangerously-bypass-approvals-and-sandbox`.**

- [ ] **Step 3: Save the round-trip fixture.** Save the captured JSONL (tool discovered → called → approved → result returned → final `agent_message` echoing the sentinel → `turn.completed` with `usage`) to `tests/fixtures/codex/round_trip.jsonl`. Confirm the sentinel reached the final message (proves the full round-trip Task 0 exists to prove).

- [ ] **Step 4: Save a refusal fixture.** Prompt Daybreak Blue with something it refuses; capture the JSONL to `tests/fixtures/codex/refusal.jsonl`. Record in `NOTES.md` how the refusal surfaces (agent_message text? a finish/stop field? a dedicated item type?) — this feeds Task 7's refusal detection.

- [ ] **Step 5: Record go/no-go.** In `NOTES.md`, state: can scoped auto-approve complete the round-trip without the bypass flag? YES → proceed. NO → stop and surface to the operator.

- [ ] **Step 6: Commit the fixtures.**
```bash
git add tests/fixtures/codex/
git commit -m "Add Codex app-server event fixtures from Phase 0 feasibility gate (spec §12)"
```

---

## Task 1: Transport-neutral tool descriptors + SDK adapter (Recon scope)

Establish the descriptor pattern and prove it against the smallest scope (Recon) by making `build_recon_tools` delegate to it with **no behavior change**.

**Files:**
- Create: `flosswing/agent/tool_descriptors.py`
- Modify: `flosswing/agent/tool_registry.py` (make `build_recon_tools` delegate)
- Test: `tests/unit/test_tool_descriptors.py`

**Interfaces:**
- Produces:
  - `@dataclass(frozen=True) class ToolDescriptor` with fields `name: str`, `description: str`, `input_model: type[BaseModel]`, `call: Callable[[dict[str, Any]], dict[str, Any]]` — where `call(args)` validates `args` against `input_model`, invokes the bound pure impl, and returns the MCP content/`ToolError` payload (the `_wrap_call` shape).
  - `to_sdk_tool(d: ToolDescriptor) -> Any` — wraps a descriptor as a `claude_agent_sdk.@tool` callable named `d.name`.
  - `build_recon_descriptors(*, repo_root: Path, run_id: str, budget_total: int) -> list[ToolDescriptor]`.
- Consumes: pure impls `flosswing.tools.{fs,search,findings}` (unchanged); `ToolValidationError`, `FlosswingError` from `flosswing.errors`.

- [ ] **Step 1: Write the failing test** (`tests/unit/test_tool_descriptors.py`):
```python
from __future__ import annotations
from pathlib import Path
from flosswing.agent import tool_descriptors as td

def test_recon_descriptors_names_and_order():
    ds = td.build_recon_descriptors(repo_root=Path("/repo"), run_id="r", budget_total=20)
    assert [d.name for d in ds] == [
        "read_file", "list_dir", "grep", "record_recon_artifact", "add_hunt_task",
    ]

def test_descriptor_call_validation_error_is_tool_error():
    ds = {d.name: d for d in td.build_recon_descriptors(
        repo_root=Path("/repo"), run_id="r", budget_total=20)}
    # read_file requires `path`; omitting it must yield an is_error payload, not raise.
    out = ds["read_file"].call({})
    assert out["is_error"] is True
    assert "content" in out

def test_to_sdk_tool_preserves_name():
    d = td.build_recon_descriptors(repo_root=Path("/repo"), run_id="r", budget_total=20)[0]
    sdk_tool = td.to_sdk_tool(d)
    assert getattr(sdk_tool, "name", "") == "read_file"
```

- [ ] **Step 2: Run it to verify it fails.** Run: `pytest tests/unit/test_tool_descriptors.py -v` — Expected: FAIL (`module ... has no attribute`).

- [ ] **Step 3: Implement `tool_descriptors.py`.** Move the shared `_ok`/`_err`/`_wrap_call` helpers here (they are currently duplicated per stage) and define:
```python
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from claude_agent_sdk import tool
from pydantic import BaseModel, ValidationError
from flosswing.errors import FlosswingError, ToolValidationError
from flosswing.tools import findings as t_findings, fs as t_fs, search as t_search

class _ToolError(BaseModel):
    error: str
    message: str
    retryable: bool

def _ok(payload: BaseModel) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": payload.model_dump_json()}]}

def _err(code: str, message: str, retryable: bool) -> dict[str, Any]:
    return {"content": [{"type": "text",
            "text": _ToolError(error=code, message=message, retryable=retryable).model_dump_json()}],
            "is_error": True}

def _invoke(fn: Callable[..., BaseModel], input_model: type[BaseModel],
            args: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
    try:
        inp = input_model.model_validate(args)
    except ValidationError as e:
        return _err(ToolValidationError.code, str(e), retryable=False)
    try:
        out = fn(inp, **kwargs)
    except FlosswingError as e:
        return _err(e.code, e.message, retryable=e.retryable)
    return _ok(out)

@dataclass(frozen=True)
class ToolDescriptor:
    name: str
    description: str
    input_model: type[BaseModel]
    call: Callable[[dict[str, Any]], dict[str, Any]]

def _desc(name: str, description: str, input_model: type[BaseModel],
          fn: Callable[..., BaseModel], **bound: Any) -> ToolDescriptor:
    return ToolDescriptor(name, description, input_model,
                          lambda args: _invoke(fn, input_model, args, **bound))

def to_sdk_tool(d: ToolDescriptor) -> Any:
    @tool(d.name, d.description, d.input_model.model_json_schema())
    async def _t(args: dict[str, Any]) -> dict[str, Any]:
        return d.call(args)
    return _t

def build_recon_descriptors(*, repo_root: Path, run_id: str, budget_total: int) -> list[ToolDescriptor]:
    return [
        _desc("read_file", "Read a file (or line range) from the target repository (read-only).",
              t_fs.ReadFileInput, t_fs.read_file, repo_root=repo_root),
        _desc("list_dir", "List immediate children of a directory in the target repository.",
              t_fs.ListDirInput, t_fs.list_dir, repo_root=repo_root),
        _desc("grep", "Regex search the target repository via ripgrep.",
              t_search.GrepInput, t_search.grep, repo_root=repo_root),
        _desc("record_recon_artifact",
              "Save Recon's architecture analysis (languages, build commands, entry points, trust boundaries, subsystems).",
              t_findings.RecordReconArtifactInput, t_findings.record_recon_artifact, run_id=run_id),
        _desc("add_hunt_task", "Enqueue a Hunt task. Returns accepted=False if budget exhausted.",
              t_findings.AddHuntTaskInput, t_findings.add_hunt_task,
              run_id=run_id, source="recon", budget_total=budget_total),
    ]
```
Copy each description string **verbatim** from `tool_registry.py` (L94-153).

- [ ] **Step 4: Run tests to verify they pass.** Run: `pytest tests/unit/test_tool_descriptors.py -v` — Expected: PASS.

- [ ] **Step 5: Make `build_recon_tools` delegate.** In `tool_registry.py`, replace the body of `build_recon_tools(ctx)` with:
```python
from flosswing.agent.tool_descriptors import build_recon_descriptors, to_sdk_tool
def build_recon_tools(ctx: RegistryContext) -> list[Any]:
    return [to_sdk_tool(d) for d in build_recon_descriptors(
        repo_root=ctx.repo_root, run_id=ctx.run_id, budget_total=ctx.budget_total)]
```
Leave `RegistryContext` as-is.

- [ ] **Step 6: Run the recon stage's existing unit tests to prove no behavior change.** Run: `pytest tests/unit/test_stages_recon.py -v` — Expected: PASS unchanged.

- [ ] **Step 7: Lint & type.** Run: `ruff check . && mypy --strict flosswing` — Expected: clean.

- [ ] **Step 8: Commit.**
```bash
git add flosswing/agent/tool_descriptors.py flosswing/agent/tool_registry.py tests/unit/test_tool_descriptors.py
git commit -m "Add transport-neutral tool descriptors; delegate Recon tools (spec §5)"
```

---

## Task 2: Descriptors for Hunt/Validate/Dedupe/Trace/Gapfill scopes

Extend the descriptor module to every remaining scope and make each stage's `_build_<scope>_tools` delegate — no behavior change.

**Files:**
- Modify: `flosswing/agent/tool_descriptors.py` (add 5 builders)
- Modify: `flosswing/stages/{hunt,validate,dedupe,trace,gapfill}.py` (delegate tool-building)
- Test: `tests/unit/test_tool_descriptors.py` (extend)

**Interfaces (Produces):**
- `build_hunt_descriptors(*, repo_root: Path, run_id: str, hunt_task_id: str) -> list[ToolDescriptor]`
- `build_validate_descriptors(*, repo_root: Path, run_id: str, agent_session_id: str) -> list[ToolDescriptor]`
- `build_dedupe_descriptors(*, repo_root: Path, run_id: str) -> list[ToolDescriptor]`
- `build_trace_descriptors(*, repo_root: Path, run_id: str, agent_session_id: str) -> list[ToolDescriptor]`
- `build_gapfill_descriptors(*, repo_root: Path, run_id: str, gapfill_new_task_cap: int, budget_total: int, total_token_budget: int) -> list[ToolDescriptor]`

Note: `compile_and_run` (Validate) is the only **async** tool. Add `_invoke_async(...)` mirroring `_invoke` with `out = await fn(...)`, and a `is_async: bool` flag on `ToolDescriptor` (default `False`); `to_sdk_tool` awaits when set, and the stdio server (Task 3) awaits when set.

- [ ] **Step 1: Write failing tests** asserting names+order per scope (from recon agent report §1). Example for hunt:
```python
def test_hunt_descriptors_names():
    ds = td.build_hunt_descriptors(repo_root=Path("/repo"), run_id="r", hunt_task_id="t")
    assert [d.name for d in ds] == [
        "read_file", "list_dir", "grep", "record_finding", "find_definition", "find_callers",
    ]
def test_validate_descriptors_names():
    ds = td.build_validate_descriptors(repo_root=Path("/repo"), run_id="r", agent_session_id="a")
    assert [d.name for d in ds] == [
        "read_file", "list_dir", "grep", "find_definition", "find_callers",
        "compile_and_run", "query_findings", "validate_finding",
    ]
    assert next(d for d in ds if d.name == "compile_and_run").is_async is True
```
Add equivalent `dedupe` (`read_file, query_findings, merge_findings, link_variant`), `trace` (`read_file, list_dir, grep, find_definition, find_callers, query_entry_points, query_findings, record_trace`), and `gapfill` (`read_file, list_dir, grep, query_findings, query_run_state, add_hunt_task`) tests.

- [ ] **Step 2: Run to verify fail.** Run: `pytest tests/unit/test_tool_descriptors.py -v` — Expected: FAIL.

- [ ] **Step 3: Implement the 5 builders.** For each, copy the `@tool` name/description/input-model/impl/kwargs **verbatim** from the recon agent report §1 (and the stage files). Add imports `from flosswing.tools import symbols as t_symbols, execution as t_execution, run_state as t_run_state` and `from flosswing.sandbox.base import CompileAndRunInput`. Bind kwargs exactly: hunt `record_finding` → `run_id, hunt_task_id, repo_root`; validate `validate_finding` → `run_id, agent_session_id`; validate `compile_and_run` → `run_id, repo_root` (async); trace `record_trace` → `run_id, agent_session_id`; gapfill `add_hunt_task` → `run_id, source="gapfill", budget_total, gapfill_new_task_cap`; gapfill `query_run_state` → `run_id, total_token_budget`.

- [ ] **Step 4: Run to verify pass.** Run: `pytest tests/unit/test_tool_descriptors.py -v` — Expected: PASS.

- [ ] **Step 5: Delegate in each stage.** Replace each `_build_<scope>_tools(...)` body with `return [to_sdk_tool(d) for d in build_<scope>_descriptors(...)]`, mapping the stage's existing params to the builder kwargs. Delete the now-unused per-stage `_ok`/`_err`/`_wrap_call`/`_wrap_async_call`/`_ToolError` duplicates in those files (import from `tool_descriptors` if still referenced elsewhere). Keep each stage's `_*_TOOL_COUNT` constant; it must still equal the new list length.

- [ ] **Step 6: Run all stage unit tests.** Run: `pytest tests/unit/test_stages_hunt.py tests/unit/test_stages_validate.py tests/unit/test_stages_dedupe.py tests/unit/test_stages_trace.py tests/unit/test_stages_gapfill.py -v` — Expected: PASS unchanged.

- [ ] **Step 7: Lint & type.** Run: `ruff check . && mypy --strict flosswing` — Expected: clean.

- [ ] **Step 8: Commit.**
```bash
git add flosswing/agent/tool_descriptors.py flosswing/stages/ tests/unit/test_tool_descriptors.py
git commit -m "Delegate all stage tool-building to transport-neutral descriptors (spec §5)"
```

---

## Task 3: Standalone stdio MCP server

A `python -m flosswing.agent.mcp_stdio_server` entry point that Codex launches as a subprocess, serving a scope's descriptors over newline-delimited JSON-RPC 2.0.

**Files:**
- Create: `flosswing/agent/mcp_stdio_server.py`
- Test: `tests/unit/test_mcp_stdio_server.py`

**Interfaces:**
- Consumes: `build_<scope>_descriptors(...)` (Tasks 1-2); `FLOSSWING_DB_URL` from env; `errors.scrub`.
- Produces: a CLI `--scope` + scope-specific ctx args (`--run-id`, `--repo-root`, `--hunt-task-id`, `--agent-session-id`, `--source`, `--budget-total`, `--gapfill-new-task-cap`, `--total-token-budget`); and `handle_message(msg: dict, descriptors_by_name: dict[str, ToolDescriptor]) -> dict | None` (pure, testable without a live process).

- [ ] **Step 1: Write failing tests** (`tests/unit/test_mcp_stdio_server.py`) against the pure `handle_message`:
```python
from __future__ import annotations
from pathlib import Path
from flosswing.agent import mcp_stdio_server as srv
from flosswing.agent import tool_descriptors as td

def _recon_by_name():
    return {d.name: d for d in td.build_recon_descriptors(
        repo_root=Path("/repo"), run_id="r", budget_total=20)}

def test_initialize_echoes_protocol_version():
    out = srv.handle_message(
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2025-06-18"}}, _recon_by_name())
    assert out["id"] == 1
    assert out["result"]["protocolVersion"] == "2025-06-18"
    assert out["result"]["serverInfo"]["name"] == "flosswing"

def test_tools_list_returns_scope_tools():
    out = srv.handle_message(
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, _recon_by_name())
    names = {t["name"] for t in out["result"]["tools"]}
    assert "read_file" in names and "add_hunt_task" in names

def test_initialized_notification_returns_none():
    assert srv.handle_message(
        {"jsonrpc": "2.0", "method": "notifications/initialized"}, _recon_by_name()) is None

def test_unknown_method_returns_jsonrpc_error():
    out = srv.handle_message(
        {"jsonrpc": "2.0", "id": 9, "method": "no/such"}, _recon_by_name())
    assert out["error"]["code"] == -32601

def test_tools_call_validation_error_is_tool_error(tmp_path):
    out = srv.handle_message(
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
         "params": {"name": "read_file", "arguments": {}}}, _recon_by_name())
    assert out["result"]["isError"] is True
```

- [ ] **Step 2: Run to verify fail.** Run: `pytest tests/unit/test_mcp_stdio_server.py -v` — Expected: FAIL.

- [ ] **Step 3: Implement the server.** Model the JSON-RPC handling on the Phase 0 spike server, but dispatch `tools/call` through the scope descriptors (awaiting `is_async` ones via `asyncio.run`). The `tools/call` result wraps the descriptor payload as MCP `{"content":[...], "isError": bool}` (derive `isError` from the descriptor payload's `is_error`). Build `descriptors_by_name` from `--scope` + ctx args in `main()`; the process reads `FLOSSWING_DB_URL` from its inherited env (do **not** add a `--db` flag). Every string written to stderr goes through `errors.scrub`.

- [ ] **Step 4: Run to verify pass.** Run: `pytest tests/unit/test_mcp_stdio_server.py -v` — Expected: PASS.

- [ ] **Step 5: Add a round-trip-over-subprocess test with a real DB write.** Spawn the server via `subprocess.Popen([sys.executable, "-m", "flosswing.agent.mcp_stdio_server", "--scope", "hunt", "--run-id", rid, "--repo-root", str(repo), "--hunt-task-id", tid])` with `env={**os.environ, "FLOSSWING_DB_URL": f"sqlite:///{tmp_path}/state.db"}`, seed the DB (run migrations + a hunt_task row) first, send `initialize`→`tools/list`→`tools/call record_finding(...)` as JSON lines, and assert the findings row exists in that DB afterward. This covers the Review Focus "subprocess write lands / linkage holds".

- [ ] **Step 6: Add an untrusted-output cap test.** Write a file larger than `t_fs._SIZE_CAP_BYTES` (256 KiB) into the temp repo, call `tools/call read_file` for it through `handle_message`, and assert the returned payload parses and carries `truncated: true` — i.e. the existing size cap survives the JSON-RPC boundary (Review Focus: untrusted tool output).

- [ ] **Step 7: Lint & type.** Run: `ruff check . && mypy --strict flosswing` — Expected: clean.

- [ ] **Step 8: Commit.**
```bash
git add flosswing/agent/mcp_stdio_server.py tests/unit/test_mcp_stdio_server.py
git commit -m "Add standalone stdio MCP server serving stage tool scopes (spec §6)"
```

---

## Task 4: `OpenAICodexProvider` skeleton — name, auth, registry promotion

Create the provider class with auth + registration, but a `run_session` that raises `NotImplementedError` for now (filled in Tasks 5-8). This makes `--provider openai` resolve past `config.resolve`'s implemented-gate.

**Files:**
- Create: `flosswing/agent/providers/openai_codex.py`
- Modify: `flosswing/agent/providers/registry.py`
- Test: `tests/unit/test_providers_openai_codex.py`
- Modify: `tests/unit/test_providers_registry.py`

**Interfaces (Produces):**
- `class OpenAICodexProvider` with `name = "openai"`, `auth_env_keys: frozenset[str] = frozenset()`, `validate_auth(self, env: Mapping[str, str]) -> None`, `async def run_session(self, *, model, system_prompt, tools, user_prompt, token_budget, auth_env, run_id, stage, task_id=None, finding_id=None, agent_session_id=None, on_usage=None) -> SessionResult`.
- Module-scope helper `_codex_logged_in() -> bool` (patchable in tests), mirroring `anthropic_sdk._has_az_session`.

- [ ] **Step 1: Write failing tests** (`tests/unit/test_providers_openai_codex.py`):
```python
from __future__ import annotations
import pytest
from flosswing.agent.providers import openai_codex as oc
from flosswing.errors import AuthCredentialMissingError

def test_name_and_no_env_keys():
    p = oc.OpenAICodexProvider()
    assert p.name == "openai"
    assert p.auth_env_keys == frozenset()

def test_validate_auth_rejects_when_not_logged_in(monkeypatch):
    monkeypatch.setattr(oc, "_codex_installed", lambda: True)
    monkeypatch.setattr(oc, "_codex_logged_in", lambda: False)
    with pytest.raises(AuthCredentialMissingError):
        oc.OpenAICodexProvider().validate_auth({})

def test_validate_auth_accepts_when_logged_in(monkeypatch):
    monkeypatch.setattr(oc, "_codex_installed", lambda: True)
    monkeypatch.setattr(oc, "_codex_logged_in", lambda: True)
    oc.OpenAICodexProvider().validate_auth({})  # no raise
```
And update `tests/unit/test_providers_registry.py`: change the stub parametrize list to `["ollama", "bedrock", "cloudflare"]`, and add `assert reg.is_implemented("openai") is True` + `isinstance(reg.get_provider("openai"), OpenAICodexProvider)`.

- [ ] **Step 2: Run to verify fail.** Run: `pytest tests/unit/test_providers_openai_codex.py tests/unit/test_providers_registry.py -v` — Expected: FAIL.

- [ ] **Step 3: Implement the provider skeleton.**
```python
from __future__ import annotations
import shutil, subprocess
from collections.abc import Mapping
from typing import Any
from flosswing.agent.providers.base import OnUsage, SessionResult
from flosswing.errors import AuthCredentialMissingError

_MISSING_AUTH_MSG = (
    "No Codex login found. Install the Codex CLI and run `codex login` with a\n"
    "Daybreak-Blue-approved account (credentials live in ~/.codex, not the env)."
)

def _codex_installed() -> bool:
    return shutil.which("codex") is not None

def _codex_logged_in() -> bool:
    # EXACT subcommand confirmed in Task 0 Step 1; default guess `codex login status`.
    try:
        r = subprocess.run(["codex", "login", "status"], check=False,
                           capture_output=True, timeout=10)
    except (subprocess.TimeoutExpired, OSError):
        return False
    return r.returncode == 0

class OpenAICodexProvider:
    name = "openai"
    auth_env_keys: frozenset[str] = frozenset()

    def validate_auth(self, env: Mapping[str, str]) -> None:
        if not (_codex_installed() and _codex_logged_in()):
            raise AuthCredentialMissingError(_MISSING_AUTH_MSG)

    async def run_session(self, *, model: str, system_prompt: str, tools: list[Any],
                          user_prompt: str, token_budget: int, auth_env: dict[str, str],
                          run_id: str, stage: str, task_id: str | None = None,
                          finding_id: str | None = None, agent_session_id: str | None = None,
                          on_usage: OnUsage | None = None) -> SessionResult:
        raise NotImplementedError("filled in by later tasks")
```
Confirm `_codex_logged_in`'s subcommand against `tests/fixtures/codex/NOTES.md` (Task 0 Step 1); fix if different.

- [ ] **Step 4: Promote in the registry.** In `registry.py`: `from flosswing.agent.providers.openai_codex import OpenAICodexProvider`; remove `"openai"` from `_STUB_NAMES`; add `"openai": OpenAICodexProvider()` to `_IMPLEMENTED`.

- [ ] **Step 5: Run tests to verify pass.** Run: `pytest tests/unit/test_providers_openai_codex.py tests/unit/test_providers_registry.py -v` — Expected: PASS.

- [ ] **Step 6: Lint & type.** Run: `ruff check . && mypy --strict flosswing` — Expected: clean.

- [ ] **Step 7: Commit.**
```bash
git add flosswing/agent/providers/openai_codex.py flosswing/agent/providers/registry.py tests/unit/test_providers_openai_codex.py tests/unit/test_providers_registry.py
git commit -m "Implement OpenAICodexProvider skeleton + auth + registry promotion (spec §7)"
```

---

## Task 5: pricing entry for Daybreak Blue

**Files:**
- Modify: `flosswing/agent/pricing.py`
- Test: `tests/unit/test_pricing.py` (create if absent)

- [ ] **Step 1: Write the failing test:**
```python
from flosswing.agent import pricing
def test_daybreak_blue_has_explicit_rate():
    assert "gpt-daybreak-blue-latest" in pricing.MODEL_RATES
    c = pricing.estimate_cost_usd(model="gpt-daybreak-blue-latest",
                                  input_tokens=1_000_000, output_tokens=0)
    # explicit rate, not the Opus fallback of 5.0
    assert c == pricing.MODEL_RATES["gpt-daybreak-blue-latest"][0]
```

- [ ] **Step 2: Run to verify fail.** Run: `pytest tests/unit/test_pricing.py -v` — Expected: FAIL.

- [ ] **Step 3: Add the entry.** In `MODEL_RATES`, add `"gpt-daybreak-blue-latest": (<in>, <out>)` with a comment: *"Daybreak via ChatGPT subscription has no per-token price; these are nominal, estimate-only (spec §10)."* Use the published GPT-5.6 input/output list rate if known at implementation time; otherwise set both to the Opus fallback `(5.0, 25.0)` and note it.

- [ ] **Step 4: Run to verify pass.** Run: `pytest tests/unit/test_pricing.py -v` — Expected: PASS.

- [ ] **Step 5: Lint & type, then commit.**
```bash
ruff check . && mypy --strict flosswing
git add flosswing/agent/pricing.py tests/unit/test_pricing.py
git commit -m "Add nominal Daybreak Blue pricing entry (spec §10)"
```

---

## Task 6: Codex event-stream parser → SessionResult

A pure parser that turns a list of Codex JSON events (the `tests/fixtures/codex/*.jsonl` from Task 0) into the inputs for `base._classify`, then returns a `SessionResult`. Kept pure and separate from subprocess I/O so it is unit-testable against real fixtures.

**Files:**
- Modify: `flosswing/agent/providers/openai_codex.py` (add parser functions)
- Test: `tests/unit/test_providers_openai_codex_parse.py`

**Interfaces (Produces):**
- `_harvest_usage(turn_completed: dict) -> dict[str, int]` — normalizes `{input_tokens, cached_input_tokens, cache_write_input_tokens, output_tokens}` to FlossWing names `{input_tokens, output_tokens, cache_read_tokens, cache_write_tokens}`.
- `_classify_events(events: list[dict], *, budget: int) -> SessionResult` — extracts `stop_reason`/`usage`/`refusal_text`/`api_error`/`tool_calls`, then returns `base._classify(...)`. Constants `_APPROVAL_EVENT_TYPE` and the refusal-detection rule are set from Task 0's `NOTES.md`.

- [ ] **Step 1: Write failing tests** loading the Phase 0 fixtures:
```python
from __future__ import annotations
import json
from pathlib import Path
from flosswing.agent.providers import openai_codex as oc

FIX = Path(__file__).parent.parent / "fixtures" / "codex"

def _events(name): return [json.loads(l) for l in (FIX / name).read_text().splitlines() if l.strip()]

def test_round_trip_completes_with_usage():
    r = oc._classify_events(_events("round_trip.jsonl"), budget=10_000_000)
    assert r.outcome == "completed"
    assert r.input_tokens > 0
    assert r.tool_calls_count >= 1

def test_refusal_fixture_is_detected():
    r = oc._classify_events(_events("refusal.jsonl"), budget=10_000_000)
    assert r.refusal_text  # recorded
    # outcome is "refused" only if the refusal was terminal (see NOTES.md)

def test_budget_exceeded_when_input_over_budget():
    r = oc._classify_events(_events("round_trip.jsonl"), budget=1)
    assert r.outcome == "budget_exceeded"
```

- [ ] **Step 2: Run to verify fail.** Run: `pytest tests/unit/test_providers_openai_codex_parse.py -v` — Expected: FAIL.

- [ ] **Step 3: Implement the parser** against the known event schema (spec §2): iterate events; count `item.completed` where `item.type == "mcp_tool_call"` (status `failed` with an approval error is still a tool-call attempt, but see Task 8); read `usage` from `turn.completed` via `_harvest_usage`; set `api_error` from a process/protocol error event; set `refusal_text`/terminal-`stop_reason` per `NOTES.md`; call `base._classify(stop_reason=..., usage=..., refusal_text=..., budget=budget, api_error=..., cost_usd=None)`. **Refusal detection must precede the error branch** (commit 892bc7b).

- [ ] **Step 4: Run to verify pass.** Run: `pytest tests/unit/test_providers_openai_codex_parse.py -v` — Expected: PASS.

- [ ] **Step 5: Lint & type, then commit.**
```bash
ruff check . && mypy --strict flosswing
git add flosswing/agent/providers/openai_codex.py tests/unit/test_providers_openai_codex_parse.py
git commit -m "Parse Codex event stream into SessionResult via _classify (spec §9-10)"
```

---

## Task 7: `run_session` — drive the app-server with scoped auto-approve

Wire the pieces: launch the stdio server + codex app-server, drive one turn, auto-approve only `flosswing` tool approvals, feed events to the parser, emit `UsageSnapshot`s. Keep the subprocess/app-server I/O behind a module-scope function the tests patch (mirroring `anthropic_sdk`'s module-level `query`).

**Files:**
- Modify: `flosswing/agent/providers/openai_codex.py`
- Test: `tests/unit/test_providers_openai_codex_run_session.py`

**Interfaces:**
- Consumes: `_classify_events` (Task 6), `build_<scope>_descriptors` indirectly via the stdio server, `tests/fixtures/codex/*.jsonl`.
- Produces: `async def _drive_turn(*, model, system_prompt, user_prompt, scope, ctx, on_usage) -> list[dict]` — the single patchable I/O boundary that launches codex + the stdio server and yields/returns events. `run_session` calls it, then `_classify_events`.

- [ ] **Step 1: Write failing tests** patching `_drive_turn` with a fake that replays a fixture (mirrors `_patch_query`):
```python
import json, pytest
from pathlib import Path
from flosswing.agent.providers import openai_codex as oc
FIX = Path(__file__).parent.parent / "fixtures" / "codex"

@pytest.mark.asyncio
async def test_run_session_completes(monkeypatch):
    events = [json.loads(l) for l in (FIX/"round_trip.jsonl").read_text().splitlines() if l.strip()]
    async def fake_drive(**kw): return events
    monkeypatch.setattr(oc, "_drive_turn", fake_drive)
    r = await oc.OpenAICodexProvider().run_session(
        model="gpt-daybreak-blue-latest", system_prompt="", tools=[], user_prompt="",
        token_budget=10_000_000, auth_env={}, run_id="r", stage="recon")
    assert r.outcome == "completed"
    assert r.cost_usd is None

@pytest.mark.asyncio
async def test_run_session_emits_usage(monkeypatch):
    events = [json.loads(l) for l in (FIX/"round_trip.jsonl").read_text().splitlines() if l.strip()]
    async def fake_drive(**kw): return events
    monkeypatch.setattr(oc, "_drive_turn", fake_drive)
    snaps = []
    await oc.OpenAICodexProvider().run_session(
        model="gpt-daybreak-blue-latest", system_prompt="", tools=[], user_prompt="",
        token_budget=10_000_000, auth_env={}, run_id="r", stage="recon", on_usage=snaps.append)
    assert snaps and snaps[-1].input_tokens > 0
```

- [ ] **Step 2: Run to verify fail.** Run: `pytest tests/unit/test_providers_openai_codex_run_session.py -v` — Expected: FAIL.

- [ ] **Step 3: Implement `run_session` + `_drive_turn`.** `run_session` maps `stage`→scope and the passed `run_id`/`task_id`/`finding_id`/`agent_session_id` into the ctx dict the stdio server needs; calls `await _drive_turn(...)`; emits an `on_usage` snapshot from the final usage; returns `_classify_events(events, budget=token_budget)`. `_drive_turn` launches `codex` (app-server adapter) with `-c` config pointing at `python -m flosswing.agent.mcp_stdio_server --scope ... <ctx>`, model `gpt-daybreak-blue-latest`, inheriting `FLOSSWING_DB_URL`; drives one turn; **auto-approves only approval requests whose server is `flosswing`** (Task 8 pins the guard); collects events. Use the app-server request/approval shapes recorded in Task 0 `NOTES.md`. **If this step reveals a library is needed to speak the app-server protocol, STOP and ask the operator** (Global Constraints / spec §15).

- [ ] **Step 4: Run to verify pass.** Run: `pytest tests/unit/test_providers_openai_codex_run_session.py -v` — Expected: PASS.

- [ ] **Step 5: Lint & type, then commit.**
```bash
ruff check . && mypy --strict flosswing
git add flosswing/agent/providers/openai_codex.py tests/unit/test_providers_openai_codex_run_session.py
git commit -m "Drive Codex app-server one-turn session with scoped auto-approve (spec §7-8)"
```

---

## Task 8: Scoped-approval guard + failure-mode hardening

Pin the Review Focus failure modes with explicit tests.

**Files:**
- Modify: `flosswing/agent/providers/openai_codex.py`
- Test: `tests/unit/test_providers_openai_codex_run_session.py` (extend)

- [ ] **Step 1: Write failing tests:**
```python
def test_only_flosswing_tools_are_approved():
    assert oc._should_auto_approve({"server": "flosswing", "tool": "read_file"}) is True
    assert oc._should_auto_approve({"server": "shell", "tool": "exec"}) is False
    assert oc._should_auto_approve({"server": "flosswing", "tool": ""}) is True

@pytest.mark.asyncio
async def test_process_crash_is_errored(monkeypatch):
    async def boom(**kw): raise OSError("codex app-server died")
    monkeypatch.setattr(oc, "_drive_turn", boom)
    r = await oc.OpenAICodexProvider().run_session(
        model="gpt-daybreak-blue-latest", system_prompt="", tools=[], user_prompt="",
        token_budget=10_000, auth_env={}, run_id="r", stage="hunt", task_id="t")
    assert r.outcome == "errored"
    assert "codex" in (r.error_text or "").lower()
```

- [ ] **Step 2: Run to verify fail.** Run: `pytest tests/unit/test_providers_openai_codex_run_session.py -v` — Expected: FAIL.

- [ ] **Step 3: Implement.** Add `def _should_auto_approve(req: dict) -> bool: return req.get("server") == "flosswing"`. Wrap `_drive_turn` in `run_session` with `try/except (OSError, subprocess.SubprocessError) as e:` → return `base._classify(stop_reason=None, usage={}, refusal_text=None, budget=token_budget, api_error=f"codex app-server failure: {e}", cost_usd=None)` (scrubbed by `_classify`). Use `_should_auto_approve` in `_drive_turn`'s approval handler.

- [ ] **Step 4: Run to verify pass.** Run: `pytest tests/unit/test_providers_openai_codex_run_session.py -v` — Expected: PASS.

- [ ] **Step 5: Lint & type, then commit.**
```bash
ruff check . && mypy --strict flosswing
git add flosswing/agent/providers/openai_codex.py tests/unit/test_providers_openai_codex_run_session.py
git commit -m "Harden Codex provider: scoped approval guard + process-failure mapping (Review Focus)"
```

---

## Task 9: Gated integration test + eval parity wiring

**Files:**
- Create: `tests/integration/test_openai_codex_live.py`
- Test: the eval path accepts `--provider openai` (verify, add CLI plumbing only if missing)

- [ ] **Step 1: Write a gated integration test** skipped unless `FLOSSWING_INTEGRATION=1` and `codex` is logged in:
```python
import os, pytest
from pathlib import Path
from flosswing.agent.providers.openai_codex import OpenAICodexProvider
from flosswing.agent.tool_descriptors import build_recon_descriptors, to_sdk_tool

pytestmark = pytest.mark.skipif(
    os.environ.get("FLOSSWING_INTEGRATION") != "1", reason="integration gated")

@pytest.mark.asyncio
async def test_recon_one_turn_live_daybreak(tmp_path):
    repo = Path(os.environ["FLOSSWING_INTEGRATION_REPO"])  # the pinned corpus repo
    tools = [to_sdk_tool(d) for d in build_recon_descriptors(
        repo_root=repo, run_id="itest", budget_total=20)]
    result = await OpenAICodexProvider().run_session(
        model="gpt-daybreak-blue-latest", system_prompt="You are a recon agent.",
        tools=tools, user_prompt="List the languages used in this repo via the tools.",
        token_budget=100_000, auth_env={}, run_id="itest", stage="recon")
    assert result.outcome in {"completed", "refused"}
    assert result.input_tokens > 0
```
Mirror the existing `tests/integration/` suite's corpus-repo fixture for `FLOSSWING_INTEGRATION_REPO` (reuse whatever that suite already uses to point at the tiny pinned repo); do not introduce a new corpus.

- [ ] **Step 2: Verify eval accepts the provider.** Run (gated): `FLOSSWING_INTEGRATION=1 flosswing eval --corpus v02_smoke --corpus-root tests/corpus --provider openai`. If `flosswing eval` lacks a `--provider` pass-through, add it mirroring `scan`'s `--provider` flag (config.resolve already accepts `provider=`); otherwise no code change.

- [ ] **Step 3: Confirm the full unit suite + lint + types.** Run: `pytest tests/unit && ruff check . && mypy --strict flosswing` — Expected: all PASS/clean.

- [ ] **Step 4: Commit.**
```bash
git add tests/integration/test_openai_codex_live.py flosswing/
git commit -m "Add gated Daybreak integration test + eval --provider wiring (spec §11)"
```

---

## Notes for the executor

- **Task 0 is a hard gate.** If its go/no-go is NO, stop and surface to the operator; Tasks 1-9 assume a YES and real fixtures in `tests/fixtures/codex/`.
- **Tasks 1-5 do not depend on Task 0** (descriptors, stdio server, skeleton, pricing are protocol-independent) and can proceed even while Task 0's app-server details are being pinned — but Tasks 6-9 consume Task 0's fixtures and `NOTES.md`.
- **The dependency gate is real:** if Task 7 Step 3 finds the app-server protocol needs a library, stop and ask before adding it.
- Run the migration-reversibility check only if a schema change sneaks in — none is planned, so it should stay untouched.

---

## Checkpoint review addenda (2026-10-06) — RESOLVE BEFORE TASK 7

A whole-batch review after Tasks 1–5 surfaced two items that are **operator decisions**, not code defects, and that reshape Tasks 7–8. Resolve them before implementing Task 7.

**OP-1 — ctx not derivable from the frozen `run_session` signature.** `mcp_stdio_server` needs, per scope: `repo_root` (all), `budget_total` (recon, gapfill), `gapfill_new_task_cap` + `total_token_budget` (gapfill). But `Provider.run_session` only receives `run_id, stage, task_id, finding_id, agent_session_id` and an opaque `tools` list (and `to_sdk_tool` does not attach the descriptor to the SDK object, so nothing is recoverable from `tools`). Task 7 Step 3 as written cannot produce those values. Options: **(a, recommended)** recover from the state DB by `run_id` inside the provider — `runs.target_repo_path`→repo_root, `runs.budget_total`→budget_total, gapfill cap recomputed from `hunt_tasks`, `total_token_budget` from `runs.config_json`; **(b)** extend the `Provider` protocol (forbidden without operator sign-off); **(c)** stage-side provider branching (leaks provider logic into stages). `task_id→--hunt-task-id` and `agent_session_id→--agent-session-id` already work and need no change. Decide (a/b/c) before Task 7.

**OP-2 — Codex built-in tools + untrusted `AGENTS.md` (security, add to Review Focus).** The Codex app-server gives the model its own built-in shell/read tools and injects `AGENTS.md` from its working directory. If Task 7 launches `codex` with `cwd=<target repo>`: (i) the untrusted repo's `AGENTS.md` becomes model instructions (violates "target repo is untrusted input"); (ii) read-only sandboxed shell typically needs no approval, so the Task 8 scoped-approval guard does **not** stop the model from reading `/repo` directly — bypassing `_SIZE_CAP_BYTES` and `scrub()`. Mitigation for Task 7: launch `codex` with `cwd=` an empty scratch dir, and disable Codex's built-in tools (if the config surface allows) so the `flosswing` MCP tools are the only route to the repo. This is a new **Review Focus** line for Tasks 7–8.

**Checkpoint must-fixes applied to Tasks 3/4 (this batch):** strengthened the stdio round-trip test to assert the `hunt_task_id` linkage (spec §6); added a top-level teardown guard to `mcp_stdio_server.main()` (BrokenPipe/KeyboardInterrupt/Exception) so normal Task-7 teardown does not emit an unscrubbed traceback; added the GPL header + module docstring to `openai_codex.py`. Still pending (operator/Task 0): confirm the `codex login status` subcommand against codex-cli v0.160.1.
