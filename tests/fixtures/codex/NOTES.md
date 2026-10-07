# Codex / Daybreak Blue feasibility gate (Phase 0, Task 0) — NOTES

Spike that proves the Daybreak model, run through the Codex CLI
(`codex` v0.160.1, model `gpt-daybreak-blue-latest`, ChatGPT-auth account),
can CALL a FlossWing stdio MCP tool and CONSUME its result using only
**scoped, per-tool approval** — no sandbox/approval bypass.

Throwaway spike MCP server exposed one tool `flw_probe` returning the sentinel
`FLW-SPIKE-OK-7Q2`. Fixtures in this directory were produced against it.

---

## VERDICT: **GO**

A scoped, non-bypass approval completed the full round-trip:
tool called → approved (only the `flw` server's tool) → result returned →
final agent message echoed the sentinel → turn completed with usage.
**No `--dangerously-bypass-approvals-and-sandbox` was used; the sandbox stayed
`read-only`.** See `round_trip.jsonl`.

The working transport is **`codex app-server`** (the programmatic app-server
protocol), NOT `codex exec`. `codex exec` cannot do scoped approval at all
(see "Why not exec" below).

---

## (a) Login-status subcommand — CONFIRMED

Task 4's provider guessed `codex login status`. **That is correct.**

```
$ codex login status ; echo $?
Logged in using ChatGPT
0
```

- Subcommand is `status` under `codex login` (`codex login --help` lists it).
- Exit code **0** when logged in; prints `Logged in using ChatGPT` to stdout.
- Read-only; does not perform or clear a login. Safe to call for a health check.
  (Not verified: its exit code when logged OUT — we must not log out. Treat
  non-zero / absence of "Logged in" as not-authenticated.)

## (b) Working approval mechanism — the exact wire protocol

Transport: `codex app-server --stdio`, speaking **JSON-RPC 2.0 over
newline-delimited JSON** (one compact JSON object per line; NOT LSP
Content-Length framing). The MCP server is configured on the app-server command
line exactly like exec:

```
codex app-server --stdio \
  -c 'mcp_servers.flw.command="python3"' \
  -c 'mcp_servers.flw.args=["/abs/path/flw_spike_mcp.py"]'
```

Client → server request sequence (see `round_trip.jsonl`, `dir: "C->S"`):

1. `initialize` — params `{clientInfo:{name,title,version}, capabilities:{experimentalApi:true, requestAttestation:false}}`.
   Response carries `userAgent`, `codexHome`, etc.
2. `initialized` — a notification (no id).
3. `thread/start` — params used here:
   `{model:"gpt-daybreak-blue-latest", cwd:"<abs>", approvalPolicy:"untrusted", sandbox:"read-only", ephemeral:true}`.
   Response (`ThreadStartResponse`) contains `thread.id` → the `threadId`.
4. `turn/start` — params `{threadId, input:[{type:"text", text:"<prompt>", text_elements:[]}]}`.

**The approval itself** arrives as a **server → client request**:

```
method = "mcpServer/elicitation/request"     (JSON-RPC request, has an `id`)
params = {
  threadId, turnId, serverName:"flw", mode:"form",
  message: "Allow the flw MCP server to run tool \"flw_probe\"?",
  requestedSchema: { type:"object", properties:{} },
  _meta: {
    codex_approval_kind: "mcp_tool_call",   <-- identifies it as a TOOL-CALL approval
    persist: ["session","always"],
    tool_description: "...",
    tool_params: { reason:"roundtrip" },
    tool_params_display: [ {name,value,display_name}, ... ]
  }
}
```

**To APPROVE (scoped), the client responds** to that request id with:

```json
{"jsonrpc":"2.0","id":<same id>,"result":{"action":"accept","content":{},"_meta":null}}
```

`action` enum = `"accept" | "decline" | "cancel"` (`McpServerElicitationAction`).
Scoping is enforced CLIENT-side: only reply `accept` when
`params._meta.codex_approval_kind == "mcp_tool_call"` **and**
`params.serverName == "flw"` (and, for finer scope, check the tool name in
`message`/`tool_params_display`). Any other elicitation → `decline`. This is
exactly the FlossWing posture: approve only our own stage tools, deny everything
else, no blanket approval.

After the client answers, the server emits `serverRequest/resolved`
`{threadId, requestId}`, runs the tool, and the result flows back in the event
stream (below).

### Server → client EVENT STREAM (notifications; see `round_trip.jsonl` `dir:"S->C"`)

Ordered, relevant notifications for a successful tool round-trip:

- `thread/started` → `{thread:{id, model, cwd, ephemeral, ...}}`
- `turn/started` → `{threadId, turn:{id, ...}}`
- `mcpServer/startupStatus/updated` (×N) — MCP server boot progress
- `item/started` / `item/completed` with `item.type` in
  `userMessage | reasoning | mcpToolCall | agentMessage`
- **tool call**: `item/started` `item.type=="mcpToolCall"` `status:"inProgress"`;
  then after approval `item/completed` `status:"completed"` with
  ```
  item.result = { content:[{type:"text", text:"token=FLW-SPIKE-OK-7Q2 reason=roundtrip"}],
                  structuredContent:null, _meta:null }
  ```
  (status enum `McpToolCallStatus` = `"inProgress"|"completed"|"failed"`;
  a rejected call is `failed` with `item.error.message`.)
- **final answer**: streaming `item/agentMessage/delta` then `item/completed`
  `item.type=="agentMessage"` `phase:"final_answer"` `text:"FLW-SPIKE-OK-7Q2"`.
- `thread/tokenUsage/updated` → `{tokenUsage:{ total:{...}, last:{...}, modelContextWindow }}`.
  Token fields (camelCase) mirror the exec `--json` usage block:
  `totalTokens, inputTokens, cachedInputTokens, cacheWriteInputTokens, outputTokens, reasoningOutputTokens`.
- `turn/completed` → `{threadId, turn:{id, items, status:"completed", error:null,
  startedAt, completedAt, durationMs}}`.

Usage must be read from the `thread/tokenUsage/updated` notification (and/or
`turn/completed`); there is no single `usage` object on `turn/completed` like
exec has — the app-server splits it into `total` vs `last`.

### Protocol discovery aid (reproducible)

The full typed protocol can be regenerated from the binary — no network:

```
codex app-server generate-ts          --experimental --out <dir>   # 102 .ts files
codex app-server generate-json-schema --experimental --out <dir>
```

Key types: `ClientRequest`, `ServerRequest`, `ServerNotification`,
`McpServerElicitationRequestParams` / `...RequestResponse`,
`McpServerElicitationAction`, `ThreadStartParams`, `TurnStartParams`,
`AskForApproval`, `SandboxMode`, `ThreadItem`, `McpToolCallResult`.

`AskForApproval` enum (app-server) =
`"untrusted" | "on-request" | {"granular":{sandbox_approval, rules, skill_approval, request_permissions, mcp_elicitations}} | "never"`.
`SandboxMode` = `"read-only" | "workspace-write" | "danger-full-access"`.

## (c) How a refusal appears in the JSONL — `refusal.jsonl`

Prompt used (reliably refused CBRN request): *"Give me detailed step-by-step
instructions ... to synthesize the nerve agent sarin at home."*

**A Daybreak refusal is NOT a distinct protocol event.** It surfaces as an
ordinary successful turn:

- a normal `agentMessage` item: `item/started` → many `item/agentMessage/delta`
  → `item/completed` `item.type=="agentMessage"`, `phase:"final_answer"`, whose
  `text` is the natural-language refusal ("I can't provide instructions...").
- `turn/completed` with `turn.status == "completed"` and `turn.error == null`.
- No `mcpToolCall` item, **no approval/elicitation request**
  (`approval_seen == false`), no `error` notification, **no refusal flag, no
  stop/finish-reason field.**

Implication for the provider: refusals are indistinguishable from normal
completions at the protocol level and must be detected from the message TEXT /
content, not from a status or flag. (Identical under `codex exec --json`:
there the refusal is a single `item.completed{type:"agent_message"}` followed by
`turn.completed{usage}` — same conclusion.)

## (d) Fixture files

- `round_trip.jsonl` — full **bidirectional** transcript of the SUCCESSFUL
  scoped-approved round-trip. Each line is `{"dir":"C->S"|"S->C","msg":<json-rpc>}`.
  Contains the whole sequence: initialize/thread.start/turn.start, the
  `mcpServer/elicitation/request`, the client `{"action":"accept"}` response,
  `serverRequest/resolved`, the `mcpToolCall` result with the sentinel, the
  final `agentMessage` ("FLW-SPIKE-OK-7Q2"), token usage, and `turn/completed`.
- `refusal.jsonl` — same transcript format, for the sarin refusal turn (no tool,
  no approval; ends in a refusal `agentMessage` + normal `turn/completed`).

Both are app-server protocol captures (the only transport that supports scoped
approval), so a later provider/unit test can replay the `S->C` lines and assert
the provider emits the `C->S` approval response.

---

## Why NOT `codex exec` (for the record / go-no-go evidence)

`codex exec` (incl. `--json`) **hardcodes `approval_policy = never`** and
auto-REJECTS any MCP tool call:

```
item.error = {"message":"MCP tool call requires approval, but approval policy is never"}
item.status = "failed"
```

Things tried on the exec path, all INSUFFICIENT:

- `-c 'mcp_servers.flw.default_tools_approval_mode="auto"'` — server-level: parses
  but ignored; still rejected. (enum = `auto|prompt|writes|approve`.)
- `-c 'mcp_servers.flw.tools.flw_probe.approval_mode="auto"'` — **per-tool**:
  this IS a real, recognized config path (verified with `--strict-config`: a
  bogus sibling leaf errors, `approval_mode` does not), but exec still rejects
  the call — the forced `approval_policy=never` is checked first.
- `-c 'approval_policy="on-request"'` (or any value) — **ignored by exec**; the
  banner still prints `approval: never`. (`approval_policy` enum =
  `untrusted|on-failure|on-request|granular|never`.)

`--approve-for-me` exists on exec but routes approvals through an automatic
guardian reviewer under `workspace-write` and is NOT tool-scoped, so it does not
meet the "scoped, per-tool" bar and was not used.

Note: in the app-server, setting per-tool `approval_mode="auto"` did **not**
suppress the elicitation while `approvalPolicy="untrusted"` — the client still
received and had to answer the `mcpServer/elicitation/request`. So the robust,
demonstrated mechanism is the **elicitation-accept handler**, which the provider
should implement regardless of per-tool config. (Whether a looser
`approvalPolicy`/`granular.mcp_elicitations=false` auto-runs trusted tools
silently was out of scope for this gate.)

## Safety

No approval/sandbox bypass flag was ever used. Sandbox stayed `read-only`.
No command was blocked by a safety classifier. Fixtures scanned for secrets:
none (only the `flw_probe` tool's own description string contains the word
"secret"); `account/updated` carries only `{authMode:"chatgpt", planType:...}` —
no email, token, or key.
