# Design: OpenAI Codex / Daybreak Blue provider backend

- **Status:** Draft for review (brainstorming output; precedes writing-plans)
- **Date:** 2026-10-06
- **Author:** Thomas Dang (with Claude Code)
- **Related:** `ARCHITECTURE.md` § "Model providers"; `flosswing/agent/providers/`;
  `docs/specs/2026-06-17-model-provider-abstraction-design.md`

## 1. Purpose & context

Make the registered-but-unimplemented `openai` provider stub a **co-equal,
production-grade backend** that drives OpenAI's **Daybreak Blue** cyber-defense
access tier (model `gpt-daybreak-blue-latest`) through the **Codex CLI**, so a
FlossWing run can be pointed at Daybreak Blue instead of Anthropic.

Daybreak Blue is OpenAI's approval-gated *defensive* cyber tier (vulnerability
discovery, secure code review, malware analysis) — a direct fit for FlossWing's
authorized vulnerability-research purpose. It is reachable via "Sign in with
ChatGPT" / Codex CLI for an approved account.

Decisions fixed during brainstorming:

- **Bar:** co-equal with the Anthropic backend — all stages, full
  budget/usage/refusal handling, happy + refused path tests, held to the same
  standard. (Not an eval-only experiment; not a default-swap; not merely
  "selectable".)
- **Harness:** drive the `codex` binary as a subprocess — specifically the
  Codex **app-server** adapter (see §7; `codex exec` is unusable here, see §2).
- **Auth:** account login (`codex login`), not an API key. Credentials live in
  `~/.codex` (like an `az login` session); FlossWing reads **no** credential
  from the environment.
- **Selection:** per-run, via the existing global `--provider openai` /
  `FLOSSWING_PROVIDER`. Per-stage / cross-provider heterogeneity is a deliberate
  **follow-up**, out of scope here.

## 2. Spike findings (2026-10-06)

A throwaway spike (artifacts in session scratch, nothing committed) established:

**Proven:**

1. **Daybreak Blue runs via non-interactive Codex** as
   `model: gpt-daybreak-blue-latest, provider: openai`. The entitlement
   survives a non-interactive run — it is *not* silently downgraded to a
   standard model (the failure mode of codex#47103).
2. **The stdio MCP bridge works.** Codex discovered a `-c`-injected
   `mcp_servers.<name>` stdio server, listed its tool, and the Daybreak model
   issued a correct `mcp_tool_call` with the right arguments. The server was
   **~80 lines of Python stdlib** — so the MCP *transport* needs no heavyweight
   dependency.
3. **`codex exec --json` emits a clean, parseable JSONL event stream:**
   `thread.started` → `turn.started` → `item.started`/`item.completed` (typed
   `mcp_tool_call` and `agent_message` items) → `turn.completed` with a
   structured `usage` block (`input_tokens`, `cached_input_tokens`,
   `cache_write_input_tokens`, `output_tokens`, `reasoning_output_tokens`).
   This maps directly onto `base._classify` and `UsageSnapshot`.

**The blocker that reshaped the design:**

4. `codex exec` **hardcodes `approval_policy = "never"`**, which auto-rejects
   MCP tool calls (`"MCP tool call requires approval, but approval policy is
   never"`). `default_tools_approval_mode="auto"` via `-c` did **not** override
   it in codex-cli v0.160.1. The only `exec` workaround is
   `--dangerously-bypass-approvals-and-sandbox`, which (a) was blocked by this
   environment's safety classifier and (b) is **wrong for FlossWing regardless**
   because it disables Codex's command sandbox, contradicting FlossWing's threat
   model. References: codex#24135, codex#47103, codex#15824, Codex config
   reference, Codex MCP-server implementation docs.

**Consequence:** the backend is driven through the Codex **app-server** adapter,
which exposes a programmatic approval workflow (server-initiated elicitation
requests correlated by a request-id→callback map). FlossWing answers those
requests to **auto-approve only its own `flosswing` MCP tools** — the analog of
the Anthropic backend pre-authorizing `mcp__flosswing__*` via `allowed_tools` —
with no human and no bypass flag.

**Not yet empirically proven (→ Phase 0, §12):** the full round-trip (tool
executes → result returns to the model) through the app-server with scoped
auto-approve; the exact app-server wire protocol; the `codex login` status
subcommand; the JSONL shape of a real Daybreak refusal.

## 3. Constraints & non-goals

Binding project rules this design must honor:

- **Tool contracts are frozen.** We re-serve the *same* pure tool
  implementations over a new transport — no signature, field, or
  error-semantics change. (`docs/tool-contracts.md` untouched.)
- **No schema change / no migration.** Adding a backend writes no new columns.
  (`docs/schema.sql` untouched.)
- **No edits to curated docs** (`ARCHITECTURE.md`, `docs/tool-contracts.md`,
  `docs/schema.sql`, `CLAUDE.md`). If any turn out to need a note, propose a diff
  — do not edit.
- **No write access to the target repo.** The stdio server reads `/repo`
  read-only; writes go only to scratch / the state DB.
- **FlossWing "serves nothing, listens on nothing."** The tool transport is
  **stdio**, not a localhost HTTP MCP server — no listening socket (also keeps
  the transport dependency-free).
- **Credentials never touch env/DB/logs/errors.** Login stays in `~/.codex`;
  `errors.scrub()` runs over all strings bound for stderr, the state DB, or the
  report.
- **Untrusted repo input.** Repo content reaching the model via tool results is
  data, never instructions — no new injection surface beyond the Anthropic path.
- **Dependency policy.** Transport is stdlib (proven). Any dependency to drive
  the app-server (e.g. a small JSON-RPC client) must be confirmed and
  operator-approved **before** adding; default assumption is stdlib-only.
- **Provider protocol is not modified.** `Provider` / `run_session` signatures
  in `providers/base.py` stay as-is.

## 4. Architecture overview

One new backend behind the existing `Provider` protocol, selected per-run. No
pipeline-stage changes.

```
stage (recon/hunt/validate/dedupe/trace/gapfill)
  │  builds tool descriptors  +  runtime.run_session(provider="openai", …)
  ▼
OpenAICodexProvider.run_session()            [new: agent/providers/openai_codex.py]
  │  1. launch standalone stdio MCP server (subprocess) for this stage's scope
  │  2. start `codex` app-server subprocess, model=gpt-daybreak-blue-latest
  │  3. drive one turn; AUTO-APPROVE only `flosswing` MCP tool calls via the
  │     app-server approval callback (no human, no --dangerously flag)
  │  4. parse event stream → usage / tool-calls / refusal / stop / error
  ▼
flosswing stdio MCP server                   [new: agent/mcp_stdio_server.py]
  │  exposes the SAME pure tool impls (flosswing/tools/{fs,search,findings})
  ▼  (reads /repo read-only; writes only state DB / scratch)
SessionResult  ← base._classify(...)         +  UsageSnapshot via on_usage
```

Two new seams, both **additive** (the Anthropic path is unchanged):

- **Transport-neutral tool descriptors** (§5)
- **The stdio MCP server** (§6)

## 5. Component: transport-neutral tool descriptors

Problem: "co-equal, all stages" means re-serving every stage's tools, but the
tools are not centralized — Recon's are in `tool_registry.py::build_recon_tools`,
while Hunt / Validate / Dedupe / Trace / Gapfill define their `@tool`s **inline**
in their stage modules.

Design: introduce a transport-neutral descriptor, roughly

```python
@dataclass(frozen=True)
class ToolDescriptor:
    name: str
    description: str
    input_model: type[BaseModel]
    impl: Callable[..., BaseModel]   # the pure tool fn (writes nothing itself)
    needs_ctx: frozenset[str]        # which per-session values impl requires,
                                     # e.g. {"repo_root", "run_id", "db",
                                     # "agent_session_id"}
```

`needs_ctx` declares what the pure impl must be handed at call time. The two
transports satisfy it differently: the Anthropic `@tool` adapter closes over
in-process values (as today); the stdio server reconstructs them in its
subprocess from the CLI args in §6. The descriptor itself holds no live handles,
so it is safe to build once and reuse.

Each stage produces descriptors from the *same* source it currently uses to
build `@tool` callables. A thin adapter converts a descriptor into:

- a claude-agent-sdk `@tool` callable (Anthropic path — **unchanged behavior**,
  proven by the existing stage tests + a byte-for-byte adapter test), or
- a registration in the stdio MCP server (Codex path).

One definition, two transports, no contract drift.

*Touches:* `tool_registry.py` + the five stage modules that define tools inline.
All additive.

## 6. Component: the stdio MCP server

`flosswing/agent/mcp_stdio_server.py`, a `python -m flosswing.agent.mcp_stdio_server`
entrypoint that the Codex app-server launches as a subprocess. It speaks MCP as
newline-delimited JSON-RPC 2.0 over stdio (`initialize`,
`notifications/initialized`, `tools/list`, `tools/call`, `ping`).

Because it is a **separate process**, it cannot share the in-process closures the
Anthropic path uses (DB session, pre-allocated IDs). It is therefore
parameterized explicitly via CLI args:

```
--scope <recon|hunt|validate|dedupe|trace|gapfill>
--run-id <ulid>
--repo-root /repo
--db-path <~/.flosswing/runs/<id>/state.db>
--budget <int>
--agent-session-id <ulid>    # validate only
```

It opens its **own** state-DB session (WAL + `busy_timeout` are already enabled —
commit 31c53b3 — so concurrent processes are safe), rebuilds the scope's
descriptors (§5), and dispatches `tools/call → pure impl`, reusing the exact
`_wrap_call` success/`ToolError` payload semantics (`{"content":[...],
"is_error": ...}`). `/repo` stays read-only; writes go only to the state DB /
scratch. `errors.scrub()` applies to everything crossing to the DB or stderr.

**Transactionality divergence (explicit).** Some tools *write*: Hunt's
`record_finding`, and Validate's `validate_finding` (documented as writing "in
the same transaction as the verdict"). With the writer now in a subprocess, that
same-transaction invariant cannot hold across processes. This design specifies:
the subprocess **owns** the row write and preserves the `agent_session_id`
linkage; the main process reads the row back after the session — rather than
assuming a shared transaction. This is the one place the Codex path's semantics
intentionally differ from the Anthropic path, and tests must cover it.

## 7. Component: `OpenAICodexProvider` + app-server driver + auth

`flosswing/agent/providers/openai_codex.py` implements the existing `Provider`
protocol unchanged:

- `name = "openai"` (promoted from the `_STUBS` set to `_IMPLEMENTED` in
  `registry.py`, so `--provider openai` resolves instead of raising
  `ProviderNotImplementedError`).
- `auth_env_keys = frozenset()` — no env credential, so `config.AUTH_ENV_KEYS`
  and `config.DOTENV_ALLOWED_KEYS` are **unchanged**.
- `validate_auth(env)` — mirrors the Anthropic `_has_az_session()` pattern:
  `shutil.which("codex")` then a timeout-bounded `codex login` status probe;
  raise `AuthCredentialMissingError` (with a "run `codex login`" message) if
  either fails. *(Exact status subcommand pinned in Phase 0.)*

`run_session(...)` (exact protocol signature):

1. Launch the flosswing stdio MCP server (§6) for the caller's scope.
2. Start the **codex app-server** subprocess with a `-c`-injected config:
   `model = gpt-daybreak-blue-latest` (overridable by FlossWing `--model`),
   `mcp_servers.flosswing.{command,args}` → our server, and the approval wiring
   that routes tool-approval requests to us.
3. Send one turn (system prompt + user prompt); consume the event stream.
4. **Auto-approve** every `flosswing` tool approval request via the app-server
   callback, scoped to *only* our server's tools (never blanket, never the
   `--dangerously` flag).
5. Build `SessionResult` via `base._classify(...)`.

The provider ignores `auth_env` for *credentials* (login lives in `~/.codex`) but
ensures the subprocess environment can resolve the `codex` and `python3`
binaries (PATH).

## 8. Data flow (one session)

1. A stage builds its tool descriptors and calls `runtime.run_session(...,
   provider="openai")`.
2. The provider launches the scoped stdio MCP server and the codex app-server.
3. The model issues tool calls; the app-server requests approval; the provider
   auto-approves `flosswing` tools; the stdio server executes the pure impls
   against `/repo` (read-only) and the state DB (writes).
4. Per assistant turn, the provider emits a cumulative `UsageSnapshot` via
   `on_usage` (throttled, never fatal — matches the Anthropic path).
5. On terminal event, the provider maps the outcome via `_classify` and returns
   `SessionResult` (with `cost_usd=None`; see §10).

## 9. Error & refusal handling

`base._classify` precedence is fixed and shared: **api_error > refusal > budget >
completed**. The provider's job is to produce those inputs correctly.

- **`errored`** — app-server/MCP subprocess crash, non-zero exit with no result,
  JSON-RPC protocol error, network failure, or Daybreak entitlement rejection →
  a scrubbed `api_error` string.
- **`refused`** — Daybreak Blue is safety-gated, so refusals are first-class.
  Per commit 892bc7b ("stop laundering classifier refusals into generic API
  errors"), refusal detection **must precede** the generic error path so a
  refusal is never mis-booked as `errored`. `stop_reason="refusal"` is set only
  when the refusal is *terminal*; `refusal_text` is recorded on every non-error
  branch (matching the Anthropic semantics — a recovered refusal still produced
  a verdict). **The exact refusal-event JSONL shape is unknown and is captured
  in Phase 0.**
- **`budget_exceeded`** — `input_tokens > budget` from the usage block.
- **`completed`** — clean `turn.completed`.

**Exit-code carve-out.** As the Anthropic backend guards against "clean result,
then non-zero exit" (issue #22 / `_is_spurious_sdk_exit_error`), the Codex
provider treats a clean terminal `turn.completed` as authoritative and does not
let a trailing non-zero exit flip a good session to `errored`. Anchor on the
structured event, not loose string matching.

## 10. Usage, cost, budget

- **Usage:** parsed from the `turn.completed` usage block; normalized to
  FlossWing's field names (`input_tokens`, `output_tokens`, `cache_read_tokens`,
  `cache_write_tokens`) the way `_harvest_usage` does for Anthropic.
- **Cost:** `cost_usd = None` — Daybreak via ChatGPT subscription has no
  per-call cost figure — so callers fall back to
  `flosswing.agent.pricing.estimate_cost_usd`. `pricing.py` gains a **nominal**
  Daybreak token-price entry, clearly commented as an estimate only (subscription
  billing makes per-token cost approximate).
- **Budget:** enforced against cumulative input tokens. Granularity is
  **per-turn** (Codex reports usage at `turn.completed`), so a turn that exceeds
  budget is caught at its end and marked `budget_exceeded`. This matches the
  effectively post-hoc nature of the Anthropic enforcement.

## 11. Testing strategy

- **Unit (CI gate).** The Anthropic path mocks the SDK at `query()`/`tool()`;
  Codex has no `query()`, so the boundary is the **app-server event stream**.
  Unit tests feed canned JSONL/JSON-RPC sequences and assert `run_session`
  produces the correct `SessionResult` for: happy, terminal refusal, recovered
  refusal, budget_exceeded, errored, and the spurious-exit carve-out. Plus:
  stdio-server tests (`initialize`/`tools/list`/`tools/call`, `ToolError`
  semantics, writes to a temp `state.db`), and a descriptor-adapter test proving
  the Anthropic `@tool` output is byte-for-byte unchanged. Honors the
  "every stage has happy + refused path" rule.
- **Integration (gated `FLOSSWING_INTEGRATION=1`, not CI).** Real `codex` + real
  Daybreak + the tiny pinned corpus, one attack class. Needs the operator's
  logged-in session.
- **Eval parity (highest fidelity).** `flosswing eval --corpus v02_smoke
  --corpus-root tests/corpus --provider openai` scored against known-CVE ground
  truth, compared to the Anthropic baseline. Run before merge — this is the real
  "co-equal" proof.

## 12. Phase 0 feasibility gate (go/no-go, before product code)

Prove, end-to-end and throwaway, the one thing the spike could not finish:

- app-server one-turn drive with **scoped auto-approve** completing the full
  round-trip (tool executes → result returns to the Daybreak model → sentinel
  echoed), using the stdlib stdio server, **without** the bypass flag.

And capture the three unknowns:

- the app-server turn-request / event / approval-elicitation JSON schema,
- the `codex login` status subcommand,
- one real Daybreak **refusal's** JSONL shape.

**Go/no-go:** if scoped auto-approve cannot be made to work without the
`--dangerously` flag, stop and reconsider the harness rather than build on it.

## 13. Build & commit sequence

Each commit references this spec (e.g. *"Add transport-neutral tool descriptors
per docs/superpowers/specs/2026-10-06-…"*). Order matters:

1. Transport-neutral descriptor seam (additive; existing tests prove the
   Anthropic path intact).
2. stdio MCP server + its tests.
3. `OpenAICodexProvider` + app-server driver + registry promotion + unit tests.
4. `pricing.py` Daybreak entry.
5. Integration + eval wiring.

`ruff check .` and `mypy --strict flosswing` must pass throughout.

## 14. Open questions / risks

- **App-server wire protocol** — exact request/event/approval schema is unpinned
  (Phase 0). Highest remaining risk.
- **Refusal event shape** — unknown until a real Daybreak refusal is observed
  (Phase 0). Drives §9 correctness.
- **Cross-process tool writes** — the `validate_finding` same-transaction
  invariant is relaxed (§6); tests must confirm the `agent_session_id` linkage
  and readback hold.
- **Dependency** — whether driving the app-server needs a JSON-RPC client dep or
  stays stdlib. Confirm before adding; operator-approve if needed.
- **codex version drift** — behavior pinned against codex-cli v0.160.1; later
  versions may change event/config surface.
- **Daybreak entitlement scope** — assumes the operator's account keeps Daybreak
  Blue approved and `codex login` valid; FlossWing cannot provision this.

## 15. Dependencies

- MCP **transport**: Python stdlib only (spike-proven).
- App-server **driver**: stdlib assumed; any client library is subject to
  operator approval per `CLAUDE.md` dependency policy before it is added.
- External runtime prerequisite (not a Python dep): the `codex` CLI installed and
  logged in with a Daybreak-Blue-approved account.
