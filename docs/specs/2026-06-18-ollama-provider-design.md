# Ollama provider — native local model backend

**Status:** approved (design)
**Date:** 2026-06-18
**Depends on:** `2026-06-17-model-provider-abstraction-design.md` (the Provider seam)

## Goal

Add a working `ollama` provider so that

```
flosswing scan <path> --provider ollama --model <m>
```

runs the full pipeline (Recon → Hunt → Validate → Gapfill → Dedupe → Trace →
Report) end-to-end against a locally-running model. This replaces the current
`UnimplementedProvider` stub registered for `"ollama"` in
`flosswing/agent/providers/registry.py`.

Success criterion: an operator with Ollama running locally and a tool-calling
model pulled can complete a scan against a corpus repo and get a report, with
no Anthropic credentials present.

## Decisions (from brainstorming, 2026-06-18)

1. **Native Ollama loop.** The provider drives its own in-process agentic
   tool-use loop against the Ollama HTTP API. It does *not* reuse the
   `claude_agent_sdk` subprocess (the Anthropic path) and does *not* require an
   external translation proxy.
2. **`ollama` package** is the HTTP client (operator-approved new top-level
   dependency).
3. **Preflight = ping host + check model.** `validate_auth` confirms the Ollama
   server is reachable and the requested model is pulled, failing fast with an
   actionable message.
4. **No synthesized refusals.** Ollama exposes no reliable structured refusal
   signal, and the target repo is untrusted input, so heuristic string-matching
   on model output is rejected. The provider never returns `refused`; refusal
   detection stays an Anthropic-only capability.
5. **Ollama-specific default model.** When `provider == ollama` and no `--model`
   is given, use `DEFAULT_OLLAMA_MODEL` (`qwen2.5-coder:7b`); the preflight
   model-check then emits a friendly `ollama pull …` message if it is absent.

## Architecture

### New: `flosswing/agent/providers/ollama_native.py` — `OllamaProvider`

Implements the `Provider` Protocol.

- `name = "ollama"`
- `auth_env_keys = frozenset({"OLLAMA_HOST"})` — the `ollama` package reads
  `OLLAMA_HOST` natively; the key flows through `config.resolve`'s `auth_env`
  dict and is handed to the client.

#### `validate_auth(env, *, model=None)`

- Construct a synchronous `ollama.Client(host=env.get("OLLAMA_HOST"))`.
- Call `client.list()` to confirm the server is reachable. On failure raise with
  `ollama not reachable at <host>` (host scrubbed of any credential — none
  expected, but `errors.scrub()` runs over the message regardless).
- If `model` is provided, verify it appears in the pulled-model list; otherwise
  raise `model <m> not pulled; run: ollama pull <m>`.
- Error type: a new `OllamaBackendUnavailableError` (subclass of the existing
  config/auth error family) chosen in the plan; the message must be actionable
  and credential-free.

`validate_auth` is synchronous because `config.resolve()` is synchronous.

#### `run_session(...)` — native agentic loop

Same signature as the `Provider` Protocol (and the Anthropic impl).

1. **Seed messages:** `system_prompt` → `{"role": "system"}`, `user_prompt` →
   `{"role": "user"}`.
2. **Convert tools:** for each `SdkMcpTool` in `tools`, build an Ollama tool
   spec from `.name`, `.description`, and `.input_schema` (the real tools pass
   `Model.model_json_schema()`, already a JSON-Schema dict — used directly as
   `function.parameters`).
3. **Loop** (bounded by the guards below):
   - `client.chat(model=..., messages=..., tools=...)`.
   - If the assistant message has `tool_calls`: for each call, look up the tool
     by name, `await tool.handler(call.function.arguments)`, flatten the
     returned `{"content": [...]}` blocks to text, append a `{"role": "tool"}`
     message (carrying `is_error` if present), and continue the loop.
   - If there are no tool calls: this is the final answer — stop, outcome
     `completed`.
   - An unknown tool name is dispatched to a synthetic error tool-result so the
     model can recover, not a hard crash.
4. **Usage accounting:** accumulate per-response `prompt_eval_count` → input
   tokens, `eval_count` → output tokens. `cache_read_tokens` /
   `cache_write_tokens` are always `0` (Ollama has no prompt cache).
5. **Classify:** pass accumulated usage / terminal state through the shared
   `_classify(...)` and return a `SessionResult` with `duration_ms` measured
   over the whole session.

#### Safety guards

- **Wall-clock deadline:** module constant; exceeding it ends the session with
  outcome `timed_out`.
- **Max tool-iteration cap:** module constant; hitting it ends the session with
  outcome `errored` (`max_tool_iterations_exceeded`). Prevents an infinite
  tool-call loop from a confused local model.

Both constants are defined in `ollama_native.py` and documented; exact values
are set in the plan.

### Outcome mapping

| Condition                                              | Outcome           |
| ------------------------------------------------------ | ----------------- |
| Model returns a final message with no tool calls       | `completed`       |
| Accumulated input tokens > `token_budget`              | `budget_exceeded` |
| Wall-clock deadline exceeded                           | `timed_out`       |
| Max tool-iteration cap hit                             | `errored`         |
| Client / model / connection error (incl. model gone)   | `errored`         |
| (refusal)                                              | never produced    |

`budget_exceeded` is produced by the existing `_classify` check
(`input_tokens > budget`); the provider also breaks the loop early once it has
overshot, mirroring the Anthropic impl.

## Seam changes (internal — not the frozen agent-facing tool contracts)

These modify the Provider abstraction introduced in #32. None of them touch
`docs/tool-contracts.md` (the frozen agent-facing MCP tools).

1. **`Provider.validate_auth` gains a keyword-only `model: str | None = None`.**
   Backward compatible: existing callers (`prov.validate_auth(os.environ)`) keep
   working, and `AnthropicSDKProvider.validate_auth` ignores the new argument.
   `base.py` Protocol, `anthropic_sdk.py`, the `UnimplementedProvider` stub, and
   any re-export update accordingly.
2. **`config.resolve` changes:**
   - Resolve the effective model *before* calling `validate_auth`, so the model
     can be passed to the preflight.
   - When `provider == "ollama"` and no `--model` was supplied, default to
     `DEFAULT_OLLAMA_MODEL` instead of the Anthropic `DEFAULT_MODEL`.
   - Widen `config.AUTH_ENV_KEYS` (the `.env` auto-load allowlist) to the
     **union** of every *implemented* provider's `auth_env_keys`, so a
     working-directory `.env` may carry `OLLAMA_HOST`. A small registry helper
     exposes the implemented providers for this union.
3. **`registry.py`:** move `"ollama"` out of `_STUB_NAMES` and into
   `_IMPLEMENTED` with an `OllamaProvider()` instance.

## Dependency

- Add `ollama` to `pyproject.toml` `dependencies` (operator-approved).
- **Operator-curated doc diffs (require explicit approval, proposed in the
  plan, not applied unprompted):**
  - One line in the `CLAUDE.md` dependency-policy stack list for `ollama`.
  - Update the `ARCHITECTURE.md` wording that lists `ollama` as an unimplemented
    stub to reflect that it is now an implemented v1 backend.

## Configuration / CLI

- No new CLI flags. Selection is the existing `--provider ollama` /
  `FLOSSWING_PROVIDER`, and `--model` / its default.
- `OLLAMA_HOST` (optional) selects a non-default host; honored by the `ollama`
  client and `.env`-loadable via the widened allowlist.
- New constant `DEFAULT_OLLAMA_MODEL = "qwen2.5-coder:7b"` in `config.py`.
- Wall-clock-deadline and max-iteration constants live in `ollama_native.py`.

## Error handling & security

- All operator-facing strings (preflight errors, `error_text`) pass through
  `errors.scrub()`, consistent with the existing providers.
- No credentials are involved, but the no-logging / no-persisting discipline is
  unchanged; `OLLAMA_HOST` is config, not a secret, and may appear in messages.
- The model runs locally and has no repo write access: it can only act through
  the same `SdkMcpTool` handlers the Anthropic path uses, which already enforce
  read-only `/repo`, sandboxed `compile_and_run`, and scratch-only writes. The
  provider adds no new capability surface.
- The target repo remains untrusted input; the provider treats all model output
  as data and never executes it directly (only dispatches declared tool calls).

## Testing

- **Unit** — `tests/unit/test_providers_ollama.py`: mock the `ollama` client at
  the package boundary (not HTTP). Cover: single-round completion, multi-round
  tool dispatch, tool `is_error` propagation, unknown-tool recovery, budget
  cutoff (`budget_exceeded`), wall-clock `timed_out`, iteration-cap `errored`,
  connection-error `errored`, the no-refusal contract, and the `validate_auth`
  preflight (reachable / unreachable / model-missing).
- **Registry/config unit updates** — `test_providers_registry` (ollama now
  implemented), `test_config` (model-first resolution, Ollama default model,
  `AUTH_ENV_KEYS` union), and any `test_providers_base` change for the
  `validate_auth` signature.
- **Integration (gated)** — new `FLOSSWING_OLLAMA_INTEGRATION=1` gate that hits a
  real local Ollama with a small tool-calling model against the pinned corpus
  repo, running a single stage. Not in normal CI (mirrors the existing
  `FLOSSWING_INTEGRATION` discipline).
- **Manual end-to-end runbook** — the acceptance check:
  1. `ollama pull qwen2.5-coder:7b`
  2. `flosswing scan tests/corpus/<repo> --provider ollama`
  3. confirm a report is produced.

## Out of scope (deferred / non-goals)

- Streaming token display / live progress from the local model.
- Refusal heuristics.
- The other stub providers (`openai`, `bedrock`, `cloudflare`).
- Eval-corpus scoring/threshold tuning for local-model quality.
- Per-stage model routing or multi-model configs.

## Workspace

All implementation happens in a dedicated git worktree (via the
`using-git-worktrees` skill), isolated from `main`.

## Files touched

**New:**
- `flosswing/agent/providers/ollama_native.py`
- `tests/unit/test_providers_ollama.py`
- integration test (gated)

**Modified:**
- `flosswing/agent/providers/base.py` (validate_auth signature)
- `flosswing/agent/providers/anthropic_sdk.py` (signature compat)
- `flosswing/agent/providers/registry.py` (ollama → implemented)
- `flosswing/config.py` (model-first resolve, default model, AUTH_ENV_KEYS union)
- `pyproject.toml` (ollama dependency)
- `tests/unit/test_providers_registry.py`
- `tests/unit/test_config.py`
- possibly `flosswing/agent/runtime.py` (re-exports) / `test_providers_base.py`

**Proposed diff, approval required before applying:**
- `CLAUDE.md` (dependency list line)
- `ARCHITECTURE.md` (ollama no longer a stub)
