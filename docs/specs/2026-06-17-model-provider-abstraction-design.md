# Model-provider abstraction design

## Context

Today every model invocation in FlossWing funnels through a single chokepoint:
`run_session()` in `flosswing/agent/runtime.py`. That function is hardcoded to
the Claude Agent SDK — it builds `ClaudeAgentOptions`, calls
`claude_agent_sdk.query()`, and spawns the `claude` CLI subprocess, which talks
the **Anthropic Messages API**. All three currently-supported "modes" (direct
`ANTHROPIC_API_KEY`, Azure Foundry routing, Entra ID) are *auth/routing*
variations on the same Anthropic-Messages-API backend — not different model
APIs (`flosswing/config.py`, `ARCHITECTURE.md` § Auth).

`ARCHITECTURE.md:529` lists **"Non-Anthropic model providers"** under *Deferred
to v2*, and `ARCHITECTURE.md:519` states v1 is "BYO `ANTHROPIC_API_KEY`". The
operator has decided (2026-06-17) to **promote a model-provider abstraction into
v1 scope**, with the doc edits made as part of this work.

The goal is **not** a working non-Anthropic model in this PR. The goal is a
clean *provider seam* so that Bedrock / Cloudflare / OpenAI / Ollama can be
slotted in by later PRs without re-plumbing the pipeline. Anthropic remains the
sole working backend and the default. This aligns with the forward-looking note
already in the doc — tools "work for any future LLM provider that speaks MCP"
(`ARCHITECTURE.md:379`).

### Operator decisions (2026-06-17)

- **Scope of this PR** → the abstraction + the existing Anthropic Agent-SDK path
  refactored behind it. No working Ollama/OpenAI/Bedrock/Cloudflare client; those
  ship as registered-but-unimplemented stubs.
- **Stub failure mode** → fail **early at `config.resolve()` / CLI startup** when
  an unimplemented provider is selected, before any scan work begins. The stub's
  `run_session` still raises as a defense-in-depth backstop.
- **Docs** → `ARCHITECTURE.md` is operator-curated; the edits below are proposed
  as a diff in chat and committed only after explicit approval.

### Non-goals (this PR)

- No real Ollama/OpenAI/Bedrock/Cloudflare client; no second agent loop; no
  OpenAI-style tool-calling adapter.
- No state-DB column for provider → **no schema change, no Alembic migration**.
- No change to the frozen agent-facing tool contracts (`docs/tool-contracts.md`).
- No change to sandbox, orchestrator, or any pipeline stage logic beyond passing
  the selected provider through to `run_session`.

## Architecture

The seam sits exactly at `run_session()`. Everything upstream (stages, tool
registry, sandbox, orchestrator) is untouched; everything that defines *how a
model session is driven* moves behind a `Provider` interface.

New subpackage `flosswing/agent/providers/`, mirroring the existing
`flosswing/sandbox/` pattern (a `base.py` Protocol + per-backend modules +
selection):

```
flosswing/agent/providers/
  __init__.py
  base.py          # Provider Protocol; SessionResult (moved here); shared _classify()
  anthropic_sdk.py # AnthropicSDKProvider: today's runtime.py body
  registry.py      # name -> Provider; get_provider(); is_implemented(); stub registration
```

`flosswing/agent/runtime.py` becomes a **thin facade**. `run_session(...)` gains
a `provider: str = "anthropic"` parameter, resolves the provider via the
registry, and delegates. The public `run_session` name and its existing keyword
signature are preserved so the six stage modules need only add one argument.

### Provider Protocol (`base.py`)

```python
class Provider(Protocol):
    name: str
    required_env_keys: frozenset[str]   # auth/config keys this provider reads from env
    def validate_auth(self, env: Mapping[str, str]) -> None: ...  # raise AuthCredentialMissingError
    async def run_session(
        self, *, model: str, system_prompt: str, tools: list[Any],
        user_prompt: str, token_budget: int, auth_env: dict[str, str],
        run_id: str, stage: str, task_id: str | None = None,
        finding_id: str | None = None, agent_session_id: str | None = None,
    ) -> SessionResult: ...
```

- `SessionResult` (the existing dataclass) **moves to `base.py`** — it is the
  provider-agnostic return contract.
- The outcome taxonomy (`completed / refused / budget_exceeded / timed_out /
  errored`) and the pure `_classify()` mapping are **shared** in `base.py`; they
  describe FlossWing's session contract, not anything Anthropic-specific.
- Anthropic-specific SDK parsing (`_harvest_usage`, `_api_error_from_result`,
  `_is_spurious_sdk_exit_error`, the `query()` loop) moves into `anthropic_sdk.py`.

### AnthropicSDKProvider (`anthropic_sdk.py`)

A faithful relocation of the current `runtime.py` body — no behavioral change.
`name = "anthropic"`. `required_env_keys` is the existing Anthropic/Foundry/Entra
key set (see Config below). `validate_auth()` contains the auth-path check that
currently lives inline in `config.resolve()` (direct key OR Foundry routing +
one of {Foundry key, Entra SP triple, az-login session}), raising the same
`AuthCredentialMissingError` with the same message.

### Registry (`registry.py`)

- Maps provider name → `Provider`.
- `get_provider(name) -> Provider`; unknown name raises `UnknownProviderError`
  listing the registered names.
- `is_implemented(name) -> bool`.
- Registers `ollama`, `openai`, `bedrock`, `cloudflare` as
  `UnimplementedProvider(name)` instances. Their `run_session` raises
  `ProviderNotImplementedError`; `validate_auth` is a no-op. Registering them
  (rather than leaving them unknown) means `--provider ollama` yields a precise
  "not yet implemented" message and reserves the names.

## Config & selection

- New field `Config.provider: str`, default `"anthropic"`.
- New CLI flag `--provider` on `flosswing scan`, threaded into `eval` for parity.
- `config.resolve(provider=...)` resolution order matches `model`: CLI flag →
  env (`FLOSSWING_PROVIDER`) → (config.toml *iff* `model` is already toml-loaded;
  match whatever `model` does today) → default `"anthropic"`.
- **Auth becomes provider-delegated.** `resolve()` looks up the selected provider
  and calls `provider.validate_auth(os.environ)`. For `anthropic` this reproduces
  today's behavior and error message exactly (the logic relocates, unchanged).
- **Early stub rejection.** After determining the provider name, `resolve()` (or
  the CLI layer it calls) checks `registry.is_implemented(name)`; if false it
  raises `ProviderNotImplementedError` before doing any auth probing or scan
  setup.

### `.env` auto-load allowlist

`config.AUTH_ENV_KEYS` (the allowlist that restricts the default `.env`
auto-load so a planted `.env` cannot inject arbitrary env vars) is **derived from
`AnthropicSDKProvider.required_env_keys`** rather than kept as a standalone
literal. Value is unchanged for this PR (Anthropic is the only real provider). A
future real provider extends the allowlist simply by declaring its keys, and the
security property is preserved automatically. A unit test locks
`AUTH_ENV_KEYS == AnthropicSDKProvider.required_env_keys`.

No credential value is ever logged, persisted to the state DB, or placed in an
error message. New provider error strings route through `errors.scrub()` like
everything else.

## Error handling

Add to `flosswing/errors.py` (both scrubbed, both subclasses of the existing
error base used for CLI-surfaced failures):

- `ProviderNotImplementedError` — raised at `resolve()` for a registered-but-stub
  provider, and as a backstop inside `UnimplementedProvider.run_session`.
- `UnknownProviderError` — raised by `registry.get_provider()` for an unregistered
  name; message lists the registered names.

## Testing

Unit tests only (CLAUDE.md: mock the SDK at the `query()`/`tool()` boundary, never
HTTP). No integration/eval changes needed — Anthropic behavior is unchanged.

- `registry`: `get_provider("anthropic")` returns the SDK provider; unknown name
  raises `UnknownProviderError`; each stub name returns an `UnimplementedProvider`
  and `is_implemented()` is correct.
- `UnimplementedProvider.run_session` raises `ProviderNotImplementedError`.
- `config.resolve`: `--provider` plumbing + precedence; default is `anthropic`;
  selecting a stub raises `ProviderNotImplementedError` at resolve time; Anthropic
  `validate_auth` reproduces today's missing-credential error.
- Regression guard: drive `run_session(provider="anthropic")` through the mocked
  SDK and assert the same `SessionResult` as the pre-refactor code path.
- `AUTH_ENV_KEYS == AnthropicSDKProvider.required_env_keys`.

## Files touched

New:
- `flosswing/agent/providers/__init__.py`
- `flosswing/agent/providers/base.py`
- `flosswing/agent/providers/anthropic_sdk.py`
- `flosswing/agent/providers/registry.py`
- `tests/unit/test_providers.py` (and additions to existing config/runtime tests)

Modified:
- `flosswing/agent/runtime.py` — thin facade delegating to the registry.
- `flosswing/config.py` — `provider` field, resolution, provider-delegated auth,
  derived `AUTH_ENV_KEYS`.
- `flosswing/cli.py` — `--provider` flag, early stub rejection.
- `flosswing/eval/runner.py` — pass provider through for parity.
- `flosswing/stages/{recon,hunt,validate,gapfill,dedupe,trace}.py` — one line each:
  `provider=cfg.provider` at the `run_session(...)` call.
- `flosswing/errors.py` — two new scrubbed error types.
- `ARCHITECTURE.md` — **proposed diff, committed only after operator approval**:
  (1) remove "Non-Anthropic model providers" from the v2 list; (2) add a "Model
  providers" subsection under *Agent runtime* describing the seam, the default,
  and the registered-but-unimplemented stubs; (3) note the abstraction in the v1
  scope summary with Anthropic-only as the working backend.

## Verification

`ruff check` and `mypy --strict` pass; full unit suite green
(`pytest tests/unit`). No migration, so the CI schema-sync check is unaffected.
