# Env-configurable Model Selection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let operators set FlossWing's model via a `FLOSSWING_MODEL` env var (settable from `.env`), keep `--model` as the top override, and bump the built-in default to `claude-opus-4-8`.

**Architecture:** Single model for all stages (`cfg.model`, unchanged). Resolution gains a middle tier: `--model` flag > `FLOSSWING_MODEL` env > `DEFAULT_MODEL`. A new `DOTENV_ALLOWED_KEYS` (= `AUTH_ENV_KEYS` ∪ `{FLOSSWING_MODEL}`) lets the default `.env` auto-load accept the model key without changing the meaning of `AUTH_ENV_KEYS` (which must stay exactly the provider's auth keys).

**Tech Stack:** Python 3.11+, click, pytest. No new dependencies.

## Global Constraints

- Python 3.11+, full type hints; `ruff check .` and `mypy --strict flosswing` must pass.
- Unit tests mock at `query()`/`tool()` — but these tasks touch only config/env, no SDK.
- Do NOT modify `AUTH_ENV_KEYS`'s value (a provider attribute); `test_auth_env_keys_match_anthropic_provider` pins `AnthropicSDKProvider.auth_env_keys == AUTH_ENV_KEYS`.
- Do NOT edit `CLAUDE.md`, `ARCHITECTURE.md`, `docs/tool-contracts.md`, `docs/schema.sql` (operator-curated; CLAUDE.md tweak is proposed separately in Task 3).
- Commit messages reference the spec: `docs/superpowers/specs/2026-07-16-model-env-config-design.md`.

---

### Task 1: Model resolution via `FLOSSWING_MODEL` + default bump

**Files:**
- Modify: `flosswing/config.py` (DEFAULT_MODEL line ~57; add MODEL_ENV_VAR; resolve model line ~130)
- Test: `tests/unit/test_config.py`

**Interfaces:**
- Consumes: existing `resolve(*, repo_root, model, ...)` and module constant `DEFAULT_MODEL`.
- Produces: `config.MODEL_ENV_VAR: str = "FLOSSWING_MODEL"`; `config.DEFAULT_MODEL == "claude-opus-4-8"`; `resolve()` model precedence `model or os.environ.get(MODEL_ENV_VAR) or DEFAULT_MODEL`.

- [ ] **Step 1: Add `FLOSSWING_MODEL` to the test clean-slate helper**

In `tests/unit/test_config.py`, inside `_strip_all_auth`, after the `FLOSSWING_PROVIDER` delenv line, add:

```python
    monkeypatch.delenv("FLOSSWING_MODEL", raising=False)
```

- [ ] **Step 2: Update the existing default-model assertion (will fail first)**

In `tests/unit/test_config.py`, in `test_resolves_with_anthropic_api_key`, change:

```python
    assert cfg.model == "claude-opus-4-7"
```
to:
```python
    assert cfg.model == "claude-opus-4-8"
```

- [ ] **Step 3: Add precedence tests**

Append to `tests/unit/test_config.py`:

```python
def test_default_model_is_opus_4_8(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _strip_all_auth(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    cfg = resolve(
        repo_root=tmp_path, model=None, recon_token_budget=None,
        hunt_token_budget=None, validate_token_budget=None,
        gapfill_token_budget=None,
    )
    assert cfg.model == "claude-opus-4-8"
    assert cfg.model == cfg_mod.DEFAULT_MODEL


def test_model_from_flosswing_model_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _strip_all_auth(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("FLOSSWING_MODEL", "claude-sonnet-5")
    cfg = resolve(
        repo_root=tmp_path, model=None, recon_token_budget=None,
        hunt_token_budget=None, validate_token_budget=None,
        gapfill_token_budget=None,
    )
    assert cfg.model == "claude-sonnet-5"


def test_cli_model_beats_flosswing_model_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _strip_all_auth(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("FLOSSWING_MODEL", "claude-sonnet-5")
    cfg = resolve(
        repo_root=tmp_path, model="claude-opus-4-8", recon_token_budget=None,
        hunt_token_budget=None, validate_token_budget=None,
        gapfill_token_budget=None,
    )
    assert cfg.model == "claude-opus-4-8"
```

- [ ] **Step 4: Run the tests to verify the two new-behavior tests + the edited assertion fail**

Run: `cd /home/tdang/projects/personal/FlossWing/.claude/worktrees/configurable-model-env && .venv/bin/python -m pytest tests/unit/test_config.py -k "default_model_is_opus or flosswing_model_env or resolves_with_anthropic_api_key" -q`
Expected: FAIL — `test_default_model_is_opus_4_8` and `test_resolves_with_anthropic_api_key` assert `claude-opus-4-8` but code returns `claude-opus-4-7`; `test_model_from_flosswing_model_env` returns the default, not the env value.

- [ ] **Step 5: Implement the config change**

In `flosswing/config.py`, change line ~57:
```python
DEFAULT_MODEL: str = "claude-opus-4-7"
```
to:
```python
DEFAULT_MODEL: str = "claude-opus-4-8"

# Operator-settable default model (overridden by the --model flag). Loadable
# from a working-directory .env (see DOTENV_ALLOWED_KEYS).
MODEL_ENV_VAR: str = "FLOSSWING_MODEL"
```

In `resolve()`, change the model line (~130):
```python
        model=model or DEFAULT_MODEL,
```
to:
```python
        model=model or os.environ.get(MODEL_ENV_VAR) or DEFAULT_MODEL,
```

(`os` is already imported at the top of `config.py`.)

- [ ] **Step 6: Run the full config test module**

Run: `cd /home/tdang/projects/personal/FlossWing/.claude/worktrees/configurable-model-env && .venv/bin/python -m pytest tests/unit/test_config.py -q`
Expected: PASS (all, including the edited assertion and 3 new tests).

- [ ] **Step 7: Commit**

```bash
git add flosswing/config.py tests/unit/test_config.py
git commit -m "Add FLOSSWING_MODEL env + bump default to claude-opus-4-8

Per docs/superpowers/specs/2026-07-16-model-env-config-design.md.
Precedence: --model > FLOSSWING_MODEL > DEFAULT_MODEL.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 2: Make `FLOSSWING_MODEL` loadable from the default `.env`

**Files:**
- Modify: `flosswing/config.py` (add `DOTENV_ALLOWED_KEYS` after `AUTH_ENV_KEYS`, ~line 77)
- Modify: `flosswing/cli.py` (default `.env` load, ~lines 88-91)
- Test: `tests/unit/test_config.py`

**Interfaces:**
- Consumes: `config.AUTH_ENV_KEYS` (frozenset), `config.MODEL_ENV_VAR` (from Task 1), `envfile.load_env_file(path, allowed_keys=...)`.
- Produces: `config.DOTENV_ALLOWED_KEYS: frozenset[str]` = `AUTH_ENV_KEYS | {MODEL_ENV_VAR}`; `cli.main` default-load passes `DOTENV_ALLOWED_KEYS`.

- [ ] **Step 1: Write the failing test**

Append to `tests/unit/test_config.py`:

```python
def test_dotenv_allowlist_includes_model_but_not_auth_keys_set() -> None:
    # AUTH_ENV_KEYS must remain exactly the provider's auth keys.
    assert "FLOSSWING_MODEL" not in cfg_mod.AUTH_ENV_KEYS
    # The dotenv allowlist is a superset that also permits the model key.
    assert "FLOSSWING_MODEL" in cfg_mod.DOTENV_ALLOWED_KEYS
    assert cfg_mod.AUTH_ENV_KEYS <= cfg_mod.DOTENV_ALLOWED_KEYS
    assert cfg_mod.MODEL_ENV_VAR in cfg_mod.DOTENV_ALLOWED_KEYS
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/tdang/projects/personal/FlossWing/.claude/worktrees/configurable-model-env && .venv/bin/python -m pytest tests/unit/test_config.py::test_dotenv_allowlist_includes_model_but_not_auth_keys_set -q`
Expected: FAIL with `AttributeError: module 'flosswing.config' has no attribute 'DOTENV_ALLOWED_KEYS'`.

- [ ] **Step 3: Add the allowlist constant**

In `flosswing/config.py`, immediately after the `AUTH_ENV_KEYS` definition (~line 77), add:

```python
# The default `.env` auto-load allowlist: auth keys plus FlossWing config keys
# the operator may set persistently. Kept separate from AUTH_ENV_KEYS so the
# latter stays exactly the provider's credential keys.
DOTENV_ALLOWED_KEYS: frozenset[str] = AUTH_ENV_KEYS | frozenset({MODEL_ENV_VAR})
```

- [ ] **Step 4: Wire cli.py to the new allowlist**

In `flosswing/cli.py`, in the default-load branch (~lines 88-91), change:
```python
        from flosswing.config import AUTH_ENV_KEYS
```
to:
```python
        from flosswing.config import DOTENV_ALLOWED_KEYS
```
and change:
```python
        loaded = envfile.load_env_file(Path(source), allowed_keys=AUTH_ENV_KEYS)
```
to:
```python
        loaded = envfile.load_env_file(Path(source), allowed_keys=DOTENV_ALLOWED_KEYS)
```

- [ ] **Step 5: Run the config test module + the cli-env test**

Run: `cd /home/tdang/projects/personal/FlossWing/.claude/worktrees/configurable-model-env && .venv/bin/python -m pytest tests/unit/test_config.py tests/unit/test_cli_env.py tests/unit/test_envfile.py -q`
Expected: PASS (new test passes; existing cli/env tests unaffected).

- [ ] **Step 6: Commit**

```bash
git add flosswing/config.py flosswing/cli.py tests/unit/test_config.py
git commit -m "Allow FLOSSWING_MODEL from the default .env auto-load

Per docs/superpowers/specs/2026-07-16-model-env-config-design.md.
New DOTENV_ALLOWED_KEYS = AUTH_ENV_KEYS | {FLOSSWING_MODEL}; cli default
load uses it. AUTH_ENV_KEYS value unchanged.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 3: Runtime rollout, Foundry verification, and full gate

**Files:**
- Modify: `/home/tdang/projects/personal/FlossWing/.env` (runtime file in the MAIN checkout — git-ignored, NOT in the worktree, NOT committed)
- No code files.

**Interfaces:** none (operational task).

- [ ] **Step 1: Run the full lint/type/test gate in the worktree**

Run:
```bash
cd /home/tdang/projects/personal/FlossWing/.claude/worktrees/configurable-model-env
.venv/bin/ruff check . && .venv/bin/mypy --strict flosswing && .venv/bin/python -m pytest tests/unit -q
```
Expected: ruff clean, mypy clean, unit suite green.

- [ ] **Step 2: Update the runtime `.env` in the main checkout**

Edit `/home/tdang/projects/personal/FlossWing/.env` (create the lines if absent, replace if present — do NOT touch the Foundry credential lines):
```
FLOSSWING_MODEL=claude-opus-4-8
ANTHROPIC_DEFAULT_OPUS_MODEL=claude-opus-4-8
ANTHROPIC_DEFAULT_SONNET_MODEL=claude-sonnet-5
ANTHROPIC_DEFAULT_HAIKU_MODEL=claude-haiku-4-5
```
Confirm `.env` is still git-ignored: `git -C /home/tdang/projects/personal/FlossWing check-ignore .env` prints `.env`.

- [ ] **Step 3: Verify `claude-opus-4-8` runs on Foundry for this workload**

Run (in the MAIN checkout so the project context loads, reproducing the scan's environment):
```bash
cd /home/tdang/projects/personal/FlossWing
set -a; source .env; set +a
claude -p "reply with the single word OK" --model claude-opus-4-8
```
Expected: `OK` (not a Usage-Policy block, not a model-not-found error). If it blocks or errors, STOP and report — the default may need to stay `claude-opus-4-7` or use a different Foundry deployment name.

- [ ] **Step 4: Propose (do NOT apply) the CLAUDE.md wording tweak**

`CLAUDE.md` line 37 says the default `.env` auto-load is "restricted to known credential/config keys (`config.AUTH_ENV_KEYS`)". Propose to the operator changing `config.AUTH_ENV_KEYS` → `config.DOTENV_ALLOWED_KEYS` (which is `AUTH_ENV_KEYS` plus `FLOSSWING_MODEL`). Present the one-line diff and wait for approval; do not edit CLAUDE.md in this plan.

- [ ] **Step 5: No commit (runtime `.env` is git-ignored; CLAUDE.md deferred)**

Nothing to commit for this task. Report gate results, the Foundry probe outcome, and the proposed CLAUDE.md diff.

---

## Self-Review

- **Spec coverage:** DEFAULT_MODEL bump (T1 S5), MODEL_ENV_VAR + precedence (T1 S5), DOTENV_ALLOWED_KEYS + cli wiring (T2), tests for precedence/default/allowlist (T1 S3, T2 S1), runtime `.env` (T3 S2), CLAUDE.md flagged-not-edited (T3 S4), security note is design-only, Foundry runtime gate (T3 S3). All spec sections mapped.
- **Placeholders:** none — every code step shows exact before/after.
- **Type consistency:** `MODEL_ENV_VAR` (str) and `DOTENV_ALLOWED_KEYS` (frozenset[str]) defined in T1/T2 and referenced consistently; `resolve()` signature unchanged.
