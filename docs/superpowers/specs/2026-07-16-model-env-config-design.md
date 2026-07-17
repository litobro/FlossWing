# Env-configurable model selection

**Date:** 2026-07-16
**Status:** Approved (design)

## Problem

`flosswing/config.py` hardcodes `DEFAULT_MODEL = "claude-opus-4-7"`. The only way
to change the model per run is the `--model` CLI flag; there is no way to set a
persistent default via configuration. The default is also stale (Opus 4.7).

This surfaced while running a scan on an operator whose `.env` remaps the SDK
alias `opus → claude-fable-5`. That remap does **not** affect FlossWing (it passes
the concrete `DEFAULT_MODEL` string, never the alias), so the scan silently ran
Opus 4.7. Separately, Fable 5's dual-use cyber safety measures hard-block
vulnerability-research requests at the Usage-Policy level, so Fable is not a
viable model for this tool regardless — an Opus-tier model is required.

## Goal

Let the operator set FlossWing's model from `.env` (persistent, no flag), keep the
CLI flag as the highest-precedence override, and bump the built-in default to
`claude-opus-4-8`.

## Design

Single model for all stages (unchanged — `cfg.model`). Add one env var and a
three-tier resolution.

### `flosswing/config.py`

- `DEFAULT_MODEL`: `"claude-opus-4-7"` → `"claude-opus-4-8"`.
- New constant `MODEL_ENV_VAR: str = "FLOSSWING_MODEL"`.
- `resolve()` model line changes from `model=model or DEFAULT_MODEL` to:
  `model = model or os.environ.get(MODEL_ENV_VAR) or DEFAULT_MODEL`
  (precedence: `--model` flag > `FLOSSWING_MODEL` env > `DEFAULT_MODEL`).
- New `DOTENV_ALLOWED_KEYS: frozenset[str] = AUTH_ENV_KEYS | frozenset({MODEL_ENV_VAR})`.
  Keeps `AUTH_ENV_KEYS` meaning "auth credentials" (a provider attribute) while
  giving the `.env` auto-loader a superset that also permits the model config key.

### `flosswing/cli.py`

- The default `.env` auto-load (currently `allowed_keys=AUTH_ENV_KEYS`) passes
  `DOTENV_ALLOWED_KEYS` instead, so `FLOSSWING_MODEL` is loadable from a
  working-directory `.env`. `--env-file PATH` (load-everything) and `--no-env-file`
  paths are unchanged.

### `.env` (runtime, git-ignored, not committed)

```
FLOSSWING_MODEL=claude-opus-4-8
ANTHROPIC_DEFAULT_OPUS_MODEL=claude-opus-4-8
ANTHROPIC_DEFAULT_SONNET_MODEL=claude-sonnet-5
ANTHROPIC_DEFAULT_HAIKU_MODEL=claude-haiku-4-5
```

The `ANTHROPIC_DEFAULT_*` lines are SDK alias mappings (general Claude Code
config); only `FLOSSWING_MODEL` drives the scan. They are set together so the
operator's environment is coherent and the broken `opus → claude-fable-5` remap
is corrected.

## Testing

Unit tests (`tests/unit/`, SDK not involved):

- `resolve()` precedence: `--model` wins over `FLOSSWING_MODEL`; `FLOSSWING_MODEL`
  wins over the default; default applies when neither is set.
- Default value is `claude-opus-4-8`.
- `envfile.load_env_file` with `DOTENV_ALLOWED_KEYS` loads `FLOSSWING_MODEL` and
  still rejects an unknown key.

## Docs impact

`CLAUDE.md` line 37 names `config.AUTH_ENV_KEYS` as the dotenv allowlist. After
this change the allowlist is `DOTENV_ALLOWED_KEYS`. CLAUDE.md is operator-curated,
so the wording tweak is proposed separately for explicit approval, not changed as
part of the implementation.

## Security

Adding `FLOSSWING_MODEL` to the dotenv allowlist means a `.env` in the working
directory can set the scan model. This is benign and bounded — a model-name
string, not arbitrary env injection — and it is the operator's own working-dir
file, never the untrusted target repo (whose contents are never auto-loaded).
Consistent with the existing threat model; credentials remain the only sensitive
values and are unaffected.

## Out of scope (YAGNI)

- Per-stage model selection (FlossWing is single-model by design).
- Adding `FLOSSWING_PROVIDER` to the dotenv allowlist (separate knob; not requested).
- Editing CLAUDE.md (proposed separately).

## Runtime prerequisite

Before relaunching any scan on the new default, confirm `claude-opus-4-8` resolves
and runs on the operator's Foundry deployment for this workload (a trivial
`claude -p` probe in the project context). Not a code concern, but a gate before
declaring the model switch usable.
