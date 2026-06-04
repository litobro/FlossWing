"""Config resolution: model, per-stage token budgets, auth detection.

Auth modes (aligned with Microsoft Learn "Configure Claude Code for
Microsoft Foundry"):

  Direct: ANTHROPIC_API_KEY
  Foundry routing: CLAUDE_CODE_USE_FOUNDRY=1 + ANTHROPIC_FOUNDRY_RESOURCE,
    plus one of:
      ANTHROPIC_FOUNDRY_API_KEY (API-key auth), OR
      an active az-login session (Entra ID), OR
      AZURE_CLIENT_ID + AZURE_TENANT_ID + AZURE_CLIENT_SECRET (Entra SP)
"""

from __future__ import annotations

from pathlib import Path

import pytest

from flosswing import config as cfg_mod
from flosswing import config as fcfg
from flosswing.config import Config, resolve
from flosswing.errors import AuthCredentialMissingError

_ALL_AUTH_ENV: tuple[str, ...] = (
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_FOUNDRY_API_KEY",
    "CLAUDE_CODE_USE_FOUNDRY",
    "ANTHROPIC_FOUNDRY_RESOURCE",
    "AZURE_CLIENT_ID",
    "AZURE_TENANT_ID",
    "AZURE_CLIENT_SECRET",
    "ANTHROPIC_DEFAULT_OPUS_MODEL",
    "ANTHROPIC_DEFAULT_SONNET_MODEL",
    "ANTHROPIC_DEFAULT_HAIKU_MODEL",
)


def _strip_all_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    for k in _ALL_AUTH_ENV:
        monkeypatch.delenv(k, raising=False)
    # Block any az-login probe; tests opt back in by re-patching.
    monkeypatch.setattr(cfg_mod, "_has_az_session", lambda: False)


def test_resolves_with_anthropic_api_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _strip_all_auth(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    cfg = resolve(
        repo_root=tmp_path,
        model=None,
        recon_token_budget=None,
        hunt_token_budget=None,
        validate_token_budget=None,
        gapfill_token_budget=None,
    )
    assert isinstance(cfg, Config)
    assert cfg.model == "claude-opus-4-7"
    assert cfg.recon_token_budget == 200_000
    assert cfg.hunt_token_budget == 200_000
    assert "ANTHROPIC_API_KEY" in cfg.auth_env


def test_resolves_with_foundry_api_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _strip_all_auth(monkeypatch)
    monkeypatch.setenv("CLAUDE_CODE_USE_FOUNDRY", "1")
    monkeypatch.setenv("ANTHROPIC_FOUNDRY_RESOURCE", "test-resource")
    monkeypatch.setenv("ANTHROPIC_FOUNDRY_API_KEY", "foundry-test")
    monkeypatch.setenv("ANTHROPIC_DEFAULT_OPUS_MODEL", "claude-opus-4-8")
    cfg = resolve(
        repo_root=tmp_path,
        model=None,
        recon_token_budget=None,
        hunt_token_budget=None,
        validate_token_budget=None,
        gapfill_token_budget=None,
    )
    assert cfg.auth_env["CLAUDE_CODE_USE_FOUNDRY"] == "1"
    assert cfg.auth_env["ANTHROPIC_FOUNDRY_RESOURCE"] == "test-resource"
    assert cfg.auth_env["ANTHROPIC_FOUNDRY_API_KEY"] == "foundry-test"
    assert cfg.auth_env["ANTHROPIC_DEFAULT_OPUS_MODEL"] == "claude-opus-4-8"


def test_resolves_with_foundry_routing_and_az_login(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Plain az-login session (no key, no SP triple) is the third Foundry auth."""
    _strip_all_auth(monkeypatch)
    monkeypatch.setenv("CLAUDE_CODE_USE_FOUNDRY", "1")
    monkeypatch.setenv("ANTHROPIC_FOUNDRY_RESOURCE", "test-resource")
    monkeypatch.setattr(cfg_mod, "_has_az_session", lambda: True)
    cfg = resolve(
        repo_root=tmp_path,
        model=None,
        recon_token_budget=None,
        hunt_token_budget=None,
        validate_token_budget=None,
        gapfill_token_budget=None,
    )
    assert cfg.auth_env["ANTHROPIC_FOUNDRY_RESOURCE"] == "test-resource"
    # az-login is detected via probe; not stored in auth_env.
    assert "ANTHROPIC_FOUNDRY_API_KEY" not in cfg.auth_env


def test_resolves_with_foundry_routing_and_entra_sp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _strip_all_auth(monkeypatch)
    monkeypatch.setenv("CLAUDE_CODE_USE_FOUNDRY", "1")
    monkeypatch.setenv("ANTHROPIC_FOUNDRY_RESOURCE", "test-resource")
    monkeypatch.setenv("AZURE_CLIENT_ID", "cli")
    monkeypatch.setenv("AZURE_TENANT_ID", "ten")
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "sec")
    cfg = resolve(
        repo_root=tmp_path,
        model=None,
        recon_token_budget=None,
        hunt_token_budget=None,
        validate_token_budget=None,
        gapfill_token_budget=None,
    )
    assert "AZURE_CLIENT_ID" in cfg.auth_env
    assert "AZURE_TENANT_ID" in cfg.auth_env
    assert "AZURE_CLIENT_SECRET" in cfg.auth_env


def test_foundry_key_without_routing_does_not_authenticate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A Foundry API key alone (no CLAUDE_CODE_USE_FOUNDRY=1) is rejected."""
    _strip_all_auth(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_FOUNDRY_API_KEY", "foundry-test")
    with pytest.raises(AuthCredentialMissingError):
        resolve(
            repo_root=tmp_path,
            model=None,
            recon_token_budget=None,
            hunt_token_budget=None,
            validate_token_budget=None,
            gapfill_token_budget=None,
        )


def test_per_stage_budget_overrides_apply(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _strip_all_auth(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    cfg = resolve(
        repo_root=tmp_path,
        model="claude-sonnet-4-6",
        recon_token_budget=11_111,
        hunt_token_budget=22_222,
        validate_token_budget=None,
        gapfill_token_budget=None,
    )
    assert cfg.model == "claude-sonnet-4-6"
    assert cfg.recon_token_budget == 11_111
    assert cfg.hunt_token_budget == 22_222


def test_independent_budget_overrides(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _strip_all_auth(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    cfg = resolve(
        repo_root=tmp_path,
        model=None,
        recon_token_budget=42,
        hunt_token_budget=None,
        validate_token_budget=None,
        gapfill_token_budget=None,
    )
    assert cfg.recon_token_budget == 42
    assert cfg.hunt_token_budget == 200_000

    cfg2 = resolve(
        repo_root=tmp_path,
        model=None,
        recon_token_budget=None,
        hunt_token_budget=99,
        validate_token_budget=None,
        gapfill_token_budget=None,
    )
    assert cfg2.recon_token_budget == 200_000
    assert cfg2.hunt_token_budget == 99


def test_missing_all_credentials_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _strip_all_auth(monkeypatch)
    with pytest.raises(AuthCredentialMissingError) as exc:
        resolve(
            repo_root=tmp_path,
            model=None,
            recon_token_budget=None,
            hunt_token_budget=None,
            validate_token_budget=None,
            gapfill_token_budget=None,
        )
    msg = str(exc.value)
    assert "ANTHROPIC_API_KEY" in msg
    assert "CLAUDE_CODE_USE_FOUNDRY" in msg
    assert "az-login" in msg or "az login" in msg


def test_foundry_model_deployments_forwarded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """All three ANTHROPIC_DEFAULT_*_MODEL vars get forwarded to auth_env."""
    _strip_all_auth(monkeypatch)
    monkeypatch.setenv("CLAUDE_CODE_USE_FOUNDRY", "1")
    monkeypatch.setenv("ANTHROPIC_FOUNDRY_RESOURCE", "test-resource")
    monkeypatch.setenv("ANTHROPIC_FOUNDRY_API_KEY", "k")
    monkeypatch.setenv("ANTHROPIC_DEFAULT_OPUS_MODEL", "claude-opus-4-8")
    monkeypatch.setenv("ANTHROPIC_DEFAULT_SONNET_MODEL", "claude-sonnet-4-6")
    monkeypatch.setenv("ANTHROPIC_DEFAULT_HAIKU_MODEL", "claude-haiku-4-5")
    cfg = resolve(
        repo_root=tmp_path,
        model=None,
        recon_token_budget=None,
        hunt_token_budget=None,
        validate_token_budget=None,
        gapfill_token_budget=None,
    )
    assert cfg.auth_env["ANTHROPIC_DEFAULT_OPUS_MODEL"] == "claude-opus-4-8"
    assert cfg.auth_env["ANTHROPIC_DEFAULT_SONNET_MODEL"] == "claude-sonnet-4-6"
    assert cfg.auth_env["ANTHROPIC_DEFAULT_HAIKU_MODEL"] == "claude-haiku-4-5"


def test_resolve_uses_default_validate_token_budget_when_not_passed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "x")
    cfg = fcfg.resolve(
        repo_root=Path("/tmp/x"),
        model=None,
        recon_token_budget=None,
        hunt_token_budget=None,
        validate_token_budget=None,
        gapfill_token_budget=None,
    )
    assert cfg.validate_token_budget == 100_000
    assert cfg.validate_token_budget == fcfg.DEFAULT_VALIDATE_TOKEN_BUDGET


def test_resolve_uses_cli_validate_token_budget_when_passed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "x")
    cfg = fcfg.resolve(
        repo_root=Path("/tmp/x"),
        model=None,
        recon_token_budget=None,
        hunt_token_budget=None,
        validate_token_budget=42_000,
        gapfill_token_budget=None,
    )
    assert cfg.validate_token_budget == 42_000


def test_resolve_uses_default_gapfill_token_budget_when_not_passed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "x")
    cfg = fcfg.resolve(
        repo_root=Path("/tmp/x"),
        model=None,
        recon_token_budget=None,
        hunt_token_budget=None,
        validate_token_budget=None,
        gapfill_token_budget=None,
    )
    assert cfg.gapfill_token_budget == 50_000
    assert cfg.gapfill_token_budget == fcfg.DEFAULT_GAPFILL_TOKEN_BUDGET


def test_resolve_uses_cli_gapfill_token_budget_when_passed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "x")
    cfg = fcfg.resolve(
        repo_root=Path("/tmp/x"),
        model=None,
        recon_token_budget=None,
        hunt_token_budget=None,
        validate_token_budget=None,
        gapfill_token_budget=12_345,
    )
    assert cfg.gapfill_token_budget == 12_345


def test_resolve_uses_default_dedupe_token_budget_when_not_passed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "x")
    cfg = fcfg.resolve(
        repo_root=Path("/tmp/x"),
        model=None,
        recon_token_budget=None,
        hunt_token_budget=None,
        validate_token_budget=None,
        gapfill_token_budget=None,
        dedupe_token_budget=None,
    )
    assert cfg.dedupe_token_budget == 50_000
    assert cfg.dedupe_token_budget == fcfg.DEFAULT_DEDUPE_TOKEN_BUDGET


def test_resolve_uses_cli_dedupe_token_budget_when_passed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "x")
    cfg = fcfg.resolve(
        repo_root=Path("/tmp/x"),
        model=None,
        recon_token_budget=None,
        hunt_token_budget=None,
        validate_token_budget=None,
        gapfill_token_budget=None,
        dedupe_token_budget=33_333,
    )
    assert cfg.dedupe_token_budget == 33_333


def test_resolve_uses_default_trace_token_budget_when_not_passed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "x")
    cfg = fcfg.resolve(
        repo_root=Path("/tmp/x"),
        model=None,
        recon_token_budget=None,
        hunt_token_budget=None,
        validate_token_budget=None,
        gapfill_token_budget=None,
        dedupe_token_budget=None,
        trace_token_budget=None,
    )
    assert cfg.trace_token_budget == 50_000
    assert cfg.trace_token_budget == fcfg.DEFAULT_TRACE_TOKEN_BUDGET


def test_resolve_uses_cli_trace_token_budget_when_passed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "x")
    cfg = fcfg.resolve(
        repo_root=Path("/tmp/x"),
        model=None,
        recon_token_budget=None,
        hunt_token_budget=None,
        validate_token_budget=None,
        gapfill_token_budget=None,
        dedupe_token_budget=None,
        trace_token_budget=27_777,
    )
    assert cfg.trace_token_budget == 27_777


def test_resolve_uses_default_trace_max_depth_when_not_passed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "x")
    cfg = fcfg.resolve(
        repo_root=Path("/tmp/x"),
        model=None,
        recon_token_budget=None,
        hunt_token_budget=None,
        validate_token_budget=None,
        gapfill_token_budget=None,
        dedupe_token_budget=None,
        trace_max_depth=None,
    )
    assert cfg.trace_max_depth == 8
    assert cfg.trace_max_depth == fcfg.DEFAULT_TRACE_MAX_DEPTH


def test_resolve_uses_cli_trace_max_depth_when_passed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "x")
    cfg = fcfg.resolve(
        repo_root=Path("/tmp/x"),
        model=None,
        recon_token_budget=None,
        hunt_token_budget=None,
        validate_token_budget=None,
        gapfill_token_budget=None,
        dedupe_token_budget=None,
        trace_max_depth=12,
    )
    assert cfg.trace_max_depth == 12
