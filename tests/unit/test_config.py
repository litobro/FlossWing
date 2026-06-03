"""Config resolution: model, per-stage token budgets, auth detection.

Three auth modes accepted (per v0.2 § Authentication, unchanged in v0.3):
  A) ANTHROPIC_FOUNDRY_API_KEY (Foundry API key)
  B) az login session (Entra ID, signaled here by AZURE_* env vars)
  C) ANTHROPIC_API_KEY (direct Anthropic)
"""

from __future__ import annotations

from pathlib import Path

import pytest

from flosswing.config import Config, resolve
from flosswing.errors import AuthCredentialMissingError


def test_resolves_with_anthropic_api_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ANTHROPIC_FOUNDRY_API_KEY", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    cfg = resolve(
        repo_root=tmp_path,
        model=None,
        recon_token_budget=None,
        hunt_token_budget=None,
    )
    assert isinstance(cfg, Config)
    assert cfg.model == "claude-opus-4-7"
    assert cfg.recon_token_budget == 200_000
    assert cfg.hunt_token_budget == 200_000
    assert "ANTHROPIC_API_KEY" in cfg.auth_env


def test_resolves_with_foundry_api_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("ANTHROPIC_FOUNDRY_API_KEY", "foundry-test")
    cfg = resolve(
        repo_root=tmp_path,
        model=None,
        recon_token_budget=None,
        hunt_token_budget=None,
    )
    assert "ANTHROPIC_FOUNDRY_API_KEY" in cfg.auth_env


def test_resolves_with_entra_id_env_vars(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_FOUNDRY_API_KEY", raising=False)
    monkeypatch.setenv("AZURE_CLIENT_ID", "cli")
    monkeypatch.setenv("AZURE_TENANT_ID", "ten")
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "sec")
    cfg = resolve(
        repo_root=tmp_path,
        model=None,
        recon_token_budget=None,
        hunt_token_budget=None,
    )
    assert "AZURE_CLIENT_ID" in cfg.auth_env


def test_per_stage_budget_overrides_apply(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    cfg = resolve(
        repo_root=tmp_path,
        model="claude-sonnet-4-6",
        recon_token_budget=11_111,
        hunt_token_budget=22_222,
    )
    assert cfg.model == "claude-sonnet-4-6"
    assert cfg.recon_token_budget == 11_111
    assert cfg.hunt_token_budget == 22_222


def test_independent_budget_overrides(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """recon override does not affect hunt, and vice versa."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    cfg = resolve(
        repo_root=tmp_path,
        model=None,
        recon_token_budget=42,
        hunt_token_budget=None,
    )
    assert cfg.recon_token_budget == 42
    assert cfg.hunt_token_budget == 200_000

    cfg2 = resolve(
        repo_root=tmp_path,
        model=None,
        recon_token_budget=None,
        hunt_token_budget=99,
    )
    assert cfg2.recon_token_budget == 200_000
    assert cfg2.hunt_token_budget == 99


def test_missing_all_credentials_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for k in (
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_FOUNDRY_API_KEY",
        "AZURE_CLIENT_ID",
        "AZURE_TENANT_ID",
        "AZURE_CLIENT_SECRET",
    ):
        monkeypatch.delenv(k, raising=False)
    with pytest.raises(AuthCredentialMissingError) as exc:
        resolve(
            repo_root=tmp_path,
            model=None,
            recon_token_budget=None,
            hunt_token_budget=None,
        )
    msg = str(exc.value)
    assert "ANTHROPIC_API_KEY" in msg
    assert "ANTHROPIC_FOUNDRY_API_KEY" in msg
    assert "az login" in msg
