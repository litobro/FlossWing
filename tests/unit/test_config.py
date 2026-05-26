"""Config resolution: model, token budget, auth-credential detection.

Three auth modes accepted (per design § Authentication):
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
    cfg = resolve(repo_root=tmp_path, model=None, token_budget=None)
    assert isinstance(cfg, Config)
    assert cfg.model == "claude-opus-4-7"
    assert cfg.token_budget == 200_000
    assert "ANTHROPIC_API_KEY" in cfg.auth_env
    assert "ANTHROPIC_FOUNDRY_API_KEY" not in cfg.auth_env


def test_resolves_with_foundry_api_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("ANTHROPIC_FOUNDRY_API_KEY", "foundry-test")
    cfg = resolve(repo_root=tmp_path, model=None, token_budget=None)
    assert "ANTHROPIC_FOUNDRY_API_KEY" in cfg.auth_env


def test_resolves_with_entra_id_env_vars(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_FOUNDRY_API_KEY", raising=False)
    monkeypatch.setenv("AZURE_CLIENT_ID", "cli")
    monkeypatch.setenv("AZURE_TENANT_ID", "ten")
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "sec")
    cfg = resolve(repo_root=tmp_path, model=None, token_budget=None)
    assert "AZURE_CLIENT_ID" in cfg.auth_env


def test_overrides_apply(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    cfg = resolve(repo_root=tmp_path, model="claude-sonnet-4-6", token_budget=42)
    assert cfg.model == "claude-sonnet-4-6"
    assert cfg.token_budget == 42


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
        resolve(repo_root=tmp_path, model=None, token_budget=None)
    msg = str(exc.value)
    assert "ANTHROPIC_API_KEY" in msg
    assert "ANTHROPIC_FOUNDRY_API_KEY" in msg
    assert "az login" in msg
