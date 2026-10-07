from __future__ import annotations

import pytest

from flosswing.agent.providers import openai_codex as oc
from flosswing.errors import AuthCredentialMissingError


def test_name_and_no_env_keys() -> None:
    p = oc.OpenAICodexProvider()
    assert p.name == "openai"
    assert p.auth_env_keys == frozenset()


def test_validate_auth_rejects_when_not_logged_in(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(oc, "_codex_installed", lambda: True)
    monkeypatch.setattr(oc, "_codex_logged_in", lambda: False)
    with pytest.raises(AuthCredentialMissingError):
        oc.OpenAICodexProvider().validate_auth({})


def test_validate_auth_accepts_when_logged_in(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(oc, "_codex_installed", lambda: True)
    monkeypatch.setattr(oc, "_codex_logged_in", lambda: True)
    oc.OpenAICodexProvider().validate_auth({})  # no raise
