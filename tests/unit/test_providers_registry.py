"""providers.registry: lookup, implemented-flag, stub behavior."""

from __future__ import annotations

import asyncio

import pytest

from flosswing.agent.providers import registry as reg
from flosswing.agent.providers.anthropic_sdk import AnthropicSDKProvider
from flosswing.errors import ProviderNotImplementedError, UnknownProviderError


def test_anthropic_is_implemented_and_returned() -> None:
    assert reg.is_implemented("anthropic") is True
    assert isinstance(reg.get_provider("anthropic"), AnthropicSDKProvider)


@pytest.mark.parametrize("name", ["openai", "bedrock", "cloudflare"])
def test_stubs_registered_but_not_implemented(name: str) -> None:
    assert name in reg.registered_names()
    assert reg.is_implemented(name) is False
    prov = reg.get_provider(name)
    assert prov.name == name


def test_unknown_provider_raises_listing_names() -> None:
    with pytest.raises(UnknownProviderError) as ei:
        reg.get_provider("gpt5")
    assert "anthropic" in ei.value.message


def test_stub_run_session_raises() -> None:
    prov = reg.get_provider("openai")
    with pytest.raises(ProviderNotImplementedError):
        asyncio.run(
            prov.run_session(
                model="x", system_prompt="s", tools=[], user_prompt="u",
                token_budget=1, auth_env={}, run_id="r", stage="hunt",
            )
        )


def test_ollama_is_implemented() -> None:
    from flosswing.agent.providers.ollama_native import OllamaProvider

    assert reg.is_implemented("ollama") is True
    assert isinstance(reg.get_provider("ollama"), OllamaProvider)


def test_implemented_providers_includes_anthropic_and_ollama() -> None:
    names = {p.name for p in reg.implemented_providers()}
    assert {"anthropic", "ollama"} <= names
