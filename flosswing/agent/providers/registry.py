# FlossWing — local-CLI vulnerability research harness.
# Copyright (C) 2026  FlossWing contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Provider registry: name -> Provider, with unimplemented stubs."""

from __future__ import annotations

from typing import Any

from flosswing.agent.providers.anthropic_sdk import AnthropicSDKProvider
from flosswing.agent.providers.base import Provider, SessionResult
from flosswing.agent.providers.ollama_native import OllamaProvider
from flosswing.errors import ProviderNotImplementedError, UnknownProviderError

_STUB_NAMES: tuple[str, ...] = ("openai", "bedrock", "cloudflare")


class UnimplementedProvider:
    """Registered placeholder for a backend not yet built.

    Selecting it is rejected early at config.resolve(); this class's
    run_session raise is a defense-in-depth backstop.
    """

    def __init__(self, name: str) -> None:
        self.name = name
        self.auth_env_keys: frozenset[str] = frozenset()

    def validate_auth(
        self, env: Any, *, model: str | None = None
    ) -> None:  # no-op by design
        del model
        return None

    async def run_session(self, **_kwargs: Any) -> SessionResult:
        raise ProviderNotImplementedError(
            f"{self.name} provider is not yet implemented; see ARCHITECTURE.md"
        )


_IMPLEMENTED: dict[str, Provider] = {
    "anthropic": AnthropicSDKProvider(),
    "ollama": OllamaProvider(),
}
_STUBS: dict[str, Provider] = {n: UnimplementedProvider(n) for n in _STUB_NAMES}
_REGISTRY: dict[str, Provider] = {**_IMPLEMENTED, **_STUBS}


def registered_names() -> tuple[str, ...]:
    return tuple(_REGISTRY)


def is_implemented(name: str) -> bool:
    return name in _IMPLEMENTED


def get_provider(name: str) -> Provider:
    try:
        return _REGISTRY[name]
    except KeyError:
        raise UnknownProviderError(
            f"Unknown provider {name!r}. Registered: "
            f"{', '.join(sorted(_REGISTRY))}."
        ) from None


def implemented_providers() -> tuple[Provider, ...]:
    """All providers with a working backend (not stubs).

    Used by config to build the .env auto-load allowlist (AUTH_ENV_KEYS)
    from the union of every implemented provider's declared auth keys.
    """
    return tuple(_IMPLEMENTED.values())
