"""CLI / env config resolution for v0.2.

Accepts any one of three auth modes (see
docs/specs/2026-05-25-v0.2-recon-plumbing-design.md § Authentication):
  A) ANTHROPIC_FOUNDRY_API_KEY (Foundry API key)
  B) az login session (Entra ID; signaled here by AZURE_* env vars)
  C) ANTHROPIC_API_KEY (direct Anthropic)

Credential values are never logged or persisted. The full set of
detected auth env vars is passed verbatim to ClaudeAgentOptions.env
so the spawned subprocess can route however the CLI decides.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from flosswing.errors import AuthCredentialMissingError

DEFAULT_MODEL: str = "claude-opus-4-7"
DEFAULT_TOKEN_BUDGET: int = 200_000

_DIRECT_KEYS: tuple[str, ...] = ("ANTHROPIC_API_KEY",)
_FOUNDRY_API_KEYS: tuple[str, ...] = (
    "ANTHROPIC_FOUNDRY_API_KEY",
    "ANTHROPIC_FOUNDRY_RESOURCE",  # resource subdomain; may or may not be set
)
_ENTRA_KEYS: tuple[str, ...] = (
    "AZURE_CLIENT_ID",
    "AZURE_TENANT_ID",
    "AZURE_CLIENT_SECRET",
)


@dataclass(frozen=True)
class Config:
    repo_root: Path
    model: str
    token_budget: int
    auth_env: dict[str, str] = field(default_factory=dict)


def _collect_present(keys: tuple[str, ...]) -> dict[str, str]:
    return {k: os.environ[k] for k in keys if k in os.environ}


def resolve(
    *,
    repo_root: Path,
    model: str | None,
    token_budget: int | None,
) -> Config:
    """Build a Config from CLI flags + env. Raises if no auth path."""
    auth_env: dict[str, str] = {}
    auth_env.update(_collect_present(_DIRECT_KEYS))
    auth_env.update(_collect_present(_FOUNDRY_API_KEYS))
    auth_env.update(_collect_present(_ENTRA_KEYS))

    has_direct = "ANTHROPIC_API_KEY" in auth_env
    has_foundry_key = "ANTHROPIC_FOUNDRY_API_KEY" in auth_env
    has_entra = all(k in auth_env for k in _ENTRA_KEYS)

    if not (has_direct or has_foundry_key or has_entra):
        raise AuthCredentialMissingError(
            "No auth credential found. Set one of:\n"
            "  - ANTHROPIC_API_KEY (direct Anthropic API)\n"
            "  - ANTHROPIC_FOUNDRY_API_KEY (Azure AI Foundry API key)\n"
            "  - az login + AZURE_CLIENT_ID/AZURE_TENANT_ID/"
            "AZURE_CLIENT_SECRET (Entra ID service principal)"
        )

    return Config(
        repo_root=repo_root,
        model=model or DEFAULT_MODEL,
        token_budget=token_budget if token_budget is not None else DEFAULT_TOKEN_BUDGET,
        auth_env=auth_env,
    )
