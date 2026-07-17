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

"""CLI / env config resolution.

Auth modes (per v0.2 spec § Authentication, aligned with Microsoft Learn
"Configure Claude Code for Microsoft Foundry"):

  Foundry mode (routing):
    CLAUDE_CODE_USE_FOUNDRY=1 AND ANTHROPIC_FOUNDRY_RESOURCE=<name>
    plus one of:
      - ANTHROPIC_FOUNDRY_API_KEY  (API-key auth), OR
      - an active az-login session (Entra ID; Claude Code auto-detects), OR
      - AZURE_CLIENT_ID + AZURE_TENANT_ID + AZURE_CLIENT_SECRET
        (Entra ID service principal).
    Plus at least one of:
      - ANTHROPIC_DEFAULT_OPUS_MODEL
      - ANTHROPIC_DEFAULT_SONNET_MODEL
      - ANTHROPIC_DEFAULT_HAIKU_MODEL
    naming the Foundry deployment(s) Claude Code routes to.

  Direct mode:
    ANTHROPIC_API_KEY (direct Anthropic API; no Foundry routing).

Credential values are never logged or persisted. The full set of detected
auth/routing env vars is passed verbatim to ClaudeAgentOptions.env so the
spawned subprocess can route however the CLI decides.

v0.3 splits the single `token_budget` into per-stage budgets
(`recon_token_budget`, `hunt_token_budget`) per design decision #1. No
backward-compat alias for the old `token_budget` name.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from flosswing.agent.providers import registry
from flosswing.agent.providers.anthropic_sdk import AnthropicSDKProvider
from flosswing.errors import ProviderNotImplementedError

DEFAULT_MODEL: str = "claude-opus-4-8"

# Operator-settable default model (overridden by the --model flag). Loadable
# from a working-directory .env (see DOTENV_ALLOWED_KEYS).
MODEL_ENV_VAR: str = "FLOSSWING_MODEL"

DEFAULT_RECON_TOKEN_BUDGET: int = 200_000
DEFAULT_HUNT_TOKEN_BUDGET: int = 200_000
DEFAULT_VALIDATE_TOKEN_BUDGET: int = 100_000
DEFAULT_GAPFILL_TOKEN_BUDGET: int = 50_000
DEFAULT_DEDUPE_TOKEN_BUDGET: int = 50_000
DEFAULT_TRACE_TOKEN_BUDGET: int = 50_000
DEFAULT_TRACE_MAX_DEPTH: int = 8
DEFAULT_AUTO_RENDER: bool = True
DEFAULT_OUTPUT_FORMATS: tuple[str, ...] = ("md", "json")
DEFAULT_OUTPUT_DIR: Path | None = None

DEFAULT_PROVIDER: str = "anthropic"
PROVIDER_ENV_VAR: str = "FLOSSWING_PROVIDER"

# The default `.env` auto-load (flosswing/cli.py) is restricted to this
# allowlist. Derived from the Anthropic provider's declared keys so a future
# real provider extends it just by declaring auth_env_keys. FLOSSWING_PROVIDER
# is intentionally NOT here: provider selection is not a credential and must
# not be settable by an auto-loaded .env.
AUTH_ENV_KEYS: frozenset[str] = AnthropicSDKProvider.auth_env_keys


@dataclass(frozen=True)
class Config:
    repo_root: Path
    model: str
    recon_token_budget: int
    hunt_token_budget: int
    validate_token_budget: int
    gapfill_token_budget: int
    auth_env: dict[str, str] = field(default_factory=dict)
    provider: str = DEFAULT_PROVIDER
    dedupe_token_budget: int = DEFAULT_DEDUPE_TOKEN_BUDGET
    trace_token_budget: int = DEFAULT_TRACE_TOKEN_BUDGET
    trace_max_depth: int = DEFAULT_TRACE_MAX_DEPTH
    auto_render: bool = DEFAULT_AUTO_RENDER
    output_formats: list[str] = field(
        default_factory=lambda: list(DEFAULT_OUTPUT_FORMATS)
    )
    output_dir: Path | None = DEFAULT_OUTPUT_DIR


def resolve(
    *,
    repo_root: Path,
    model: str | None,
    recon_token_budget: int | None,
    hunt_token_budget: int | None,
    validate_token_budget: int | None,
    gapfill_token_budget: int | None,
    dedupe_token_budget: int | None = None,
    trace_token_budget: int | None = None,
    trace_max_depth: int | None = None,
    auto_render: bool | None = None,
    output_formats: list[str] | None = None,
    output_dir: Path | None = None,
    provider: str | None = None,
) -> Config:
    """Build a Config from CLI flags + env. Raises if no auth path."""
    provider_name = provider or os.environ.get(PROVIDER_ENV_VAR) or DEFAULT_PROVIDER
    prov = registry.get_provider(provider_name)  # UnknownProviderError if bogus
    if not registry.is_implemented(provider_name):
        raise ProviderNotImplementedError(
            f"{provider_name} provider is not yet implemented; see ARCHITECTURE.md"
        )
    prov.validate_auth(os.environ)  # AuthCredentialMissingError if no usable path
    auth_env: dict[str, str] = {
        k: os.environ[k] for k in prov.auth_env_keys if k in os.environ
    }

    return Config(
        repo_root=repo_root,
        model=model or os.environ.get(MODEL_ENV_VAR) or DEFAULT_MODEL,
        recon_token_budget=(
            recon_token_budget
            if recon_token_budget is not None
            else DEFAULT_RECON_TOKEN_BUDGET
        ),
        hunt_token_budget=(
            hunt_token_budget
            if hunt_token_budget is not None
            else DEFAULT_HUNT_TOKEN_BUDGET
        ),
        validate_token_budget=(
            validate_token_budget
            if validate_token_budget is not None
            else DEFAULT_VALIDATE_TOKEN_BUDGET
        ),
        gapfill_token_budget=(
            gapfill_token_budget
            if gapfill_token_budget is not None
            else DEFAULT_GAPFILL_TOKEN_BUDGET
        ),
        auth_env=auth_env,
        provider=provider_name,
        dedupe_token_budget=(
            dedupe_token_budget
            if dedupe_token_budget is not None
            else DEFAULT_DEDUPE_TOKEN_BUDGET
        ),
        trace_token_budget=(
            trace_token_budget
            if trace_token_budget is not None
            else DEFAULT_TRACE_TOKEN_BUDGET
        ),
        trace_max_depth=(
            trace_max_depth
            if trace_max_depth is not None
            else DEFAULT_TRACE_MAX_DEPTH
        ),
        auto_render=(
            auto_render if auto_render is not None else DEFAULT_AUTO_RENDER
        ),
        output_formats=(
            list(output_formats)
            if output_formats is not None
            else list(DEFAULT_OUTPUT_FORMATS)
        ),
        output_dir=(
            output_dir if output_dir is not None else DEFAULT_OUTPUT_DIR
        ),
    )
