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
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from flosswing.errors import AuthCredentialMissingError

DEFAULT_MODEL: str = "claude-opus-4-7"
DEFAULT_RECON_TOKEN_BUDGET: int = 200_000
DEFAULT_HUNT_TOKEN_BUDGET: int = 200_000
DEFAULT_VALIDATE_TOKEN_BUDGET: int = 100_000
DEFAULT_GAPFILL_TOKEN_BUDGET: int = 50_000
DEFAULT_DEDUPE_TOKEN_BUDGET: int = 50_000

# Direct Anthropic API: just the key.
_DIRECT_KEYS: tuple[str, ...] = ("ANTHROPIC_API_KEY",)

# Foundry routing: enables Foundry mode + names the resource the CLI hits.
_FOUNDRY_ROUTING_KEYS: tuple[str, ...] = (
    "CLAUDE_CODE_USE_FOUNDRY",
    "ANTHROPIC_FOUNDRY_RESOURCE",
)

# Foundry auth: one of these auth backends, OR an active az-login session.
_FOUNDRY_API_KEY: str = "ANTHROPIC_FOUNDRY_API_KEY"
_ENTRA_SP_KEYS: tuple[str, ...] = (
    "AZURE_CLIENT_ID",
    "AZURE_TENANT_ID",
    "AZURE_CLIENT_SECRET",
)

# Foundry deployment names per model role. Claude Code uses these to know
# which deployment to call when the agent asks for `claude-opus-X`, etc.
_FOUNDRY_MODEL_KEYS: tuple[str, ...] = (
    "ANTHROPIC_DEFAULT_OPUS_MODEL",
    "ANTHROPIC_DEFAULT_SONNET_MODEL",
    "ANTHROPIC_DEFAULT_HAIKU_MODEL",
)


@dataclass(frozen=True)
class Config:
    repo_root: Path
    model: str
    recon_token_budget: int
    hunt_token_budget: int
    validate_token_budget: int
    gapfill_token_budget: int
    auth_env: dict[str, str] = field(default_factory=dict)
    dedupe_token_budget: int = DEFAULT_DEDUPE_TOKEN_BUDGET


def _collect_present(keys: tuple[str, ...]) -> dict[str, str]:
    return {k: os.environ[k] for k in keys if k in os.environ}


def _has_az_session() -> bool:
    """Return True iff `az account show` succeeds (== plain az-login is active).

    Used as the third Foundry-auth path (after API key, after SP triple).
    Probed only when neither of those is set; the subprocess call is
    bounded by a 5-second timeout.
    """
    if shutil.which("az") is None:
        return False
    try:
        r = subprocess.run(
            ["az", "account", "show"],
            check=False,
            capture_output=True,
            timeout=5,
        )
    except (subprocess.TimeoutExpired, OSError):
        return False
    return r.returncode == 0


def resolve(
    *,
    repo_root: Path,
    model: str | None,
    recon_token_budget: int | None,
    hunt_token_budget: int | None,
    validate_token_budget: int | None,
    gapfill_token_budget: int | None,
    dedupe_token_budget: int | None = None,
) -> Config:
    """Build a Config from CLI flags + env. Raises if no auth path."""
    auth_env: dict[str, str] = {}
    auth_env.update(_collect_present(_DIRECT_KEYS))
    auth_env.update(_collect_present(_FOUNDRY_ROUTING_KEYS))
    if _FOUNDRY_API_KEY in os.environ:
        auth_env[_FOUNDRY_API_KEY] = os.environ[_FOUNDRY_API_KEY]
    auth_env.update(_collect_present(_ENTRA_SP_KEYS))
    auth_env.update(_collect_present(_FOUNDRY_MODEL_KEYS))

    has_direct = "ANTHROPIC_API_KEY" in auth_env

    foundry_routing_enabled = (
        auth_env.get("CLAUDE_CODE_USE_FOUNDRY") == "1"
        and "ANTHROPIC_FOUNDRY_RESOURCE" in auth_env
    )
    has_foundry_key = _FOUNDRY_API_KEY in auth_env
    has_entra_sp = all(k in auth_env for k in _ENTRA_SP_KEYS)
    # Only probe az session when no env-vars cover it (avoids a subprocess
    # call on the happy direct/Foundry-key paths).
    has_az_login = (
        foundry_routing_enabled
        and not has_foundry_key
        and not has_entra_sp
        and _has_az_session()
    )
    has_foundry = foundry_routing_enabled and (
        has_foundry_key or has_entra_sp or has_az_login
    )

    if not (has_direct or has_foundry):
        raise AuthCredentialMissingError(
            "No auth credential found. Set one of:\n"
            "  - ANTHROPIC_API_KEY (direct Anthropic API), OR\n"
            "  - Foundry routing: CLAUDE_CODE_USE_FOUNDRY=1 +\n"
            "    ANTHROPIC_FOUNDRY_RESOURCE=<name>, plus one of:\n"
            "      ANTHROPIC_FOUNDRY_API_KEY=<key>, OR\n"
            "      an active az-login session, OR\n"
            "      AZURE_CLIENT_ID + AZURE_TENANT_ID + AZURE_CLIENT_SECRET\n"
            "      (Entra ID service principal)."
        )

    return Config(
        repo_root=repo_root,
        model=model or DEFAULT_MODEL,
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
        dedupe_token_budget=(
            dedupe_token_budget
            if dedupe_token_budget is not None
            else DEFAULT_DEDUPE_TOKEN_BUDGET
        ),
    )
