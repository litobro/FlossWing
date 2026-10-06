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

"""OpenAI Codex / Daybreak Blue backend.

Auth is the local ``codex login`` session (no env credential); ``run_session`` is
filled in by later tasks.
"""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Mapping
from typing import Any

from flosswing.agent.providers.base import OnUsage, SessionResult
from flosswing.errors import AuthCredentialMissingError

_MISSING_AUTH_MSG = (
    "No Codex login found. Install the Codex CLI and run `codex login` with a\n"
    "Daybreak-Blue-approved account (credentials live in ~/.codex, not the env)."
)


def _codex_installed() -> bool:
    return shutil.which("codex") is not None


def _codex_logged_in() -> bool:
    # EXACT subcommand confirmed in Task 0 Step 1; default guess `codex login status`.
    try:
        r = subprocess.run(
            ["codex", "login", "status"],
            check=False,
            capture_output=True,
            timeout=10,
        )
    except (subprocess.TimeoutExpired, OSError):
        return False
    return r.returncode == 0


class OpenAICodexProvider:
    name = "openai"
    auth_env_keys: frozenset[str] = frozenset()

    def validate_auth(self, env: Mapping[str, str]) -> None:
        if not (_codex_installed() and _codex_logged_in()):
            raise AuthCredentialMissingError(_MISSING_AUTH_MSG)

    async def run_session(
        self,
        *,
        model: str,
        system_prompt: str,
        tools: list[Any],
        user_prompt: str,
        token_budget: int,
        auth_env: dict[str, str],
        run_id: str,
        stage: str,
        task_id: str | None = None,
        finding_id: str | None = None,
        agent_session_id: str | None = None,
        on_usage: OnUsage | None = None,
    ) -> SessionResult:
        raise NotImplementedError("filled in by later tasks")
