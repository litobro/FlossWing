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

"""compile_and_run — the frozen-contract execution tool.

Per docs/tool-contracts.md § Scope: execution and
docs/specs/2026-06-02-v0.4-sandbox-design.md § Component responsibilities
tools/execution.py.

This wrapper validates the contract input, applies the env allowlist,
checks the per-attack-class network policy, generates a ULID
invocation_id, and delegates to whichever Sandbox `select_backend()`
returns. No DB writes — v0.4 logs to scratch dir on disk only (per
design decision #5).

The wrapper is the public entry; Hunt and Validate consume it in a
follow-on milestone. v0.4 leaves both stages untouched.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

from ulid import ULID

from flosswing import attack_classes
from flosswing.errors import (
    LanguageNotSupportedError,
    NetworkNotPermittedError,
    ResourceLimitExceededError,
)
from flosswing.sandbox import policy as sandbox_policy
from flosswing.sandbox.base import (
    CompileAndRunInput,
    CompileAndRunOutput,
    SandboxInvocation,
)
from flosswing.sandbox.select import select_backend

_VALID_LANGUAGES: Final[frozenset[str]] = frozenset(
    {"c", "cpp", "rust", "go", "python", "javascript", "typescript", "java"}
)

_ENV_ALLOWLIST: Final[frozenset[str]] = frozenset({
    "LANG",
    "LC_ALL",
    "PYTHONUNBUFFERED",
    "RUSTFLAGS",
    "CARGO_HOME",
    "GOFLAGS",
    "GOPATH",
    "NODE_OPTIONS",
})

_TIMEOUT_HARD_CAP_SECONDS: Final[int] = 300
_TIMEOUT_MIN_SECONDS: Final[int] = 1


def _filter_env(env: dict[str, str]) -> dict[str, str]:
    return {k: v for k, v in env.items() if k in _ENV_ALLOWLIST}


async def compile_and_run(
    inp: CompileAndRunInput,
    *,
    run_id: str,
    repo_root: Path,
) -> CompileAndRunOutput:
    """Build and execute attacker-supplied PoC code in a sandbox.

    See docs/tool-contracts.md § Scope: execution for the contract.
    """
    # Validate timeout.
    if (
        inp.timeout_seconds < _TIMEOUT_MIN_SECONDS
        or inp.timeout_seconds > _TIMEOUT_HARD_CAP_SECONDS
    ):
        raise ResourceLimitExceededError(
            f"timeout_seconds={inp.timeout_seconds} outside "
            f"{_TIMEOUT_MIN_SECONDS}..{_TIMEOUT_HARD_CAP_SECONDS}"
        )

    # Validate language (Pydantic catches this at construction, but a
    # model_construct bypass would slip through — defensive check).
    if inp.language not in _VALID_LANGUAGES:
        raise LanguageNotSupportedError(inp.language)

    # Validate attack_class exists in the registry.
    attack_classes.validate(inp.attack_class)

    # Validate network policy.
    pol = sandbox_policy.lookup(inp.attack_class)
    if inp.network and not pol.network_permitted:
        raise NetworkNotPermittedError(
            f"attack_class={inp.attack_class!r} does not permit network "
            "access (sandbox policy gate)"
        )

    invocation = SandboxInvocation(
        invocation_id=str(ULID()),
        run_id=run_id,
        attack_class=inp.attack_class,
        language=inp.language,
        files=inp.files,
        build_command=inp.build_command,
        run_command=inp.run_command,
        stdin=inp.stdin,
        args=inp.args,
        env=_filter_env(inp.env),
        timeout_seconds=inp.timeout_seconds,
        network=inp.network,
    )

    backend = await select_backend()
    return await backend.execute(invocation, repo_root=repo_root)


__all__ = ["CompileAndRunInput", "CompileAndRunOutput", "compile_and_run"]
