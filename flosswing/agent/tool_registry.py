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


"""SDK tool registration helper.

Tool definitions live in ``flosswing.agent.tool_descriptors`` (transport
neutral); this module adapts them to claude_agent_sdk @tool callables.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from flosswing.agent.tool_descriptors import build_recon_descriptors, to_sdk_tool


@dataclass
class RegistryContext:
    repo_root: Path
    run_id: str
    budget_total: int


def build_recon_tools(ctx: RegistryContext) -> list[Any]:
    """Build the 5 Recon-scoped tool callables for ClaudeAgentOptions."""
    return [
        to_sdk_tool(d)
        for d in build_recon_descriptors(
            repo_root=ctx.repo_root, run_id=ctx.run_id, budget_total=ctx.budget_total
        )
    ]
