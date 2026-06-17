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

"""Shared pytest fixtures."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _disable_dotenv_autoload(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the suite hermetic: never auto-load a developer's real ``.env``.

    The CLI auto-loads ``.env`` for operator convenience; a developer's file may
    hold live credentials, which must not leak into the test process. Tests that
    specifically exercise the loader delete this guard and run in a temp dir.
    """
    monkeypatch.setenv("FLOSSWING_DISABLE_DOTENV", "1")
