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

"""Read-only query layer for the FlossWing TUI.

This is the ONLY TUI module that touches SQLAlchemy. Every function opens a
read session, snapshots rows into frozen dataclasses before the scope
closes, and returns those dataclasses. No ORM entity escapes this module.

Display text is shown as-is: finding/title/description text is already
credential-scrubbed by the upstream stage that wrote it (see
flosswing.stages.report module docstring). Only error/stderr text elsewhere
in the TUI is run through flosswing.errors.scrub.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import func, select

from flosswing.state import session as st_session
from flosswing.state.models import Finding, Run


def _short_id(run_id: str) -> str:
    """Last 8 chars of a ULID — enough to disambiguate in a list."""
    return run_id[-8:] if len(run_id) > 8 else run_id


@dataclass(frozen=True)
class RunRow:
    id: str
    short_id: str
    target_repo_path: str
    status: str
    started_at: str
    finished_at: str | None
    findings_count: int


def list_runs() -> list[RunRow]:
    """All runs, newest started_at first, with finding counts."""
    with st_session.session_scope() as s:
        counts: dict[str, int] = dict(
            s.execute(
                select(Finding.run_id, func.count(Finding.id)).group_by(Finding.run_id)
            ).all()  # type: ignore[arg-type]  # SA Row tuples satisfy Iterable[tuple[str, int]]
        )
        runs = (
            s.execute(select(Run).order_by(Run.started_at.desc()))
            .scalars()
            .all()
        )
        return [
            RunRow(
                id=r.id,
                short_id=_short_id(r.id),
                target_repo_path=r.target_repo_path,
                status=r.status,
                started_at=r.started_at,
                finished_at=r.finished_at,
                findings_count=int(counts.get(r.id, 0)),
            )
            for r in runs
        ]
