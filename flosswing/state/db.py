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

"""State store primitives: shared MetaData and SQLite connection setup.

The naming convention here MUST match the header of ``docs/schema.sql``.
Alembic batch mode cannot drop or alter anonymous constraints, and the
schema-drift CI check compares against the names in that header.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from sqlalchemy import MetaData, event
from sqlalchemy.engine import Engine
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.sql.schema import CheckConstraint, Table


def _ck_constraint_name(constraint: CheckConstraint, table: Table) -> str:
    """Idempotent ``%(constraint_name)s`` token for the ``ck`` naming convention.

    SQLAlchemy's ``ConventionDict.__getitem__`` checks the naming-convention dict
    before falling back to its built-in ``_key_constraint_name`` method, so
    placing a callable under the ``"constraint_name"`` key overrides the default
    token resolution for CHECK constraints.

    If the author already wrote the full ``ck_<table>_<suffix>`` name (the style
    used in migration 001), this strips the redundant ``ck_<table>_`` prefix
    before it is re-applied by the ``ck_%(table_name)s_%(constraint_name)s``
    template, preventing the ``ck_<table>_ck_<table>_<suffix>`` doubling.  A
    bare suffix (e.g. ``"nonneg"``) is returned unchanged so the template
    produces ``ck_<table>_nonneg`` as normal.  Both authoring styles are
    therefore idempotent.
    """
    name = constraint.name
    if not isinstance(name, str):
        raise InvalidRequestError(
            "Naming convention with %(constraint_name)s requires the "
            "CHECK constraint to be explicitly named."
        )
    raw = name
    prefix = f"ck_{table.name}_"
    # Defensive: mirror SQLAlchemy's _key_constraint_name side-effect. In practice
    # _constraint_name overwrites name with conv(...) unconditionally, so this isn't
    # load-bearing today, but omitting it would diverge from the built-in's contract
    # and could break under a future SQLAlchemy refactor.
    constraint.name = None
    return raw[len(prefix):] if raw.startswith(prefix) else raw


NAMING_CONVENTION: dict[str, str | Callable[[CheckConstraint, Table], str]] = {
    "ix": "ix_%(table_name)s_%(column_0_name)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "constraint_name": _ck_constraint_name,
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

metadata: MetaData = MetaData(naming_convention=NAMING_CONVENTION)  # type: ignore[arg-type]  # SQLAlchemy stubs type naming_convention as Mapping[str, str]; custom token callables are supported at runtime


# SQLite ships with FK enforcement off by default; we require it on for every
# connection (Alembic, app, tests). Non-SQLite drivers without a `cursor()` would
# error here, but FlossWing only targets SQLite.
@event.listens_for(Engine, "connect")
def _enable_sqlite_foreign_keys(dbapi_connection: Any, connection_record: Any) -> None:
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA foreign_keys=ON")
    finally:
        cursor.close()
