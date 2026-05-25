"""State store primitives: shared MetaData and SQLite connection setup.

The naming convention here MUST match the header of ``docs/schema.sql``.
Alembic batch mode cannot drop or alter anonymous constraints, and the
schema-drift CI check compares against the names in that header.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import MetaData, event
from sqlalchemy.engine import Engine

NAMING_CONVENTION: dict[str, str] = {
    "ix": "ix_%(table_name)s_%(column_0_name)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

metadata: MetaData = MetaData(naming_convention=NAMING_CONVENTION)


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
