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

"""Engine + session-scope helpers for the FlossWing state DB.

The DB lives at ~/.flosswing/state.db by default; FLOSSWING_DB_URL
overrides for tests and CI. On first use, if the DB file doesn't exist
yet (or the URL is :memory:), we run `alembic upgrade head` automatically
so first-run UX is "flosswing scan ./repo" and it Just Works. If the
file exists with stale schema we do not guess — the user is told to
run upgrade manually.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from alembic import command as alembic_command
from alembic.config import Config as AlembicConfig
from sqlalchemy import create_engine
from sqlalchemy.engine import Connection, Engine, make_url
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

# Ensure the connect listener (PRAGMA foreign_keys=ON) is registered.
import flosswing.state.db  # noqa: F401

# Re-exported for type hints elsewhere (e.g. flosswing.stages.index_build).
SessionFactory = sessionmaker[Session]

_DEFAULT_DB_PATH = Path.home() / ".flosswing" / "state.db"
_ALEMBIC_INI = Path(__file__).resolve().parents[2] / "alembic.ini"

_cached_engine: Engine | None = None
_cached_session_factory: sessionmaker[Session] | None = None


def _resolve_db_url() -> str:
    env = os.environ.get("FLOSSWING_DB_URL")
    if env:
        return env
    _DEFAULT_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{_DEFAULT_DB_PATH}"


def _alembic_cfg(db_url: str) -> AlembicConfig:
    cfg = AlembicConfig(str(_ALEMBIC_INI))
    cfg.set_main_option("sqlalchemy.url", db_url)
    return cfg


def _run_alembic_upgrade_via_connection(conn: Connection, db_url: str) -> None:
    """Run alembic upgrade head using an existing open connection.

    By injecting the connection via config.attributes["connection"], env.py
    skips creating its own engine. This is critical for in-memory (StaticPool)
    DBs where each new connection would otherwise open a blank DB.
    """
    cfg = _alembic_cfg(db_url)
    cfg.attributes["connection"] = conn
    alembic_command.upgrade(cfg, "head")


def engine() -> Engine:
    """Return the cached engine, creating + migrating on first call."""
    global _cached_engine, _cached_session_factory
    if _cached_engine is not None:
        return _cached_engine

    db_url = _resolve_db_url()
    parsed = make_url(db_url)

    # Auto-upgrade is safe in two cases:
    #   - in-memory DBs (always fresh)
    #   - SQLite file URLs that don't exist yet
    # Otherwise we leave the schema alone and let the user run upgrade.
    is_memory = parsed.database == ":memory:"
    needs_upgrade = False
    if is_memory:
        needs_upgrade = True
    elif parsed.drivername.startswith("sqlite"):
        db_path = parsed.database or ""
        if db_path and not Path(db_path).exists():
            needs_upgrade = True

    # In-memory SQLite: use StaticPool so every connection in this process
    # shares the single in-process DB. Without StaticPool, each connect()
    # opens a brand-new empty DB, and Alembic's DDL becomes invisible to
    # later application connections.
    if is_memory:
        _cached_engine = create_engine(
            db_url,
            future=True,
            poolclass=StaticPool,
            connect_args={"check_same_thread": False},
        )
    else:
        _cached_engine = create_engine(db_url, future=True)

    if needs_upgrade:
        with _cached_engine.begin() as conn:
            _run_alembic_upgrade_via_connection(conn, db_url)

    _cached_session_factory = sessionmaker(bind=_cached_engine, future=True)
    return _cached_engine


def session_factory() -> sessionmaker[Session]:
    """Return the cached session factory, initialising the engine if needed."""
    if _cached_session_factory is None:
        engine()
    if _cached_session_factory is None:
        raise RuntimeError(
            "engine() completed without initialising _cached_session_factory; "
            "this is a bug in flosswing.state.session"
        )
    return _cached_session_factory


@contextmanager
def session_scope() -> Iterator[Session]:
    """Transactional session: commits on success, rolls back on exception."""
    sess = session_factory()()
    try:
        yield sess
        sess.commit()
    except Exception:
        sess.rollback()
        raise
    finally:
        sess.close()
