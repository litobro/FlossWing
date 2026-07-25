"""state.session tests: engine creation, session_scope, FK pragma."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import text

from flosswing.state import db as st_db
from flosswing.state import session as st_session
from flosswing.state.models import Run


@pytest.fixture()
def fresh_memory_db(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Force a fresh in-memory SQLite engine per test."""
    monkeypatch.setenv("FLOSSWING_DB_URL", "sqlite:///:memory:")
    # The module caches the engine; reset for the test.
    st_session._cached_engine = None  # type: ignore[attr-defined]
    st_session._cached_session_factory = None  # type: ignore[attr-defined]
    yield
    st_session._cached_engine = None  # type: ignore[attr-defined]
    st_session._cached_session_factory = None  # type: ignore[attr-defined]


@pytest.fixture()
def fresh_file_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Force a fresh file-backed SQLite engine — WAL needs a real file."""
    monkeypatch.setenv("FLOSSWING_DB_URL", f"sqlite:///{tmp_path / 'state.db'}")
    st_session._cached_engine = None  # type: ignore[attr-defined]
    st_session._cached_session_factory = None  # type: ignore[attr-defined]
    yield
    st_session._cached_engine = None  # type: ignore[attr-defined]
    st_session._cached_session_factory = None  # type: ignore[attr-defined]


def test_engine_runs_migrations_on_fresh_db(fresh_memory_db: None) -> None:
    eng = st_session.engine()
    with eng.connect() as conn:
        names = {
            r[0]
            for r in conn.execute(
                text("SELECT name FROM sqlite_master WHERE type='table'")
            )
        }
    assert "runs" in names
    assert "agent_sessions" in names
    assert "findings" in names


def test_engine_enables_foreign_keys(fresh_memory_db: None) -> None:
    eng = st_session.engine()
    with eng.connect() as conn:
        assert conn.execute(text("PRAGMA foreign_keys")).scalar() == 1


def test_engine_sets_busy_timeout(fresh_memory_db: None) -> None:
    eng = st_session.engine()
    with eng.connect() as conn:
        got = conn.execute(text("PRAGMA busy_timeout")).scalar()
    assert got == st_db.SQLITE_BUSY_TIMEOUT_MS


def test_file_backed_engine_uses_wal(fresh_file_db: None) -> None:
    eng = st_session.engine()
    with eng.connect() as conn:
        assert conn.execute(text("PRAGMA journal_mode")).scalar() == "wal"


def test_reader_not_blocked_while_writer_holds_lock(fresh_file_db: None) -> None:
    """Regression: the TUI polls state.db while a scan holds write locks.

    Under the default rollback journal a writer's EXCLUSIVE lock blocks readers
    outright, and with SQLite's default busy_timeout of 0 the reader fails
    instantly with "database is locked" — which stopped the TUI's poll timer
    for good. Under WAL the reader proceeds against its own snapshot.
    """
    eng = st_session.engine()
    with eng.connect() as writer:
        writer.execute(text("BEGIN EXCLUSIVE"))
        try:
            with eng.connect() as reader:
                assert reader.execute(text("SELECT count(*) FROM runs")).scalar() == 0
        finally:
            writer.execute(text("ROLLBACK"))


def test_session_scope_commits_on_success(fresh_memory_db: None) -> None:
    with st_session.session_scope() as s:
        s.add(
            Run(
                id="01TEST0000000000000000RUN1",
                target_repo_path="/tmp/x",
                depth="standard",
                budget_total=20,
                started_at="2026-05-25T00:00:00Z",
                config_json="{}",
                flosswing_version="0.2.0",
            )
        )
    with st_session.session_scope() as s2:
        assert s2.query(Run).count() == 1


def test_session_scope_rolls_back_on_exception(fresh_memory_db: None) -> None:
    with pytest.raises(RuntimeError, match="boom"), st_session.session_scope() as s:
        s.add(
            Run(
                id="01TEST0000000000000000RUN2",
                target_repo_path="/tmp/x",
                depth="standard",
                budget_total=20,
                started_at="2026-05-25T00:00:00Z",
                config_json="{}",
                flosswing_version="0.2.0",
            )
        )
        raise RuntimeError("boom")

    with st_session.session_scope() as s2:
        assert s2.query(Run).count() == 0
