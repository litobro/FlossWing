"""SQLAlchemy models for symbols / call_sites / entry_points.

Per docs/specs/2026-06-02-v0.5-symbol-index-design.md § SQLAlchemy models.
The three tables already exist in the DB (created by 001_initial); v0.5
adds models without a schema migration. These tests confirm the model
columns line up with docs/schema.sql.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from ulid import ULID

from flosswing.state import session as st_session
from flosswing.state.models import (
    CallSite,
    EntryPoint,
    ReconArtifact,
    Run,
    Symbol,
)


@pytest.fixture()
def isolated_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("FLOSSWING_DB_URL", f"sqlite:///{tmp_path}/state.db")
    monkeypatch.setattr(st_session, "_cached_engine", None, raising=False)
    monkeypatch.setattr(
        st_session, "_cached_session_factory", None, raising=False
    )
    return tmp_path


def _make_run() -> str:
    run_id = str(ULID())
    with st_session.session_scope() as s:
        s.add(
            Run(
                id=run_id,
                target_repo_path="/tmp/fake",
                target_repo_sha=None,
                depth="standard",
                budget_total=20,
                budget_used=0,
                started_at="2026-06-02T00:00:00Z",
                status="running",
                config_json="{}",
                flosswing_version="0.5.0",
            )
        )
    return run_id


def _make_recon_artifact(run_id: str) -> str:
    artifact_id = str(ULID())
    with st_session.session_scope() as s:
        s.add(
            ReconArtifact(
                id=artifact_id,
                run_id=run_id,
                languages_json="[]",
                build_commands_json="[]",
                trust_boundaries_json="[]",
                subsystems_json="[]",
                notes="",
                recorded_at="2026-06-02T00:00:00Z",
            )
        )
    return artifact_id


def test_symbol_model_round_trip(isolated_db: Path) -> None:
    run_id = _make_run()
    sid = str(ULID())
    with st_session.session_scope() as s:
        s.add(
            Symbol(
                id=sid,
                run_id=run_id,
                symbol="greet",
                fully_qualified_name="src.example.cli.greet",
                file="src/example/cli.py",
                line_start=10,
                line_end=12,
                kind="function",
                language="python",
            )
        )
    with st_session.session_scope() as s:
        row = s.get(Symbol, sid)
        assert row is not None
        assert row.symbol == "greet"
        assert row.kind == "function"
        assert row.language == "python"
        assert row.line_start == 10
        assert row.line_end == 12


def test_call_site_model_round_trip(isolated_db: Path) -> None:
    run_id = _make_run()
    caller_id = str(ULID())
    callee_id = str(ULID())
    with st_session.session_scope() as s:
        s.add_all([
            Symbol(
                id=caller_id, run_id=run_id, symbol="main",
                fully_qualified_name="src.example.cli.main",
                file="src/example/cli.py", line_start=15, line_end=20,
                kind="function", language="python",
            ),
            Symbol(
                id=callee_id, run_id=run_id, symbol="greet",
                fully_qualified_name="src.example.cli.greet",
                file="src/example/cli.py", line_start=10, line_end=12,
                kind="function", language="python",
            ),
        ])
    cs_id = str(ULID())
    with st_session.session_scope() as s:
        s.add(
            CallSite(
                id=cs_id,
                run_id=run_id,
                caller_symbol_id=caller_id,
                callee_symbol_id=callee_id,
                callee_text="greet",
                file="src/example/cli.py",
                line=19,
                snippet="    greet(sys.argv[1])",
            )
        )
    with st_session.session_scope() as s:
        row = s.get(CallSite, cs_id)
        assert row is not None
        assert row.caller_symbol_id == caller_id
        assert row.callee_symbol_id == callee_id
        assert row.callee_text == "greet"


def test_call_site_model_allows_null_callee(isolated_db: Path) -> None:
    """callee_symbol_id is nullable per docs/schema.sql line 231."""
    run_id = _make_run()
    caller_id = str(ULID())
    with st_session.session_scope() as s:
        s.add(
            Symbol(
                id=caller_id, run_id=run_id, symbol="main",
                fully_qualified_name="src.example.cli.main",
                file="src/example/cli.py", line_start=15, line_end=20,
                kind="function", language="python",
            )
        )
    cs_id = str(ULID())
    with st_session.session_scope() as s:
        s.add(
            CallSite(
                id=cs_id,
                run_id=run_id,
                caller_symbol_id=caller_id,
                callee_symbol_id=None,
                callee_text="external_lib.do_thing",
                file="src/example/cli.py",
                line=18,
                snippet="    external_lib.do_thing()",
            )
        )
    with st_session.session_scope() as s:
        row = s.get(CallSite, cs_id)
        assert row is not None
        assert row.callee_symbol_id is None


def test_entry_point_model_round_trip(isolated_db: Path) -> None:
    run_id = _make_run()
    artifact_id = _make_recon_artifact(run_id)
    ep_id = str(ULID())
    with st_session.session_scope() as s:
        s.add(
            EntryPoint(
                id=ep_id,
                recon_artifact_id=artifact_id,
                run_id=run_id,
                symbol="main",
                file="src/example/cli.py",
                line=15,
                kind="cli",
                attacker_controlled_input=1,
                notes="sys.argv parsed in main",
            )
        )
    with st_session.session_scope() as s:
        row = s.get(EntryPoint, ep_id)
        assert row is not None
        assert row.kind == "cli"
        assert row.attacker_controlled_input == 1
        assert row.notes == "sys.argv parsed in main"


def test_symbol_kind_constraint_enforced_by_db(isolated_db: Path) -> None:
    """ck_symbols_kind is DB-side; invalid kind raises IntegrityError."""
    from sqlalchemy.exc import IntegrityError

    run_id = _make_run()
    sid = str(ULID())
    with (
        pytest.raises(IntegrityError),
        st_session.session_scope() as s,
    ):
        s.add(
            Symbol(
                id=sid, run_id=run_id, symbol="x",
                fully_qualified_name="x", file="x.py",
                line_start=1, line_end=1,
                kind="not_a_real_kind",   # violates ck_symbols_kind
                language="python",
            )
        )


def test_entry_point_attacker_controlled_input_constraint(isolated_db: Path) -> None:
    from sqlalchemy.exc import IntegrityError

    run_id = _make_run()
    artifact_id = _make_recon_artifact(run_id)
    ep_id = str(ULID())
    with (
        pytest.raises(IntegrityError),
        st_session.session_scope() as s,
    ):
        s.add(
            EntryPoint(
                id=ep_id, recon_artifact_id=artifact_id, run_id=run_id,
                symbol="x", file="x.py", line=1, kind="cli",
                attacker_controlled_input=2,   # not 0 or 1
                notes="",
            )
        )
