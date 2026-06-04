"""SQLAlchemy model for the validations table + extended Finding mapping.

Per docs/specs/2026-06-02-v0.6-validate-design.md § SQLAlchemy models.
The validations table already exists in the DB (created by 001_initial);
v0.6 adds the model without a schema migration. The Finding model gains
a validated_at column mapping in the same commit.

CHECK / UNIQUE constraints stay DB-side per the v0.3 belt-and-suspenders
pattern (Pydantic at the input boundary, SQLite enforcement at the
second).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy.exc import IntegrityError
from ulid import ULID

from flosswing.state import session as st_session
from flosswing.state.models import (
    AgentSession,
    Finding,
    HuntTask,
    Run,
    Validation,
)


@pytest.fixture()
def isolated_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("FLOSSWING_DB_URL", f"sqlite:///{tmp_path}/state.db")
    monkeypatch.setattr(st_session, "_cached_engine", None, raising=False)
    monkeypatch.setattr(
        st_session, "_cached_session_factory", None, raising=False
    )
    return tmp_path


def _make_run_finding_session() -> tuple[str, str, str]:
    """Returns (run_id, finding_id, agent_session_id) of a fresh row triple.

    Inserts are split across session_scopes so each parent row commits
    before its children reference it, mirroring the v0.5 symbol-model
    test pattern. PRAGMA foreign_keys=ON is enforced by the session
    layer, so single-scope multi-table inserts can fail on the SQLite
    side regardless of SQLAlchemy's unit-of-work ordering.
    """
    run_id = str(ULID())
    task_id = str(ULID())
    finding_id = str(ULID())
    agent_session_id = str(ULID())
    with st_session.session_scope() as s:
        s.add(
            Run(
                id=run_id, target_repo_path="/tmp/fake", target_repo_sha=None,
                depth="standard", budget_total=20, budget_used=0,
                started_at="2026-06-02T00:00:00Z", status="running",
                config_json="{}", flosswing_version="0.6.0",
            )
        )
    with st_session.session_scope() as s:
        s.add(
            HuntTask(
                id=task_id, run_id=run_id,
                attack_class="command_injection",
                scope_hint="src/", rationale="",
                priority="normal", source="recon",
                parent_finding_id=None, status="completed",
                created_at="2026-06-02T00:00:00Z",
                started_at="2026-06-02T00:00:01Z",
                finished_at="2026-06-02T00:00:02Z",
                findings_count=1,
            )
        )
    with st_session.session_scope() as s:
        s.add(
            Finding(
                id=finding_id, run_id=run_id, hunt_task_id=task_id,
                attack_class="command_injection",
                file="src/example/cli.py", function="greet",
                line_start=10, line_end=12,
                severity="high", confidence="likely",
                status="pending_validation",
                title="shell injection via greet name arg",
                description="ten-x more interesting than nothing at all" * 3,
                poc_code=None, poc_result_json=None,
                suggested_fix=None,
                created_at="2026-06-02T00:00:03Z",
            )
        )
        s.add(
            AgentSession(
                id=agent_session_id, run_id=run_id,
                stage="validate", task_id=None, finding_id=finding_id,
                model="claude-opus-4-7",
                system_prompt_hash="0" * 64,
                input_tokens=100, output_tokens=50,
                cache_read_tokens=0, cache_write_tokens=0,
                cost_usd=0.01, duration_ms=1000,
                outcome="completed",
                refusal_text=None, error_text=None,
                tool_calls_count=2,
                started_at="2026-06-02T00:00:04Z",
                finished_at="2026-06-02T00:00:05Z",
            )
        )
    return run_id, finding_id, agent_session_id


def test_validation_model_round_trip(isolated_db: Path) -> None:
    _run_id, finding_id, agent_session_id = _make_run_finding_session()
    vid = str(ULID())
    with st_session.session_scope() as s:
        s.add(
            Validation(
                id=vid,
                finding_id=finding_id,
                verdict="confirmed",
                rationale="x" * 60,
                evidence_files_json='["src/example/cli.py"]',
                agent_session_id=agent_session_id,
                created_at="2026-06-02T00:00:06Z",
            )
        )
    with st_session.session_scope() as s:
        row = s.get(Validation, vid)
        assert row is not None
        assert row.finding_id == finding_id
        assert row.verdict == "confirmed"
        assert row.rationale.startswith("x")
        assert row.evidence_files_json == '["src/example/cli.py"]'
        assert row.agent_session_id == agent_session_id


def test_validation_verdict_constraint_enforced_by_db(isolated_db: Path) -> None:
    """ck_validations_verdict is DB-side; invalid verdict raises IntegrityError."""
    _run_id, finding_id, agent_session_id = _make_run_finding_session()
    vid = str(ULID())
    with (
        pytest.raises(IntegrityError),
        st_session.session_scope() as s,
    ):
        s.add(
            Validation(
                id=vid, finding_id=finding_id,
                verdict="maybe_someday",  # violates ck_validations_verdict
                rationale="x" * 60,
                evidence_files_json="[]",
                agent_session_id=agent_session_id,
                created_at="2026-06-02T00:00:06Z",
            )
        )


def test_validation_evidence_files_json_must_be_valid_json(
    isolated_db: Path,
) -> None:
    """ck_validations_evidence_valid is DB-side; bad JSON raises IntegrityError."""
    _run_id, finding_id, agent_session_id = _make_run_finding_session()
    vid = str(ULID())
    with (
        pytest.raises(IntegrityError),
        st_session.session_scope() as s,
    ):
        s.add(
            Validation(
                id=vid, finding_id=finding_id,
                verdict="rejected",
                rationale="x" * 60,
                evidence_files_json="this is not json",
                agent_session_id=agent_session_id,
                created_at="2026-06-02T00:00:06Z",
            )
        )


def test_validation_uniqueness_per_finding(isolated_db: Path) -> None:
    """uq_validations_finding_id enforces one validation per finding."""
    _run_id, finding_id, agent_session_id = _make_run_finding_session()
    with st_session.session_scope() as s:
        s.add(
            Validation(
                id=str(ULID()), finding_id=finding_id,
                verdict="confirmed", rationale="x" * 60,
                evidence_files_json="[]",
                agent_session_id=agent_session_id,
                created_at="2026-06-02T00:00:06Z",
            )
        )
    with (
        pytest.raises(IntegrityError),
        st_session.session_scope() as s,
    ):
        s.add(
            Validation(
                id=str(ULID()), finding_id=finding_id,
                verdict="rejected", rationale="y" * 60,
                evidence_files_json="[]",
                agent_session_id=agent_session_id,
                created_at="2026-06-02T00:00:07Z",
            )
        )


def test_finding_validated_at_column_is_mapped_and_round_trips(
    isolated_db: Path,
) -> None:
    """The v0.6 extension to the Finding mapping: validated_at is now writable."""
    _run_id, finding_id, _ = _make_run_finding_session()
    with st_session.session_scope() as s:
        f = s.get(Finding, finding_id)
        assert f is not None
        assert f.validated_at is None
        f.validated_at = "2026-06-02T00:00:07Z"
        f.status = "confirmed"
    with st_session.session_scope() as s:
        f = s.get(Finding, finding_id)
        assert f is not None
        assert f.validated_at == "2026-06-02T00:00:07Z"
        assert f.status == "confirmed"
