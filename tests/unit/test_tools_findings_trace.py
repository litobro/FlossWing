"""tools/findings.py: trace-side tool implementation (record_trace).

Per docs/tool-contracts.md § record_trace and
docs/specs/2026-06-02-v0.9-trace-design.md § Component responsibilities.

Fixture strategy mirrors test_tools_findings_dedupe.py:
- Per-test isolated_db using a file-backed SQLite in tmp_path so Alembic
  upgrade runs once on first session.
- Separate session_scopes per FK level (Run -> HuntTask -> Finding ->
  AgentSession -> ReconArtifact -> EntryPoint) because SQLite FK
  enforcement is on and a single flush can't always infer the ordering.
- record_trace requires an agent_sessions row to exist because
  traces.agent_session_id is FK'd with ON DELETE RESTRICT. The Trace
  stage in production seeds this row first (see plan task design).
- For tests that resolve entry_point_id, we also seed a recon_artifacts
  row first (entry_points.recon_artifact_id is NOT NULL FK), then the
  entry_points row.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import select
from ulid import ULID

from flosswing.errors import (
    EmptyCallChainError,
    FindingNotFoundError,
    FindingNotTraceableError,
    InconsistentTraceError,
    RationaleEmptyError,
    TraceAlreadyExistsError,
)
from flosswing.state import session as st_session
from flosswing.state.models import (
    AgentSession,
    EntryPoint,
    Finding,
    HuntTask,
    ReconArtifact,
    Run,
    Trace,
)
from flosswing.tools.findings import (
    CallChainStep,
    RecordTraceInput,
    RecordTraceOutput,
    record_trace,
)

# -----------------------------------------------------------------------------
# Fixtures
# -----------------------------------------------------------------------------


@pytest.fixture()
def isolated_db(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[Path]:
    monkeypatch.setenv("FLOSSWING_DB_URL", f"sqlite:///{tmp_path}/state.db")
    monkeypatch.setattr(st_session, "_cached_engine", None, raising=False)
    monkeypatch.setattr(
        st_session, "_cached_session_factory", None, raising=False
    )
    yield tmp_path


def _now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _seed_run_and_task() -> tuple[str, str]:
    """Insert a Run + a HuntTask; return (run_id, task_id).

    Separate session_scopes per FK level — Run must commit before HuntTask
    flushes, same pattern as _seed_run_with_findings in
    test_tools_findings.py and test_tools_findings_dedupe.py.
    """
    run_id = str(ULID())
    task_id = str(ULID())
    now = _now_iso()
    with st_session.session_scope() as s:
        s.add(
            Run(
                id=run_id,
                target_repo_path="/tmp/x",
                target_repo_sha=None,
                depth="standard",
                budget_total=20,
                budget_used=0,
                started_at=now,
                status="running",
                config_json="{}",
                flosswing_version="0.9.0",
            )
        )
    with st_session.session_scope() as s:
        s.add(
            HuntTask(
                id=task_id,
                run_id=run_id,
                attack_class="command_injection",
                scope_hint="src/",
                rationale="",
                priority="normal",
                source="recon",
                parent_finding_id=None,
                status="completed",
                created_at=now,
                started_at=now,
                finished_at=now,
                findings_count=0,
            )
        )
    return run_id, task_id


def _seed_finding(
    *,
    run_id: str,
    task_id: str,
    status: str = "confirmed",
    dedupe_role: str | None = None,
    file: str = "src/a.py",
) -> str:
    """Insert one Finding row; return its id.

    Defaults to a trace-eligible row: status='confirmed',
    dedupe_role IS NULL. Tests overriding either field exercise the
    record_trace traceability check.
    """
    fid = str(ULID())
    with st_session.session_scope() as s:
        s.add(
            Finding(
                id=fid,
                run_id=run_id,
                hunt_task_id=task_id,
                attack_class="command_injection",
                file=file,
                function="some_fn",
                line_start=10,
                line_end=12,
                severity="high",
                confidence="likely",
                status=status,
                title=f"command_injection in {file}",
                description=(
                    "A reasonable description, fifty chars or more."
                ),
                poc_code=None,
                poc_result_json=None,
                suggested_fix=None,
                created_at=_now_iso(),
                dedupe_role=dedupe_role,
            )
        )
    return fid


def _seed_agent_session(
    *, run_id: str, finding_id: str
) -> str:
    """Insert an agent_sessions row representing the in-flight Trace
    session. record_trace requires this row to exist so its
    traces.agent_session_id FK can be satisfied (FK is ON DELETE
    RESTRICT, so it must be present at INSERT-time).
    """
    sid = str(ULID())
    with st_session.session_scope() as s:
        s.add(
            AgentSession(
                id=sid,
                run_id=run_id,
                stage="trace",
                task_id=None,
                finding_id=finding_id,
                model="claude-opus-4-7",
                system_prompt_hash="0" * 64,
                input_tokens=0,
                output_tokens=0,
                cache_read_tokens=0,
                cache_write_tokens=0,
                cost_usd=0.0,
                duration_ms=0,
                outcome="completed",
                refusal_text=None,
                error_text=None,
                tool_calls_count=0,
                started_at=_now_iso(),
                finished_at=_now_iso(),
            )
        )
    return sid


def _seed_recon_artifact(*, run_id: str) -> str:
    """Insert a recon_artifacts row; return its id.

    Needed before any entry_points row can be inserted because
    entry_points.recon_artifact_id is NOT NULL FK.
    """
    artifact_id = str(ULID())
    with st_session.session_scope() as s:
        s.add(
            ReconArtifact(
                id=artifact_id,
                run_id=run_id,
                languages_json="[]",
                build_commands_json="{}",
                trust_boundaries_json="[]",
                subsystems_json="[]",
                notes="",
                recorded_at=_now_iso(),
            )
        )
    return artifact_id


def _seed_entry_point(
    *,
    run_id: str,
    recon_artifact_id: str,
    symbol: str = "main",
    file: str = "src/cli.py",
) -> str:
    """Insert an entry_points row; return its id."""
    ep_id = str(ULID())
    with st_session.session_scope() as s:
        s.add(
            EntryPoint(
                id=ep_id,
                recon_artifact_id=recon_artifact_id,
                run_id=run_id,
                symbol=symbol,
                file=file,
                line=1,
                kind="cli",
                attacker_controlled_input=1,
                notes="",
            )
        )
    return ep_id


def _call_chain() -> list[CallChainStep]:
    """Two-step call chain used by happy-path tests."""
    return [
        CallChainStep(
            symbol="main",
            file="src/cli.py",
            line=1,
            is_entry_point=True,
            notes="entry",
        ),
        CallChainStep(
            symbol="some_fn",
            file="src/a.py",
            line=10,
            is_entry_point=False,
            notes="sink",
        ),
    ]


_RATIONALE = (
    "Argv flows directly from main() into the shell-invoking sink at "
    "src/a.py:10 with no intervening sanitisation."
)


# -----------------------------------------------------------------------------
# record_trace happy paths
# -----------------------------------------------------------------------------


def test_record_trace_happy_path_reachable(isolated_db: Path) -> None:
    """reachable='reachable' with an entry_point_symbol that doesn't match
    any entry_points row resolves to entry_point_id=NULL (the schema
    permits NULL when no row matches the symbol)."""
    run_id, task_id = _seed_run_and_task()
    finding_id = _seed_finding(run_id=run_id, task_id=task_id)
    agent_session_id = _seed_agent_session(
        run_id=run_id, finding_id=finding_id
    )

    chain = _call_chain()
    out = record_trace(
        RecordTraceInput(
            finding_id=finding_id,
            reachable="reachable",
            entry_point_symbol="main",
            call_chain=chain,
            rationale=_RATIONALE,
        ),
        run_id=run_id,
        agent_session_id=agent_session_id,
    )
    assert isinstance(out, RecordTraceOutput)
    # ULIDs are 26 chars.
    assert len(out.trace_id) == 26

    with st_session.session_scope() as s:
        trace = s.execute(
            select(Trace).where(Trace.id == out.trace_id)
        ).scalar_one()
        assert trace.finding_id == finding_id
        assert trace.reachable == "reachable"
        assert trace.entry_point_symbol == "main"
        assert trace.entry_point_id is None
        assert trace.rationale == _RATIONALE
        assert trace.agent_session_id == agent_session_id
        assert trace.created_at
        # call_chain_json round-trips to the original step list.
        decoded = json.loads(trace.call_chain_json)
        assert isinstance(decoded, list)
        assert len(decoded) == 2
        assert decoded[0]["symbol"] == "main"
        assert decoded[0]["is_entry_point"] is True
        assert decoded[1]["symbol"] == "some_fn"
        assert decoded[1]["is_entry_point"] is False

        finding = s.get(Finding, finding_id)
        assert finding is not None
        assert finding.reachable == "reachable"


def test_record_trace_entry_point_id_resolved(isolated_db: Path) -> None:
    """When entry_points.symbol matches inp.entry_point_symbol within the
    same run_id, the new traces row's entry_point_id points at it."""
    run_id, task_id = _seed_run_and_task()
    finding_id = _seed_finding(run_id=run_id, task_id=task_id)
    agent_session_id = _seed_agent_session(
        run_id=run_id, finding_id=finding_id
    )
    artifact_id = _seed_recon_artifact(run_id=run_id)
    ep_id = _seed_entry_point(
        run_id=run_id, recon_artifact_id=artifact_id, symbol="main"
    )

    out = record_trace(
        RecordTraceInput(
            finding_id=finding_id,
            reachable="reachable",
            entry_point_symbol="main",
            call_chain=_call_chain(),
            rationale=_RATIONALE,
        ),
        run_id=run_id,
        agent_session_id=agent_session_id,
    )

    with st_session.session_scope() as s:
        trace = s.execute(
            select(Trace).where(Trace.id == out.trace_id)
        ).scalar_one()
        assert trace.entry_point_id == ep_id
        assert trace.entry_point_symbol == "main"


def test_record_trace_happy_path_unreachable(isolated_db: Path) -> None:
    """reachable='unreachable' with entry_point_symbol=None succeeds; the
    consistency check only fires for reachable=='reachable'."""
    run_id, task_id = _seed_run_and_task()
    finding_id = _seed_finding(run_id=run_id, task_id=task_id)
    agent_session_id = _seed_agent_session(
        run_id=run_id, finding_id=finding_id
    )

    out = record_trace(
        RecordTraceInput(
            finding_id=finding_id,
            reachable="unreachable",
            entry_point_symbol=None,
            call_chain=_call_chain(),
            rationale=_RATIONALE,
        ),
        run_id=run_id,
        agent_session_id=agent_session_id,
    )

    with st_session.session_scope() as s:
        trace = s.execute(
            select(Trace).where(Trace.id == out.trace_id)
        ).scalar_one()
        assert trace.reachable == "unreachable"
        assert trace.entry_point_symbol is None
        assert trace.entry_point_id is None
        finding = s.get(Finding, finding_id)
        assert finding is not None
        assert finding.reachable == "unreachable"


def test_record_trace_happy_path_uncertain(isolated_db: Path) -> None:
    """reachable='uncertain' with entry_point_symbol=None succeeds."""
    run_id, task_id = _seed_run_and_task()
    finding_id = _seed_finding(run_id=run_id, task_id=task_id)
    agent_session_id = _seed_agent_session(
        run_id=run_id, finding_id=finding_id
    )

    out = record_trace(
        RecordTraceInput(
            finding_id=finding_id,
            reachable="uncertain",
            entry_point_symbol=None,
            call_chain=_call_chain(),
            rationale=_RATIONALE,
        ),
        run_id=run_id,
        agent_session_id=agent_session_id,
    )

    with st_session.session_scope() as s:
        trace = s.execute(
            select(Trace).where(Trace.id == out.trace_id)
        ).scalar_one()
        assert trace.reachable == "uncertain"
        finding = s.get(Finding, finding_id)
        assert finding is not None
        assert finding.reachable == "uncertain"


# -----------------------------------------------------------------------------
# record_trace error paths
# -----------------------------------------------------------------------------


def test_record_trace_finding_not_found(isolated_db: Path) -> None:
    """An unknown finding_id under this run raises FindingNotFoundError."""
    run_id, task_id = _seed_run_and_task()
    # Seed a real finding so we have something to anchor the agent_session
    # row to; the call below uses a bogus finding_id.
    real_id = _seed_finding(run_id=run_id, task_id=task_id)
    agent_session_id = _seed_agent_session(
        run_id=run_id, finding_id=real_id
    )
    bogus_id = "01BOGUSBOGUSBOGUSBOGUSBOGU"
    with pytest.raises(FindingNotFoundError):
        record_trace(
            RecordTraceInput(
                finding_id=bogus_id,
                reachable="reachable",
                entry_point_symbol="main",
                call_chain=_call_chain(),
                rationale=_RATIONALE,
            ),
            run_id=run_id,
            agent_session_id=agent_session_id,
        )


def test_record_trace_finding_not_traceable_status_uncertain(
    isolated_db: Path,
) -> None:
    """status='uncertain' (not 'confirmed') is rejected."""
    run_id, task_id = _seed_run_and_task()
    finding_id = _seed_finding(
        run_id=run_id, task_id=task_id, status="uncertain"
    )
    agent_session_id = _seed_agent_session(
        run_id=run_id, finding_id=finding_id
    )
    with pytest.raises(FindingNotTraceableError):
        record_trace(
            RecordTraceInput(
                finding_id=finding_id,
                reachable="reachable",
                entry_point_symbol="main",
                call_chain=_call_chain(),
                rationale=_RATIONALE,
            ),
            run_id=run_id,
            agent_session_id=agent_session_id,
        )


def test_record_trace_finding_not_traceable_status_rejected(
    isolated_db: Path,
) -> None:
    """status='rejected' is rejected."""
    run_id, task_id = _seed_run_and_task()
    finding_id = _seed_finding(
        run_id=run_id, task_id=task_id, status="rejected"
    )
    agent_session_id = _seed_agent_session(
        run_id=run_id, finding_id=finding_id
    )
    with pytest.raises(FindingNotTraceableError):
        record_trace(
            RecordTraceInput(
                finding_id=finding_id,
                reachable="reachable",
                entry_point_symbol="main",
                call_chain=_call_chain(),
                rationale=_RATIONALE,
            ),
            run_id=run_id,
            agent_session_id=agent_session_id,
        )


def test_record_trace_finding_not_traceable_status_superseded(
    isolated_db: Path,
) -> None:
    """status='superseded' is rejected — supersededs are Dedupe artefacts
    and not eligible for the Trace stage."""
    run_id, task_id = _seed_run_and_task()
    finding_id = _seed_finding(
        run_id=run_id, task_id=task_id, status="superseded"
    )
    agent_session_id = _seed_agent_session(
        run_id=run_id, finding_id=finding_id
    )
    with pytest.raises(FindingNotTraceableError):
        record_trace(
            RecordTraceInput(
                finding_id=finding_id,
                reachable="reachable",
                entry_point_symbol="main",
                call_chain=_call_chain(),
                rationale=_RATIONALE,
            ),
            run_id=run_id,
            agent_session_id=agent_session_id,
        )


def test_record_trace_finding_not_traceable_dedupe_role_duplicate(
    isolated_db: Path,
) -> None:
    """status='confirmed' but dedupe_role='duplicate' is rejected — only
    NULL and 'primary' roles are trace-eligible."""
    run_id, task_id = _seed_run_and_task()
    finding_id = _seed_finding(
        run_id=run_id,
        task_id=task_id,
        status="confirmed",
        dedupe_role="duplicate",
    )
    agent_session_id = _seed_agent_session(
        run_id=run_id, finding_id=finding_id
    )
    with pytest.raises(FindingNotTraceableError):
        record_trace(
            RecordTraceInput(
                finding_id=finding_id,
                reachable="reachable",
                entry_point_symbol="main",
                call_chain=_call_chain(),
                rationale=_RATIONALE,
            ),
            run_id=run_id,
            agent_session_id=agent_session_id,
        )


def test_record_trace_finding_not_traceable_dedupe_role_variant(
    isolated_db: Path,
) -> None:
    """status='confirmed' but dedupe_role='variant' is rejected."""
    run_id, task_id = _seed_run_and_task()
    finding_id = _seed_finding(
        run_id=run_id,
        task_id=task_id,
        status="confirmed",
        dedupe_role="variant",
    )
    agent_session_id = _seed_agent_session(
        run_id=run_id, finding_id=finding_id
    )
    with pytest.raises(FindingNotTraceableError):
        record_trace(
            RecordTraceInput(
                finding_id=finding_id,
                reachable="reachable",
                entry_point_symbol="main",
                call_chain=_call_chain(),
                rationale=_RATIONALE,
            ),
            run_id=run_id,
            agent_session_id=agent_session_id,
        )


def test_record_trace_already_exists(isolated_db: Path) -> None:
    """Calling record_trace twice on the same finding raises on the second
    call. The findings.reachable value from the first call is unchanged."""
    run_id, task_id = _seed_run_and_task()
    finding_id = _seed_finding(run_id=run_id, task_id=task_id)
    first_session_id = _seed_agent_session(
        run_id=run_id, finding_id=finding_id
    )

    record_trace(
        RecordTraceInput(
            finding_id=finding_id,
            reachable="reachable",
            entry_point_symbol="main",
            call_chain=_call_chain(),
            rationale=_RATIONALE,
        ),
        run_id=run_id,
        agent_session_id=first_session_id,
    )

    # Fresh agent_sessions row for the second attempt — the production
    # Trace stage allocates a new session per finding, so we mirror that.
    second_session_id = _seed_agent_session(
        run_id=run_id, finding_id=finding_id
    )
    with pytest.raises(TraceAlreadyExistsError):
        record_trace(
            RecordTraceInput(
                finding_id=finding_id,
                reachable="unreachable",
                entry_point_symbol=None,
                call_chain=_call_chain(),
                rationale=_RATIONALE,
            ),
            run_id=run_id,
            agent_session_id=second_session_id,
        )

    # The original reachable value survives — the second call never
    # mutated the finding row.
    with st_session.session_scope() as s:
        finding = s.get(Finding, finding_id)
        assert finding is not None
        assert finding.reachable == "reachable"


def test_record_trace_inconsistent_trace(isolated_db: Path) -> None:
    """reachable='reachable' with entry_point_symbol=None is rejected
    (matches the DB-side ck_traces_reachable_has_entry_point CHECK).
    findings.reachable is unchanged."""
    run_id, task_id = _seed_run_and_task()
    finding_id = _seed_finding(run_id=run_id, task_id=task_id)
    agent_session_id = _seed_agent_session(
        run_id=run_id, finding_id=finding_id
    )
    with pytest.raises(InconsistentTraceError):
        record_trace(
            RecordTraceInput(
                finding_id=finding_id,
                reachable="reachable",
                entry_point_symbol=None,
                call_chain=_call_chain(),
                rationale=_RATIONALE,
            ),
            run_id=run_id,
            agent_session_id=agent_session_id,
        )

    with st_session.session_scope() as s:
        finding = s.get(Finding, finding_id)
        assert finding is not None
        assert finding.reachable is None


def test_record_trace_empty_call_chain(isolated_db: Path) -> None:
    """An empty call_chain list is rejected."""
    run_id, task_id = _seed_run_and_task()
    finding_id = _seed_finding(run_id=run_id, task_id=task_id)
    agent_session_id = _seed_agent_session(
        run_id=run_id, finding_id=finding_id
    )
    with pytest.raises(EmptyCallChainError):
        record_trace(
            RecordTraceInput(
                finding_id=finding_id,
                reachable="reachable",
                entry_point_symbol="main",
                call_chain=[],
                rationale=_RATIONALE,
            ),
            run_id=run_id,
            agent_session_id=agent_session_id,
        )


def test_record_trace_rationale_empty(isolated_db: Path) -> None:
    """A whitespace-only rationale is rejected (post-strip check)."""
    run_id, task_id = _seed_run_and_task()
    finding_id = _seed_finding(run_id=run_id, task_id=task_id)
    agent_session_id = _seed_agent_session(
        run_id=run_id, finding_id=finding_id
    )
    with pytest.raises(RationaleEmptyError):
        record_trace(
            RecordTraceInput(
                finding_id=finding_id,
                reachable="reachable",
                entry_point_symbol="main",
                call_chain=_call_chain(),
                rationale="   ",
            ),
            run_id=run_id,
            agent_session_id=agent_session_id,
        )


def test_record_trace_rationale_empty_zero_length(
    isolated_db: Path,
) -> None:
    """A zero-length rationale is rejected."""
    run_id, task_id = _seed_run_and_task()
    finding_id = _seed_finding(run_id=run_id, task_id=task_id)
    agent_session_id = _seed_agent_session(
        run_id=run_id, finding_id=finding_id
    )
    with pytest.raises(RationaleEmptyError):
        record_trace(
            RecordTraceInput(
                finding_id=finding_id,
                reachable="reachable",
                entry_point_symbol="main",
                call_chain=_call_chain(),
                rationale="",
            ),
            run_id=run_id,
            agent_session_id=agent_session_id,
        )
