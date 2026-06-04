"""query_run_state — read-only run-state aggregation tool.

Per docs/tool-contracts.md § Scope: run state (read-only). The Pydantic
QueryRunStateInput/Output models are frozen — copy verbatim. The tool
reads from `runs`, `recon_artifacts`, `hunt_tasks`, and `agent_sessions`
to produce a single aggregate view for the Gapfill agent.

Per plan-time decision #1 the function reads the DB directly at call
time (no in-memory result-object shortcut), which makes the aggregation
deterministic from DB state alone.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from ulid import ULID

from flosswing.state import session as st_session
from flosswing.state.models import (
    AgentSession,
    HuntTask,
    ReconArtifact,
    Run,
)
from flosswing.tools.findings import RecordReconArtifactInput
from flosswing.tools.run_state import (
    HuntTaskSummary,
    QueryRunStateInput,
    QueryRunStateOutput,
    query_run_state,
)


def _now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


@pytest.fixture()
def isolated_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("FLOSSWING_DB_URL", f"sqlite:///{tmp_path}/state.db")
    monkeypatch.setattr(st_session, "_cached_engine", None, raising=False)
    return tmp_path


def _seed_run(*, run_id: str | None = None) -> str:
    rid = run_id or str(ULID())
    with st_session.session_scope() as s:
        s.add(
            Run(
                id=rid, target_repo_path="/tmp/x", target_repo_sha=None,
                depth="standard", budget_total=20, budget_used=0,
                started_at=_now_iso(), status="running",
                config_json="{}", flosswing_version="0.7.0",
            )
        )
    return rid


def _seed_recon_artifact(run_id: str) -> str:
    aid = str(ULID())
    with st_session.session_scope() as s:
        s.add(
            ReconArtifact(
                id=aid, run_id=run_id,
                languages_json=json.dumps(["python"]),
                build_commands_json=json.dumps({"primary": "make"}),
                trust_boundaries_json=json.dumps([
                    {"kind": "subprocess",
                     "description": "shells out to git",
                     "files": ["src/exec.py"]},
                ]),
                subsystems_json=json.dumps([
                    {"name": "cli", "description": "argparse front-end",
                     "paths": ["src/cli/"], "languages": ["python"],
                     "notes": ""},
                ]),
                notes="single-file CLI",
                recorded_at=_now_iso(),
            )
        )
    return aid


def _seed_hunt_task(
    run_id: str, *,
    source: str = "recon",
    status: str = "pending",
    attack_class: str = "command_injection",
    scope_hint: str = "src/",
    findings_count: int = 0,
) -> str:
    tid = str(ULID())
    with st_session.session_scope() as s:
        s.add(
            HuntTask(
                id=tid, run_id=run_id,
                attack_class=attack_class,
                scope_hint=scope_hint, rationale="",
                priority="normal", source=source,
                parent_finding_id=None, status=status,
                created_at=_now_iso(),
                started_at=None, finished_at=None,
                findings_count=findings_count,
            )
        )
    return tid


def _seed_agent_session(
    run_id: str, *,
    stage: str = "recon",
    input_tokens: int = 100,
    output_tokens: int = 50,
    outcome: str = "completed",
) -> str:
    sid = str(ULID())
    with st_session.session_scope() as s:
        s.add(
            AgentSession(
                id=sid, run_id=run_id,
                stage=stage, task_id=None, finding_id=None,
                model="claude-opus-4-7",
                system_prompt_hash="0" * 64,
                input_tokens=input_tokens, output_tokens=output_tokens,
                cache_read_tokens=0, cache_write_tokens=0,
                cost_usd=0.0, duration_ms=0,
                outcome=outcome,
                refusal_text=None, error_text=None,
                tool_calls_count=0,
                started_at=_now_iso(), finished_at=_now_iso(),
            )
        )
    return sid


def test_query_run_state_happy_path_returns_full_shape(
    isolated_db: Path,
) -> None:
    """Per docs/tool-contracts.md § Scope: run state. All four projections
    fire: recon_artifact present, multiple hunt_tasks, budget_used computed
    from agent_sessions sum, budget_remaining derived from the kwarg."""
    run_id = _seed_run()
    _seed_recon_artifact(run_id)
    _seed_hunt_task(run_id, attack_class="command_injection",
                    status="completed", findings_count=1)
    _seed_hunt_task(run_id, attack_class="ssrf",
                    status="pending", findings_count=0)
    _seed_agent_session(run_id, stage="recon",
                        input_tokens=200, output_tokens=100)
    _seed_agent_session(run_id, stage="hunt",
                        input_tokens=500, output_tokens=300)

    out = query_run_state(
        QueryRunStateInput(),
        run_id=run_id,
        total_token_budget=10_000,
    )
    assert isinstance(out, QueryRunStateOutput)
    assert out.run_id == run_id
    assert out.recon_artifact is not None
    assert isinstance(out.recon_artifact, RecordReconArtifactInput)
    assert out.recon_artifact.languages == ["python"]
    assert out.recon_artifact.build_commands == {"primary": "make"}
    assert len(out.recon_artifact.subsystems) == 1
    assert out.recon_artifact.subsystems[0].name == "cli"
    assert len(out.recon_artifact.trust_boundaries) == 1
    assert out.recon_artifact.notes == "single-file CLI"

    assert len(out.hunt_tasks) == 2
    statuses = {t.status for t in out.hunt_tasks}
    assert statuses == {"completed", "pending"}
    classes = {t.attack_class for t in out.hunt_tasks}
    assert classes == {"command_injection", "ssrf"}
    assert all(isinstance(t, HuntTaskSummary) for t in out.hunt_tasks)
    # findings_count round-trips.
    completed_task = next(
        t for t in out.hunt_tasks if t.status == "completed"
    )
    assert completed_task.findings_count == 1

    # budget_used = sum of input + output across all agent_sessions
    # = (200+100) + (500+300) = 1100.
    assert out.budget_used == 1_100
    # budget_remaining = max(0, total_token_budget - budget_used)
    assert out.budget_remaining == 10_000 - 1_100


def test_query_run_state_missing_recon_artifact_returns_none(
    isolated_db: Path,
) -> None:
    """Per the contract: recon_artifact is Optional. When no
    recon_artifacts row exists, the field is None — not an error."""
    run_id = _seed_run()
    _seed_hunt_task(run_id)
    out = query_run_state(
        QueryRunStateInput(),
        run_id=run_id,
        total_token_budget=0,
    )
    assert out.recon_artifact is None
    assert len(out.hunt_tasks) == 1


def test_query_run_state_no_agent_sessions_yields_zero_budget_used(
    isolated_db: Path,
) -> None:
    """Per plan-time decision #4 the budget is summed from agent_sessions;
    no rows means zero used. budget_remaining clamps to >=0."""
    run_id = _seed_run()
    out = query_run_state(
        QueryRunStateInput(),
        run_id=run_id,
        total_token_budget=5_000,
    )
    assert out.budget_used == 0
    assert out.budget_remaining == 5_000


def test_query_run_state_budget_remaining_clamps_to_zero(
    isolated_db: Path,
) -> None:
    """If observed token use exceeds the passed budget envelope (off-by-
    a-round, or the caller passed a smaller cap by accident), the
    remaining figure must not go negative."""
    run_id = _seed_run()
    _seed_agent_session(run_id, input_tokens=10_000, output_tokens=5_000)
    out = query_run_state(
        QueryRunStateInput(),
        run_id=run_id,
        total_token_budget=1_000,
    )
    assert out.budget_used == 15_000
    assert out.budget_remaining == 0


def test_query_run_state_cross_run_isolation(isolated_db: Path) -> None:
    """A call scoped to run_id=A must not return hunt_tasks or
    agent_sessions or the recon_artifact from run_id=B."""
    run_a = _seed_run()
    run_b = _seed_run()
    _seed_recon_artifact(run_a)
    _seed_hunt_task(run_a, attack_class="command_injection")
    _seed_hunt_task(run_b, attack_class="ssrf")
    _seed_agent_session(run_a, input_tokens=100)
    _seed_agent_session(run_b, input_tokens=99_999)

    out_a = query_run_state(
        QueryRunStateInput(), run_id=run_a, total_token_budget=0
    )
    assert {t.attack_class for t in out_a.hunt_tasks} == {
        "command_injection"
    }
    assert out_a.recon_artifact is not None
    # budget sum comes from agent_sessions for run_a only — not run_b's 99_999.
    assert out_a.budget_used == 100 + 50

    out_b = query_run_state(
        QueryRunStateInput(), run_id=run_b, total_token_budget=0
    )
    assert {t.attack_class for t in out_b.hunt_tasks} == {"ssrf"}
    assert out_b.recon_artifact is None
    assert out_b.budget_used == 99_999 + 50


def test_query_run_state_empty_run(isolated_db: Path) -> None:
    """A run with no recon_artifact, no hunt_tasks, no agent_sessions
    returns the empty shape rather than raising."""
    run_id = _seed_run()
    out = query_run_state(
        QueryRunStateInput(), run_id=run_id, total_token_budget=42
    )
    assert out.run_id == run_id
    assert out.recon_artifact is None
    assert out.hunt_tasks == []
    assert out.budget_used == 0
    assert out.budget_remaining == 42


def test_query_run_state_input_is_parameterless(isolated_db: Path) -> None:
    """The contract says QueryRunStateInput has no fields; constructing
    one with no args must succeed and produce an instance accepted by
    query_run_state."""
    inp = QueryRunStateInput()
    run_id = _seed_run()
    # Should not raise.
    query_run_state(inp, run_id=run_id, total_token_budget=0)


def test_query_run_state_hunt_task_summary_shape(isolated_db: Path) -> None:
    """Each row of hunt_tasks is the HuntTaskSummary shape — exactly the
    fields task_id, attack_class, scope_hint, status, findings_count."""
    run_id = _seed_run()
    tid = _seed_hunt_task(
        run_id,
        attack_class="ssrf",
        scope_hint="src/net/",
        status="errored",
        findings_count=3,
    )
    out = query_run_state(
        QueryRunStateInput(), run_id=run_id, total_token_budget=0
    )
    assert len(out.hunt_tasks) == 1
    t = out.hunt_tasks[0]
    assert t.task_id == tid
    assert t.attack_class == "ssrf"
    assert t.scope_hint == "src/net/"
    assert t.status == "errored"
    assert t.findings_count == 3
    # Contract: HuntTaskSummary has exactly these fields and no others.
    assert set(t.model_dump().keys()) == {
        "task_id", "attack_class", "scope_hint", "status", "findings_count",
    }
