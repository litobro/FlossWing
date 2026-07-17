"""flosswing.stages.validate — Validate stage orchestration.

Per docs/specs/2026-06-02-v0.6-validate-design.md § Component
responsibilities stages/validate.py.

Stage-level tests with a stubbed runtime.run_session returning canned
successful / refused / budget-exceeded / errored / no-verdict sessions.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import select
from ulid import ULID

from flosswing.agent.runtime import SessionResult
from flosswing.config import Config
from flosswing.stages import validate as validate_stage
from flosswing.state import session as st_session
from flosswing.state.models import (
    AgentSession,
    Finding,
    HuntTask,
    Run,
    Validation,
)
from flosswing.tools.findings import ValidateFindingInput, validate_finding


def _now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


@pytest.fixture()
def isolated_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("FLOSSWING_DB_URL", f"sqlite:///{tmp_path}/state.db")
    monkeypatch.setattr(st_session, "_cached_engine", None, raising=False)
    monkeypatch.setattr(
        st_session, "_cached_session_factory", None, raising=False
    )
    return tmp_path


def _seed_run_with_findings(
    *,
    severities: list[str],
    statuses: list[str] | None = None,
) -> tuple[str, list[str]]:
    if statuses is None:
        statuses = ["pending_validation"] * len(severities)
    run_id = str(ULID())
    task_id = str(ULID())
    finding_ids: list[str] = []
    with st_session.session_scope() as s:
        s.add(
            Run(
                id=run_id,
                target_repo_path="/tmp/x",
                target_repo_sha=None,
                depth="standard",
                budget_total=20,
                budget_used=0,
                started_at=_now_iso(),
                status="running",
                config_json="{}",
                flosswing_version="0.6.0",
            )
        )
        s.flush()
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
                created_at=_now_iso(),
                started_at=_now_iso(),
                finished_at=_now_iso(),
                findings_count=len(severities),
            )
        )
        s.flush()
        for i, (sev, st) in enumerate(zip(severities, statuses, strict=True)):
            fid = str(ULID())
            finding_ids.append(fid)
            s.add(
                Finding(
                    id=fid,
                    run_id=run_id,
                    hunt_task_id=task_id,
                    attack_class="command_injection",
                    file=f"src/{i}.py",
                    function="greet",
                    line_start=10,
                    line_end=12,
                    severity=sev,
                    confidence="likely",
                    status=st,
                    title="x" * 60,
                    description="y" * 60,
                    poc_code=None,
                    poc_result_json=None,
                    suggested_fix=None,
                    created_at=_now_iso(),
                )
            )
    return run_id, finding_ids


def _minimal_cfg(repo: Path) -> Config:
    return Config(
        repo_root=repo,
        model="claude-opus-4-7",
        recon_token_budget=200_000,
        hunt_token_budget=200_000,
        validate_token_budget=100_000,
        gapfill_token_budget=1_000_000,
        auth_env={"ANTHROPIC_API_KEY": "x"},
    )


@pytest.mark.asyncio
async def test_validate_stage_processes_pending_findings_in_severity_order(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per spec § Component responsibilities: ORDER BY severity DESC,
    created_at ASC."""
    run_id, _ = _seed_run_with_findings(severities=["low", "high", "medium"])
    seen_order: list[str] = []

    async def fake_run_session(**kw: object) -> SessionResult:
        finding_id = kw["finding_id"]
        assert isinstance(finding_id, str)
        seen_order.append(finding_id)
        return SessionResult(
            outcome="completed",
            input_tokens=100,
            output_tokens=50,
            cache_read_tokens=0,
            cache_write_tokens=0,
            duration_ms=1000,
            tool_calls_count=1,
            refusal_text=None,
            error_text=None,
        )

    monkeypatch.setattr(
        validate_stage, "run_session", AsyncMock(side_effect=fake_run_session)
    )

    result = await validate_stage.run(
        run_id=run_id,
        repo=isolated_db,
        cfg=_minimal_cfg(isolated_db),
        session_factory=st_session.session_factory(),
    )
    assert result.findings_processed == 3
    # Per spec: severity DESC, created_at ASC. We seeded ["low", "high",
    # "medium"]. Expected order: high, medium, low.
    with st_session.session_scope() as s:
        rows_in_order = (
            s.execute(
                select(Finding)
                .where(Finding.run_id == run_id)
                .order_by(Finding.created_at)
            )
            .scalars()
            .all()
        )
        sev_to_id = {r.severity: r.id for r in rows_in_order}
    sev_order = ["high", "medium", "low"]
    expected_ids = [sev_to_id[sev] for sev in sev_order]
    assert seen_order == expected_ids


@pytest.mark.asyncio
async def test_validate_stage_completed_session_with_no_call_leaves_pending(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per spec § Component responsibilities: completed session without
    validate_finding call -> finding stays pending_validation, surfaced as
    its own bucket in the result."""
    run_id, _ = _seed_run_with_findings(severities=["high"])

    async def fake_run_session(**kw: object) -> SessionResult:
        # Agent completed but did NOT call validate_finding.
        return SessionResult(
            outcome="completed",
            input_tokens=100,
            output_tokens=50,
            cache_read_tokens=0,
            cache_write_tokens=0,
            duration_ms=1000,
            tool_calls_count=0,
            refusal_text=None,
            error_text=None,
        )

    monkeypatch.setattr(
        validate_stage, "run_session", AsyncMock(side_effect=fake_run_session)
    )
    result = await validate_stage.run(
        run_id=run_id,
        repo=isolated_db,
        cfg=_minimal_cfg(isolated_db),
        session_factory=st_session.session_factory(),
    )
    # No validation row -> finding still pending_validation.
    with st_session.session_scope() as s:
        f = s.execute(
            select(Finding).where(Finding.run_id == run_id)
        ).scalar_one()
        assert f.status == "pending_validation"
        assert f.validated_at is None
        v = s.execute(
            select(Validation).where(Validation.finding_id == f.id)
        ).scalar_one_or_none()
        assert v is None
    # The terminal-verdict counts are zero and the no-verdict bucket >= 1.
    assert result.findings_confirmed == 0
    assert result.findings_rejected == 0
    assert result.findings_uncertain == 0
    assert result.findings_no_verdict == 1


@pytest.mark.asyncio
async def test_validate_stage_refused_session_leaves_pending(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per design decision #5: refused session -> no validations row;
    finding stays pending_validation."""
    run_id, _ = _seed_run_with_findings(severities=["high"])

    async def fake_run_session(**kw: object) -> SessionResult:
        return SessionResult(
            outcome="refused",
            input_tokens=100,
            output_tokens=50,
            cache_read_tokens=0,
            cache_write_tokens=0,
            duration_ms=500,
            tool_calls_count=0,
            refusal_text="I cannot do this task",
            error_text=None,
        )

    monkeypatch.setattr(
        validate_stage, "run_session", AsyncMock(side_effect=fake_run_session)
    )
    result = await validate_stage.run(
        run_id=run_id,
        repo=isolated_db,
        cfg=_minimal_cfg(isolated_db),
        session_factory=st_session.session_factory(),
    )
    assert result.findings_refused == 1
    with st_session.session_scope() as s:
        f = s.execute(
            select(Finding).where(Finding.run_id == run_id)
        ).scalar_one()
        assert f.status == "pending_validation"
        v = s.execute(
            select(Validation).where(Validation.finding_id == f.id)
        ).scalar_one_or_none()
        assert v is None
        # An agent_sessions row WAS written with outcome='refused'.
        sess = s.execute(
            select(AgentSession).where(
                AgentSession.run_id == run_id,
                AgentSession.stage == "validate",
            )
        ).scalar_one()
        assert sess.outcome == "refused"
        assert sess.refusal_text == "I cannot do this task"


@pytest.mark.asyncio
async def test_validate_stage_budget_exceeded_session_leaves_pending(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id, _ = _seed_run_with_findings(severities=["high"])

    async def fake_run_session(**kw: object) -> SessionResult:
        return SessionResult(
            outcome="budget_exceeded",
            input_tokens=150_000,
            output_tokens=2_000,
            cache_read_tokens=0,
            cache_write_tokens=0,
            duration_ms=20_000,
            tool_calls_count=4,
            refusal_text=None,
            error_text=None,
        )

    monkeypatch.setattr(
        validate_stage, "run_session", AsyncMock(side_effect=fake_run_session)
    )
    result = await validate_stage.run(
        run_id=run_id,
        repo=isolated_db,
        cfg=_minimal_cfg(isolated_db),
        session_factory=st_session.session_factory(),
    )
    assert result.findings_budget_exceeded == 1
    with st_session.session_scope() as s:
        f = s.execute(
            select(Finding).where(Finding.run_id == run_id)
        ).scalar_one()
        assert f.status == "pending_validation"


@pytest.mark.asyncio
async def test_validate_stage_errored_session_leaves_pending(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id, _ = _seed_run_with_findings(severities=["high"])

    async def fake_run_session(**kw: object) -> SessionResult:
        return SessionResult(
            outcome="errored",
            input_tokens=100,
            output_tokens=0,
            cache_read_tokens=0,
            cache_write_tokens=0,
            duration_ms=200,
            tool_calls_count=0,
            refusal_text=None,
            error_text="network unreachable",
        )

    monkeypatch.setattr(
        validate_stage, "run_session", AsyncMock(side_effect=fake_run_session)
    )
    result = await validate_stage.run(
        run_id=run_id,
        repo=isolated_db,
        cfg=_minimal_cfg(isolated_db),
        session_factory=st_session.session_factory(),
    )
    assert result.findings_errored == 1
    with st_session.session_scope() as s:
        f = s.execute(
            select(Finding).where(Finding.run_id == run_id)
        ).scalar_one()
        assert f.status == "pending_validation"
        sess = s.execute(
            select(AgentSession).where(AgentSession.stage == "validate")
        ).scalar_one()
        assert sess.outcome == "errored"
        assert sess.error_text == "network unreachable"


@pytest.mark.asyncio
async def test_validate_stage_completed_session_with_call_flips_status(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Happy path: the simulated agent calls validate_finding inside the
    stubbed session, so the validations row gets written and the finding's
    status flips. The stage reads the validation row to count verdicts."""
    run_id, ids = _seed_run_with_findings(severities=["high"])
    finding_id = ids[0]

    # The stubbed runtime invokes validate_finding directly (mimicking
    # the in-process MCP tool invocation that the real SDK would do).
    captured_agent_session_ids: list[str] = []

    async def fake_run_session(**kw: object) -> SessionResult:
        # The stage pre-allocates an agent_session_id and passes it to
        # run_session alongside task_id / finding_id (parity with the
        # rest of the runtime kwargs; the runtime accepts and discards it).
        # We pull it off the kwargs so the stub can mimic the real
        # validate_finding tool's closed-over agent_session_id.
        agent_session_id = kw.get("agent_session_id")
        assert agent_session_id is not None, (
            "stages/validate.py must pass agent_session_id to run_session "
            "so the validate_finding tool wrapper closes over it"
        )
        captured_agent_session_ids.append(str(agent_session_id))
        # Simulate the model calling validate_finding mid-session.
        validate_finding(
            ValidateFindingInput(
                finding_id=finding_id,
                verdict="confirmed",
                rationale=(
                    "reproduced via running the PoC; "
                    "exit code 0, expected stdout observed"
                ),
                evidence_files=["src/0.py"],
            ),
            run_id=str(kw["run_id"]),
            agent_session_id=str(agent_session_id),
        )
        return SessionResult(
            outcome="completed",
            input_tokens=120,
            output_tokens=80,
            cache_read_tokens=0,
            cache_write_tokens=0,
            duration_ms=2000,
            tool_calls_count=1,
            refusal_text=None,
            error_text=None,
        )

    monkeypatch.setattr(
        validate_stage, "run_session", AsyncMock(side_effect=fake_run_session)
    )

    result = await validate_stage.run(
        run_id=run_id,
        repo=isolated_db,
        cfg=_minimal_cfg(isolated_db),
        session_factory=st_session.session_factory(),
    )
    assert result.findings_processed == 1
    assert result.findings_confirmed == 1
    assert result.findings_no_verdict == 0
    with st_session.session_scope() as s:
        f = s.get(Finding, finding_id)
        assert f is not None
        assert f.status == "confirmed"
        assert f.validated_at is not None
        v = s.execute(
            select(Validation).where(Validation.finding_id == finding_id)
        ).scalar_one()
        assert v.verdict == "confirmed"
        # The agent_session_id on the validation row matches the one
        # the stage emitted for this Validator session.
        assert v.agent_session_id in captured_agent_session_ids


@pytest.mark.asyncio
async def test_validate_stage_skips_findings_not_in_pending_validation(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Already-validated or rejected findings are NOT re-processed."""
    run_id, _ = _seed_run_with_findings(
        severities=["high", "medium", "low"],
        statuses=["confirmed", "pending_validation", "rejected"],
    )
    seen: list[str] = []

    async def fake_run_session(**kw: object) -> SessionResult:
        seen.append(str(kw["finding_id"]))
        return SessionResult(
            outcome="completed",
            input_tokens=100,
            output_tokens=50,
            cache_read_tokens=0,
            cache_write_tokens=0,
            duration_ms=1000,
            tool_calls_count=0,
            refusal_text=None,
            error_text=None,
        )

    monkeypatch.setattr(
        validate_stage, "run_session", AsyncMock(side_effect=fake_run_session)
    )
    result = await validate_stage.run(
        run_id=run_id,
        repo=isolated_db,
        cfg=_minimal_cfg(isolated_db),
        session_factory=st_session.session_factory(),
    )
    # Only the one pending_validation finding got processed.
    assert result.findings_processed == 1
    assert len(seen) == 1


@pytest.mark.asyncio
async def test_validate_stage_empty_run_returns_skipped_result(
    isolated_db: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id = str(ULID())
    with st_session.session_scope() as s:
        s.add(
            Run(
                id=run_id,
                target_repo_path="/tmp/x",
                target_repo_sha=None,
                depth="standard",
                budget_total=20,
                budget_used=0,
                started_at=_now_iso(),
                status="running",
                config_json="{}",
                flosswing_version="0.6.0",
            )
        )
    result = await validate_stage.run(
        run_id=run_id,
        repo=isolated_db,
        cfg=_minimal_cfg(isolated_db),
        session_factory=st_session.session_factory(),
    )
    assert result.findings_processed == 0


@pytest.mark.asyncio
async def test_validate_tool_builder_registers_all_eight_tools(
    isolated_db: Path,
) -> None:
    """Per design decision #1 (UPSIZED): full per-matrix scope is 8 tools."""
    tools = validate_stage._build_validate_tools(
        repo_root=isolated_db,
        run_id="01RUN",
        finding_id="01FIND",
        agent_session_id="01SESS",
    )
    assert len(tools) == 8
    tool_names = {
        getattr(t, "name", None) or getattr(t, "__name__", "")
        for t in tools
    }
    assert tool_names == {
        "read_file",
        "list_dir",
        "grep",
        "find_definition",
        "find_callers",
        "compile_and_run",
        "query_findings",
        "validate_finding",
    }
    # record_finding is NOT registered for Validate (defence in depth
    # per spec § "Defence-in-depth: record_finding is not in Validate's
    # scope").
    assert "record_finding" not in tool_names


def test_validate_prompt_includes_hardcoded_secrets_disqualifiers() -> None:
    from flosswing.stages.validate import _compose_user_prompt
    from flosswing.state.models import Finding

    f = Finding(
        id="01F", run_id="01R", hunt_task_id="01H",
        attack_class="hardcoded_secrets", file="docker-compose.yml",
        line_start=1, line_end=1, severity="high", confidence="likely",
        status="pending_validation", title="t",
        description="d" * 60, created_at="2026-07-16T00:00:00Z",
    )
    prompt = _compose_user_prompt(f)
    assert "Disqualifiers" in prompt or "placeholder" in prompt.lower()


def test_gate_downgrades_dev_default_secret(isolated_db: Path) -> None:
    """Per spec § Part C: a confirmed hardcoded_secrets finding whose value
    is an obvious dev default (docker-compose.yml, sentinel value) gets its
    severity downgraded to info. Status never changes.

    Reuses _seed_run_with_findings to satisfy the Run/HuntTask FKs, then
    flips the seeded finding's fields to the shape under test (see task
    brief note: insert a matching Run row first / reuse the helper)."""
    from flosswing.stages.validate import _maybe_downgrade_secret
    from flosswing.state.models import Finding

    (isolated_db / "docker-compose.yml").write_text(
        "services:\n  es:\n    environment:\n      ELASTIC_PASSWORD: devpass\n",
        encoding="utf-8",
    )
    _run_id, finding_ids = _seed_run_with_findings(
        severities=["high"], statuses=["confirmed"]
    )
    finding_id = finding_ids[0]
    with st_session.session_scope() as s:
        f = s.get(Finding, finding_id)
        assert f is not None
        f.attack_class = "hardcoded_secrets"
        f.file = "docker-compose.yml"
        f.line_start = 4
        f.line_end = 4

    _maybe_downgrade_secret(finding_id, isolated_db)

    with st_session.session_scope() as s:
        f = s.get(Finding, finding_id)
        assert f is not None
        assert f.severity == "info"
        assert f.status == "confirmed"  # never changes status
        assert "secrets_triage" in (f.root_cause_summary or "")


def test_gate_does_not_raise_on_nul_byte_in_path(isolated_db: Path) -> None:
    """Per final-fix-brief Fix 2: `_read_source_span` and the `evidence`
    construction must run INSIDE the fail-open try/except, so a
    non-OSError (e.g. ValueError: embedded null byte, raised when the
    Hunt-agent-influenced `finding.file` contains a NUL) does not escape
    and crash the Validate stage. Severity is left unchanged."""
    from flosswing.stages.validate import _maybe_downgrade_secret
    from flosswing.state.models import Finding

    _run_id, finding_ids = _seed_run_with_findings(
        severities=["high"], statuses=["confirmed"]
    )
    finding_id = finding_ids[0]
    with st_session.session_scope() as s:
        f = s.get(Finding, finding_id)
        assert f is not None
        f.attack_class = "hardcoded_secrets"
        f.file = "a\x00b.py"
        f.line_start = 1
        f.line_end = 1

    # Must not raise.
    _maybe_downgrade_secret(finding_id, isolated_db)

    with st_session.session_scope() as s:
        f = s.get(Finding, finding_id)
        assert f is not None
        assert f.severity == "high"  # unchanged
        assert f.status == "confirmed"  # unchanged


def test_gate_leaves_real_secret_and_other_classes(isolated_db: Path) -> None:
    """A confirmed hardcoded_secrets finding on a real high-entropy secret in
    a prod .py file, and a confirmed sqli finding, are both left untouched by
    the gate."""
    from flosswing.stages.validate import _maybe_downgrade_secret
    from flosswing.state.models import Finding

    (isolated_db / "prod.py").write_text(
        'API_KEY = "a9F3k1Lz8Qw2Rt7Yb4Xc6Vn0Ms5Pd3Hj1Gf9Kd2"\n', encoding="utf-8"
    )
    (isolated_db / "docker-compose.yml").write_text(
        "services:\n  db:\n    image: postgres\n", encoding="utf-8"
    )
    _run_id, finding_ids = _seed_run_with_findings(
        severities=["high", "high"], statuses=["confirmed", "confirmed"]
    )
    real_id, sqli_id = finding_ids
    with st_session.session_scope() as s:
        real = s.get(Finding, real_id)
        assert real is not None
        real.attack_class = "hardcoded_secrets"
        real.file = "prod.py"
        real.line_start = 1
        real.line_end = 1

        sqli = s.get(Finding, sqli_id)
        assert sqli is not None
        sqli.attack_class = "sqli"
        sqli.file = "docker-compose.yml"
        sqli.line_start = 1
        sqli.line_end = 1

    _maybe_downgrade_secret(real_id, isolated_db)
    _maybe_downgrade_secret(sqli_id, isolated_db)

    with st_session.session_scope() as s:
        f_real = s.get(Finding, real_id)
        f_sqli = s.get(Finding, sqli_id)
        assert f_real is not None
        assert f_sqli is not None
        assert f_real.severity == "high"
        assert f_sqli.severity == "high"
