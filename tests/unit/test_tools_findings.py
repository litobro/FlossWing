"""tools/findings.py: state-writing tool implementations."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest
from ulid import ULID

from flosswing.errors import (
    FlosswingError,
    InvalidAttackClassError,
    ReconAlreadyRecordedError,
)
from flosswing.state import session as st_session
from flosswing.state.models import Finding, HuntTask, ReconArtifact, Run
from flosswing.tools.findings import (
    AddHuntTaskInput,
    RecordFindingInput,
    RecordReconArtifactInput,
    add_hunt_task,
    record_finding,
    record_recon_artifact,
)


@pytest.fixture()
def fresh_db(monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    monkeypatch.setenv("FLOSSWING_DB_URL", "sqlite:///:memory:")
    st_session._cached_engine = None  # type: ignore[attr-defined]
    st_session._cached_session_factory = None  # type: ignore[attr-defined]
    run_id = str(ULID())
    with st_session.session_scope() as s:
        s.add(
            Run(
                id=run_id,
                target_repo_path="/tmp/x",
                depth="standard",
                budget_total=20,
                started_at="2026-05-25T00:00:00Z",
                config_json="{}",
                flosswing_version="0.2.0",
            )
        )
    yield run_id
    st_session._cached_engine = None  # type: ignore[attr-defined]
    st_session._cached_session_factory = None  # type: ignore[attr-defined]


def test_record_recon_artifact_writes_row(fresh_db: str) -> None:
    out = record_recon_artifact(
        RecordReconArtifactInput(
            languages=["python"],
            build_commands={"primary": "pip install ."},
            entry_points=[],
            trust_boundaries=[],
            subsystems=[],
            notes="hello",
        ),
        run_id=fresh_db,
    )
    assert out.artifact_id
    with st_session.session_scope() as s:
        rows = s.query(ReconArtifact).all()
        assert len(rows) == 1
        assert json.loads(rows[0].languages_json) == ["python"]


def test_record_recon_artifact_twice_raises(fresh_db: str) -> None:
    inp = RecordReconArtifactInput(
        languages=["python"],
        build_commands={},
        entry_points=[],
        trust_boundaries=[],
        subsystems=[],
        notes="",
    )
    record_recon_artifact(inp, run_id=fresh_db)
    with pytest.raises(ReconAlreadyRecordedError):
        record_recon_artifact(inp, run_id=fresh_db)


def test_add_hunt_task_accepts_valid(fresh_db: str) -> None:
    out = add_hunt_task(
        AddHuntTaskInput(
            attack_class="command_injection",
            scope_hint="src/cli/exec.py",
            rationale="user input flows here",
        ),
        run_id=fresh_db,
        source="recon",
        budget_total=20,
    )
    assert out.accepted is True
    assert out.task_id
    with st_session.session_scope() as s:
        assert s.query(HuntTask).count() == 1


def test_add_hunt_task_rejects_invalid_class(fresh_db: str) -> None:
    with pytest.raises(InvalidAttackClassError):
        add_hunt_task(
            AddHuntTaskInput(
                attack_class="not_a_real_class",
                scope_hint="src/",
                rationale="",
            ),
            run_id=fresh_db,
            source="recon",
            budget_total=20,
        )


def test_add_hunt_task_budget_exhausted(fresh_db: str) -> None:
    for i in range(3):
        add_hunt_task(
            AddHuntTaskInput(
                attack_class="sqli",
                scope_hint=f"file{i}.py",
                rationale="",
            ),
            run_id=fresh_db,
            source="recon",
            budget_total=3,
        )
    out = add_hunt_task(
        AddHuntTaskInput(
            attack_class="sqli",
            scope_hint="overflow.py",
            rationale="",
        ),
        run_id=fresh_db,
        source="recon",
        budget_total=3,
    )
    assert out.accepted is False
    assert out.reason


# -----------------------------------------------------------------------------
# record_finding cases (v0.3) — per docs/specs/2026-06-02-v0.3-hunt-plumbing-design.md
# § Testing strategy.
# -----------------------------------------------------------------------------


@pytest.fixture()
def fresh_db_with_task(
    fresh_db: str, tmp_path: Path
) -> Iterator[tuple[str, str, Path]]:
    """Reuse fresh_db; seed one hunt_task and return (run_id, task_id, repo_root)."""
    repo_root = tmp_path / "repo"
    (repo_root / "src").mkdir(parents=True)
    (repo_root / "src" / "exec.py").write_text(
        "def run(name):\n    return name\n",
        encoding="utf-8",
    )
    out = add_hunt_task(
        AddHuntTaskInput(
            attack_class="command_injection",
            scope_hint="src/exec.py",
            rationale="user input flows to shell",
        ),
        run_id=fresh_db,
        source="recon",
        budget_total=20,
    )
    assert out.accepted
    yield fresh_db, out.task_id, repo_root


def _base_input(file: str = "src/exec.py") -> RecordFindingInput:
    return RecordFindingInput(
        attack_class="command_injection",
        file=file,
        function="run",
        line_start=3,
        line_end=3,
        severity="high",
        confidence="likely",
        title="user-controlled string flows to shell sink",
        description=(
            "The `name` parameter reaches the shell-invoking subprocess API "
            "without escaping; a caller can inject arbitrary commands."
        ),
        poc_code="run('; touch /tmp/pwn ;')",
        suggested_fix="Pass argv list instead of building a shell string.",
    )


def test_record_finding_happy_path_likely(
    fresh_db_with_task: tuple[str, str, Path],
) -> None:
    run_id, task_id, repo_root = fresh_db_with_task
    out = record_finding(_base_input(), run_id=run_id, hunt_task_id=task_id, repo_root=repo_root)
    assert out.finding_id
    assert out.duplicate_of is None
    with st_session.session_scope() as s:
        rows = s.query(Finding).all()
        assert len(rows) == 1
        assert rows[0].confidence == "likely"
        assert rows[0].hunt_task_id == task_id
        assert rows[0].status == "pending_validation"


def test_record_finding_happy_path_speculative(
    fresh_db_with_task: tuple[str, str, Path],
) -> None:
    run_id, task_id, repo_root = fresh_db_with_task
    inp = _base_input().model_copy(update={"confidence": "speculative"})
    out = record_finding(inp, run_id=run_id, hunt_task_id=task_id, repo_root=repo_root)
    assert out.finding_id
    with st_session.session_scope() as s:
        assert s.query(Finding).count() == 1


def test_record_finding_invalid_attack_class(
    fresh_db_with_task: tuple[str, str, Path],
) -> None:
    run_id, task_id, repo_root = fresh_db_with_task
    inp = _base_input().model_copy(update={"attack_class": "not_a_real_class"})
    with pytest.raises(InvalidAttackClassError):
        record_finding(inp, run_id=run_id, hunt_task_id=task_id, repo_root=repo_root)


def test_record_finding_path_not_in_repo(
    fresh_db_with_task: tuple[str, str, Path],
) -> None:
    run_id, task_id, repo_root = fresh_db_with_task
    inp = _base_input().model_copy(update={"file": "../escape.py"})
    with pytest.raises(FlosswingError) as exc:
        record_finding(inp, run_id=run_id, hunt_task_id=task_id, repo_root=repo_root)
    assert exc.value.code == "path_not_in_repo"


def test_record_finding_line_range_invalid_start_zero(
    fresh_db_with_task: tuple[str, str, Path],
) -> None:
    run_id, task_id, repo_root = fresh_db_with_task
    inp = _base_input().model_copy(update={"line_start": 0, "line_end": 1})
    with pytest.raises(FlosswingError) as exc:
        record_finding(inp, run_id=run_id, hunt_task_id=task_id, repo_root=repo_root)
    assert exc.value.code == "line_range_invalid"


def test_record_finding_line_range_invalid_end_before_start(
    fresh_db_with_task: tuple[str, str, Path],
) -> None:
    run_id, task_id, repo_root = fresh_db_with_task
    inp = _base_input().model_copy(update={"line_start": 10, "line_end": 5})
    with pytest.raises(FlosswingError) as exc:
        record_finding(inp, run_id=run_id, hunt_task_id=task_id, repo_root=repo_root)
    assert exc.value.code == "line_range_invalid"


def test_record_finding_confirmed_without_evidence_raises(
    fresh_db_with_task: tuple[str, str, Path],
) -> None:
    run_id, task_id, repo_root = fresh_db_with_task
    inp = _base_input().model_copy(
        update={
            "confidence": "confirmed",
            "description": "",
            "poc_code": None,
        }
    )
    with pytest.raises(FlosswingError) as exc:
        record_finding(inp, run_id=run_id, hunt_task_id=task_id, repo_root=repo_root)
    assert exc.value.code == "description_required_for_confirmed"


def test_record_finding_increments_hunt_task_findings_count(
    fresh_db_with_task: tuple[str, str, Path],
) -> None:
    run_id, task_id, repo_root = fresh_db_with_task
    for i in range(3):
        inp = _base_input().model_copy(update={"title": f"finding {i}"})
        record_finding(inp, run_id=run_id, hunt_task_id=task_id, repo_root=repo_root)
    with st_session.session_scope() as s:
        task = s.get(HuntTask, task_id)
        assert task is not None
        assert task.findings_count == 3


def test_record_finding_description_too_large(
    fresh_db_with_task: tuple[str, str, Path],
) -> None:
    run_id, task_id, repo_root = fresh_db_with_task
    big = "x" * (65 * 1024)
    inp = _base_input().model_copy(update={"description": big})
    with pytest.raises(FlosswingError) as exc:
        record_finding(inp, run_id=run_id, hunt_task_id=task_id, repo_root=repo_root)
    assert exc.value.code == "description_too_large"


def test_record_finding_suggested_fix_too_large(
    fresh_db_with_task: tuple[str, str, Path],
) -> None:
    run_id, task_id, repo_root = fresh_db_with_task
    big = "y" * (65 * 1024)
    inp = _base_input().model_copy(update={"suggested_fix": big})
    with pytest.raises(FlosswingError) as exc:
        record_finding(inp, run_id=run_id, hunt_task_id=task_id, repo_root=repo_root)
    assert exc.value.code == "suggested_fix_too_large"


# ==============================================================================
# v0.6: query_findings (Validate-side; also Dedupe/Trace later) and
# validate_finding (Validate-side write).
#
# Per docs/tool-contracts.md § findings (Validate-side) and
# docs/plans/2026-06-02-v0.6-validate.md Task 4. Per the operator override
# on 2026-06-03 (plan preamble decision #3), the 64 KB byte-level cap on
# evidence_files_json is NOT implemented — only the 100-entry list cap
# ships. The originally-planned `evidence_files_too_large` test is omitted.
# ==============================================================================

from datetime import UTC, datetime  # noqa: E402

from sqlalchemy import select  # noqa: E402

from flosswing.errors import (  # noqa: E402
    EvidenceFilesTooManyError,
    FindingAlreadyValidatedError,
    FindingNotFoundError,
    RationaleTooShortError,
)
from flosswing.state.models import AgentSession, Validation  # noqa: E402
from flosswing.tools.findings import (  # noqa: E402
    QueryFindingsInput,
    QueryFindingsOutput,
    ValidateFindingInput,
    ValidateFindingOutput,
    query_findings,
    validate_finding,
)


@pytest.fixture()
def isolated_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("FLOSSWING_DB_URL", f"sqlite:///{tmp_path}/state.db")
    monkeypatch.setattr(st_session, "_cached_engine", None, raising=False)
    monkeypatch.setattr(
        st_session, "_cached_session_factory", None, raising=False
    )
    return tmp_path


def _now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _seed_run_with_findings(
    *,
    attack_classes: list[str],
    files: list[str],
    severities: list[str],
    statuses: list[str] | None = None,
) -> tuple[str, list[str]]:
    """Build a Run + HuntTask + N findings; return (run_id, [finding_ids])."""
    if statuses is None:
        statuses = ["pending_validation"] * len(attack_classes)
    run_id = str(ULID())
    task_id = str(ULID())
    finding_ids: list[str] = []
    # Use separate session_scopes per FK level: SQLAlchemy without explicit
    # relationship() hints can't infer Run -> HuntTask -> Finding ordering,
    # and SQLite FK enforcement is on, so a single flush sometimes fails.
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
                created_at=_now_iso(),
                started_at=_now_iso(),
                finished_at=_now_iso(),
                findings_count=len(attack_classes),
            )
        )
    with st_session.session_scope() as s:
        for ac, f, sev, st in zip(
            attack_classes, files, severities, statuses, strict=True
        ):
            fid = str(ULID())
            finding_ids.append(fid)
            s.add(
                Finding(
                    id=fid,
                    run_id=run_id,
                    hunt_task_id=task_id,
                    attack_class=ac,
                    file=f,
                    function="some_fn",
                    line_start=10,
                    line_end=12,
                    severity=sev,
                    confidence="likely",
                    status=st,
                    title=f"{ac} in {f}",
                    description=(
                        "A reasonable description, fifty chars or more."
                    ),
                    poc_code=None,
                    poc_result_json=None,
                    suggested_fix=None,
                    created_at=_now_iso(),
                )
            )
    return run_id, finding_ids


def test_query_findings_happy_path_returns_all_findings(
    isolated_db: Path,
) -> None:
    run_id, _ = _seed_run_with_findings(
        attack_classes=["command_injection", "ssrf", "path_traversal"],
        files=["a.py", "b.py", "c.py"],
        severities=["high", "medium", "low"],
    )
    out = query_findings(QueryFindingsInput(), run_id=run_id)
    assert isinstance(out, QueryFindingsOutput)
    assert len(out.findings) == 3
    assert out.truncated is False
    assert {f.attack_class for f in out.findings} == {
        "command_injection",
        "ssrf",
        "path_traversal",
    }


def test_query_findings_filter_by_finding_id(isolated_db: Path) -> None:
    run_id, ids = _seed_run_with_findings(
        attack_classes=["command_injection", "ssrf"],
        files=["a.py", "b.py"],
        severities=["high", "medium"],
    )
    target = ids[1]
    out = query_findings(
        QueryFindingsInput(finding_id=target), run_id=run_id
    )
    assert len(out.findings) == 1
    assert out.findings[0].finding_id == target


def test_query_findings_filter_by_attack_class(isolated_db: Path) -> None:
    run_id, _ = _seed_run_with_findings(
        attack_classes=["command_injection", "ssrf", "command_injection"],
        files=["a.py", "b.py", "c.py"],
        severities=["high", "medium", "low"],
    )
    out = query_findings(
        QueryFindingsInput(attack_class="command_injection"), run_id=run_id
    )
    assert len(out.findings) == 2
    assert all(f.attack_class == "command_injection" for f in out.findings)


def test_query_findings_filter_by_file(isolated_db: Path) -> None:
    run_id, _ = _seed_run_with_findings(
        attack_classes=["command_injection", "ssrf"],
        files=["src/a.py", "src/b.py"],
        severities=["high", "medium"],
    )
    out = query_findings(
        QueryFindingsInput(file="src/b.py"), run_id=run_id
    )
    assert len(out.findings) == 1
    assert out.findings[0].file == "src/b.py"


def test_query_findings_filter_by_status(isolated_db: Path) -> None:
    run_id, _ = _seed_run_with_findings(
        attack_classes=["command_injection", "ssrf"],
        files=["a.py", "b.py"],
        severities=["high", "medium"],
        statuses=["pending_validation", "confirmed"],
    )
    out_p = query_findings(
        QueryFindingsInput(status="pending_validation"), run_id=run_id
    )
    out_c = query_findings(
        QueryFindingsInput(status="confirmed"), run_id=run_id
    )
    assert len(out_p.findings) == 1
    assert len(out_c.findings) == 1
    assert out_p.findings[0].status == "pending_validation"
    assert out_c.findings[0].status == "confirmed"


def test_query_findings_filter_by_min_severity(isolated_db: Path) -> None:
    run_id, _ = _seed_run_with_findings(
        attack_classes=["command_injection", "ssrf", "path_traversal", "xss"],
        files=["a.py", "b.py", "c.py", "d.py"],
        severities=["critical", "high", "medium", "low"],
    )
    out = query_findings(
        QueryFindingsInput(min_severity="high"), run_id=run_id
    )
    assert {f.severity for f in out.findings} == {"critical", "high"}


def test_query_findings_cross_run_isolation(isolated_db: Path) -> None:
    """A query under run_id=A must not return rows from run_id=B."""
    run_a, _ = _seed_run_with_findings(
        attack_classes=["command_injection"],
        files=["a.py"],
        severities=["high"],
    )
    run_b, _ = _seed_run_with_findings(
        attack_classes=["ssrf"],
        files=["b.py"],
        severities=["medium"],
    )
    out_a = query_findings(QueryFindingsInput(), run_id=run_a)
    out_b = query_findings(QueryFindingsInput(), run_id=run_b)
    assert {f.attack_class for f in out_a.findings} == {"command_injection"}
    assert {f.attack_class for f in out_b.findings} == {"ssrf"}


def test_query_findings_truncation_at_cap(isolated_db: Path) -> None:
    """Plan-time decision #4: cap=100 rows; truncated=True when hit."""
    run_id, _ = _seed_run_with_findings(
        attack_classes=["command_injection"] * 150,
        files=[f"f{i}.py" for i in range(150)],
        severities=["high"] * 150,
    )
    out = query_findings(QueryFindingsInput(), run_id=run_id)
    assert out.truncated is True
    assert len(out.findings) == 100


def test_query_findings_has_poc_result_is_computed_bool(
    isolated_db: Path,
) -> None:
    """has_poc_result is a derived bool over poc_result_json IS NOT NULL."""
    run_id, ids = _seed_run_with_findings(
        attack_classes=["command_injection"],
        files=["a.py"],
        severities=["high"],
    )
    # Mutate: give one finding a poc_result_json blob.
    with st_session.session_scope() as s:
        f = s.get(Finding, ids[0])
        assert f is not None
        f.poc_result_json = json.dumps({"exit_code": 0})
    out = query_findings(QueryFindingsInput(), run_id=run_id)
    assert out.findings[0].has_poc_result is True
    # Sanity: the JSON blob is NOT in the Finding row.
    assert not hasattr(out.findings[0], "poc_result_json")


def _make_validate_session(run_id: str) -> str:
    """Insert an agent_sessions row representing the in-flight Validate session.

    validate_finding requires this row to exist so its FK can be satisfied.
    """
    sid = str(ULID())
    with st_session.session_scope() as s:
        s.add(
            AgentSession(
                id=sid,
                run_id=run_id,
                stage="validate",
                task_id=None,
                finding_id=None,
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


@pytest.mark.parametrize("verdict", ["confirmed", "rejected", "uncertain"])
def test_validate_finding_happy_path_writes_validation_and_flips_status(
    isolated_db: Path, verdict: str,
) -> None:
    run_id, ids = _seed_run_with_findings(
        attack_classes=["command_injection"],
        files=["src/a.py"],
        severities=["high"],
    )
    finding_id = ids[0]
    agent_session_id = _make_validate_session(run_id)

    out = validate_finding(
        ValidateFindingInput(
            finding_id=finding_id,
            verdict=verdict,  # type: ignore[arg-type]
            rationale="x" * 60,
            evidence_files=["src/a.py"],
        ),
        run_id=run_id,
        agent_session_id=agent_session_id,
    )
    assert isinstance(out, ValidateFindingOutput)
    assert out.finding_id == finding_id
    assert out.new_status == verdict

    with st_session.session_scope() as s:
        f = s.get(Finding, finding_id)
        assert f is not None
        assert f.status == verdict
        assert f.validated_at is not None
        v = s.execute(
            select(Validation).where(Validation.finding_id == finding_id)
        ).scalar_one()
        assert v.verdict == verdict
        assert v.rationale == "x" * 60
        assert v.evidence_files_json == json.dumps(["src/a.py"])
        assert v.agent_session_id == agent_session_id


def test_validate_finding_raises_finding_not_found(isolated_db: Path) -> None:
    run_id, _ = _seed_run_with_findings(
        attack_classes=["command_injection"],
        files=["a.py"],
        severities=["high"],
    )
    agent_session_id = _make_validate_session(run_id)
    with pytest.raises(FindingNotFoundError):
        validate_finding(
            ValidateFindingInput(
                finding_id="01BOGUSBOGUSBOGUSBOGUSBOGU",
                verdict="confirmed",
                rationale="x" * 60,
                evidence_files=[],
            ),
            run_id=run_id,
            agent_session_id=agent_session_id,
        )


def test_validate_finding_raises_finding_not_found_for_other_run(
    isolated_db: Path,
) -> None:
    """Cross-run isolation: a finding under run B is invisible to run A."""
    run_a, _ = _seed_run_with_findings(
        attack_classes=["command_injection"],
        files=["a.py"],
        severities=["high"],
    )
    _run_b, ids_b = _seed_run_with_findings(
        attack_classes=["ssrf"],
        files=["b.py"],
        severities=["medium"],
    )
    agent_session_id = _make_validate_session(run_a)
    with pytest.raises(FindingNotFoundError):
        validate_finding(
            ValidateFindingInput(
                finding_id=ids_b[0],
                verdict="confirmed",
                rationale="x" * 60,
                evidence_files=[],
            ),
            run_id=run_a,  # querying under A; finding is in B
            agent_session_id=agent_session_id,
        )


def test_validate_finding_raises_finding_already_validated(
    isolated_db: Path,
) -> None:
    run_id, ids = _seed_run_with_findings(
        attack_classes=["command_injection"],
        files=["a.py"],
        severities=["high"],
    )
    finding_id = ids[0]
    agent_session_id = _make_validate_session(run_id)
    validate_finding(
        ValidateFindingInput(
            finding_id=finding_id,
            verdict="confirmed",
            rationale="x" * 60,
            evidence_files=[],
        ),
        run_id=run_id,
        agent_session_id=agent_session_id,
    )
    with pytest.raises(FindingAlreadyValidatedError):
        validate_finding(
            ValidateFindingInput(
                finding_id=finding_id,
                verdict="rejected",
                rationale="y" * 60,
                evidence_files=[],
            ),
            run_id=run_id,
            agent_session_id=agent_session_id,
        )


def test_validate_finding_raises_rationale_too_short(
    isolated_db: Path,
) -> None:
    run_id, ids = _seed_run_with_findings(
        attack_classes=["command_injection"],
        files=["a.py"],
        severities=["high"],
    )
    agent_session_id = _make_validate_session(run_id)
    with pytest.raises(RationaleTooShortError):
        validate_finding(
            ValidateFindingInput(
                finding_id=ids[0],
                verdict="confirmed",
                rationale="too short",  # 9 chars < 50
                evidence_files=[],
            ),
            run_id=run_id,
            agent_session_id=agent_session_id,
        )


def test_validate_finding_raises_evidence_files_too_many(
    isolated_db: Path,
) -> None:
    run_id, ids = _seed_run_with_findings(
        attack_classes=["command_injection"],
        files=["a.py"],
        severities=["high"],
    )
    agent_session_id = _make_validate_session(run_id)
    too_many = [f"f{i}.py" for i in range(101)]
    with pytest.raises(EvidenceFilesTooManyError):
        validate_finding(
            ValidateFindingInput(
                finding_id=ids[0],
                verdict="confirmed",
                rationale="x" * 60,
                evidence_files=too_many,
            ),
            run_id=run_id,
            agent_session_id=agent_session_id,
        )


def test_validate_finding_default_evidence_files_serializes_empty_array(
    isolated_db: Path,
) -> None:
    """evidence_files defaults to []; the DB column gets '[]', not NULL."""
    run_id, ids = _seed_run_with_findings(
        attack_classes=["command_injection"],
        files=["a.py"],
        severities=["high"],
    )
    agent_session_id = _make_validate_session(run_id)
    validate_finding(
        ValidateFindingInput(
            finding_id=ids[0],
            verdict="uncertain",
            rationale=(
                "A reasonably-sized rationale of at least fifty chars long."
            ),
        ),
        run_id=run_id,
        agent_session_id=agent_session_id,
    )
    with st_session.session_scope() as s:
        v = s.execute(
            select(Validation).where(Validation.finding_id == ids[0])
        ).scalar_one()
        assert v.evidence_files_json == "[]"
