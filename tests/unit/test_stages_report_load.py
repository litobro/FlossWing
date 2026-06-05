"""flosswing.stages.report._load — DB → ReportV1 projection.

Per docs/specs/2026-06-02-v1.0-report-design.md § Architecture and
§ JSON schema — ReportV1. The loader runs a single session_scope() block,
snapshots ORM attrs as Pydantic models, then returns a deterministic
ReportV1.

Covers: happy path with full join coverage (Validation + Trace +
DedupeCluster), empty findings list, sort order (severity desc, then
reachability, then ULID asc), graceful degradation when optional rows are
absent, RunNotFoundError for unknown run_id, and rendered_at ISO format.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from ulid import ULID

from flosswing.errors import RunNotFoundError
from flosswing.stages import report as report_stage
from flosswing.state import session as st_session
from flosswing.state.models import (
    AgentSession,
    DedupeCluster,
    Finding,
    HuntTask,
    Run,
    Trace,
    Validation,
)


def _now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


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


# ---------------------------------------------------------------------------
# Seed helpers — split across session_scopes so each parent row commits
# before its children reference it (PRAGMA foreign_keys=ON enforced).
# ---------------------------------------------------------------------------


def _seed_run(
    run_id: str,
    *,
    status: str = "completed",
    config_json: str = '{"model": "claude-opus-4-7"}',
    budget_total: int = 100,
    budget_used: int = 25,
    target_repo_path: str = "/tmp/x",
) -> None:
    with st_session.session_scope() as s:
        s.add(
            Run(
                id=run_id,
                target_repo_path=target_repo_path,
                target_repo_sha=None,
                depth="standard",
                budget_total=budget_total,
                budget_used=budget_used,
                started_at=_now_iso(),
                finished_at=_now_iso(),
                status=status,
                config_json=config_json,
                flosswing_version="1.0.0",
            )
        )


def _seed_task(run_id: str) -> str:
    task_id = str(ULID())
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
                findings_count=0,
            )
        )
    return task_id


def _seed_finding(
    *,
    run_id: str,
    task_id: str,
    finding_id: str | None = None,
    attack_class: str = "command_injection",
    file: str = "src/a.py",
    function: str | None = "some_fn",
    line_start: int = 10,
    line_end: int = 12,
    severity: str = "high",
    confidence: str = "likely",
    status: str = "confirmed",
    title: str = "shell injection",
    description: str = (
        "A reasonable description, fifty chars or more for realism."
    ),
    poc_code: str | None = None,
    suggested_fix: str | None = None,
    reachable: str | None = None,
    dedupe_role: str | None = None,
    dedupe_cluster_id: str | None = None,
    primary_finding_id: str | None = None,
) -> str:
    fid = finding_id if finding_id is not None else str(ULID())
    with st_session.session_scope() as s:
        s.add(
            Finding(
                id=fid,
                run_id=run_id,
                hunt_task_id=task_id,
                attack_class=attack_class,
                file=file,
                function=function,
                line_start=line_start,
                line_end=line_end,
                severity=severity,
                confidence=confidence,
                status=status,
                title=title,
                description=description,
                poc_code=poc_code,
                poc_result_json=None,
                suggested_fix=suggested_fix,
                created_at=_now_iso(),
                reachable=reachable,
                dedupe_role=dedupe_role,
                dedupe_cluster_id=dedupe_cluster_id,
                primary_finding_id=primary_finding_id,
            )
        )
    return fid


def _seed_agent_session(
    *,
    run_id: str,
    finding_id: str | None = None,
    stage: str = "validate",
) -> str:
    sid = str(ULID())
    with st_session.session_scope() as s:
        s.add(
            AgentSession(
                id=sid,
                run_id=run_id,
                stage=stage,
                task_id=None,
                finding_id=finding_id,
                model="claude-opus-4-7",
                system_prompt_hash="0" * 64,
                input_tokens=100,
                output_tokens=50,
                cache_read_tokens=0,
                cache_write_tokens=0,
                cost_usd=0.01,
                duration_ms=1000,
                outcome="completed",
                refusal_text=None,
                error_text=None,
                tool_calls_count=2,
                started_at=_now_iso(),
                finished_at=_now_iso(),
            )
        )
    return sid


def _seed_validation(
    *, finding_id: str, agent_session_id: str, verdict: str = "confirmed"
) -> str:
    vid = str(ULID())
    with st_session.session_scope() as s:
        s.add(
            Validation(
                id=vid,
                finding_id=finding_id,
                verdict=verdict,
                rationale=(
                    "Rationale must be at least fifty chars to clear the cap."
                ),
                evidence_files_json='["src/a.py"]',
                agent_session_id=agent_session_id,
                created_at=_now_iso(),
            )
        )
    return vid


def _seed_trace(
    *,
    finding_id: str,
    agent_session_id: str,
    reachable: str = "reachable",
    entry_point_symbol: str | None = "main",
    call_chain_json: str = '[{"file": "src/a.py", "line": 10}]',
) -> str:
    tid = str(ULID())
    with st_session.session_scope() as s:
        s.add(
            Trace(
                id=tid,
                finding_id=finding_id,
                reachable=reachable,
                entry_point_symbol=entry_point_symbol,
                entry_point_id=None,
                call_chain_json=call_chain_json,
                rationale="Reachable from the CLI entry point.",
                agent_session_id=agent_session_id,
                created_at=_now_iso(),
            )
        )
    return tid


def _seed_dedupe_cluster(
    *,
    run_id: str,
    primary_finding_id: str,
    member_ids: list[str],
    root_cause_summary: str = (
        "All findings share the same unsanitised input variable."
    ),
) -> str:
    cluster_id = str(ULID())
    with st_session.session_scope() as s:
        s.add(
            DedupeCluster(
                id=cluster_id,
                run_id=run_id,
                primary_finding_id=primary_finding_id,
                root_cause_summary=root_cause_summary,
                created_at=_now_iso(),
                member_count=len(member_ids),
            )
        )
    with st_session.session_scope() as s:
        for fid in member_ids:
            row = s.get(Finding, fid)
            assert row is not None
            row.dedupe_cluster_id = cluster_id
    return cluster_id


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_load_happy_path_full_join(isolated_db: Path) -> None:
    """Three CONFIRMED findings each with Validation + Trace; one cluster.

    Asserts the projected ReportV1 has the run row, summary counts,
    findings (with their Validation + Trace + Dedupe attachments), and
    the dedupe_clusters list.
    """
    run_id = str(ULID())
    _seed_run(run_id)
    task_id = _seed_task(run_id)

    fid_a = _seed_finding(
        run_id=run_id, task_id=task_id, file="src/a.py",
        severity="critical", reachable="reachable",
    )
    fid_b = _seed_finding(
        run_id=run_id, task_id=task_id, file="src/b.py",
        severity="high", reachable="uncertain",
    )
    fid_c = _seed_finding(
        run_id=run_id, task_id=task_id, file="src/c.py",
        severity="medium", reachable="unreachable",
    )
    for fid in (fid_a, fid_b, fid_c):
        sid = _seed_agent_session(
            run_id=run_id, finding_id=fid, stage="validate",
        )
        _seed_validation(finding_id=fid, agent_session_id=sid)
        tsid = _seed_agent_session(
            run_id=run_id, finding_id=fid, stage="trace",
        )
        _seed_trace(finding_id=fid, agent_session_id=tsid)

    _seed_dedupe_cluster(
        run_id=run_id,
        primary_finding_id=fid_a,
        member_ids=[fid_a, fid_b, fid_c],
    )

    report = report_stage._load(
        run_id, st_session.session_factory()
    )

    assert report.schema_version == "1.0"
    assert report.run.id == run_id
    assert report.run.status == "completed"
    assert report.run.model == "claude-opus-4-7"
    assert report.run.budget_total == 100
    assert report.run.budget_used == 25
    assert report.summary.findings_total == 3
    assert report.summary.findings_confirmed == 3
    assert report.summary.clusters_total == 1
    assert report.summary.traces_total == 3
    assert report.summary.reachable_total == 1
    assert len(report.findings) == 3
    for rf in report.findings:
        assert rf.validation is not None
        assert rf.validation.verdict == "confirmed"
        assert rf.trace is not None
    assert len(report.dedupe_clusters) == 1
    assert report.dedupe_clusters[0].primary_finding_id == fid_a
    assert report.dedupe_clusters[0].member_count == 3


def test_load_empty_findings(isolated_db: Path) -> None:
    """A Run with zero findings projects to ReportV1 with empty lists."""
    run_id = str(ULID())
    _seed_run(run_id)

    report = report_stage._load(
        run_id, st_session.session_factory()
    )

    assert report.findings == []
    assert report.dedupe_clusters == []
    assert report.summary.findings_total == 0
    assert report.summary.findings_confirmed == 0
    assert report.summary.clusters_total == 0
    assert report.summary.traces_total == 0
    assert report.summary.reachable_total == 0
    assert report.summary.by_severity == {}
    assert report.summary.by_attack_class == {}


def test_load_sort_order(isolated_db: Path) -> None:
    """Severity desc, then reachability (reachable→uncertain→unreachable→NULL),
    then ULID asc as the deterministic tiebreaker.

    Two ULIDs are crafted by hand (low-then-high) for two findings that
    share severity AND reachability so the ULID-asc tiebreaker is
    exercised. The remaining findings live in distinct severity /
    reachability cells.
    """
    run_id = str(ULID())
    _seed_run(run_id)
    task_id = _seed_task(run_id)

    # Construct ulids so we can prove the third-axis sort.
    low_ulid = "01AAAAAAAAAAAAAAAAAAAAAAAA"
    high_ulid = "01ZZZZZZZZZZZZZZZZZZZZZZZZ"

    # Two findings sharing severity=high, reachable=reachable; ULID order
    # is the tiebreaker.
    _seed_finding(
        run_id=run_id, task_id=task_id, finding_id=high_ulid,
        severity="high", reachable="reachable", file="src/h-reach-z.py",
    )
    _seed_finding(
        run_id=run_id, task_id=task_id, finding_id=low_ulid,
        severity="high", reachable="reachable", file="src/h-reach-a.py",
    )
    # high + uncertain — comes after both reachable-high above.
    fid_high_uncertain = _seed_finding(
        run_id=run_id, task_id=task_id,
        severity="high", reachable="uncertain", file="src/h-unc.py",
    )
    # high + None reachable — comes after high+unreachable would, if any;
    # NULL reachable is last within severity.
    fid_high_null = _seed_finding(
        run_id=run_id, task_id=task_id,
        severity="high", reachable=None, file="src/h-null.py",
    )
    # critical (highest) — must come first regardless of reachability.
    fid_crit = _seed_finding(
        run_id=run_id, task_id=task_id,
        severity="critical", reachable=None, file="src/crit.py",
    )

    report = report_stage._load(
        run_id, st_session.session_factory()
    )

    ids_in_order = [f.id for f in report.findings]
    assert ids_in_order == [
        fid_crit,
        low_ulid,
        high_ulid,
        fid_high_uncertain,
        fid_high_null,
    ]


def test_load_missing_optional_rows_graceful(isolated_db: Path) -> None:
    """A finding with no Validation / Trace / DedupeCluster row projects
    to ReportFinding with those fields set to None."""
    run_id = str(ULID())
    _seed_run(run_id)
    task_id = _seed_task(run_id)
    fid = _seed_finding(run_id=run_id, task_id=task_id)

    report = report_stage._load(
        run_id, st_session.session_factory()
    )

    assert len(report.findings) == 1
    rf = report.findings[0]
    assert rf.id == fid
    assert rf.validation is None
    assert rf.trace is None
    assert rf.dedupe_cluster_id is None
    assert rf.primary_finding_id is None
    assert report.dedupe_clusters == []


def test_load_unknown_run_id_raises(isolated_db: Path) -> None:
    """Loader raises RunNotFoundError when the runs row is missing."""
    # No _seed_run — DB is migrated but empty.
    # Provoke engine init so the DB file is created.
    with st_session.session_scope() as _:
        pass
    bogus = str(ULID())
    with pytest.raises(RunNotFoundError) as excinfo:
        report_stage._load(bogus, st_session.session_factory())
    assert bogus in str(excinfo.value)


def test_load_rendered_at_is_iso_z(isolated_db: Path) -> None:
    """`rendered_at` is ISO-8601 UTC with the Z suffix."""
    run_id = str(ULID())
    _seed_run(run_id)
    report = report_stage._load(
        run_id, st_session.session_factory()
    )
    # Loose ISO Z form: 2026-06-04T12:34:56(.fff)Z
    pattern = re.compile(
        r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$"
    )
    assert pattern.match(report.rendered_at), report.rendered_at
