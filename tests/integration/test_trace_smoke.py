"""Gated integration smoke for the v0.9 Trace stage.

Gated by FLOSSWING_INTEGRATION=1.

Per docs/specs/2026-06-02-v0.9-trace-design.md § Success criteria and
docs/plans/2026-06-04-v0.9-trace.md § Task I. Asserts the full
Recon -> Hunt -> Validate -> Gapfill -> Dedupe -> Trace pipeline against
tests/corpus/v02_smoke/ produces:

- exactly one runs row with status='completed' and budget_used > 0;
- >= 1 findings row;
- >= 1 traces row with a valid reachable verdict, schema-consistent
  entry_point_symbol (NOT NULL when reachable='reachable' per
  ck_traces_reachable_has_entry_point), and findings.reachable mirrored
  from the traces row;
- >= 1 agent_sessions row with stage='trace', finding_id NOT NULL, and a
  terminal outcome;
- runs.config_json carrying trace_token_budget AND trace_max_depth.

A guard at the top of the assertion block sanity-checks the test's
premise: v02_smoke is expected to land >= 1 confirmed finding after
Validate. A run with zero confirmed findings would skip Trace entirely
(per orchestrator's `if dedupe_result.confirmed_primaries > 0:` gate),
which would make every trace assertion vacuously satisfied — that's a
silent regression we surface explicitly with a clear failure message.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from sqlalchemy import select

from flosswing.config import DEFAULT_MODEL, Config
from flosswing.orchestrator import run_scan
from flosswing.stages.report import ReportV1
from flosswing.state import session as st_session
from flosswing.state.models import AgentSession, Finding, Run, Trace

pytestmark = pytest.mark.skipif(
    os.environ.get("FLOSSWING_INTEGRATION") != "1",
    reason="integration test gated by FLOSSWING_INTEGRATION=1",
)

CORPUS_REPO = Path(__file__).parent.parent / "corpus" / "v02_smoke"


def _resolve_auth_env() -> dict[str, str]:
    """Pick up whichever auth mode the operator has configured.

    Delegates to flosswing.config.resolve() so the test gate matches
    production semantics exactly. Returns an empty dict if no auth
    path is available — the calling test then skips.
    """
    from pathlib import Path as _Path

    from flosswing import config as _cfg
    from flosswing.errors import AuthCredentialMissingError as _AuthMissing

    try:
        c = _cfg.resolve(
            repo_root=_Path("."),
            model=None,
            recon_token_budget=None,
            hunt_token_budget=None,
            validate_token_budget=None,
            gapfill_token_budget=None,
            dedupe_token_budget=None,
            trace_token_budget=None,
            trace_max_depth=None,
        )
    except _AuthMissing:
        return {}
    return dict(c.auth_env)


@pytest.mark.asyncio
async def test_trace_smoke_runs_end_to_end_against_v02_smoke(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    auth = _resolve_auth_env()
    if not auth:
        pytest.skip("no auth credentials available")
    monkeypatch.setenv("FLOSSWING_DB_URL", f"sqlite:///{tmp_path}/state.db")
    monkeypatch.setattr(st_session, "_cached_engine", None, raising=False)
    monkeypatch.setattr(
        st_session, "_cached_session_factory", None, raising=False
    )
    monkeypatch.setenv("HOME", str(tmp_path))

    # Modest budgets — this test consumes API credit. Matches the
    # 200_000-per-stage shape used by test_dedupe_smoke.py / test_gapfill_smoke.py.
    # trace_max_depth=8 matches the DEFAULT_TRACE_MAX_DEPTH default; pinned here
    # so the assertion on runs.config_json is independent of any future default
    # change.
    # auto_render=True and output_formats=["md", "json"] are the defaults
    # per docs/specs/2026-06-02-v1.0-report-design.md § Config, but pinned
    # here so the assertions on runs.config_json and on rendered artefacts
    # are independent of any future default change.
    # output_dir is pinned under tmp_path so pytest cleans it up; the
    # orchestrator's default would be ~/.flosswing/runs/<run_id>/output/.
    report_output_dir = tmp_path / "report-output"
    cfg = Config(
        repo_root=CORPUS_REPO.resolve(),
        model=DEFAULT_MODEL,
        recon_token_budget=200_000,
        hunt_token_budget=200_000,
        validate_token_budget=200_000,
        gapfill_token_budget=200_000,
        dedupe_token_budget=200_000,
        trace_token_budget=200_000,
        trace_max_depth=8,
        auto_render=True,
        output_formats=["md", "json"],
        output_dir=report_output_dir,
        auth_env=auth,
    )
    result = await run_scan(cfg)

    # Snapshot every attribute we'll assert on INSIDE the session scope;
    # SQLAlchemy 2.0 expires ORM instances on commit and any post-scope
    # attribute access raises DetachedInstanceError. See v0.5/v0.6/v0.7/v0.8
    # smoke tests for the same pattern.
    with st_session.session_scope() as s:
        run_rows: list[tuple[str, str, int, str]] = [
            (r.id, r.status, r.budget_used, r.config_json)
            for r in s.execute(
                select(Run).where(Run.id == result.run_id)
            ).scalars().all()
        ]
        finding_rows: list[tuple[str, str, str | None, str]] = [
            (f.id, f.status, f.reachable, f.attack_class)
            for f in s.execute(
                select(Finding).where(Finding.run_id == result.run_id)
            ).scalars().all()
        ]
        trace_rows: list[
            tuple[str, str, str, str | None, str, str]
        ] = [
            (
                t.id,
                t.finding_id,
                t.reachable,
                t.entry_point_symbol,
                t.call_chain_json,
                t.rationale,
            )
            for t in s.execute(
                select(Trace)
                .join(Finding, Trace.finding_id == Finding.id)
                .where(Finding.run_id == result.run_id)
            ).scalars().all()
        ]
        trace_sessions: list[tuple[str, str, str | None]] = [
            (sess.id, sess.outcome, sess.finding_id)
            for sess in s.execute(
                select(AgentSession).where(
                    AgentSession.run_id == result.run_id,
                    AgentSession.stage == "trace",
                )
            ).scalars().all()
        ]

    # Per § Success criteria #1: exactly one runs row, status='completed',
    # budget_used > 0.
    assert len(run_rows) == 1, (
        f"expected exactly 1 runs row, got {len(run_rows)}"
    )
    _run_id, run_status, budget_used, config_json = run_rows[0]
    assert run_status == "completed", (
        f"expected runs.status='completed', got {run_status!r}; "
        f"summary={result.summary}"
    )
    assert budget_used > 0, (
        f"expected runs.budget_used > 0, got {budget_used}"
    )

    # Per spec § Success criteria #8 (mirrored from v0.7/v0.8 pattern):
    # runs.config_json includes trace_token_budget AND trace_max_depth.
    config = json.loads(config_json)
    assert "trace_token_budget" in config, (
        f"runs.config_json missing trace_token_budget; got keys "
        f"{sorted(config.keys())}"
    )
    assert "trace_max_depth" in config, (
        f"runs.config_json missing trace_max_depth; got keys "
        f"{sorted(config.keys())}"
    )

    # Per § Success criteria #2: >= 1 findings row.
    assert len(finding_rows) >= 1, (
        f"expected >= 1 findings row, got {len(finding_rows)}"
    )

    # Sanity-check the test's premise (per task description #9): v02_smoke
    # must produce >= 1 confirmed command_injection finding after Validate.
    # Without that, the Trace stage is skipped entirely and every assertion
    # below would be vacuously satisfied — a silent regression. Fail loudly.
    confirmed = [
        fid
        for fid, status, _reach, _ac in finding_rows
        if status == "confirmed"
    ]
    assert len(confirmed) >= 1, (
        f"test premise violated: v02_smoke produced 0 confirmed findings "
        f"(out of {len(finding_rows)} total). Trace stage would be skipped, "
        f"making downstream assertions vacuous. summary={result.summary}"
    )

    # Per § Success criteria (task description #3): >= 1 traces row.
    assert len(trace_rows) >= 1, (
        f"expected >= 1 traces row, got {len(trace_rows)}; "
        f"summary={result.summary}"
    )

    # Per task description #4: trace.reachable in the verdict set.
    valid_reachable = {"reachable", "unreachable", "uncertain"}
    for tid, fid, reachable, entry_sym, _chain, _rationale in trace_rows:
        assert reachable in valid_reachable, (
            f"trace {tid} (finding {fid}) has unexpected reachable "
            f"{reachable!r}; expected one of {sorted(valid_reachable)}"
        )
        # Per task description #5: matches schema's
        # ck_traces_reachable_has_entry_point — reachable='reachable'
        # implies entry_point_symbol IS NOT NULL.
        if reachable == "reachable":
            assert entry_sym is not None, (
                f"trace {tid} has reachable='reachable' but "
                f"entry_point_symbol IS NULL; violates "
                f"ck_traces_reachable_has_entry_point"
            )

    # Per task description #6: every finding referenced by a trace has
    # its own findings.reachable matching the trace verdict (record_trace
    # writes both rows in one transaction).
    finding_reachable_by_id: dict[str, str | None] = {
        fid: reach for fid, _status, reach, _ac in finding_rows
    }
    for tid, fid, reachable, _esym, _chain, _rat in trace_rows:
        assert fid in finding_reachable_by_id, (
            f"trace {tid} references finding {fid} not present in "
            f"this run's findings rows"
        )
        f_reach = finding_reachable_by_id[fid]
        assert f_reach == reachable, (
            f"finding {fid}.reachable={f_reach!r} does not match "
            f"trace {tid}.reachable={reachable!r}; record_trace should "
            f"write both in one transaction"
        )

    # Per task description #7: >= 1 agent_sessions row with stage='trace',
    # finding_id NOT NULL, terminal outcome.
    assert len(trace_sessions) >= 1, (
        f"expected >= 1 trace agent_sessions row, got {len(trace_sessions)}"
    )
    valid_outcomes = {
        "completed", "refused", "errored", "budget_exceeded"
    }
    for sess_id, outcome, sess_finding_id in trace_sessions:
        assert outcome in valid_outcomes, (
            f"trace session {sess_id} has unexpected outcome "
            f"{outcome!r}; expected one of {sorted(valid_outcomes)}"
        )
        # Per spec § Component responsibilities: each Tracer session is
        # bound to its assigned finding; agent_sessions.finding_id must
        # not be NULL for stage='trace' rows.
        assert sess_finding_id is not None, (
            f"trace session {sess_id} has NULL finding_id; expected the "
            "assigned finding id"
        )

    # v1.0 Report assertions per docs/plans/2026-06-04-v1.0-report.md
    # Task E: the orchestrator auto-rendered the report after run
    # completion. cfg.output_dir was pinned to tmp_path / "report-output"
    # above, so that's where the orchestrator should have written.
    report_output = report_output_dir
    report_md_path = report_output / "report.md"
    report_json_path = report_output / "report.json"

    if report_output.exists():
        output_listing: list[str] | str = sorted(
            p.name for p in report_output.iterdir()
        )
    else:
        output_listing = "(missing)"
    assert report_md_path.exists(), (
        f"expected report.md at {report_md_path}; "
        f"output_dir contents: {output_listing}"
    )
    assert report_json_path.exists(), (
        f"expected report.json at {report_json_path}; "
        f"output_dir contents: {output_listing}"
    )

    # Parse report.json via the canonical model and assert schema_version,
    # run linkage, and non-empty findings.
    report = ReportV1.model_validate_json(report_json_path.read_text())
    assert report.schema_version == "1.0", (
        f"expected schema_version='1.0', got {report.schema_version!r}"
    )
    assert report.run.id == result.run_id, (
        f"expected report.run.id={result.run_id!r}, got {report.run.id!r}"
    )
    assert len(report.findings) >= 1, (
        f"expected >= 1 finding in report.findings, got "
        f"{len(report.findings)}"
    )

    # >= 1 findings/<id>/ directory exists; each has finding.md.
    findings_root = report_output / "findings"
    assert findings_root.exists() and findings_root.is_dir(), (
        f"expected findings/ subdir at {findings_root}"
    )
    finding_subdirs = [p for p in findings_root.iterdir() if p.is_dir()]
    assert len(finding_subdirs) >= 1, (
        f"expected >= 1 findings/<id>/ subdir, got {len(finding_subdirs)}; "
        f"contents: {sorted(p.name for p in findings_root.iterdir())}"
    )
    for fd in finding_subdirs:
        finding_md = fd / "finding.md"
        assert finding_md.exists(), (
            f"expected {finding_md} to exist; poc.py is optional but "
            f"finding.md is required for every findings/<id>/ dir"
        )

    # The CONFIRMED command_injection finding (per the v02_smoke premise
    # already asserted above) must appear in the JSON findings list with
    # status='confirmed' AND attack_class='command_injection'. Cross-check
    # by ID against the DB snapshot so a renamed/renumbered finding shows
    # as a clear mismatch rather than an opaque attribute miss.
    confirmed_ci_ids_db = {
        fid
        for fid, status, _reach, ac in finding_rows
        if status == "confirmed" and ac == "command_injection"
    }
    assert len(confirmed_ci_ids_db) >= 1, (
        f"test premise violated: v02_smoke produced 0 confirmed "
        f"command_injection findings (out of {len(finding_rows)} total). "
        f"finding_rows={finding_rows}"
    )
    confirmed_ci_ids_report = {
        rf.id
        for rf in report.findings
        if rf.attack_class == "command_injection" and rf.status == "confirmed"
    }
    assert confirmed_ci_ids_db & confirmed_ci_ids_report, (
        f"expected at least one confirmed command_injection finding ID "
        f"to be shared between DB and report.json. db={confirmed_ci_ids_db}, "
        f"report={confirmed_ci_ids_report}"
    )

    # runs.config_json carries auto_render and output_formats (v1.0
    # additions). config was already json.loads()'d above for the v0.9
    # trace_token_budget / trace_max_depth checks; reuse it here.
    assert config.get("auto_render") is True, (
        f"runs.config_json: expected auto_render=True, got "
        f"{config.get('auto_render')!r}"
    )
    assert config.get("output_formats") == ["md", "json"], (
        f"runs.config_json: expected output_formats=['md','json'], got "
        f"{config.get('output_formats')!r}"
    )
