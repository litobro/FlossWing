"""flosswing.stages.report._render_markdown — markdown rendering rules.

Per docs/specs/2026-06-02-v1.0-report-design.md § Markdown rendering and
§ Security considerations. Covers:

- Severity section ordering: critical, high, medium, low, info.
- Within severity, reachability ordering: reachable, uncertain,
  unreachable, NULL.
- UNCERTAIN-status findings display a literal ``[uncertain]`` badge in
  their section header.
- Injection safety: triple-backtick in PoC code does not prematurely
  close the fence; ``<script>`` in descriptions is HTML-escaped.
- Empty run renders a valid markdown doc with summary showing zero
  counts.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from ulid import ULID

from flosswing.stages import report as report_stage
from flosswing.state import session as st_session
from flosswing.state.models import (
    Finding,
    HuntTask,
    Run,
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


def _seed_run(run_id: str) -> None:
    with st_session.session_scope() as s:
        s.add(
            Run(
                id=run_id,
                target_repo_path="/tmp/x",
                target_repo_sha=None,
                depth="standard",
                budget_total=100,
                budget_used=0,
                started_at=_now_iso(),
                finished_at=_now_iso(),
                status="completed",
                config_json='{"model": "claude-opus-4-7"}',
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
    severity: str = "high",
    status: str = "confirmed",
    title: str = "shell injection vuln",
    description: str = (
        "A reasonable description, fifty chars or more for realism."
    ),
    poc_code: str | None = None,
    suggested_fix: str | None = None,
    reachable: str | None = None,
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
                function="some_fn",
                line_start=10,
                line_end=12,
                severity=severity,
                confidence="likely",
                status=status,
                title=title,
                description=description,
                poc_code=poc_code,
                poc_result_json=None,
                suggested_fix=suggested_fix,
                created_at=_now_iso(),
                reachable=reachable,
            )
        )
    return fid


def _load(run_id: str) -> report_stage.ReportV1:
    return report_stage._load(run_id, st_session.session_factory())


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_markdown_severity_sections_in_canonical_order(
    isolated_db: Path,
) -> None:
    """Sections appear in order critical, high, medium, low, info."""
    run_id = str(ULID())
    _seed_run(run_id)
    task_id = _seed_task(run_id)
    for sev in ("info", "low", "medium", "high", "critical"):
        _seed_finding(
            run_id=run_id, task_id=task_id, severity=sev,
            file=f"src/{sev}.py", title=f"{sev}-titled finding",
        )

    md = report_stage._render_markdown(_load(run_id))
    idx = {
        sev: md.index(f"### Severity: {sev}")
        for sev in ("critical", "high", "medium", "low", "info")
    }
    assert (
        idx["critical"]
        < idx["high"]
        < idx["medium"]
        < idx["low"]
        < idx["info"]
    )


def test_markdown_reachability_ordering_within_severity(
    isolated_db: Path,
) -> None:
    """Reachable group appears before uncertain/unreachable/NULL groups
    within a single severity section."""
    run_id = str(ULID())
    _seed_run(run_id)
    task_id = _seed_task(run_id)
    # All high severity; different reachability values.
    _seed_finding(
        run_id=run_id, task_id=task_id, severity="high",
        reachable="unreachable", file="src/u.py",
        title="unreachable finding",
    )
    _seed_finding(
        run_id=run_id, task_id=task_id, severity="high",
        reachable="reachable", file="src/r.py",
        title="reachable finding",
    )
    _seed_finding(
        run_id=run_id, task_id=task_id, severity="high",
        reachable="uncertain", file="src/q.py",
        title="uncertain reachability finding",
    )
    _seed_finding(
        run_id=run_id, task_id=task_id, severity="high",
        reachable=None, file="src/n.py",
        title="not-analyzed finding",
    )

    md = report_stage._render_markdown(_load(run_id))
    # Group headers live below the severity header; their ordering
    # establishes the reachability priority.
    sev_idx = md.index("### Severity: high")
    sub_md = md[sev_idx:]
    idx_reach = sub_md.index("Reachable (")
    idx_uncertain = sub_md.index("Reachability uncertain (")
    idx_unreach = sub_md.index("Unreachable (")
    idx_null = sub_md.index("Reachability not analyzed (")
    assert idx_reach < idx_uncertain < idx_unreach < idx_null


def test_markdown_uncertain_status_has_badge_in_title(
    isolated_db: Path,
) -> None:
    """A finding with ``status='uncertain'`` displays ``[uncertain]``
    in the markdown header for its section."""
    run_id = str(ULID())
    _seed_run(run_id)
    task_id = _seed_task(run_id)
    _seed_finding(
        run_id=run_id, task_id=task_id, status="uncertain",
        title="suspicious-looking call but unverified",
    )

    md = report_stage._render_markdown(_load(run_id))
    assert "[uncertain]" in md
    # Specifically: prefix immediately before the rendered title.
    assert "#### [uncertain] suspicious-looking call but unverified" in md


def test_markdown_poc_triple_backtick_does_not_close_fence(
    isolated_db: Path,
) -> None:
    """A PoC that contains the literal ``\\`\\`\\``` token must not
    prematurely close our markdown fence."""
    run_id = str(ULID())
    _seed_run(run_id)
    task_id = _seed_task(run_id)
    poc_with_fence = (
        "print('hi')\n```\nthis text would otherwise leak out of the fence\n"
    )
    _seed_finding(
        run_id=run_id, task_id=task_id, status="confirmed",
        poc_code=poc_with_fence, title="poc-fence-injection",
    )

    md = report_stage._render_markdown(_load(run_id))
    # The literal triple-backtick from poc_code must have been rewritten
    # to triple single-quote.
    assert "'''" in md
    # Count of ``` in output should equal exactly the markdown fences
    # that the renderer itself wrote — for a single finding that's an
    # open + close = 2 occurrences. The attacker-supplied ``` is gone.
    assert md.count("```") == 2


def test_markdown_description_html_is_escaped(isolated_db: Path) -> None:
    """A description containing ``<script>`` is HTML-escaped before
    reaching the rendered markdown."""
    run_id = str(ULID())
    _seed_run(run_id)
    task_id = _seed_task(run_id)
    _seed_finding(
        run_id=run_id, task_id=task_id, status="confirmed",
        description=(
            "Naughty content: <script>alert('xss')</script> "
            "with enough characters to clear the validate-side cap."
        ),
        title="injection-via-description",
    )

    md = report_stage._render_markdown(_load(run_id))
    # Raw HTML tag must not survive.
    assert "<script>" not in md
    # HTML-escaped form must be present.
    assert "&lt;script&gt;" in md


def test_markdown_empty_run_renders_zero_counts(isolated_db: Path) -> None:
    """A run with no findings still renders a valid report.md with
    a summary section showing zero counts."""
    run_id = str(ULID())
    _seed_run(run_id)

    md = report_stage._render_markdown(_load(run_id))
    assert "# FlossWing report" in md
    assert "## Summary" in md
    assert "Total findings:** 0" in md
    # The findings section exists but degrades to "No findings.".
    assert "## Findings" in md
    assert "_No findings._" in md
