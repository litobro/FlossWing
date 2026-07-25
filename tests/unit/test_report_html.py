"""report_html tests: triage ordering, ASCII payload, script-block safety."""

from __future__ import annotations

import json

from flosswing.stages import report_html
from flosswing.stages.report import (
    ReportFinding,
    ReportRun,
    ReportSummary,
    ReportV1,
)


def _finding(**kw: object) -> ReportFinding:
    """A ReportFinding with all required fields defaulted."""
    base: dict[str, object] = {
        "id": "01FIND0000000000000000001",
        "attack_class": "ssrf",
        "file": "src/a.py",
        "function": "fetch",
        "line_start": 10,
        "line_end": 12,
        "severity": "medium",
        "confidence": "likely",
        "status": "confirmed",
        "title": "Example finding",
        "description": "A description.",
        "poc_code": None,
        "suggested_fix": None,
        "created_at": "2026-07-25T00:00:00Z",
    }
    base.update(kw)
    return ReportFinding(**base)  # type: ignore[arg-type]  # kwargs are dynamic by design


def _report(findings: list[ReportFinding]) -> ReportV1:
    return ReportV1(
        rendered_at="2026-07-25T00:00:00Z",
        run=ReportRun(
            id="01RUN00000000000000000001",
            target_repo_path="/tmp/repo",
            status="completed",
            started_at="2026-07-25T00:00:00Z",
            finished_at="2026-07-25T01:00:00Z",
            exit_code=0,
            budget_total=20,
            budget_used=100,
            model="claude-opus-4-8",
            config={},
        ),
        summary=ReportSummary(
            findings_total=len(findings),
            findings_confirmed=sum(f.status == "confirmed" for f in findings),
            findings_uncertain=sum(f.status == "uncertain" for f in findings),
            findings_rejected=sum(f.status == "rejected" for f in findings),
            findings_pending=0,
            findings_superseded=0,
            by_severity={},
            by_attack_class={},
            clusters_total=0,
            traces_total=0,
            reachable_total=0,
        ),
        findings=findings,
        dedupe_clusters=[],
    )


def test_confirmed_sorts_ahead_of_rejected_regardless_of_severity() -> None:
    """Severity is frequently degenerate; verdict is the triage axis."""
    rejected_high = _finding(id="a", status="rejected", severity="high", title="A")
    confirmed_low = _finding(id="b", status="confirmed", severity="low", title="B")
    payload = json.loads(report_html._payload_json(_report([rejected_high, confirmed_low])))
    assert [f["id"] for f in payload["findings"]] == ["b", "a"]


def test_reachable_sorts_ahead_of_unproven_within_same_status() -> None:
    unproven = _finding(id="a", status="confirmed", reachable="uncertain", title="A")
    reachable = _finding(id="b", status="confirmed", reachable="reachable", title="B")
    payload = json.loads(report_html._payload_json(_report([unproven, reachable])))
    assert [f["id"] for f in payload["findings"]] == ["b", "a"]


def test_payload_is_pure_ascii() -> None:
    """Agent rationales contain em-dashes; a raw UTF-8 byte mojibakes over file://."""
    f = _finding(description="An em-dash — and an arrow →.")
    payload = report_html._payload_json(_report([f]))
    assert payload.isascii()
    assert "—" in json.loads(payload)["findings"][0]["description"]


def test_payload_escapes_angle_bracket_so_it_cannot_close_the_script_block() -> None:
    """Repo-derived text reaches a <script> block; '</script>' would end it early."""
    f = _finding(title="</script><img src=x onerror=alert(1)>")
    payload = report_html._payload_json(_report([f]))
    assert "</script" not in payload
    assert "<" not in payload
    # Still decodes back to the original text.
    assert json.loads(payload)["findings"][0]["title"] == "</script><img src=x onerror=alert(1)>"


def test_render_html_is_pure_ascii() -> None:
    html = report_html.render_html(_report([_finding(description="dash — here")]))
    assert html.isascii()


def test_render_html_references_no_external_resources() -> None:
    """Must render fully offline from file://; no CDN, font, or remote image."""
    html = report_html.render_html(_report([_finding()]))
    assert "http://" not in html
    assert "https://" not in html


def test_render_html_does_not_let_repo_text_become_markup() -> None:
    """The whole point: untrusted repo text must never reach live markup."""
    payload = "</script><img src=x onerror=alert(1)>"
    html = report_html.render_html(_report([_finding(title=payload, description=payload)]))
    # Exactly one script element -- the payload did not open or close one.
    assert html.count("<script") == 1
    assert html.count("</script>") == 1
    # The raw attack string never appears as markup anywhere in the document.
    assert payload not in html


def test_render_html_states_that_zero_findings_is_not_a_clean_bill() -> None:
    """ARCHITECTURE.md threat model item 5 requires the report to say so."""
    html = report_html.render_html(_report([]))
    assert "not" in html.lower()
    assert "secure" in html.lower()


def test_render_html_survives_missing_validation_and_trace() -> None:
    """Report may run before Validate/Trace land; must degrade, not raise."""
    f = _finding(validation=None, trace=None, reachable=None)
    html = report_html.render_html(_report([f]))
    assert f.title in json.loads(
        html.split("const REPORT = ", 1)[1].split(";\n", 1)[0].replace("\\u003c", "<")
    )["findings"][0]["title"]
