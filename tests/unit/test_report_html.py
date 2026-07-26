"""report_html tests: triage ordering, ASCII payload, script-block safety."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

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


def _report(
    findings: list[ReportFinding], *, run_id: str = "01RUN00000000000000000001"
) -> ReportV1:
    return ReportV1(
        rendered_at="2026-07-25T00:00:00Z",
        run=ReportRun(
            id=run_id,
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


def test_pending_validation_sorts_between_uncertain_and_rejected() -> None:
    """Regression: the real DB status value is 'pending_validation', not
    'pending'. The wrong magic string used to miss ``_STATUS_ORDER``
    entirely, falling through to the unknown-status default (99) -- which
    sorted a pending_validation finding *after* superseded and also gave it
    no filter chip in the JS (see STATUSES in _JS). Test pins both Python
    _STATUS_ORDER and JS STATUSES array against each other."""
    uncertain = _finding(id="a", status="uncertain", title="A")
    pending = _finding(id="b", status="pending_validation", title="B")
    rejected = _finding(id="c", status="rejected", title="C")
    superseded = _finding(id="d", status="superseded", title="D")
    payload = json.loads(
        report_html._payload_json(_report([superseded, rejected, pending, uncertain]))
    )
    assert [f["id"] for f in payload["findings"]] == ["a", "b", "c", "d"]
    # Pin JS STATUSES array against Python _STATUS_ORDER: reverting either
    # without the other silently breaks filter chips in the rendered HTML.
    assert all(f"'{s}'" in report_html._JS for s in report_html._STATUS_ORDER)


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
    """Must render fully offline from file://; no CDN, font, or remote image.

    Scoped to the parts that could actually load a resource -- the CSS, the
    JS, and the HTML skeleton -- rather than the embedded JSON payload.
    Finding descriptions are free text from an untrusted repo and routinely
    cite https:// advisory links (expected content, not a resource load);
    scanning the whole document would fail spuriously on the first such
    fixture.
    """
    report = _report([_finding(description="See https://advisory.example/CVE-1 for details.")])
    html = report_html.render_html(report)
    payload = report_html._payload_json(report)
    skeleton = html.replace(payload, "", 1)

    assert "http://" not in report_html._CSS
    assert "https://" not in report_html._CSS
    assert "http://" not in report_html._JS
    assert "https://" not in report_html._JS
    assert "http://" not in skeleton
    assert "https://" not in skeleton


def test_render_html_title_does_not_embed_run_id_as_markup() -> None:
    """`report.run.id` used to be concatenated straight into <title>, the only
    field bypassing the escaped JSON payload. A hostile or non-ASCII id must
    still only reach the page through that payload (and later `document.title`
    in JS, a DOM property assignment, not markup) -- never break the "exactly
    one <script>" or "pure ASCII" invariants."""
    malicious_id = "</script><img src=x onerror=alert(1)>é"
    html = report_html.render_html(_report([_finding()], run_id=malicious_id))
    assert html.count("<script") == 1
    assert html.count("</script>") == 1
    assert html.isascii()


def test_js_never_uses_markup_sinks_like_innerhtml() -> None:
    """Coarse proxy for "all text reaches the DOM via textContent".

    This is a cheap fast-fail that works without node: grep the JS source
    for markup sinks that would let repo-controlled text become live DOM
    instead of an inert string. It is necessarily a blocklist, so it can
    only catch sink names someone thought to enumerate here -- it already
    missed ``setHTMLUnsafe`` once (a prior review swapped exactly that in
    for ``n.textContent`` and every test, including this one, stayed green).

    The real guarantee now lives in ``test_report_html_js.py``, which
    actually executes ``_JS`` under node against a deny-by-default DOM shim
    that throws on any sink outside its safe allowlist -- catching
    unenumerated sinks too, not just ones named below. Keep this test as
    well: it runs everywhere (no node required) and fails fast.
    """
    forbidden = (
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "eval(",
        "Function(",
        "setHTMLUnsafe",
        "parseHTMLUnsafe",
        "srcdoc",
        "createContextualFragment",
        "DOMParser",
        "document.writeln",
    )
    for sink in forbidden:
        assert sink not in report_html._JS


def test_js_ends_with_the_render_call() -> None:
    """Guards against shipping a permanently blank report.

    No JS engine is available in this suite, so nothing here actually
    executes ``_JS`` and notices the page never populates ``#app``.
    Deleting the trailing ``render();`` call leaves every other test
    green -- the JSON payload, the CSS, and the source text of ``_JS``
    itself are all unchanged -- while the shipped page silently renders
    blank. Pin the call itself so that failure mode has a test.
    """
    assert report_html._JS.rstrip().endswith("render();")


def test_status_pill_class_collapses_whitespace() -> None:
    """`ReportFinding.status` is a bare `str` with no character restrictions;
    a crafted value containing whitespace (e.g. "confirmed hidden") would
    otherwise split into extra class tokens when concatenated raw into
    className, letting repo-controlled text toggle an unrelated existing
    class (such as one that hides the badge). No JS engine is available, so
    this checks the source builds the class name through a
    whitespace-collapsing regex rather than raw concatenation with f.status.
    """
    assert "'pill s-' + String(f.status).replace(/\\s+/g, '-')" in report_html._JS
    assert "'pill s-' + f.status" not in report_html._JS


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
    """ARCHITECTURE.md threat model item 5 requires the report to say so.

    Asserts on text unique to the caveat sentence itself, not the unrelated
    'PoC - not run against a live target' string that also lives in _JS (the
    previous 'not' / 'secure' substring checks passed on that string alone,
    unconditionally, whether or not the caveat was ever rendered). Also
    asserts the caveat is actually wired into the render path -- that the
    'caveat' class is passed to `el()` as the direct argument of an
    `app.appendChild()` call -- so deleting that append still fails this
    test instead of silently leaving dead code in _JS.
    """
    html = report_html.render_html(_report([]))
    assert "not evidence that this repository is" in html
    assert "app.appendChild(el('p', 'caveat'," in html


def test_render_html_survives_missing_validation_and_trace() -> None:
    """Report may run before Validate/Trace land; must degrade, not raise."""
    f = _finding(validation=None, trace=None, reachable=None)
    html = report_html.render_html(_report([f]))
    assert f.title in json.loads(
        html.split("const REPORT = ", 1)[1].split(";\n", 1)[0].replace("\\u003c", "<")
    )["findings"][0]["title"]


def test_render_writes_report_html(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """--format html writes report.html and reports it as written."""
    from flosswing.stages import report as report_stage

    # Patch the loader so the test needs no database.
    monkeypatch.setattr(
        report_stage, "_load", lambda run_id, session_factory: _report([_finding()])
    )
    out = tmp_path / "out"
    result = report_stage.render(
        run_id="01RUN00000000000000000001",
        session_factory=None,  # type: ignore[arg-type]  # unused once _load is patched
        output_dir=out,
        formats=["html"],
    )

    assert "html" in result.formats_written
    written = (out / "report.html").read_text(encoding="utf-8")
    assert written.startswith("<!doctype html>")
