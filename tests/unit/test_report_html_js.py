"""Runtime DOM-execution test for `report_html._JS`.

`flosswing/stages/report_html.py` embeds untrusted, repo-derived finding text
into a rendered HTML report. The security claim is that every finding field
reaches the DOM via `textContent` (data) and never as markup.

Previously that claim was checked only by grepping `_JS`'s source for a
blocklist of known markup sinks (see
`test_js_never_uses_markup_sinks_like_innerhtml` in `test_report_html.py`)
-- and that blocklist had already missed `setHTMLUnsafe`: swapping
`n.textContent = String(text)` for `n.setHTMLUnsafe(String(text))` produces
real script execution in a browser while the blocklist, and the rest of the
suite, stayed green, because nobody had thought to name that sink yet.

This test instead actually executes `_JS` under Node against
`tests/unit/js/dom_shim.js` -- a deny-by-default DOM shim that implements
only the exact safe surface `_JS` legitimately needs (`textContent`,
`className`, `dataset.status`, `type`, `hidden`, `appendChild`,
`setAttribute`, `addEventListener`, `classList.toggle`, `querySelectorAll`,
`getElementById`, `createElement`) and throws a descriptive error on
anything else -- any property write or method call outside that list. Any
markup-parsing sink -- `innerHTML`, `setHTMLUnsafe`, or one invented next
year -- fails this test by construction, without anyone having to name it.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

from flosswing.stages import report_html
from flosswing.stages.report import ReportTrace, ReportV1, ReportValidation
from tests.unit.test_report_html import _finding, _report

_NODE = shutil.which("node")
_DOM_SHIM = Path(__file__).parent / "js" / "dom_shim.js"

pytestmark = pytest.mark.skipif(
    _NODE is None, reason="node not installed; runtime DOM-execution test needs node"
)

# A single hostile marker reused across every finding field _JS renders.
# `</script>` would try to close the enclosing <script> element early;
# `<img onerror=...>` / `<svg onload=...>` are classic auto-executing
# markup sinks. If any of it ever reached the DOM as markup instead of
# text, the shim's serializer makes that visible.
_XSS = "</script><img src=x onerror=alert(1)><svg onload=alert(2)>"


def _hostile_report() -> ReportV1:
    """A ReportV1 with the hostile payload in every text field `_JS` renders."""
    finding = _finding(
        title=f"Hostile finding title {_XSS}",
        description=f"Hostile description {_XSS}",
        file=f"src/{_XSS}.py",
        function=f"fn_{_XSS}",
        validation=ReportValidation(
            verdict="confirmed",
            rationale=f"Hostile validation rationale {_XSS}",
            validated_at="2026-07-25T00:00:00Z",
            agent_session_id="01SESSION0000000000000001",
        ),
        trace=ReportTrace(
            reachable="reachable",
            entry_point_symbol="main",
            call_chain=[],
            rationale=f"Hostile trace rationale {_XSS}",
        ),
        reachable="reachable",
    )
    return _report([finding])


def _compose_script(js_source: str, report: ReportV1) -> str:
    """The script a browser would run: shim, then `const REPORT = ...`, then JS.

    Mirrors `render_html`'s own `<script>` body exactly: a `const REPORT =
    <payload>;` literal followed directly by `_JS`.
    """
    shim = _DOM_SHIM.read_text(encoding="utf-8")
    payload = report_html._payload_json(report)
    browser_script = f"{shim}\nconst REPORT = {payload};\n{js_source}"
    # Everything above is what a browser would run. This last line is not --
    # it is how the Node harness hands the resulting DOM back to the test
    # process once the script (which ends by calling `render()`) has
    # finished building it.
    return browser_script + "\nprocess.stdout.write(__shim_serialize__());\n"


def _run_node(script: str, tmp_path: Path) -> subprocess.CompletedProcess[str]:
    script_path = tmp_path / "run.js"
    script_path.write_text(script, encoding="utf-8")
    assert _NODE is not None  # narrows for mypy; skipif already guarantees this at runtime
    return subprocess.run(
        [_NODE, str(script_path)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def test_js_execution_denies_by_default_and_treats_all_finding_text_as_text(
    tmp_path: Path,
) -> None:
    """Execute `_JS` for real against a deny-by-default DOM shim.

    Proves, by actually running the code (not by grepping it), that title,
    description, file, function, validation rationale, and trace rationale
    all reach the DOM only through the shim's allowed safe surface -- never
    through a markup-parsing sink, named or not.
    """
    report = _hostile_report()
    script = _compose_script(report_html._JS, report)
    result = _run_node(script, tmp_path)

    assert result.returncode == 0, (
        "_JS touched a sink the DOM shim does not allow -- a markup sink, "
        f"enumerated or not, would show up here as a thrown error:\n{result.stderr}"
    )

    dom = result.stdout
    assert dom, "shim produced no serialized DOM output"

    # (b) No hostile element was ever actually created, and no on* attribute
    # exists on any real element -- the payload only ever appears as text.
    assert not re.search(r"<(img|script|svg)\b", dom, re.IGNORECASE), dom
    assert not re.search(r"<[a-zA-Z][^>]*\son\w+\s*=", dom, re.IGNORECASE), dom

    # (c) The hostile payload is present, but only as HTML-escaped text.
    assert "&lt;img" in dom
    assert "onerror=alert(1)" in dom  # unaffected by escaping; proves it IS there, as text
    assert "<img" not in dom
    assert "<script" not in dom

    # (d) render() actually ran and populated #app with real content.
    assert "Hostile finding title" in dom
