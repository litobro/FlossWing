# HTML Report Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `report.html` as a fourth Report-stage output format — a self-contained, triage-ordered view of a run's findings, opened directly from disk.

**Architecture:** A new pure module `flosswing/stages/report_html.py` turns the existing `ReportV1` model into an HTML string. Findings are sorted into triage order **in Python** (so ordering is unit-testable), serialised to ASCII-only JSON, and embedded in a `<script>` block; inline JS builds the DOM using `textContent`. `report.py` stays the orchestrator and only gains a format branch.

**Tech Stack:** Python 3.11+, Pydantic v2 (already a dependency), stdlib `json`. No new dependencies. No JS framework — hand-written DOM calls.

**Spec:** `docs/specs/2026-07-25-html-report-design.md`

## Global Constraints

- Python 3.11+, full type hints on every function. `ruff check .` and `mypy --strict flosswing` must pass. `# type: ignore` only with an inline comment explaining why.
- **No new top-level dependency.** Adding one requires operator approval.
- **Output must be pure ASCII.** Every byte of `render_html()` output `< 0x80`.
- **No external resources.** No `http://` or `https://` in any `src`/`href`; no CDN, webfont, or remote image. The document must render fully offline from `file://`.
- **Finding text is NOT credential-scrubbed** by Report — that is the upstream stage's job (`flosswing/stages/report.py:47-49`). Do not add `errors.scrub()` calls to the renderer.
- **The target repo is untrusted input.** Finding titles, descriptions, file paths and function names are repo-derived. Never concatenate them into markup.
- Do not edit `docs/tool-contracts.md` or `docs/schema.sql` — no agent-facing tool and no schema changes here.
- Commit messages reference the spec, e.g. `per docs/specs/2026-07-25-html-report-design.md § Testing`.

---

### Task 1: Triage ordering and the ASCII JSON payload

Pure data preparation — no HTML. Everything here is directly unit-testable in Python.

**Files:**
- Create: `flosswing/stages/report_html.py`
- Test: `tests/unit/test_report_html.py`

**Interfaces:**
- Consumes: `ReportV1`, `ReportFinding` from `flosswing.stages.report`.
- Produces: `_triage_sort_key(f: ReportFinding) -> tuple[int, int, int, str]` and `_payload_json(report: ReportV1) -> str`. Task 2 calls `_payload_json`.

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_report_html.py`:

```python
"""report_html tests: triage ordering, ASCII payload, script-block safety."""

from __future__ import annotations

import json

from flosswing.stages.report import (
    ReportFinding,
    ReportRun,
    ReportSummary,
    ReportV1,
)
from flosswing.stages import report_html


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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/unit/test_report_html.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'flosswing.stages.report_html'`

- [ ] **Step 3: Write the implementation**

Create `flosswing/stages/report_html.py`. Copy the GPL header from `flosswing/stages/report.py` lines 1-15 verbatim, then:

```python
"""Render a ReportV1 as a self-contained HTML triage view.

Per docs/specs/2026-07-25-html-report-design.md.

The target repo is untrusted input, so finding text never reaches markup by
concatenation. It is serialised into a JSON payload and assigned through
``textContent`` in the browser, which cannot interpret markup.
"""

from __future__ import annotations

import json

from flosswing.stages.report import ReportFinding, ReportV1

# Triage order: the adjudication Validate and Trace already performed.
# Severity is deliberately the *last* key -- on a real run it is frequently
# degenerate (the 2026-07-25 home-assistant/core scan was six medium and two
# low), so sorting on it first sorts nothing.
_STATUS_ORDER: dict[str, int] = {
    "confirmed": 0,
    "uncertain": 1,
    "pending": 2,
    "rejected": 3,
    "superseded": 4,
}
_REACH_ORDER: dict[str | None, int] = {
    "reachable": 0,
    "uncertain": 1,
    "unreachable": 2,
    None: 3,
}
_SEV_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


def _triage_sort_key(f: ReportFinding) -> tuple[int, int, int, str]:
    """Sort key placing 'open this first' findings at the top."""
    return (
        _STATUS_ORDER.get(f.status, 99),
        _REACH_ORDER.get(f.reachable, 99),
        _SEV_ORDER.get(f.severity, 99),
        f.title,
    )


def _payload_json(report: ReportV1) -> str:
    """Serialise ``report`` as ASCII-only JSON safe to embed in a <script>.

    Two hardening steps, both load-bearing:

    * ``ensure_ascii=True`` -- agent-authored rationales contain em-dashes and
      arrows. A raw UTF-8 byte in a file opened over ``file://`` mojibakes when
      the browser falls back to latin-1, and a local file has no server charset
      header to rely on.
    * ``<`` -> ``\\u003c`` -- the payload sits inside a ``<script>`` element. A
      finding title containing ``</script>`` (titles are repo-derived, therefore
      untrusted) would close the element early and turn everything after it into
      live markup. ``<`` only ever occurs inside JSON string values, never in
      JSON structure, so escaping it wholesale is safe and reverses on parse.
    """
    data = report.model_dump(mode="json")
    data["findings"] = [
        f.model_dump(mode="json") for f in sorted(report.findings, key=_triage_sort_key)
    ]
    return json.dumps(data, ensure_ascii=True, sort_keys=True).replace("<", "\\u003c")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/unit/test_report_html.py -q`
Expected: PASS (4 tests)

- [ ] **Step 5: Run the type and lint gates**

Run: `.venv/bin/ruff check . && .venv/bin/mypy --strict flosswing`
Expected: `All checks passed!` and `Success: no issues found`

- [ ] **Step 6: Commit**

```bash
git add flosswing/stages/report_html.py tests/unit/test_report_html.py
git commit -m "Add triage ordering + ASCII JSON payload for report.html

Per docs/specs/2026-07-25-html-report-design.md. Sorting happens in Python
so it is unit-testable; the browser renders in array order.

The payload escapes '<' as \\u003c because it is embedded in a <script>
element and finding titles are repo-derived: a title containing '</script>'
would otherwise close the element and make the remainder live markup."
```

---

### Task 2: Assemble the HTML document

**Files:**
- Modify: `flosswing/stages/report_html.py`
- Test: `tests/unit/test_report_html.py`

**Interfaces:**
- Consumes: `_payload_json(report: ReportV1) -> str` from Task 1.
- Produces: `render_html(report: ReportV1) -> str` — the sole public entry point. Task 3 calls it.

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_report_html.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/unit/test_report_html.py -q`
Expected: FAIL — `AttributeError: module 'flosswing.stages.report_html' has no attribute 'render_html'`

- [ ] **Step 3: Write the implementation**

Append to `flosswing/stages/report_html.py`:

```python
_CSS = """
*,*::before,*::after{box-sizing:border-box}
:root{color-scheme:light dark;
--bg:#EDF0F3;--surface:#fff;--surface2:#F4F7F9;--line:#D2D9E0;
--text:#131920;--text2:#4B5866;--text3:#73828F;--accent:#0B6E66;
--confirm:#A8323F;--uncertain:#8A6410;--reject:#5F6B7C;
--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
--sans:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
@media(prefers-color-scheme:dark){:root{
--bg:#10141A;--surface:#171C24;--surface2:#1C222B;--line:#2C333E;
--text:#E3E9EF;--text2:#A2AFBC;--text3:#798693;--accent:#4FBDB1;
--confirm:#F0808E;--uncertain:#E0AC4E;--reject:#8494A5}}
body{margin:0;background:var(--bg);color:var(--text);font-family:var(--sans);
font-size:15px;line-height:1.6}
main{max-width:1060px;margin:0 auto;padding:36px 22px 80px;
display:flex;flex-direction:column;gap:24px}
h1{font-size:30px;letter-spacing:-.02em;margin:0}
.eyebrow{font-family:var(--mono);font-size:11px;letter-spacing:.16em;
text-transform:uppercase;color:var(--text3);margin:0}
.readout{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;
background:var(--line);border:1px solid var(--line);border-radius:3px;overflow:hidden}
.readout div{background:var(--surface);padding:9px 12px;display:flex;
flex-direction:column;gap:2px}
.readout dt{font-family:var(--mono);font-size:10px;letter-spacing:.12em;
text-transform:uppercase;color:var(--text3)}
.readout dd{margin:0;font-family:var(--mono);font-size:13px;
font-variant-numeric:tabular-nums;overflow-wrap:anywhere}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px}
.tile{background:var(--surface);border:1px solid var(--line);border-top-width:2px;
border-radius:3px;padding:12px 14px;display:flex;flex-direction:column;gap:3px}
.tile .n{font-family:var(--mono);font-size:27px;line-height:1;
font-variant-numeric:tabular-nums}
.tile .l{font-size:13px;font-weight:600}
.t-confirmed{border-top-color:var(--confirm)}.t-confirmed .n{color:var(--confirm)}
.t-uncertain{border-top-color:var(--uncertain)}.t-uncertain .n{color:var(--uncertain)}
.t-rejected{border-top-color:var(--reject)}.t-rejected .n{color:var(--reject)}
.t-total{border-top-color:var(--accent)}.t-total .n{color:var(--accent)}
.filters{display:flex;flex-wrap:wrap;gap:7px;border-bottom:1px solid var(--line);
padding-bottom:10px}
.chip{font-family:var(--mono);font-size:11px;letter-spacing:.06em;
text-transform:uppercase;padding:6px 10px;border:1px solid var(--line);
background:var(--surface);color:var(--text2);border-radius:3px;cursor:pointer}
.chip[aria-pressed=true]{background:var(--accent);border-color:var(--accent);color:#fff}
ol.findings{list-style:none;margin:0;padding:0;display:flex;
flex-direction:column;gap:9px}
.f{background:var(--surface);border:1px solid var(--line);border-radius:3px;
overflow:hidden}
.f[hidden]{display:none}
.frow{width:100%;display:grid;grid-template-columns:26px 1fr auto;gap:11px;
align-items:start;background:none;border:none;text-align:left;padding:12px 14px;
cursor:pointer;color:inherit;font:inherit}
.frow:hover{background:var(--surface2)}
.rank{font-family:var(--mono);font-size:12px;color:var(--text3);
font-variant-numeric:tabular-nums;padding-top:2px}
.fmain{display:flex;flex-direction:column;gap:4px;min-width:0}
.ftitle{font-weight:590;font-size:14.5px;line-height:1.4}
.fmeta{font-family:var(--mono);font-size:11.5px;color:var(--text3);
display:flex;flex-wrap:wrap;gap:5px 9px}
.fmeta .cls{color:var(--accent)}
.pills{display:flex;flex-wrap:wrap;gap:5px;justify-content:flex-end}
.pill{font-family:var(--mono);font-size:10.5px;letter-spacing:.07em;
text-transform:uppercase;padding:3px 7px;border-radius:2px;white-space:nowrap;
background:var(--surface2);color:var(--text2);border:1px solid var(--line)}
.pill.s-confirmed{color:var(--confirm);border-color:var(--confirm)}
.pill.s-uncertain{color:var(--uncertain);border-color:var(--uncertain)}
.pill.s-rejected{color:var(--reject);border-color:var(--reject)}
.detail{display:none;border-top:1px solid var(--line);padding:0 14px 16px;
flex-direction:column;gap:0}
.f.open .detail{display:flex}
.stage{padding-top:14px;display:flex;flex-direction:column;gap:6px}
.stage+.stage{border-top:1px dashed var(--line)}
.stage h3{margin:0;font-family:var(--mono);font-size:10.5px;letter-spacing:.15em;
text-transform:uppercase;color:var(--text3);font-weight:500}
.stage p{margin:0;color:var(--text2);font-size:14px;max-width:74ch;
white-space:pre-wrap}
.stage pre{margin:0;background:var(--surface2);border:1px solid var(--line);
border-radius:3px;padding:10px 12px;overflow-x:auto}
.stage pre code{font-family:var(--mono);font-size:12.5px;color:var(--text2);
white-space:pre}
.caveat{border-top:1px solid var(--line);padding-top:18px;color:var(--text2);
font-size:13.5px;max-width:78ch}
button:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
@media(max-width:700px){.readout{grid-template-columns:repeat(2,1fr)}}
"""

_JS = """
const STATUSES = ['confirmed','uncertain','pending','rejected','superseded'];
const app = document.getElementById('app');

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined && text !== null) n.textContent = String(text);
  return n;
}

function readout(pairs) {
  const dl = el('dl', 'readout');
  for (const [k, v] of pairs) {
    const d = el('div');
    d.appendChild(el('dt', null, k));
    d.appendChild(el('dd', null, v));
    dl.appendChild(d);
  }
  return dl;
}

function stage(label, body, isCode) {
  const s = el('section', 'stage');
  s.appendChild(el('h3', null, label));
  if (isCode) {
    const pre = el('pre');
    pre.appendChild(el('code', null, body));
    s.appendChild(pre);
  } else {
    s.appendChild(el('p', null, body));
  }
  return s;
}

function findingRow(f, idx) {
  const li = el('li', 'f');
  li.dataset.status = f.status;

  const row = el('button', 'frow');
  row.type = 'button';
  row.setAttribute('aria-expanded', 'false');
  row.appendChild(el('span', 'rank', String(idx + 1).padStart(2, '0')));

  const main = el('div', 'fmain');
  main.appendChild(el('span', 'ftitle', f.title));
  const meta = el('span', 'fmeta');
  meta.appendChild(el('span', 'cls', f.attack_class));
  meta.appendChild(el('span', null, f.file + ':' + f.line_start));
  if (f.function) meta.appendChild(el('span', null, f.function + '()'));
  main.appendChild(meta);
  row.appendChild(main);

  const pills = el('span', 'pills');
  pills.appendChild(el('span', 'pill s-' + f.status, f.status));
  if (f.reachable) pills.appendChild(el('span', 'pill', 'reach: ' + f.reachable));
  pills.appendChild(el('span', 'pill', f.severity));
  pills.appendChild(el('span', 'pill', f.confidence));
  row.appendChild(pills);

  const detail = el('div', 'detail');
  detail.appendChild(stage('Hunt - what was found', f.description, false));
  if (f.validation) {
    detail.appendChild(stage(
      'Validate - ' + f.validation.verdict, f.validation.rationale, false));
  }
  if (f.trace) {
    detail.appendChild(stage(
      'Trace - ' + f.trace.reachable, f.trace.rationale, false));
  }
  if (f.suggested_fix) detail.appendChild(stage('Suggested fix', f.suggested_fix, false));
  if (f.poc_code) detail.appendChild(stage('PoC - not run against a live target', f.poc_code, true));

  row.addEventListener('click', () => {
    const open = li.classList.toggle('open');
    row.setAttribute('aria-expanded', open ? 'true' : 'false');
  });

  li.appendChild(row);
  li.appendChild(detail);
  return li;
}

function render() {
  const r = REPORT, s = r.summary;

  app.appendChild(el('p', 'eyebrow', 'FlossWing scan report'));
  app.appendChild(el('h1', null, r.run.target_repo_path));
  app.appendChild(readout([
    ['Run', r.run.id],
    ['Status', r.run.status],
    ['Model', r.run.model],
    ['Started', r.run.started_at],
    ['Finished', r.run.finished_at || '-'],
    ['Findings', s.findings_total],
    ['Clusters', s.clusters_total],
    ['Rendered', r.rendered_at],
  ]));

  const tiles = el('div', 'tiles');
  for (const [n, lbl, cls] of [
    [s.findings_confirmed, 'Act on these', 't-confirmed'],
    [s.findings_uncertain, 'Needs your call', 't-uncertain'],
    [s.findings_rejected, 'Dismissed', 't-rejected'],
    [s.findings_total, 'Raised by Hunt', 't-total'],
  ]) {
    const t = el('div', 'tile ' + cls);
    t.appendChild(el('span', 'n', n));
    t.appendChild(el('span', 'l', lbl));
    tiles.appendChild(t);
  }
  app.appendChild(tiles);

  const present = STATUSES.filter(st => r.findings.some(f => f.status === st));
  const filters = el('nav', 'filters');
  const list = el('ol', 'findings');
  const mk = (key, label) => {
    const b = el('button', 'chip', label);
    b.type = 'button';
    b.setAttribute('aria-pressed', key === 'all' ? 'true' : 'false');
    b.addEventListener('click', () => {
      filters.querySelectorAll('.chip').forEach(
        c => c.setAttribute('aria-pressed', String(c === b)));
      list.querySelectorAll('.f').forEach(
        li => { li.hidden = key !== 'all' && li.dataset.status !== key; });
    });
    return b;
  };
  filters.appendChild(mk('all', 'All ' + r.findings.length));
  present.forEach(st => filters.appendChild(
    mk(st, st + ' ' + r.findings.filter(f => f.status === st).length)));
  app.appendChild(filters);

  r.findings.forEach((f, i) => list.appendChild(findingRow(f, i)));
  app.appendChild(list);

  app.appendChild(el('p', 'caveat',
    'A scan that finds nothing is not evidence that this repository is '
    + 'secure. FlossWing only looks for the attack classes Recon queued for '
    + 'this run, and every verdict here is a static argument over source that '
    + 'has not been confirmed against a running instance. Re-check each '
    + 'finding against current upstream before acting on it.'));
}

render();
"""


def render_html(report: ReportV1) -> str:
    """Render ``report`` as a standalone HTML document.

    The result is self-contained: inline CSS and JS, no external resource of
    any kind, so it renders offline straight from ``file://``.
    """
    payload = _payload_json(report)
    return (
        "<!doctype html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>FlossWing report {report.run.id}</title>\n"
        f"<style>{_CSS}</style>\n"
        "</head>\n"
        "<body>\n"
        '<main id="app"></main>\n'
        f"<script>const REPORT = {payload};\n{_JS}</script>\n"
        "</body>\n"
        "</html>\n"
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/unit/test_report_html.py -q`
Expected: PASS (9 tests)

- [ ] **Step 5: Run the gates**

Run: `.venv/bin/ruff check . && .venv/bin/mypy --strict flosswing`
Expected: `All checks passed!` and `Success: no issues found`

- [ ] **Step 6: Eyeball the real output once**

```bash
.venv/bin/python -c "
from flosswing.state import session
from flosswing.stages.report import load_report
from flosswing.stages.report_html import render_html
r = load_report('01KYBAE5BYVXPNZDDFFSKZTVWH', session.session_factory())
open('/tmp/rh.html','w').write(render_html(r))
print('ok')
"
```
Expected: `ok`. Open `/tmp/rh.html` in a browser: findings appear confirmed-first, filters work, rows expand. Delete `/tmp/rh.html` afterwards.

(If that run id no longer exists locally, substitute any completed run id from
`sqlite3 ~/.flosswing/state.db "select id from runs where status='completed' limit 1;"`.)

- [ ] **Step 7: Commit**

```bash
git add flosswing/stages/report_html.py tests/unit/test_report_html.py
git commit -m "Render ReportV1 as a self-contained HTML document

Per docs/specs/2026-07-25-html-report-design.md § Architecture. Inline CSS
and JS, no external resources, renders offline from file://.

All finding text reaches the DOM through textContent, so repo-derived
strings cannot become markup. Carries the ARCHITECTURE.md threat-model
requirement that zero findings is not evidence of security."
```

---

### Task 3: Wire `html` into the Report stage

**Files:**
- Modify: `flosswing/stages/report.py:820` (`_VALID_FORMATS`) and the format loop at `:845-880`
- Test: `tests/unit/test_report_html.py`

**Interfaces:**
- Consumes: `render_html(report: ReportV1) -> str` from Task 2.
- Produces: `render(...)` accepts `"html"` and writes `output_dir / "report.html"`, appending `"html"` to `ReportRenderResult.formats_written`.

- [ ] **Step 1: Write the failing test**

Append to `tests/unit/test_report_html.py`:

First add the two imports this test needs to the **top** of
`tests/unit/test_report_html.py`, below the existing `import json`:

```python
from pathlib import Path

import pytest
```

(They are added here rather than in Task 1 because ruff's `F401` would have
failed on them while unused.)

Then append the test:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/unit/test_report_html.py::test_render_writes_report_html -q`
Expected: FAIL — `assert 'html' in []` (the format is skipped by the `else: continue` branch)

- [ ] **Step 3: Add `html` to the valid formats**

In `flosswing/stages/report.py`, change line 820 from:

```python
_VALID_FORMATS: frozenset[str] = frozenset({"md", "json", "sarif"})
```

to:

```python
_VALID_FORMATS: frozenset[str] = frozenset({"md", "json", "sarif", "html"})
```

- [ ] **Step 4: Add the write branch**

In the same file, add this branch immediately after the `elif fmt == "json":` block and before `elif fmt == "sarif":`:

```python
        elif fmt == "html":
            from flosswing.stages.report_html import render_html

            content = render_html(report)
            path = output_dir / "report.html"
            path.write_text(content, encoding="utf-8")
            bytes_written += path.stat().st_size
            formats_written.append("html")
```

Then update the `render()` docstring — replace the line
`` ``report.md`` and/or ``report.json`` depending on ``formats``; `` with:

```
    ``report.md``, ``report.json`` and/or ``report.html`` depending on
    ``formats``;
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/unit/test_report_html.py tests/unit/test_cli_report.py -q`
Expected: PASS — no regression in the existing report tests

- [ ] **Step 6: Run the gates**

Run: `.venv/bin/ruff check . && .venv/bin/mypy --strict flosswing`
Expected: `All checks passed!` and `Success: no issues found`

- [ ] **Step 7: Commit**

```bash
git add flosswing/stages/report.py tests/unit/test_report_html.py
git commit -m "Accept --format html in the Report stage

Per docs/specs/2026-07-25-html-report-design.md § Architecture. Adds html to
_VALID_FORMATS and one write branch; report.py stays the orchestrator."
```

---

### Task 4: Make `html` a default format in the CLI and TUI

**Files:**
- Modify: `flosswing/cli.py:172,175` (scan) and `:224,227` (report)
- Modify: `flosswing/tui/screens/new_scan.py:33,48`
- Test: `tests/unit/test_cli_help.py:104,113`

**Interfaces:**
- Consumes: `"html"` accepted by `report.render()` from Task 3.
- Produces: no new symbols. Default format string becomes `md,json,html` in all four places.

- [ ] **Step 1: Tighten the help-text tests so they can actually fail**

In `tests/unit/test_cli_help.py`, line 103-104 currently reads:

```python
    # Default is md,json — must appear in the help text.
    assert "md,json" in result.output
```

`"md,json"` is a substring of `"md,json,html"`, so this assertion would keep
passing while no longer testing the real default. Replace with:

```python
    # Default is md,json,html — assert the full string so this test still
    # fails if the default changes.
    assert "md,json,html" in result.output
```

Apply the same change at line 113 (in `test_report_help_exits_zero_and_lists_options`), replacing `assert "md,json" in result.output` with `assert "md,json,html" in result.output`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/unit/test_cli_help.py -q`
Expected: FAIL — 2 failures, `assert 'md,json,html' in '...default md,json...'`

- [ ] **Step 3: Update both CLI defaults**

In `flosswing/cli.py`, in **both** the `scan` option block (line ~168) and the `report` option block (line ~220), change:

```python
    default="md,json",
    help=(
        "Comma-separated output formats for the report "
        "(default md,json; valid: md, json, sarif)."
    ),
```

to:

```python
    default="md,json,html",
    help=(
        "Comma-separated output formats for the report "
        "(default md,json,html; valid: md, json, sarif, html)."
    ),
```

- [ ] **Step 4: Update the TUI new-scan screen**

In `flosswing/tui/screens/new_scan.py`, line 33, change:

```python
_FORMATS: list[str] = ["md", "json", "sarif"]
```

to:

```python
_FORMATS: list[str] = ["md", "json", "sarif", "html"]
```

Without this the TUI rejects `html` as an invalid format at line 77.

Then at line 48, change:

```python
            yield Input(value="md,json", placeholder="formats (comma sep)", id="scan-formats")
```

to:

```python
            yield Input(value="md,json,html", placeholder="formats (comma sep)", id="scan-formats")
```

- [ ] **Step 5: Run the full suite**

Run: `.venv/bin/python -m pytest tests/unit -q`
Expected: exit code 0, no failures

- [ ] **Step 6: Run the gates**

Run: `.venv/bin/ruff check . && .venv/bin/mypy --strict flosswing`
Expected: `All checks passed!` and `Success: no issues found`

- [ ] **Step 7: Commit**

```bash
git add flosswing/cli.py flosswing/tui/screens/new_scan.py tests/unit/test_cli_help.py
git commit -m "Default --format to md,json,html in CLI and TUI

Per docs/specs/2026-07-25-html-report-design.md § Configuration / CLI.

The TUI keeps its own _FORMATS list and its own default; without updating
both it would reject html as invalid. Also tightens the help-text assertions
from 'md,json' to the full default -- the old substring kept passing against
'md,json,html' while no longer testing anything."
```

---

### Task 5: Record the scope decision in ARCHITECTURE.md

This is an operator-curated document. The wording matters more than the code: it must record that a static file is a report format **without** reading as license for a server later.

**Files:**
- Modify: `ARCHITECTURE.md` § *Stage 8: Report* (output list ~line 246, v1.0 scope note ~line 258)

**Interfaces:**
- Consumes: nothing. Produces: nothing. Documentation only.

- [ ] **Step 1: Add `report.html` to the output list**

In `ARCHITECTURE.md`, in the Stage 8 output list, after the `report.sarif` bullet, add:

```markdown
- `report.html` — self-contained triage view: findings ordered by validation
  verdict and reachability rather than severity, opened directly from disk
```

- [ ] **Step 2: Extend the v1.0 scope note**

Immediately after the existing v1.0 scope-note blockquote, add a second blockquote:

```markdown
> **`report.html` and the "no web UI" non-goal (operator decision,
> 2026-07-25):** `report.html` is a static file rendered from the same state
> as the other formats, not a service. The "no web UI" hard non-goal and the
> v2 "local server mode" item both stand: FlossWing serves nothing, listens
> on no port, and opens no browser. A file on disk that an operator chooses
> to open is not a UI. See
> `docs/specs/2026-07-25-html-report-design.md`.
```

- [ ] **Step 3: Verify no other doc claims the format list is exhaustive**

Run: `grep -rn "md, json, sarif\|md,json" ARCHITECTURE.md docs/*.md`
Expected: only the lines just edited, plus `docs/specs/` design docs which are
historical records and must **not** be retro-edited.

- [ ] **Step 4: Run the full suite one last time**

Run: `.venv/bin/python -m pytest tests/unit -q && .venv/bin/ruff check . && .venv/bin/mypy --strict flosswing`
Expected: exit 0, `All checks passed!`, `Success: no issues found`

- [ ] **Step 5: Commit**

```bash
git add ARCHITECTURE.md
git commit -m "Record report.html scope decision in ARCHITECTURE.md

Per docs/specs/2026-07-25-html-report-design.md § Documentation changes.

Adds report.html to the Stage 8 output list and records the operator
decision that a static file is a report format, not the 'no web UI'
non-goal -- worded so it cannot later be cited as precedent for a server."
```

---

## Verification before opening the PR

- [ ] `.venv/bin/python -m pytest tests/unit -q` — exit 0
- [ ] `.venv/bin/ruff check .` — `All checks passed!`
- [ ] `.venv/bin/mypy --strict flosswing` — `Success: no issues found`
- [ ] `flosswing report <run_id>` on a real completed run writes `report.html`; open it and confirm ordering, filters, and expand all work
- [ ] `grep -c '[^\x00-\x7F]' report.html` returns 0 (pure ASCII)
- [ ] No `docs/schema.sql` or `docs/tool-contracts.md` changes in `git diff main...HEAD --stat`
