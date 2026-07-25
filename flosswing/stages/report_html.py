# FlossWing — local-CLI vulnerability research harness.
# Copyright (C) 2026  FlossWing contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Render a ReportV1 as a self-contained HTML triage view.

Per docs/specs/2026-07-25-html-report-design.md.

The target repo is untrusted input, so finding text is hardened against injection
via two distinct mechanisms:

1. The JSON payload is embedded as a raw ``const REPORT = <json>`` literal inside
   a ``<script>`` element. A finding title containing ``</script>`` would close the
   element early and turn the rest into live markup, so ``<`` is escaped to
   ``\\u003c`` to prevent that.
2. Individual finding fields are later written into DOM nodes via ``textContent``,
   which cannot interpret markup.
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
    "pending_validation": 2,
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
    # Sort findings once and serialize each exactly once, avoiding the overhead
    # of an initial report.model_dump() that gets immediately discarded.
    sorted_findings: list[dict[str, object]] = [
        f.model_dump(mode="json") for f in sorted(report.findings, key=_triage_sort_key)
    ]
    data = report.model_dump(mode="json", exclude={"findings"})
    data["findings"] = sorted_findings
    return json.dumps(data, ensure_ascii=True, sort_keys=True).replace("<", "\\u003c")


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
h1,.ftitle,.fmeta,.fmeta span,.stage p{overflow-wrap:anywhere}
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
.pill.s-pending_validation{color:var(--uncertain);border-color:var(--uncertain)}
.pill.s-rejected{color:var(--reject);border-color:var(--reject)}
.pill.s-superseded{color:var(--reject);border-color:var(--reject)}
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
const STATUSES = ['confirmed','uncertain','pending_validation','rejected','superseded'];
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
  // f.status is a bare string with no character restrictions upstream; a
  // crafted value containing whitespace would otherwise split into extra
  // class tokens when concatenated raw into className, letting repo text
  // toggle an unrelated existing class (e.g. one that hides the badge).
  const statusCls = 'pill s-' + String(f.status).replace(/\\s+/g, '-');
  pills.appendChild(el('span', statusCls, f.status));
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
  if (f.poc_code) {
    detail.appendChild(stage('PoC - not run against a live target', f.poc_code, true));
  }

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

  // run.id is repo/run-derived and only ever flows through this escaped
  // JSON payload; setting the DOM `title` property (not markup) is what
  // keeps a hostile id from ever being parsed as HTML.
  document.title = 'FlossWing report ' + r.run.id;

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
        "<title>FlossWing report</title>\n"
        f"<style>{_CSS}</style>\n"
        "</head>\n"
        "<body>\n"
        "<noscript>"
        "<p>This report renders its findings with JavaScript, which is "
        "disabled or unavailable in this browser. Script-free alternatives "
        "-- report.md and report.json -- are in the same output directory "
        "as this file.</p>"
        "</noscript>\n"
        '<main id="app"></main>\n'
        f"<script>const REPORT = {payload};\n{_JS}</script>\n"
        "</body>\n"
        "</html>\n"
    )
