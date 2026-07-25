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
