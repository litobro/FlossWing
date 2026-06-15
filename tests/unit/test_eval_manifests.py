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

from __future__ import annotations

from flosswing.eval import corpus


def test_packaged_manifests_load_and_validate() -> None:
    """Every shipped ground-truth manifest parses and validates."""
    entries = corpus.load_corpus()  # DEFAULT_MANIFEST_DIR
    by_name = {e.name: e for e in entries}
    assert {"v02_smoke", "v08_dedupe_smoke"} <= set(by_name)

    v02 = by_name["v02_smoke"]
    assert v02.repo == "v02_smoke"
    assert len(v02.vulns) == 1
    assert v02.vulns[0].attack_class == "command_injection"
    assert v02.vulns[0].file == "src/example/cli.py"
    assert v02.vulns[0].id == "cmdi-greet"
    assert v02.vulns[0].line_start == 16
    assert v02.vulns[0].line_end == 16

    # One real root-cause vuln despite two sinks (dedupe collapses them).
    v08 = by_name["v08_dedupe_smoke"]
    assert len(v08.vulns) == 1
    assert v08.vulns[0].attack_class == "command_injection"
    assert v08.vulns[0].id == "cmdi-run-ops"
    assert v08.vulns[0].line_start == 10
    assert v08.vulns[0].line_end == 14
    assert v08.vulns[0].tolerance == 5
