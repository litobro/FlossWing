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

"""Integration smoke test for the flosswing eval corpus-scoring pipeline.

Gated by FLOSSWING_INTEGRATION=1 — NOT run in normal CI. Uses
whichever auth env vars are present (direct Anthropic, Foundry API
key, or Entra ID via az login).

Per docs/specs/2026-06-15-eval-design.md § Testing strategy: a single
gated invocation that runs the full eval pipeline against
tests/corpus/v02_smoke/ and scores the result.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from flosswing.eval import corpus, runner

pytestmark = pytest.mark.skipif(
    os.environ.get("FLOSSWING_INTEGRATION") != "1",
    reason="integration tests gated by FLOSSWING_INTEGRATION=1",
)


def test_eval_runs_full_pipeline_against_v02_smoke() -> None:
    """Default eval path: scan v02_smoke end-to-end, then score.

    Asserts the command produces a structured result, NOT a specific score
    (LLM output is non-deterministic).
    """
    entry = corpus.find_entry("v02_smoke")
    result = runner.run_evaluation(
        corpus_root=Path("tests/corpus"), corpus_name="v02_smoke",
    )
    assert len(result.repos) == 1
    assert result.repos[0].name == "v02_smoke"
    assert (
        result.aggregate.true_positives + result.aggregate.false_negatives
        == len(entry.vulns)
    )
