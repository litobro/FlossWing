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

from flosswing.eval import scoring
from flosswing.eval.corpus import GroundTruthVuln
from flosswing.eval.scoring import ScoredFinding


def _gt(id: str, file: str, ls: int, le: int, ac: str, tol: int = 10) -> GroundTruthVuln:
    return GroundTruthVuln(
        id=id, file=file, line_start=ls, line_end=le, attack_class=ac, tolerance=tol
    )


def _f(file: str, ls: int, le: int, ac: str) -> ScoredFinding:
    return ScoredFinding(file=file, line_start=ls, line_end=le, attack_class=ac)


def test_exact_match() -> None:
    r = scoring.score(
        [_gt("g", "a.py", 10, 10, "command_injection")],
        [_f("a.py", 10, 10, "command_injection")],
    )
    assert (r.true_positives, r.false_positives, r.false_negatives) == (1, 0, 0)
    assert r.precision == 1.0 and r.recall == 1.0 and r.f1 == 1.0


def test_within_tolerance_boundary() -> None:
    gt = [_gt("g", "a.py", 10, 10, "command_injection", tol=5)]
    assert scoring.score(gt, [_f("a.py", 15, 15, "command_injection")]).true_positives == 1
    assert scoring.score(gt, [_f("a.py", 16, 16, "command_injection")]).true_positives == 0


def test_attack_class_mismatch_no_match() -> None:
    r = scoring.score(
        [_gt("g", "a.py", 10, 10, "command_injection")],
        [_f("a.py", 10, 10, "path_traversal")],
    )
    assert (r.true_positives, r.false_positives, r.false_negatives) == (0, 1, 1)


def test_file_mismatch_no_match() -> None:
    r = scoring.score(
        [_gt("g", "a.py", 10, 10, "command_injection")],
        [_f("b.py", 10, 10, "command_injection")],
    )
    assert r.true_positives == 0 and r.false_positives == 1 and r.false_negatives == 1


def test_two_findings_one_gt_extra_is_fp() -> None:
    r = scoring.score(
        [_gt("g", "a.py", 10, 14, "command_injection")],
        [
            _f("a.py", 10, 10, "command_injection"),
            _f("a.py", 14, 14, "command_injection"),
        ],
    )
    assert (r.true_positives, r.false_positives, r.false_negatives) == (1, 1, 0)
    assert r.precision == 0.5 and r.recall == 1.0


def test_recall_zero_when_no_findings() -> None:
    r = scoring.score([_gt("g", "a.py", 10, 10, "command_injection")], [])
    assert r.true_positives == 0 and r.false_negatives == 1
    assert r.precision is None  # no findings -> precision undefined
    assert r.recall == 0.0
    assert r.f1 is None


def test_empty_ground_truth_precision_none() -> None:
    r = scoring.score([], [_f("a.py", 1, 1, "command_injection")])
    assert r.recall is None and r.precision == 0.0 and r.false_positives == 1


def test_per_attack_class_breakdown() -> None:
    r = scoring.score(
        [
            _gt("g1", "a.py", 10, 10, "command_injection"),
            _gt("g2", "b.py", 20, 20, "path_traversal"),
        ],
        [
            _f("a.py", 10, 10, "command_injection"),
            _f("c.py", 99, 99, "path_traversal"),
        ],
    )
    assert r.by_attack_class["command_injection"].true_positives == 1
    assert r.by_attack_class["command_injection"].false_positives == 0
    assert r.by_attack_class["path_traversal"].true_positives == 0
    assert r.by_attack_class["path_traversal"].false_negatives == 1
    assert r.by_attack_class["path_traversal"].false_positives == 1


def test_aggregate_sums_and_recomputes() -> None:
    r1 = scoring.score(
        [_gt("g", "a.py", 10, 10, "command_injection")],
        [_f("a.py", 10, 10, "command_injection")],
    )
    r2 = scoring.score(
        [_gt("g", "b.py", 10, 10, "command_injection")],
        [_f("z.py", 1, 1, "command_injection")],
    )
    agg = scoring.aggregate([r1, r2])
    assert agg.true_positives == 1 and agg.false_positives == 1 and agg.false_negatives == 1
    assert agg.precision == 0.5 and agg.recall == 0.5
    assert agg.matches == []  # indices are per-report, not aggregatable
    assert agg.by_attack_class["command_injection"].true_positives == 1
