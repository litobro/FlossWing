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

"""Pure precision/recall/F1 scorer for eval.

Matches pipeline findings against ground-truth vulns: same file, same
attack class, finding location within ±tolerance of the ground-truth
location, at most one finding per ground-truth entry. No DB, no API —
a deterministic function of its inputs. See docs/specs/2026-06-15-eval-design.md.
"""

from __future__ import annotations

from dataclasses import dataclass

from pydantic import BaseModel

from flosswing.eval.corpus import GroundTruthVuln


@dataclass(frozen=True)
class ScoredFinding:
    """Minimal projection of a pipeline finding used for scoring."""

    file: str
    line_start: int
    line_end: int
    attack_class: str


class Match(BaseModel):
    gt_id: str
    finding_index: int
    line_distance: int


class ClassScore(BaseModel):
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float | None
    recall: float | None


class ScoreReport(BaseModel):
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float | None
    recall: float | None
    f1: float | None
    matches: list[Match]
    by_attack_class: dict[str, ClassScore]


def _interval_distance(a0: int, a1: int, b0: int, b1: int) -> int:
    """Gap between intervals [a0,a1] and [b0,b1]; 0 if they overlap."""
    if a1 < b0:
        return b0 - a1
    if b1 < a0:
        return a0 - b1
    return 0


def _ratio(num: int, den: int) -> float | None:
    """num/den, or None when den == 0 (undefined)."""
    return None if den == 0 else num / den


def _f1(precision: float | None, recall: float | None) -> float | None:
    """Harmonic mean of precision and recall; None if either is undefined."""
    if precision is None or recall is None:
        return None
    if precision + recall == 0:
        return 0.0
    return 2 * precision * recall / (precision + recall)


def score(
    ground_truth: list[GroundTruthVuln], findings: list[ScoredFinding]
) -> ScoreReport:
    """Score ``findings`` against ``ground_truth``.

    Greedy assignment: ground-truth entries are processed in order; each
    consumes the closest still-unmatched candidate finding (ties broken by
    line_start, then finding index). Unmatched findings are false positives;
    unmatched ground-truth entries are false negatives.

    When two ground-truth entries are within tolerance of the same finding,
    ground-truth list order decides which claims it; later entries compete
    only for the remaining unmatched findings.
    """
    consumed: set[int] = set()
    matches: list[Match] = []
    for gt in ground_truth:
        best_key: tuple[int, int, int] | None = None
        best_idx: int | None = None
        for i, f in enumerate(findings):
            if i in consumed or f.file != gt.file or f.attack_class != gt.attack_class:
                continue
            dist = _interval_distance(
                f.line_start, f.line_end, gt.line_start, gt.line_end
            )
            if dist > gt.tolerance:
                continue
            key = (dist, f.line_start, i)
            if best_key is None or key < best_key:
                best_key, best_idx = key, i
        if best_idx is not None and best_key is not None:
            consumed.add(best_idx)
            matches.append(
                Match(gt_id=gt.id, finding_index=best_idx, line_distance=best_key[0])
            )

    tp = len(matches)
    fp = len(findings) - tp
    fn = len(ground_truth) - tp
    precision = _ratio(tp, len(findings))
    recall = _ratio(tp, len(ground_truth))

    matched_idx = {m.finding_index for m in matches}
    matched_gt = {m.gt_id for m in matches}
    classes = sorted(
        {g.attack_class for g in ground_truth} | {f.attack_class for f in findings}
    )
    by_class: dict[str, ClassScore] = {}
    for c in classes:
        gt_c = [g for g in ground_truth if g.attack_class == c]
        find_c = [i for i, f in enumerate(findings) if f.attack_class == c]
        tp_c = sum(1 for g in gt_c if g.id in matched_gt)
        fp_c = sum(1 for i in find_c if i not in matched_idx)
        fn_c = len(gt_c) - tp_c
        by_class[c] = ClassScore(
            true_positives=tp_c,
            false_positives=fp_c,
            false_negatives=fn_c,
            precision=_ratio(tp_c, tp_c + fp_c),
            recall=_ratio(tp_c, tp_c + fn_c),
        )

    return ScoreReport(
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        precision=precision,
        recall=recall,
        f1=_f1(precision, recall),
        matches=matches,
        by_attack_class=by_class,
    )


def aggregate(reports: list[ScoreReport]) -> ScoreReport:
    """Combine per-repo reports into one. ``matches`` is dropped (indices are
    per-report and not comparable across repos)."""
    tp = sum(r.true_positives for r in reports)
    fp = sum(r.false_positives for r in reports)
    fn = sum(r.false_negatives for r in reports)
    class_keys = sorted({c for r in reports for c in r.by_attack_class})
    by_class: dict[str, ClassScore] = {}
    for c in class_keys:
        parts = [r.by_attack_class[c] for r in reports if c in r.by_attack_class]
        tpc = sum(p.true_positives for p in parts)
        fpc = sum(p.false_positives for p in parts)
        fnc = sum(p.false_negatives for p in parts)
        by_class[c] = ClassScore(
            true_positives=tpc,
            false_positives=fpc,
            false_negatives=fnc,
            precision=_ratio(tpc, tpc + fpc),
            recall=_ratio(tpc, tpc + fnc),
        )
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    return ScoreReport(
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        precision=precision,
        recall=recall,
        f1=_f1(precision, recall),
        matches=[],
        by_attack_class=by_class,
    )
