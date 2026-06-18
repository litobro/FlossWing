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
"""Eval runner: score an existing run or run the pipeline then score.

`score_run` / `run_evaluation(--from-run)` / `render_scorecard` are pure
(no API) and unit-tested. `run_and_score` and the scan branch drive the real
pipeline via orchestrator.run_scan and are operator-run / integration-gated.
See docs/specs/2026-06-15-eval-design.md.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from pydantic import BaseModel

from flosswing import config as fcfg
from flosswing import orchestrator
from flosswing.errors import EvalConfigError
from flosswing.eval import corpus as eval_corpus
from flosswing.eval import scoring
from flosswing.eval.corpus import CorpusEntry
from flosswing.eval.scoring import ScoredFinding, ScoreReport
from flosswing.stages import report as report_stage
from flosswing.state import session as st_session

# Score only what the operator-facing pipeline treats as distinct, traceable
# findings: unclustered (NULL) or dedupe 'primary'. 'duplicate' and 'variant'
# roles are intentionally excluded (mirrors the Trace stage's eligibility
# filter).
_ELIGIBLE_DEDUPE_ROLES: frozenset[str | None] = frozenset({None, "primary"})


class RepoResult(BaseModel):
    name: str
    run_id: str
    score: ScoreReport


class EvalResult(BaseModel):
    repos: list[RepoResult]
    aggregate: ScoreReport


def _empty_score() -> ScoreReport:
    return ScoreReport(
        true_positives=0, false_positives=0, false_negatives=0,
        precision=None, recall=None, f1=None, matches=[], by_attack_class={},
    )


def _scored_findings_for_run(
    run_id: str, *, include_uncertain: bool
) -> list[ScoredFinding]:
    """Operator-facing findings for ``run_id`` projected for scoring.

    Filters to confirmed (plus uncertain when requested) findings that are
    dedupe primaries or unclustered — the same eligibility the operator sees.
    """
    # session_factory() is accepted for API symmetry but ignored by
    # report._load, which uses the module-level session scope keyed off
    # FLOSSWING_DB_URL.
    report = report_stage.load_report(run_id, st_session.session_factory())
    allowed = {"confirmed"} | ({"uncertain"} if include_uncertain else set())
    out: list[ScoredFinding] = []
    for f in report.findings:
        if f.status not in allowed:
            continue
        if f.dedupe_role not in _ELIGIBLE_DEDUPE_ROLES:
            continue
        out.append(ScoredFinding(
            file=f.file, line_start=f.line_start,
            line_end=f.line_end, attack_class=f.attack_class,
        ))
    return out


def score_run(
    run_id: str, entry: CorpusEntry, *, include_uncertain: bool = False
) -> ScoreReport:
    """Score an existing run's findings against a corpus entry. No API."""
    findings = _scored_findings_for_run(run_id, include_uncertain=include_uncertain)
    return scoring.score(entry.vulns, findings)


def run_and_score(
    entry: CorpusEntry, *, corpus_root: Path, include_uncertain: bool = False
) -> tuple[str, ScoreReport]:
    """Run the full pipeline against the entry's repo, then score it.

    API-touching; operator-run / integration-gated.
    """
    repo_root = (corpus_root / entry.repo).resolve()
    cfg = fcfg.resolve(
        repo_root=repo_root, model=None, provider=None,
        recon_token_budget=None, hunt_token_budget=None,
        validate_token_budget=None, gapfill_token_budget=None,
        dedupe_token_budget=None, trace_token_budget=None,
        trace_max_depth=None, auto_render=False, output_formats=["json"],
    )
    result = asyncio.run(orchestrator.run_scan(cfg))
    return result.run_id, score_run(
        result.run_id, entry, include_uncertain=include_uncertain
    )


def run_evaluation(
    *,
    manifest_dir: Path = eval_corpus.DEFAULT_MANIFEST_DIR,
    corpus_root: Path,
    from_run: str | None = None,
    corpus_name: str | None = None,
    include_uncertain: bool = False,
) -> EvalResult:
    """Score one existing run (``from_run``) or scan+score the corpus."""
    if from_run is not None:
        if corpus_name is None:
            raise EvalConfigError("corpus_name is required with --from-run")
        entry = eval_corpus.find_entry(corpus_name, manifest_dir)
        rep = score_run(from_run, entry, include_uncertain=include_uncertain)
        return EvalResult(
            repos=[RepoResult(name=entry.name, run_id=from_run, score=rep)],
            aggregate=rep,
        )

    entries = (
        [eval_corpus.find_entry(corpus_name, manifest_dir)]
        if corpus_name is not None
        else eval_corpus.load_corpus(manifest_dir)
    )
    repos: list[RepoResult] = []
    for entry in entries:
        run_id, rep = run_and_score(
            entry, corpus_root=corpus_root, include_uncertain=include_uncertain
        )
        repos.append(RepoResult(name=entry.name, run_id=run_id, score=rep))
    agg = scoring.aggregate([r.score for r in repos]) if repos else _empty_score()
    return EvalResult(repos=repos, aggregate=agg)


def _fmt(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.3f}"


def render_scorecard(result: EvalResult) -> str:
    """Render a human-readable scorecard (per-repo rows + aggregate)."""
    header = "repo                 TP  FP  FN  precision  recall  f1"
    lines = [header, "-" * len(header)]
    for r in result.repos:
        s = r.score
        lines.append(
            f"{r.name:<20} {s.true_positives:>3} {s.false_positives:>3} "
            f"{s.false_negatives:>3}  {_fmt(s.precision):>9}  "
            f"{_fmt(s.recall):>6}  {_fmt(s.f1)}"
        )
    a = result.aggregate
    lines.append(
        f"{'AGGREGATE':<20} {a.true_positives:>3} {a.false_positives:>3} "
        f"{a.false_negatives:>3}  {_fmt(a.precision):>9}  "
        f"{_fmt(a.recall):>6}  {_fmt(a.f1)}"
    )
    return "\n".join(lines)
