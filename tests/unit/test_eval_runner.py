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
"""Unit tests for flosswing.eval.runner (score_run, run_evaluation, render_scorecard).

Tests use a seeded in-process SQLite DB (via isolated_db fixture) and exercise
pure scoring paths only — no API calls, no orchestrator.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from ulid import ULID

from flosswing.errors import EvalConfigError
from flosswing.eval import runner
from flosswing.eval.corpus import CorpusEntry, GroundTruthVuln
from flosswing.state import session as st_session
from flosswing.state.models import Finding, HuntTask, Run


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


@pytest.fixture()
def isolated_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    monkeypatch.setenv("FLOSSWING_DB_URL", f"sqlite:///{tmp_path}/state.db")
    monkeypatch.setattr(st_session, "_cached_engine", None, raising=False)
    monkeypatch.setattr(st_session, "_cached_session_factory", None, raising=False)
    yield tmp_path


def _seed_run(run_id: str) -> None:
    with st_session.session_scope() as s:
        s.add(Run(
            id=run_id, target_repo_path="/tmp/x", target_repo_sha=None,
            depth="standard", budget_total=100, budget_used=1,
            started_at=_now(), finished_at=_now(), status="completed",
            config_json='{"model": "claude-opus-4-7"}', flosswing_version="1.0.1",
        ))


def _seed_task(run_id: str) -> str:
    tid = str(ULID())
    with st_session.session_scope() as s:
        s.add(HuntTask(
            id=tid, run_id=run_id, attack_class="command_injection",
            scope_hint="src/", rationale="", priority="normal", source="recon",
            parent_finding_id=None, status="completed", created_at=_now(),
            started_at=_now(), finished_at=_now(), findings_count=0,
        ))
    return tid


def _seed_finding(run_id: str, tid: str, *, file: str, line: int,
                  status: str = "confirmed", attack_class: str = "command_injection",
                  dedupe_role: str | None = None,
                  primary_finding_id: str | None = None) -> str:
    fid = str(ULID())
    with st_session.session_scope() as s:
        s.add(Finding(
            id=fid, run_id=run_id, hunt_task_id=tid, attack_class=attack_class,
            file=file, function="fn", line_start=line, line_end=line,
            severity="high", confidence="likely", status=status,
            title="t", description="d" * 60, poc_code=None, poc_result_json=None,
            suggested_fix=None, created_at=_now(), reachable=None,
            dedupe_role=dedupe_role, dedupe_cluster_id=None,
            primary_finding_id=primary_finding_id,
        ))
    return fid


_ENTRY = CorpusEntry(
    name="v02_smoke", repo="v02_smoke", description="",
    vulns=[GroundTruthVuln(
        id="cmdi", file="src/example/cli.py", line_start=16, line_end=16,
        attack_class="command_injection",
    )],
)


def test_score_run_confirmed_primary_matches(isolated_db: Path) -> None:
    run_id = str(ULID())
    _seed_run(run_id)
    tid = _seed_task(run_id)
    _seed_finding(run_id, tid, file="src/example/cli.py", line=16)

    report = runner.score_run(run_id, _ENTRY)
    assert report.true_positives == 1
    assert report.false_positives == 0
    assert report.recall == 1.0


def test_score_run_excludes_unconfirmed_and_nonprimary(isolated_db: Path) -> None:
    run_id = str(ULID())
    _seed_run(run_id)
    tid = _seed_task(run_id)
    primary = _seed_finding(run_id, tid, file="src/example/cli.py", line=16,
                            dedupe_role="primary")
    # A duplicate (non-primary) on the same spot must be ignored, not counted FP.
    _seed_finding(run_id, tid, file="src/example/cli.py", line=16,
                  dedupe_role="duplicate", primary_finding_id=primary)
    # A variant (non-primary) on the same spot must likewise be ignored.
    _seed_finding(run_id, tid, file="src/example/cli.py", line=16,
                  dedupe_role="variant", primary_finding_id=primary)
    # An uncertain finding elsewhere must be excluded by default.
    _seed_finding(run_id, tid, file="src/other.py", line=99, status="uncertain")

    report = runner.score_run(run_id, _ENTRY)
    assert report.true_positives == 1
    assert report.false_positives == 0


def test_score_run_include_uncertain(isolated_db: Path) -> None:
    run_id = str(ULID())
    _seed_run(run_id)
    tid = _seed_task(run_id)
    _seed_finding(run_id, tid, file="src/example/cli.py", line=16)
    _seed_finding(run_id, tid, file="src/other.py", line=99, status="uncertain")

    report = runner.score_run(run_id, _ENTRY, include_uncertain=True)
    assert report.true_positives == 1
    assert report.false_positives == 1  # the uncertain finding now counts


def test_run_evaluation_from_run(isolated_db: Path, tmp_path: Path) -> None:
    run_id = str(ULID())
    _seed_run(run_id)
    tid = _seed_task(run_id)
    _seed_finding(run_id, tid, file="src/example/cli.py", line=16)

    # Manifest dir containing just v02_smoke.
    mdir = tmp_path / "gt"
    mdir.mkdir()
    (mdir / "v02_smoke.toml").write_text(
        'name = "v02_smoke"\nrepo = "v02_smoke"\n\n'
        '[[vuln]]\nid = "cmdi"\nfile = "src/example/cli.py"\n'
        'line_start = 16\nline_end = 16\nattack_class = "command_injection"\n',
        encoding="utf-8",
    )
    result = runner.run_evaluation(
        manifest_dir=mdir, corpus_root=Path("tests/corpus"),
        from_run=run_id, corpus_name="v02_smoke",
    )
    assert len(result.repos) == 1
    assert result.repos[0].run_id == run_id
    assert result.aggregate.true_positives == 1


def test_run_evaluation_from_run_without_corpus_name_raises(
    isolated_db: Path,
) -> None:
    with pytest.raises(EvalConfigError):
        runner.run_evaluation(
            corpus_root=Path("tests/corpus"), from_run="whatever",
        )


def test_run_evaluation_empty_corpus(isolated_db: Path, tmp_path: Path) -> None:
    # Empty manifest dir + no from_run/corpus_name: load_corpus() returns [],
    # so the scan loop never runs (no API) and we exercise _empty_score().
    mdir = tmp_path / "gt"
    mdir.mkdir()
    result = runner.run_evaluation(
        manifest_dir=mdir, corpus_root=Path("tests/corpus"),
    )
    assert result.repos == []
    assert result.aggregate.true_positives == 0
    assert result.aggregate.precision is None
    assert result.aggregate.recall is None


def test_render_scorecard_contains_metrics(isolated_db: Path) -> None:
    run_id = str(ULID())
    _seed_run(run_id)
    tid = _seed_task(run_id)
    _seed_finding(run_id, tid, file="src/example/cli.py", line=16)
    report = runner.score_run(run_id, _ENTRY)
    result = runner.EvalResult(
        repos=[runner.RepoResult(name="v02_smoke", run_id=run_id, score=report)],
        aggregate=report,
    )
    text = runner.render_scorecard(result)
    assert "v02_smoke" in text
    assert "precision" in text.lower()
    assert "recall" in text.lower()
