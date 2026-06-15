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
"""Unit tests for the `flosswing eval` CLI command."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from click.testing import CliRunner
from ulid import ULID

from flosswing.cli import main
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


def _seed(run_id: str, *, file: str = "src/example/cli.py", line: int = 16) -> None:
    with st_session.session_scope() as s:
        s.add(Run(
            id=run_id, target_repo_path="/tmp/x", target_repo_sha=None,
            depth="standard", budget_total=100, budget_used=1,
            started_at=_now(), finished_at=_now(), status="completed",
            config_json='{"model": "m"}', flosswing_version="1.0.1",
        ))
    tid = str(ULID())
    with st_session.session_scope() as s:
        s.add(HuntTask(
            id=tid, run_id=run_id, attack_class="command_injection",
            scope_hint="src/", rationale="", priority="normal", source="recon",
            parent_finding_id=None, status="completed", created_at=_now(),
            started_at=_now(), finished_at=_now(), findings_count=0,
        ))
    with st_session.session_scope() as s:
        s.add(Finding(
            id=str(ULID()), run_id=run_id, hunt_task_id=tid,
            attack_class="command_injection", file=file, function="greet",
            line_start=line, line_end=line, severity="high", confidence="likely",
            status="confirmed", title="t", description="d" * 60, poc_code=None,
            poc_result_json=None, suggested_fix=None, created_at=_now(),
            reachable=None, dedupe_role=None, dedupe_cluster_id=None,
            primary_finding_id=None,
        ))


def _mdir(tmp_path: Path) -> Path:
    d = tmp_path / "gt"
    d.mkdir(exist_ok=True)
    (d / "v02_smoke.toml").write_text(
        'name = "v02_smoke"\nrepo = "v02_smoke"\n\n'
        '[[vuln]]\nid = "cmdi"\nfile = "src/example/cli.py"\n'
        'line_start = 16\nline_end = 16\nattack_class = "command_injection"\n',
        encoding="utf-8",
    )
    return d


def test_eval_from_run_prints_scorecard(isolated_db: Path, tmp_path: Path) -> None:
    run_id = str(ULID())
    _seed(run_id)
    res = CliRunner().invoke(main, [
        "eval", "--from-run", run_id, "--corpus", "v02_smoke",
        "--manifest-dir", str(_mdir(tmp_path)),
    ])
    assert res.exit_code == 0, res.output
    assert "v02_smoke" in res.output
    assert "AGGREGATE" in res.output


def test_eval_from_run_requires_corpus(isolated_db: Path, tmp_path: Path) -> None:
    run_id = str(ULID())
    _seed(run_id)
    res = CliRunner().invoke(main, [
        "eval", "--from-run", run_id, "--manifest-dir", str(_mdir(tmp_path)),
    ])
    assert res.exit_code == 2
    assert "corpus" in res.stderr.lower()


def test_eval_min_recall_gate_fails(isolated_db: Path, tmp_path: Path) -> None:
    # Seed a finding in the WRONG place so recall is 0 -> gate fails.
    run_id = str(ULID())
    _seed(run_id, file="src/wrong.py", line=999)
    res = CliRunner().invoke(main, [
        "eval", "--from-run", run_id, "--corpus", "v02_smoke",
        "--manifest-dir", str(_mdir(tmp_path)), "--min-recall", "0.5",
    ])
    assert res.exit_code == 1
    assert "v02_smoke" in res.output  # scorecard still printed


def test_eval_min_precision_gate_fails(isolated_db: Path, tmp_path: Path) -> None:
    # Seed a finding in the WRONG place so precision is 0.0 (1 finding, 0 TP)
    # -> gate fails.
    run_id = str(ULID())
    _seed(run_id, file="src/wrong.py", line=999)
    res = CliRunner().invoke(main, [
        "eval", "--from-run", run_id, "--corpus", "v02_smoke",
        "--manifest-dir", str(_mdir(tmp_path)), "--min-precision", "0.5",
    ])
    assert res.exit_code == 1
    assert "v02_smoke" in res.output  # scorecard still printed


def test_eval_unknown_corpus_exits_2(isolated_db: Path, tmp_path: Path) -> None:
    run_id = str(ULID())
    _seed(run_id)
    res = CliRunner().invoke(main, [
        "eval", "--from-run", run_id, "--corpus", "nope",
        "--manifest-dir", str(_mdir(tmp_path)),
    ])
    assert res.exit_code == 2


def test_eval_json_output(isolated_db: Path, tmp_path: Path) -> None:
    run_id = str(ULID())
    _seed(run_id)
    out = tmp_path / "card.json"
    res = CliRunner().invoke(main, [
        "eval", "--from-run", run_id, "--corpus", "v02_smoke",
        "--manifest-dir", str(_mdir(tmp_path)), "--json", str(out),
    ])
    assert res.exit_code == 0
    assert out.exists()
    assert '"true_positives"' in out.read_text(encoding="utf-8")
