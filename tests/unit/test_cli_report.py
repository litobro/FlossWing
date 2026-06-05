"""flosswing.cli — ``flosswing report <run_id>`` subcommand wiring.

Per docs/specs/2026-06-02-v1.0-report-design.md § cli.py extension and
v1.0 Task A's "real" wiring (Task D completes it).

Covers:

- Subcommand against a seeded DB exits 0 and writes expected files.
- Re-render parity: running the subcommand twice yields byte-identical
  output except for ``rendered_at`` (and any other run-time-stamped
  fields).
- Unknown ``run_id`` exits 1 with a clear stderr message.
- ``--format md`` only writes ``report.md`` (not ``report.json``).
- ``--format sarif`` prints "not yet implemented" to stderr and
  continues; combined with ``md,json`` the other files still write.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from click.testing import CliRunner
from ulid import ULID

from flosswing.cli import main
from flosswing.state import session as st_session
from flosswing.state.models import (
    Finding,
    HuntTask,
    Run,
)


def _now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


@pytest.fixture()
def isolated_db(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[Path]:
    monkeypatch.setenv("FLOSSWING_DB_URL", f"sqlite:///{tmp_path}/state.db")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setattr(st_session, "_cached_engine", None, raising=False)
    monkeypatch.setattr(
        st_session, "_cached_session_factory", None, raising=False
    )
    yield tmp_path


def _seed_run(run_id: str) -> None:
    with st_session.session_scope() as s:
        s.add(
            Run(
                id=run_id,
                target_repo_path="/tmp/x",
                target_repo_sha=None,
                depth="standard",
                budget_total=100,
                budget_used=0,
                started_at=_now_iso(),
                finished_at=_now_iso(),
                status="completed",
                config_json='{"model": "claude-opus-4-7"}',
                flosswing_version="1.0.0",
            )
        )


def _seed_task(run_id: str) -> str:
    task_id = str(ULID())
    with st_session.session_scope() as s:
        s.add(
            HuntTask(
                id=task_id,
                run_id=run_id,
                attack_class="command_injection",
                scope_hint="src/",
                rationale="",
                priority="normal",
                source="recon",
                parent_finding_id=None,
                status="completed",
                created_at=_now_iso(),
                started_at=_now_iso(),
                finished_at=_now_iso(),
                findings_count=0,
            )
        )
    return task_id


def _seed_finding(
    *,
    run_id: str,
    task_id: str,
    status: str = "confirmed",
    poc_code: str | None = "print('proof')\n",
    file: str = "src/a.py",
) -> str:
    fid = str(ULID())
    with st_session.session_scope() as s:
        s.add(
            Finding(
                id=fid,
                run_id=run_id,
                hunt_task_id=task_id,
                attack_class="command_injection",
                file=file,
                function="some_fn",
                line_start=10,
                line_end=12,
                severity="high",
                confidence="likely",
                status=status,
                title="shell injection",
                description=(
                    "A reasonable description, fifty chars or more for realism."
                ),
                poc_code=poc_code,
                poc_result_json=None,
                suggested_fix=None,
                created_at=_now_iso(),
            )
        )
    return fid


def _seed_simple_run_with_one_finding(run_id: str) -> str:
    _seed_run(run_id)
    task_id = _seed_task(run_id)
    return _seed_finding(run_id=run_id, task_id=task_id)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_report_subcommand_seeded_db_exits_zero(
    isolated_db: Path, tmp_path: Path,
) -> None:
    """``flosswing report <run_id>`` against a seeded DB exits 0 and
    writes report.md + report.json + findings/<id>/."""
    run_id = str(ULID())
    fid = _seed_simple_run_with_one_finding(run_id)

    out_dir = tmp_path / "out"
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["report", "--output-dir", str(out_dir), run_id],
    )
    assert result.exit_code == 0, result.output
    assert (out_dir / "report.md").exists()
    assert (out_dir / "report.json").exists()
    assert (out_dir / "findings" / fid).exists()


def test_report_subcommand_rerender_parity(
    isolated_db: Path, tmp_path: Path,
) -> None:
    """Two consecutive renders produce byte-identical output except for
    ``rendered_at`` (which the loader stamps with ``_now_iso()``)."""
    run_id = str(ULID())
    _seed_simple_run_with_one_finding(run_id)

    out_dir = tmp_path / "out"
    runner = CliRunner()
    r1 = runner.invoke(
        main, ["report", "--output-dir", str(out_dir), run_id],
    )
    assert r1.exit_code == 0, r1.output
    md_1 = (out_dir / "report.md").read_text(encoding="utf-8")
    j_1 = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))

    r2 = runner.invoke(
        main, ["report", "--output-dir", str(out_dir), run_id],
    )
    assert r2.exit_code == 0, r2.output
    md_2 = (out_dir / "report.md").read_text(encoding="utf-8")
    j_2 = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))

    # JSON: every field except rendered_at must match.
    j_1.pop("rendered_at")
    j_2.pop("rendered_at")
    assert j_1 == j_2

    # Markdown: strip the single line carrying ``Rendered at`` and
    # compare the remainder.
    def _without_rendered_at(md: str) -> str:
        return "\n".join(
            line for line in md.splitlines()
            if not line.startswith("_Rendered at ")
        )

    assert _without_rendered_at(md_1) == _without_rendered_at(md_2)


def test_report_subcommand_unknown_run_id_exits_two(
    isolated_db: Path, tmp_path: Path,
) -> None:
    """An unknown run_id exits 2 with the canonical 'no run with id ...'
    message, per spec § Error handling and RunNotFoundError docstring.
    Distinct from exit 1 (which is reserved for render-time failures)."""
    # Touch the DB to ensure migrations have run, so the runs table is
    # present and just-plain-empty rather than "no such table".
    with st_session.session_scope() as _:
        pass

    bogus = str(ULID())
    out_dir = tmp_path / "out"
    runner = CliRunner()
    result = runner.invoke(
        main, ["report", "--output-dir", str(out_dir), bogus],
    )
    assert result.exit_code == 2, (result.output, result.stderr)
    assert "no run with id" in result.stderr
    assert bogus in result.stderr


def test_report_subcommand_format_md_skips_json(
    isolated_db: Path, tmp_path: Path,
) -> None:
    """``--format md`` writes report.md only; report.json absent."""
    run_id = str(ULID())
    _seed_simple_run_with_one_finding(run_id)

    out_dir = tmp_path / "out"
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "report",
            "--format", "md",
            "--output-dir", str(out_dir),
            run_id,
        ],
    )
    assert result.exit_code == 0, result.output
    assert (out_dir / "report.md").exists()
    assert not (out_dir / "report.json").exists()


def test_report_subcommand_sarif_writes_placeholder_file(
    isolated_db: Path, tmp_path: Path,
) -> None:
    """``--format md,json,sarif`` prints the SARIF stub to stderr AND
    writes a placeholder ``report.sarif`` file containing a single
    $comment field (per spec § SARIF stance, so existing CI scripts
    don't break). report.md and report.json are also written."""
    run_id = str(ULID())
    _seed_simple_run_with_one_finding(run_id)

    out_dir = tmp_path / "out"
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "report",
            "--format", "md,json,sarif",
            "--output-dir", str(out_dir),
            run_id,
        ],
    )
    assert result.exit_code == 0, (result.output, result.stderr)
    assert "not yet implemented" in result.stderr
    assert (out_dir / "report.md").exists()
    assert (out_dir / "report.json").exists()
    sarif_path = out_dir / "report.sarif"
    assert sarif_path.exists(), "spec § SARIF stance requires the placeholder file"
    sarif_text = sarif_path.read_text(encoding="utf-8")
    assert '"$comment"' in sarif_text
    assert "not yet implemented" in sarif_text
    assert "v1.1" in sarif_text
