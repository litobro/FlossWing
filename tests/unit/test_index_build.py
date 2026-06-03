"""flosswing.index.build — IndexBuild orchestration.

Per docs/specs/2026-06-02-v0.5-symbol-index-design.md § Component
responsibilities flosswing/index/build.py and design decision #7.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import func, select
from ulid import ULID

from flosswing.index.build import IndexBuildResult, build_index
from flosswing.state import session as st_session
from flosswing.state.models import (
    CallSite,
    EntryPoint,
    ReconArtifact,
    Run,
    Symbol,
)


@pytest.fixture()
def isolated_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("FLOSSWING_DB_URL", f"sqlite:///{tmp_path}/state.db")
    monkeypatch.setattr(st_session, "_cached_engine", None, raising=False)
    monkeypatch.setattr(
        st_session, "_cached_session_factory", None, raising=False
    )
    return tmp_path


def _make_run_and_artifact() -> tuple[str, str]:
    run_id = str(ULID())
    artifact_id = str(ULID())
    with st_session.session_scope() as s:
        s.add(
            Run(
                id=run_id, target_repo_path="/tmp/x", target_repo_sha=None,
                depth="standard", budget_total=20, budget_used=0,
                started_at="2026-06-02T00:00:00Z", status="running",
                config_json="{}", flosswing_version="0.5.0",
            )
        )
    with st_session.session_scope() as s:
        s.add(
            ReconArtifact(
                id=artifact_id, run_id=run_id,
                languages_json='["python"]',
                build_commands_json="[]",
                trust_boundaries_json="[]",
                subsystems_json="[]",
                notes="", recorded_at="2026-06-02T00:00:00Z",
            )
        )
    return run_id, artifact_id


def _make_python_repo(tmp_path: Path) -> Path:
    """Tiny Python repo with a greet + main + main->greet call edge."""
    repo = tmp_path / "repo"
    (repo / "src" / "example").mkdir(parents=True)
    (repo / "src" / "example" / "__init__.py").write_text("", encoding="utf-8")
    (repo / "src" / "example" / "cli.py").write_text(
        "def greet(name):\n"
        "    print(name)\n"
        "\n"
        "def main():\n"
        "    greet('x')\n",
        encoding="utf-8",
    )
    return repo


@pytest.mark.asyncio
async def test_build_index_writes_symbols_for_tiny_python_repo(
    isolated_db: Path,
) -> None:
    run_id, artifact_id = _make_run_and_artifact()
    repo = _make_python_repo(isolated_db)
    scratch = isolated_db / "runs" / run_id / "index"
    scratch.mkdir(parents=True)

    result = await build_index(
        run_id=run_id,
        recon_artifact_id=artifact_id,
        repo=repo,
        languages={"python"},
        session_factory=st_session.session_factory(),
        scratch_dir=scratch,
    )

    assert isinstance(result, IndexBuildResult)
    assert result.symbols >= 2
    assert result.call_sites >= 1
    assert result.duration_ms >= 0
    assert result.files_parsed >= 1

    with st_session.session_scope() as s:
        rows = list(
            s.execute(select(Symbol).where(Symbol.run_id == run_id))
            .scalars().all()
        )
        names = {r.symbol for r in rows}
    assert "greet" in names
    assert "main" in names


@pytest.mark.asyncio
async def test_build_index_resolves_main_to_greet_call_edge(
    isolated_db: Path,
) -> None:
    """Per spec § Success criteria #2: main -> greet call site is resolved."""
    run_id, artifact_id = _make_run_and_artifact()
    repo = _make_python_repo(isolated_db)
    scratch = isolated_db / "runs" / run_id / "index"
    scratch.mkdir(parents=True)

    await build_index(
        run_id=run_id, recon_artifact_id=artifact_id, repo=repo,
        languages={"python"}, session_factory=st_session.session_factory(),
        scratch_dir=scratch,
    )

    with st_session.session_scope() as s:
        greet = s.execute(
            select(Symbol).where(
                Symbol.run_id == run_id, Symbol.symbol == "greet"
            )
        ).scalar_one()
        main = s.execute(
            select(Symbol).where(
                Symbol.run_id == run_id, Symbol.symbol == "main"
            )
        ).scalar_one()
        cs = list(
            s.execute(
                select(CallSite).where(
                    CallSite.run_id == run_id,
                    CallSite.callee_symbol_id == greet.id,
                )
            ).scalars().all()
        )
        assert len(cs) == 1
        assert cs[0].caller_symbol_id == main.id
        assert cs[0].callee_text == "greet"


@pytest.mark.asyncio
async def test_build_index_writes_cli_entry_point_for_main(
    isolated_db: Path,
) -> None:
    run_id, artifact_id = _make_run_and_artifact()
    repo = _make_python_repo(isolated_db)
    scratch = isolated_db / "runs" / run_id / "index"
    scratch.mkdir(parents=True)

    await build_index(
        run_id=run_id, recon_artifact_id=artifact_id, repo=repo,
        languages={"python"}, session_factory=st_session.session_factory(),
        scratch_dir=scratch,
    )

    with st_session.session_scope() as s:
        eps = list(
            s.execute(
                select(EntryPoint).where(EntryPoint.run_id == run_id)
            ).scalars().all()
        )
        kinds = {(e.kind, e.symbol) for e in eps}
    assert ("cli", "main") in kinds


@pytest.mark.asyncio
async def test_build_index_empty_repo_returns_zero_symbols(
    isolated_db: Path,
) -> None:
    """No source files -> result.symbols == 0; build does NOT raise."""
    run_id, artifact_id = _make_run_and_artifact()
    repo = isolated_db / "empty_repo"
    repo.mkdir()
    scratch = isolated_db / "runs" / run_id / "index"
    scratch.mkdir(parents=True)

    result = await build_index(
        run_id=run_id, recon_artifact_id=artifact_id, repo=repo,
        languages={"python"}, session_factory=st_session.session_factory(),
        scratch_dir=scratch,
    )
    assert result.symbols == 0
    assert result.call_sites == 0
    assert result.entry_points == 0

    with st_session.session_scope() as s:
        n = s.execute(
            select(func.count()).select_from(Symbol).where(
                Symbol.run_id == run_id
            )
        ).scalar_one()
    assert n == 0


@pytest.mark.asyncio
async def test_build_index_skips_unparseable_file_and_continues(
    isolated_db: Path,
) -> None:
    """A garbage .py file is skipped; good files still produce rows."""
    run_id, artifact_id = _make_run_and_artifact()
    repo = isolated_db / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "good.py").write_text(
        "def hello():\n    pass\n", encoding="utf-8"
    )
    (repo / "src" / "bad.py").write_text(
        "def f(\n", encoding="utf-8"
    )
    scratch = isolated_db / "runs" / run_id / "index"
    scratch.mkdir(parents=True)

    result = await build_index(
        run_id=run_id, recon_artifact_id=artifact_id, repo=repo,
        languages={"python"}, session_factory=st_session.session_factory(),
        scratch_dir=scratch,
    )
    # `hello` must still land.
    with st_session.session_scope() as s:
        rows = list(
            s.execute(
                select(Symbol).where(Symbol.run_id == run_id)
            ).scalars().all()
        )
        names = {r.symbol for r in rows}
    assert "hello" in names
    # The build should have logged the bad file but not crashed.
    log = (scratch / "index_build.log").read_text(encoding="utf-8")
    assert "bad.py" in log or result.files_parsed >= 1


@pytest.mark.asyncio
async def test_build_index_writes_log_to_scratch(isolated_db: Path) -> None:
    run_id, artifact_id = _make_run_and_artifact()
    repo = _make_python_repo(isolated_db)
    scratch = isolated_db / "runs" / run_id / "index"
    scratch.mkdir(parents=True)

    await build_index(
        run_id=run_id, recon_artifact_id=artifact_id, repo=repo,
        languages={"python"}, session_factory=st_session.session_factory(),
        scratch_dir=scratch,
    )
    log_path = scratch / "index_build.log"
    assert log_path.exists()
    assert log_path.stat().st_size > 0


@pytest.mark.asyncio
async def test_build_index_call_site_with_unresolved_callee_uses_null(
    isolated_db: Path,
) -> None:
    """A call to an external lib has callee_symbol_id = NULL."""
    run_id, artifact_id = _make_run_and_artifact()
    repo = isolated_db / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "m.py").write_text(
        "import os\n"
        "def main():\n"
        "    os.unlink('/tmp/x')\n",
        encoding="utf-8",
    )
    scratch = isolated_db / "runs" / run_id / "index"
    scratch.mkdir(parents=True)

    await build_index(
        run_id=run_id, recon_artifact_id=artifact_id, repo=repo,
        languages={"python"}, session_factory=st_session.session_factory(),
        scratch_dir=scratch,
    )
    with st_session.session_scope() as s:
        unresolved = list(
            s.execute(
                select(CallSite).where(
                    CallSite.run_id == run_id,
                    CallSite.callee_symbol_id.is_(None),
                )
            ).scalars().all()
        )
        # `os.unlink` is external -> callee_symbol_id is NULL.
        by_text = {cs.callee_text for cs in unresolved}
    assert "unlink" in by_text


@pytest.mark.asyncio
async def test_build_index_resolves_call_edge_for_non_python_language(
    isolated_db: Path,
) -> None:
    """Regression test for PR #9 review issue #1: non-Python FQNs use
    `<file>::<short_name>` (e.g. `m.go::greet`), so the resolution
    suffix-match must accept both `.short` (Python) and `::short`
    (every other v1 language). Before the fix, `callee_symbol_id`
    stayed NULL for every non-Python call site even when the callee
    was indexed in the same file.
    """
    run_id, artifact_id = _make_run_and_artifact()
    repo = isolated_db / "repo"
    repo.mkdir(parents=True)
    (repo / "m.go").write_text(
        "package main\n"
        "\n"
        "func greet(name string) {\n"
        "    println(name)\n"
        "}\n"
        "\n"
        "func main() {\n"
        "    greet(\"x\")\n"
        "}\n",
        encoding="utf-8",
    )
    scratch = isolated_db / "runs" / run_id / "index"
    scratch.mkdir(parents=True)

    await build_index(
        run_id=run_id, recon_artifact_id=artifact_id, repo=repo,
        languages={"go"}, session_factory=st_session.session_factory(),
        scratch_dir=scratch,
    )
    with st_session.session_scope() as s:
        greet = s.execute(
            select(Symbol).where(
                Symbol.run_id == run_id, Symbol.symbol == "greet"
            )
        ).scalar_one()
        main = s.execute(
            select(Symbol).where(
                Symbol.run_id == run_id, Symbol.symbol == "main"
            )
        ).scalar_one()
        edges = list(
            s.execute(
                select(CallSite).where(
                    CallSite.run_id == run_id,
                    CallSite.callee_symbol_id == greet.id,
                )
            ).scalars().all()
        )
        assert len(edges) >= 1, "Go main -> greet call edge not resolved"
        assert any(e.caller_symbol_id == main.id for e in edges)
