"""flosswing.tools.symbols — find_definition / find_callers / query_entry_points.

Per docs/tool-contracts.md § Scope: symbols (frozen) and
docs/specs/2026-06-02-v0.5-symbol-index-design.md § Component
responsibilities flosswing/tools/symbols.py.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from ulid import ULID

from flosswing.errors import (
    AmbiguousSymbolError,
    NotIndexedError,
    SymbolNotFoundError,
)
from flosswing.state import session as st_session
from flosswing.state.models import (
    CallSite,
    EntryPoint,
    ReconArtifact,
    Run,
    Symbol,
)
from flosswing.tools.symbols import (
    FindCallersInput,
    FindDefinitionInput,
    QueryEntryPointsInput,
    find_callers,
    find_definition,
    query_entry_points,
)


@pytest.fixture()
def isolated_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("FLOSSWING_DB_URL", f"sqlite:///{tmp_path}/state.db")
    monkeypatch.setattr(st_session, "_cached_engine", None, raising=False)
    monkeypatch.setattr(
        st_session, "_cached_session_factory", None, raising=False
    )
    return tmp_path


def _seed_run_with_greet_main(run_id: str | None = None) -> tuple[str, str, str]:
    """Seed a run with greet, main, and a main->greet call site."""
    if run_id is None:
        run_id = str(ULID())
    artifact_id = str(ULID())
    greet_id = str(ULID())
    main_id = str(ULID())
    # Separate session_scope per FK-tier so commits land in dependency
    # order (Run -> ReconArtifact + Symbols -> CallSite + EntryPoint).
    # SQLite enforces FKs at row insert; add_all() doesn't guarantee
    # cross-table ordering within a single flush.
    with st_session.session_scope() as s:
        s.add(Run(
            id=run_id, target_repo_path="/tmp/x", target_repo_sha=None,
            depth="standard", budget_total=20, budget_used=0,
            started_at="2026-06-02T00:00:00Z", status="running",
            config_json="{}", flosswing_version="0.5.0",
        ))
    with st_session.session_scope() as s:
        s.add_all([
            ReconArtifact(
                id=artifact_id, run_id=run_id, languages_json='["python"]',
                build_commands_json="[]", trust_boundaries_json="[]",
                subsystems_json="[]", notes="",
                recorded_at="2026-06-02T00:00:00Z",
            ),
            Symbol(
                id=greet_id, run_id=run_id, symbol="greet",
                fully_qualified_name="src.example.cli.greet",
                file="src/example/cli.py",
                line_start=10, line_end=12, kind="function", language="python",
            ),
            Symbol(
                id=main_id, run_id=run_id, symbol="main",
                fully_qualified_name="src.example.cli.main",
                file="src/example/cli.py",
                line_start=15, line_end=20, kind="function", language="python",
            ),
        ])
    with st_session.session_scope() as s:
        s.add_all([
            CallSite(
                id=str(ULID()), run_id=run_id,
                caller_symbol_id=main_id, callee_symbol_id=greet_id,
                callee_text="greet", file="src/example/cli.py", line=19,
                snippet="    greet(sys.argv[1])",
            ),
            EntryPoint(
                id=str(ULID()), recon_artifact_id=artifact_id, run_id=run_id,
                symbol="main", file="src/example/cli.py", line=15,
                kind="cli", attacker_controlled_input=1,
                notes="`main` in python",
            ),
        ])
    return run_id, greet_id, main_id


def test_find_definition_returns_one_match(isolated_db: Path) -> None:
    run_id, _, _ = _seed_run_with_greet_main()
    out = find_definition(
        FindDefinitionInput(symbol="greet"), run_id=run_id
    )
    assert len(out.definitions) == 1
    d = out.definitions[0]
    assert d.symbol == "greet"
    assert d.fully_qualified_name == "src.example.cli.greet"
    assert d.file == "src/example/cli.py"
    assert d.line_start == 10
    assert d.line_end == 12
    assert d.kind == "function"
    assert d.language == "python"
    assert out.truncated is False


def test_find_definition_unknown_symbol_returns_empty(isolated_db: Path) -> None:
    run_id, _, _ = _seed_run_with_greet_main()
    out = find_definition(
        FindDefinitionInput(symbol="not_a_symbol"), run_id=run_id
    )
    assert out.definitions == []
    assert out.truncated is False


def test_find_definition_raises_not_indexed_when_table_empty(
    isolated_db: Path,
) -> None:
    """Per docs/tool-contracts.md § find_definition errors."""
    # No symbols seeded for this run_id.
    bare_run_id = str(ULID())
    with st_session.session_scope() as s:
        s.add(Run(
            id=bare_run_id, target_repo_path="/tmp/x", target_repo_sha=None,
            depth="standard", budget_total=20, budget_used=0,
            started_at="2026-06-02T00:00:00Z", status="running",
            config_json="{}", flosswing_version="0.5.0",
        ))
    with pytest.raises(NotIndexedError):
        find_definition(
            FindDefinitionInput(symbol="greet"), run_id=bare_run_id
        )


def test_find_definition_narrows_by_file_hint(isolated_db: Path) -> None:
    run_id, _, _ = _seed_run_with_greet_main()
    # Seed a second symbol with the same short name in a different file.
    with st_session.session_scope() as s:
        s.add(Symbol(
            id=str(ULID()), run_id=run_id, symbol="greet",
            fully_qualified_name="src.other.greet",
            file="src/other.py",
            line_start=1, line_end=3, kind="function", language="python",
        ))
    out = find_definition(
        FindDefinitionInput(symbol="greet", file_hint="src/other.py"),
        run_id=run_id,
    )
    assert len(out.definitions) == 1
    assert out.definitions[0].file == "src/other.py"


def test_find_definition_narrows_by_language(isolated_db: Path) -> None:
    run_id, _, _ = _seed_run_with_greet_main()
    with st_session.session_scope() as s:
        s.add(Symbol(
            id=str(ULID()), run_id=run_id, symbol="greet",
            fully_qualified_name="greet",
            file="main.go",
            line_start=1, line_end=3, kind="function", language="go",
        ))
    out = find_definition(
        FindDefinitionInput(symbol="greet", language="go"),
        run_id=run_id,
    )
    assert len(out.definitions) == 1
    assert out.definitions[0].language == "go"


def test_find_callers_returns_caller_for_greet(isolated_db: Path) -> None:
    run_id, _, _ = _seed_run_with_greet_main()
    out = find_callers(
        FindCallersInput(symbol="greet"), run_id=run_id
    )
    assert out.target is not None
    assert out.target.symbol == "greet"
    assert len(out.call_sites) == 1
    c = out.call_sites[0]
    assert c.caller_symbol == "src.example.cli.main"
    assert c.file == "src/example/cli.py"
    assert c.line == 19
    assert "greet" in c.snippet
    assert out.truncated is False


def test_find_callers_raises_symbol_not_found(isolated_db: Path) -> None:
    run_id, _, _ = _seed_run_with_greet_main()
    with pytest.raises(SymbolNotFoundError):
        find_callers(
            FindCallersInput(symbol="not_a_symbol"), run_id=run_id
        )


def test_find_callers_raises_ambiguous_when_multiple_definitions(
    isolated_db: Path,
) -> None:
    run_id, _, _ = _seed_run_with_greet_main()
    with st_session.session_scope() as s:
        s.add(Symbol(
            id=str(ULID()), run_id=run_id, symbol="greet",
            fully_qualified_name="src.other.greet",
            file="src/other.py",
            line_start=1, line_end=3, kind="function", language="python",
        ))
    with pytest.raises(AmbiguousSymbolError) as exc:
        find_callers(FindCallersInput(symbol="greet"), run_id=run_id)
    assert "src/example/cli.py" in str(exc.value)
    assert "src/other.py" in str(exc.value)


def test_find_callers_honours_max_results(isolated_db: Path) -> None:
    run_id, greet_id, main_id = _seed_run_with_greet_main()
    with st_session.session_scope() as s:
        for i in range(5):
            s.add(CallSite(
                id=str(ULID()), run_id=run_id,
                caller_symbol_id=main_id, callee_symbol_id=greet_id,
                callee_text="greet", file="src/example/cli.py",
                line=20 + i, snippet=f"    greet(x)  # {i}",
            ))
    out = find_callers(
        FindCallersInput(symbol="greet", max_results=3), run_id=run_id
    )
    assert len(out.call_sites) == 3
    assert out.truncated is True


def test_query_entry_points_returns_cli_entry(isolated_db: Path) -> None:
    run_id, _, _ = _seed_run_with_greet_main()
    out = query_entry_points(QueryEntryPointsInput(), run_id=run_id)
    assert len(out.entry_points) == 1
    ep = out.entry_points[0]
    assert ep.symbol == "main"
    assert ep.kind == "cli"
    assert ep.attacker_controlled_input is True
    assert ep.notes == "`main` in python"


def test_query_entry_points_filters_by_kind(isolated_db: Path) -> None:
    run_id, _, _ = _seed_run_with_greet_main()
    out = query_entry_points(
        QueryEntryPointsInput(kind="http"), run_id=run_id
    )
    assert out.entry_points == []


def test_query_entry_points_empty_for_unseeded_run(isolated_db: Path) -> None:
    bare = str(ULID())
    with st_session.session_scope() as s:
        s.add(Run(
            id=bare, target_repo_path="/tmp/x", target_repo_sha=None,
            depth="standard", budget_total=20, budget_used=0,
            started_at="2026-06-02T00:00:00Z", status="running",
            config_json="{}", flosswing_version="0.5.0",
        ))
    out = query_entry_points(QueryEntryPointsInput(), run_id=bare)
    assert out.entry_points == []
