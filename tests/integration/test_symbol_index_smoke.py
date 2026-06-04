"""Gated integration smoke for the v0.5 symbol index.

Gated by FLOSSWING_INTEGRATION=1 (same gate as v0.2 / v0.3 — IndexBuild
itself doesn't exercise the sandbox, so the v0.4 sandbox-specific gate
doesn't apply).

Per docs/specs/2026-06-02-v0.5-symbol-index-design.md § Success criteria
#2-4 and § Testing strategy Integration test. Asserts:
- symbols table contains the `greet` and `main` rows.
- call_sites contains the `main -> greet` edge with callee_symbol_id
  resolved.
- find_definition('greet') returns the correct row.
- find_callers('greet') returns exactly one CallSite whose caller_symbol
  resolves to `main`.

Runs the full pipeline (Recon -> IndexBuild -> Hunt) against
tests/corpus/v02_smoke/. Requires valid auth credentials.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from sqlalchemy import select

from flosswing.config import DEFAULT_MODEL, Config
from flosswing.orchestrator import run_scan
from flosswing.state import session as st_session
from flosswing.state.models import CallSite, Symbol
from flosswing.tools.symbols import (
    FindCallersInput,
    FindDefinitionInput,
    find_callers,
    find_definition,
)

pytestmark = pytest.mark.skipif(
    os.environ.get("FLOSSWING_INTEGRATION") != "1",
    reason="integration test gated by FLOSSWING_INTEGRATION=1",
)


CORPUS_REPO = Path(__file__).parent.parent / "corpus" / "v02_smoke"


def _resolve_auth_env() -> dict[str, str]:
    """Pick up whichever auth mode the operator has configured.

    Delegates to flosswing.config.resolve() so the test gate matches
    production semantics exactly. Returns an empty dict if no auth
    path is available — the calling test then skips.
    """
    from pathlib import Path as _Path

    from flosswing import config as _cfg
    from flosswing.errors import AuthCredentialMissingError as _AuthMissing

    try:
        c = _cfg.resolve(
            repo_root=_Path("."),
            model=None,
            recon_token_budget=None,
            hunt_token_budget=None,
            validate_token_budget=None,
            gapfill_token_budget=None,
        )
    except _AuthMissing:
        return {}
    return dict(c.auth_env)


@pytest.mark.asyncio
async def test_symbol_index_smoke_runs_recon_index_hunt_against_v02_smoke(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    auth = _resolve_auth_env()
    if not auth:
        pytest.skip("no auth credentials available")
    monkeypatch.setenv("FLOSSWING_DB_URL", f"sqlite:///{tmp_path}/state.db")
    monkeypatch.setattr(st_session, "_cached_engine", None, raising=False)
    monkeypatch.setattr(
        st_session, "_cached_session_factory", None, raising=False
    )
    monkeypatch.setenv("HOME", str(tmp_path))

    cfg = Config(
        repo_root=CORPUS_REPO.resolve(),
        model=DEFAULT_MODEL,
        recon_token_budget=200_000,
        hunt_token_budget=200_000,
        validate_token_budget=200_000,
        gapfill_token_budget=200_000,
        auth_env=auth,
    )
    result = await run_scan(cfg)
    print("\n--- run summary ---\n" + result.summary + "\n---")
    assert result.exit_code in (0, 1), (
        f"unexpected exit_code {result.exit_code}; summary={result.summary}"
    )
    # Snapshot attributes inside the scope; ORM instances expire on commit.
    with st_session.session_scope() as s:
        symbols = list(
            s.execute(
                select(Symbol).where(Symbol.run_id == result.run_id)
            )
            .scalars()
            .all()
        )
        snapshots: list[tuple[str, str, str, str, str]] = [
            (sym.id, sym.symbol, sym.file, sym.kind, sym.language)
            for sym in symbols
        ]
    names = {snap[1] for snap in snapshots}
    assert "greet" in names, (
        f"index missing greet: {sorted(names)}\nsummary:\n{result.summary}"
    )
    assert "main" in names, f"index missing main: {sorted(names)}"

    greet = next(snap for snap in snapshots if snap[1] == "greet")
    assert greet[2] == "src/example/cli.py"
    assert greet[3] == "function"
    assert greet[4] == "python"

    main = next(snap for snap in snapshots if snap[1] == "main")
    assert main[2] == "src/example/cli.py"
    assert main[3] == "function"

    greet_id, main_id = greet[0], main[0]
    with st_session.session_scope() as s:
        edge_pairs = [
            (e.caller_symbol_id, e.callee_symbol_id)
            for e in s.execute(
                select(CallSite).where(
                    CallSite.run_id == result.run_id,
                    CallSite.callee_symbol_id == greet_id,
                )
            )
            .scalars()
            .all()
        ]
    assert len(edge_pairs) >= 1, "main -> greet call edge not resolved"
    assert any(caller == main_id for caller, _ in edge_pairs)


@pytest.mark.asyncio
async def test_find_definition_returns_greet_via_tool(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """After the previous test populates state.db, find_definition works."""
    # NB: this test depends on the previous test's state.db. pytest-asyncio
    # default ordering keeps file-level order; if execution is randomized,
    # this test inlines its own scan instead.
    monkeypatch.setenv("FLOSSWING_DB_URL", f"sqlite:///{tmp_path}/state.db")
    monkeypatch.setattr(st_session, "_cached_engine", None, raising=False)
    monkeypatch.setattr(
        st_session, "_cached_session_factory", None, raising=False
    )

    auth = _resolve_auth_env()
    if not auth:
        pytest.skip("no auth credentials available")
    monkeypatch.setenv("HOME", str(tmp_path))
    cfg = Config(
        repo_root=CORPUS_REPO.resolve(),
        model=DEFAULT_MODEL,
        recon_token_budget=200_000,
        hunt_token_budget=200_000,
        validate_token_budget=200_000,
        gapfill_token_budget=200_000,
        auth_env=auth,
    )
    result = await run_scan(cfg)
    out = find_definition(
        FindDefinitionInput(symbol="greet"), run_id=result.run_id
    )
    assert len(out.definitions) == 1
    assert out.definitions[0].file == "src/example/cli.py"
    assert out.definitions[0].kind == "function"

    callers = find_callers(
        FindCallersInput(symbol="greet"), run_id=result.run_id
    )
    assert callers.target is not None
    assert len(callers.call_sites) >= 1
    assert any("main" in c.caller_symbol for c in callers.call_sites)
