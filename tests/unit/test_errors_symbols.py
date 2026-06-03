"""Symbol-index error classes per docs/tool-contracts.md § Scope: symbols
and docs/specs/2026-06-02-v0.5-symbol-index-design.md § Error and refusal
handling.

Exercises the contract-mapping: which Python class raises which on-the-wire
error code.
"""

from __future__ import annotations

import pytest

from flosswing.errors import (
    AmbiguousSymbolError,
    FlosswingError,
    IndexBuildError,
    LanguageGrammarNotLoadedError,
    NotIndexedError,
    SymbolNotFoundError,
)


def test_index_build_error_distinct_code() -> None:
    err = IndexBuildError(
        "no symbols extracted from 4 files in 1 languages"
    )
    assert isinstance(err, FlosswingError)
    assert err.code == "index_build_empty"
    assert err.retryable is False
    assert "no symbols" in str(err)


def test_language_grammar_not_loaded_distinct_code() -> None:
    """Per-file build failure; never surfaces to agents."""
    err = LanguageGrammarNotLoadedError("rust")
    assert isinstance(err, FlosswingError)
    assert err.code == "language_grammar_not_loaded"
    assert err.retryable is False
    assert "rust" in str(err)


def test_symbol_not_found_wire_code() -> None:
    """Per docs/tool-contracts.md § find_callers errors."""
    err = SymbolNotFoundError("greet")
    assert err.code == "symbol_not_found"
    assert err.retryable is False
    assert "greet" in str(err)


def test_ambiguous_symbol_wire_code() -> None:
    """Per docs/tool-contracts.md § find_callers errors. Includes candidates."""
    err = AmbiguousSymbolError(
        symbol="greet",
        candidates=[
            "src/example/cli.py:10",
            "src/example/util.py:5",
        ],
    )
    assert err.code == "ambiguous_symbol"
    assert err.retryable is False
    assert "src/example/cli.py:10" in str(err)
    assert "src/example/util.py:5" in str(err)


def test_not_indexed_wire_code() -> None:
    """Per docs/tool-contracts.md § find_definition errors."""
    err = NotIndexedError("symbols table empty for run_id=01XYZ")
    assert err.code == "not_indexed"
    assert err.retryable is False


def test_all_new_errors_inherit_flosswing_error() -> None:
    for cls in (
        IndexBuildError,
        LanguageGrammarNotLoadedError,
        SymbolNotFoundError,
        NotIndexedError,
    ):
        with pytest.raises(FlosswingError):
            raise cls("m")
    with pytest.raises(FlosswingError):
        raise AmbiguousSymbolError(symbol="x", candidates=[])
