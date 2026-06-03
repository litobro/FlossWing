"""flosswing.index.grammars — tree-sitter parser registry.

Per docs/specs/2026-06-02-v0.5-symbol-index-design.md § Component
responsibilities flosswing/index/parser.py (renamed to grammars.py
per plan-time decision). Tests assert lazy loading, per-process
caching, error semantics on unknown / unloadable languages.

These tests exercise the real grammar packages since those are
pre-installed via pyproject.toml.
"""

from __future__ import annotations

import pytest

from flosswing.errors import LanguageGrammarNotLoadedError
from flosswing.index import grammars


@pytest.fixture(autouse=True)
def _reset_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    """Clear the process-level grammar cache between tests."""
    monkeypatch.setattr(grammars, "_LANGUAGE_CACHE", {}, raising=False)
    monkeypatch.setattr(grammars, "_PARSER_CACHE", {}, raising=False)


def test_supported_languages_is_eight() -> None:
    expected = frozenset(
        {"python", "c", "cpp", "rust", "go", "javascript", "typescript", "java"}
    )
    assert expected == grammars.SUPPORTED_LANGUAGES


def test_extension_map_includes_common_extensions() -> None:
    """Per spec § Tree-sitter parser registry: extension -> language."""
    assert grammars.EXTENSION_TO_LANGUAGE[".py"] == "python"
    assert grammars.EXTENSION_TO_LANGUAGE[".c"] == "c"
    assert grammars.EXTENSION_TO_LANGUAGE[".cc"] == "cpp"
    assert grammars.EXTENSION_TO_LANGUAGE[".cpp"] == "cpp"
    assert grammars.EXTENSION_TO_LANGUAGE[".rs"] == "rust"
    assert grammars.EXTENSION_TO_LANGUAGE[".go"] == "go"
    assert grammars.EXTENSION_TO_LANGUAGE[".js"] == "javascript"
    assert grammars.EXTENSION_TO_LANGUAGE[".ts"] == "typescript"
    assert grammars.EXTENSION_TO_LANGUAGE[".java"] == "java"


def test_get_language_python_returns_language_object() -> None:
    """Smoke test: the python grammar loads."""
    import tree_sitter

    lang = grammars.get_language("python")
    assert isinstance(lang, tree_sitter.Language)


def test_get_parser_python_parses_minimal_source() -> None:
    parser = grammars.get_parser("python")
    tree = parser.parse(b"def greet(name): pass\n")
    assert tree.root_node.type == "module"
    # First child of a python module is a function_definition for the def above.
    func = tree.root_node.children[0]
    assert func.type == "function_definition"


def test_get_language_unknown_raises() -> None:
    with pytest.raises(LanguageGrammarNotLoadedError) as exc:
        grammars.get_language("scheme")
    assert exc.value.language == "scheme"


def test_get_parser_unknown_raises() -> None:
    with pytest.raises(LanguageGrammarNotLoadedError) as exc:
        grammars.get_parser("ruby")
    assert exc.value.language == "ruby"


def test_get_language_caches_per_process() -> None:
    a = grammars.get_language("python")
    b = grammars.get_language("python")
    assert a is b


def test_get_parser_caches_per_process() -> None:
    a = grammars.get_parser("python")
    b = grammars.get_parser("python")
    assert a is b


def test_grammar_load_failure_raises_language_grammar_not_loaded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If the grammar import succeeds but Language() blows up, surface the error."""
    import tree_sitter

    def _explode(*args: object, **kwargs: object) -> object:
        raise RuntimeError("simulated grammar load failure")

    monkeypatch.setattr(tree_sitter, "Language", _explode)
    monkeypatch.setattr(grammars, "_LANGUAGE_CACHE", {}, raising=False)
    with pytest.raises(LanguageGrammarNotLoadedError) as exc:
        grammars.get_language("python")
    assert exc.value.language == "python"


def test_language_for_path_known_extensions() -> None:
    assert grammars.language_for_path("src/cli.py") == "python"
    assert grammars.language_for_path("main.go") == "go"
    assert grammars.language_for_path("lib.rs") == "rust"
    assert grammars.language_for_path("App.java") == "java"


def test_language_for_path_unknown_extension_returns_none() -> None:
    assert grammars.language_for_path("README.md") is None
    assert grammars.language_for_path("Dockerfile") is None
