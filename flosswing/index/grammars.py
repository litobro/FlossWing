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

"""Tree-sitter parser registry.

Per docs/specs/2026-06-02-v0.5-symbol-index-design.md § Component
responsibilities flosswing/index/parser.py (renamed to grammars.py in
this implementation — see the plan's plan-time decisions).

This is the only module in the v0.5 package that imports `tree_sitter`
directly. All other modules consume Parser/Language objects through
the get_parser / get_language façade.

Grammars are lazy-loaded on first request and cached for the process
lifetime — long Hunt runs do not re-load. If the per-language PyPI
package import or the Language() construction raises, we wrap the
exception in LanguageGrammarNotLoadedError so the build skip can be
diagnosed without losing the underlying traceback.
"""

from __future__ import annotations

import importlib
from typing import Final

import tree_sitter

from flosswing.errors import LanguageGrammarNotLoadedError

SUPPORTED_LANGUAGES: Final[frozenset[str]] = frozenset({
    "python",
    "c",
    "cpp",
    "rust",
    "go",
    "javascript",
    "typescript",
    "java",
})

# File extension -> language id. Multi-extension languages list each.
# Keys are lowercase, leading dot included.
EXTENSION_TO_LANGUAGE: Final[dict[str, str]] = {
    ".py": "python",
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
    ".rs": "rust",
    ".go": "go",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
}

# PyPI package name -> module attribute for each grammar's language() callable.
# Lazily imported in _load_language so a missing grammar doesn't break import.
_GRAMMAR_PACKAGES: Final[dict[str, str]] = {
    "python": "tree_sitter_python",
    "c": "tree_sitter_c",
    "cpp": "tree_sitter_cpp",
    "rust": "tree_sitter_rust",
    "go": "tree_sitter_go",
    "javascript": "tree_sitter_javascript",
    "typescript": "tree_sitter_typescript",
    "java": "tree_sitter_java",
}

_LANGUAGE_CACHE: dict[str, tree_sitter.Language] = {}
_PARSER_CACHE: dict[str, tree_sitter.Parser] = {}


def _load_language(language: str) -> tree_sitter.Language:
    """Import the grammar package and construct a Language object."""
    pkg_name = _GRAMMAR_PACKAGES[language]
    try:
        module = importlib.import_module(pkg_name)
    except ImportError as e:
        raise LanguageGrammarNotLoadedError(language) from e

    # TypeScript's grammar package exposes language_typescript() and
    # language_tsx() instead of a bare language(). Default to typescript.
    callable_name = "language_typescript" if language == "typescript" else "language"
    lang_callable = getattr(module, callable_name, None)
    if lang_callable is None:
        # Fall back to bare `language()` if the package shape changes.
        lang_callable = getattr(module, "language", None)
    if lang_callable is None:
        raise LanguageGrammarNotLoadedError(language)

    try:
        return tree_sitter.Language(lang_callable())
    except Exception as e:
        raise LanguageGrammarNotLoadedError(language) from e


def get_language(language: str) -> tree_sitter.Language:
    """Return the tree_sitter.Language for `language`, loading on first use.

    Raises LanguageGrammarNotLoadedError if `language` is unknown or the
    grammar package fails to import/construct.
    """
    if language not in SUPPORTED_LANGUAGES:
        raise LanguageGrammarNotLoadedError(language)
    cached = _LANGUAGE_CACHE.get(language)
    if cached is not None:
        return cached
    lang = _load_language(language)
    _LANGUAGE_CACHE[language] = lang
    return lang


def get_parser(language: str) -> tree_sitter.Parser:
    """Return a tree_sitter.Parser configured for `language`."""
    cached = _PARSER_CACHE.get(language)
    if cached is not None:
        return cached
    parser = tree_sitter.Parser()
    parser.language = get_language(language)
    _PARSER_CACHE[language] = parser
    return parser


def language_for_path(repo_relative_path: str) -> str | None:
    """Return the language id for `repo_relative_path` or None if no match."""
    lower = repo_relative_path.lower()
    for ext, lang in EXTENSION_TO_LANGUAGE.items():
        if lower.endswith(ext):
            return lang
    return None


__all__ = [
    "EXTENSION_TO_LANGUAGE",
    "SUPPORTED_LANGUAGES",
    "get_language",
    "get_parser",
    "language_for_path",
]
