"""Per-language symbol + call-site extraction from a tree-sitter tree.

Per docs/specs/2026-06-02-v0.5-symbol-index-design.md § Component
responsibilities flosswing/index/extractor.py and the per-language
coverage table in § Tree-sitter queries.

Per the operator-upsized plan-time decision #4 (2026-06-02), v0.5 ships
production-quality coverage for all 8 v1 languages — definitions AND
call sites — for Python, C, C++, Rust, Go, JavaScript, TypeScript,
and Java.

S-expression queries are inlined here per plan-time decision #3.

Design notes:

- The query for each language captures `@def.<kind>` on the definition
  node and `@name` on the inner identifier. The driver code pairs them
  by source-byte enclosure rather than by relying on match boundaries.
  This works whether the underlying `Query.captures()` returns a
  ``{capture_name: [Node, ...]}`` dict (current tree-sitter Python
  binding) or a list of ``(Node, capture_name)`` tuples (older
  bindings); the implementation supports both shapes.

- `kind` is taken from the trailing component of the `@def.<kind>`
  capture name. For ambiguous cases — Rust functions-inside-impl as
  methods, C++ free vs member functions — a post-pass adjusts the kind
  based on ancestor node types.

- For Python alone, `fully_qualified_name` is derived as
  ``<dotted_module_path>.<short_name>`` per plan-time decision #5,
  nested through enclosing classes and functions. For non-Python
  languages there is no settled convention, so we use
  ``<repo_relative_file>::<short_name>`` (opaque per row per the
  schema; resolved by `build.py` via `(file, fqn)` lookup).

Skip semantics: nodes with no name, no source range, or invalid line
ranges are dropped silently with a counter increment so build.py can
log totals.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Final, Literal, cast, get_args

import tree_sitter
from pydantic import BaseModel

from flosswing.index.grammars import SUPPORTED_LANGUAGES, get_language

logger = logging.getLogger(__name__)

_KIND_LITERAL = Literal[
    "function", "method", "class", "struct", "enum", "macro", "type"
]
_VALID_KINDS: Final[frozenset[str]] = frozenset(get_args(_KIND_LITERAL))


class SymbolRow(BaseModel):
    symbol: str
    fully_qualified_name: str
    file: str
    line_start: int
    line_end: int
    kind: _KIND_LITERAL
    language: str


class CallSiteRow(BaseModel):
    caller_fqn: str
    callee_text: str
    file: str
    line: int
    snippet: str


@dataclass
class ExtractResult:
    symbols: list[SymbolRow] = field(default_factory=list)
    call_sites: list[CallSiteRow] = field(default_factory=list)
    parse_errors: int = 0
    skipped_rows: int = 0


_SNIPPET_MAX_BYTES: Final[int] = 200


# ---------------------------------------------------------------------------
# Query strings — one definitions query + one calls query per language.
# Capture naming convention: `@def.<kind>` on the definition node,
# `@name` on the identifier carrying the symbol's short name.
# ---------------------------------------------------------------------------

_PY_DEF_QUERY: Final[str] = r"""
(function_definition name: (identifier) @name) @def.function
(class_definition name: (identifier) @name) @def.class
"""

_PY_CALL_QUERY: Final[str] = r"""
(call function: (identifier) @callee.name) @call.site
(call function: (attribute attribute: (identifier) @callee.name)) @call.site
"""

_C_DEF_QUERY: Final[str] = r"""
(function_definition
  declarator: (function_declarator
    declarator: (identifier) @name)) @def.function
(function_definition
  declarator: (pointer_declarator
    declarator: (function_declarator
      declarator: (identifier) @name))) @def.function
(struct_specifier name: (type_identifier) @name) @def.struct
(enum_specifier name: (type_identifier) @name) @def.enum
(type_definition declarator: (type_identifier) @name) @def.type
(preproc_function_def name: (identifier) @name) @def.macro
"""

_C_CALL_QUERY: Final[str] = r"""
(call_expression function: (identifier) @callee.name) @call.site
(call_expression
  function: (field_expression field: (field_identifier) @callee.name)) @call.site
"""

# C++ adds class, method (function_definition inside a class/struct body
# uses field_identifier), namespace-qualified free functions, references.
_CPP_DEF_QUERY: Final[str] = r"""
(class_specifier name: (type_identifier) @name) @def.class
(struct_specifier name: (type_identifier) @name) @def.struct
(enum_specifier name: (type_identifier) @name) @def.enum
(type_definition declarator: (type_identifier) @name) @def.type
(preproc_function_def name: (identifier) @name) @def.macro

(function_definition
  declarator: (function_declarator
    declarator: (identifier) @name)) @def.function
(function_definition
  declarator: (function_declarator
    declarator: (field_identifier) @name)) @def.method
(function_definition
  declarator: (pointer_declarator
    declarator: (function_declarator
      declarator: (identifier) @name))) @def.function
(function_definition
  declarator: (pointer_declarator
    declarator: (function_declarator
      declarator: (field_identifier) @name))) @def.method
(function_definition
  declarator: (reference_declarator
    (function_declarator
      declarator: (identifier) @name))) @def.function
"""

_CPP_CALL_QUERY: Final[str] = r"""
(call_expression function: (identifier) @callee.name) @call.site
(call_expression
  function: (field_expression field: (field_identifier) @callee.name)) @call.site
(call_expression
  function: (qualified_identifier name: (identifier) @callee.name)) @call.site
"""

_RUST_DEF_QUERY: Final[str] = r"""
(function_item name: (identifier) @name) @def.function
(struct_item name: (type_identifier) @name) @def.struct
(enum_item name: (type_identifier) @name) @def.enum
(type_item name: (type_identifier) @name) @def.type
(macro_definition name: (identifier) @name) @def.macro
"""

_RUST_CALL_QUERY: Final[str] = r"""
(call_expression function: (identifier) @callee.name) @call.site
(call_expression
  function: (scoped_identifier name: (identifier) @callee.name)) @call.site
(call_expression
  function: (field_expression field: (field_identifier) @callee.name)) @call.site
"""

# Go: a `type_spec` with a struct type is captured as @def.struct AND
# @def.type because Go uses one node for both shapes. The driver
# deduplicates by node identity and prefers the more-specific kind
# (struct > type).
_GO_DEF_QUERY: Final[str] = r"""
(function_declaration name: (identifier) @name) @def.function
(method_declaration name: (field_identifier) @name) @def.method
(type_spec name: (type_identifier) @name type: (struct_type)) @def.struct
(type_spec name: (type_identifier) @name) @def.type
(type_alias name: (type_identifier) @name) @def.type
"""

_GO_CALL_QUERY: Final[str] = r"""
(call_expression function: (identifier) @callee.name) @call.site
(call_expression
  function: (selector_expression field: (field_identifier) @callee.name)) @call.site
"""

_JS_DEF_QUERY: Final[str] = r"""
(function_declaration name: (identifier) @name) @def.function
(class_declaration name: (identifier) @name) @def.class
(method_definition name: (property_identifier) @name) @def.method
"""

_JS_CALL_QUERY: Final[str] = r"""
(call_expression function: (identifier) @callee.name) @call.site
(call_expression
  function: (member_expression property: (property_identifier) @callee.name)) @call.site
"""

_TS_DEF_QUERY: Final[str] = r"""
(function_declaration name: (identifier) @name) @def.function
(class_declaration name: (type_identifier) @name) @def.class
(method_definition name: (property_identifier) @name) @def.method
(interface_declaration name: (type_identifier) @name) @def.type
(type_alias_declaration name: (type_identifier) @name) @def.type
(enum_declaration name: (identifier) @name) @def.enum
"""

_TS_CALL_QUERY: Final[str] = r"""
(call_expression function: (identifier) @callee.name) @call.site
(call_expression
  function: (member_expression property: (property_identifier) @callee.name)) @call.site
"""

_JAVA_DEF_QUERY: Final[str] = r"""
(class_declaration name: (identifier) @name) @def.class
(method_declaration name: (identifier) @name) @def.method
(interface_declaration name: (identifier) @name) @def.type
(enum_declaration name: (identifier) @name) @def.enum
"""

_JAVA_CALL_QUERY: Final[str] = r"""
(method_invocation name: (identifier) @callee.name) @call.site
"""


_DEF_QUERIES: Final[dict[str, str]] = {
    "python": _PY_DEF_QUERY,
    "c": _C_DEF_QUERY,
    "cpp": _CPP_DEF_QUERY,
    "rust": _RUST_DEF_QUERY,
    "go": _GO_DEF_QUERY,
    "javascript": _JS_DEF_QUERY,
    "typescript": _TS_DEF_QUERY,
    "java": _JAVA_DEF_QUERY,
}

_CALL_QUERIES: Final[dict[str, str]] = {
    "python": _PY_CALL_QUERY,
    "c": _C_CALL_QUERY,
    "cpp": _CPP_CALL_QUERY,
    "rust": _RUST_CALL_QUERY,
    "go": _GO_CALL_QUERY,
    "javascript": _JS_CALL_QUERY,
    "typescript": _TS_CALL_QUERY,
    "java": _JAVA_CALL_QUERY,
}


# Node types whose function children should be reclassified `function` -> `method`.
_METHOD_AMBIGUOUS_PARENTS: Final[dict[str, frozenset[str]]] = {
    # Python: function_definition inside a class_definition is a method.
    "python": frozenset({"class_definition"}),
    # Rust: function_item inside an impl_item or trait_item is a method.
    "rust": frozenset({"impl_item", "trait_item"}),
}

# Node types that contain enclosing-symbol declarations, used to derive
# the caller FQN for a call-site by walking ancestors.
_ENCLOSING_DEF_TYPES: Final[dict[str, frozenset[str]]] = {
    "python": frozenset({"function_definition", "class_definition"}),
    "c": frozenset({"function_definition"}),
    "cpp": frozenset({
        "function_definition", "class_specifier", "struct_specifier",
        "namespace_definition",
    }),
    "rust": frozenset({
        "function_item", "impl_item", "trait_item", "mod_item",
    }),
    "go": frozenset({"function_declaration", "method_declaration"}),
    "javascript": frozenset({
        "function_declaration", "method_definition", "class_declaration",
    }),
    "typescript": frozenset({
        "function_declaration", "method_definition", "class_declaration",
    }),
    "java": frozenset({
        "class_declaration", "interface_declaration", "enum_declaration",
        "method_declaration", "constructor_declaration",
    }),
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _snippet_for_line(source_bytes: bytes, line: int) -> str:
    """Return source line `line` (1-indexed), truncated to _SNIPPET_MAX_BYTES."""
    lines = source_bytes.splitlines()
    if line < 1 or line > len(lines):
        return ""
    raw = lines[line - 1][:_SNIPPET_MAX_BYTES]
    return raw.decode("utf-8", errors="replace")


def _captures_dict(
    raw: object,
) -> dict[str, list[tree_sitter.Node]]:
    """Normalize a `Query.captures()` return into a dict of capture-name to nodes.

    The Python tree-sitter binding currently returns a dict; older bindings
    return ``list[tuple[Node, str]]``. Support both for forward/backward
    compatibility.
    """
    if isinstance(raw, dict):
        return {
            cast(str, k): list(cast(Iterable[tree_sitter.Node], v))
            for k, v in raw.items()
        }
    out: dict[str, list[tree_sitter.Node]] = {}
    for node, name in cast(Iterable[tuple[tree_sitter.Node, str]], raw):
        out.setdefault(name, []).append(node)
    return out


def _node_text(source_bytes: bytes, node: tree_sitter.Node) -> str:
    return source_bytes[node.start_byte:node.end_byte].decode(
        "utf-8", errors="replace"
    )


def _smallest_enclosing_name(
    def_node: tree_sitter.Node, name_nodes: list[tree_sitter.Node]
) -> tree_sitter.Node | None:
    """Pick the earliest `@name` node enclosed by `def_node`.

    A `@def.function` capture's enclosed `@name` matches uniquely in
    practice, but multiple `@name`s can fall inside a `@def.class` (the
    class's own name plus its methods' names). The earliest enclosed
    `@name` — which appears in source order before any nested body —
    is the one bound by `name: (identifier) @name` at the def node's
    own level.
    """
    best: tree_sitter.Node | None = None
    for n in name_nodes:
        if not (
            def_node.start_byte <= n.start_byte
            and n.end_byte <= def_node.end_byte
        ):
            continue
        if best is None or n.start_byte < best.start_byte:
            best = n
    return best


def _kind_from_capture(capture_name: str) -> str | None:
    """Extract the kind suffix from a `@def.<kind>` capture name."""
    if not capture_name.startswith("def."):
        return None
    suffix = capture_name[len("def."):]
    if suffix in _VALID_KINDS:
        return suffix
    return None


def _python_module_path(repo_relative_file: str) -> str:
    """src/example/cli.py -> src.example.cli  (per plan-time decision #5)."""
    if not repo_relative_file.endswith(".py"):
        return repo_relative_file
    stem = repo_relative_file[:-3]
    return stem.replace("/", ".")


def _python_fqn(
    def_node: tree_sitter.Node,
    short_name: str,
    module_path: str,
    source_bytes: bytes,
) -> str:
    """Build dotted FQN for a Python definition: module.Outer.short."""
    chain: list[str] = [short_name]
    parent = def_node.parent
    while parent is not None:
        if parent.type in ("class_definition", "function_definition"):
            outer_name = parent.child_by_field_name("name")
            if outer_name is not None:
                chain.append(_node_text(source_bytes, outer_name))
        parent = parent.parent
    chain.reverse()
    if not module_path:
        return ".".join(chain)
    return module_path + "." + ".".join(chain)


def _python_enclosing_fqn(
    call_node: tree_sitter.Node,
    module_path: str,
    source_bytes: bytes,
) -> str:
    """Caller FQN for a Python call-site: enclosing def/class chain, or module."""
    chain: list[str] = []
    parent = call_node.parent
    while parent is not None:
        if parent.type in ("class_definition", "function_definition"):
            outer_name = parent.child_by_field_name("name")
            if outer_name is not None:
                chain.append(_node_text(source_bytes, outer_name))
        parent = parent.parent
    chain.reverse()
    if not chain:
        return module_path or "<module>"
    if not module_path:
        return ".".join(chain)
    return module_path + "." + ".".join(chain)


def _generic_fqn(repo_relative_file: str, short_name: str) -> str:
    """FQN for non-Python languages: opaque per row.

    Per the schema, `fully_qualified_name` is treated as a string token
    used for `(file, fqn)` lookup during link-resolution. The schema does
    not pin a specific shape per language, so we use a portable
    `<file>::<short_name>` form. Build.py looks symbols up by exact match.
    """
    return f"{repo_relative_file}::{short_name}"


def _enclosing_short_name(
    call_node: tree_sitter.Node, source_bytes: bytes, language: str
) -> str | None:
    """Walk ancestors of `call_node`, return the name of the nearest enclosing def.

    Returns None if no enclosing definition is found.
    """
    enclosing_types = _ENCLOSING_DEF_TYPES.get(language, frozenset())
    parent = call_node.parent
    while parent is not None:
        if parent.type in enclosing_types:
            # Most grammars expose a `name` field on the def node.
            name_node = parent.child_by_field_name("name")
            if name_node is None and parent.type == "function_definition":
                # C / C++ free function: name is inside function_declarator.
                decl = parent.child_by_field_name("declarator")
                name_node = _c_innermost_function_name(decl) if decl else None
            if name_node is not None:
                return _node_text(source_bytes, name_node)
        parent = parent.parent
    return None


def _c_innermost_function_name(
    node: tree_sitter.Node | None,
) -> tree_sitter.Node | None:
    """Drill into nested (pointer/reference/function) declarators to the name."""
    while node is not None:
        if node.type == "identifier" or node.type == "field_identifier":
            return node
        # Nested wrappers: pointer_declarator / reference_declarator /
        # function_declarator all expose a `declarator` field.
        inner = node.child_by_field_name("declarator")
        if inner is None:
            return None
        node = inner
    return None


def _has_ancestor_of_type(
    node: tree_sitter.Node, types: frozenset[str]
) -> bool:
    parent = node.parent
    while parent is not None:
        if parent.type in types:
            return True
        parent = parent.parent
    return False


# ---------------------------------------------------------------------------
# Per-language driver
# ---------------------------------------------------------------------------


def _extract_for_language(
    *,
    tree: tree_sitter.Tree,
    source_bytes: bytes,
    repo_relative_file: str,
    language: str,
) -> ExtractResult:
    result = ExtractResult()
    if language not in SUPPORTED_LANGUAGES:
        return result

    lang = get_language(language)
    is_python = language == "python"
    module_path = _python_module_path(repo_relative_file) if is_python else ""

    # --- Definitions ---
    def_query_src = _DEF_QUERIES.get(language)
    if def_query_src is not None:
        def_q = lang.query(def_query_src)
        def_caps = _captures_dict(def_q.captures(tree.root_node))
        name_nodes = def_caps.get("name", [])

        # Collect (def_node, kind) pairs deduplicated by node position+type.
        # The tree-sitter Python binding returns distinct wrapper objects
        # for the same underlying node across different capture lookups —
        # `id()` is unstable but `(start_byte, end_byte, type)` uniquely
        # identifies a node within a single tree.
        # When the same node matches multiple `@def.<kind>` patterns,
        # prefer the more specific kind (struct > type for Go's type_spec).
        seen: dict[tuple[int, int, str], tuple[tree_sitter.Node, str]] = {}
        for cap_name, nodes in def_caps.items():
            kind = _kind_from_capture(cap_name)
            if kind is None:
                continue
            for n in nodes:
                key = (n.start_byte, n.end_byte, n.type)
                existing = seen.get(key)
                if existing is None:
                    seen[key] = (n, kind)
                else:
                    seen[key] = (n, _pick_kind(existing[1], kind))

        for def_node, kind in seen.values():
            name_node = _smallest_enclosing_name(def_node, name_nodes)
            if name_node is None:
                result.skipped_rows += 1
                continue
            short = _node_text(source_bytes, name_node)
            line_start = def_node.start_point[0] + 1
            line_end = def_node.end_point[0] + 1
            if line_start < 1 or line_end < line_start:
                result.skipped_rows += 1
                continue

            # Post-pass: reclassify Rust functions inside impl/trait as methods.
            adjusted_kind = kind
            ambiguous_parents = _METHOD_AMBIGUOUS_PARENTS.get(language)
            if (
                adjusted_kind == "function"
                and ambiguous_parents is not None
                and _has_ancestor_of_type(def_node, ambiguous_parents)
            ):
                adjusted_kind = "method"

            if is_python:
                fqn = _python_fqn(def_node, short, module_path, source_bytes)
            else:
                fqn = _generic_fqn(repo_relative_file, short)

            # `kind` field accepts only the _KIND_LITERAL values; we narrow
            # via cast through the dict-of-strings indirection. Pydantic
            # will validate at construction; if a bug yielded a bad kind
            # the row would raise here.
            result.symbols.append(SymbolRow(
                symbol=short,
                fully_qualified_name=fqn,
                file=repo_relative_file,
                line_start=line_start,
                line_end=line_end,
                kind=adjusted_kind,  # type: ignore[arg-type]
                language=language,
            ))

    # --- Call sites ---
    call_query_src = _CALL_QUERIES.get(language)
    if call_query_src is not None:
        call_q = lang.query(call_query_src)
        call_caps = _captures_dict(call_q.captures(tree.root_node))
        callee_names = call_caps.get("callee.name", [])
        call_sites = call_caps.get("call.site", [])

        for call_node in call_sites:
            callee_node = _smallest_enclosing_name(call_node, callee_names)
            if callee_node is None:
                result.skipped_rows += 1
                continue
            callee_text = _node_text(source_bytes, callee_node)
            line = call_node.start_point[0] + 1
            if line < 1:
                result.skipped_rows += 1
                continue
            if is_python:
                caller_fqn = _python_enclosing_fqn(
                    call_node, module_path, source_bytes
                )
            else:
                enclosing = _enclosing_short_name(
                    call_node, source_bytes, language
                )
                if enclosing is None:
                    caller_fqn = f"{repo_relative_file}::<module>"
                else:
                    caller_fqn = _generic_fqn(repo_relative_file, enclosing)
            result.call_sites.append(CallSiteRow(
                caller_fqn=caller_fqn,
                callee_text=callee_text,
                file=repo_relative_file,
                line=line,
                snippet=_snippet_for_line(source_bytes, line),
            ))

    if tree.root_node.has_error:
        result.parse_errors += 1

    return result


# Kind specificity: when two patterns match the same def node, keep the
# more concrete kind. struct/enum/class/macro are concrete; type is
# the catch-all (Go: `type_spec` matches both `def.struct` and `def.type`).
_KIND_SPECIFICITY: Final[dict[str, int]] = {
    "type": 0,
    "function": 1,
    "method": 1,
    "macro": 2,
    "enum": 3,
    "struct": 4,
    "class": 4,
}


def _pick_kind(a: str, b: str) -> str:
    """Return the more specific of `a` and `b` per _KIND_SPECIFICITY."""
    sa = _KIND_SPECIFICITY.get(a, 0)
    sb = _KIND_SPECIFICITY.get(b, 0)
    return a if sa >= sb else b


# ---------------------------------------------------------------------------
# Public entrypoint
# ---------------------------------------------------------------------------


def extract(
    *,
    tree: tree_sitter.Tree,
    source_bytes: bytes,
    repo_relative_file: str,
    language: str,
) -> ExtractResult:
    """Extract symbols + call sites from a parsed tree.

    Unknown languages return an empty `ExtractResult` without raising;
    `build.py` filters by the languages allowlist before calling, so an
    unknown id here is a logic bug elsewhere and should not crash the
    pipeline.
    """
    return _extract_for_language(
        tree=tree,
        source_bytes=source_bytes,
        repo_relative_file=repo_relative_file,
        language=language,
    )


__all__ = [
    "CallSiteRow",
    "ExtractResult",
    "SymbolRow",
    "extract",
]
