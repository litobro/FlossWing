"""flosswing.index.extractor — per-language symbol / call-site extraction.

Per docs/specs/2026-06-02-v0.5-symbol-index-design.md § Component
responsibilities flosswing/index/extractor.py. Per the operator-
upsized plan-time decision #4 (2026-06-02), v0.5 ships
production-quality coverage for all 8 v1 languages — definitions
AND call sites for each.

The per-language coverage table in the design doc § Tree-sitter queries
is the contract for which tree-sitter node types map to which `kind`
literal. These tests pin that mapping.
"""

from __future__ import annotations

from typing import Any

from flosswing.index import extractor
from flosswing.index.grammars import get_parser


def _extract(language: str, source: str, file: str) -> Any:
    parser = get_parser(language)
    tree = parser.parse(source.encode("utf-8"))
    return extractor.extract(
        tree=tree,
        source_bytes=source.encode("utf-8"),
        repo_relative_file=file,
        language=language,
    )


# ---------------------------------------------------------------------------
# Python — full coverage
# ---------------------------------------------------------------------------


def test_python_extracts_function_definition() -> None:
    src = "def greet(name):\n    print(name)\n"
    result = _extract("python", src, file="src/example/cli.py")
    syms = result.symbols
    assert len(syms) == 1
    s = syms[0]
    assert s.symbol == "greet"
    assert s.fully_qualified_name == "src.example.cli.greet"
    assert s.file == "src/example/cli.py"
    assert s.line_start == 1
    assert s.line_end == 2
    assert s.kind == "function"
    assert s.language == "python"


def test_python_extracts_class_and_methods() -> None:
    src = (
        "class Foo:\n"
        "    def bar(self):\n"
        "        pass\n"
        "    def baz(self):\n"
        "        pass\n"
    )
    result = _extract("python", src, file="src/m.py")
    syms_by_name = {s.symbol: s for s in result.symbols}
    assert set(syms_by_name) == {"Foo", "bar", "baz"}
    assert syms_by_name["Foo"].kind == "class"
    assert syms_by_name["bar"].kind == "method"
    assert syms_by_name["baz"].kind == "method"
    assert syms_by_name["bar"].fully_qualified_name == "src.m.Foo.bar"
    assert syms_by_name["baz"].fully_qualified_name == "src.m.Foo.baz"


def test_python_extracts_call_site_bare_name() -> None:
    src = (
        "def greet(name):\n"
        "    print(name)\n"
        "def main():\n"
        "    greet('x')\n"
    )
    result = _extract("python", src, file="src/example/cli.py")
    by_callee = {c.callee_text: c for c in result.call_sites}
    assert "greet" in by_callee
    assert "print" in by_callee
    greet_call = by_callee["greet"]
    assert greet_call.caller_fqn == "src.example.cli.main"
    assert greet_call.line == 4
    assert "greet" in greet_call.snippet


def test_python_extracts_call_site_attribute() -> None:
    src = (
        "import os\n"
        "def main():\n"
        "    os.unlink('/tmp/x')\n"
    )
    result = _extract("python", src, file="src/m.py")
    by_callee = {c.callee_text: c for c in result.call_sites}
    assert "unlink" in by_callee
    assert by_callee["unlink"].caller_fqn == "src.m.main"


def test_python_skips_anonymous_lambda() -> None:
    src = "f = lambda x: x + 1\n"
    result = _extract("python", src, file="src/m.py")
    assert all(s.symbol != "<lambda>" for s in result.symbols)


def test_python_module_path_root_level_script() -> None:
    src = "def hello():\n    pass\n"
    result = _extract("python", src, file="script.py")
    assert result.symbols[0].fully_qualified_name == "script.hello"


def test_python_no_definitions_yields_empty_symbol_list() -> None:
    src = "x = 1\ny = 2\n"
    result = _extract("python", src, file="src/m.py")
    assert result.symbols == []


def test_python_unparseable_source_does_not_raise() -> None:
    """A syntactically broken file yields whatever the grammar recovers."""
    src = "def f("  # unterminated
    result = _extract("python", src, file="src/m.py")
    assert isinstance(result.parse_errors, int)


def test_python_call_site_at_module_scope_has_module_caller() -> None:
    src = "import os\nos.path.join('a', 'b')\n"
    result = _extract("python", src, file="src/m.py")
    callees = {c.callee_text for c in result.call_sites}
    assert "join" in callees
    join_call = next(c for c in result.call_sites if c.callee_text == "join")
    # Caller is the module itself when call is at file scope.
    assert join_call.caller_fqn == "src.m"


# ---------------------------------------------------------------------------
# C — function (with pointer-wrapped declarator), struct, enum, type, macro
# ---------------------------------------------------------------------------


def test_c_extracts_function() -> None:
    src = "int add(int a, int b) { return a + b; }\n"
    result = _extract("c", src, file="src/add.c")
    by_name = {s.symbol: s for s in result.symbols}
    assert "add" in by_name
    assert by_name["add"].kind == "function"
    assert by_name["add"].language == "c"


def test_c_extracts_pointer_return_function() -> None:
    src = "static int *foo(int x) { return 0; }\n"
    result = _extract("c", src, file="src/p.c")
    names = {s.symbol for s in result.symbols}
    assert "foo" in names


def test_c_extracts_struct_enum_typedef_macro() -> None:
    src = (
        "struct Point { int x; int y; };\n"
        "enum Color { RED, GREEN };\n"
        "typedef int MyInt;\n"
        "#define MAX(a,b) ((a)>(b)?(a):(b))\n"
    )
    result = _extract("c", src, file="src/m.c")
    by_name = {s.symbol: s.kind for s in result.symbols}
    assert by_name.get("Point") == "struct"
    assert by_name.get("Color") == "enum"
    assert by_name.get("MyInt") == "type"
    assert by_name.get("MAX") == "macro"


def test_c_extracts_call_site() -> None:
    src = (
        "int main(void) {\n"
        "    foo(1);\n"
        "    obj.method();\n"
        "    return 0;\n"
        "}\n"
    )
    result = _extract("c", src, file="src/m.c")
    callees = {c.callee_text for c in result.call_sites}
    assert "foo" in callees
    assert "method" in callees  # field_expression captures rightmost
    foo_call = next(c for c in result.call_sites if c.callee_text == "foo")
    assert foo_call.caller_fqn.endswith("main")
    assert foo_call.line == 2


# ---------------------------------------------------------------------------
# C++ — function, method, class, struct, enum, type, macro
# ---------------------------------------------------------------------------


def test_cpp_extracts_free_function_and_class_method() -> None:
    src = (
        "int g() { return 1; }\n"
        "class Foo {\n"
        "public:\n"
        "    void bar() {}\n"
        "    static int baz() { return 0; }\n"
        "};\n"
    )
    result = _extract("cpp", src, file="src/m.cpp")
    by_name = {s.symbol: s.kind for s in result.symbols}
    assert by_name.get("g") == "function"
    assert by_name.get("Foo") == "class"
    assert by_name.get("bar") == "method"
    assert by_name.get("baz") == "method"


def test_cpp_extracts_struct_enum_typedef_macro() -> None:
    src = (
        "struct S { int x; };\n"
        "enum E { A, B };\n"
        "typedef int MyInt;\n"
        "#define ID(x) (x)\n"
    )
    result = _extract("cpp", src, file="src/m.cpp")
    by_name = {s.symbol: s.kind for s in result.symbols}
    assert by_name.get("S") == "struct"
    assert by_name.get("E") == "enum"
    assert by_name.get("MyInt") == "type"
    assert by_name.get("ID") == "macro"


def test_cpp_extracts_call_site() -> None:
    src = (
        "void caller() {\n"
        "    foo();\n"
        "    obj.method();\n"
        "}\n"
    )
    result = _extract("cpp", src, file="src/m.cpp")
    callees = {c.callee_text for c in result.call_sites}
    assert "foo" in callees
    assert "method" in callees


# ---------------------------------------------------------------------------
# Rust — function, method (impl), struct, enum, type, macro
# ---------------------------------------------------------------------------


def test_rust_extracts_function_and_struct_enum() -> None:
    src = (
        "fn add(a: i32, b: i32) -> i32 { a + b }\n"
        "struct Foo { x: i32 }\n"
        "enum E { A, B }\n"
        "type Id = u32;\n"
    )
    result = _extract("rust", src, file="src/lib.rs")
    by_name = {s.symbol: s.kind for s in result.symbols}
    assert by_name.get("add") == "function"
    assert by_name.get("Foo") == "struct"
    assert by_name.get("E") == "enum"
    assert by_name.get("Id") == "type"


def test_rust_extracts_impl_method() -> None:
    src = (
        "struct Foo;\n"
        "impl Foo {\n"
        "    fn bar(&self) {}\n"
        "    fn assoc() {}\n"
        "}\n"
    )
    result = _extract("rust", src, file="src/lib.rs")
    by_name = {s.symbol: s.kind for s in result.symbols}
    # Functions inside an impl are methods (per spec coverage table:
    # Rust has both function and method).
    assert by_name.get("bar") == "method"
    assert by_name.get("assoc") == "method"


def test_rust_extracts_macro_definition() -> None:
    src = "macro_rules! foo { () => { 1 } }\n"
    result = _extract("rust", src, file="src/lib.rs")
    by_name = {s.symbol: s.kind for s in result.symbols}
    assert by_name.get("foo") == "macro"


def test_rust_extracts_call_site() -> None:
    src = (
        "fn main() {\n"
        "    foo();\n"
        "    pkg::bar();\n"
        "    obj.method();\n"
        "}\n"
    )
    result = _extract("rust", src, file="src/main.rs")
    callees = {c.callee_text for c in result.call_sites}
    assert "foo" in callees
    # scoped_identifier callee should resolve to rightmost identifier.
    assert "bar" in callees
    assert "method" in callees


# ---------------------------------------------------------------------------
# Go — function, method, struct, type
# ---------------------------------------------------------------------------


def test_go_extracts_function_and_method() -> None:
    src = (
        "package main\n"
        "func Greet(name string) {}\n"
        "func (r *Rec) M() {}\n"
    )
    result = _extract("go", src, file="main.go")
    by_name = {s.symbol: s.kind for s in result.symbols}
    assert by_name.get("Greet") == "function"
    assert by_name.get("M") == "method"


def test_go_extracts_struct_and_type() -> None:
    src = (
        "package p\n"
        "type T struct { x int }\n"
        "type Alias = int\n"
    )
    result = _extract("go", src, file="p.go")
    by_name = {s.symbol: s.kind for s in result.symbols}
    # Per spec table: Go has struct and type.
    assert by_name.get("T") == "struct"
    assert by_name.get("Alias") == "type"


def test_go_extracts_call_site() -> None:
    src = (
        "package main\n"
        "func main() {\n"
        "    foo(1)\n"
        "    pkg.Fn()\n"
        "}\n"
    )
    result = _extract("go", src, file="main.go")
    callees = {c.callee_text for c in result.call_sites}
    assert "foo" in callees
    assert "Fn" in callees


# ---------------------------------------------------------------------------
# JavaScript — function, method, class
# ---------------------------------------------------------------------------


def test_javascript_extracts_function_class_and_method() -> None:
    src = (
        "function greet(name) { return name; }\n"
        "class Foo {\n"
        "    bar() {}\n"
        "    static baz() {}\n"
        "}\n"
    )
    result = _extract("javascript", src, file="src/index.js")
    by_name = {s.symbol: s.kind for s in result.symbols}
    assert by_name.get("greet") == "function"
    assert by_name.get("Foo") == "class"
    assert by_name.get("bar") == "method"
    assert by_name.get("baz") == "method"


def test_javascript_extracts_call_site() -> None:
    src = (
        "function main() {\n"
        "    foo();\n"
        "    obj.method();\n"
        "    console.log('x');\n"
        "}\n"
    )
    result = _extract("javascript", src, file="src/index.js")
    callees = {c.callee_text for c in result.call_sites}
    assert "foo" in callees
    assert "method" in callees
    assert "log" in callees


# ---------------------------------------------------------------------------
# TypeScript — function, method, class, enum, type (interface + alias)
# ---------------------------------------------------------------------------


def test_typescript_extracts_function_class_and_method() -> None:
    src = (
        "function greet(name: string): string { return name; }\n"
        "class Foo {\n"
        "    bar(): void {}\n"
        "}\n"
    )
    result = _extract("typescript", src, file="src/index.ts")
    by_name = {s.symbol: s.kind for s in result.symbols}
    assert by_name.get("greet") == "function"
    assert by_name.get("Foo") == "class"
    assert by_name.get("bar") == "method"


def test_typescript_extracts_interface_alias_and_enum() -> None:
    src = (
        "interface I { m(): void; }\n"
        "type Alias = number;\n"
        "enum E { A, B }\n"
    )
    result = _extract("typescript", src, file="src/types.ts")
    by_name = {s.symbol: s.kind for s in result.symbols}
    # Per spec table: TypeScript has type (interface + alias) and enum.
    assert by_name.get("I") == "type"
    assert by_name.get("Alias") == "type"
    assert by_name.get("E") == "enum"


def test_typescript_extracts_call_site() -> None:
    src = (
        "function main(): void {\n"
        "    foo();\n"
        "    obj.method();\n"
        "}\n"
    )
    result = _extract("typescript", src, file="src/m.ts")
    callees = {c.callee_text for c in result.call_sites}
    assert "foo" in callees
    assert "method" in callees


# ---------------------------------------------------------------------------
# Java — function, method, class, enum
# ---------------------------------------------------------------------------


def test_java_extracts_class_and_method() -> None:
    src = (
        "public class Foo {\n"
        "    public void bar() {}\n"
        "}\n"
    )
    result = _extract("java", src, file="Foo.java")
    by_name = {s.symbol: s.kind for s in result.symbols}
    assert by_name.get("Foo") == "class"
    assert by_name.get("bar") == "method"


def test_java_extracts_enum_declaration() -> None:
    src = "enum E { A, B }\n"
    result = _extract("java", src, file="E.java")
    by_name = {s.symbol: s.kind for s in result.symbols}
    assert by_name.get("E") == "enum"


def test_java_skips_enum_constants() -> None:
    """Enum constants are not first-class symbols per spec coverage table."""
    src = "enum E { A, B }\n"
    result = _extract("java", src, file="E.java")
    names = {s.symbol for s in result.symbols}
    assert "A" not in names
    assert "B" not in names


def test_java_extracts_call_site() -> None:
    src = (
        "class X {\n"
        "    void caller() {\n"
        "        foo();\n"
        "        obj.method();\n"
        "        Class.staticM();\n"
        "    }\n"
        "}\n"
    )
    result = _extract("java", src, file="X.java")
    callees = {c.callee_text for c in result.call_sites}
    assert "foo" in callees
    assert "method" in callees
    assert "staticM" in callees


# ---------------------------------------------------------------------------
# Cross-language invariants
# ---------------------------------------------------------------------------


def test_unsupported_language_returns_empty_result() -> None:
    """An unknown language id returns an empty ExtractResult without raising."""
    parser = get_parser("python")
    tree = parser.parse(b"def f(): pass\n")
    result = extractor.extract(
        tree=tree,
        source_bytes=b"def f(): pass\n",
        repo_relative_file="x.kotlin",
        language="kotlin",  # not in SUPPORTED_LANGUAGES
    )
    assert result.symbols == []
    assert result.call_sites == []


def test_skip_count_is_integer() -> None:
    src = "def f(): pass\n"
    result = _extract("python", src, file="m.py")
    assert isinstance(result.skipped_rows, int)
