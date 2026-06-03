"""flosswing.index.entry_points — deterministic post-pass.

Per docs/specs/2026-06-02-v0.5-symbol-index-design.md § Component
responsibilities flosswing/index/entry_points.py and design decision #3.
"""

from __future__ import annotations

from flosswing.index.entry_points import EntryPointRow, detect
from flosswing.index.extractor import CallSiteRow, SymbolRow


def _py_sym(name: str, file: str, line: int = 1, kind: str = "function") -> SymbolRow:
    stem = file[:-3] if file.endswith(".py") else file
    return SymbolRow(
        symbol=name,
        fully_qualified_name=f"{stem.replace('/', '.')}.{name}",
        file=file,
        line_start=line,
        line_end=line + 2,
        kind=kind,  # type: ignore[arg-type]
        language="python",
    )


def test_detect_cli_main_python() -> None:
    symbols = [_py_sym("main", "src/example/cli.py", line=15)]
    eps = detect(symbols=symbols, call_sites=[], file_contents={})
    by_kind = {(e.kind, e.symbol): e for e in eps}
    assert ("cli", "main") in by_kind
    ep = by_kind[("cli", "main")]
    assert ep.file == "src/example/cli.py"
    assert ep.line == 15
    assert ep.attacker_controlled_input is True


def test_detect_cli_main_go() -> None:
    sym = SymbolRow(
        symbol="main",
        fully_qualified_name="main.go::main",
        file="main.go",
        line_start=5,
        line_end=8,
        kind="function",
        language="go",
    )
    eps = detect(symbols=[sym], call_sites=[], file_contents={})
    kinds = {(e.kind, e.symbol) for e in eps}
    assert ("cli", "main") in kinds


def test_detect_deserializer_yaml_load() -> None:
    """A caller of yaml.load is flagged as a deserializer entry point."""
    sym = _py_sym("load_config", "src/cfg.py", line=10)
    cs = CallSiteRow(
        caller_fqn=sym.fully_qualified_name,
        callee_text="load",  # yaml.load -> attribute call captures "load"
        file="src/cfg.py",
        line=12,
        snippet="    return yaml.load(text)",
    )
    eps = detect(symbols=[sym], call_sites=[cs], file_contents={})
    kinds = {(e.kind, e.symbol) for e in eps}
    assert ("deserializer", "load_config") in kinds


def test_detect_no_main_no_calls_yields_no_entry_points() -> None:
    sym = _py_sym("helper", "src/util.py")
    eps = detect(symbols=[sym], call_sites=[], file_contents={})
    assert eps == []


def test_detect_http_flask_route_python() -> None:
    """Decorator scan for @app.route — Flask-style HTTP entry."""
    sym = _py_sym("hello", "src/app.py", line=5)
    file_contents = {
        "src/app.py": (
            "from flask import Flask\n"
            "app = Flask(__name__)\n"
            "\n"
            "\n"
            "@app.route('/hello')\n"
            "def hello():\n"
            "    return 'hi'\n"
        )
    }
    eps = detect(symbols=[sym], call_sites=[], file_contents=file_contents)
    kinds = {(e.kind, e.symbol) for e in eps}
    assert ("http", "hello") in kinds


def test_detect_returns_entry_point_row_with_required_columns() -> None:
    sym = _py_sym("main", "src/example/cli.py", line=15)
    eps = detect(symbols=[sym], call_sites=[], file_contents={})
    assert len(eps) >= 1
    ep = eps[0]
    assert isinstance(ep, EntryPointRow)
    assert ep.symbol == "main"
    assert ep.file == "src/example/cli.py"
    assert ep.line == 15
    assert ep.kind in {"cli", "http", "exported", "deserializer", "ipc"}
    assert isinstance(ep.attacker_controlled_input, bool)
    assert isinstance(ep.notes, str)
