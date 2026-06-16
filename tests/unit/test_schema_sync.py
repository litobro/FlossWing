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

"""Structural schema-sync test: docs/schema.sql must agree with migrations."""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path

import pytest

from flosswing.state import session as st_session

_SCHEMA_SQL = Path(__file__).resolve().parents[2] / "docs" / "schema.sql"


def _excluded(name: str) -> bool:
    return name.startswith("sqlite_") or name == "alembic_version"


def _balanced_end(s: str, open_idx: int) -> int:
    """Index of the ')' matching the '(' at ``open_idx``.

    Skips single-quoted string literals (honouring the ``''`` escape) and
    ``-- ...`` line comments so a paren *inside* a CHECK string literal or an
    inline comment does not throw off the depth count.
    """
    depth = 0
    i = open_idx
    n = len(s)
    while i < n:
        ch = s[i]
        if ch == "'":  # string literal — skip to its close, handling '' escape
            i += 1
            while i < n:
                if s[i] == "'":
                    if i + 1 < n and s[i + 1] == "'":
                        i += 2
                        continue
                    break
                i += 1
            i += 1
            continue
        if ch == "-" and i + 1 < n and s[i + 1] == "-":  # line comment
            while i < n and s[i] != "\n":
                i += 1
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise ValueError("unbalanced parentheses")


def _norm(expr: str) -> str:
    return re.sub(r"\s+", " ", expr).strip().lower()


def _named_constraints(table_sql: str, keyword: str) -> frozenset[tuple[str, str]]:
    """Extract ``CONSTRAINT <name> <keyword> (<body>)`` pairs, body-normalized."""
    out: dict[str, str] = {}
    for m in re.finditer(rf"CONSTRAINT\s+(\w+)\s+{keyword}\s*\(", table_sql, re.I):
        open_idx = m.end() - 1
        close = _balanced_end(table_sql, open_idx)
        out[m.group(1)] = _norm(table_sql[open_idx + 1 : close])
    return frozenset(out.items())


def _table_struct(conn: sqlite3.Connection, table: str) -> dict[str, frozenset]:
    # cid (r[0]) is included so column *position* drift is detected, not just
    # the set of column definitions.
    columns = frozenset(
        (r[0], r[1], (r[2] or "").upper(), r[3], r[4], r[5])
        for r in conn.execute("SELECT * FROM pragma_table_info(?)", (table,))
    )

    by_id: dict[int, dict] = {}
    for r in conn.execute("SELECT * FROM pragma_foreign_key_list(?)", (table,)):
        # r = (id, seq, ref_table, from, to, on_update, on_delete, match)
        d = by_id.setdefault(
            r[0],
            {"table": r[2], "on_update": r[5], "on_delete": r[6], "match": r[7], "cols": []},
        )
        d["cols"].append((r[1], r[3], r[4]))  # (seq, from, to)
    # Preserve column order by seq so a reversed composite-FK mapping is caught.
    fks = frozenset(
        (
            d["table"],
            tuple((f, t) for _seq, f, t in sorted(d["cols"])),
            d["on_update"],
            d["on_delete"],
            d["match"],
        )
        for d in by_id.values()
    )

    indexes = set()
    for r in conn.execute("SELECT * FROM pragma_index_list(?)", (table,)):
        # r = (seq, name, unique, origin, partial); origin 'c' == CREATE INDEX
        if r[3] != "c":
            continue
        cols = tuple(
            ir[2] for ir in conn.execute("SELECT * FROM pragma_index_info(?)", (r[1],))
        )
        indexes.add((r[1], bool(r[2]), cols))

    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone()
    table_sql = row[0] if row else ""
    # FK/PK constraint *names* aren't exposed by PRAGMA; parse them from the DDL
    # so a fk_/pk_ name drift is caught (the PRAGMA-based `fks` covers semantics).
    fk_names = frozenset(
        re.findall(r"CONSTRAINT\s+(\w+)\s+FOREIGN\s+KEY", table_sql, re.I)
    )
    pk_names = frozenset(
        re.findall(r"CONSTRAINT\s+(\w+)\s+PRIMARY\s+KEY", table_sql, re.I)
    )
    return {
        "columns": columns,
        "fks": fks,
        "fk_names": fk_names,
        "pk_names": pk_names,
        "indexes": frozenset(indexes),
        "checks": _named_constraints(table_sql, "CHECK"),
        "uniques": _named_constraints(table_sql, "UNIQUE"),
    }


def _introspect(db_path: str) -> dict[str, dict[str, frozenset]]:
    conn = sqlite3.connect(db_path)
    try:
        tables = sorted(
            r[0]
            for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            if not _excluded(r[0])
        )
        return {t: _table_struct(conn, t) for t in tables}
    finally:
        conn.close()


def _diff(mig: dict, doc: dict) -> list[str]:
    msgs: list[str] = []
    for t in sorted(set(mig) | set(doc)):
        if t not in mig:
            msgs.append(f"table only in schema.sql: {t}")
            continue
        if t not in doc:
            msgs.append(f"table only in migrations: {t}")
            continue
        for aspect in (
            "columns", "fks", "fk_names", "pk_names", "indexes", "checks", "uniques"
        ):
            only_mig = mig[t][aspect] - doc[t][aspect]
            only_doc = doc[t][aspect] - mig[t][aspect]
            if only_mig or only_doc:
                # Relies on column/constraint names being unique within a table,
                # so the tuple sort always resolves at the name element and never
                # reaches a (potentially None) dflt_value / comparable-None field.
                msgs.append(
                    f"{t}.{aspect}: only-in-migrations={sorted(only_mig)} "
                    f"only-in-schema.sql={sorted(only_doc)}"
                )
    return msgs


def _build_from_schema_sql(db_path: str) -> None:
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(_SCHEMA_SQL.read_text(encoding="utf-8"))
    finally:
        conn.close()


def test_schema_sql_matches_migrations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """docs/schema.sql must structurally equal a fresh `alembic upgrade head`."""
    # DB-A: migrations (session auto-upgrades a fresh temp DB).
    db_a = tmp_path / "migrations.db"
    monkeypatch.setenv("FLOSSWING_DB_URL", f"sqlite:///{db_a}")
    monkeypatch.setattr(st_session, "_cached_engine", None, raising=False)
    monkeypatch.setattr(st_session, "_cached_session_factory", None, raising=False)
    st_session.engine()

    # DB-B: docs/schema.sql executed directly.
    db_b = tmp_path / "schema_sql.db"
    _build_from_schema_sql(str(db_b))

    diff = _diff(_introspect(str(db_a)), _introspect(str(db_b)))
    assert not diff, "schema.sql disagrees with migrations:\n" + "\n".join(diff)
