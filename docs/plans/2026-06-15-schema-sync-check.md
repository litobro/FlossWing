# Schema-sync check + constraint-name reconciliation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `docs/schema.sql` and the Alembic migrations agree, and add a CI test that enforces it — by fixing the `ck` naming convention so fresh builds produce clean constraint names, documenting one missing FK, and adding a structural schema-sync test.

**Architecture:** Three small, independent changes. (1) Make the `ck` naming convention in `flosswing/state/db.py` idempotent so a fresh `alembic upgrade head` produces clean `ck_<table>_<suffix>` names instead of doubled ones (no migration, no touching existing DBs). (2) Add the real `fk_findings_dedupe_cluster_id_dedupe_clusters` declaration to `docs/schema.sql`. (3) Add `tests/unit/test_schema_sync.py` that builds the schema two ways (migrations vs `schema.sql`) and asserts structural equality.

**Tech Stack:** Python 3.11, SQLAlchemy + Alembic (SQLite), `sqlite3` stdlib, `pytest`. No new dependencies.

**Spec:** `docs/specs/2026-06-15-schema-sync-check-design.md`

**Conventions every task follows:**
- New files start with the GPLv3 header block — copy the first 15 lines verbatim from the top of `flosswing/errors.py`, then the module `"""docstring"""`, then `from __future__ import annotations`.
- Gates after each implementation task: `ruff check .`, `mypy --strict flosswing`, `pytest tests/unit -q`. Activate the venv first: `source .venv/bin/activate`.
- Work on branch `fix/schema-sync-check` (already created). Do NOT touch `main` or edit migration `001`.
- Commit at the end of each task with a spec-referencing message.

---

### Task 1: Idempotent `ck` naming convention

**Files:**
- Modify: `flosswing/state/db.py` (the `NAMING_CONVENTION` dict, ~lines 31-39)
- Test: `tests/unit/test_db_naming.py` (new)

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_db_naming.py` (prepend the GPLv3 header, then):

```python
from __future__ import annotations

from sqlalchemy import CheckConstraint, Column, Integer, MetaData, Table
from sqlalchemy.dialects import sqlite
from sqlalchemy.schema import CreateTable

from flosswing.state.db import NAMING_CONVENTION


def _ddl() -> str:
    md = MetaData(naming_convention=NAMING_CONVENTION)
    t = Table(
        "widgets",
        md,
        Column("n", Integer),
        # Authored with the FULL name (the 001 style that caused doubling):
        CheckConstraint("n >= 0", name="ck_widgets_nonneg"),
        # Authored with a BARE suffix (the recommended style):
        CheckConstraint("n < 100", name="toobig"),
    )
    return str(CreateTable(t).compile(dialect=sqlite.dialect()))


def test_ck_naming_is_idempotent() -> None:
    ddl = _ddl()
    # Both forms resolve to the clean single-prefixed name.
    assert "ck_widgets_nonneg" in ddl
    assert "ck_widgets_toobig" in ddl
    # And nothing is doubled.
    assert "ck_widgets_ck_widgets" not in ddl
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_db_naming.py -v`
Expected: FAIL — with the current static `ck` convention, the full-named constraint compiles to `ck_widgets_ck_widgets_nonneg`, so `assert "ck_widgets_ck_widgets" not in ddl` fails.

- [ ] **Step 3: Make the convention idempotent**

In `flosswing/state/db.py`, replace the imports/`NAMING_CONVENTION`/`metadata` block. The current block is:

```python
from sqlalchemy import MetaData, event
from sqlalchemy.engine import Engine

NAMING_CONVENTION: dict[str, str] = {
    "ix": "ix_%(table_name)s_%(column_0_name)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

metadata: MetaData = MetaData(naming_convention=NAMING_CONVENTION)
```

Replace it with:

```python
from collections.abc import Callable

from sqlalchemy import MetaData, event
from sqlalchemy.engine import Engine
from sqlalchemy.sql.schema import CheckConstraint, Table


def _ck_suffix(constraint: CheckConstraint, table: Table) -> str:
    """Idempotent CHECK-constraint suffix for the ``ck`` naming convention.

    A plain-string constraint name is fed through the convention as the
    ``%(ck_suffix)s`` token. If the author already wrote the full
    ``ck_<table>_<suffix>`` name, strip the redundant ``ck_<table>_`` prefix so
    the ``ck_%(table_name)s_%(ck_suffix)s`` template does not double it; a bare
    suffix passes through unchanged. This makes the convention robust to either
    authoring style and is why migration 001's full-name checks build clean.
    """
    raw = constraint.name or ""
    prefix = f"ck_{table.name}_"
    return raw[len(prefix):] if raw.startswith(prefix) else raw


NAMING_CONVENTION: dict[str, str | Callable[[CheckConstraint, Table], str]] = {
    "ix": "ix_%(table_name)s_%(column_0_name)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(ck_suffix)s",
    "ck_suffix": _ck_suffix,
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

metadata: MetaData = MetaData(naming_convention=NAMING_CONVENTION)
```

If `mypy --strict` objects to passing the `str | Callable` dict to `MetaData(naming_convention=...)`, add a precise inline ignore with a reason, e.g.:
`metadata: MetaData = MetaData(naming_convention=NAMING_CONVENTION)  # type: ignore[arg-type]  # SQLAlchemy stubs type naming_convention as Mapping[str, str]; custom token callables are supported at runtime`

- [ ] **Step 4: Run the test to verify it passes**

Run: `pytest tests/unit/test_db_naming.py -v`
Expected: PASS.

- [ ] **Step 5: Verify a fresh migration build now has clean names**

Run:
```bash
TMP=$(mktemp -u --suffix=.db)
FLOSSWING_DB_URL="sqlite:///$TMP" python -c "
import re, sqlite3, os
from flosswing.state import session as s
s.engine()
c = sqlite3.connect(os.environ['FLOSSWING_DB_URL'])
doubled = sum(len(re.findall(r'CONSTRAINT ck_(\w+?)_ck_\1_\w+ CHECK', sql)) for _, sql in c.execute(\"SELECT name, sql FROM sqlite_master WHERE type='table'\"))
total = sum(len(re.findall(r'CONSTRAINT ck_\w+ CHECK', sql)) for _, sql in c.execute(\"SELECT name, sql FROM sqlite_master WHERE type='table'\"))
print('doubled=', doubled, 'total_ck=', total)
"
rm -f "$TMP"
```
Expected: `doubled= 0 total_ck= 46`.

- [ ] **Step 6: Gates + commit**

```bash
ruff check . && mypy --strict flosswing && pytest tests/unit -q
git add flosswing/state/db.py tests/unit/test_db_naming.py
git commit -m "Make ck naming convention idempotent (clean check names) per docs/specs/2026-06-15-schema-sync-check-design.md"
```

---

### Task 2: Structural schema-sync test (proves it catches the FK drift)

**Files:**
- Create: `tests/unit/test_schema_sync.py`

After Task 1 the constraint names match, so this test fails on exactly one
remaining difference — the `findings` foreign key that `schema.sql` still omits.
That demonstrates the check catches real drift; Task 3 makes it pass.

- [ ] **Step 1: Write the test (and its comparator helpers)**

Create `tests/unit/test_schema_sync.py` (prepend the GPLv3 header, then):

```python
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
    """Index of the ')' matching the '(' at ``open_idx``."""
    depth = 0
    for i in range(open_idx, len(s)):
        if s[i] == "(":
            depth += 1
        elif s[i] == ")":
            depth -= 1
            if depth == 0:
                return i
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
    columns = frozenset(
        (r[1], (r[2] or "").upper(), r[3], r[4], r[5])
        for r in conn.execute(f"PRAGMA table_info('{table}')")
    )

    by_id: dict[int, dict] = {}
    for r in conn.execute(f"PRAGMA foreign_key_list('{table}')"):
        # r = (id, seq, ref_table, from, to, on_update, on_delete, match)
        d = by_id.setdefault(
            r[0],
            {"table": r[2], "on_update": r[5], "on_delete": r[6], "match": r[7], "cols": []},
        )
        d["cols"].append((r[3], r[4]))
    fks = frozenset(
        (d["table"], tuple(sorted(d["cols"])), d["on_update"], d["on_delete"], d["match"])
        for d in by_id.values()
    )

    indexes = set()
    for r in conn.execute(f"PRAGMA index_list('{table}')"):
        # r = (seq, name, unique, origin, partial); origin 'c' == CREATE INDEX
        if r[3] != "c":
            continue
        cols = tuple(ir[2] for ir in conn.execute(f"PRAGMA index_info('{r[1]}')"))
        indexes.add((r[1], bool(r[2]), cols))

    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone()
    table_sql = row[0] if row else ""
    return {
        "columns": columns,
        "fks": fks,
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
        for aspect in ("columns", "fks", "indexes", "checks", "uniques"):
            only_mig = mig[t][aspect] - doc[t][aspect]
            only_doc = doc[t][aspect] - mig[t][aspect]
            if only_mig or only_doc:
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
```

- [ ] **Step 2: Run the test to verify it fails on the FK only**

Run: `pytest tests/unit/test_schema_sync.py -v`
Expected: FAIL with a message like
`findings.fks: only-in-migrations=[('dedupe_clusters', (('dedupe_cluster_id','id'),), 'NO ACTION', 'SET NULL', 'NONE')] only-in-schema.sql=[]`
(constraint names already match thanks to Task 1; the only structural diff is the missing FK). If any OTHER differences appear, STOP and report them — the comparator may need adjustment or there is unexpected drift.

- [ ] **Step 3: (no code yet)** — the fix is Task 3. Do not modify the test to pass artificially.

- [ ] **Step 4: Commit the test as-is (red)**

Commit the comparator now; Task 3 turns it green in the same branch.

```bash
ruff check . && mypy --strict flosswing
git add tests/unit/test_schema_sync.py
git commit -m "Add structural schema-sync test (red: catches the findings FK drift) per docs/specs/2026-06-15-schema-sync-check-design.md"
```

(Do not run the full `pytest tests/unit` green-gate here — this one test is intentionally red until Task 3. `ruff`/`mypy` must still pass.)

---

### Task 3: Document the `findings.dedupe_cluster_id` FK in `schema.sql`

**Files:**
- Modify: `docs/schema.sql` (the `findings` table, line ~351)

- [ ] **Step 1: Replace the placeholder comment with the real FK**

In `docs/schema.sql`, inside the `findings` `CREATE TABLE`, replace this line:

```sql
    -- dedupe_cluster_id FK declared on the cluster side via the link table; see below.
```

with:

```sql
    CONSTRAINT fk_findings_dedupe_cluster_id_dedupe_clusters
        FOREIGN KEY (dedupe_cluster_id) REFERENCES dedupe_clusters(id)
        ON DELETE SET NULL,
```

(It sits among the other `fk_findings_*` declarations, immediately before the
`CONSTRAINT ck_findings_severity` line, matching the surrounding style.)

- [ ] **Step 2: Run the sync test to verify it now passes**

Run: `pytest tests/unit/test_schema_sync.py -v`
Expected: PASS (no structural differences).

- [ ] **Step 3: Full gates**

Run:
```bash
ruff check .
mypy --strict flosswing
pytest tests/unit -q
```
Expected: ruff clean; mypy clean; all unit tests pass (including `test_schema_sync` and `test_db_naming`).

- [ ] **Step 4: Verify the alembic round-trip still works**

Run (mirrors the CI step):
```bash
TMPDB="$(mktemp -u --suffix=.db)"
FLOSSWING_DB_URL="sqlite:///${TMPDB}" alembic -c alembic.ini upgrade head
FLOSSWING_DB_URL="sqlite:///${TMPDB}" alembic -c alembic.ini downgrade base
FLOSSWING_DB_URL="sqlite:///${TMPDB}" alembic -c alembic.ini upgrade head
rm -f "${TMPDB}"
```
Expected: all three commands succeed (exit 0).

- [ ] **Step 5: Commit**

```bash
git add docs/schema.sql
git commit -m "Document findings.dedupe_cluster_id FK in schema.sql; schema-sync test green per docs/specs/2026-06-15-schema-sync-check-design.md"
```

---

## Self-Review

**Spec coverage:**
- Idempotent `ck` convention (fresh build clean, 0 doubled) → Task 1 (db.py + test + Step-5 verification). ✓
- `schema.sql` declares the FK, still executes as a script → Task 3 (the sync test executes the script in `_build_from_schema_sql`, so a syntax error would fail it). ✓
- Structural sync check (columns/fks/indexes/checks/uniques; excludes `sqlite_%` + `alembic_version` both sides) → Task 2. ✓
- Idempotency unit test → Task 1 `test_ck_naming_is_idempotent`. ✓
- Runs in existing `pytest tests/unit` CI step; no `ci.yml` change → both tests under `tests/unit/`. ✓
- alembic round-trip stays green → Task 3 Step 4. ✓
- No new migration; no change to existing DBs → nothing in the plan adds a migration or writes to `~/.flosswing`. ✓

**Placeholder scan:** No TBD/TODO/"handle edge cases". Every code step is complete. Task 2 Step 3 is intentionally "no code" (the fix is Task 3) — this is a deliberate red→green sequencing, not a placeholder.

**Type consistency:** `_ck_suffix(constraint, table) -> str` matches the `Callable[[CheckConstraint, Table], str]` annotation and the `%(ck_suffix)s` token. Comparator helpers (`_introspect`, `_table_struct`, `_diff`, `_named_constraints`, `_balanced_end`, `_norm`, `_build_from_schema_sql`) are all defined in `test_schema_sync.py` and referenced consistently. The five compared aspects (`columns`, `fks`, `indexes`, `checks`, `uniques`) match between `_table_struct` (producer) and `_diff` (consumer).
