# Schema-sync check + constraint-name reconciliation design

## Context

`CLAUDE.md` and `docs/schema.sql` both claim CI verifies that `docs/schema.sql`
(the canonical schema reference) agrees with the Alembic migrations (the source
of truth applied to live DBs). No such check exists in `.github/workflows/ci.yml`.

Adding the check surfaced that the two **do not currently agree**, in two
substantive ways (beyond cosmetic whitespace/comments):

1. **46 CHECK constraints have doubled names** in the migration-built schema.
   Migration `001_initial` declares each check with a plain full-name string
   (`sa.CheckConstraint(..., name="ck_runs_depth")`). Because the metadata has a
   `ck` naming convention (`flosswing/state/db.py`,
   `ck_%(table_name)s_%(constraint_name)s`), SQLAlchemy treats the plain string
   as the `constraint_name` token and wraps it again → `ck_runs_ck_runs_depth`.
   `docs/schema.sql` documents the intended clean names (`ck_runs_depth`). The
   model declares no checks (they live only in migrations).
2. **One foreign key exists only in the migration.** `001` creates
   `fk_findings_dedupe_cluster_id_dedupe_clusters`; `schema.sql` omits it
   (a misleading comment at line 351 stands in its place).

Operator decisions (2026-06-15):
- **CHECK names** → fix the convention so the schema is clean, going forward and
  on fresh builds; do not rebuild live DBs.
- **FK** → the migration is right; keep the FK, document it in `schema.sql`.
- **Comparator** → structural (PRAGMA-based), not text comparison.

### Why no rename migration

Renaming the 46 checks on existing DBs is impractical and risky: SQLite cannot
rename a constraint, and Alembic batch `drop_constraint(name, type_="check")`
fails because SQLite does not expose named CHECK constraints to reflection
(verified: `ValueError: No such constraint: 'ck_runs_ck_runs_depth'`). It would
require full table rebuilds of all 13 affected tables on live data.

Instead, the doubling is fixed at its source — the naming convention. Making the
`ck` convention **idempotent** (strip a redundant `ck_<table>_` prefix if the
provided name already carries it) causes a fresh `alembic upgrade head` to
produce the clean names directly. Verified: with the idempotent convention a
fresh `001` build yields `doubled=0, total_ck=46` (e.g. `ck_runs_depth`). This
needs **no new migration** and touches **no existing data**. Already-migrated
DBs keep their legacy doubled names (the constraints enforce identically); the
schema the migrations build *going forward* (fresh installs, CI) is clean and
matches `schema.sql`, which is exactly what the sync check validates.

## Success criteria

- The `ck` naming convention is idempotent: a fresh `alembic upgrade head`
  produces clean `ck_<table>_<suffix>` names (no doubling) for all 46 checks,
  and any future constraint named with either a bare suffix or a full name
  comes out clean.
- `docs/schema.sql` declares the `fk_findings_dedupe_cluster_id_dedupe_clusters`
  foreign key (replacing the line-351 comment) and still executes as a script.
- `tests/unit/test_schema_sync.py` builds the schema two ways (fresh migrations
  vs `schema.sql`), asserts structural equality, and fails with a readable diff
  on future drift.
- CI alembic round-trip (`upgrade head` → `downgrade base` → `upgrade head`)
  stays green; `ruff`, `mypy --strict flosswing`, `pytest tests/unit` pass.
- No new migration; no change to existing databases.

## Scope

### In scope

- `flosswing/state/db.py`: make the `ck` naming convention idempotent.
- `docs/schema.sql`: add the one FK declaration.
- `tests/unit/test_schema_sync.py`: the structural sync check.

### Out of scope (not now)

- Any new migration / renaming constraints in existing DBs. Legacy DBs keep
  their doubled names; this is accepted (constraints function identically).
- Editing migration `001` (immutable applied history).
- Moving CHECK constraints into the model metadata. The project keeps checks in
  migrations; the sync check (DB-vs-doc) is the guard.
- Any column/type/index change, and the cosmetic `DEFAULT x NOT NULL` vs
  `NOT NULL DEFAULT x` ordering (the structural comparator ignores it).

## Architecture

### Part A1 — idempotent `ck` naming convention (`flosswing/state/db.py`)

Replace the static `ck` template with a custom token function that yields the
bare suffix even when handed a full `ck_<table>_<suffix>` name, so prepending
`ck_<table>_` never doubles:

```python
from collections.abc import Callable
from sqlalchemy.sql.schema import CheckConstraint, Table


def _ck_suffix(constraint: CheckConstraint, table: Table) -> str:
    """Idempotent CHECK-constraint suffix.

    A plain-string constraint name is fed through this convention as the
    ``%(ck_suffix)s`` token. If the author already wrote the full
    ``ck_<table>_<suffix>`` name, strip the redundant ``ck_<table>_`` prefix so
    the template does not double it; a bare suffix passes through unchanged.
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
```

Empirically validated: signature `(constraint, table)` is what SQLAlchemy calls
for a custom convention token; a fresh `001` upgrade under this convention
produced all 46 clean names with zero doubling. Only the `ck` entry changes;
`ix`/`uq`/`fk`/`pk` are untouched. No model-level checks exist, so autogenerate
behavior is unaffected.

### Part A2 — `docs/schema.sql` FK

Replace the comment at `docs/schema.sql:351`
(`-- dedupe_cluster_id FK declared on the cluster side ...`) with the real
constraint, matching the migration, in the `findings` table's constraint list:

```sql
    CONSTRAINT fk_findings_dedupe_cluster_id_dedupe_clusters
        FOREIGN KEY (dedupe_cluster_id) REFERENCES dedupe_clusters(id)
        ON DELETE SET NULL,
```

No migration change — the FK already exists in `001` and live DBs.

### Part B — `tests/unit/test_schema_sync.py` (structural comparator)

Builds two temp SQLite DBs and compares them structurally:

- **DB-A (migrations):** a temp file DB; point `FLOSSWING_DB_URL` at it, reset
  `flosswing.state.session._cached_engine`/`_cached_session_factory`, and call
  `engine()` (auto-runs `alembic upgrade head`).
- **DB-B (doc):** a temp file DB; `sqlite3.connect(...).executescript(schema_sql)`
  where `schema_sql = Path("docs/schema.sql").read_text()`.

For every user table (excluding `sqlite_%` and `alembic_version` on **both**
sides), compare:

| Aspect | Source | Normalization |
|--------|--------|---------------|
| Tables present | `sqlite_master` (type=table) | set equality |
| Columns | `PRAGMA table_info(t)` | tuple `(name, type, notnull, dflt_value, pk)`; per-table set — ignores clause ordering/formatting |
| Foreign keys | `PRAGMA foreign_key_list(t)` | tuple `(table, from, to, on_update, on_delete, match)`; per-table set |
| Indexes | `PRAGMA index_list(t)` + `PRAGMA index_info` | `(name, unique, tuple(columns))`; per-table set; skip auto-indexes (`origin == 'pk'`/`'u'` retained only if named in both — in practice both DBs emit the same named indexes) |
| CHECK constraints | parsed from `sqlite_master.sql` | per-table set of `(name, normalized_expr)`; `normalized_expr` = the `CHECK(...)` body, whitespace-collapsed and lower-cased. Names compared too — this is what the convention fix makes match. |

The comparator returns a structured diff. The test asserts no differences; on
mismatch it prints, per table and per aspect, the symmetric difference so the
failure names exactly what drifted (e.g.
`findings: check names only-in-migrations={...}`).

Lives under `tests/unit/` so the existing `pytest tests/unit` CI step runs it;
no `ci.yml` change required. Also runnable locally.

CHECK extraction: a regex over each table's `CREATE TABLE` text capturing
`CONSTRAINT (<name>) CHECK (<expr>)`. SQLite preserves original DDL text, so
both sides parse with the same regex; only `(name, normalized_expr)` is compared.

## Data flow

```
test_schema_sync:
  DB-A = temp file; FLOSSWING_DB_URL -> reset caches -> engine() upgrades head
  DB-B = temp file; executescript(read docs/schema.sql)
  for each db: introspect -> {table: {columns, fks, indexes, checks}}
  diff(A, B) -> [] (pass) | structured per-table differences (fail w/ message)
```

## Error handling / edge cases

- `schema.sql` must execute cleanly as a script (the test exercises this — a
  syntax error in the doc fails the test, which is desirable).
- `alembic_version` (defined in **both** the migrations and `schema.sql`) and
  `sqlite_%` internal tables are excluded on both sides.
- Auto-created indexes from UNIQUE/PK: both DBs create the same named indexes,
  so they compare equal; unnamed internal autoindexes are excluded.
- Introspection is read-only; temp DBs are removed after.

## Security considerations

- Test + a convention change only; no agent/network surface, no credentials.
- No migration, no table rebuild, no change to existing databases.

## Testing strategy

### Unit (CI)

- `test_schema_sync.py` — the structural comparator (above). Primary deliverable
  and the ongoing guard. After the convention + FK fixes it passes; it would
  fail if a future migration drifts from `schema.sql` (including re-introducing
  doubled names).
- A focused `test_ck_naming_is_idempotent` (in the same file or alongside the
  db tests) asserting that a `CheckConstraint` named with a full
  `ck_<table>_<x>` and one named with bare `<x>` both resolve to
  `ck_<table>_<x>` under the metadata convention.

### Migration round-trip (existing CI step)

- CI's existing step (`upgrade head` → `downgrade base` → `upgrade head`) must
  stay green. The convention change affects only DDL name generation; `001`
  up/down is otherwise unchanged.

## Definition of "done"

- `ck` convention is idempotent; a fresh `upgrade head` yields 46 clean check
  names (0 doubled).
- `schema.sql` declares the FK and still executes as a script.
- `test_schema_sync.py` passes (structural equality) and runs in CI; the
  idempotency unit test passes.
- alembic round-trip green; `ruff` + `mypy --strict` + `pytest tests/unit` green.
- No new migration; no change to existing databases.

## Open questions / decisions — RESOLVED 2026-06-15

1. Reconcile direction → fix the convention so fresh/CI schema is clean; do not
   rebuild live DBs (legacy doubled names retained, harmless).
2. FK → keep it; document in `schema.sql`.
3. Comparator → structural via PRAGMA + parsed checks (ignores formatting and
   clause ordering).
4. Check location → `tests/unit/test_schema_sync.py` (runs in existing CI step).
5. Rename migration → NOT done; superseded by the idempotent-convention fix,
   which is lower-risk and validated to produce clean fresh builds.
