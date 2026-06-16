# Schema-sync check + constraint-name reconciliation design

## Context

`CLAUDE.md` and `docs/schema.sql` both claim CI verifies that `docs/schema.sql`
(the canonical schema reference) agrees with the Alembic migrations (the source
of truth applied to live DBs). No such check exists in `.github/workflows/ci.yml`.

Adding the check surfaced that the two **do not currently agree**, in two
substantive ways (beyond cosmetic whitespace/comments):

1. **46 CHECK constraints have doubled names** in the migration-built schema.
   Migration `001_initial` declares each check with its full name
   (`sa.CheckConstraint(..., name="ck_runs_depth")`), and the `ck` naming
   convention (`flosswing/state/db.py:34`, `ck_%(table_name)s_%(constraint_name)s`)
   wraps it again → `ck_runs_ck_runs_depth`. `docs/schema.sql` documents the
   intended clean names (`ck_runs_depth`). The model declares no checks (they
   live only in migrations).
2. **One foreign key exists only in the migration.** `001` creates
   `fk_findings_dedupe_cluster_id_dedupe_clusters`; `schema.sql` omits it
   (a misleading comment at line 351 stands in its place).

Operator decisions (2026-06-15):
- **CHECK names** → the doc is right; fix the live schema to the clean names.
- **FK** → the migration is right; keep the FK, document it in `schema.sql`.
- **Comparator** → structural (PRAGMA-based), not text comparison.

## Success criteria

- A new migration renames all 46 doubled CHECK constraints to their clean
  `ck_<table>_<suffix>` names. A fresh `alembic upgrade head` and an upgrade of
  an existing `001`-only DB both converge to the clean names.
- `docs/schema.sql` declares the `fk_findings_dedupe_cluster_id_dedupe_clusters`
  foreign key (replacing the line-351 comment).
- `tests/unit/test_schema_sync.py` builds the schema two ways (migrations vs
  `schema.sql`) and asserts structural equality; it passes after the fixes and
  fails with a readable diff on future drift.
- CI alembic round-trip (`upgrade head` → `downgrade base` → `upgrade head`)
  stays green; `ruff`, `mypy --strict flosswing`, `pytest tests/unit` pass.
- Batch rebuild preserves existing row data.

## Scope

### In scope

- New migration `002_normalize_check_constraint_names.py` (rename only).
- `docs/schema.sql`: add the one FK declaration.
- `tests/unit/test_schema_sync.py`: the structural sync check.

### Out of scope (not now)

- Moving CHECK constraints into the model metadata (`db.py`/`models.py`). The
  project deliberately keeps checks in migrations; doing so would change
  autogenerate behavior. The sync check (DB-vs-doc) is the guard instead.
- Editing migration `001` (immutable applied history).
- Any column/type/index change. This is a name-only + doc-only reconciliation.
- Fixing the cosmetic `DEFAULT x NOT NULL` vs `NOT NULL DEFAULT x` ordering —
  the structural comparator ignores it.

## Architecture

### Part A1 — migration `002` (constraint rename)

`flosswing/state/migrations/versions/002_normalize_check_constraint_names.py`,
`down_revision = "001_initial"`. For each of the 13 affected tables, a
`with op.batch_alter_table(<table>) as batch:` block drops each doubled-name
check and recreates it with the clean name and the **identical expression**
copied from `001`. `render_as_batch` is already enforced in `env.py`.

Naming caveat to verify during implementation: `create_check_constraint`'s name
argument is fed through the same `ck` naming convention that doubled the names
in `001`. The implementer MUST confirm (via the round-trip + sync test) which
form yields the clean `ck_<table>_<suffix>` name — passing the bare suffix
(e.g. `"depth"`) if the convention is applied, or the full clean name if it is
not — and use whichever produces the correct final name. The sync test fails
loudly if the resulting name is wrong, so this is self-checking.

`downgrade()` reverses each rename (clean → doubled) so the alembic round-trip
passes.

The full authoritative mapping (doubled → clean), grouped by table:

```
agent_sessions:  stage, outcome, tokens, cost
call_sites:      line
dedupe_clusters: member_count
entry_points:    kind, attacker_input, line
finding_links:   relationship, distinct
findings:        severity, confidence, status, dedupe_role, reachable, lines,
                 poc_result_valid, confirmed_evidence
hunt_tasks:      priority, source, status, findings_count
recon_artifacts: languages_valid, builds_valid, trust_valid, subsystems_valid
runs:            depth, status, budget, config_json_valid
sandbox_runs:    language, network, backend, files_valid, args_valid, env_valid,
                 build_result_valid, run_result_valid
symbols:         kind, lines
traces:          reachable, call_chain_valid, reachable_has_entry_point
validations:     verdict, evidence_valid
```

(doubled = `ck_<table>_ck_<table>_<suffix>`, clean = `ck_<table>_<suffix>`).
Each clean name and its CHECK expression are taken verbatim from `001`; the
expression text is unchanged — only the constraint name changes.

### Part A2 — `docs/schema.sql` FK

Replace the comment at `docs/schema.sql:351`
(`-- dedupe_cluster_id FK declared on the cluster side ...`) with the real
constraint, matching the migration:

```sql
    CONSTRAINT fk_findings_dedupe_cluster_id_dedupe_clusters
        FOREIGN KEY (dedupe_cluster_id) REFERENCES dedupe_clusters(id)
        ON DELETE SET NULL,
```

placed in the `findings` table's constraint list consistent with surrounding
style. No migration change — the FK already exists in `001` and live DBs.

### Part B — `tests/unit/test_schema_sync.py` (structural comparator)

Builds two temp SQLite DBs and compares them structurally:

- **DB-A (migrations):** a temp file DB; run `alembic upgrade head`
  (programmatically, or rely on the state-session auto-upgrade by pointing
  `FLOSSWING_DB_URL` at a fresh temp file and initialising the engine).
- **DB-B (doc):** a temp file DB; execute `docs/schema.sql` via
  `sqlite3.connect(...).executescript(schema_sql)`.

For every user table (excluding `sqlite_%` and `alembic_version`), compare:

| Aspect | Source | Normalization |
|--------|--------|---------------|
| Tables present | `sqlite_master` (type=table) | set equality |
| Columns | `PRAGMA table_info(t)` | tuple `(name, type, notnull, dflt_value, pk)`; order-independent set per table — ignores clause ordering/formatting |
| Foreign keys | `PRAGMA foreign_key_list(t)` | tuple `(table, from, to, on_update, on_delete, match)`; set per table |
| Indexes | `PRAGMA index_list(t)` + `PRAGMA index_info` | `(name, unique, tuple(columns))`; set; exclude auto-indexes (`origin != 'c'` skipped only for unnamed) |
| CHECK constraints | parsed from `sqlite_master.sql` | set of `(name, normalized_expr)` per table, where `normalized_expr` = the `CHECK(...)` body with whitespace collapsed and lower-cased; names compared too (this is what the rename fixes) |

The comparator yields a structured diff. The test asserts no differences; on
mismatch it prints, per table, the symmetric difference of each aspect so the
failure names exactly what drifted (e.g. `findings: check names only-in-migrations={...}`).

Lives under `tests/unit/` so the existing `pytest tests/unit` CI step runs it;
no `ci.yml` change required. Also runnable locally.

CHECK-constraint extraction: a small regex over each table's `CREATE TABLE`
text capturing `CONSTRAINT (<name>) CHECK (<expr>)`. SQLite preserves the
original DDL text, so both sides parse with the same regex; only the captured
name + whitespace-normalized expr are compared.

## Data flow

```
test_schema_sync:
  DB-A  = temp file; FLOSSWING_DB_URL -> engine() auto-upgrades to head
  DB-B  = temp file; executescript(read docs/schema.sql)
  for each db: introspect -> {table: {columns, fks, indexes, checks}}
  diff(A, B) -> [] (pass) | structured per-table differences (fail w/ message)
```

## Error handling / edge cases

- `schema.sql` must execute cleanly as a script (the test exercises this — a
  syntax error in the doc fails the test, which is desirable).
- `alembic_version` (defined in **both** the migrations and `schema.sql`) and
  `sqlite_%` internal tables are excluded from the comparison on both sides.
- Auto-created indexes (from UNIQUE/PK) are excluded from the index set or
  compared consistently on both sides (both DBs create them, so they match).
- The structural introspection is read-only; temp DBs are cleaned up.

## Security considerations

- Test-only + migration; no agent/network surface. No credentials involved.
- The migration rebuilds tables via batch copy; row data is preserved. The
  migration is verified against a **copy** of any real `state.db`, never the
  original, before relying on it.

## Testing strategy

### Unit (CI)

- `test_schema_sync.py` — the structural comparator (above). The primary
  deliverable and the ongoing guard.

### Migration verification (manual + CI alembic step)

- CI's existing step runs `upgrade head` → `downgrade base` → `upgrade head`
  against a temp SQLite DB. `002`'s `upgrade`/`downgrade` must both succeed.
- Locally: apply `002` to a **copy** of `~/.flosswing/state.db` and confirm
  row counts in affected tables are unchanged and constraint names are clean.

## Definition of "done"

- `002` renames all 46 doubled checks; fresh + existing upgrades converge to
  clean names.
- `schema.sql` declares the FK; `schema.sql` still executes as a script.
- `test_schema_sync.py` passes (structural equality) and is in CI.
- alembic round-trip green; `ruff` + `mypy --strict` + `pytest tests/unit` green.
- Migration diff shown for operator approval before commit (hand-written, but
  the migration-review rule in `CLAUDE.md` applies).

## Open questions / decisions — RESOLVED 2026-06-15

1. Reconcile direction → fix live schema to match the doc (clean names).
2. FK → keep it; document in `schema.sql`.
3. Comparator → structural via PRAGMA + parsed checks (ignores formatting and
   clause ordering).
4. Check location → `tests/unit/test_schema_sync.py` (runs in existing CI step).
