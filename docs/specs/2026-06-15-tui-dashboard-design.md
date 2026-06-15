# TUI dashboard design (`flosswing tui`)

**Status:** drafted — pending operator review
**Date:** 2026-06-15
**Replaces:** —
**Supersedes:** —
**Authors:** thomas + claude

---

## Context

After a scan, the operator inspects results either through `flosswing
report <run_id>` (which renders files to disk) or by opening
`~/.flosswing/state.db` in `sqlite3` directly. There is no interactive,
human-facing way to:

- see all runs at a glance and pick one,
- watch a scan's progress while it runs,
- drill from a run into its findings and into a single finding's
  PoC / validation / trace detail,
- kick off a new scan against a repo without dropping back to the shell.

This spec defines `flosswing tui`: an interactive, terminal-based
dashboard over the existing state DB and CLI. It adds no new pipeline
behavior and no new persisted state — it is a read-only viewer over
`state.db` plus a launcher that spawns the existing `flosswing scan` /
`flosswing report` commands as child processes.

## Scope decision — relationship to non-goals

`ARCHITECTURE.md` lists as a **hard non-goal**: *"Not a service. No
daemon, no web UI, no multi-tenant anything. Local CLI only."* and
defers *"Web UI / local server mode"* to v2.

The operator (the project owner) has explicitly greenlit this work as an
**in-scope CLI enhancement**, on the following understanding, which this
design is bound by:

- It is a **terminal UI**, not a web UI. No HTTP server, no browser, no
  network listener of any kind.
- It is **foreground and single-user**. It runs only while the operator
  has it open. There is **no daemon** and no background process that
  outlives the operator's session beyond a scan child the operator
  themselves launched (see § Scan launching).
- It is **read-only against `state.db`**. The TUI never writes, updates,
  or deletes a row. The only mutations to FlossWing state happen inside
  the `flosswing scan` child process, exactly as if the operator had
  typed the command.
- No telemetry, no phone-home — consistent with the existing non-goals.

This document does **not** edit `ARCHITECTURE.md`. If the operator wants
the non-goals text amended to mention the TUI explicitly, that is a
separate operator-curated change.

## Goals

1. List all runs, newest first, with status, target repo, finding count,
   and a live indicator for running scans.
2. Drill into a run: pipeline stage progress, budget usage, Hunt task
   table, and finding count — refreshed live while the run is `running`.
3. Drill into findings: a per-run findings list and a per-finding detail
   view (description, PoC code + result, validation verdict, trace call
   chain, suggested fix).
4. Review agent sessions for a run (model, tokens, cost, outcome), with
   refusals surfaced explicitly.
5. Launch a new scan against a chosen repo path with the common options,
   then land on its live run-detail screen.
6. Re-render a report for an existing run from within the TUI.

## Non-goals (this milestone)

- No editing of findings, runs, or any state (read-only viewer).
- No in-process execution of the pipeline (always a child process).
- No full parity with every `flosswing scan` flag in the new-scan form
  (common options only; power users use the CLI directly).
- No SARIF-specific UI, no diff/compare-runs view (`flosswing diff` is a
  v2 non-goal).
- No mouse-driven design requirement; keyboard-first. (Textual provides
  mouse support for free; we do not rely on it.)

## Dependency

Adds **`textual`** to `[project.dependencies]` in `pyproject.toml`
(pulls in `rich` transitively). Operator-approved 2026-06-15. Textual is
chosen over hand-rolled `curses` / `rich`-only because the dashboard is
inherently multi-screen with live updates, tables, and key bindings —
exactly Textual's wheelhouse — and because `run_test()` gives us a
headless pilot for unit-testable screens.

`mypy --strict` config: add `textual` / `textual.*` (and `rich.*` if
needed) to the existing `[[tool.mypy.overrides]]` `ignore_missing_imports`
block only if stubs prove insufficient. Prefer real types where Textual
ships them (it ships `py.typed`).

## Architecture

New package `flosswing/tui/`. One responsibility per module:

```
flosswing/tui/
  __init__.py
  app.py              # Textual App: screen stack, global keys, refresh timer
  data.py             # read-only query layer -> plain dataclasses (no ORM leak)
  launcher.py         # spawn/track `flosswing scan` & `flosswing report` children
  screens/
    __init__.py
    runs.py           # Runs list screen
    run_detail.py     # Stage progress + Hunt task table + budget
    findings.py       # Findings list for a run
    finding_detail.py # One finding: PoC / validation / trace / fix
    sessions.py       # Agent-session table for a run
    new_scan.py       # New-scan form (modal screen)
```

CLI wiring: add a `tui` command to `flosswing/cli.py` as a sibling of
`scan` / `report` / `eval`. The command body **lazy-imports**
`flosswing.tui.app` inside the callback (mirroring how `report`
lazy-imports the state layer) so that `textual` and the TUI import graph
stay off the startup path of `scan`/`report`/`eval`.

### Layer boundaries

- **`data.py`** is the only module that touches SQLAlchemy. It opens
  read-only sessions via the existing `flosswing.state.session`
  helpers and returns **plain, immutable dataclasses** (or reuses the
  pydantic `ReportV1` from `stages/report.py`). No `Session` or ORM
  entity escapes this module — screens depend on dataclasses only. This
  keeps screens trivially testable and prevents detached-instance bugs.
- **`launcher.py`** is the only module that spawns subprocesses. It
  builds argv for `flosswing scan` / `flosswing report`, starts the
  child, and exposes its liveness + exit status. It does not touch the DB.
- **`screens/*`** are pure view + key handling. They call `data.py` to
  read and `launcher.py` to spawn. They hold no business logic beyond
  formatting.
- **`app.py`** owns the screen stack, global key bindings (`q` to quit
  with the live-scan guard, `esc` to pop a screen), and the single
  shared refresh timer.

## Data access (`data.py`)

Functions (names indicative; all read-only):

- `list_runs() -> list[RunRow]` — all runs ordered by `started_at`
  descending. `RunRow` carries `id`, `target_repo_path`, `status`,
  `started_at`, `finished_at`, `findings_count` (computed), and a
  `short_id` for display.
- `run_progress(run_id) -> RunProgress` — per-stage state derived from
  the rows that exist:
  - stage presence/derivation: Recon done iff a `recon_artifacts` row
    exists for the run; symbol index done iff `symbols` rows exist; Hunt
    progress from `hunt_tasks` (`done`/`total` by `status`); Validate
    from `validations` count vs findings; Dedupe from `dedupe_clusters`;
    Trace from `traces`; Report from presence of output (best-effort —
    DB has no report row, so Report shows "rendered" only if we can
    confirm an output dir, otherwise "n/a").
  - budget: `runs.budget_used` / `runs.budget_total`.
  - counts: findings total, by severity, by status.
  - Hunt task list: `(attack_class, scope_hint, status, findings_count)`.
- `load_report(run_id) -> ReportV1` — **reuse**
  `flosswing.stages.report.load_report`. This already assembles findings
  with their validations, traces, and dedupe clusters in display order.
  Used by the findings and finding-detail screens.
- `list_sessions(run_id) -> list[SessionRow]` — agent sessions: stage,
  model, input/output tokens, cost, duration, outcome, and (scrubbed)
  refusal/error text.

All free-text fields that originate from the target repo or agent output
(titles, descriptions, rationales, refusal text, scope hints) are passed
through `flosswing.errors.scrub()` **in `data.py`** before leaving the
layer, so no screen can accidentally render an unscrubbed credential-like
string. (Defensive: the DB should already be clean, but the threat model
treats agent/repo text as untrusted.)

### Stage-progress derivation note

The state DB has no explicit "current stage" column; stages are inferred
from which rows exist. This inference is the one piece of non-trivial
logic in `data.py` and gets its own focused unit tests. Where a stage's
state is genuinely unknowable from the DB (e.g. whether Report files were
written), the TUI shows a neutral state rather than guessing.

## Scan launching (`launcher.py` + `new_scan.py`)

**Mechanism.** Subprocess, not in-process. The TUI spawns
`flosswing scan <path> [--depth …] [--format …] [--hunt-token-budget …]`
as a child process using the same Python entry point. The TUI does
**not** import or call `orchestrator.run_scan` in its own event loop —
this keeps the agent/SDK/sandbox import graph and any pipeline
crash/refusal out of the UI process.

**Progress source.** Once spawned, progress is read from `state.db` by
the refresh timer (§ Refresh), not by parsing the child's stdout. The
child's stdout/stderr is redirected to
`~/.flosswing/runs/<run_id>/tui-scan.log` for post-hoc inspection. Note:
the `run_id` is generated by the scan process itself, so the TUI
correlates the new run by polling `list_runs()` for a new `running` row
whose `target_repo_path` matches the launched path and whose
`started_at` is after launch time; until that row appears, the run-detail
screen shows a "starting…" state.

**New-scan form (`new_scan.py`, modal screen).** Fields:

- repo path (text input; defaults to `cwd`; validated to be an existing
  directory before the scan is allowed — reuses the same
  `exists/dir_okay` constraints `flosswing scan` enforces).
- depth (choice: `standard` / `deep`; default `standard`).
- output format (multi-select among `md` / `json` / `sarif`; default
  `md,json`).
- token-budget override (optional integer; maps to
  `--hunt-token-budget`, the most impactful single budget knob).

On submit: validate, spawn via `launcher.py`, close the modal, push the
run-detail screen in "starting…" state.

**Lifecycle / quit guard.** The TUI tracks child processes it spawned. On
quit (`q`) **while a spawned scan child is still alive**, show a
confirmation modal with three choices:

- **Detach** — leave the scan running; the TUI exits and the scan
  continues to completion (visible on next launch). This is possible
  because progress lives in `state.db`, not in the TUI.
- **Kill** — terminate the scan child (SIGTERM, then SIGKILL after a
  short grace period) before exiting.
- **Cancel** — stay in the TUI.

If no spawned child is alive, `q` quits immediately. The TUI never kills
a scan it did not spawn (a scan started from another terminal is treated
as read-only progress, never managed).

## Refresh (`app.py`)

A single `set_interval` timer (default ~2s; constant, not configurable in
this milestone) drives live updates. On each tick:

- If the visible screen concerns a run whose status is `running` (or a
  newly-launched scan still resolving its `run_id`), re-query the
  relevant `data.py` function and re-render.
- If the visible screen concerns only completed/static data, the tick is
  a no-op (no query). This avoids pointless DB reads when nothing can
  change.

Re-render is idempotent: each tick rebuilds the view model from a fresh
read; no incremental diffing state is kept in the screen.

## Screens (behavior summary)

- **Runs list** (`runs.py`, initial screen): table of runs. `enter`
  opens run-detail; `n` opens the new-scan modal; `r` re-renders the
  report for the selected run (spawns `flosswing report <id>` via
  `launcher.py`); `q` quits (with guard). Live badge on `running` rows.
- **Run detail** (`run_detail.py`): stage strip
  (Recon · Index · Hunt · Validate · Gapfill · Dedupe · Trace · Report)
  with per-stage status glyphs, budget bar, finding count, Hunt task
  table. `f` → findings list; `s` → sessions; `esc` → back.
- **Findings list** (`findings.py`): findings for the run with severity /
  confidence / status / reachability badges (from `load_report`).
  `enter` → finding detail; `esc` → back.
- **Finding detail** (`finding_detail.py`): title, location, badges,
  description, PoC code + run result, validation verdict + rationale,
  trace reachability + call chain, suggested fix. Read-only scrollable.
  `esc` → back.
- **Sessions** (`sessions.py`): agent-session table for the run. Refusals
  and errors shown as distinct, visible states (not hidden). `esc` →
  back.
- **New scan** (`new_scan.py`, modal): the form described above.

## Error handling

- **Missing / empty `state.db`** → Runs list shows a friendly empty state
  ("No runs yet — press `n` to start a scan."), never a traceback.
- **Stale schema** → the existing session layer refuses to auto-migrate
  an existing DB with stale schema; the TUI catches that condition and
  shows the layer's "run `alembic upgrade`" guidance verbatim, then exits
  cleanly.
- **Child spawn failure** (e.g. bad path, missing `flosswing` on PATH) →
  inline error in the modal / a notification; the TUI stays open.
- **Report re-render failure** → notification with the scrubbed error;
  TUI stays open. (Re-uses the same scrub discipline as
  `cli.py report`.)
- All DB free-text is scrubbed in `data.py` (above). The TUI never
  prints environment credential values; it does not read credentials at
  all (it spawns children that inherit the environment, exactly as the
  shell would).

## Testing

- **`data.py`** is the testable core. Unit tests seed an in-memory DB
  (`FLOSSWING_DB_URL=sqlite:///:memory:` via the existing session
  helpers / fixtures), insert representative rows, and assert:
  - `list_runs` ordering and finding-count computation,
  - `run_progress` stage derivation across partial-pipeline states
    (Recon-only, mid-Hunt, fully complete, refused tasks),
  - scrubbing is applied to free-text fields,
  - `list_sessions` surfaces refusals/errors.
- **`launcher.py`** unit-tested with the child command mocked
  (`subprocess`/`asyncio` patched): assert correct argv is built from
  form inputs, log path is correct, liveness/exit reported correctly,
  and kill escalates SIGTERM→SIGKILL. No real scan is run.
- **Screens** get light smoke tests via Textual's `run_test()` pilot:
  mount each screen against seeded `data.py` results and assert the key
  widgets exist and render expected text; exercise primary key bindings
  (e.g. `enter` pushes the next screen). These are unit tests, not
  integration — no API, no real pipeline.
- **No eval impact.** The pipeline is unchanged, so `flosswing eval`
  behavior and corpus scoring are unaffected; no eval run is required to
  merge, though the existing suite must stay green.
- `ruff check` and `mypy --strict` must pass over the new package.

## Open questions

None blocking. Defaults chosen above for: refresh interval (2s, fixed),
new-scan option set (path + depth + format + hunt-token-budget),
quit-guard (detach/kill/cancel), and report Report-stage display
("rendered"/"n/a" best-effort).

## Out of scope / future

- Configurable refresh interval.
- Compare two runs (blocked on `flosswing diff`, a v2 non-goal).
- Full scan-flag parity in the form.
- Cancelling individual Hunt tasks (would require pipeline changes —
  out of scope and adjacent to "not a coding agent / read-only" stance).
