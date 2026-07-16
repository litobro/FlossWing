# TUI live scan status — design

**Date:** 2026-07-15
**Status:** proposed (awaiting operator review)
**Scope:** `flosswing/runpid.py` (new), `flosswing/orchestrator.py`, `flosswing/tui/data.py`, `flosswing/tui/screens/runs.py`, `flosswing/tui/screens/run_detail.py`, plus unit tests.

## Problem

The TUI already lists runs and shows per-stage progress, but it cannot tell whether a
run whose `status == "running"` is *actually alive*. `Run.status` is written `"running"`
at scan start (`orchestrator.run_scan`) and only overwritten at the very end. If the scan
process crashes, is killed, or the machine reboots mid-run, the row stays `"running"`
forever. There is no PID, heartbeat, or `updated_at` column on `runs`, and the TUI never
learns the `run_id` of the child processes it launches (the child generates its own ULID),
so it cannot map its own live processes back to run rows either.

Operator-selected gaps to close:

1. **Stale `running` rows** — reconcile displayed status against real liveness.
2. **At-a-glance live view** — current stage, elapsed, live tokens per running run, in the runs list.
3. **Activity view** — a live sense of "what is it doing right now".
4. **Active-scans surfacing** — make running scans easy to spot.

## Key finding that shapes the design

A running scan is **silent on stdout** until the final summary — `cli.scan` only calls
`click.echo(result.summary)` once, at the end — and no stage emits progress logging (only
`flosswing/index/*` use `logging`, and no handler is configured). Streaming a running
scan's captured output would therefore show an empty pane until completion. The genuinely
informative "what is it doing" signal is entirely **DB-derived**: which stage is active,
Hunt-task status transitions, and `agent_sessions` rows appearing with tokens/outcome as
each stage completes. The activity view is built from that, not from stdout.

## Approach

### 1. Liveness signal: a per-run PID file (operator-approved)

A new stdlib-only module `flosswing/runpid.py` is the single source of truth for the
PID-file path, format, and liveness check. It is deliberately **pure** (no SQLAlchemy, no
Textual) so both the producer (`orchestrator`) and the consumer (`tui/data`) can import it
without a layering violation.

Path: `~/.flosswing/runs/<run_id>/run.pid` — inside the existing per-run scratch dir that
`orchestrator._ensure_run_dir` already creates. This is allowed scratch space (CLAUDE.md:
writes only happen in scratch); it is **not** a schema change and **not** a new dependency.

> **Not daemonization.** The PID file is a liveness marker for a *foreground* process that
> still runs in the foreground and exits normally. It does not background the process, open
> a socket, or phone home. It does not cross the "Not a service" / "no daemon" non-goal in
> ARCHITECTURE.md.

Public functions:

```python
def run_pid_path(run_id: str) -> Path: ...
def write_pid_file(run_id: str) -> None:      # writes {"pid": os.getpid(), "created_at": iso}
def clear_pid_file(run_id: str) -> None:      # unlink, ignore-missing
def read_pid(run_id: str) -> int | None:      # None if absent/corrupt
def run_is_live(run_id: str) -> bool:         # read_pid() and _pid_is_flosswing(pid)
```

Liveness check (`run_is_live`):

- `os.kill(pid, 0)` → `ProcessLookupError` means dead → not live. `PermissionError`
  (process exists but owned by another user) counts as existing.
- PID-reuse guard, strongest first:
  - **Process start time** — the record stores the writer's `/proc/<pid>/stat` start time
    (clock ticks since boot). When both the stored and the live start time are available,
    the comparison is conclusive: it distinguishes a reused PID from the original instance
    even when the two processes share byte-identical argv (which two `flosswing scan <same
    repo>` invocations do).
  - **Command line** — fallback when the start time can't be read (non-Linux, or a legacy
    record predating the field): the live `/proc/<pid>/cmdline` must equal the stored one.
  - When neither guard can be applied, plain liveness is trusted (documented small reuse
    risk off-Linux).

The PID file contains only a PID and an ISO timestamp — no credentials, no repo contents.

### 2. Orchestrator wiring

In `run_scan`, immediately after `_ensure_run_dir(run_id)` and **before** inserting the
`Run` row (so there is never a committed `running` row without a live PID file, which the
TUI would misread as `stale`):

```python
runpid.write_pid_file(run_id)
try:
    with st_session.session_scope() as s:
        s.add(Run(..., status="running", ...))
    ...  # the entire existing Recon -> ... -> Report pipeline body, unchanged
    return ScanResult(...)
finally:
    runpid.clear_pid_file(run_id)
```

- Normal completion **and** a Python exception both clear the file (the `finally`).
- `SIGKILL` / power loss leaves the file behind; the TUI's `os.kill` liveness check then
  reports the run as stale. That is the intended fallback.
- `ScanResult` and all existing behaviour are unchanged. This is the only edit to
  `orchestrator.py`.

### 3. TUI read layer (`tui/data.py`) — display-only reconciliation

The TUI stays **read-only** with respect to the DB (the module's stated invariant). It
*annotates* liveness; it never writes corrected status back (writing would risk racing a
still-alive run).

Classification helper (module-level, uses `runpid`):

```python
def _liveness(run_id: str, status: str) -> str:
    if status != "running":
        return "done"            # terminal (completed | errored)
    if runpid.run_is_live(run_id):
        return "live"
    if runpid.read_pid(run_id) is None:
        return "unknown"         # no usable PID file — can't conclude crashed
    return "stale"               # PID file present but its process is dead
```

The `unknown` state matters: a `running` row with **no** PID file is not proof of a crash.
It may predate liveness tracking (a scan already running across the upgrade), have been
started by another build, or have hit a swallowed write failure. Only a PID file whose
recorded process is actually dead earns `stale` (and the alarming "crashed or killed"
banner). `unknown` gets a neutral marker and an honest "liveness unknown" message.

`RunRow` gains three fields:

- `liveness: str`  — `"live" | "stale" | "unknown" | "done"`.
- `tokens_used: int` — one grouped `sum(input+output)` over `agent_sessions` for all runs
  (same pattern as the existing findings-count group-by; one query, not N).
- `active_stage: str | None` — the name of the currently-active stage for running rows,
  else `None`.

`active_stage` is computed **without per-run N queries**: `list_runs` runs a fixed set of
grouped/`DISTINCT` evidence queries once (which `run_id`s have recon artifacts, symbols,
hunt-task totals/done counts, validations, dedupe clusters, traces), then reuses the
existing `_derive_stages(...)` in Python per run and picks
`next((st.name for st in stages if st.state == "active"), None)`. Terminal rows short-circuit.

`RunProgress` gains `liveness: str` (computed via the same helper) so the detail screen can
render its banner without re-reading the PID file itself.

`_derive_stages` and `run_progress` are otherwise unchanged.

### 4. Runs list (`tui/screens/runs.py`) — enrich in place

Keep the existing 2s poll, the read-only discipline, and the `Text(...)`-wrapping of
untrusted repo-derived strings (repo path, attack class, scope hint).

Columns become: **Run · Repo · Status · Live · Stage · Findings · Tokens · Elapsed · Started**.

- **Live** — a glyph: `●` live (green), `⚠` stale (yellow), `?` unknown (dim), `·` done.
  Rendered as styled `Text` so it can't be interpreted as markup.
- **Stage** — `active_stage or ""` (populated for all running rows regardless of liveness;
  for a stale row it shows the stage the scan was in when it died).
- **Tokens** — `tokens_used` (thousands-separated).
- **Elapsed** — computed in-screen from `started_at` for **live** rows only. A stale
  (crashed) run keeps DB status `running`, so gating on status would grow its elapsed
  unbounded and present a dead scan as if still working; `""` for stale and terminal rows.
  `_format_elapsed` swallows any parse/`TypeError` (e.g. a timezone-naive timestamp) so it
  can never raise into the 2s poll.

A stale row keeps its DB `Status` text (`running`) — truth is not rewritten — but the `⚠`
Live glyph and the elapsed value make it obvious the process is gone.

### 5. Run detail (`tui/screens/run_detail.py`) — liveness banner + activity feed

- **Liveness banner** (new `Static`), shown when `status == "running"`:
  - live → `● live` (optionally with the pid).
  - unknown → `? liveness unknown — no PID file for this run (it may predate liveness
    tracking or was started by another build); the DB still shows 'running'.` No crash
    claim, no "re-run" advice.
  - stale → `⚠ process not found — the scan appears to have stopped (crashed or killed);
    the DB still shows 'running'. Re-run the scan or 'flosswing report <id>' to recover.`
- **Recent activity panel** (new): the tail (last ~5) of `data.list_sessions(run_id)` —
  each line `stage · outcome · in/out tokens · $cost`, with any refusal/error text shown
  scrubbed and rendered literally. This is the DB-derived live feed; it grows as stages
  finish. The full session list stays reachable on `s` (existing `SessionsScreen`).
- **Polling**: stop the 2s poll only when the run reaches a terminal DB status. It does
  **not** stop on `stale`: a stale reading can be false/transient (e.g. a PID-file write
  that hasn't landed, or a momentary read failure), and the interval is armed only in
  `on_mount`, so stopping there would freeze the view for the rest of a still-running scan
  with no way to recover. Continuing to poll lets a false-stale view self-heal; for a
  genuinely crashed run the rows simply never change (cheap, and matches the pre-existing
  behaviour for any running row).

## Data flow

```
scan process                          TUI (read-only)
------------                          ---------------
run_scan(run_id)                      runs list / run detail (poll 2s)
  _ensure_run_dir                       data.list_runs / data.run_progress
  insert Run(status=running)              -> runpid.run_is_live(run_id)
  runpid.write_pid_file  --------------->    reads ~/.flosswing/runs/<id>/run.pid
  ... pipeline ...                           os.kill(pid,0) + /proc cmdline
  update Run(status=final)                 -> "live" | "stale" | "unknown" | "done"
  finally: runpid.clear_pid_file
```

## Error handling

- `runpid` never raises to callers: `clear_pid_file` ignores a missing file; `read_pid`
  returns `None` on absent/corrupt/permission errors; `run_is_live` returns `False` on any
  error. A liveness check must never crash the dashboard or the scan.
- `data.py` continues to catch DB errors and surface guidance (existing `RunsScreen`
  behaviour). Liveness read failures degrade to `"stale"`/`"done"`, never an exception.
- The orchestrator's `finally` clear is best-effort; a failure to unlink is swallowed
  inside `clear_pid_file` (a lingering file only makes a finished run briefly look live
  until its status flips terminal, at which point `_liveness` returns `"done"` regardless).

## Testing

- **`tests/unit/test_runpid.py` (new):** write/read/clear round-trip; `run_is_live` true
  for the current process' pid, false after clear, false for a known-dead pid, false on a
  corrupt file; `/proc` cmdline mismatch → not live (Linux-guarded, skipped elsewhere).
- **`tests/unit/test_tui_data.py` (extend):** `RunRow.liveness` is `"live"` for a running
  run with a live pid, `"stale"` with no/dead pid, `"done"` for terminal status;
  `tokens_used` summed correctly; `active_stage` derived for a mid-pipeline run.
- **`tests/unit/test_tui_screens.py` (extend):** runs list renders the Live/Stage/Tokens/
  Elapsed columns and the `⚠` marker for a stale run; run detail shows the stale banner,
  stops polling when stale, and populates the recent-activity panel.
- **Orchestrator (extend existing test module):** `run_scan` writes the pid file during the
  run and the file is absent afterwards on both the normal path and when a stage raises
  (assert the `finally` clear fires). Uses a temp `HOME` and monkeypatched stage runners.

## Non-functional / rules compliance

- **No tool-contract change**, **no schema change** (PID file is scratch, not DB), **no new
  dependency** (`os`, `json`, `pathlib` only).
- `ruff check` and `mypy --strict` must pass; full type hints on all new code.
- TUI remains **read-only** w.r.t. the state DB.
- Untrusted repo-derived strings rendered via `rich.text.Text` (unchanged discipline).
- No credential ever written to the PID file, DB, logs, or error text.
- Non-goals respected: not a daemon (foreground marker only), no telemetry, no writes to
  the target repo.

## Out of scope (not built here)

- Reaping/rewriting stale rows in the DB (a `flosswing` CLI reaper) — the TUI only
  *displays* staleness. Could be a future CLI subcommand; not part of this change.
- Streaming real per-stage progress logs (would require instrumenting every stage /
  the agent runtime — far beyond the TUI).
- Any change to how child processes are launched or tracked for the quit-guard.

## Implementation order

1. `flosswing/runpid.py` + `tests/unit/test_runpid.py`.
2. `orchestrator.py` wiring + orchestrator pid-lifecycle test.
3. `tui/data.py` (`_liveness`, `RunRow`/`RunProgress` fields, grouped evidence) + data tests.
4. `tui/screens/runs.py` columns/markers/elapsed.
5. `tui/screens/run_detail.py` banner + recent-activity + poll-stop + screen tests.

Verify after each step: `pytest tests/unit`, `ruff check`, `mypy --strict`.
