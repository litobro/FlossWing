# TUI live token & cost ticker — design

**Date:** 2026-07-16
**Status:** implemented (2026-07-17)

> **Post-review adjustment.** Code review found that for the pre-insert stages
> (validate/dedupe/trace), the committed 0-token placeholder `agent_sessions`
> row is visible to the Sessions/activity views for the whole in-flight window,
> producing a contradictory "completed 0/0 tok $0.00" entry beside the live
> line. Fixed by adding a nullable `agent_session_id` column to
> `session_heartbeats` (set by those three stages) and having `list_sessions`
> hide the row whose id matches the live heartbeat's `agent_session_id`. The
> schema block and migration below reflect this added column.
**Scope:** `flosswing/agent/providers/base.py`, `flosswing/agent/providers/anthropic_sdk.py`, `flosswing/agent/runtime.py`, `flosswing/agent/pricing.py` (new), `flosswing/state/heartbeat.py` (new), `flosswing/state/models.py`, `flosswing/state/migrations/versions/002_session_heartbeats.py` (new), `docs/schema.sql`, the 6 stage files (`flosswing/stages/{recon,hunt,validate,gapfill,dedupe,trace}.py`), `flosswing/orchestrator.py`, `flosswing/tui/data.py`, `flosswing/tui/screens/{runs,run_detail,sessions}.py`, plus unit tests.

## Problem

The TUI already shows live token counts and dollar cost while a scan runs: `RunDetailScreen`
polls the state DB every 2s and renders `tokens … cost $…` plus a "recent activity" feed of
completed agent sessions (`flosswing/tui/screens/run_detail.py:83-88, 136-157`), and the runs
list shows a live `Tokens` column (`runs.py:89`). Those figures are summed from the
`agent_sessions` table via `GROUP BY run_id` queries in `flosswing/tui/data.py`.

Operator ask: *"add live token consumption and cost counts to the TUI on a running scan to
make it more interactive."* The existing display has three gaps that make it feel un-live:

1. **Granularity ceiling (primary).** `agent_sessions` rows are written only when a *whole*
   agent session finishes — one Hunt task, the Recon call, one Validate finding. During a
   single long-running session (Recon, or a multi-tool Hunt task running for a minute+) the
   counters sit frozen. There is no sub-session signal anywhere today.
2. **Cost is systematically wrong.** `cost_usd` comes from `_estimate_cost_usd()`, a hardcoded
   placeholder rate table **copy-pasted identically into all six stage files**, that ignores
   cache tokens. Meanwhile the SDK returns an authoritative `ResultMessage.total_cost_usd`
   (confirmed a real field on the pinned `claude_agent_sdk`) that is currently discarded in
   `anthropic_sdk.py`'s `ResultMessage` branch.
3. **Polish gaps.** The runs list has no `Cost` column (only `Tokens`); the full `SessionsScreen`
   is a static snapshot (no polling); there is no rate/velocity readout.

## Key findings that shape the design

- **One session in flight per run.** The scan (`flosswing scan`) is one asyncio process running
  stages strictly sequentially; within Hunt/Validate, tasks/findings are also strictly
  sequential (`validate.py` docstring: *"sequential per-finding execution… no asyncio.gather,
  no Semaphore"*). So **at most one agent session is ever in flight per `run_id`** at any instant.
- **Two clean insertion points already exist.** `run_session()` in `anthropic_sdk.py` already
  accepts `run_id/stage/task_id/finding_id/agent_session_id` as reserved-but-unused params
  ("for per-session telemetry tagging… later milestones"), and its `async for message in
  query(...)` loop already harvests rolling usage from every `AssistantMessage` (via
  `_harvest_usage`) but only keeps it in a local variable.
- **The provider layer has no DB access, by design.** `agent/providers/*` never imports
  SQLAlchemy; stages own the DB writes. Any live-usage plumbing must preserve that boundary.
- **The TUI is a separate process.** `flosswing tui` shares nothing with the scan but the
  filesystem — it only reads the SQLite state DB (`~/.flosswing/state.db`). So sub-session
  usage must be *persisted* by the scan process for the TUI to see it. (Operator decision:
  use a DB row, not a scratch-file heartbeat.)

## Approach (B: separate `session_heartbeats` table)

An ephemeral in-flight ticker lives in its own table, kept strictly separate from the
`agent_sessions` audit log. The provider emits rolling usage through an opaque callback; a
stage-layer helper writes it to the heartbeat row; the row is deleted in the *same
transaction* as the terminal `agent_sessions` write. The TUI's live total is
`SUM(agent_sessions) + heartbeat`, gated on process liveness.

Rejected alternative (A): add a non-terminal `'running'` value to `agent_sessions`' outcome
CHECK and mutate the row in place. It lets existing `SUM()` queries "just work," but (1) it
alters a CHECK constraint through SQLite batch-mode table-recreation — the highest-risk
schema op, which CLAUDE.md explicitly distrusts; (2) it injects non-terminal rows into the
audit log that other consumers (report stage, eval) may assume are terminal; (3) it changes
three stages' write timing and crash semantics. B avoids all three at the cost of a two-source
read query, which is well-contained in `tui/data.py`.

### 1. Provider contract — `on_usage` callback + authoritative cost (`base.py`, `anthropic_sdk.py`, `runtime.py`)

- `base.py`: add a frozen `UsageSnapshot` dataclass (`input_tokens, output_tokens,
  cache_read_tokens, cache_write_tokens, tool_calls_count, cost_usd: float | None`) and
  `OnUsage = Callable[[UsageSnapshot], None]`. Add `cost_usd: float | None = None` as the last
  field of `SessionResult` (default preserves every existing keyword construction). Thread
  `cost_usd` through `_classify()` as a pure pass-through (it does not compute cost). Add
  `on_usage: OnUsage | None = None` as the last param of the `Provider.run_session` Protocol.
- `anthropic_sdk.py`: `run_session(..., on_usage=None)`. In the `AssistantMessage` branch,
  after harvesting usage, build a `UsageSnapshot` and invoke `on_usage`, **throttled to
  ≥250ms** between emits (`time.monotonic`-based). The callback is wrapped in
  `try/except` + log — a telemetry write must never abort an in-flight session. In the
  `ResultMessage` branch, capture `message.total_cost_usd` (authoritative) and always
  force-flush a final `on_usage` regardless of throttle. Return
  `SessionResult(..., cost_usd=authoritative_cost_usd)` — `None` when no `ResultMessage`
  was seen (early budget break, refusal, spurious-exit path).
- `runtime.py`: facade gains `on_usage` and forwards it verbatim; re-export `UsageSnapshot`.
  The `UnimplementedProvider` stub already swallows `**kwargs`, so it needs no change.

This is honestly **per-assistant-turn** granularity — the finest the SDK's message stream
exposes without deeper protocol hooking. It is a large improvement over per-session, and the
term "live" in the UI is scoped accordingly.

### 2. Shared pricing module (`flosswing/agent/pricing.py`, new)

Extract the 6 duplicated `_estimate_cost_usd` defs into one `estimate_cost_usd(*, model,
input_tokens, output_tokens, cache_read_tokens=0, cache_write_tokens=0)`. Same `MODEL_RATES`
table and `(15.0, 75.0)` default for unknown models, **plus** cache-token pricing (reads
≈0.1× input rate, writes ≈1.25× input rate). This is a deliberate, small numeric change to
the fallback estimate — it is only used as the *interim* live figure during a session and as
the *fallback* when `SessionResult.cost_usd is None` (e.g. a future non-Anthropic provider).
The authoritative `total_cost_usd` supersedes it on finalize.

### 3. Heartbeat table (`session_heartbeats`) — schema + migration

New table, PK = `run_id` (exploiting the ≤1-in-flight invariant), FK to `runs` with
`ON DELETE CASCADE`, all constraints explicitly named per the `docs/schema.sql` convention:

```sql
CREATE TABLE session_heartbeats (
    run_id              TEXT NOT NULL,
    stage               TEXT NOT NULL,        -- recon|hunt|validate|gapfill|dedupe|trace
    task_id             TEXT,
    finding_id          TEXT,
    agent_session_id    TEXT,                 -- pre-insert stages' placeholder row id (post-review); NULL otherwise
    model               TEXT NOT NULL,
    input_tokens        INTEGER NOT NULL DEFAULT 0,
    output_tokens       INTEGER NOT NULL DEFAULT 0,
    cache_read_tokens   INTEGER NOT NULL DEFAULT 0,
    cache_write_tokens  INTEGER NOT NULL DEFAULT 0,
    cost_usd            REAL    NOT NULL DEFAULT 0,   -- interim estimate; superseded on finalize
    tool_calls_count    INTEGER NOT NULL DEFAULT 0,
    started_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    CONSTRAINT pk_session_heartbeats PRIMARY KEY (run_id),
    CONSTRAINT fk_session_heartbeats_run_id_runs
        FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE,
    CONSTRAINT ck_session_heartbeats_stage
        CHECK (stage IN ('recon','hunt','validate','gapfill','dedupe','trace')),
    CONSTRAINT ck_session_heartbeats_tokens
        CHECK (input_tokens >= 0 AND output_tokens >= 0
               AND cache_read_tokens >= 0 AND cache_write_tokens >= 0),
    CONSTRAINT ck_session_heartbeats_cost CHECK (cost_usd >= 0),
    CONSTRAINT ck_session_heartbeats_tool_calls CHECK (tool_calls_count >= 0)
);
```

Migration `002_session_heartbeats.py` (`down_revision="001_initial"`) is a hand-written
`op.create_table(...)` mirroring the above; `downgrade()` is `op.drop_table`. This is the
lowest-risk schema op (purely additive CREATE TABLE — no batch recreation). `docs/schema.sql`
is updated in the same commit. Verify with `alembic upgrade head && downgrade base && upgrade
head` and `pytest tests/unit/test_schema_sync.py` (generic structural diff — auto-covers the
new table). No secondary index (PK-only lookups; table cardinality ≤ concurrent scan count).

`state/models.py`: add a `SessionHeartbeat` model mirroring the columns; CHECKs stay
server-side only (matches existing convention).

### 4. Heartbeat writer (`flosswing/state/heartbeat.py`, new)

Stage-layer module (imports SQLAlchemy; never imported by `agent/providers/*`):

- `make_on_usage(*, run_id, stage, model, task_id=None, finding_id=None) -> OnUsage` — returns a
  callback that upserts the single `session_heartbeats` row (insert-if-absent, else update),
  resolving `cost = snap.cost_usd if not None else estimate_cost_usd(...)`.
- `clear(s, run_id)` — DELETE inside an **already-open** session; called from the same
  `session_scope()` block that writes the terminal `agent_sessions` row.
- `clear_run(run_id)` — standalone, own-transaction, best-effort, **never raises** (mirrors
  `runpid.py` discipline); called from `orchestrator`'s `finally`.

### 5. Stage wiring (6 files) — minimal, uniform edits

Per stage, keeping the existing `agent_sessions` write timing exactly as-is:

1. Delete the local `_estimate_cost_usd`; import the shared one and `state.heartbeat`.
2. Before `run_session(...)`: build `on_usage = heartbeat.make_on_usage(run_id=…, stage=…,
   model=cfg.model, task_id=…, finding_id=…)`; pass `on_usage=on_usage` into the call.
3. Cost: `cost = result.cost_usd if result.cost_usd is not None else estimate_cost_usd(...)`.
4. Add `heartbeat.clear(s, run_id)` **inside the existing `session_scope()` block** that writes
   the terminal `agent_sessions` row — this is the entire double-counting fix.

Placement: recon/hunt/gapfill (insert-after) — inside the single `s.add(AgentSession(...))`
block. validate/dedupe (pre-insert + finalize UPDATE) — inside the final UPDATE block. trace —
in **both** its normal-path UPDATE and its per-finding crash-recovery `except` UPDATE, so the
row is cleared on every exit path. dedupe Pass 1 (deterministic) never calls `run_session` and
is unaffected.

### 6. Orchestrator hygiene (`orchestrator.py`)

In the existing outer `finally`, add unconditional `heartbeat.clear_run(run_id)` alongside the
`runpid.clear_pid_file` call — sweeps an orphan left by any Python-level crash mid-session.
(A hard `SIGKILL` is handled by the TUI liveness gate below, not by cleanup.)

### 7. TUI read + display (`tui/data.py`, 3 screens)

- `data.py`: add `POLL_INTERVAL_SECONDS = 1.0` (single source of truth, replaces the three
  hardcoded `2.0`s). Add `live_session(run_id) -> LiveSessionRow | None` that reads the
  heartbeat row and returns `None` unless `_liveness(run_id, status) == "live"` — the
  orphan-safety / anti-double-count backstop, reusing existing PID liveness.
  `run_progress().tokens_used`/`.cost_usd` become live-inclusive (`committed + heartbeat if
  live`). New `RunProgress` fields: `tokens_per_sec`, `cost_per_min` (whole-run wall-clock
  average from `Run.started_at`), and `projected_cost_usd` (linear extrapolation from Hunt
  completion fraction: `cost_total * hunt_total / hunt_done` when `hunt_done > 0`, else `None`;
  a rough estimate, shown as a dash before Hunt starts and labeled an estimate). `RunRow`
  (used by `list_runs`) gains `cost_usd: float`, computed live-inclusive via one grouped query
  (mirroring the existing `token_sums` pattern — one query for all runs).
- `runs.py`: add a `Cost` column after `Tokens` (`f"${r.cost_usd:.2f}"`); poll interval →
  `POLL_INTERVAL_SECONDS`.
- `run_detail.py`: poll interval → constant; prepend a `▶ LIVE …` line to the activity feed
  from `live_session`; optionally append `tok/s` and `$/min` to the meta line.
- `sessions.py`: add a `set_interval(POLL_INTERVAL_SECONDS, refresh_rows)` (currently a
  one-shot mount), refactoring population into `refresh_rows`; append a distinctly-styled
  synthetic `● live` row from `live_session` (display-only — never written to the DB, so the
  frozen `ck_agent_sessions_outcome` vocabulary is untouched).

## Double-counting avoidance (the load-bearing invariant)

The heartbeat DELETE and the terminal `agent_sessions` write **commit in the same SQLite
transaction**. WAL-mode readers (the separate TUI process) see a transaction atomically, so
there are only two observable states, never an in-between:

- **Before finalize:** heartbeat present (ticking), no new `agent_sessions` row → TUI shows
  `committed + heartbeat`.
- **After finalize (atomic):** heartbeat gone, `agent_sessions` row reflects final numbers →
  TUI shows `committed` alone, now including this session.

No moment shows both (double count) or neither (undercount) for a clean finalize. The only
residual case — a `SIGKILL` mid-write before finalize — is handled by the **liveness gate**:
`live_session()` adds the heartbeat's numbers only when the run's PID-derived liveness is
`"live"`, so a dead process's orphan reads as `stale`/`unknown` and is ignored. The
orchestrator `finally` sweep additionally clears orphans from Python-level crashes.

## Test plan

- `test_providers_base.py`: `_classify(..., cost_usd=…)` passes through in all branches;
  `SessionResult` defaults `cost_usd=None`.
- **New** `test_providers_anthropic_run_session.py` (fills a real coverage gap — no test mocks
  `claude_agent_sdk.query` today): async-generator monkeypatch of `query`; assert `on_usage`
  fires per `AssistantMessage`; two emits <250ms collapse to one (monkeypatch `time.monotonic`);
  `ResultMessage` force-flushes; `SessionResult.cost_usd == total_cost_usd` when present, `None`
  when absent; `on_usage=None` is a no-op.
- **New** `test_state_heartbeat.py`: upsert creates then updates one PK row (no dup-PK);
  `clear` in-session; `clear_run` never raises when empty; `ON DELETE CASCADE` on parent delete.
- `test_schema_sync.py`: no edit — generic diff auto-covers the new table. Plus the CLAUDE.md
  reversibility gate (`upgrade/downgrade/upgrade`).
- 6 stage test files (happy **and** refused paths, per the "every stage has happy + refused"
  rule): assert `run_session` called with `on_usage` not None; after any outcome, no
  `session_heartbeats` row remains; two cost sub-cases (authoritative `cost_usd` used verbatim;
  `None` → fallback estimate). trace also exercises the crash-recovery clear path.
- `test_tui_data.py`: heartbeat included only when liveness `"live"`, excluded otherwise (core
  anti-orphan test); rate/projection math incl. zero-denominator `None`; `list_runs` `cost_usd`.
- `test_tui_screens.py`: `RunsScreen` Cost column; `SessionsScreen` now has a `Timer` and renders
  the live row; `run_detail` activity shows the live line.
- `test_orchestrator.py`: a stage-raises test asserts no heartbeat row remains after `run_scan`
  propagates (exercises the `finally` sweep).
- `FLOSSWING_INTEGRATION=1` smoke (not CI): confirm a real `ResultMessage.total_cost_usd` lands
  and roughly matches published pricing; sanity-check DB read/write volume under the faster poll
  over a multi-minute Hunt.

## Build order

Schema + migration → `base.py`/`anthropic_sdk.py`/`runtime.py` (provider contract) → `pricing.py`
→ `state/heartbeat.py` + `models.py` → 6 stage files → `orchestrator.py` → `tui/data.py` →
3 screen files. Each step keeps `ruff check .` / `mypy --strict flosswing` / `pytest tests/unit`
green.

## Risks / CLAUDE.md interactions

- **Schema change, hard-gated.** Hand-authored migration (not autogenerated), shown as a diff
  and approved before commit; `docs/schema.sql` changed in the same commit; `render_as_batch`
  and named constraints already satisfied. CREATE TABLE is the safest schema op.
- **Not a tool-contract change.** `docs/tool-contracts.md` governs the agent-facing `@tool`
  surface; it never references `agent_sessions`/`SessionResult`/`run_session`. The `Provider`
  Protocol and `SessionResult` changes are purely additive (new optional kwarg / defaulted
  field) — no caller breaks, including the unimplemented provider stubs.
- **Provider DB-agnosticism preserved.** `agent/providers/*` gains no SQLAlchemy import;
  `state/heartbeat.py` is imported only by stages/orchestrator.
- **Write/read amplification.** 250ms provider throttle + ~1s TUI poll write/read the SQLite
  file more than today (was 2s poll, zero in-session writes). WAL + `synchronous=NORMAL` should
  absorb a single local writer; confirm under integration before merge.
- **Cache-token estimate behavior change.** Fallback now folds cache tokens into the input rate
  (previously ignored). Low-risk (fallback path only), flagged explicitly.
- **`projected_cost_usd` heuristic** (Hunt-fraction extrapolation) and **poll interval 1.0s**
  are judgment calls within the operator's ask — easy to change (both are single constants).
- **Non-goals check.** All data stays in the local `state.db`, read only by the local TUI —
  no telemetry, no daemon, no auto-anything. Nothing here is a v2-marked feature.
- **Parallel worktree.** `.claude/worktrees/ollama-provider/` holds separate copies of the 6
  stage files; whoever lands that branch rebases through this change. Flagged, not fixed here.
