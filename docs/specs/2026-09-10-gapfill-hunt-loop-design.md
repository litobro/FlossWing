# Gapfill → Hunt loop (auto-re-pass)

> Status: approved (operator, 2026-09-10). Realizes the Gapfill→Hunt feedback
> arrow already drawn in `ARCHITECTURE.md` § Pipeline stages.

## Problem

Gapfill spends a full agent session identifying under-investigated subsystems
and queues new `hunt_tasks` rows (`source='gapfill'`), but nothing consumes
them within the run. The orchestrator runs Hunt exactly once, *before*
Gapfill, so Gapfill's queued tasks sit at `status='pending'` until a manual
re-invocation that never comes in the common case. Every token Gapfill spends
produces zero findings. This is the documented "auto-re-pass is a follow-on
milestone" gap in `ARCHITECTURE.md` § Stage 4.

## Goal

Close the loop: after Gapfill queues tasks, run one bounded second Hunt pass
over them, and validate/dedupe/trace the resulting findings the same way as
first-pass findings.

## Non-goals

- **No recursion.** Exactly one Gapfill and one second Hunt pass per run,
  matching "Gapfill runs once per run; no recursive expansion in v1".
- **No new stage, no new tables, no tool-contract changes.**
- **No changes to any stage's `.run()` internals.** `hunt_stage.run()`
  already selects only `status='pending'` tasks; the change is orchestration
  only.

## Design

### Stage reordering

Change the orchestrator sequence from:

```
Recon → Index → Hunt → Validate → Dedupe → Gapfill → Trace → Report
```

to:

```
Recon → Index → Hunt(1) → Gapfill → Hunt(2) → Validate → Dedupe → Trace → Report
```

The Gapfill block moves up to immediately after Hunt(1); the Validate and
Dedupe blocks move down to after Hunt(2). Gapfill's tool scope includes
`query_run_state`, `query_findings`, `read_file`/`grep`/`list_dir`, and
`add_hunt_task`; it does not need Validate/Dedupe output to run.

**Verdict-visibility tradeoff (operator-accepted 2026-09-10):** because
Gapfill now runs before Validate, findings are still `pending_validation`
when Gapfill inspects them via `query_findings`, so it can no longer judge
under-representation by validation verdict — only by severity (Hunter-set at
record time) and finding presence/count. The operator accepted this partial
degradation in exchange for the single-Validate-pass design; the Gapfill
system prompt (`prompts/system/gapfill.md`) is updated to direct the agent to
severity and presence rather than verdict.

### Hunt(2) gate

```
if recon_ok and gapfill_result.tasks_queued >= 1:
    hunt2_result = await hunt_stage.run(run_id=..., repo=..., cfg=..., session_factory=...)
else:
    hunt2_result = hunt_stage.HuntStageResult.skipped()
```

`hunt_stage.run()` re-selects `status='pending'`. After Hunt(1) every
recon-sourced task is terminal, so Hunt(2) processes exactly the
Gapfill-queued tasks and nothing else. No new parameters.

### Count composition

`HuntStageResult.findings_total` is a run-wide `COUNT(findings WHERE
run_id=?)`, not a per-pass delta, so `hunt2_result.findings_total` already
includes Hunt(1)'s findings. Define:

```
combined_findings_total = (
    hunt2_result.findings_total if hunt2_ran else hunt1_result.findings_total
)
```

`hunt2_ran` is true iff the Hunt(2) gate fired.

### Run finalization (best-effort Hunt(2))

Operator decision 2026-09-10: Hunt(2) is best-effort; its failures never flip
an otherwise-good run to `errored` (same posture as Trace).

- The `not recon_ok` gate is unchanged.
- The "Hunt processed ≥1 AND zero succeeded → errored" gate keeps reading
  **Hunt(1)** (`hunt1_result.tasks_succeeded < 1`). Hunt(2) outcomes are
  excluded.
- The "findings == 0 → completed, skip Validate" gate reads
  **`combined_findings_total`**, so a run that found nothing in Hunt(1) but
  something after Gapfill still gets validated rather than short-circuited to
  `completed`.
- The Validate terminal-verdict gate is unchanged (Validate already queries
  all `pending_validation` findings for the run, which now includes Hunt(2)'s).

### Budget and token totals

`runs.budget_used` and the summary's `total_in_tokens` / `total_out_tokens`
gain `hunt2_result.input_tokens_total` / `output_tokens_total`. Per-session
token budgets already bound each Hunt(2) session; the Gapfill 20% task cap
(`max(1, recon_task_count // 5)`) already bounds the task count.

### Summary output

Add a distinct "hunt (gapfill pass)" section printing Hunt(2)'s
processed/succeeded/refused/budget_exceeded/errored, findings recorded, and
tokens when it ran; a single "skipped (gapfill queued no tasks)" line when it
did not. The two passes stay individually legible rather than silently summed.

## Documentation

`ARCHITECTURE.md` § Stage 4 (Gapfill) v0.7 scope note currently states
auto-re-pass does not exist. Update it to record that the loop is now wired,
preserving the "runs once, no recursion" invariant. Operator approved editing
ARCHITECTURE.md in this PR (2026-09-10). The pipeline diagram already shows the
arrow and needs no change.

## Testing

`tests/unit/test_orchestrator.py` (mocks each stage `.run()`):

1. Gapfill queues ≥1 task → Hunt(2) runs; its findings reach Validate.
2. Hunt(1) finds nothing, Gapfill queues, Hunt(2) finds one → run
   `completed` (not short-circuited), Validate ran.
3. Hunt(2) all-refused → run still `completed`.
4. Gapfill queues nothing → Hunt(2) skipped; first-pass behavior unchanged.

Existing tests whose `fake_gapfill` returns `skipped()` stay green (Hunt(2)
never fires). Gates: `pytest tests/unit`, `ruff check .`,
`mypy --strict flosswing`.

## Files touched

- `flosswing/orchestrator.py` — reorder, Hunt(2) gate, finalization, summary.
- `tests/unit/test_orchestrator.py` — new cases above.
- `ARCHITECTURE.md` — Stage 4 scope-note update (operator-approved).
