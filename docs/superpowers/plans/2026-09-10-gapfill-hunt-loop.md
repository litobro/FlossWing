# Gapfill → Hunt Loop Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run one bounded second Hunt pass over Gapfill's queued tasks within the same scan, so Gapfill-driven findings get validated, deduped, and traced.

**Architecture:** Reorder `orchestrator.run_scan` so Gapfill runs immediately after the first Hunt pass; if Gapfill queued ≥1 task, invoke `hunt_stage.run` a second time (it re-selects only `status='pending'` tasks, which are exactly Gapfill's), then run Validate/Dedupe/Trace once over the union of both passes' findings. Hunt-2 is best-effort: its failures never flip the run to `errored`.

**Tech Stack:** Python 3.11+, asyncio, SQLAlchemy over SQLite, pytest (SDK mocked at `stage.run`), ruff, mypy --strict.

## Global Constraints

- Python 3.11+, full type hints; `ruff check .` and `mypy --strict flosswing` must pass. (`pyproject.toml`)
- Tool contracts are frozen — this change adds no tools and alters no signatures.
- No schema change, no migration, no new dependency.
- Commit messages reference the spec, e.g. `... per docs/specs/2026-09-10-gapfill-hunt-loop-design.md`.
- Every commit ends with the trailer:
  `Claude-Session: https://claude.ai/code/session_013GuJYRU6zEfB7dbSNWVRYV`
- Run all commands from the worktree dir `/home/tdang/projects/personal/FlossWing/.claude/worktrees/gapfill-hunt-loop`, using the main-repo venv binary `/home/tdang/projects/personal/FlossWing/.venv/bin/pytest` (per CLAUDE.md worktree gotcha).
- Spec of record: `docs/specs/2026-09-10-gapfill-hunt-loop-design.md`.

---

### Task 1: Reorder orchestrator and add the second Hunt pass

**Files:**
- Modify: `flosswing/orchestrator.py` (stage-sequence blocks ~188–247, finalization ~283–334, summary ~421–437 and the hunt summary section ~578–588)
- Modify: `tests/unit/test_orchestrator.py` (add loop tests; adjust one existing budget test)

**Interfaces:**
- Consumes (all already exist, no signature changes):
  - `hunt_stage.run(*, run_id: str, repo: Path, cfg: Config, session_factory) -> HuntStageResult`
  - `hunt_stage.HuntStageResult.skipped() -> HuntStageResult`
  - `HuntStageResult` fields: `tasks_processed, tasks_succeeded, tasks_refused, tasks_budget_exceeded, tasks_errored, findings_total, input_tokens_total, output_tokens_total`
  - `gapfill_stage.run(...) -> GapfillStageResult` with field `tasks_queued: int`
- Produces: no new public symbols. Local names introduced in `run_scan`: `hunt1_result`, `gapfill_result`, `hunt2_ran: bool`, `hunt2_result: HuntStageResult`, `combined_findings_total: int`.

- [ ] **Step 1: Write the failing test — Hunt-2 runs and its findings reach Validate**

Add to `tests/unit/test_orchestrator.py` (uses existing `_recon`, `_hunt`, `_validate`, `_gapfill`, `fresh_db`, `_cfg`):

```python
def test_hunt2_runs_when_gapfill_queues_tasks(
    fresh_db: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Gapfill queues >=1 task -> a second Hunt pass runs, and Validate
    runs after it. Per docs/specs/2026-09-10-gapfill-hunt-loop-design.md."""
    from flosswing import orchestrator
    from flosswing.stages import gapfill as gapfill_stage
    from flosswing.stages import hunt as hunt_stage
    from flosswing.stages import recon as recon_stage
    from flosswing.stages import validate as validate_stage

    hunt_calls = 0
    validate_called = False

    async def fake_recon(**kwargs: object) -> RunReconResult:
        return _recon()

    async def fake_hunt(**kwargs: object) -> HuntStageResult:
        nonlocal hunt_calls
        hunt_calls += 1
        # Pass 1: 1 finding. Pass 2: findings_total is run-wide, so it
        # reports the cumulative 2. Mirror that here.
        if hunt_calls == 1:
            return _hunt(processed=2, succeeded=2, findings=1)
        return _hunt(processed=1, succeeded=1, findings=2)

    async def fake_validate(**kwargs: object) -> ValidateStageResult:
        nonlocal validate_called
        validate_called = True
        return _validate(processed=2, confirmed=2)

    async def fake_gapfill(**kwargs: object) -> GapfillStageResult:
        return _gapfill(outcome="completed", tasks_queued=1, cap=1)

    monkeypatch.setattr(recon_stage, "run", fake_recon)
    monkeypatch.setattr(hunt_stage, "run", fake_hunt)
    monkeypatch.setattr(validate_stage, "run", fake_validate)
    monkeypatch.setattr(gapfill_stage, "run", fake_gapfill)

    result = asyncio.run(orchestrator.run_scan(_cfg(tmp_path)))
    assert hunt_calls == 2
    assert validate_called is True
    assert result.exit_code == 0
    with st_session.session_scope() as s:
        assert s.query(Run).all()[0].status == "completed"
```

- [ ] **Step 2: Run it to verify it fails**

Run: `/home/tdang/projects/personal/FlossWing/.venv/bin/pytest tests/unit/test_orchestrator.py::test_hunt2_runs_when_gapfill_queues_tasks -x -q`
Expected: FAIL — `hunt_calls == 2` fails with `assert 1 == 2` (Hunt currently runs once).

- [ ] **Step 3: Reorder the stage blocks and add the Hunt-2 gate**

In `flosswing/orchestrator.py`, rename the first Hunt result to `hunt1_result` and restructure. Replace the current block that runs Hunt, then Validate, then Dedupe, then Gapfill (the `if recon_ok:` Hunt block through the Gapfill `else:` branch) with this exact ordering:

```python
        if recon_ok:
            hunt1_result = await hunt_stage.run(
                run_id=run_id,
                repo=cfg.repo_root,
                cfg=cfg,
                session_factory=st_session.session_factory(),
            )
        else:
            hunt1_result = hunt_stage.HuntStageResult.skipped()

        # Gapfill runs right after the first Hunt pass (moved ahead of
        # Validate/Dedupe per docs/specs/2026-09-10-gapfill-hunt-loop-design.md
        # § Stage reordering). Gate unchanged: Hunt succeeded >=1 task.
        if recon_ok and hunt1_result.tasks_succeeded >= 1:
            gapfill_result = await gapfill_stage.run(
                run_id=run_id,
                repo=cfg.repo_root,
                cfg=cfg,
                session_factory=st_session.session_factory(),
            )
        else:
            gapfill_result = gapfill_stage.GapfillStageResult.skipped()

        # Second (Gapfill-driven) Hunt pass. Runs only when Gapfill queued
        # >=1 task. hunt_stage.run re-selects status='pending', which after
        # pass 1 is exactly the Gapfill-queued tasks. Best-effort: failures
        # here never flip the run to errored (finalization reads hunt1).
        hunt2_ran = recon_ok and gapfill_result.tasks_queued >= 1
        if hunt2_ran:
            hunt2_result = await hunt_stage.run(
                run_id=run_id,
                repo=cfg.repo_root,
                cfg=cfg,
                session_factory=st_session.session_factory(),
            )
        else:
            hunt2_result = hunt_stage.HuntStageResult.skipped()

        # Authoritative run-wide finding count. HuntStageResult.findings_total
        # is a COUNT over all findings for the run, so hunt2_result already
        # includes pass-1 findings when it ran.
        combined_findings_total = (
            hunt2_result.findings_total if hunt2_ran else hunt1_result.findings_total
        )

        # Validate runs after BOTH Hunt passes, over the union of findings.
        if recon_ok and combined_findings_total >= 1:
            validate_result = await validate_stage.run(
                run_id=run_id,
                repo=cfg.repo_root,
                cfg=cfg,
                session_factory=st_session.session_factory(),
            )
        else:
            validate_result = validate_stage.ValidateStageResult.skipped()

        # Dedupe runs after Validate over the union of findings.
        if recon_ok and combined_findings_total > 0:
            dedupe_result = await dedupe_stage.run(
                run_id=run_id,
                repo=cfg.repo_root,
                cfg=cfg,
                session_factory=st_session.session_factory(),
            )
        else:
            dedupe_result = DedupeStageResult.skipped()
```

Leave the existing Trace block (which follows) unchanged.

- [ ] **Step 4: Update finalization to use hunt1 / combined totals**

In the finalization branch (currently referencing `hunt_result`), make these exact substitutions:

```python
        if not recon_ok:
            final_status = "errored"
        elif hunt1_result.tasks_succeeded < 1:
            final_status = "errored"
        elif combined_findings_total == 0:
            final_status = "completed"
        elif (
            validate_result.findings_confirmed
            + validate_result.findings_rejected
            + validate_result.findings_uncertain
            >= 1
        ):
            final_status = "completed"
        else:
            final_status = "errored"
```

- [ ] **Step 5: Add Hunt-2 tokens to budget_used and summary token totals**

In the `row.budget_used = (...)` sum, add Hunt-2 after the existing Hunt line:

```python
            row.budget_used = (
                recon_result.input_tokens
                + recon_result.output_tokens
                + hunt1_result.input_tokens_total
                + hunt1_result.output_tokens_total
                + hunt2_result.input_tokens_total
                + hunt2_result.output_tokens_total
                + validate_result.input_tokens_total
                + validate_result.output_tokens_total
                + gapfill_result.input_tokens
                + gapfill_result.output_tokens
                + dedupe_result.input_tokens
                + dedupe_result.output_tokens
                + trace_result.input_tokens
                + trace_result.output_tokens
            )
```

In `total_in_tokens = (...)` and `total_out_tokens = (...)`, replace `hunt_result.input_tokens_total` with `hunt1_result.input_tokens_total + hunt2_result.input_tokens_total`, and likewise for output.

- [ ] **Step 6: Rename remaining hunt_result references and add the Hunt-2 summary section**

Every remaining `hunt_result.` in the summary-building section (the `hunt:` block) becomes `hunt1_result.`. Build a Hunt-2 section before `summary_lines` is assembled:

```python
        if hunt2_ran:
            hunt2_lines: list[str] = [
                "  hunt (gapfill pass):",
                f"    tasks processed:    {hunt2_result.tasks_processed}",
                f"    succeeded:          {hunt2_result.tasks_succeeded}",
                f"    refused:            {hunt2_result.tasks_refused}",
                f"    budget_exceeded:    {hunt2_result.tasks_budget_exceeded}",
                f"    errored:            {hunt2_result.tasks_errored}",
                f"    tokens in/out:      "
                f"{hunt2_result.input_tokens_total} / "
                f"{hunt2_result.output_tokens_total}",
            ]
        else:
            hunt2_lines = ["  hunt (gapfill pass): skipped (gapfill queued no tasks)"]
```

Then add `*hunt2_lines,` into the `summary_lines` list immediately after the first Hunt block's `*task_lines,` entry and before the `"  validate:"` entry.

- [ ] **Step 7: Run the new test to verify it passes**

Run: `/home/tdang/projects/personal/FlossWing/.venv/bin/pytest tests/unit/test_orchestrator.py::test_hunt2_runs_when_gapfill_queues_tasks -x -q`
Expected: PASS.

- [ ] **Step 8: Add the zero-then-found test (findings only appear after Gapfill)**

```python
def test_hunt2_findings_trigger_validate_when_pass1_empty(
    fresh_db: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pass 1 finds nothing; Gapfill queues; pass 2 finds one. The run must
    NOT short-circuit to 'completed, Validate skipped' — combined findings
    drive the Validate gate."""
    from flosswing import orchestrator
    from flosswing.stages import gapfill as gapfill_stage
    from flosswing.stages import hunt as hunt_stage
    from flosswing.stages import recon as recon_stage
    from flosswing.stages import validate as validate_stage

    hunt_calls = 0
    validate_called = False

    async def fake_recon(**kwargs: object) -> RunReconResult:
        return _recon()

    async def fake_hunt(**kwargs: object) -> HuntStageResult:
        nonlocal hunt_calls
        hunt_calls += 1
        if hunt_calls == 1:
            return _hunt(processed=2, succeeded=2, findings=0)
        return _hunt(processed=1, succeeded=1, findings=1)

    async def fake_validate(**kwargs: object) -> ValidateStageResult:
        nonlocal validate_called
        validate_called = True
        return _validate(processed=1, confirmed=1)

    async def fake_gapfill(**kwargs: object) -> GapfillStageResult:
        return _gapfill(outcome="completed", tasks_queued=1, cap=1)

    monkeypatch.setattr(recon_stage, "run", fake_recon)
    monkeypatch.setattr(hunt_stage, "run", fake_hunt)
    monkeypatch.setattr(validate_stage, "run", fake_validate)
    monkeypatch.setattr(gapfill_stage, "run", fake_gapfill)

    result = asyncio.run(orchestrator.run_scan(_cfg(tmp_path)))
    assert hunt_calls == 2
    assert validate_called is True
    assert result.exit_code == 0
    with st_session.session_scope() as s:
        assert s.query(Run).all()[0].status == "completed"
```

Run: `/home/tdang/projects/personal/FlossWing/.venv/bin/pytest tests/unit/test_orchestrator.py::test_hunt2_findings_trigger_validate_when_pass1_empty -x -q`
Expected: PASS.

- [ ] **Step 9: Add the best-effort test (Hunt-2 all-refused stays completed)**

```python
def test_hunt2_all_refused_does_not_error_run(
    fresh_db: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Hunt-2 is best-effort: a wholesale pass-2 failure never flips an
    otherwise-good run to errored. Per design § Run finalization."""
    from flosswing import orchestrator
    from flosswing.stages import gapfill as gapfill_stage
    from flosswing.stages import hunt as hunt_stage
    from flosswing.stages import recon as recon_stage
    from flosswing.stages import validate as validate_stage

    hunt_calls = 0

    async def fake_recon(**kwargs: object) -> RunReconResult:
        return _recon()

    async def fake_hunt(**kwargs: object) -> HuntStageResult:
        nonlocal hunt_calls
        hunt_calls += 1
        if hunt_calls == 1:
            return _hunt(processed=2, succeeded=2, findings=1)
        # Pass 2: every task refused, zero succeeded. findings_total stays
        # at the run-wide 1 from pass 1.
        return _hunt(processed=1, succeeded=0, refused=1, findings=1)

    async def fake_validate(**kwargs: object) -> ValidateStageResult:
        return _validate(processed=1, confirmed=1)

    async def fake_gapfill(**kwargs: object) -> GapfillStageResult:
        return _gapfill(outcome="completed", tasks_queued=1, cap=1)

    monkeypatch.setattr(recon_stage, "run", fake_recon)
    monkeypatch.setattr(hunt_stage, "run", fake_hunt)
    monkeypatch.setattr(validate_stage, "run", fake_validate)
    monkeypatch.setattr(gapfill_stage, "run", fake_gapfill)

    result = asyncio.run(orchestrator.run_scan(_cfg(tmp_path)))
    assert hunt_calls == 2
    assert result.exit_code == 0
    with st_session.session_scope() as s:
        assert s.query(Run).all()[0].status == "completed"
```

Run: `/home/tdang/projects/personal/FlossWing/.venv/bin/pytest tests/unit/test_orchestrator.py::test_hunt2_all_refused_does_not_error_run -x -q`
Expected: PASS.

- [ ] **Step 10: Add the skip test (Gapfill queues nothing → Hunt-2 skipped)**

```python
def test_hunt2_skipped_when_gapfill_queues_nothing(
    fresh_db: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """tasks_queued == 0 -> no second Hunt pass; first-pass behavior and
    the summary's skip line are unchanged."""
    from flosswing import orchestrator
    from flosswing.stages import gapfill as gapfill_stage
    from flosswing.stages import hunt as hunt_stage
    from flosswing.stages import recon as recon_stage
    from flosswing.stages import validate as validate_stage

    hunt_calls = 0

    async def fake_recon(**kwargs: object) -> RunReconResult:
        return _recon()

    async def fake_hunt(**kwargs: object) -> HuntStageResult:
        nonlocal hunt_calls
        hunt_calls += 1
        return _hunt(processed=2, succeeded=2, findings=1)

    async def fake_validate(**kwargs: object) -> ValidateStageResult:
        return _validate(processed=1, confirmed=1)

    async def fake_gapfill(**kwargs: object) -> GapfillStageResult:
        return _gapfill(outcome="completed", tasks_queued=0, cap=1)

    monkeypatch.setattr(recon_stage, "run", fake_recon)
    monkeypatch.setattr(hunt_stage, "run", fake_hunt)
    monkeypatch.setattr(validate_stage, "run", fake_validate)
    monkeypatch.setattr(gapfill_stage, "run", fake_gapfill)

    result = asyncio.run(orchestrator.run_scan(_cfg(tmp_path)))
    assert hunt_calls == 1
    assert result.exit_code == 0
    assert "hunt (gapfill pass): skipped" in result.summary
```

Run: `/home/tdang/projects/personal/FlossWing/.venv/bin/pytest tests/unit/test_orchestrator.py::test_hunt2_skipped_when_gapfill_queues_nothing -x -q`
Expected: PASS.

- [ ] **Step 11: Fix the one existing test that now runs Hunt twice**

`test_orchestrator_budget_used_includes_gapfill_tokens` sets `tasks_queued=1`, which now triggers Hunt-2 and changes `budget_used`. Keep that test focused on its original purpose (Gapfill tokens are summed) by making Gapfill queue nothing. In that test's `fake_gapfill`, change `tasks_queued=1` to `tasks_queued=0` and add a comment above the return:

```python
        # tasks_queued=0 keeps this test focused on gapfill-token accounting;
        # the second Hunt pass and its budget contribution are covered by
        # test_hunt2_tokens_counted_in_budget.
        return _gapfill(
            outcome="completed",
            tasks_queued=0,
            cap=1,
            input_tokens=300,
            output_tokens=80,
        )
```

The `assert runs[0].budget_used == 830` line is unchanged and now holds again.

- [ ] **Step 12: Add the Hunt-2 budget test**

```python
def test_hunt2_tokens_counted_in_budget(
    fresh_db: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """budget_used sums BOTH Hunt passes when the second runs."""
    from flosswing import orchestrator
    from flosswing.stages import gapfill as gapfill_stage
    from flosswing.stages import hunt as hunt_stage
    from flosswing.stages import recon as recon_stage
    from flosswing.stages import validate as validate_stage

    hunt_calls = 0

    async def fake_recon(**kwargs: object) -> RunReconResult:
        return _recon()  # input=1000, output=200

    async def fake_hunt(**kwargs: object) -> HuntStageResult:
        nonlocal hunt_calls
        hunt_calls += 1
        if hunt_calls == 1:
            return _hunt(
                processed=1, succeeded=1, findings=1,
                input_tokens_total=100, output_tokens_total=50,
            )
        return _hunt(
            processed=1, succeeded=1, findings=1,
            input_tokens_total=70, output_tokens_total=30,
        )

    async def fake_validate(**kwargs: object) -> ValidateStageResult:
        return _validate(processed=1, confirmed=1)

    async def fake_gapfill(**kwargs: object) -> GapfillStageResult:
        return _gapfill(
            outcome="completed", tasks_queued=1, cap=1,
            input_tokens=0, output_tokens=0,
        )

    monkeypatch.setattr(recon_stage, "run", fake_recon)
    monkeypatch.setattr(hunt_stage, "run", fake_hunt)
    monkeypatch.setattr(validate_stage, "run", fake_validate)
    monkeypatch.setattr(gapfill_stage, "run", fake_gapfill)

    asyncio.run(orchestrator.run_scan(_cfg(tmp_path)))
    with st_session.session_scope() as s:
        runs = s.query(Run).all()
        # recon 1200 + hunt1 150 + hunt2 100 + validate 0 + gapfill 0 = 1450
        assert runs[0].budget_used == 1450
```

Run: `/home/tdang/projects/personal/FlossWing/.venv/bin/pytest tests/unit/test_orchestrator.py::test_hunt2_tokens_counted_in_budget -x -q`
Expected: PASS.

- [ ] **Step 13: Run the full unit suite, then lint and types**

Run: `/home/tdang/projects/personal/FlossWing/.venv/bin/pytest tests/unit -p no:warnings -q`
Expected: PASS (766 tests; four new tests added, no regressions).
Run: `/home/tdang/projects/personal/FlossWing/.venv/bin/ruff check .`
Expected: no errors.
Run: `/home/tdang/projects/personal/FlossWing/.venv/bin/mypy --strict flosswing`
Expected: no errors.

- [ ] **Step 14: Commit**

```
git add flosswing/orchestrator.py tests/unit/test_orchestrator.py
git commit -m "Wire Gapfill→Hunt second pass per docs/specs/2026-09-10-gapfill-hunt-loop-design.md

Reorder run_scan to Recon→Index→Hunt(1)→Gapfill→Hunt(2)→Validate→Dedupe→Trace.
Hunt(2) runs only when Gapfill queued >=1 task; it is best-effort (never
errors the run). Validate/Dedupe gate on combined findings so post-Gapfill
findings are validated. budget_used and summary token totals include both
passes; a 'hunt (gapfill pass)' summary section reports pass 2.

Claude-Session: https://claude.ai/code/session_013GuJYRU6zEfB7dbSNWVRYV"
```

---

### Task 2: Update ARCHITECTURE.md Stage 4 scope note

**Files:**
- Modify: `ARCHITECTURE.md` (Stage 4 "v0.7 scope note", lines ~185–189)

**Interfaces:** None (documentation).

- [ ] **Step 1: Replace the pending-implementation scope note**

In `ARCHITECTURE.md`, replace the block:

```
> **v0.7 scope note (pending implementation):** The first Gapfill plumbing
> milestone queues new Hunt tasks but does **not** auto-trigger a second Hunt
> pass against them within the same run. Newly queued tasks sit in
> `status='pending'` for the operator's next invocation; auto-re-pass is a
> follow-on milestone. See `docs/specs/2026-06-02-v0.7-gapfill-design.md`.
```

with:

```
> **v0.7 scope note:** Gapfill queues new Hunt tasks; the orchestrator then
> runs one bounded second Hunt pass over them within the same run (the
> Gapfill→Hunt arrow in the pipeline diagram). The second pass is best-effort
> — its failures never mark the run `errored` — and there is no further
> expansion: exactly one Gapfill and one second Hunt pass per run. See
> `docs/specs/2026-06-02-v0.7-gapfill-design.md` and
> `docs/specs/2026-09-10-gapfill-hunt-loop-design.md`.
```

Leave the Stage 4 body (`Outputs new Hunt tasks ... no recursive expansion in v1.`) unchanged — it remains accurate.

- [ ] **Step 2: Verify no other ARCHITECTURE.md text claims the loop is unwired**

Run: `grep -n "auto-re-pass\|next invocation\|does \*\*not\*\* auto-trigger" ARCHITECTURE.md`
Expected: no matches.

- [ ] **Step 3: Commit**

```
git add ARCHITECTURE.md
git commit -m "Update Stage 4 scope note: Gapfill→Hunt auto-re-pass now wired

Operator-approved edit (2026-09-10). Records that the orchestrator runs one
best-effort second Hunt pass over Gapfill-queued tasks, per
docs/specs/2026-09-10-gapfill-hunt-loop-design.md.

Claude-Session: https://claude.ai/code/session_013GuJYRU6zEfB7dbSNWVRYV"
```

---

## Notes for the implementer

- The reorder is the whole change — do not touch any `stage.run` internals, tool contracts, schema, or migrations.
- `HuntStageResult.findings_total` is run-wide, not per-pass; that is why `combined_findings_total` prefers `hunt2_result.findings_total` when the second pass ran.
- The "processed ≥1 AND zero succeeded → errored" gate intentionally still reads `hunt1_result` only. That is the best-effort decision; do not switch it to combined counts.
