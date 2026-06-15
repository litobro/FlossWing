# Eval — corpus scoring & `flosswing eval` design

## Context

`ARCHITECTURE.md` lists `flosswing/eval/` (`corpus.py`, `scoring.py`,
`runner.py`) and names corpus-based scoring with `flosswing eval` as in-scope
for v1 (`ARCHITECTURE.md` § "v1 scope summary"). `CLAUDE.md` calls the eval
"the highest-fidelity check" — it "runs the full pipeline against
`tests/corpus/` and scores against known-CVE ground truth" and is to be run
before merging any prompt change.

Today the subsystem does not exist: `flosswing/eval/__init__.py` is empty and
`flosswing eval` (`flosswing/cli.py`) prints `not implemented`. This spec
designs the **machinery** — ground-truth format, registry, scorer, runner, and
CLI — wired to the existing smoke fixtures. Curating a broad real-CVE corpus is
explicitly out of scope (see below); adding a corpus repo is a data-only
drop-in once the machinery exists.

## Success criteria

- `flosswing eval --from-run <run_id> --corpus <name>` scores a completed run's
  operator-facing findings against ground truth with **no API call** and prints
  a deterministic scorecard (per-repo and aggregate precision / recall / F1,
  plus a per-attack-class breakdown).
- `flosswing eval` (no `--from-run`) runs the full pipeline (`run_scan`) against
  each registered corpus repo, then scores. This path touches the real API and
  is operator-run / `FLOSSWING_INTEGRATION`-gated — **not** in normal CI.
- The scoring core (`scoring.py`) and registry (`corpus.py`) are pure and fully
  unit-tested in normal CI; the `--from-run` CLI path is unit-tested against a
  temp DB seeded with known findings.
- Ground-truth manifests exist for both current fixtures (`v02_smoke`,
  `v08_dedupe_smoke`).
- `ruff check .`, `mypy --strict flosswing`, and `pytest tests/unit` pass.

## Scope

### In scope

- Ground-truth manifest format (TOML) + pydantic validation.
- `corpus.py`: load/validate manifests into `CorpusEntry` objects.
- `scoring.py`: pure match + precision/recall/F1, per-class breakdown.
- `runner.py`: orchestrate scans (default) or re-score an existing run
  (`--from-run`); produce an aggregate scorecard; optional exit-code gating.
- `flosswing eval` CLI wired to the runner (replaces the stub).
- Ground-truth manifests for `v02_smoke` and `v08_dedupe_smoke`.
- A thin public `load_report()` wrapper over `report._load` for reuse.

Ground-truth manifests ship as **package data** under `flosswing/eval/`, not
under `tests/`. They are part of the eval subsystem, not test fixtures, and the
target repos they reference are untrusted and write-free.

### Out of scope (not now)

- Curating real-world CVE corpus repos beyond the two existing smoke fixtures.
  The format and registry make this a pure data drop-in (add repo under
  `tests/corpus/<name>/` + a `ground_truth/<name>.toml`); no code change.
- Any change to the Report JSON schema, tool contracts, or DB schema.
- Scoring Trace/reachability accuracy or PoC success — v1 eval scores
  **finding detection** only (file + attack class + location).

### Explicit non-goals (per `ARCHITECTURE.md`)

- Telemetry of eval results. Scorecard goes to stdout / a local `--json` file
  only.
- No network beyond what `run_scan` itself already does via the agent SDK.

## Architecture

### Module layout

```
flosswing/eval/
  __init__.py
  corpus.py       # ground-truth manifest registry + pydantic models
  scoring.py      # pure matcher + precision/recall/F1
  runner.py       # `flosswing eval` backend: scan-or-rescore, aggregate
  ground_truth/   # package data — ground-truth manifests
    v02_smoke.toml
    v08_dedupe_smoke.toml

tests/corpus/
  v02_smoke/            # existing — the scanned (untrusted) repo
  v08_dedupe_smoke/     # existing
```

Manifests ship as eval package data and live **outside** the scanned repo
directories. The target repo is untrusted input and FlossWing never writes to
it, so eval metadata must not live inside `tests/corpus/<name>/`. The `repo`
field is resolved against a separate **corpus root** (default `tests/corpus/`,
see `--corpus-root`) and is only needed by the scan path — `--from-run`
scoring never touches the repo directory.

Package-data inclusion: `*.toml` under `flosswing/eval/ground_truth/` is added
to the wheel via the hatchling build config in `pyproject.toml`.

### Ground-truth manifest (TOML, `tomllib` + pydantic)

```toml
name = "v02_smoke"            # registry key, must match file stem
repo = "v02_smoke"            # directory under tests/corpus/
description = "..."           # optional, informational

[[vuln]]
id = "cmdi-1"                 # unique within manifest
file = "src/example/cli.py"  # repo-relative POSIX path
line_start = 42
line_end = 42                 # >= line_start
attack_class = "command_injection"
tolerance = 10               # optional, ± lines; default from config (10)
cve = "CVE-..."              # optional, informational
severity = "high"           # optional, informational
notes = "..."               # optional
```

Pydantic models: `GroundTruthVuln`, `CorpusEntry` (`name`, `repo`,
`description`, `vulns: list[GroundTruthVuln]`). Validation errors (missing
field, `line_end < line_start`, duplicate `id`, `name` != file stem) raise a
clear `EvalConfigError` naming the manifest path. No credential or repo content
is ever read into these models.

### `corpus.py`

- `DEFAULT_TOLERANCE = 10`
- `DEFAULT_MANIFEST_DIR` = the packaged `flosswing/eval/ground_truth/` dir
  (resolved via `importlib.resources` / `Path(__file__).parent`).
- `load_manifest(path: Path) -> CorpusEntry`
- `load_corpus(manifest_dir: Path) -> list[CorpusEntry]` (sorted by name;
  empty dir → empty list, not an error)
- `find_entry(manifest_dir: Path, name: str) -> CorpusEntry` (missing → error)

Pure file IO + validation. No DB, no API.

### `scoring.py` (pure — the CI-testable core)

Inputs:
- `ground_truth: list[GroundTruthVuln]`
- `findings: list[ScoredFinding]` — a minimal value object
  (`file`, `line_start`, `line_end`, `attack_class`), built by the runner from
  the operator-facing report findings.

Match rule (per design decision):
- Candidate match iff **same repo-relative file** AND **same `attack_class`**
  AND the finding's `[line_start, line_end]` lies within ±`tolerance` of the
  GT entry's `[line_start, line_end]` (interval distance ≤ tolerance).
- **At most one finding per GT entry**: among candidates, the finding with the
  smallest line distance wins (ties broken by `line_start`, then a stable
  index). A finding already consumed by an earlier GT entry cannot match
  another. Findings left unmatched are **false positives** (so duplicate
  findings on one real bug count as FPs — this also surfaces Dedupe
  regressions). GT entries left unmatched are **false negatives**.

Outputs — `ScoreReport` (pydantic / frozen dataclass):
- `true_positives`, `false_positives`, `false_negatives` (ints)
- `matches: list[Match]` (gt id ↔ finding index, line distance)
- `precision`, `recall`, `f1` — `float | None` (None when denominator is 0,
  rendered as `n/a`)
- `by_attack_class: dict[str, ClassScore]` (TP/FP/FN/precision/recall per class)

`aggregate(reports: list[ScoreReport]) -> ScoreReport` sums counts across
repos and recomputes ratios.

### `runner.py` (the only API-touching module)

- `score_run(run_id, entry, session_factory, *, include_uncertain=False)
  -> ScoreReport`: load the run's operator-facing findings via the report
  loader, filter to `confirmed` (plus `uncertain` if `include_uncertain`),
  drop dedupe non-primaries (the report view already collapses these), project
  to `ScoredFinding`, and score against `entry.vulns`. **No API.**
- `run_and_score(entry, cfg_factory, ...) -> tuple[str, ScoreReport]`: call
  `run_scan` for the repo (real API), then `score_run` on the resulting run id.
- `run_evaluation(...) -> EvalResult`: iterate corpus entries (or a single
  `--from-run` + `--corpus` pair), accumulate per-repo reports + aggregate,
  return a structured `EvalResult` for rendering.

Findings come from the **operator-facing** report view (deduped primaries,
`confirmed` by default) so eval measures exactly what a user sees. This reuses
`report._load`, promoted to a public `load_report(run_id, session_factory)
-> ReportV1` (additive; `_load` kept as a private alias to avoid churn).

### CLI surface (`flosswing eval`)

```
flosswing eval [OPTIONS]

  --from-run TEXT        Score an existing run instead of scanning (no API).
                         Requires --corpus.
  --corpus TEXT          Corpus entry name (manifest stem). Required with
                         --from-run; otherwise defaults to all registered.
  --manifest-dir PATH    Ground-truth dir (default: packaged
                         flosswing/eval/ground_truth).
  --corpus-root PATH     Root for resolving a manifest's `repo` dir on the scan
                         path (default tests/corpus). Unused by --from-run.
  --include-uncertain    Also score findings with status 'uncertain'.
  --json PATH            Write the scorecard JSON to PATH.
  --min-recall FLOAT     Exit non-zero if aggregate recall < value.
  --min-precision FLOAT  Exit non-zero if aggregate precision < value.
```

Default (no `--from-run`) runs the full pipeline against every registered
corpus repo — operator-run, API-touching. Stdout shows a per-repo table and an
aggregate line. Gates (`--min-*`) set exit code 1 when unmet; absent gates exit
0 regardless of score.

## Data flow

`--from-run` (deterministic, CI-tested):
```
find_entry(name) -> CorpusEntry
load_report(run_id) -> ReportV1 -> filter confirmed/primary -> [ScoredFinding]
score(entry.vulns, findings) -> ScoreReport -> render stdout (+ --json)
-> exit code from --min-* gates
```

Default (operator-run, gated):
```
load_corpus(manifest_dir) -> [CorpusEntry]
  for each: resolve repo under --corpus-root -> run_scan(cfg) -> run_id
            -> score_run -> ScoreReport
aggregate -> render -> exit code
```

## Determinism

Scoring is a pure function of (ground truth, findings); identical inputs →
identical `ScoreReport`. The matcher's tie-breaking is total (line distance,
then `line_start`, then stable finding index) so there is no ordering
ambiguity. JSON output uses sorted keys. The `run_scan` path is inherently
non-deterministic (LLM) and therefore excluded from CI.

## Error handling

- Malformed / invalid manifest → `EvalConfigError` naming the path; eval aborts
  before any scan.
- `--from-run` with unknown run id, or `--corpus` naming a missing entry →
  clear error, exit 2.
- `--from-run` without `--corpus` → usage error.
- All error strings pass through `errors.scrub()` before stderr, per the
  credential rule. Ground-truth manifests contain no credentials; findings are
  already-scrubbed report data.

## Security considerations

- Ground-truth manifests are operator-authored fixtures, not target-repo
  content; still parsed as data (`tomllib`), never executed.
- Eval reads the state DB and (default path) drives `run_scan`, which already
  enforces the sandbox / no-write-to-repo guarantees. Eval adds no new repo
  access and no network of its own.
- No eval result is logged anywhere but stdout / the `--json` file the operator
  names.

## Testing strategy

### Unit tests (normal CI, no API)

- `test_eval_scoring.py`: exact match; tolerance boundary (just inside / just
  outside); attack-class mismatch → no match; two findings on one GT entry →
  1 TP + 1 FP; file mismatch; zero findings vs non-empty GT (recall 0); empty
  GT (precision/recall `None`); multi-class breakdown; `aggregate` across repos.
- `test_eval_corpus.py`: valid manifest loads; `line_end < line_start`,
  duplicate `id`, name/stem mismatch, missing file → `EvalConfigError`; empty
  dir → `[]`.
- `test_cli_eval.py`: `--from-run` against a temp SQLite DB seeded with known
  `Finding` rows (confirmed + uncertain + a dedupe non-primary) → asserts the
  exact scorecard and that `--include-uncertain` / `--min-recall` change the
  result and exit code. Mock at the report-loader / session boundary, not HTTP.

### Integration (gated, NOT in CI)

- Extend the existing `FLOSSWING_INTEGRATION` smoke set so the default
  `flosswing eval` path runs `v02_smoke` end-to-end and produces a scorecard.
  Asserts the command runs and emits a structured result, not a specific score
  (LLM output is non-deterministic).

### CI changes

None required for the gates. Optionally a follow-up could add a `flosswing
eval --from-run` step against a checked-in fixture run, but that's out of scope
here.

## Open questions / decisions — RESOLVED 2026-06-15

1. **Scope** → machinery only; wire to existing smoke fixtures; real-CVE corpus
   curation deferred to a data-only drop-in.
2. **Runner model** → run pipeline by default; `--from-run` re-scores an
   existing run (pure, CI-testable).
3. **Match rule** → same file + same attack class + line within ±tolerance;
   at most one finding per GT entry; extra findings = FP.
4. **Findings scored** → operator-facing `confirmed` findings by default;
   `--include-uncertain` opt-in.
5. **Gating** → optional `--min-recall` / `--min-precision` set exit code;
   default no gate.
6. **Manifest location** → `flosswing/eval/ground_truth/<name>.toml` (eval
   package data), outside the scanned repos; the `repo` field resolves under a
   separate `--corpus-root` (default `tests/corpus/`) on the scan path only.

## Definition of "done"

- `flosswing/eval/{corpus,scoring,runner}.py` implemented; `flosswing eval`
  wired (stub removed).
- `report.load_report` public wrapper added.
- Ground-truth manifests for `v02_smoke` and `v08_dedupe_smoke`.
- Unit tests above pass in CI; `ruff` + `mypy --strict` clean.
- `flosswing eval --from-run <id> --corpus v02_smoke` prints a deterministic
  scorecard (operator-smoke-verified with a real run).
