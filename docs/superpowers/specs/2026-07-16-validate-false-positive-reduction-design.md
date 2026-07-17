# Validate-stage false-positive reduction

**Date:** 2026-07-16
**Branch:** `fp-reduction`
**Status:** Design — awaiting operator review

## Problem

A triage pass over 49 "confirmed" findings from a full six-module scan of
the `assemblyline` repo surfaced two systematic false-positive drivers:

1. **`hardcoded_secrets` fires on dev/test defaults.** Every confirmed
   `hardcoded_secrets` hit was a localhost dev default, a self-describing
   placeholder (`Ch@ngeTh!sPa33w0rd` = "change this password", `devpass`,
   MinIO defaults), or a value in a non-production artifact
   (`docker-compose.yml`, `*.template`, `test/`). All were reported at
   `high`/`medium` severity with confidence `likely`, indistinguishable
   from a real committed production secret.

2. **Circular PoCs earn `confirmed`.** Multiple findings were "confirmed
   via runnable PoC" where the PoC *re-implemented the sink itself* — a
   hand-written `renderMuiLinkLike()` instead of the real MUI `<Link>`, a
   reconstructed `safe_str` using the wrong codec, a copied `for..in`
   loop — then asserted its own output. The exit code proves nothing
   about the real repo code, yet the Validator treated it as strong
   evidence.

Root causes, from reading the code:

- `hardcoded_secrets` has **no attack-class fragment**. Only
  `prompts/attack_classes/command_injection.md` exists; every other class
  falls back to generic guidance with no disqualifiers
  (`hunt.py:_load_attack_class_fragment`).
- `validate.md`'s evidence model says `confirmed` needs "a runnable PoC"
  *or* "a reachability argument," but (a) a secret cannot be *executed*,
  so the PoC path degenerates to re-printing the constant, and (b)
  nothing tells the Validator that a PoC which mocks/re-implements the
  sink is non-probative.

## Goals

- Stop dev/test/placeholder secrets from surfacing as high/medium
  `confirmed` findings, **without dropping them entirely** (keep operator
  visibility; zero recall loss).
- Teach the Validator to discount circular/self-mocking PoCs.
- No changes to frozen contracts (`docs/tool-contracts.md`,
  `docs/schema.sql`, `ARCHITECTURE.md`). No new dependencies. No schema
  change.

## Non-goals

- Not touching other attack classes' false-positive behavior in this
  change (SSRF/deserialization mislabels seen in triage are out of scope).
- Not building a general provenance/reachability classifier — the secrets
  gate is deliberately narrow.
- Not adding a deterministic "PoC must import the real module" check (see
  rationale in Part B).

## Design

Three parts, independently landable.

### Part A — Prompt guidance for `hardcoded_secrets` (lever 1)

**New file:** `prompts/attack_classes/hardcoded_secrets.md`, mirroring the
shape of `command_injection.md`. Content:

- **Qualifies** only when the literal is a credential that plausibly
  survives into a *production* artifact and is not overridden at deploy.
- **Disqualifiers (do not report, or report at `info`):**
  - Self-describing placeholder / vendor-default values (`changeme`,
    `change_me`, `changeit`, `password`, `admin`, `minioadmin`, `devpass`,
    `example`, `sample`, `<YOUR_...>` template markers, `your-...`).
  - Low-entropy / dictionary-word values.
  - Host is `localhost` / `127.0.0.1` / `0.0.0.0` / RFC-1918.
  - File is a dev/test/example artifact: `test/`, `tests/`, `fixtures/`,
    `examples/`, `docker-compose*.yml`, `*.template`, CI config.
  - The literal is a **default overridden by operator config**
    (`os.environ.get("KEY", DEFAULT)` pattern) rather than a shipped value.
- Requires the finding to argue *why the secret reaches production*, not
  merely that a literal exists.

**Shared loader lift.** `_load_attack_class_fragment` currently lives in
`hunt.py` as a single-consumer private helper; its own docstring says to
"lift to a shared API only when Validate / Gapfill need it." That time is
now — Validate is where the confirm/downgrade decision happens. Lift it to
a shared location (`flosswing/prompts/__init__.py`, new
`load_attack_class_fragment(attack_class) -> str`) and have both `hunt.py`
and `validate.py` consume it. `validate.py` injects the fragment into the
Validate user prompt (`_compose_user_prompt`) so the Validator sees the
same disqualifiers the Hunter does.

### Part B — Circular-PoC discount (prompt-only)

**Edit `validate.md`.** In the "strongest evidence is a runnable PoC"
section, add: a PoC that re-implements, mocks, or hand-rolls the sink or a
helper (rather than importing and executing the **real repo module**) is
**non-probative** — its exit code proves nothing. When a faithful PoC
cannot run (e.g. the target package is not importable in the sandbox),
**do not** treat a self-mocking PoC as confirmation; fall back to the
reachability-argument path or return `uncertain`.

**Edit `hunt.md`** (light): when authoring `poc_code`, prefer PoCs that
import/exercise the real target module over standalone reconstructions.

**Why prompt-only, not a deterministic import-check.** The triage found
the real `assemblyline` package is frequently *not importable* inside the
sandbox (heavy deps, no install step). A hard "poc_code must import the
target package" rule would be unsatisfiable for exactly those findings and
would push everything to `uncertain`, destroying signal. Recognizing a
self-mock is a judgment task; keep it in the prompt.

### Part C — Deterministic secrets-triage downgrade gate (lever 3)

**New pure module:** `flosswing/secrets_triage.py`. No I/O, no state, fully
unit-testable.

```
class SecretTriage(BaseModel):
    downgradeable: bool
    classification: Literal["real", "dev_default", "placeholder", "test_fixture"]
    reason: str            # machine-readable, e.g. "sentinel-value:devpass"

def classify_secret(file_path: str, evidence_text: str) -> SecretTriage: ...
```

- `evidence_text` = the finding's source span (`file`, `line_start..
  line_end`, read **read-only** from the repo) concatenated with
  `finding.poc_code`. Keeps the function pure — the caller does the read.
- **Trigger policy: strong-signal-required** (conservative — chosen as the
  default to minimize false negatives, i.e. never silently demote a real
  secret):

  Downgrade **iff**
  `(value on SENTINEL denylist OR value matches /change|example|sample|dev|test|dummy|placeholder/i OR path is a dev/test/template/compose/example artifact OR (low entropy AND localhost host))`
  **AND NOT** `(max-literal Shannon entropy ≥ 3.5 AND file is a production source path)`.

  The counter-signal (`AND NOT ...`) is the false-negative guard: a
  high-entropy value in production source is never downgraded even if a
  weak dev signal is present.

- Entropy is computed over quoted string literals extracted from
  `evidence_text` (regex, best-effort); path classification is
  deterministic from `file_path`. Path signal alone is strong.

**Integration in `validate.py`.** After the per-finding verdict is
recorded (the block ~L534 that reads the `validations` row and finalizes
`findings.status`), add a post-step:

```
if finding.attack_class == "hardcoded_secrets" and finding.status == "confirmed":
    triage = classify_secret(finding.file, <span_text> + (finding.poc_code or ""))
    if triage.downgradeable and finding.severity != "info":
        finding.severity = "info"
        finding.root_cause_summary = (finding.root_cause_summary or "") + \
            f"\n[secrets_triage: {triage.classification} — {triage.reason}; overridden in prod / not a shipped secret]"
        session.add(finding); session.flush()
```

- **Only downgrades severity to `info`.** Never deletes, never changes
  `status` (stays `confirmed`), never touches non-`hardcoded_secrets`
  findings. The finding remains in the report, just out of the
  high/critical triage view.
- `severity="info"` is already in the `ck_findings_severity` CHECK
  constraint — **no schema change**.
- The gate is best-effort: any exception in `classify_secret` is caught
  and logged, leaving the agent's verdict untouched (fail-open to the
  existing behavior, never crash the stage).

## Data flow

```
Hunt ──(hardcoded_secrets.md disqualifiers)──> fewer/《info》 candidates
Validate agent ──> verdict (confirmed/…)         [Part A fragment + Part B rules in prompt]
        │
        └─(post-verdict, Part C)─> classify_secret(file, span+poc)
                                       └─ downgradeable? ─> severity:=info + annotate
```

## Error handling / edge cases

- `classify_secret` never raises to the caller; the gate wraps it and logs.
- Reading the source span uses the existing read-only repo path; a missing
  file / bad line range → empty `evidence_text` → path signal only.
- Idempotent: re-running the gate on an already-`info` finding is a no-op.
- Credential values are **never** logged or written to the DB by the gate;
  only the machine reason (e.g. `sentinel-value:devpass` for a known
  public placeholder) and classification are persisted. Real high-entropy
  values are never emitted (they are never downgraded, and the reason
  string uses the classification, not the value). Consistent with the
  "never log/store credential values" rule.

## Testing

- `tests/unit/test_secrets_triage.py` — table-driven over the real triage
  examples: `devpass@localhost`, `Ch@ngeTh!sPa33w0rd`, MinIO defaults,
  `docker-compose.yml`/`*.template` paths → `downgradeable=True`; a
  synthetic 40-char high-entropy secret in `flosswing/foo.py` →
  `downgradeable=False` (false-negative guard).
- `tests/unit/test_stages_validate.py` (extend) — a `confirmed`
  `hardcoded_secrets` finding on a dev-default → severity becomes `info`
  after the gate; a `confirmed` finding of another class → untouched.
- Prompt changes (Parts A, B): per CLAUDE.md, verified via
  `flosswing eval` against `tests/corpus/` (hits real API; run manually,
  not in CI). Check the confirmed/rejected/severity deltas vs. known-CVE
  ground truth do not regress recall.

## Files touched (order)

1. NEW `flosswing/secrets_triage.py` (+ tests) — self-contained, land first.
2. NEW `tests/unit/test_secrets_triage.py`.
3. EDIT `flosswing/prompts/__init__.py` — add shared
   `load_attack_class_fragment`.
4. EDIT `flosswing/stages/hunt.py` — use the shared loader.
5. NEW `flosswing/prompts/attack_classes/hardcoded_secrets.md`.
6. EDIT `flosswing/prompts/system/validate.md` — class-aware evidence +
   circular-PoC rule.
7. EDIT `flosswing/prompts/system/hunt.md` — PoC-should-exercise-real-code note.
8. EDIT `flosswing/stages/validate.py` — inject fragment + post-verdict gate.
9. EXTEND `tests/unit/test_stages_validate.py`.

This is >3 files, so per CLAUDE.md it needs operator approval before
implementation — this spec is that gate.

## Constraints honored

- No edits to `ARCHITECTURE.md`, `docs/tool-contracts.md`,
  `docs/schema.sql`, or `CLAUDE.md`.
- No new dependencies (`math`, `re`, `pathlib`, existing `pydantic`).
- No schema/migration change (`info` severity already exists).
- Tool contracts unchanged; no agent-facing tool added or modified.
