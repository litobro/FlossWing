# Validate-stage False-Positive Reduction — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cut two systematic Validate-stage false positives — dev/placeholder `hardcoded_secrets` reported as high-severity, and circular self-mocking PoCs earning `confirmed`.

**Architecture:** A pure deterministic classifier (`secrets_triage.py`) runs as a post-verdict gate in the Validate stage and downgrades (never drops) dev/placeholder secret findings to `severity=info`. Prompt guidance teaches Hunt and Validate the `hardcoded_secrets` disqualifiers (via a shared attack-class-fragment loader) and teaches Validate to discount self-mocking PoCs.

**Tech Stack:** Python 3.11+, pydantic, SQLAlchemy, pytest. Stdlib only for the classifier (`math`, `re`, `pathlib`).

## Global Constraints

- Python 3.11+, full type hints; `ruff check` and `mypy --strict` must pass. `pyproject.toml` owns config.
- Add `# type: ignore` / `# noqa` only with an inline comment explaining why.
- No new top-level dependencies.
- Do NOT edit `ARCHITECTURE.md`, `docs/tool-contracts.md`, `docs/schema.sql`, `CLAUDE.md`.
- No schema/migration change. `severity="info"` already exists in `ck_findings_severity`.
- Tool contracts frozen: no agent-facing tool added or modified.
- Never log or persist a credential *value*; the downgrade reason uses the classification + a signal name, never a real high-entropy secret.
- Commit messages reference the spec: `docs/superpowers/specs/2026-07-16-validate-false-positive-reduction-design.md`.
- Work in worktree `.claude/worktrees/fp-reduction` (branch `fp-reduction`).

---

## Task 1: Deterministic secrets-triage classifier

**Files:**
- Create: `flosswing/secrets_triage.py`
- Test: `tests/unit/test_secrets_triage.py`

**Interfaces:**
- Produces: `classify_secret(file_path: str, evidence_text: str) -> SecretTriage`; `SecretTriage(BaseModel)` with fields `downgradeable: bool`, `classification: Literal["real","dev_default","placeholder","test_fixture"]`, `reason: str`.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_secrets_triage.py
"""secrets_triage.py: deterministic dev/placeholder secret classifier."""

from __future__ import annotations

import pytest

from flosswing.secrets_triage import classify_secret

# High-entropy 40-char value that must NEVER be downgraded in prod source.
_REAL = '"a9F3k1Lz8Qw2Rt7Yb4Xc6Vn0Ms5Pd3Hj1Gf9Kd2"'


@pytest.mark.parametrize(
    ("file_path", "evidence", "expect_downgrade"),
    [
        # Real triage examples -> downgradeable
        ("docker/docker-compose.yml", "ELASTIC_PASSWORD: devpass", True),
        ("docker/config.yml.template", "elastic:devpass@localhost", True),
        ("config.py", 'password = "Ch@ngeTh!sPa33w0rd"', True),
        ("assemblyline/common/config.py", 'key = "changeme"', True),
        ("test/docker-compose.yml", f"secret = {_REAL}", True),  # test path wins
        ("docker-compose.dev.yaml", "MINIO_SECRET_KEY: minioadmin", True),
        ("app.py", 'host = "http://user:pass@localhost:9200"', True),
        # Real secret in production source -> NOT downgradeable (guard)
        ("flosswing/prod.py", f"API_KEY = {_REAL}", False),
        ("assemblyline/service.py", f'token = {_REAL}', False),
    ],
)
def test_classify_secret_downgrade_decision(
    file_path: str, evidence: str, expect_downgrade: bool
) -> None:
    result = classify_secret(file_path, evidence)
    assert result.downgradeable is expect_downgrade


def test_classify_secret_never_emits_real_value() -> None:
    result = classify_secret("flosswing/prod.py", f"API_KEY = {_REAL}")
    assert "a9F3k1Lz" not in result.reason


def test_classify_secret_empty_evidence_uses_path_only() -> None:
    assert classify_secret("tests/fixtures/x.py", "").downgradeable is True
    assert classify_secret("flosswing/x.py", "").downgradeable is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd .claude/worktrees/fp-reduction && python -m pytest tests/unit/test_secrets_triage.py -q`
Expected: FAIL — `ModuleNotFoundError: flosswing.secrets_triage`.

- [ ] **Step 3: Write the implementation**

```python
# flosswing/secrets_triage.py
"""Deterministic post-verdict triage for hardcoded_secrets findings.

Pure, side-effect-free. The Validate stage uses this to downgrade a
`confirmed` hardcoded_secrets finding whose value is obviously a
dev/test default, placeholder, or vendor default — never a shipped
production secret.

Policy: strong-signal-required. Downgrade only when a high-confidence
dev signal is present AND there is no strong "real secret" counter-signal
(a high-entropy literal living in a production source path). This biases
toward *keeping* findings, so a real secret is never silently demoted.
"""

from __future__ import annotations

import math
import re
from pathlib import PurePosixPath
from typing import Final, Literal

from pydantic import BaseModel

Classification = Literal["real", "dev_default", "placeholder", "test_fixture"]

# Known placeholder / vendor-default substrings (matched lowercased).
_SENTINEL_VALUES: Final[frozenset[str]] = frozenset({
    "changeme", "change_me", "changeit", "changethis", "change-this",
    "password", "passw0rd", "admin", "secret", "minioadmin", "devpass",
    "example", "sample", "dummy", "placeholder", "your_", "notsecret",
    "insecure", "letmein",
})
_SENTINEL_WORD_RE: Final[re.Pattern[str]] = re.compile(
    r"change|example|sample|dummy|placeholder|dev[_-]?pass|test[_-]?pass",
    re.IGNORECASE,
)
_TEMPLATE_RE: Final[re.Pattern[str]] = re.compile(
    r"<[^>\n]+>|\$\{[^}\n]+\}|\{\{[^}\n]+\}\}"
)
_DEV_PATH_RE: Final[re.Pattern[str]] = re.compile(
    r"(^|/)(tests?|fixtures?|examples?|sample)s?(/|$)"
    r"|docker-compose[^/]*\.ya?ml$"
    r"|\.template$"
    r"|(^|/)ci(/|$)",
    re.IGNORECASE,
)
_LOCALHOST_RE: Final[re.Pattern[str]] = re.compile(
    r"localhost|127\.0\.0\.1|0\.0\.0\.0"
    r"|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+",
    re.IGNORECASE,
)
_LITERAL_RE: Final[re.Pattern[str]] = re.compile(r"""["'`]([^"'`\n]{6,})["'`]""")
_PROD_SRC_SUFFIXES: Final[frozenset[str]] = frozenset({
    ".py", ".go", ".rs", ".c", ".cpp", ".cc", ".h", ".hpp",
    ".java", ".js", ".jsx", ".ts", ".tsx",
})

_LOW_ENTROPY: Final[float] = 3.0
_HIGH_ENTROPY: Final[float] = 3.5


class SecretTriage(BaseModel):
    downgradeable: bool
    classification: Classification
    reason: str


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _max_literal_entropy(text: str) -> float:
    best = 0.0
    for m in _LITERAL_RE.finditer(text):
        best = max(best, _shannon_entropy(m.group(1)))
    return best


def _is_prod_source(file_path: str) -> bool:
    if _DEV_PATH_RE.search(file_path):
        return False
    return PurePosixPath(file_path).suffix.lower() in _PROD_SRC_SUFFIXES


def classify_secret(file_path: str, evidence_text: str) -> SecretTriage:
    """Classify a hardcoded_secrets finding's value context.

    `evidence_text` should be the finding's source span plus any poc_code;
    `file_path` is the repo-relative path. Pure — the caller does the read.
    """
    text = evidence_text or ""
    lower = text.lower()

    is_dev_path = bool(_DEV_PATH_RE.search(file_path))
    has_sentinel = any(v in lower for v in _SENTINEL_VALUES)
    has_word = bool(_SENTINEL_WORD_RE.search(text))
    has_template = bool(_TEMPLATE_RE.search(text))
    is_localhost = bool(_LOCALHOST_RE.search(text))
    max_entropy = _max_literal_entropy(text)
    low_entropy = max_entropy < _LOW_ENTROPY

    dev_signal = (
        has_sentinel or has_word or has_template
        or is_dev_path or (low_entropy and is_localhost)
    )
    # False-negative guard: never demote a high-entropy value in prod source.
    counter_signal = max_entropy >= _HIGH_ENTROPY and _is_prod_source(file_path)
    downgradeable = dev_signal and not counter_signal

    if is_dev_path:
        classification: Classification = "test_fixture"
        reason = "dev/test artifact path"
    elif has_template:
        classification = "placeholder"
        reason = "templated placeholder value"
    elif has_sentinel or has_word:
        classification = "placeholder"
        reason = "sentinel/placeholder value"
    elif is_localhost and low_entropy:
        classification = "dev_default"
        reason = "localhost low-entropy default"
    else:
        classification = "real"
        reason = "no dev signal"

    return SecretTriage(
        downgradeable=downgradeable, classification=classification, reason=reason
    )


__all__ = ["SecretTriage", "classify_secret"]
```

- [ ] **Step 4: Run tests + lint + types**

Run: `python -m pytest tests/unit/test_secrets_triage.py -q && ruff check flosswing/secrets_triage.py tests/unit/test_secrets_triage.py && mypy --strict flosswing/secrets_triage.py`
Expected: tests PASS, ruff clean, mypy clean.

- [ ] **Step 5: Commit**

```bash
git add flosswing/secrets_triage.py tests/unit/test_secrets_triage.py
git commit -m "Add secrets_triage classifier per false-positive-reduction spec § Part C"
```

---

## Task 2: Shared attack-class-fragment loader

**Files:**
- Create: `flosswing/prompts/__init__.py`
- Modify: `flosswing/stages/hunt.py` (remove local loader, import shared)
- Modify: `tests/unit/test_stages_hunt.py:385,390` (retarget to shared function)

**Interfaces:**
- Produces: `load_attack_class_fragment(attack_class: str) -> str` in `flosswing.prompts`.
- Consumes: nothing.

- [ ] **Step 1: Write the failing test**

```python
# Append to tests/unit/test_stages_hunt.py (top-level, after imports)
def test_shared_loader_returns_authored_fragment() -> None:
    from flosswing.prompts import load_attack_class_fragment

    assert "Attack class: command_injection" in load_attack_class_fragment(
        "command_injection"
    )


def test_shared_loader_falls_back_for_unauthored_class() -> None:
    from flosswing.prompts import load_attack_class_fragment

    assert "No attack-class-specific guidance" in load_attack_class_fragment(
        "buffer_overflow"
    )
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_stages_hunt.py::test_shared_loader_returns_authored_fragment -q`
Expected: FAIL — `ImportError: cannot import name 'load_attack_class_fragment'`.

- [ ] **Step 3: Create the shared loader**

```python
# flosswing/prompts/__init__.py
"""Prompt-asset loading shared across pipeline stages."""

from __future__ import annotations

from pathlib import Path
from typing import Final

_PROMPTS_ROOT: Final[Path] = Path(__file__).resolve().parent
_ATTACK_CLASS_DIR: Final[Path] = _PROMPTS_ROOT / "attack_classes"

_GENERIC_FRAGMENT_FALLBACK: Final[str] = (
    "No attack-class-specific guidance has been authored for "
    "`{attack_class}` yet. Apply general code-review principles for "
    "this class, lean toward `confidence='speculative'`, and stop "
    "after a single pass through the scope hint."
)


def load_attack_class_fragment(attack_class: str) -> str:
    """Load the per-attack-class prompt fragment, or a generic fallback."""
    p = _ATTACK_CLASS_DIR / f"{attack_class}.md"
    if p.exists():
        return p.read_text(encoding="utf-8")
    return _GENERIC_FRAGMENT_FALLBACK.format(attack_class=attack_class)


__all__ = ["load_attack_class_fragment"]
```

- [ ] **Step 4: Refactor `hunt.py` to use it**

In `flosswing/stages/hunt.py`:
1. Delete `_ATTACK_CLASS_DIR = ...` (line ~56), the `_GENERIC_FRAGMENT_FALLBACK = (...)` block (lines ~58-64), and the entire `_load_attack_class_fragment` function (lines ~96-106). Keep `_PROMPTS_ROOT` and `_HUNT_SYSTEM_PROMPT_PATH`.
2. Add import near the other `from flosswing...` imports:

```python
from flosswing.prompts import load_attack_class_fragment
```

3. In `_compose_user_prompt`, change:

```python
    fragment = _load_attack_class_fragment(task.attack_class)
```
to:
```python
    fragment = load_attack_class_fragment(task.attack_class)
```

- [ ] **Step 5: Retarget the two existing hunt tests**

In `tests/unit/test_stages_hunt.py` lines ~385 and ~390, replace `hunt._load_attack_class_fragment(` with `load_attack_class_fragment(` and add `from flosswing.prompts import load_attack_class_fragment` at the top of the file if not already present.

- [ ] **Step 6: Run tests + lint + types**

Run: `python -m pytest tests/unit/test_stages_hunt.py -q && ruff check flosswing/prompts/__init__.py flosswing/stages/hunt.py && mypy --strict flosswing/prompts/__init__.py flosswing/stages/hunt.py`
Expected: PASS, clean.

- [ ] **Step 7: Commit**

```bash
git add flosswing/prompts/__init__.py flosswing/stages/hunt.py tests/unit/test_stages_hunt.py
git commit -m "Lift attack-class fragment loader to shared flosswing.prompts (spec § Part A)"
```

---

## Task 3: `hardcoded_secrets` fragment + inject into Validate prompt

**Files:**
- Create: `flosswing/prompts/attack_classes/hardcoded_secrets.md`
- Modify: `flosswing/stages/validate.py` (`_compose_user_prompt`)
- Modify: `tests/unit/test_stages_validate.py` (assert prompt carries disqualifiers)

**Interfaces:**
- Consumes: `load_attack_class_fragment` (Task 2).

- [ ] **Step 1: Write the failing test**

```python
# Append to tests/unit/test_stages_validate.py
def test_validate_prompt_includes_hardcoded_secrets_disqualifiers() -> None:
    from flosswing.stages.validate import _compose_user_prompt
    from flosswing.state.models import Finding

    f = Finding(
        id="01F", run_id="01R", hunt_task_id="01H",
        attack_class="hardcoded_secrets", file="docker-compose.yml",
        line_start=1, line_end=1, severity="high", confidence="likely",
        status="pending_validation", title="t",
        description="d" * 60, created_at="2026-07-16T00:00:00Z",
    )
    prompt = _compose_user_prompt(f)
    assert "Disqualifiers" in prompt or "placeholder" in prompt.lower()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest "tests/unit/test_stages_validate.py::test_validate_prompt_includes_hardcoded_secrets_disqualifiers" -q`
Expected: FAIL — prompt has no fragment yet.

- [ ] **Step 3: Author the fragment**

```markdown
# flosswing/prompts/attack_classes/hardcoded_secrets.md
# Attack class: hardcoded_secrets

A credential — password, API key, token, private key, or connection
string — is embedded as a literal in source or config and would grant
access if it reached a running production system. The bug is a *shipped*
secret, not merely a string that looks like one.

## What qualifies

A literal credential that (a) is used as a real authentication value by
production code paths, and (b) is not overridden by operator
configuration or environment at deploy time. The finding must argue *how
the value reaches production* — which prod code reads it, and why a
deployment would not replace it.

## Disqualifiers — do NOT confirm at high/medium (report at `info` or reject)

- **Self-describing placeholders / vendor defaults:** `changeme`,
  `change_me`, `Ch@ngeTh!sPa33w0rd`, `devpass`, `password`, `admin`,
  `minioadmin`, `example`, `sample`, `<YOUR_...>`, `${...}` template
  markers. These are prompts to the operator, not secrets.
- **Low-entropy / dictionary-word values.** A real key is high-entropy;
  a short English word or obvious phrase is a default.
- **Localhost / private-range hosts** (`localhost`, `127.0.0.1`,
  RFC-1918). Dev-stack wiring, not a production credential.
- **Dev/test/example artifacts:** `test/`, `tests/`, `fixtures/`,
  `examples/`, `docker-compose*.yml`, `*.template`, CI config. These are
  not deployed.
- **Env-overridden defaults:** `os.environ.get("KEY", DEFAULT)` — the
  literal is a fallback the operator replaces; report the *missing
  fail-closed* as `info` at most, not a shipped secret.

## Evidence

A secret cannot be *executed*, so a PoC that merely re-prints the literal
is **non-probative** — do not treat it as confirmation. Confirmation
requires a deployment-reachability argument: the value is read by
production code and survives deployment. Absent that, prefer `info`
severity or `rejected`.
```

- [ ] **Step 4: Inject the fragment into the Validate prompt**

In `flosswing/stages/validate.py`, add import near other `from flosswing...` lines:

```python
from flosswing.prompts import load_attack_class_fragment
```

Then in `_compose_user_prompt`, append the fragment before the final return string. Replace the function's `return (...)` with:

```python
    fragment = load_attack_class_fragment(finding.attack_class)
    return (
        f"Finding under review:\n"
        f"  finding_id:   {finding.id}\n"
        f"  attack_class: {finding.attack_class}\n"
        f"  file:         {finding.file}\n"
        f"  function:     {finding.function or '<unknown>'}\n"
        f"  lines:        {finding.line_start}-{finding.line_end}\n"
        f"  severity:     {finding.severity}\n"
        f"  confidence:   {finding.confidence}\n"
        f"  title:        {finding.title}\n"
        "\n"
        "Description:\n"
        f"{finding.description}\n"
        "\n"
        f"PoC code (if any):\n"
        f"{finding.poc_code or '<none>'}\n"
        "\n"
        "---\n"
        "Attack-class guidance:\n"
        f"{fragment}\n"
    )
```

- [ ] **Step 5: Run tests + lint + types**

Run: `python -m pytest tests/unit/test_stages_validate.py -q && ruff check flosswing/stages/validate.py && mypy --strict flosswing/stages/validate.py`
Expected: PASS, clean.

- [ ] **Step 6: Commit**

```bash
git add flosswing/prompts/attack_classes/hardcoded_secrets.md flosswing/stages/validate.py tests/unit/test_stages_validate.py
git commit -m "Add hardcoded_secrets fragment + inject class guidance into Validate (spec § Part A)"
```

---

## Task 4: Circular-PoC discount (prompt prose)

**Files:**
- Modify: `flosswing/prompts/system/validate.md`
- Modify: `flosswing/prompts/system/hunt.md`
- Test: `tests/unit/test_prompt_guidance.py` (new; guards against accidental deletion)

**Interfaces:** none (prose).

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_prompt_guidance.py
"""Guards that key anti-false-positive guidance stays in the prompts."""

from __future__ import annotations

from pathlib import Path

_PROMPTS = Path(__file__).resolve().parent.parent.parent / "flosswing" / "prompts"


def test_validate_prompt_has_circular_poc_rule() -> None:
    text = (_PROMPTS / "system" / "validate.md").read_text(encoding="utf-8")
    assert "non-probative" in text
    assert "mocks the sink" in text or "re-implements" in text


def test_hunt_prompt_prefers_real_code_pocs() -> None:
    text = (_PROMPTS / "system" / "hunt.md").read_text(encoding="utf-8")
    assert "import" in text.lower() and "real" in text.lower()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_prompt_guidance.py -q`
Expected: FAIL — phrases absent.

- [ ] **Step 3: Edit `validate.md`**

In `flosswing/prompts/system/validate.md`, in the `## Encouraged investigation paths` section, immediately after the `**Run the PoC.**` paragraph (ends "...for `confirmed`."), insert:

```markdown
**A PoC that mocks the sink proves nothing.** Confirmation via
`compile_and_run` counts only when the PoC exercises the **real target
code** — it imports the repo module under review and drives the actual
function or class. A PoC that re-implements, mocks, or hand-rolls the
sink or a helper — defines its own copy of the vulnerable function,
hardcodes the "vulnerable" output, or reconstructs a sanitizer from
memory — is **non-probative**: its exit code describes the PoC's own
code, not the repo's. When the real module cannot be imported or run in
the sandbox (heavy dependencies, no install step), do **not** accept a
self-mocking PoC as evidence — use the reachability-argument path, or
return `uncertain`. This applies with special force to classes that
cannot be *executed* at all (e.g. `hardcoded_secrets`), where a PoC that
merely re-prints the literal confirms nothing.
```

- [ ] **Step 4: Edit `hunt.md`**

In `flosswing/prompts/system/hunt.md`, locate the guidance on writing `poc_code` for `record_finding` (search for `poc_code`). Add this bullet/sentence there:

```markdown
When you include `poc_code`, prefer a PoC that **imports and drives the
real target module** over a standalone reconstruction. A PoC that
re-implements the sink cannot be validated and will be discounted.
```

If no `poc_code` guidance paragraph exists, add the above as a new short paragraph under the section describing `record_finding`.

- [ ] **Step 5: Run test + lint**

Run: `python -m pytest tests/unit/test_prompt_guidance.py -q && ruff check tests/unit/test_prompt_guidance.py`
Expected: PASS, clean. (Markdown files are not linted.)

- [ ] **Step 6: Commit**

```bash
git add flosswing/prompts/system/validate.md flosswing/prompts/system/hunt.md tests/unit/test_prompt_guidance.py
git commit -m "Discount circular self-mocking PoCs in Validate/Hunt prompts (spec § Part B)"
```

---

## Task 5: Post-verdict downgrade gate in Validate stage

**Files:**
- Modify: `flosswing/stages/validate.py` (add logger, `_read_source_span`, `_maybe_downgrade_secret`, call in confirmed branch)
- Modify: `tests/unit/test_stages_validate.py` (gate behavior test)

**Interfaces:**
- Consumes: `classify_secret` (Task 1); `run(..., repo: Path, ...)` already has `repo`.
- Produces: `_maybe_downgrade_secret(finding_id: str, repo: Path) -> None`.

- [ ] **Step 1: Write the failing test**

```python
# Append to tests/unit/test_stages_validate.py
def test_gate_downgrades_dev_default_secret(tmp_path: Path) -> None:
    from flosswing.stages.validate import _maybe_downgrade_secret
    from flosswing.state.models import Finding

    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  es:\n    environment:\n      ELASTIC_PASSWORD: devpass\n",
        encoding="utf-8",
    )
    with st_session.session_scope() as s:
        s.add(Finding(
            id="01SEC", run_id="01R", hunt_task_id="01H",
            attack_class="hardcoded_secrets", file="docker-compose.yml",
            line_start=4, line_end=4, severity="high", confidence="likely",
            status="confirmed", title="t", description="d" * 60,
            created_at="2026-07-16T00:00:00Z",
        ))

    _maybe_downgrade_secret("01SEC", tmp_path)

    with st_session.session_scope() as s:
        f = s.get(Finding, "01SEC")
        assert f is not None
        assert f.severity == "info"
        assert f.status == "confirmed"  # never changes status
        assert "secrets_triage" in (f.root_cause_summary or "")


def test_gate_leaves_real_secret_and_other_classes(tmp_path: Path) -> None:
    from flosswing.stages.validate import _maybe_downgrade_secret
    from flosswing.state.models import Finding

    (tmp_path / "prod.py").write_text(
        'API_KEY = "a9F3k1Lz8Qw2Rt7Yb4Xc6Vn0Ms5Pd3Hj1Gf9Kd2"\n', encoding="utf-8"
    )
    with st_session.session_scope() as s:
        s.add(Finding(
            id="01REAL", run_id="01R", hunt_task_id="01H",
            attack_class="hardcoded_secrets", file="prod.py",
            line_start=1, line_end=1, severity="high", confidence="likely",
            status="confirmed", title="t", description="d" * 60,
            created_at="2026-07-16T00:00:00Z",
        ))
        s.add(Finding(
            id="01SQLI", run_id="01R", hunt_task_id="01H",
            attack_class="sqli", file="docker-compose.yml",
            line_start=1, line_end=1, severity="high", confidence="likely",
            status="confirmed", title="t", description="d" * 60,
            created_at="2026-07-16T00:00:00Z",
        ))

    _maybe_downgrade_secret("01REAL", tmp_path)
    _maybe_downgrade_secret("01SQLI", tmp_path)

    with st_session.session_scope() as s:
        assert s.get(Finding, "01REAL").severity == "high"
        assert s.get(Finding, "01SQLI").severity == "high"
```

Note: these tests rely on the module's existing in-memory `fresh_db`/`FLOSSWING_DB_URL` fixture pattern — reuse whatever autouse/fixture `test_stages_validate.py` already uses to seed `runs`; if `_seed_run_with_findings` is the seeding helper, call it or set `FLOSSWING_DB_URL=sqlite:///:memory:` as the other tests do. Insert a matching `Run` row first if the FK requires it (mirror `_seed_run_with_findings`).

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest "tests/unit/test_stages_validate.py::test_gate_downgrades_dev_default_secret" -q`
Expected: FAIL — `ImportError: cannot import name '_maybe_downgrade_secret'`.

- [ ] **Step 3: Implement the gate in `validate.py`**

Add near the top imports:

```python
import logging
```
and after imports:
```python
logger = logging.getLogger(__name__)
```
Add import with the other `from flosswing...` lines:
```python
from flosswing.secrets_triage import classify_secret
```
Add these helpers above `async def run(`:

```python
def _read_source_span(repo: Path, file: str, line_start: int, line_end: int) -> str:
    try:
        lines = (repo / file).read_text(
            encoding="utf-8", errors="replace"
        ).splitlines()
    except OSError:
        return ""
    lo = max(line_start - 1, 0)
    hi = min(line_end, len(lines))
    return "\n".join(lines[lo:hi])


def _maybe_downgrade_secret(finding_id: str, repo: Path) -> None:
    """Downgrade a confirmed hardcoded_secrets dev/placeholder to info.

    Post-verdict gate: never drops, never changes status, never touches
    other attack classes. Fails open — any error leaves the verdict as-is.
    """
    with st_session.session_scope() as s:
        finding = s.get(Finding, finding_id)
        if (
            finding is None
            or finding.attack_class != "hardcoded_secrets"
            or finding.status != "confirmed"
            or finding.severity == "info"
        ):
            return
        span = _read_source_span(
            repo, finding.file, finding.line_start, finding.line_end
        )
        evidence = f"{span}\n{finding.poc_code or ''}"
        try:
            triage = classify_secret(finding.file, evidence)
        except Exception:  # noqa: BLE001 - gate must fail open, never crash stage
            logger.exception("secrets_triage failed for finding %s", finding_id)
            return
        if not triage.downgradeable:
            return
        finding.severity = "info"
        finding.root_cause_summary = (finding.root_cause_summary or "") + (
            f"\n[secrets_triage: {triage.classification} — {triage.reason}; "
            "dev/placeholder value, not a shipped production secret]"
        )
```

- [ ] **Step 4: Call the gate in the confirmed branch**

In `run()`, in the outcome-classification block, change:

```python
            elif verdict == "confirmed":
                findings_confirmed += 1
```
to:
```python
            elif verdict == "confirmed":
                findings_confirmed += 1
                _maybe_downgrade_secret(finding_id, repo)
```

- [ ] **Step 5: Run tests + lint + types**

Run: `python -m pytest tests/unit/test_stages_validate.py -q && ruff check flosswing/stages/validate.py tests/unit/test_stages_validate.py && mypy --strict flosswing/stages/validate.py`
Expected: PASS, clean.

- [ ] **Step 6: Commit**

```bash
git add flosswing/stages/validate.py tests/unit/test_stages_validate.py
git commit -m "Add post-verdict secrets downgrade gate to Validate (spec § Part C)"
```

---

## Task 6: Full verification

- [ ] **Step 1: Whole suite + lint + types**

Run: `python -m pytest tests/unit -q && ruff check flosswing tests && mypy --strict flosswing`
Expected: all PASS, clean.

- [ ] **Step 2: Prompt-change eval (manual, gated)**

Per CLAUDE.md, prompt changes (Tasks 3–4) require `flosswing eval` against `tests/corpus/` before merge. This hits the real API and is not in CI. Run:

`FLOSSWING_INTEGRATION=1 flosswing eval` (or the operator's documented eval invocation)

Confirm no recall regression on known-CVE ground truth and that dev-default secrets now land at `info`. Record the delta in the PR description. **Do not merge Tasks 3–4 without this.**

- [ ] **Step 3: Finish the branch**

Use `superpowers:finishing-a-development-branch` to open a PR from `fp-reduction`, referencing the spec and this plan.

---

## Self-Review (completed)

- **Spec coverage:** Part A → Tasks 2+3; Part B → Task 4; Part C → Tasks 1+5. Testing → Tasks 1,3,4,5 + Task 6. All covered.
- **Placeholder scan:** none — every code step has full code.
- **Type consistency:** `classify_secret(file_path, evidence_text) -> SecretTriage` used identically in Task 1 and Task 5; `load_attack_class_fragment(attack_class) -> str` used identically in Tasks 2/3; `_maybe_downgrade_secret(finding_id, repo)` signature matches call site.
