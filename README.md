# FlossWing

A local-CLI vulnerability research harness. Point it at a cloned
open-source repository and it runs a multi-stage LLM-agent pipeline
that produces a ranked list of confirmed vulnerabilities with
reproduction PoCs and in-repo reachability analysis.

Inspired by Cloudflare's Project Glasswing harness, adapted for
single-developer, single-repo, BYO-API-key use.

> **Status:** v1 — the eight-stage pipeline (Recon → Hunt → Validate
> → Gapfill → Dedupe → Trace → Report) ships and writes operator-
> facing output. See [ARCHITECTURE.md](ARCHITECTURE.md) for the full
> design and what's deferred to v2.

## What FlossWing is NOT

These are hard non-goals — see [ARCHITECTURE.md § "What FlossWing is
NOT"](ARCHITECTURE.md#what-flosswing-is-not) for the full list.

- Not a service. Local CLI only.
- Not a coding agent. FlossWing never modifies the target repository.
- Not an autonomous discloser. No telemetry, no email, no GitHub
  comments. Disclosure drafts go to stdout for the operator.
- Not a cross-repo system in v1. Reachability traces stop at the
  repo boundary.

## Requirements

- **Python 3.11+**
- **Docker** (primary sandbox backend; Firejail is the fallback).
- One of:
  - `ANTHROPIC_API_KEY` env var, OR
  - `ANTHROPIC_FOUNDRY_API_KEY` env var (Microsoft Foundry routing,
    plus `ANTHROPIC_FOUNDRY_RESOURCE`, `CLAUDE_CODE_USE_FOUNDRY=1`),
    OR
  - A valid `az login` session.
- The target repo cloned locally.

## Install

```bash
git clone https://github.com/litobro/FlossWing.git
cd FlossWing
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
```

## Usage

### Scan a repo

```bash
flosswing scan ./path/to/target-repo
```

This runs the full pipeline and, on success, writes a report
automatically. Output lands in
`~/.flosswing/runs/<run_id>/output/`:

- `report.md` — markdown report, findings ordered by severity then
  reachability.
- `report.json` — `ReportV1` Pydantic projection with
  `schema_version: "1.0"`.
- `findings/<id>/` — per-confirmed-finding directory containing
  `finding.md` (the bug write-up) and `poc.py` (the reproduction
  PoC, when one exists).

State (`runs`, `findings`, `agent_sessions`, etc.) is persisted to
`~/.flosswing/state.db` — a SQLite database you can inspect with
`sqlite3` directly.

### Re-render a previous run

```bash
flosswing report <run_id>
```

Re-renders the operator-facing output from the state DB. Useful
after `--no-report`, or after a render failure during the scan.

### Common flags

| Flag | Default | Description |
|------|---------|-------------|
| `--no-report` | (off) | Skip end-of-scan auto-render. |
| `--format md,json,sarif` | `md,json` | Pick output formats. `sarif` writes a v1.1 placeholder file. |
| `--output-dir DIR` | `~/.flosswing/runs/<run_id>/output/` | Override the output location. |
| `--recon-token-budget INT` | 100 000 | Per-session input-token cap. Similar flags for `hunt`, `validate`, `gapfill`, `dedupe`, `trace`. |
| `--trace-max-depth INT` | 8 | `find_callers` walk depth before Trace emits `uncertain`. |

`flosswing --help` lists everything.

## Where things live

- **State DB**: `~/.flosswing/state.db`
- **Run scratch dirs**: `~/.flosswing/runs/<run_id>/`
- **Per-run output**: `~/.flosswing/runs/<run_id>/output/`
- **Target repo**: read-only, untouched.

The target repo is treated as **untrusted input** — READMEs,
comments, and source files may contain prompt-injection content.
FlossWing handles this defensively at every stage.

## Project documentation

Operator-curated source-of-truth docs:

- **[ARCHITECTURE.md](ARCHITECTURE.md)** — pipeline stages, component
  boundaries, threat model summary, v1/v2 split.
- **[docs/tool-contracts.md](docs/tool-contracts.md)** — frozen
  agent-facing tool API. Input/output Pydantic models, tool scope
  matrix per stage, error semantics.
- **[docs/schema.sql](docs/schema.sql)** — canonical reference for
  the SQLite state schema.
- **[CLAUDE.md](CLAUDE.md)** — instructions for AI agents (Claude
  Code, etc.) editing this codebase.

## Development

```bash
# Lint + type-check (CI runs both)
ruff check .
mypy --strict flosswing

# Unit tests
pytest tests/unit

# Integration smoke (consumes API credit; gated)
FLOSSWING_INTEGRATION=1 pytest tests/integration
```

CI runs on Python 3.11. The `tree-sitter` grammar bindings pinned in
`pyproject.toml` are 3.11-compatible; newer Python versions may
require local-only grammar fixups.

## License

GNU General Public License v3.0 or later (GPL-3.0-or-later). See
[LICENSE](LICENSE) for the full text.
