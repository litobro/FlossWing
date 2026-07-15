# FlossWing — local-CLI vulnerability research harness.
# Copyright (C) 2026  FlossWing contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Report stage — deterministic SQLite-to-files renderer.

Per docs/specs/2026-06-02-v1.0-report-design.md (approved 2026-06-04) and
ARCHITECTURE.md § Stage 8 (Report). This module is **deterministic, no
agent, no SDK calls**: it loads the run's rows via a single
``session_scope()`` block, projects them into the operator-facing
``ReportV1`` Pydantic model, and writes ``report.md``, ``report.json``,
and per-finding directories under ``output_dir``.

Spec § Architecture, § JSON schema — ReportV1, § Markdown rendering,
§ Per-finding directories, § Determinism, § Graceful degradation.

Escape strategy (applies to user-controlled strings — repo contents,
descriptions, PoC source — that flow through this module unchanged from
``findings`` rows):

- **Inside code fences:** literal triple-backtick sequences in the
  content are rewritten to triple single-quotes so the user cannot close
  the fence prematurely and inject markdown.
- **Outside code fences (titles, descriptions, suggested fixes):** runs
  through ``html.escape`` to neutralise ``<``, ``>``, ``&`` (defence in
  depth — most markdown viewers do not render HTML, but the JSON output
  is consumed by other tools that may). Additionally, lines that begin
  with ``#`` are prefixed with ``\\`` so untrusted text cannot inject a
  new markdown header into our document outline.
- **Table cells** (file paths, function names) replace ``|`` with
  ``\\|`` and newlines with spaces, then truncate to 200 chars with a
  ``…`` suffix if longer.

Per spec § Security considerations: ``description`` / ``poc_code`` /
``suggested_fix`` are not credential-scrubbed by Report — that would
corrupt the operator's view of the finding. Credential scrubbing is the
upstream stage's job (see ``flosswing.errors.scrub``).
"""

from __future__ import annotations

import html
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from flosswing.errors import RunNotFoundError
from flosswing.state import session as st_session
from flosswing.state.models import (
    DedupeCluster,
    Finding,
    Run,
    Trace,
    Validation,
)

SessionFactory = sessionmaker[Session]

# Ordering tables (per spec § Determinism, § Markdown rendering)

# Severity rank: critical highest, info lowest. Anything outside this set
# sorts after "info" but stays stable on its string value.
_SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}
_SEVERITY_DISPLAY: tuple[str, ...] = ("critical", "high", "medium", "low", "info")

# Reachability rank within a severity group: reachable first, unknown last.
# Per spec Q#3 resolution: severity first, then reachability.
_REACHABLE_ORDER: dict[str | None, int] = {
    "reachable": 0,
    "uncertain": 1,
    "unreachable": 2,
    None: 3,
}
_REACHABLE_DISPLAY: tuple[str | None, ...] = (
    "reachable",
    "uncertain",
    "unreachable",
    None,
)
_REACHABLE_LABEL: dict[str | None, str] = {
    "reachable": "Reachable",
    "uncertain": "Reachability uncertain",
    "unreachable": "Unreachable",
    None: "Reachability not analyzed",
}

# Max length for a markdown table cell before truncation (spec
# § Security considerations).
_TABLE_CELL_MAX: int = 200


# ---------------------------------------------------------------------------
# Pydantic models — operator-facing public schema (NOT subject to the frozen
# tool-contracts.md guarantee, but stable under schema_version "1.0").
# ---------------------------------------------------------------------------


class ReportRun(BaseModel):
    id: str
    target_repo_path: str
    status: str
    started_at: str
    finished_at: str | None
    exit_code: int | None
    # DEPRECATED in schema 1.x: ``budget_total`` is a legacy default-valued
    # column on the ``runs`` table (literal ``20``) and does NOT represent
    # the run's actual per-stage budget caps. Consumers should ignore this
    # field; the canonical per-stage budgets live in
    # ``config.recon_token_budget``, ``config.hunt_token_budget``, etc. The
    # field stays in the JSON schema to keep ``schema_version: "1.0"``
    # backward-compatible; it will be removed in ``schema_version: "2.0"``.
    budget_total: int
    budget_used: int
    model: str
    config: dict[str, Any]


class ReportSummary(BaseModel):
    findings_total: int
    findings_confirmed: int
    findings_uncertain: int
    findings_rejected: int
    findings_pending: int
    findings_superseded: int
    by_severity: dict[str, int]
    by_attack_class: dict[str, int]
    clusters_total: int
    traces_total: int
    reachable_total: int


class ReportValidation(BaseModel):
    verdict: str
    rationale: str
    validated_at: str
    agent_session_id: str


class ReportTrace(BaseModel):
    reachable: str
    entry_point_symbol: str | None
    call_chain: list[dict[str, Any]]
    rationale: str


class ReportDedupeCluster(BaseModel):
    id: str
    primary_finding_id: str
    member_count: int
    root_cause_summary: str


class ReportFinding(BaseModel):
    id: str
    attack_class: str
    file: str
    function: str | None
    line_start: int
    line_end: int
    severity: str
    confidence: str
    status: str
    title: str
    description: str
    poc_code: str | None
    suggested_fix: str | None
    created_at: str
    validation: ReportValidation | None = None
    dedupe_cluster_id: str | None = None
    dedupe_role: str | None = None
    primary_finding_id: str | None = None
    trace: ReportTrace | None = None
    reachable: str | None = None


class ReportV1(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    rendered_at: str
    run: ReportRun
    summary: ReportSummary
    findings: list[ReportFinding]
    dedupe_clusters: list[ReportDedupeCluster]


@dataclass(frozen=True)
class ReportRenderResult:
    formats_written: list[str]
    findings_dirs_written: int
    output_dir: Path
    bytes_written: int
    sarif_skipped: bool


# Loader — single session_scope() snapshotting all relevant rows.


def _now_iso() -> str:
    """ISO-8601 UTC with the ``Z`` suffix conventional in this codebase."""
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _parse_config_json(raw: str) -> dict[str, Any]:
    """Parse ``runs.config_json``. CHECK constraint guarantees JSON;
    return ``{}`` on any parse anomaly (graceful degradation)."""
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _parse_call_chain(raw: str) -> list[dict[str, Any]]:
    """Parse ``traces.call_chain_json``. CHECK constraint guarantees a
    JSON array of objects; return ``[]`` on any parse anomaly."""
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return []
    if not isinstance(parsed, list):
        return []
    return [step for step in parsed if isinstance(step, dict)]


def _resolve_model(config: dict[str, Any]) -> str:
    """``runs.model`` lives inside config_json; "" if missing."""
    model = config.get("model")
    return model if isinstance(model, str) else ""


def _build_validation(v: Validation | None) -> ReportValidation | None:
    if v is None:
        return None
    return ReportValidation(
        verdict=v.verdict, rationale=v.rationale,
        validated_at=v.created_at, agent_session_id=v.agent_session_id,
    )


def _build_trace(t: Trace | None) -> ReportTrace | None:
    if t is None:
        return None
    return ReportTrace(
        reachable=t.reachable, entry_point_symbol=t.entry_point_symbol,
        call_chain=_parse_call_chain(t.call_chain_json), rationale=t.rationale,
    )


def _finding_sort_key(f: ReportFinding) -> tuple[int, int, str]:
    """Severity desc, reachability order, then ULID ascending."""
    return (
        _SEVERITY_ORDER.get(f.severity, len(_SEVERITY_ORDER)),
        _REACHABLE_ORDER.get(f.reachable, len(_REACHABLE_ORDER)),
        f.id,
    )


def _load(run_id: str, session_factory: SessionFactory) -> ReportV1:
    """Project current DB state for ``run_id`` into a ``ReportV1``.

    Single ``session_scope()`` block; all ORM attributes are snapshotted
    into the Pydantic models before the scope closes. ``RunNotFoundError``
    is raised if the runs row does not exist.

    Graceful degradation (spec § Graceful degradation): missing Validate,
    Trace, or Dedupe rows project to ``None`` / ``[]`` — never an error.
    """
    # session_factory is accepted for API symmetry with the other stages
    # (and so callers can inject a test sessionmaker), but we delegate to
    # the module-level session_scope() helper which uses the process-wide
    # cached factory. In tests, callers set FLOSSWING_DB_URL before
    # touching either path.
    del session_factory

    with st_session.session_scope() as s:
        run = s.get(Run, run_id)
        if run is None:
            raise RunNotFoundError(f"no run with id {run_id!r} in state.db")

        config = _parse_config_json(run.config_json)
        # runs table has no exit_code column in v1.0; surface as None.
        run_model = ReportRun(
            id=run.id, target_repo_path=run.target_repo_path, status=run.status,
            started_at=run.started_at, finished_at=run.finished_at,
            exit_code=None, budget_total=run.budget_total,
            budget_used=run.budget_used, model=_resolve_model(config),
            config=config,
        )

        # ULID ascending = creation order — stable baseline before sorting.
        finding_rows = list(
            s.execute(
                select(Finding).where(Finding.run_id == run_id).order_by(Finding.id)
            ).scalars()
        )
        finding_ids = [f.id for f in finding_rows]

        # LEFT JOIN semantics: missing rows project to None.
        validations_by_finding: dict[str, Validation] = (
            {
                v.finding_id: v
                for v in s.execute(
                    select(Validation).where(Validation.finding_id.in_(finding_ids))
                ).scalars()
            }
            if finding_ids
            else {}
        )
        traces_by_finding: dict[str, Trace] = (
            {
                t.finding_id: t
                for t in s.execute(
                    select(Trace).where(Trace.finding_id.in_(finding_ids))
                ).scalars()
            }
            if finding_ids
            else {}
        )

        report_findings = [
            ReportFinding(
                id=f.id, attack_class=f.attack_class, file=f.file,
                function=f.function, line_start=f.line_start,
                line_end=f.line_end, severity=f.severity,
                confidence=f.confidence, status=f.status, title=f.title,
                description=f.description, poc_code=f.poc_code,
                suggested_fix=f.suggested_fix, created_at=f.created_at,
                validation=_build_validation(validations_by_finding.get(f.id)),
                dedupe_cluster_id=f.dedupe_cluster_id,
                dedupe_role=f.dedupe_role,
                primary_finding_id=f.primary_finding_id,
                trace=_build_trace(traces_by_finding.get(f.id)),
                reachable=f.reachable,
            )
            for f in finding_rows
        ]
        report_findings.sort(key=_finding_sort_key)

        report_clusters = [
            ReportDedupeCluster(
                id=c.id, primary_finding_id=c.primary_finding_id,
                member_count=c.member_count, root_cause_summary=c.root_cause_summary,
            )
            for c in s.execute(
                select(DedupeCluster)
                .where(DedupeCluster.run_id == run_id)
                .order_by(DedupeCluster.id)
            ).scalars()
        ]

    # ----- Summary projection (counts; no further DB access needed) -----
    by_severity: dict[str, int] = {}
    by_attack_class: dict[str, int] = {}
    status_counts: dict[str, int] = {}
    reachable_total = 0
    traces_total = 0
    for rf in report_findings:
        by_severity[rf.severity] = by_severity.get(rf.severity, 0) + 1
        by_attack_class[rf.attack_class] = by_attack_class.get(rf.attack_class, 0) + 1
        status_counts[rf.status] = status_counts.get(rf.status, 0) + 1
        if rf.reachable == "reachable":
            reachable_total += 1
        if rf.trace is not None:
            traces_total += 1

    summary = ReportSummary(
        findings_total=len(report_findings),
        findings_confirmed=status_counts.get("confirmed", 0),
        findings_uncertain=status_counts.get("uncertain", 0),
        findings_rejected=status_counts.get("rejected", 0),
        findings_pending=status_counts.get("pending_validation", 0),
        findings_superseded=status_counts.get("superseded", 0),
        by_severity=by_severity, by_attack_class=by_attack_class,
        clusters_total=len(report_clusters), traces_total=traces_total,
        reachable_total=reachable_total,
    )

    return ReportV1(
        rendered_at=_now_iso(), run=run_model, summary=summary,
        findings=report_findings, dedupe_clusters=report_clusters,
    )


def load_report(run_id: str, session_factory: SessionFactory) -> ReportV1:
    """Public entry point for the operator-facing ReportV1 projection.

    Stable wrapper over :func:`_load` for callers outside the Report stage
    (e.g. the eval runner).

    ``session_factory`` is accepted for signature symmetry with the other
    stage entry points (see :func:`render` and :func:`_load`), but is
    currently **ignored**: the loader reads from the process-wide state DB
    selected by ``FLOSSWING_DB_URL`` via ``session_scope()``. Tests target an
    alternate DB by setting that env var and resetting the cached engine, not
    by passing a factory here.
    """
    return _load(run_id, session_factory)


# Escape helpers — see module docstring for the strategy.


def _escape_inline(text: str) -> str:
    """Escape user-controlled text for safe inclusion outside code fences.

    1. HTML-escape ``<``, ``>``, ``&``.
    2. Prefix any line starting with ``#`` (after HTML escape) with ``\\``
       to prevent unexpected markdown headers.
    """
    if not text:
        return ""
    escaped = html.escape(text, quote=False)
    lines = escaped.splitlines()
    out_lines: list[str] = []
    for line in lines:
        stripped = line.lstrip()
        if stripped.startswith("#"):
            # Preserve leading whitespace if any.
            leading = line[: len(line) - len(stripped)]
            out_lines.append(f"{leading}\\{stripped}")
        else:
            out_lines.append(line)
    return "\n".join(out_lines)


def _escape_table_cell(text: str | None) -> str:
    """Escape a cell value: replace ``|`` and newlines, truncate to
    _TABLE_CELL_MAX chars with a single-char ellipsis suffix."""
    if text is None:
        return ""
    flat = text.replace("\n", " ").replace("|", "\\|")
    if len(flat) > _TABLE_CELL_MAX:
        flat = flat[: _TABLE_CELL_MAX - 1] + "…"
    return flat


def _fence_safe(content: str) -> str:
    """Make ``content`` safe for inclusion inside a triple-backtick code
    fence: rewrite any literal triple-backtick to triple single-quote so
    the fence cannot be closed prematurely by attacker-controlled text."""
    if not content:
        return ""
    return content.replace("```", "'''")


# Markdown rendering — pure-string assembly, no template engine.


# Markdown code-fence language tag by file extension. Empty string when
# unknown — yields a plain ``` fence, which is fine.
_LANG_HINT: dict[str, str] = {
    "py": "python", "c": "c", "h": "c", "cc": "cpp", "cpp": "cpp",
    "hpp": "cpp", "cxx": "cpp", "go": "go", "rs": "rust",
    "ts": "typescript", "tsx": "tsx", "js": "javascript", "jsx": "jsx",
    "java": "java", "rb": "ruby", "sh": "bash",
}


def _lang_hint_for(file_path: str) -> str:
    return _LANG_HINT.get(Path(file_path).suffix.lower().lstrip("."), "")


# Source-file extensions to preserve on the per-finding poc.<ext>
# filename. Languages we don't recognise fall back to ``.txt`` so the
# file always has a non-empty extension. .tsx/.jsx normalise to .ts/.js
# respectively — the language is the same, the JSX is a syntactic
# superset, and operators expect ``poc.ts`` not ``poc.tsx``.
_POC_EXT_BY_SOURCE_EXT: dict[str, str] = {
    "py": ".py", "c": ".c", "h": ".c", "cc": ".cpp", "cpp": ".cpp",
    "hpp": ".cpp", "cxx": ".cpp", "go": ".go", "rs": ".rs",
    "ts": ".ts", "tsx": ".ts", "js": ".js", "mjs": ".js", "cjs": ".js",
    "jsx": ".js", "java": ".java",
}


def _poc_extension_for(source_file_path: str) -> str:
    """Pick the PoC filename extension for a finding's source file.

    The poc file content is whatever the Hunt agent produced as
    ``poc_code``; the extension just needs to match the language so
    syntax highlighters and copy-paste workflows do the right thing.
    Unknown source extensions fall back to ``.txt`` rather than no
    extension at all.
    """
    suffix = Path(source_file_path).suffix.lower().lstrip(".")
    return _POC_EXT_BY_SOURCE_EXT.get(suffix, ".txt")


def _render_run_header(run: ReportRun) -> str:
    # Under Foundry mode `model` is a tier alias (e.g. claude-opus-4-7); the
    # deployment inference actually ran on is recorded in config_json. Surface
    # it next to the alias so the header isn't misleading. Absent = direct mode.
    model_cell = _escape_table_cell(run.model)
    deployment = run.config.get("foundry_deployment")
    if isinstance(deployment, str) and deployment:
        model_cell = f"{model_cell} (foundry deployment: {_escape_table_cell(deployment)})"
    rows = [
        ("target_repo_path", _escape_table_cell(run.target_repo_path)),
        ("status", _escape_table_cell(run.status)),
        ("started_at", _escape_table_cell(run.started_at)),
        ("finished_at", _escape_table_cell(run.finished_at or "")),
        # `Run.budget_total` is a legacy default-valued column (literal
        # 20) and not the actual per-stage budget cap, so showing
        # "<used> / <budget_total>" mis-conveys "20 tokens budgeted".
        # Render just the used count; per-stage caps are in
        # `runs.config_json` for operators who want to compute headroom.
        ("budget_used", f"{run.budget_used} tokens"),
        ("model", model_cell),
    ]
    lines = ["| Field | Value |", "| --- | --- |"]
    lines.extend(f"| {k} | {v} |" for k, v in rows)
    return "\n".join(lines)


def _render_count_table(
    header: str, counts: dict[str, int], canonical_order: tuple[str, ...] = ()
) -> list[str]:
    """Render a two-column count table; canonical_order entries appear
    first in the given order, then any extra keys alphabetically."""
    if not counts:
        return ["_No findings._"]
    out = [f"| {header} | Count |", "| --- | --- |"]
    seen = set(counts)
    for k in canonical_order:
        if k in seen:
            out.append(f"| {k} | {counts[k]} |")
            seen.discard(k)
    for k in sorted(seen):
        out.append(f"| {_escape_table_cell(k)} | {counts[k]} |")
    return out


def _render_summary(summary: ReportSummary) -> str:
    lines: list[str] = [
        "## Summary",
        "",
        f"- **Total findings:** {summary.findings_total}",
        f"- Confirmed: {summary.findings_confirmed}",
        f"- Uncertain: {summary.findings_uncertain}",
        f"- Pending validation: {summary.findings_pending}",
        f"- Rejected: {summary.findings_rejected}",
        f"- Superseded: {summary.findings_superseded}",
        f"- Reachable: {summary.reachable_total}",
        f"- Traces recorded: {summary.traces_total}",
        f"- Dedupe clusters: {summary.clusters_total}",
        "",
        "### By severity",
        "",
    ]
    lines += _render_count_table("Severity", summary.by_severity, _SEVERITY_DISPLAY)
    lines += ["", "### By attack class", ""]
    lines += _render_count_table("Attack class", summary.by_attack_class)
    return "\n".join(lines)


def _finding_badges(f: ReportFinding) -> list[str]:
    badges = [
        f"severity: {f.severity}",
        f"confidence: {f.confidence}",
        f"status: {f.status}",
    ]
    if f.reachable is not None:
        badges.append(f"reachable: {f.reachable}")
    if f.dedupe_role is not None:
        badges.append(f"dedupe: {f.dedupe_role}")
    return badges


def _finding_location(f: ReportFinding) -> str:
    location = f"`{_escape_table_cell(f.file)}`:{f.line_start}-{f.line_end}"
    if f.function:
        location += f" — `{_escape_table_cell(f.function)}`"
    return location


def _render_finding_section(f: ReportFinding) -> str:
    """Render a single finding as a level-4 markdown section."""
    # UNCERTAIN findings carry an explicit badge in the title per spec
    # Q#4 resolution.
    title_prefix = "[uncertain] " if f.status == "uncertain" else ""
    badges = _finding_badges(f)
    lines = [
        f"#### {title_prefix}{_escape_inline(f.title)}",
        "",
        f"- **id:** `{f.id}`",
        f"- **attack class:** {_escape_inline(f.attack_class)}",
        f"- **location:** {_finding_location(f)}",
        f"- **badges:** {', '.join(badges)}",
        "",
        "**Description:**",
        "",
        _escape_inline(f.description),
        "",
    ]
    if f.poc_code:
        lang = _lang_hint_for(f.file)
        fence_open = f"```{lang}" if lang else "```"
        lines += [
            "**Proof-of-concept (not executed by Report):**",
            "",
            fence_open,
            _fence_safe(f.poc_code),
            "```",
            "",
        ]
    if f.validation is not None:
        v = f.validation
        lines += [
            "**Validation:**",
            "",
            f"- verdict: {v.verdict}",
            f"- validated_at: {v.validated_at}",
            f"- agent_session_id: `{v.agent_session_id}`",
            "",
            _escape_inline(v.rationale),
            "",
        ]
    if f.trace is not None:
        t = f.trace
        ep = t.entry_point_symbol or "(none)"
        lines += [
            "**Trace:**",
            "",
            f"- reachable: {t.reachable}",
            f"- entry point: `{_escape_table_cell(ep)}`",
            f"- call chain length: {len(t.call_chain)}",
            "",
            _escape_inline(t.rationale),
            "",
        ]
    if f.suggested_fix:
        lines += [
            "**Suggested fix:**",
            "",
            _escape_inline(f.suggested_fix),
            "",
        ]
    return "\n".join(lines)


def _render_findings_sections(findings: list[ReportFinding]) -> str:
    """Group findings by severity (descending), then by reachability."""
    out: list[str] = ["## Findings", ""]
    if not findings:
        out.append("_No findings._")
        return "\n".join(out)

    by_severity: dict[str, list[ReportFinding]] = {}
    for f in findings:
        by_severity.setdefault(f.severity, []).append(f)

    # Canonical severity order first, then any extras alphabetically.
    seen_sevs = set(by_severity)
    severities_in_order = [s for s in _SEVERITY_DISPLAY if s in seen_sevs]
    severities_in_order += sorted(seen_sevs - set(_SEVERITY_DISPLAY))

    for sev in severities_in_order:
        sev_findings = by_severity[sev]
        out += [f"### Severity: {sev} ({len(sev_findings)})", ""]
        by_reach: dict[str | None, list[ReportFinding]] = {}
        for f in sev_findings:
            by_reach.setdefault(f.reachable, []).append(f)
        for reach in _REACHABLE_DISPLAY:
            group = by_reach.get(reach, [])
            if not group:
                continue
            out += [f"#### {_REACHABLE_LABEL[reach]} ({len(group)})", ""]
            out += [_render_finding_section(f) for f in group]
    return "\n".join(out)


def _render_dedupe_clusters(clusters: list[ReportDedupeCluster]) -> str:
    if not clusters:
        return "## Dedupe clusters\n\n_No dedupe clusters._"
    lines = [
        "## Dedupe clusters",
        "",
        "| Cluster id | Primary finding | Members | Root cause |",
        "| --- | --- | --- | --- |",
    ]
    for c in clusters:
        rc = _escape_table_cell(c.root_cause_summary)
        lines.append(
            f"| `{c.id}` | `{c.primary_finding_id}` | {c.member_count} | {rc} |"
        )
    return "\n".join(lines)


def _render_markdown(report: ReportV1) -> str:
    """Render the full ``report.md`` content as a single string."""
    footer = (
        f"_Rendered at {report.rendered_at} "
        f"(schema_version {report.schema_version})._"
    )
    parts = [
        f"# FlossWing report — run `{report.run.id}`",
        "",
        _render_run_header(report.run),
        "",
        _render_summary(report.summary),
        "",
        _render_findings_sections(report.findings),
        "",
        _render_dedupe_clusters(report.dedupe_clusters),
        "",
        footer,
        "",
    ]
    return "\n".join(parts)


# JSON renderer


def _render_json(report: ReportV1) -> str:
    return report.model_dump_json(indent=2)


# Per-finding directories


def _render_single_finding_md(f: ReportFinding) -> str:
    """Render ``findings/<id>/finding.md`` — title, metadata, description,
    suggested fix. PoC code lives in a sibling ``poc.<ext>`` chosen by
    :func:`_poc_extension_for` (falls back to ``poc.txt`` for unknown
    source extensions) per spec § Per-finding directories."""
    lines = [
        f"# {_escape_inline(f.title)}",
        "",
        f"- **id:** `{f.id}`",
        f"- **attack class:** {_escape_inline(f.attack_class)}",
        f"- **location:** {_finding_location(f)}",
        f"- **badges:** {', '.join(_finding_badges(f))}",
        "",
        "## Description",
        "",
        _escape_inline(f.description),
        "",
    ]
    if f.suggested_fix:
        lines += [
            "## Suggested fix",
            "",
            _escape_inline(f.suggested_fix),
            "",
        ]
    return "\n".join(lines)


def _write_findings_dirs(
    report: ReportV1, output_dir: Path
) -> tuple[int, int]:
    """Write one ``findings/<id>/`` directory per CONFIRMED finding.

    Returns ``(dirs_written, bytes_written)``. ``output_dir/findings/``
    is always created (even if no confirmed findings exist) so the
    integration smoke can rely on its presence.
    """
    findings_root = output_dir / "findings"
    findings_root.mkdir(parents=True, exist_ok=True)

    dirs_written = 0
    bytes_written = 0
    for f in report.findings:
        if f.status != "confirmed":
            continue
        # ULIDs only contain Crockford base32 chars (no path separators)
        # so this cannot escape ``findings_root``. Defensive: assert by
        # constructing via ``/`` rather than string formatting.
        d = findings_root / f.id
        d.mkdir(parents=True, exist_ok=True)
        finding_md = _render_single_finding_md(f)
        md_path = d / "finding.md"
        md_path.write_text(finding_md, encoding="utf-8")
        bytes_written += md_path.stat().st_size

        if f.poc_code is not None:
            # Pick the PoC extension off the source file's extension so
            # a TS finding ends up at ``poc.ts``, not ``poc.py``. The
            # original v1.0 lock to ``.py`` was a known cosmetic gap
            # documented in spec § Per-finding directories; this is
            # the language-aware variant. The fallback is ``.txt`` for
            # unmapped extensions (the renderer must never write a
            # zero-suffix path).
            poc_path = d / f"poc{_poc_extension_for(f.file)}"
            poc_path.write_text(f.poc_code, encoding="utf-8")
            bytes_written += poc_path.stat().st_size

        dirs_written += 1

    return dirs_written, bytes_written


# Public entry point


_VALID_FORMATS: frozenset[str] = frozenset({"md", "json", "sarif"})


def render(
    *,
    run_id: str,
    session_factory: SessionFactory,
    output_dir: Path,
    formats: list[str],
) -> ReportRenderResult:
    """Render the v1.0 report for ``run_id`` into ``output_dir``.

    Deterministic given the state DB and ``_now_iso()``. Writes
    ``report.md`` and/or ``report.json`` depending on ``formats``;
    ``sarif`` is accepted but emits a stderr stub (tracked in v1.1, per
    spec § SARIF stance). Per-finding directories are written regardless
    of which formats were requested.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "findings").mkdir(parents=True, exist_ok=True)

    report = _load(run_id, session_factory)

    formats_written: list[str] = []
    bytes_written = 0
    sarif_skipped = False

    for fmt in formats:
        if fmt == "md":
            content = _render_markdown(report)
            path = output_dir / "report.md"
            path.write_text(content, encoding="utf-8")
            bytes_written += path.stat().st_size
            formats_written.append("md")
        elif fmt == "json":
            content = _render_json(report)
            path = output_dir / "report.json"
            path.write_text(content, encoding="utf-8")
            bytes_written += path.stat().st_size
            formats_written.append("json")
        elif fmt == "sarif":
            # Per spec § SARIF stance: write a placeholder report.sarif
            # file containing exactly one `$comment` field, plus emit a
            # stderr notice. The file exists so existing CI configs that
            # ask for SARIF don't error; they just get a placeholder
            # until v1.1 ships real SARIF 2.1.0 output.
            import sys

            placeholder = (
                '{"$comment": "sarif output is not yet implemented; '
                'tracked in v1.1"}\n'
            )
            sarif_path = output_dir / "report.sarif"
            sarif_path.write_text(placeholder, encoding="utf-8")
            bytes_written += sarif_path.stat().st_size
            sys.stderr.write(
                "sarif: not yet implemented; tracked in v1.1\n"
            )
            sarif_skipped = True
        else:
            # Unknown format strings are the CLI's job to reject; if one
            # reaches us, skip silently rather than crash the render.
            continue

    dirs_written, dirs_bytes = _write_findings_dirs(report, output_dir)
    bytes_written += dirs_bytes

    return ReportRenderResult(
        formats_written=formats_written,
        findings_dirs_written=dirs_written,
        output_dir=output_dir,
        bytes_written=bytes_written,
        sarif_skipped=sarif_skipped,
    )
