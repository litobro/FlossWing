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

"""Dedupe stage orchestration.

Two-pass stage. Pass 1 is deterministic, pure-Python SQL: group the
current run's findings into ``dedupe_clusters`` rows by
``(file, function, attack_class, line_start ± 5)`` and stamp every
member's ``dedupe_cluster_id``. Pass 2 spins up one agent session per
cluster with ``member_count > 1`` and lets the agent call
``merge_findings`` / ``link_variant`` (or do nothing).

Per docs/specs/2026-06-02-v0.8-dedupe-design.md § Component
responsibilities ``stages/dedupe.py``. Pass 1 always commits before
Pass 2 begins (open question Q#5 resolution: TWO transactions, not one).
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, NamedTuple

from claude_agent_sdk import tool
from pydantic import BaseModel, ValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker
from ulid import ULID

from flosswing.agent import pricing
from flosswing.agent.runtime import run_session
from flosswing.config import Config
from flosswing.errors import FlosswingError, ToolValidationError
from flosswing.state import heartbeat as st_heartbeat
from flosswing.state import session as st_session
from flosswing.state.models import (
    AgentSession,
    DedupeCluster,
    Finding,
    FindingLink,
)
from flosswing.tools import findings as t_findings
from flosswing.tools import fs as t_fs

_PROMPTS_ROOT = Path(__file__).resolve().parent.parent / "prompts"
_DEDUPE_SYSTEM_PROMPT_PATH = _PROMPTS_ROOT / "system" / "dedupe.md"

SessionFactory = sessionmaker[Session]

# Per docs/tool-contracts.md § Tool scope matrix: Dedupe = 4 tools
# (read_file, query_findings, merge_findings, link_variant). Kept
# alongside the builder so the count is auditable.
_DEDUPE_TOOL_COUNT: int = 4

# ``line_start`` proximity threshold for Pass 1 clustering. Findings in
# the same (file, function, attack_class) bucket whose line_start values
# differ by <= this many lines fall into the same cluster (transitively
# along the sort order). Per spec § Pass 1 step 2.
_LINE_PROXIMITY: int = 5

# Pass-1 placeholder summaries. Singletons get the "no review needed"
# string; multi-member clusters get the "pending agent review" string,
# which Pass 2 / merge_findings overwrites on success. The helper
# ``_count_dedupe_writes`` treats anything other than these two strings
# as a "real" agent-supplied summary.
_PASS1_SINGLETON_SUMMARY: str = "(singleton; no agent review needed)"
_PASS1_PENDING_SUMMARY: str = "(pending agent review)"


@dataclass(frozen=True)
class DedupeStageResult:
    outcome: Literal["completed", "errored", "skipped"]
    clusters_total: int = 0
    clusters_reviewed: int = 0  # member_count > 1
    merges_performed: int = 0
    variants_linked: int = 0
    clusters_refused: int = 0
    clusters_errored: int = 0
    findings_total: int = 0
    findings_superseded: int = 0
    input_tokens: int = 0
    output_tokens: int = 0

    @classmethod
    def skipped(cls) -> DedupeStageResult:
        return cls(outcome="skipped")


# -----------------------------------------------------------------------------
# Private helpers
# -----------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _load_prompt() -> tuple[str, str]:
    """Load dedupe.md and hash it. No template substitution in v0.8."""
    text = _DEDUPE_SYSTEM_PROMPT_PATH.read_text(encoding="utf-8")
    sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return text, sha


class _DedupeDeltaSnapshot(NamedTuple):
    """Per-run counters used to compute per-session merge/link deltas.

    ``clusters_with_real_summary`` counts ``dedupe_clusters`` rows whose
    ``root_cause_summary`` is anything other than the two Pass-1
    placeholders — i.e. rows merge_findings has touched.
    ``finding_link_count`` counts ``finding_links`` rows for the run's
    findings (we count by joining link.finding_id_a back to findings.run_id).
    """

    clusters_with_real_summary: int
    finding_link_count: int


def _count_dedupe_writes(run_id: str) -> _DedupeDeltaSnapshot:
    """Snapshot the two counters used to compute per-session deltas.

    Called immediately before and immediately after each Pass-2 agent
    session; the difference attributes merge/link writes to that session.
    Because v0.8 is sequential single-writer (one cluster reviewed at a
    time), the delta is unambiguous.
    """
    with st_session.session_scope() as s:
        clusters_with_real_summary = int(
            s.execute(
                select(func.count())
                .select_from(DedupeCluster)
                .where(
                    DedupeCluster.run_id == run_id,
                    DedupeCluster.root_cause_summary
                    != _PASS1_PENDING_SUMMARY,
                    DedupeCluster.root_cause_summary
                    != _PASS1_SINGLETON_SUMMARY,
                )
            ).scalar_one()
        )
        # Count finding_links rows whose finding_id_a belongs to this run.
        # finding_id_a / finding_id_b are FK'd to findings and we always
        # set both in link_variant; joining on either side gives the same
        # answer in v0.8 (both ends share a cluster, hence a run).
        finding_link_count = int(
            s.execute(
                select(func.count())
                .select_from(FindingLink)
                .join(Finding, FindingLink.finding_id_a == Finding.id)
                .where(Finding.run_id == run_id)
            ).scalar_one()
        )
    return _DedupeDeltaSnapshot(
        clusters_with_real_summary=clusters_with_real_summary,
        finding_link_count=finding_link_count,
    )


# -----------------------------------------------------------------------------
# Pass 1 — deterministic clustering (sync, no SDK)
# -----------------------------------------------------------------------------


def _pass1(run_id: str, session_factory: SessionFactory) -> int:
    """Group eligible findings into ``dedupe_clusters`` rows.

    Per spec § Pass 1: SELECT findings for the run where status is not
    'superseded' and ``dedupe_cluster_id IS NULL``, bucket by
    ``(file, function or '', attack_class)``, sort each bucket by
    ``line_start`` and walk linearly — a new cluster starts when the
    gap from the previous member's ``line_start`` exceeds
    ``_LINE_PROXIMITY``. This is functionally equivalent to union-find
    with the same predicate, since the relation is sort-order linkage.

    Stages all writes inside a single ``session_scope()`` transaction so
    Pass 1 either fully commits or fully rolls back.

    The ``session_factory`` parameter is accepted for stage-API parity
    but unused — ``st_session.session_scope()`` provides its own factory.
    Returns the number of clusters created.
    """
    del session_factory  # st_session.session_scope provides the factory

    # Buckets are keyed by (file, function or "", attack_class). The
    # nested list inside each bucket is sorted by line_start before the
    # walk so the linear-gap predicate produces a deterministic grouping.
    buckets: dict[tuple[str, str, str], list[Finding]] = {}

    now = _now_iso()
    cluster_count = 0

    with st_session.session_scope() as s:
        rows = (
            s.execute(
                select(Finding).where(
                    Finding.run_id == run_id,
                    Finding.status != "superseded",
                    Finding.dedupe_cluster_id.is_(None),
                )
            )
            .scalars()
            .all()
        )

        # Snapshot the minimal fields we need OUTSIDE the bucket walk —
        # we'll go back to the ORM rows by id to set dedupe_cluster_id.
        # Keep the ORM instance available so the assignment inside the
        # same session_scope() flushes naturally.
        for r in rows:
            key = (r.file, r.function or "", r.attack_class)
            buckets.setdefault(key, []).append(r)

        for key, members in buckets.items():
            del key  # only the grouping mattered; the key isn't persisted
            # Sort ascending by line_start; ties broken by ULID id so two
            # findings on the same line still get a stable order.
            members.sort(key=lambda f: (f.line_start, f.id))

            # Linear walk: a new cluster begins when the gap from the
            # previous member's line_start exceeds _LINE_PROXIMITY.
            current_cluster: list[Finding] = []
            for member in members:
                if not current_cluster:
                    current_cluster.append(member)
                    continue
                prev = current_cluster[-1]
                if member.line_start - prev.line_start > _LINE_PROXIMITY:
                    _emit_cluster(
                        s, run_id=run_id, members=current_cluster, now=now
                    )
                    cluster_count += 1
                    current_cluster = [member]
                else:
                    current_cluster.append(member)
            if current_cluster:
                _emit_cluster(
                    s, run_id=run_id, members=current_cluster, now=now
                )
                cluster_count += 1

    return cluster_count


def _emit_cluster(
    s: Session,
    *,
    run_id: str,
    members: list[Finding],
    now: str,
) -> None:
    """INSERT a dedupe_clusters row and stamp each member's cluster id.

    Per spec § Pass 1 step 3-4: primary = lowest-ULID member;
    root_cause_summary placeholder differs for singletons vs multi-member
    clusters. Only ``dedupe_cluster_id`` is touched on the findings;
    ``dedupe_role``, ``primary_finding_id``, ``root_cause_summary``, and
    ``superseded_at`` remain untouched (those are Pass-2 / tool-layer
    responsibility per docs/tool-contracts.md § findings (Dedupe-side)).
    """
    # Lowest-ULID = lexicographically smallest id, because ULIDs sort
    # naturally as strings in time order.
    primary = min(members, key=lambda f: f.id)
    size = len(members)
    summary = (
        _PASS1_SINGLETON_SUMMARY if size == 1 else _PASS1_PENDING_SUMMARY
    )
    cluster_id = str(ULID())
    s.add(
        DedupeCluster(
            id=cluster_id,
            run_id=run_id,
            primary_finding_id=primary.id,
            root_cause_summary=summary,
            created_at=now,
            member_count=size,
        )
    )
    for member in members:
        member.dedupe_cluster_id = cluster_id


# -----------------------------------------------------------------------------
# Tool builder — Dedupe-scoped (4 tools per docs/tool-contracts.md § Tool
# scope matrix). Mirrors stages/gapfill.py shape.
# -----------------------------------------------------------------------------


class _ToolError(BaseModel):
    error: str
    message: str
    retryable: bool


def _ok(payload: BaseModel) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": payload.model_dump_json()}]}


def _err(code: str, message: str, retryable: bool) -> dict[str, Any]:
    return {
        "content": [
            {
                "type": "text",
                "text": _ToolError(
                    error=code, message=message, retryable=retryable
                ).model_dump_json(),
            }
        ],
        "is_error": True,
    }


def _wrap_call(
    fn: Callable[..., BaseModel],
    *,
    input_model: type[BaseModel],
    args: dict[str, Any],
    **kwargs: Any,
) -> dict[str, Any]:
    try:
        inp = input_model.model_validate(args)
    except ValidationError as e:
        return _err(ToolValidationError.code, str(e), retryable=False)
    try:
        out = fn(inp, **kwargs)
    except FlosswingError as e:
        return _err(e.code, e.message, retryable=e.retryable)
    return _ok(out)


def _build_dedupe_tools(
    *,
    repo_root: Path,
    run_id: str,
) -> list[Any]:
    """Build the 4 Dedupe-scoped tool callables for ClaudeAgentOptions.

    Per docs/tool-contracts.md § Tool scope matrix: read_file,
    query_findings, merge_findings, link_variant.
    """

    @tool(
        "read_file",
        "Read a file (or line range) from the target repository (read-only).",
        t_fs.ReadFileInput.model_json_schema(),
    )
    async def _read_file(args: dict[str, Any]) -> dict[str, Any]:
        return _wrap_call(
            t_fs.read_file,
            input_model=t_fs.ReadFileInput,
            args=args,
            repo_root=repo_root,
        )

    @tool(
        "query_findings",
        (
            "Read findings from the current run with optional filters on"
            " finding_id, attack_class, file, status, min_severity."
            " Use this to fetch the full body of each cluster member."
        ),
        t_findings.QueryFindingsInput.model_json_schema(),
    )
    async def _query_findings(args: dict[str, Any]) -> dict[str, Any]:
        return _wrap_call(
            t_findings.query_findings,
            input_model=t_findings.QueryFindingsInput,
            args=args,
            run_id=run_id,
        )

    @tool(
        "merge_findings",
        (
            "Collapse N duplicate findings into a single primary. Pass"
            " ALL duplicate IDs in one call; root_cause_summary must be"
            " >= 50 chars of substantive prose. Duplicates become"
            " status='superseded' — irreversible within the run."
        ),
        t_findings.MergeFindingsInput.model_json_schema(),
    )
    async def _merge_findings(args: dict[str, Any]) -> dict[str, Any]:
        return _wrap_call(
            t_findings.merge_findings,
            input_model=t_findings.MergeFindingsInput,
            args=args,
            run_id=run_id,
        )

    @tool(
        "link_variant",
        (
            "Flag a relationship between two findings without merging."
            " Both findings must share a dedupe_cluster_id. relationship"
            " is one of: same_root_cause, exploit_chain, preconditions."
        ),
        t_findings.LinkVariantInput.model_json_schema(),
    )
    async def _link_variant(args: dict[str, Any]) -> dict[str, Any]:
        return _wrap_call(
            t_findings.link_variant,
            input_model=t_findings.LinkVariantInput,
            args=args,
            run_id=run_id,
        )

    return [
        _read_file,
        _query_findings,
        _merge_findings,
        _link_variant,
    ]


# -----------------------------------------------------------------------------
# Pass 2 — per-cluster agent review
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class _Pass2Totals:
    clusters_reviewed: int = 0
    merges_performed: int = 0
    variants_linked: int = 0
    clusters_refused: int = 0
    clusters_errored: int = 0
    input_tokens: int = 0
    output_tokens: int = 0


def _compose_user_prompt(
    *,
    cluster_id: str,
    member_ids: list[str],
    suggested_primary_id: str,
    file: str,
    function: str | None,
    attack_class: str,
    line_min: int,
    line_max: int,
) -> str:
    """Per-cluster header passed to the Dedupe session.

    Per spec § Pass 2 step 2a: cluster id, member finding ids, and the
    deterministic key shared by the cluster's members. The agent fetches
    full finding bodies via ``query_findings(finding_id=...)``; we do not
    inline them here (keeps the user prompt small and reproducible).
    """
    members_block = "\n".join(f"  - {fid}" for fid in member_ids)
    return (
        f"Cluster under review:\n"
        f"  cluster_id:        {cluster_id}\n"
        f"  suggested_primary: {suggested_primary_id}\n"
        f"  file:              {file}\n"
        f"  function:          {function or '<unknown>'}\n"
        f"  attack_class:      {attack_class}\n"
        f"  line_range:        {line_min}-{line_max}\n"
        f"\n"
        f"Member finding IDs (ULID order):\n"
        f"{members_block}\n"
        f"\n"
        "Call query_findings(finding_id=...) for each member to read the "
        "full body, then decide: merge_findings(...), link_variant(...) "
        "pairwise, or take no action."
    )


async def _pass2(
    *,
    run_id: str,
    repo: Path,
    cfg: Config,
    session_factory: SessionFactory,
) -> _Pass2Totals:
    """Spin up one agent session per cluster with member_count > 1.

    Per spec § Pass 2: ordered by cluster id (ULID = creation order),
    sequential (one session at a time). Per-cluster failures are
    swallowed and counted in the returned totals; the stage as a whole
    completes regardless.
    """
    del session_factory  # st_session.session_scope provides the factory

    system_prompt, prompt_hash = _load_prompt()

    # Snapshot the clusters and per-cluster member details OUTSIDE the
    # agent loop. SQLAlchemy ORM rows expire on session_scope() exit, so
    # we materialize everything we'll read inside the loop into plain
    # tuples up-front.
    @dataclass(frozen=True)
    class _ClusterSnapshot:
        cluster_id: str
        suggested_primary_id: str
        member_ids: list[str]
        file: str
        function: str | None
        attack_class: str
        line_min: int
        line_max: int

    snapshots: list[_ClusterSnapshot] = []
    with st_session.session_scope() as s:
        cluster_rows = (
            s.execute(
                select(DedupeCluster)
                .where(
                    DedupeCluster.run_id == run_id,
                    DedupeCluster.member_count > 1,
                )
                .order_by(DedupeCluster.id)
            )
            .scalars()
            .all()
        )
        for c in cluster_rows:
            members = (
                s.execute(
                    select(Finding)
                    .where(Finding.dedupe_cluster_id == c.id)
                    .order_by(Finding.id)
                )
                .scalars()
                .all()
            )
            if not members:
                # Defensive: a cluster row without findings shouldn't be
                # reachable (Pass 1 always writes findings + cluster in
                # one transaction). Skip rather than crash.
                continue
            line_starts = [m.line_start for m in members]
            line_ends = [m.line_end for m in members]
            # Take attack_class / file / function from the first member;
            # Pass 1's bucket key guarantees they're shared across the
            # whole cluster.
            head = members[0]
            snapshots.append(
                _ClusterSnapshot(
                    cluster_id=c.id,
                    suggested_primary_id=c.primary_finding_id,
                    member_ids=[m.id for m in members],
                    file=head.file,
                    function=head.function,
                    attack_class=head.attack_class,
                    line_min=min(line_starts),
                    line_max=max(line_ends),
                )
            )

    totals = _Pass2Totals()

    for snap in snapshots:
        agent_session_id = str(ULID())
        started_at = _now_iso()

        user_prompt = _compose_user_prompt(
            cluster_id=snap.cluster_id,
            member_ids=snap.member_ids,
            suggested_primary_id=snap.suggested_primary_id,
            file=snap.file,
            function=snap.function,
            attack_class=snap.attack_class,
            line_min=snap.line_min,
            line_max=snap.line_max,
        )

        # INSERT a minimal agent_sessions row before awaiting the
        # session. Per plan-time decision: Dedupe mirrors v0.6 Validate's
        # partial-INSERT pattern (not v0.3 Hunt's "INSERT after") so
        # merge_findings / link_variant could in principle FK to
        # agent_sessions during the session. They don't today (neither
        # tool writes an audit row referencing the session), but the
        # placeholder terminal-outcome shape is cheap and uniform. The
        # schema CHECK on outcome is satisfied with a placeholder
        # 'completed' that the post-session UPDATE overwrites.
        with st_session.session_scope() as s:
            s.add(
                AgentSession(
                    id=agent_session_id,
                    run_id=run_id,
                    stage="dedupe",
                    task_id=None,
                    finding_id=None,
                    model=cfg.model,
                    system_prompt_hash=prompt_hash,
                    input_tokens=0,
                    output_tokens=0,
                    cache_read_tokens=0,
                    cache_write_tokens=0,
                    cost_usd=0.0,
                    duration_ms=0,
                    outcome="completed",
                    refusal_text=None,
                    error_text=None,
                    tool_calls_count=0,
                    started_at=started_at,
                    finished_at=started_at,
                )
            )

        tools = _build_dedupe_tools(repo_root=repo, run_id=run_id)

        before = _count_dedupe_writes(run_id)

        session_result = await run_session(
            model=cfg.model,
            provider=cfg.provider,
            system_prompt=system_prompt,
            tools=tools,
            user_prompt=user_prompt,
            token_budget=cfg.dedupe_token_budget,
            auth_env=cfg.auth_env,
            run_id=run_id,
            stage="dedupe",
            agent_session_id=agent_session_id,
            on_usage=st_heartbeat.make_on_usage(
                run_id=run_id,
                stage="dedupe",
                model=cfg.model,
                agent_session_id=agent_session_id,
            ),
        )
        finished_at = _now_iso()
        cost = pricing.resolve_cost_usd(
            model=cfg.model,
            input_tokens=session_result.input_tokens,
            output_tokens=session_result.output_tokens,
            cache_read_tokens=session_result.cache_read_tokens,
            cache_write_tokens=session_result.cache_write_tokens,
            authoritative=session_result.cost_usd,
        )

        after = _count_dedupe_writes(run_id)
        merge_delta = (
            after.clusters_with_real_summary
            - before.clusters_with_real_summary
        )
        link_delta = after.finding_link_count - before.finding_link_count

        # UPDATE the audit row with real outcome / usage / timestamps, and clear
        # the live heartbeat in the same transaction (atomic swap).
        with st_session.session_scope() as s:
            sess = s.get(AgentSession, agent_session_id)
            if sess is not None:
                sess.input_tokens = session_result.input_tokens
                sess.output_tokens = session_result.output_tokens
                sess.cache_read_tokens = session_result.cache_read_tokens
                sess.cache_write_tokens = session_result.cache_write_tokens
                sess.cost_usd = cost
                sess.duration_ms = session_result.duration_ms
                sess.outcome = session_result.outcome
                sess.refusal_text = session_result.refusal_text
                sess.error_text = session_result.error_text
                sess.tool_calls_count = session_result.tool_calls_count
                sess.finished_at = finished_at
            st_heartbeat.clear(s, run_id)

        # Classify per-cluster outcome. The runtime's 'timed_out' is
        # folded into 'errored' for the stage-level total — we don't
        # surface a separate timed_out bucket.
        clusters_reviewed = totals.clusters_reviewed + 1
        merges_performed = totals.merges_performed
        variants_linked = totals.variants_linked
        clusters_refused = totals.clusters_refused
        clusters_errored = totals.clusters_errored

        if session_result.outcome == "refused":
            clusters_refused += 1
        elif session_result.outcome in {
            "errored",
            "budget_exceeded",
            "timed_out",
        }:
            clusters_errored += 1
        elif session_result.outcome != "completed":
            # Unknown outcome literal -> errored bucket.
            clusters_errored += 1

        # Always roll the deltas forward (defensive: the tool layer
        # commits atomically, so any landed write should be counted
        # regardless of how the session itself terminated). max(0, ...)
        # guards against the impossible case of the count going backward.
        merges_performed += max(0, merge_delta)
        variants_linked += max(0, link_delta)

        totals = _Pass2Totals(
            clusters_reviewed=clusters_reviewed,
            merges_performed=merges_performed,
            variants_linked=variants_linked,
            clusters_refused=clusters_refused,
            clusters_errored=clusters_errored,
            input_tokens=totals.input_tokens + session_result.input_tokens,
            output_tokens=(
                totals.output_tokens + session_result.output_tokens
            ),
        )

    return totals


# -----------------------------------------------------------------------------
# Main entry point
# -----------------------------------------------------------------------------


async def run(
    *,
    run_id: str,
    repo: Path,
    cfg: Config,
    session_factory: SessionFactory,
) -> DedupeStageResult:
    """Run Dedupe (Pass 1 + Pass 2) exactly once for ``run_id``.

    Per spec § Two passes: Pass 1 (deterministic clustering) and Pass 2
    (per-cluster agent review) run as separate transactions. Pass 1
    failing is fatal (programmer-error condition; the orchestrator marks
    the run errored and exits 1). Per-cluster Pass-2 failures are
    swallowed and counted; the stage completes regardless.
    """
    # Pass 1: deterministic clustering. Propagate any error up — the
    # orchestrator handles it (per spec § Failure modes table:
    # "Pass 1 SQL error → run errored; traceback scrubbed → exit 1").
    clusters_total = _pass1(run_id, session_factory)

    # Defensive skip: if Pass 1 produced no clusters, there's nothing
    # for Pass 2 to do. The orchestrator gates on findings_total > 0
    # upstream, so this branch shouldn't be reachable on the happy
    # path — but Pass 1 returning 0 with findings present would be an
    # invariant violation we'd rather surface as a skip than crash on.
    if clusters_total == 0:
        return DedupeStageResult.skipped()

    # Pass 2: per-cluster agent review.
    p2 = await _pass2(
        run_id=run_id,
        repo=repo,
        cfg=cfg,
        session_factory=session_factory,
    )

    # Final tallies: total and superseded finding counts.
    with st_session.session_scope() as s:
        findings_total = int(
            s.execute(
                select(func.count())
                .select_from(Finding)
                .where(Finding.run_id == run_id)
            ).scalar_one()
        )
        findings_superseded = int(
            s.execute(
                select(func.count())
                .select_from(Finding)
                .where(
                    Finding.run_id == run_id,
                    Finding.status == "superseded",
                )
            ).scalar_one()
        )

    return DedupeStageResult(
        outcome="completed",
        clusters_total=clusters_total,
        clusters_reviewed=p2.clusters_reviewed,
        merges_performed=p2.merges_performed,
        variants_linked=p2.variants_linked,
        clusters_refused=p2.clusters_refused,
        clusters_errored=p2.clusters_errored,
        findings_total=findings_total,
        findings_superseded=findings_superseded,
        input_tokens=p2.input_tokens,
        output_tokens=p2.output_tokens,
    )


__all__ = ["DedupeStageResult", "run"]
