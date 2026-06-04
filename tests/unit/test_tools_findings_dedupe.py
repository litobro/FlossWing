"""tools/findings.py: dedupe-side tool implementations (merge_findings,
link_variant).

Per docs/tool-contracts.md § findings (Dedupe-side) and
docs/specs/2026-06-02-v0.8-dedupe-design.md § Component responsibilities.

Fixture strategy mirrors test_tools_findings.py:
- Per-test isolated_db using a file-backed SQLite in tmp_path so Alembic
  upgrade runs once on first session.
- Separate session_scopes per FK level (Run -> HuntTask -> Finding ->
  DedupeCluster) because SQLite FK enforcement is on and a single flush
  can't always infer the ordering.
- DedupeCluster has a NOT NULL FK to findings.id (primary_finding_id),
  and Finding has a nullable FK to dedupe_clusters.id (dedupe_cluster_id).
  We seed findings first with NULL dedupe_cluster_id, then the cluster
  (pointing at primary), then UPDATE the findings to set their cluster id.
  Migration 001 confirms SQLite enforces FKs at modify-time only, so this
  ordering works.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import select
from ulid import ULID

from flosswing.errors import (
    FindingNotFoundError,
    FindingNotInClusterError,
    LinkAlreadyExistsError,
    PrimaryInDuplicatesError,
    RootCauseSummaryTooShortError,
    SameFindingError,
)
from flosswing.state import session as st_session
from flosswing.state.models import (
    DedupeCluster,
    Finding,
    FindingLink,
    HuntTask,
    Run,
)
from flosswing.tools.findings import (
    LinkVariantInput,
    LinkVariantOutput,
    MergeFindingsInput,
    MergeFindingsOutput,
    link_variant,
    merge_findings,
)

# -----------------------------------------------------------------------------
# Fixtures
# -----------------------------------------------------------------------------


@pytest.fixture()
def isolated_db(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[Path]:
    monkeypatch.setenv("FLOSSWING_DB_URL", f"sqlite:///{tmp_path}/state.db")
    monkeypatch.setattr(st_session, "_cached_engine", None, raising=False)
    monkeypatch.setattr(
        st_session, "_cached_session_factory", None, raising=False
    )
    yield tmp_path


def _now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _seed_run_and_task() -> tuple[str, str]:
    """Insert a Run + a HuntTask; return (run_id, task_id).

    Separate session_scopes per FK level — Run must commit before HuntTask
    flushes, same pattern as _seed_run_with_findings in
    test_tools_findings.py.
    """
    run_id = str(ULID())
    task_id = str(ULID())
    now = _now_iso()
    with st_session.session_scope() as s:
        s.add(
            Run(
                id=run_id,
                target_repo_path="/tmp/x",
                target_repo_sha=None,
                depth="standard",
                budget_total=20,
                budget_used=0,
                started_at=now,
                status="running",
                config_json="{}",
                flosswing_version="0.8.0",
            )
        )
    with st_session.session_scope() as s:
        s.add(
            HuntTask(
                id=task_id,
                run_id=run_id,
                attack_class="command_injection",
                scope_hint="src/",
                rationale="",
                priority="normal",
                source="recon",
                parent_finding_id=None,
                status="completed",
                created_at=now,
                started_at=now,
                finished_at=now,
                findings_count=0,
            )
        )
    return run_id, task_id


def _seed_finding(
    *,
    run_id: str,
    task_id: str,
    attack_class: str = "command_injection",
    file: str = "src/a.py",
    dedupe_role: str | None = None,
) -> str:
    """Insert one Finding row with dedupe_cluster_id=NULL; return its id."""
    fid = str(ULID())
    with st_session.session_scope() as s:
        s.add(
            Finding(
                id=fid,
                run_id=run_id,
                hunt_task_id=task_id,
                attack_class=attack_class,
                file=file,
                function="some_fn",
                line_start=10,
                line_end=12,
                severity="high",
                confidence="likely",
                status="pending_validation",
                title=f"{attack_class} in {file}",
                description=(
                    "A reasonable description, fifty chars or more."
                ),
                poc_code=None,
                poc_result_json=None,
                suggested_fix=None,
                created_at=_now_iso(),
                dedupe_role=dedupe_role,
            )
        )
    return fid


def _seed_cluster(
    *, run_id: str, primary_finding_id: str, member_ids: list[str]
) -> str:
    """Insert a DedupeCluster pointing at primary_finding_id, then UPDATE
    each finding in member_ids to set its dedupe_cluster_id to the new id.

    The cluster's primary_finding_id FK is NOT NULL — that's why we seed
    the findings first and the cluster second. Findings start with NULL
    dedupe_cluster_id and get patched here.
    """
    cluster_id = str(ULID())
    with st_session.session_scope() as s:
        s.add(
            DedupeCluster(
                id=cluster_id,
                run_id=run_id,
                primary_finding_id=primary_finding_id,
                root_cause_summary=(
                    "Initial summary, replaced by merge_findings call below."
                ),
                created_at=_now_iso(),
                member_count=len(member_ids),
            )
        )
    with st_session.session_scope() as s:
        for fid in member_ids:
            row = s.get(Finding, fid)
            assert row is not None
            row.dedupe_cluster_id = cluster_id
    return cluster_id


def _seed_cluster_with_n_findings(
    *, n: int
) -> tuple[str, str, list[str]]:
    """Convenience: Run+HuntTask, N findings in one cluster.

    Returns (run_id, cluster_id, [finding_ids]). The first finding id is
    the cluster's primary_finding_id (the cluster row points at it). All
    findings have dedupe_role IS NULL at this point — merge_findings or
    link_variant assigns roles.
    """
    run_id, task_id = _seed_run_and_task()
    finding_ids = [
        _seed_finding(
            run_id=run_id,
            task_id=task_id,
            file=f"src/file_{i}.py",
        )
        for i in range(n)
    ]
    cluster_id = _seed_cluster(
        run_id=run_id,
        primary_finding_id=finding_ids[0],
        member_ids=finding_ids,
    )
    return run_id, cluster_id, finding_ids


# A 50+ char root_cause_summary for happy-path merge calls. Padded to make
# the length obvious at a glance (52 chars).
_ROOT_CAUSE_50 = (
    "All three findings reach the same shell exec sink XX"
)


# -----------------------------------------------------------------------------
# merge_findings happy path
# -----------------------------------------------------------------------------


def test_merge_findings_happy_path(isolated_db: Path) -> None:
    """Primary + 2 duplicates, all sharing a cluster. After merge, primary
    is flagged primary, duplicates are flagged duplicate + superseded, the
    cluster row carries the new summary and a recounted member_count."""
    run_id, cluster_id, fids = _seed_cluster_with_n_findings(n=3)
    primary_id, dup1_id, dup2_id = fids
    assert len(_ROOT_CAUSE_50) >= 50  # fixture sanity

    out = merge_findings(
        MergeFindingsInput(
            primary_finding_id=primary_id,
            duplicate_finding_ids=[dup1_id, dup2_id],
            root_cause_summary=_ROOT_CAUSE_50,
        ),
        run_id=run_id,
    )
    assert isinstance(out, MergeFindingsOutput)
    assert out.primary_finding_id == primary_id
    assert out.merged_count == 2

    with st_session.session_scope() as s:
        primary = s.get(Finding, primary_id)
        assert primary is not None
        assert primary.dedupe_role == "primary"
        assert primary.root_cause_summary == _ROOT_CAUSE_50

        for dup_id in (dup1_id, dup2_id):
            dup = s.get(Finding, dup_id)
            assert dup is not None
            assert dup.dedupe_role == "duplicate"
            assert dup.primary_finding_id == primary_id
            assert dup.superseded_at is not None
            assert dup.status == "superseded"

        cluster = s.get(DedupeCluster, cluster_id)
        assert cluster is not None
        assert cluster.root_cause_summary == _ROOT_CAUSE_50
        assert cluster.primary_finding_id == primary_id
        assert cluster.member_count == 3


# -----------------------------------------------------------------------------
# merge_findings error paths
# -----------------------------------------------------------------------------


def test_merge_findings_root_cause_summary_too_short(
    isolated_db: Path,
) -> None:
    """49-char summary is one char under the 50-char minimum."""
    run_id, _cluster_id, fids = _seed_cluster_with_n_findings(n=2)
    primary_id, dup_id = fids
    short = "x" * 49
    assert len(short) == 49
    with pytest.raises(RootCauseSummaryTooShortError):
        merge_findings(
            MergeFindingsInput(
                primary_finding_id=primary_id,
                duplicate_finding_ids=[dup_id],
                root_cause_summary=short,
            ),
            run_id=run_id,
        )


def test_merge_findings_primary_in_duplicates(isolated_db: Path) -> None:
    """primary_finding_id appearing in duplicate_finding_ids is malformed."""
    run_id, _cluster_id, fids = _seed_cluster_with_n_findings(n=2)
    primary_id, dup_id = fids
    with pytest.raises(PrimaryInDuplicatesError):
        merge_findings(
            MergeFindingsInput(
                primary_finding_id=primary_id,
                duplicate_finding_ids=[dup_id, primary_id],
                root_cause_summary=_ROOT_CAUSE_50,
            ),
            run_id=run_id,
        )


def test_merge_findings_finding_not_found(isolated_db: Path) -> None:
    """An unknown duplicate id under this run raises FindingNotFoundError."""
    run_id, _cluster_id, fids = _seed_cluster_with_n_findings(n=2)
    primary_id, _ = fids
    bogus_id = "01BOGUSBOGUSBOGUSBOGUSBOGU"
    with pytest.raises(FindingNotFoundError):
        merge_findings(
            MergeFindingsInput(
                primary_finding_id=primary_id,
                duplicate_finding_ids=[bogus_id],
                root_cause_summary=_ROOT_CAUSE_50,
            ),
            run_id=run_id,
        )


def test_merge_findings_duplicate_dedupe_cluster_id_null(
    isolated_db: Path,
) -> None:
    """A duplicate whose dedupe_cluster_id is NULL fails the cluster
    membership check."""
    run_id, _cluster_id, fids = _seed_cluster_with_n_findings(n=2)
    primary_id, dup_id = fids
    # Find a task we can attach the orphan finding to (any task works).
    with st_session.session_scope() as s:
        task = s.execute(
            select(HuntTask).where(HuntTask.run_id == run_id)
        ).scalar_one()
        task_id: str = task.id
    orphan_id = _seed_finding(
        run_id=run_id, task_id=task_id, file="src/orphan.py"
    )
    # Sanity: orphan has no cluster.
    with st_session.session_scope() as s:
        orphan = s.get(Finding, orphan_id)
        assert orphan is not None
        assert orphan.dedupe_cluster_id is None

    with pytest.raises(FindingNotInClusterError):
        merge_findings(
            MergeFindingsInput(
                primary_finding_id=primary_id,
                duplicate_finding_ids=[dup_id, orphan_id],
                root_cause_summary=_ROOT_CAUSE_50,
            ),
            run_id=run_id,
        )


def test_merge_findings_duplicate_in_different_cluster(
    isolated_db: Path,
) -> None:
    """A duplicate whose dedupe_cluster_id is non-NULL but != primary's
    cluster id fails the cluster membership check."""
    run_id, _cluster_id_a, fids_a = _seed_cluster_with_n_findings(n=2)
    primary_id, _dup_a = fids_a
    # Build a second cluster under the same run so we have a finding with
    # a non-NULL dedupe_cluster_id != primary's.
    with st_session.session_scope() as s:
        task = s.execute(
            select(HuntTask).where(HuntTask.run_id == run_id)
        ).scalar_one()
        task_id: str = task.id
    other_fid_1 = _seed_finding(
        run_id=run_id, task_id=task_id, file="src/other1.py"
    )
    other_fid_2 = _seed_finding(
        run_id=run_id, task_id=task_id, file="src/other2.py"
    )
    _seed_cluster(
        run_id=run_id,
        primary_finding_id=other_fid_1,
        member_ids=[other_fid_1, other_fid_2],
    )

    with pytest.raises(FindingNotInClusterError):
        merge_findings(
            MergeFindingsInput(
                primary_finding_id=primary_id,
                duplicate_finding_ids=[other_fid_2],
                root_cause_summary=_ROOT_CAUSE_50,
            ),
            run_id=run_id,
        )


# -----------------------------------------------------------------------------
# link_variant happy path
# -----------------------------------------------------------------------------


def test_link_variant_happy_path(isolated_db: Path) -> None:
    """Two findings in the same cluster, both dedupe_role IS NULL. After
    the call: a finding_links row exists and both findings are 'variant'."""
    run_id, _cluster_id, fids = _seed_cluster_with_n_findings(n=2)
    fid_a, fid_b = fids
    out = link_variant(
        LinkVariantInput(
            finding_id_a=fid_a,
            finding_id_b=fid_b,
            relationship="same_root_cause",
            note="they call the same helper",
        ),
        run_id=run_id,
    )
    assert isinstance(out, LinkVariantOutput)
    assert len(out.link_id) == 26  # ULIDs are 26 chars

    with st_session.session_scope() as s:
        link = s.execute(
            select(FindingLink).where(FindingLink.id == out.link_id)
        ).scalar_one()
        assert link.finding_id_a == fid_a
        assert link.finding_id_b == fid_b
        assert link.relationship == "same_root_cause"
        assert link.note == "they call the same helper"
        assert link.created_at

        a_row = s.get(Finding, fid_a)
        b_row = s.get(Finding, fid_b)
        assert a_row is not None
        assert b_row is not None
        assert a_row.dedupe_role == "variant"
        assert b_row.dedupe_role == "variant"


# -----------------------------------------------------------------------------
# link_variant error paths
# -----------------------------------------------------------------------------


def test_link_variant_same_finding(isolated_db: Path) -> None:
    """finding_id_a == finding_id_b is rejected before any DB round-trip."""
    run_id, _cluster_id, fids = _seed_cluster_with_n_findings(n=2)
    fid_a, _ = fids
    with pytest.raises(SameFindingError):
        link_variant(
            LinkVariantInput(
                finding_id_a=fid_a,
                finding_id_b=fid_a,
                relationship="same_root_cause",
            ),
            run_id=run_id,
        )


def test_link_variant_finding_not_found(isolated_db: Path) -> None:
    """An unknown finding id under this run raises FindingNotFoundError."""
    run_id, _cluster_id, fids = _seed_cluster_with_n_findings(n=2)
    fid_a, _ = fids
    bogus_id = "01BOGUSBOGUSBOGUSBOGUSBOGU"
    with pytest.raises(FindingNotFoundError):
        link_variant(
            LinkVariantInput(
                finding_id_a=fid_a,
                finding_id_b=bogus_id,
                relationship="same_root_cause",
            ),
            run_id=run_id,
        )


def test_link_variant_findings_in_different_clusters(
    isolated_db: Path,
) -> None:
    """Two findings in different clusters can't be variant-linked."""
    run_id, _cluster_id_a, fids_a = _seed_cluster_with_n_findings(n=1)
    primary_a = fids_a[0]
    # Build a second cluster under the same run.
    with st_session.session_scope() as s:
        task = s.execute(
            select(HuntTask).where(HuntTask.run_id == run_id)
        ).scalar_one()
        task_id: str = task.id
    fid_other = _seed_finding(
        run_id=run_id, task_id=task_id, file="src/other.py"
    )
    _seed_cluster(
        run_id=run_id,
        primary_finding_id=fid_other,
        member_ids=[fid_other],
    )

    with pytest.raises(FindingNotInClusterError):
        link_variant(
            LinkVariantInput(
                finding_id_a=primary_a,
                finding_id_b=fid_other,
                relationship="same_root_cause",
            ),
            run_id=run_id,
        )


def test_link_variant_link_already_exists_forward(
    isolated_db: Path,
) -> None:
    """Calling link_variant twice with the same args raises on the second
    call."""
    run_id, _cluster_id, fids = _seed_cluster_with_n_findings(n=2)
    fid_a, fid_b = fids
    link_variant(
        LinkVariantInput(
            finding_id_a=fid_a,
            finding_id_b=fid_b,
            relationship="same_root_cause",
        ),
        run_id=run_id,
    )
    with pytest.raises(LinkAlreadyExistsError):
        link_variant(
            LinkVariantInput(
                finding_id_a=fid_a,
                finding_id_b=fid_b,
                relationship="same_root_cause",
            ),
            run_id=run_id,
        )


def test_link_variant_link_already_exists_reverse(
    isolated_db: Path,
) -> None:
    """The bidirectional check: (a, b, rel) blocks a later (b, a, rel)."""
    run_id, _cluster_id, fids = _seed_cluster_with_n_findings(n=2)
    fid_a, fid_b = fids
    link_variant(
        LinkVariantInput(
            finding_id_a=fid_a,
            finding_id_b=fid_b,
            relationship="same_root_cause",
        ),
        run_id=run_id,
    )
    with pytest.raises(LinkAlreadyExistsError):
        link_variant(
            LinkVariantInput(
                finding_id_a=fid_b,
                finding_id_b=fid_a,
                relationship="same_root_cause",
            ),
            run_id=run_id,
        )


# -----------------------------------------------------------------------------
# link_variant role preservation
# -----------------------------------------------------------------------------


def test_link_variant_preserves_primary_role(isolated_db: Path) -> None:
    """If one of the findings is already 'primary', link_variant must NOT
    downgrade it to 'variant'. The NULL-role side does become 'variant'."""
    run_id, task_id = _seed_run_and_task()
    fid_primary = _seed_finding(
        run_id=run_id, task_id=task_id, file="src/p.py", dedupe_role=None
    )
    fid_other = _seed_finding(
        run_id=run_id, task_id=task_id, file="src/o.py", dedupe_role=None
    )
    _seed_cluster(
        run_id=run_id,
        primary_finding_id=fid_primary,
        member_ids=[fid_primary, fid_other],
    )
    # Promote fid_primary to 'primary' AFTER cluster seeding (so the role
    # is set on the live row, not overwritten by _seed_finding's default).
    with st_session.session_scope() as s:
        row = s.get(Finding, fid_primary)
        assert row is not None
        row.dedupe_role = "primary"

    link_variant(
        LinkVariantInput(
            finding_id_a=fid_primary,
            finding_id_b=fid_other,
            relationship="same_root_cause",
        ),
        run_id=run_id,
    )

    with st_session.session_scope() as s:
        primary_row = s.get(Finding, fid_primary)
        other_row = s.get(Finding, fid_other)
        assert primary_row is not None
        assert other_row is not None
        assert primary_row.dedupe_role == "primary"  # preserved
        assert other_row.dedupe_role == "variant"  # promoted from NULL
