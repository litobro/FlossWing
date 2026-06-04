"""flosswing.stages.dedupe._pass1 — deterministic Pass-1 clustering.

Per docs/specs/2026-06-02-v0.8-dedupe-design.md § Pass 1 and
flosswing/stages/dedupe.py: groups eligible findings (run-scoped,
status != 'superseded', dedupe_cluster_id IS NULL) by
(file, function or '', attack_class), walks each bucket sorted by
line_start, and starts a new cluster when the gap from the previous
member exceeds 5 lines.

These tests cover Pass 1 in isolation. Pass 2 (per-cluster agent
review) is exercised in test_stages_dedupe_pass2.py (Task I).

Fixture pattern matches test_tools_findings_dedupe.py: per-test
isolated_db with file-backed SQLite so Alembic upgrade runs once on
first session, and FK-safe seeding (Run -> HuntTask -> Finding).
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import select
from ulid import ULID

from flosswing.stages.dedupe import (
    _PASS1_PENDING_SUMMARY,
    _PASS1_SINGLETON_SUMMARY,
    _pass1,
)
from flosswing.state import session as st_session
from flosswing.state.models import (
    DedupeCluster,
    Finding,
    HuntTask,
    Run,
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

    Separate session_scopes per FK level so SQLite's FK enforcement
    sees the parent row committed before its child is flushed.
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
    finding_id: str | None = None,
    attack_class: str = "command_injection",
    file: str = "src/a.py",
    function: str | None = "some_fn",
    line_start: int = 10,
    line_end: int | None = None,
    status: str = "pending_validation",
) -> str:
    """Insert one Finding row with dedupe_cluster_id=NULL; return its id.

    ``finding_id`` lets callers pin a ULID prefix (used by the
    lowest-ULID primary test where lexicographic ordering matters).
    """
    fid = finding_id if finding_id is not None else str(ULID())
    with st_session.session_scope() as s:
        s.add(
            Finding(
                id=fid,
                run_id=run_id,
                hunt_task_id=task_id,
                attack_class=attack_class,
                file=file,
                function=function,
                line_start=line_start,
                line_end=line_end if line_end is not None else line_start + 2,
                severity="high",
                confidence="likely",
                status=status,
                title=f"{attack_class} in {file}",
                description=(
                    "A reasonable description, fifty chars or more."
                ),
                poc_code=None,
                poc_result_json=None,
                suggested_fix=None,
                created_at=_now_iso(),
            )
        )
    return fid


# -----------------------------------------------------------------------------
# Pass 1 — clustering behaviour
# -----------------------------------------------------------------------------


def test_pass1_clusters_within_5_lines(isolated_db: Path) -> None:
    """Two findings same (file, function, attack_class), line_start
    distance 3, fall into the same cluster with member_count=2 and the
    'pending agent review' placeholder summary."""
    run_id, task_id = _seed_run_and_task()
    fid_a = _seed_finding(
        run_id=run_id, task_id=task_id, line_start=10
    )
    fid_b = _seed_finding(
        run_id=run_id, task_id=task_id, line_start=13
    )

    n = _pass1(run_id, st_session.session_factory())
    assert n == 1

    with st_session.session_scope() as s:
        a = s.get(Finding, fid_a)
        b = s.get(Finding, fid_b)
        assert a is not None
        assert b is not None
        assert a.dedupe_cluster_id is not None
        assert a.dedupe_cluster_id == b.dedupe_cluster_id
        cluster = s.get(DedupeCluster, a.dedupe_cluster_id)
        assert cluster is not None
        assert cluster.member_count == 2
        assert cluster.root_cause_summary == _PASS1_PENDING_SUMMARY


def test_pass1_does_not_cluster_at_distance_6(isolated_db: Path) -> None:
    """Two findings same key, line_start distance 6 -> two singleton
    clusters, each with member_count=1 and the 'singleton' summary."""
    run_id, task_id = _seed_run_and_task()
    fid_a = _seed_finding(
        run_id=run_id, task_id=task_id, line_start=10
    )
    fid_b = _seed_finding(
        run_id=run_id, task_id=task_id, line_start=16
    )

    n = _pass1(run_id, st_session.session_factory())
    assert n == 2

    with st_session.session_scope() as s:
        a = s.get(Finding, fid_a)
        b = s.get(Finding, fid_b)
        assert a is not None
        assert b is not None
        assert a.dedupe_cluster_id is not None
        assert b.dedupe_cluster_id is not None
        assert a.dedupe_cluster_id != b.dedupe_cluster_id
        for cid in (a.dedupe_cluster_id, b.dedupe_cluster_id):
            cluster = s.get(DedupeCluster, cid)
            assert cluster is not None
            assert cluster.member_count == 1
            assert cluster.root_cause_summary == _PASS1_SINGLETON_SUMMARY


def test_pass1_does_not_cluster_different_attack_classes(
    isolated_db: Path,
) -> None:
    """Same file+function+line, different attack_class -> separate
    clusters (attack_class is part of the bucket key)."""
    run_id, task_id = _seed_run_and_task()
    fid_a = _seed_finding(
        run_id=run_id,
        task_id=task_id,
        attack_class="command_injection",
        line_start=10,
    )
    fid_b = _seed_finding(
        run_id=run_id,
        task_id=task_id,
        attack_class="path_traversal",
        line_start=10,
    )

    n = _pass1(run_id, st_session.session_factory())
    assert n == 2

    with st_session.session_scope() as s:
        a = s.get(Finding, fid_a)
        b = s.get(Finding, fid_b)
        assert a is not None
        assert b is not None
        assert a.dedupe_cluster_id is not None
        assert b.dedupe_cluster_id is not None
        assert a.dedupe_cluster_id != b.dedupe_cluster_id


def test_pass1_function_none_groups_with_none_only(
    isolated_db: Path,
) -> None:
    """Three findings same file+attack_class:
        a: function=None, line=10
        b: function=None, line=12 (distance 2 -- clusters with a)
        c: function='handler', line=11 (separate; NULL function maps
           to '' in the bucket key, not a wildcard)
    Result: cluster of {a, b}, cluster of {c}."""
    run_id, task_id = _seed_run_and_task()
    fid_a = _seed_finding(
        run_id=run_id, task_id=task_id, function=None, line_start=10
    )
    fid_b = _seed_finding(
        run_id=run_id, task_id=task_id, function=None, line_start=12
    )
    fid_c = _seed_finding(
        run_id=run_id, task_id=task_id, function="handler", line_start=11
    )

    n = _pass1(run_id, st_session.session_factory())
    assert n == 2

    with st_session.session_scope() as s:
        a = s.get(Finding, fid_a)
        b = s.get(Finding, fid_b)
        c = s.get(Finding, fid_c)
        assert a is not None
        assert b is not None
        assert c is not None
        assert a.dedupe_cluster_id is not None
        assert b.dedupe_cluster_id is not None
        assert c.dedupe_cluster_id is not None
        # a and b cluster together; c is alone.
        assert a.dedupe_cluster_id == b.dedupe_cluster_id
        assert c.dedupe_cluster_id != a.dedupe_cluster_id
        ab_cluster = s.get(DedupeCluster, a.dedupe_cluster_id)
        c_cluster = s.get(DedupeCluster, c.dedupe_cluster_id)
        assert ab_cluster is not None
        assert c_cluster is not None
        assert ab_cluster.member_count == 2
        assert c_cluster.member_count == 1


def test_pass1_singleton_creates_row_with_member_count_1(
    isolated_db: Path,
) -> None:
    """One finding alone -> exactly one cluster row, member_count=1,
    root_cause_summary='(singleton; no agent review needed)'. The
    finding gets dedupe_cluster_id set."""
    run_id, task_id = _seed_run_and_task()
    fid = _seed_finding(run_id=run_id, task_id=task_id, line_start=10)

    n = _pass1(run_id, st_session.session_factory())
    assert n == 1

    with st_session.session_scope() as s:
        row = s.get(Finding, fid)
        assert row is not None
        assert row.dedupe_cluster_id is not None
        cluster = s.get(DedupeCluster, row.dedupe_cluster_id)
        assert cluster is not None
        assert cluster.member_count == 1
        assert cluster.root_cause_summary == _PASS1_SINGLETON_SUMMARY
        # Exactly one cluster row exists for this run.
        clusters = (
            s.execute(
                select(DedupeCluster).where(DedupeCluster.run_id == run_id)
            )
            .scalars()
            .all()
        )
        assert len(clusters) == 1


def test_pass1_lowest_ulid_is_primary(isolated_db: Path) -> None:
    """Cluster of 3 findings -> dedupe_clusters.primary_finding_id is
    the lowest-lexicographic ULID among the three.

    ULIDs are 26-char Crockford-base32. Prefix differences (01AAA...
    < 01BBB... < 01CCC...) make the lex ordering obvious."""
    run_id, task_id = _seed_run_and_task()
    # Deliberately seed in non-lex order to prove _emit_cluster sorts
    # by id, not insertion order.
    id_high = "01CCCCCCCCCCCCCCCCCCCCCCCC"
    id_low = "01AAAAAAAAAAAAAAAAAAAAAAAA"
    id_mid = "01BBBBBBBBBBBBBBBBBBBBBBBB"
    _seed_finding(
        run_id=run_id, task_id=task_id, finding_id=id_high, line_start=10
    )
    _seed_finding(
        run_id=run_id, task_id=task_id, finding_id=id_low, line_start=11
    )
    _seed_finding(
        run_id=run_id, task_id=task_id, finding_id=id_mid, line_start=12
    )

    n = _pass1(run_id, st_session.session_factory())
    assert n == 1

    with st_session.session_scope() as s:
        # All three share one cluster.
        row = s.get(Finding, id_low)
        assert row is not None
        cluster_id = row.dedupe_cluster_id
        assert cluster_id is not None
        cluster = s.get(DedupeCluster, cluster_id)
        assert cluster is not None
        assert cluster.primary_finding_id == id_low
        assert cluster.member_count == 3


def test_pass1_does_not_touch_dedupe_role_or_other_columns(
    isolated_db: Path,
) -> None:
    """After Pass 1: every member's dedupe_role IS NULL,
    primary_finding_id IS NULL, root_cause_summary IS NULL,
    superseded_at IS NULL. Only dedupe_cluster_id is set.

    The cluster row carries the primary id and the placeholder
    summary; the Finding row does not."""
    run_id, task_id = _seed_run_and_task()
    fid_a = _seed_finding(
        run_id=run_id, task_id=task_id, line_start=10
    )
    fid_b = _seed_finding(
        run_id=run_id, task_id=task_id, line_start=12
    )

    _pass1(run_id, st_session.session_factory())

    with st_session.session_scope() as s:
        for fid in (fid_a, fid_b):
            row = s.get(Finding, fid)
            assert row is not None
            assert row.dedupe_cluster_id is not None
            assert row.dedupe_role is None
            assert row.primary_finding_id is None
            assert row.root_cause_summary is None
            assert row.superseded_at is None


def test_pass1_idempotent(isolated_db: Path) -> None:
    """Running _pass1 twice over the same DB. Second call creates no
    new clusters (the dedupe_cluster_id IS NULL filter excludes
    already-clustered findings) and returns 0."""
    run_id, task_id = _seed_run_and_task()
    _seed_finding(run_id=run_id, task_id=task_id, line_start=10)
    _seed_finding(run_id=run_id, task_id=task_id, line_start=12)

    n1 = _pass1(run_id, st_session.session_factory())
    assert n1 == 1

    with st_session.session_scope() as s:
        before = (
            s.execute(
                select(DedupeCluster).where(DedupeCluster.run_id == run_id)
            )
            .scalars()
            .all()
        )
        before_ids = {c.id for c in before}

    n2 = _pass1(run_id, st_session.session_factory())
    assert n2 == 0

    with st_session.session_scope() as s:
        after = (
            s.execute(
                select(DedupeCluster).where(DedupeCluster.run_id == run_id)
            )
            .scalars()
            .all()
        )
        after_ids = {c.id for c in after}
    assert after_ids == before_ids


def test_pass1_returns_cluster_count(isolated_db: Path) -> None:
    """Seed N findings producing K clusters. Assert _pass1 returns K
    and matches COUNT(*) FROM dedupe_clusters WHERE run_id=...

    Layout (all same attack_class, function='some_fn'):
        file=src/a.py: line 10, 12       -> 1 cluster
        file=src/a.py: line 30           -> 1 cluster (gap 18 > 5)
        file=src/b.py: line 10           -> 1 cluster (different file)
    Total: 3 clusters from 4 findings.
    """
    run_id, task_id = _seed_run_and_task()
    _seed_finding(
        run_id=run_id, task_id=task_id, file="src/a.py", line_start=10
    )
    _seed_finding(
        run_id=run_id, task_id=task_id, file="src/a.py", line_start=12
    )
    _seed_finding(
        run_id=run_id, task_id=task_id, file="src/a.py", line_start=30
    )
    _seed_finding(
        run_id=run_id, task_id=task_id, file="src/b.py", line_start=10
    )

    n = _pass1(run_id, st_session.session_factory())
    assert n == 3

    with st_session.session_scope() as s:
        rows = (
            s.execute(
                select(DedupeCluster).where(DedupeCluster.run_id == run_id)
            )
            .scalars()
            .all()
        )
    assert len(rows) == n


def test_pass1_skips_superseded_findings(isolated_db: Path) -> None:
    """Findings with status='superseded' are excluded by the SELECT
    filter. Their dedupe_cluster_id stays NULL."""
    run_id, task_id = _seed_run_and_task()
    fid_live = _seed_finding(
        run_id=run_id, task_id=task_id, line_start=10
    )
    fid_dead = _seed_finding(
        run_id=run_id,
        task_id=task_id,
        line_start=11,
        status="superseded",
    )

    n = _pass1(run_id, st_session.session_factory())
    # Only the live finding gets a singleton cluster.
    assert n == 1

    with st_session.session_scope() as s:
        live = s.get(Finding, fid_live)
        dead = s.get(Finding, fid_dead)
        assert live is not None
        assert dead is not None
        assert live.dedupe_cluster_id is not None
        assert dead.dedupe_cluster_id is None
        cluster = s.get(DedupeCluster, live.dedupe_cluster_id)
        assert cluster is not None
        assert cluster.member_count == 1
