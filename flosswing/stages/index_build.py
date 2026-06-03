"""IndexBuild stage — thin orchestrator-stage wrapper.

Per docs/specs/2026-06-02-v0.5-symbol-index-design.md § Component
responsibilities flosswing/stages/index_build.py. Distinct from
flosswing.index.build for the same reason stages/recon.py is distinct
from agent runtime: the stage module is the orchestrator's contact
point, the package does the work.

The stage does NOT write an agent_sessions row — IndexBuild is a
deterministic phase, not an agent stage.
"""

from __future__ import annotations

from pathlib import Path

from flosswing.config import Config
from flosswing.index.build import IndexBuildResult, build_index
from flosswing.state.session import SessionFactory


async def run(
    *,
    run_id: str,
    recon_artifact_id: str,
    repo: Path,
    languages: set[str],
    cfg: Config,
    session_factory: SessionFactory,
) -> IndexBuildResult:
    """Run the deterministic IndexBuild phase for `run_id`.

    Per spec § Data flow this is called by the orchestrator between
    Recon completion and Hunt start. The result is consumed by the
    orchestrator's finalization logic — empty result (symbols == 0)
    means the run finalizes as `errored` with `index_build_empty`.
    """
    del cfg  # reserved for future depth-mode / config gating
    scratch_dir = Path.home() / ".flosswing" / "runs" / run_id / "index"
    scratch_dir.mkdir(parents=True, exist_ok=True)
    return await build_index(
        run_id=run_id,
        recon_artifact_id=recon_artifact_id,
        repo=repo,
        languages=languages,
        session_factory=session_factory,
        scratch_dir=scratch_dir,
    )


__all__ = ["run"]
