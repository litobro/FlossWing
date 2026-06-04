"""Gated integration smoke for the v0.6 Validate stage.

Gated by FLOSSWING_INTEGRATION=1 (single gate; the Validator MAY call
compile_and_run if it can build a PoC from the command_injection
finding, but the smoke does not require it to — the assertions cover
the validations-table invariants either way).

Per docs/specs/2026-06-02-v0.6-validate-design.md § Success criteria
#2-4 and § Testing strategy Integration test. Asserts:
- >=1 validations row written for the run's findings.
- The command_injection finding has terminal status (confirmed,
  rejected, or uncertain — we don't assert which; this is a real LLM
  call).
- validations.rationale is non-empty and >=50 chars.
- >=1 agent_sessions row with stage='validate' and finding_id set,
  each with terminal outcome and non-zero tokens.

Runs the full pipeline (Recon -> IndexBuild -> Hunt -> Validate)
against tests/corpus/v02_smoke/. Requires valid auth credentials.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from sqlalchemy import select

from flosswing.config import DEFAULT_MODEL, Config
from flosswing.orchestrator import run_scan
from flosswing.state import session as st_session
from flosswing.state.models import AgentSession, Finding, Validation

pytestmark = pytest.mark.skipif(
    os.environ.get("FLOSSWING_INTEGRATION") != "1",
    reason="integration test gated by FLOSSWING_INTEGRATION=1",
)


CORPUS_REPO = Path(__file__).parent.parent / "corpus" / "v02_smoke"


def _resolve_auth_env() -> dict[str, str]:
    """Pick up whichever auth mode the operator has configured.

    Delegates to flosswing.config.resolve() so the test gate matches
    production semantics exactly. Returns an empty dict if no auth
    path is available — the calling test then skips.
    """
    from pathlib import Path as _Path

    from flosswing import config as _cfg
    from flosswing.errors import AuthCredentialMissingError as _AuthMissing

    try:
        c = _cfg.resolve(
            repo_root=_Path("."),
            model=None,
            recon_token_budget=None,
            hunt_token_budget=None,
            validate_token_budget=None,
        )
    except _AuthMissing:
        return {}
    return dict(c.auth_env)


@pytest.mark.asyncio
async def test_validate_smoke_runs_end_to_end_against_v02_smoke(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    auth = _resolve_auth_env()
    if not auth:
        pytest.skip("no auth credentials available")
    monkeypatch.setenv("FLOSSWING_DB_URL", f"sqlite:///{tmp_path}/state.db")
    monkeypatch.setattr(st_session, "_cached_engine", None, raising=False)
    monkeypatch.setattr(
        st_session, "_cached_session_factory", None, raising=False
    )
    monkeypatch.setenv("HOME", str(tmp_path))

    cfg = Config(
        repo_root=CORPUS_REPO.resolve(),
        model=DEFAULT_MODEL,
        recon_token_budget=200_000,
        hunt_token_budget=200_000,
        validate_token_budget=200_000,
        auth_env=auth,
    )
    result = await run_scan(cfg)
    # exit_code 0 (everything terminal) or 1 (all Validate non-terminal)
    # are both allowed; we make per-row assertions below.
    assert result.exit_code in (0, 1), (
        f"unexpected exit_code {result.exit_code}; summary={result.summary}"
    )

    # Snapshot ORM attributes inside the scope; instances expire on commit.
    with st_session.session_scope() as s:
        findings = list(
            s.execute(
                select(Finding).where(Finding.run_id == result.run_id)
            )
            .scalars()
            .all()
        )
    assert len(findings) >= 1, (
        "Hunt did not produce any findings against v02_smoke; "
        "expected at least the command_injection finding"
    )

    with st_session.session_scope() as s:
        validations = list(
            s.execute(
                select(Validation).where(
                    Validation.finding_id.in_([f.id for f in findings])
                )
            )
            .scalars()
            .all()
        )
        validate_sessions = list(
            s.execute(
                select(AgentSession).where(
                    AgentSession.run_id == result.run_id,
                    AgentSession.stage == "validate",
                )
            )
            .scalars()
            .all()
        )

    # Per § Success criteria #2: at least one validations row.
    assert len(validations) >= 1, (
        "Validate did not produce any validations rows; expected at "
        "least one terminal verdict"
    )

    # Per § Success criteria #2: rationale non-empty and >=50 chars.
    for v in validations:
        assert isinstance(v.rationale, str)
        assert len(v.rationale) >= 50, (
            f"validations.rationale too short ({len(v.rationale)} chars): "
            f"{v.rationale!r}"
        )

    # Per § Success criteria #2: validations.verdict is terminal.
    for v in validations:
        assert v.verdict in ("confirmed", "rejected", "uncertain"), (
            f"non-terminal verdict in validations row: {v.verdict!r}"
        )

    # Per § Success criteria #2: agent_sessions row per finding.
    assert len(validate_sessions) >= 1, (
        "No agent_sessions row with stage='validate' was written"
    )
    for sess in validate_sessions:
        assert sess.finding_id is not None
        assert sess.task_id is None
        assert sess.outcome in (
            "completed",
            "refused",
            "budget_exceeded",
            "errored",
        )
        # Even refused/errored sessions consume some input tokens for
        # the system prompt + user prompt.
        assert sess.input_tokens > 0, (
            f"agent_sessions.input_tokens is 0 for sess {sess.id}; "
            "expected nonzero even on refusal"
        )

    # Per § Success criteria #2: findings that received a terminal verdict
    # have status in {confirmed, rejected, uncertain}.
    with st_session.session_scope() as s:
        refreshed = list(
            s.execute(
                select(Finding).where(Finding.run_id == result.run_id)
            )
            .scalars()
            .all()
        )
    validated_ids = {v.finding_id for v in validations}
    for f in refreshed:
        if f.id in validated_ids:
            assert f.status in ("confirmed", "rejected", "uncertain")
            assert f.validated_at is not None
        else:
            # Per design decision #5: a finding that didn't get a verdict
            # (refused / budget_exceeded / errored / no-call session)
            # stays pending_validation.
            assert f.status == "pending_validation"
            assert f.validated_at is None


@pytest.mark.asyncio
async def test_validate_smoke_command_injection_finding_gets_verdict(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The command_injection finding from v0.3's deliberate v02_smoke
    target should receive a terminal verdict. Per § Definition of done."""
    auth = _resolve_auth_env()
    if not auth:
        pytest.skip("no auth credentials available")
    monkeypatch.setenv("FLOSSWING_DB_URL", f"sqlite:///{tmp_path}/state.db")
    monkeypatch.setattr(st_session, "_cached_engine", None, raising=False)
    monkeypatch.setattr(
        st_session, "_cached_session_factory", None, raising=False
    )
    monkeypatch.setenv("HOME", str(tmp_path))

    cfg = Config(
        repo_root=CORPUS_REPO.resolve(),
        model=DEFAULT_MODEL,
        recon_token_budget=200_000,
        hunt_token_budget=200_000,
        validate_token_budget=200_000,
        auth_env=auth,
    )
    result = await run_scan(cfg)
    with st_session.session_scope() as s:
        ci_findings = list(
            s.execute(
                select(Finding).where(
                    Finding.run_id == result.run_id,
                    Finding.attack_class == "command_injection",
                )
            )
            .scalars()
            .all()
        )
    assert len(ci_findings) >= 1, (
        "Expected at least one command_injection finding from v02_smoke; "
        "v0.3's Hunt produces this deliberately"
    )
    # At least one of them should have a validations row.
    with st_session.session_scope() as s:
        validations_for_ci = list(
            s.execute(
                select(Validation).where(
                    Validation.finding_id.in_([f.id for f in ci_findings])
                )
            )
            .scalars()
            .all()
        )
    # If zero, that's allowed per design decision #5 (refusal / no-call)
    # but it's worth surfacing in the test output.
    if len(validations_for_ci) == 0:
        pytest.skip(
            "Validator did not produce a verdict for any command_injection "
            "finding in this run (refusal / no-call session). Re-run to "
            "exercise the verdict path."
        )
    # If we got here, at least one terminal verdict landed.
    for v in validations_for_ci:
        assert v.verdict in ("confirmed", "rejected", "uncertain")
        assert len(v.rationale) >= 50
