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

"""AnthropicSDKProvider.run_session — the SDK message loop.

The first tests that mock ``claude_agent_sdk.query`` directly (stage tests stub
``runtime.run_session``, bypassing this file). Covers live-usage emission,
throttling, and authoritative-cost capture.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import pytest
from claude_agent_sdk import AssistantMessage, ResultMessage, TextBlock

from flosswing.agent.providers import anthropic_sdk
from flosswing.agent.providers.base import UsageSnapshot


def _assistant(*, in_tok: int, out_tok: int) -> AssistantMessage:
    return AssistantMessage(
        content=[],
        model="claude-opus-4-8",
        usage={"input_tokens": in_tok, "output_tokens": out_tok},
        stop_reason=None,
    )


def _result(*, in_tok: int, out_tok: int, cost: float | None) -> ResultMessage:
    return ResultMessage(
        subtype="success",
        duration_ms=1,
        duration_api_ms=1,
        is_error=False,
        num_turns=1,
        session_id="s",
        stop_reason="end_turn",
        total_cost_usd=cost,
        usage={"input_tokens": in_tok, "output_tokens": out_tok},
    )


def _patch_query(monkeypatch: pytest.MonkeyPatch, messages: list[Any]) -> None:
    async def fake_query(*, prompt: str, options: Any) -> AsyncIterator[Any]:
        for m in messages:
            yield m

    monkeypatch.setattr(anthropic_sdk, "query", fake_query)


async def _run(on_usage: Any = None) -> Any:
    provider = anthropic_sdk.AnthropicSDKProvider()
    return await provider.run_session(
        model="claude-opus-4-8",
        system_prompt="",
        tools=[],
        user_prompt="",
        token_budget=10_000_000,
        auth_env={},
        run_id="r",
        stage="recon",
        on_usage=on_usage,
    )


@pytest.mark.asyncio
async def test_captures_authoritative_cost_from_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_query(monkeypatch, [_result(in_tok=1000, out_tok=200, cost=3.21)])
    result = await _run()
    assert result.outcome == "completed"
    assert result.cost_usd == 3.21


@pytest.mark.asyncio
async def test_cost_is_none_when_no_result_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Only an assistant turn, never a ResultMessage → no authoritative cost.
    _patch_query(monkeypatch, [_assistant(in_tok=1000, out_tok=200)])
    result = await _run()
    assert result.cost_usd is None


@pytest.mark.asyncio
async def test_cost_is_none_when_result_reports_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_query(monkeypatch, [_result(in_tok=10, out_tok=5, cost=None)])
    result = await _run()
    assert result.cost_usd is None


@pytest.mark.asyncio
async def test_on_usage_fires_and_is_throttled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Freeze the clock so the two rapid assistant turns fall inside one throttle
    # window: the first emits, the second is suppressed. The ResultMessage does
    # NOT emit (that final frame would only be written then immediately deleted
    # by the caller's finalize). Net: exactly 1 emit.
    monkeypatch.setattr(anthropic_sdk.time, "monotonic", lambda: 100.0)
    _patch_query(
        monkeypatch,
        [
            _assistant(in_tok=100, out_tok=10),
            _assistant(in_tok=300, out_tok=40),
            _result(in_tok=300, out_tok=40, cost=1.5),
        ],
    )
    snaps: list[UsageSnapshot] = []
    await _run(on_usage=snaps.append)
    assert len(snaps) == 1
    # Interim emit carries the latest turn's usage; cost is None (estimated
    # downstream) until the authoritative figure lands in the finalized row.
    assert snaps[0].input_tokens == 100
    assert snaps[0].cost_usd is None


@pytest.mark.asyncio
async def test_on_usage_exception_does_not_abort_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_query(
        monkeypatch,
        [_assistant(in_tok=100, out_tok=10), _result(in_tok=100, out_tok=10, cost=0.2)],
    )

    def boom(_snap: UsageSnapshot) -> None:
        raise RuntimeError("callback blew up")

    result = await _run(on_usage=boom)  # must not raise
    assert result.outcome == "completed"
    assert result.cost_usd == 0.2


@pytest.mark.asyncio
async def test_on_usage_none_is_fine(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_query(monkeypatch, [_result(in_tok=1, out_tok=1, cost=0.0)])
    result = await _run(on_usage=None)
    assert result.outcome == "completed"


# --- classifier refusals (real-time cyber safeguards) ----------------------
#
# When a safety classifier declines a request and no fallback model is
# configured, the CLI emits a *synthetic* assistant turn carrying BOTH
# stop_reason="refusal" AND error="invalid_request" — the latter because the
# SDK's AssistantMessageError enum has no refusal member and buckets it into
# the nearest category. Reported by Foundry-routed claude-opus-5 on the
# Validate stage; verified against a captured message stream.


_REFUSAL_TEXT = (
    "API Error: Claude Code is unable to respond to this request, which "
    "appears to violate our Usage Policy. This request triggered "
    "restrictions on violative cyber content."
)


def _synthetic_refusal() -> AssistantMessage:
    return AssistantMessage(
        content=[TextBlock(text=_REFUSAL_TEXT)],
        model="<synthetic>",
        usage={"input_tokens": 0, "output_tokens": 0},
        stop_reason="refusal",
        error="invalid_request",
    )


@pytest.mark.asyncio
async def test_classifier_refusal_classifies_as_refused_not_errored(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A refusal must not be laundered into a generic API error.

    ``_classify`` precedence is api_error > refusal (per the provider
    abstraction spec), so a provider that reports the SDK's "invalid_request"
    tag as api_error loses the refusal — which stages count separately and
    CLAUDE.md tracks as a first-class failure mode.
    """
    _patch_query(monkeypatch, [_assistant(in_tok=500, out_tok=20), _synthetic_refusal()])
    result = await _run()
    assert result.outcome == "refused"
    assert result.error_text is None


@pytest.mark.asyncio
async def test_classifier_refusal_captures_refusal_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The explanation lives in the synthetic turn's text block, not in
    ResultMessage.result — capture it so the operator sees *why*."""
    _patch_query(monkeypatch, [_synthetic_refusal()])
    result = await _run()
    assert result.refusal_text is not None
    assert "violative cyber content" in result.refusal_text


@pytest.mark.asyncio
async def test_refusal_survives_a_later_successful_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The production shape: the harness does NOT abort on a refused turn.

    The captured stream continues past the refusal with further assistant
    turns and terminates on a clean ``result``/``end_turn``. That overwrites
    ``stop_reason``, so the refusal is only still visible if ``refusal_text``
    is sticky — otherwise a session whose whole point was refused reports as
    an ordinary success.
    """
    _patch_query(
        monkeypatch,
        [
            _assistant(in_tok=500, out_tok=20),
            _synthetic_refusal(),
            _assistant(in_tok=1250, out_tok=200),
            _result(in_tok=1250, out_tok=233, cost=0.14),
        ],
    )
    result = await _run()
    assert result.outcome == "refused"
    assert result.refusal_text is not None
    assert result.error_text is None
    # Usage still comes from the terminal ResultMessage, not the synthetic
    # zero-token refusal turn.
    assert result.input_tokens == 1250


@pytest.mark.asyncio
async def test_non_refusal_assistant_error_still_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression guard: only a refusal-flagged turn takes the refusal path.
    An assistant error without stop_reason="refusal" stays an api_error."""
    msg = AssistantMessage(
        content=[],
        model="claude-opus-4-8",
        usage={"input_tokens": 10, "output_tokens": 0},
        stop_reason=None,
        error="server_error",
    )
    _patch_query(monkeypatch, [msg])
    result = await _run()
    assert result.outcome == "errored"
    assert result.error_text is not None
    assert "server_error" in result.error_text
