"""providers.base: SessionResult contract + pure _classify mapping."""

from __future__ import annotations

from flosswing.agent.providers import base


def test_classify_completed() -> None:
    result = base._classify(
        stop_reason="end_turn",
        usage={"input_tokens": 1234, "output_tokens": 567},
        refusal_text=None,
        budget=200_000,
        api_error=None,
    )
    assert result.outcome == "completed"
    assert result.input_tokens == 1234
    assert result.output_tokens == 567


def test_classify_refused() -> None:
    result = base._classify(
        stop_reason="refusal",
        usage={"input_tokens": 100, "output_tokens": 20},
        refusal_text="I can't help with that.",
        budget=200_000,
        api_error=None,
    )
    assert result.outcome == "refused"
    assert result.refusal_text == "I can't help with that."


def test_classify_budget_exceeded() -> None:
    result = base._classify(
        stop_reason="end_turn",
        usage={"input_tokens": 300_000, "output_tokens": 5},
        refusal_text=None,
        budget=200_000,
        api_error=None,
    )
    assert result.outcome == "budget_exceeded"


def test_classify_errored_scrubs_credentials() -> None:
    result = base._classify(
        stop_reason="error",
        usage={"input_tokens": 0, "output_tokens": 0},
        refusal_text=None,
        budget=200_000,
        api_error="500 with Authorization: Bearer eyJsecret.payload.sig in headers",
    )
    assert result.outcome == "errored"
    assert "eyJsecret.payload.sig" not in (result.error_text or "")
    assert "[REDACTED]" in (result.error_text or "")


def test_session_result_reexported_from_runtime() -> None:
    from flosswing.agent.runtime import SessionResult as RuntimeSR

    assert RuntimeSR is base.SessionResult
