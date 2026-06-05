"""agent/runtime: outcome classification against canned SDK responses.

We test _classify() directly — pure function, no SDK mocking needed.
Full run_session() coverage requires a real claude CLI subprocess and
lives in the gated integration test.
"""

from __future__ import annotations

from flosswing.agent import runtime as rt


def test_classify_completed() -> None:
    result = rt._classify(
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
    result = rt._classify(
        stop_reason="refusal",
        usage={"input_tokens": 100, "output_tokens": 20},
        refusal_text="I can't help with that.",
        budget=200_000,
        api_error=None,
    )
    assert result.outcome == "refused"
    assert result.refusal_text == "I can't help with that."


def test_classify_budget_exceeded() -> None:
    result = rt._classify(
        stop_reason="end_turn",
        usage={"input_tokens": 300_000, "output_tokens": 5},
        refusal_text=None,
        budget=200_000,
        api_error=None,
    )
    assert result.outcome == "budget_exceeded"


def test_classify_errored_scrubs_credentials() -> None:
    result = rt._classify(
        stop_reason="error",
        usage={"input_tokens": 0, "output_tokens": 0},
        refusal_text=None,
        budget=200_000,
        api_error="500 with Authorization: Bearer eyJsecret.payload.sig in headers",
    )
    assert result.outcome == "errored"
    assert "eyJsecret.payload.sig" not in (result.error_text or "")
    assert "[REDACTED]" in (result.error_text or "")


# ---------------------------------------------------------------------------
# Issue #22: SDK "is_error with subtype=success" carve-out
# ---------------------------------------------------------------------------


def test_api_error_from_result_clean_run_returns_none() -> None:
    """is_error=False is the canonical happy-path; no error to propagate."""
    assert rt._api_error_from_result(
        is_error=False, subtype="success", errors=None
    ) is None


def test_api_error_from_result_spurious_success_subtype_returns_none() -> None:
    """is_error=True with subtype="success" is the SDK's "session ran cleanly
    but the underlying HTTP call had a hiccup" pattern. The agent's output is
    intact; don't bucket as errored. Regression for the 2026-06-04 SFA scan
    where 1 of 6 Hunt tasks landed errored with `out=908` (the agent produced
    output) and error text "Claude Code returned an error result: success"."""
    assert rt._api_error_from_result(
        is_error=True, subtype="success", errors=None
    ) is None


def test_api_error_from_result_spurious_success_ignores_errors_list() -> None:
    """Even when ``errors`` is populated (e.g. ["http_429"]), the success
    subtype takes precedence — the session itself succeeded."""
    assert rt._api_error_from_result(
        is_error=True, subtype="success", errors=["http_429"]
    ) is None


def test_api_error_from_result_max_turns_propagates() -> None:
    """``error_max_turns`` is a real error: the session ran out of turns
    before finishing. Returns a structured sentinel when ``errors`` is empty."""
    assert rt._api_error_from_result(
        is_error=True, subtype="error_max_turns", errors=None
    ) == "result_is_error:error_max_turns"


def test_api_error_from_result_prefers_errors_list_over_sentinel() -> None:
    """When the SDK populates ``errors``, that's strictly more informative
    than the generic ``result_is_error:<subtype>`` sentinel — use it."""
    assert rt._api_error_from_result(
        is_error=True,
        subtype="error_during_execution",
        errors=["upstream timed out after 60s"],
    ) == "upstream timed out after 60s"


def test_api_error_from_result_joins_multiple_errors() -> None:
    """Multiple entries in ``errors`` are semicolon-joined, preserving order."""
    assert rt._api_error_from_result(
        is_error=True,
        subtype="error_during_execution",
        errors=["err one", "err two"],
    ) == "err one; err two"


def test_is_spurious_sdk_exit_error_matches_canonical_message() -> None:
    """The SDK wraps the CLI's non-zero exit as
    ``"Claude Code returned an error result: success"`` after emitting a
    ResultMessage with ``is_error=True, subtype="success"``. Identify it."""
    exc = Exception("Claude Code returned an error result: success")
    assert rt._is_spurious_sdk_exit_error(exc) is True


def test_is_spurious_sdk_exit_error_rejects_other_subtypes() -> None:
    """Other subtypes are real errors; don't suppress them."""
    exc = Exception("Claude Code returned an error result: error_max_turns")
    assert rt._is_spurious_sdk_exit_error(exc) is False


def test_is_spurious_sdk_exit_error_rejects_unrelated_exceptions() -> None:
    """Unrelated exceptions (network, programmer error, etc.) are NOT
    suppressed — only the canonical SDK wrapped-CLI-exit case is."""
    exc = ConnectionError("connection refused")
    assert rt._is_spurious_sdk_exit_error(exc) is False
