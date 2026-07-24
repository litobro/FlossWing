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


def test_session_result_cost_defaults_none() -> None:
    # A construction site that omits cost_usd (e.g. every existing test stub)
    # keeps working, with cost_usd defaulting to None.
    r = base.SessionResult(
        outcome="completed",
        input_tokens=1,
        output_tokens=1,
        cache_read_tokens=0,
        cache_write_tokens=0,
        duration_ms=0,
        tool_calls_count=0,
        refusal_text=None,
        error_text=None,
    )
    assert r.cost_usd is None


def test_classify_passes_cost_through_on_every_branch() -> None:
    common = dict(
        usage={"input_tokens": 1, "output_tokens": 1},
        refusal_text=None,
        budget=200_000,
    )
    completed = base._classify(stop_reason="end_turn", api_error=None, cost_usd=1.5, **common)
    errored = base._classify(stop_reason="error", api_error="boom", cost_usd=2.5, **common)
    refused = base._classify(
        stop_reason="refusal",
        api_error=None,
        cost_usd=3.5,
        usage={"input_tokens": 1, "output_tokens": 1},
        refusal_text="no",
        budget=200_000,
    )
    budget = base._classify(
        stop_reason="end_turn",
        api_error=None,
        cost_usd=4.5,
        usage={"input_tokens": 300_000, "output_tokens": 1},
        refusal_text=None,
        budget=200_000,
    )
    assert completed.cost_usd == 1.5
    assert errored.cost_usd == 2.5
    assert refused.cost_usd == 3.5
    assert budget.cost_usd == 4.5


def test_classify_cost_defaults_none() -> None:
    r = base._classify(
        stop_reason="end_turn",
        usage={"input_tokens": 1, "output_tokens": 1},
        refusal_text=None,
        budget=200_000,
        api_error=None,
    )
    assert r.cost_usd is None


# --- recovered refusals ----------------------------------------------------
#
# The agent harness does not abort on a refused turn: it continues and can
# terminate on a clean end_turn, having produced real work. `stop_reason` is
# therefore the discriminator for whether the refusal was TERMINAL, while
# `refusal_text` records only that a refusal happened somewhere in the session.


def test_classify_recovered_refusal_is_completed_but_keeps_text() -> None:
    """A session that was refused mid-run and then finished cleanly is
    `completed` — so the stage counts the verdict it produced — while still
    reporting the refusal so the operator knows the run was degraded."""
    r = base._classify(
        stop_reason="end_turn",
        usage={"input_tokens": 1250, "output_tokens": 233},
        refusal_text="blocked: violative cyber content",
        budget=200_000,
        api_error=None,
    )
    assert r.outcome == "completed"
    assert r.refusal_text == "blocked: violative cyber content"


def test_classify_terminal_refusal_is_still_refused() -> None:
    """When the refusal IS the terminal state, nothing recovered from it."""
    r = base._classify(
        stop_reason="refusal",
        usage={"input_tokens": 10, "output_tokens": 0},
        refusal_text="blocked: violative cyber content",
        budget=200_000,
        api_error=None,
    )
    assert r.outcome == "refused"
    assert r.refusal_text == "blocked: violative cyber content"


def test_classify_recovered_refusal_over_budget_keeps_text() -> None:
    """budget_exceeded must not silently drop the refusal either."""
    r = base._classify(
        stop_reason="end_turn",
        usage={"input_tokens": 300_000, "output_tokens": 1},
        refusal_text="blocked",
        budget=200_000,
        api_error=None,
    )
    assert r.outcome == "budget_exceeded"
    assert r.refusal_text == "blocked"


def test_classify_api_error_still_outranks_a_refusal() -> None:
    """Unchanged precedence: a real API error wins over refusal state."""
    r = base._classify(
        stop_reason="refusal",
        usage={"input_tokens": 1, "output_tokens": 1},
        refusal_text="blocked",
        budget=200_000,
        api_error="assistant_error: server_error",
    )
    assert r.outcome == "errored"
    assert r.refusal_text is None


def test_classify_no_refusal_leaves_text_none() -> None:
    r = base._classify(
        stop_reason="end_turn",
        usage={"input_tokens": 1, "output_tokens": 1},
        refusal_text=None,
        budget=200_000,
        api_error=None,
    )
    assert r.outcome == "completed"
    assert r.refusal_text is None
