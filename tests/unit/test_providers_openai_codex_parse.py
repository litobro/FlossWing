"""Codex app-server event parsing -> SessionResult, against committed fixtures."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from flosswing.agent.providers.openai_codex import _classify_events, _harvest_usage

FIX = Path(__file__).parent.parent / "fixtures" / "codex"


def _sc_events(name: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for line in (FIX / name).read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
        if rec.get("dir") == "S->C":
            out.append(rec["msg"])
    return out


def _usage_payloads(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        e["params"]["tokenUsage"]
        for e in events
        if e.get("method") == "thread/tokenUsage/updated"
    ]


def test_harvest_usage_maps_total_fields() -> None:
    last = _usage_payloads(_sc_events("round_trip.jsonl"))[-1]
    assert _harvest_usage(last) == {
        "input_tokens": 43458,
        "output_tokens": 219,
        "cache_read_tokens": 39680,
        "cache_write_tokens": 0,
    }


def test_harvest_usage_tolerates_missing_keys() -> None:
    assert _harvest_usage({}) == {
        "input_tokens": 0,
        "output_tokens": 0,
        "cache_read_tokens": 0,
        "cache_write_tokens": 0,
    }


def test_round_trip_completed() -> None:
    res = _classify_events(_sc_events("round_trip.jsonl"), budget=10_000_000)
    assert res.outcome == "completed"
    assert res.input_tokens > 0
    assert res.tool_calls_count >= 1
    assert res.cost_usd is None
    assert res.refusal_text is None


def test_refusal_fixture_refused() -> None:
    res = _classify_events(_sc_events("refusal.jsonl"), budget=10_000_000)
    assert res.outcome == "refused"
    assert res.refusal_text
    assert res.error_text is None
    assert res.tool_calls_count == 0


def test_budget_exceeded() -> None:
    res = _classify_events(_sc_events("round_trip.jsonl"), budget=1)
    assert res.outcome == "budget_exceeded"


def test_turn_error_is_errored_not_refused() -> None:
    evs = _sc_events("refusal.jsonl")
    for e in evs:
        if e.get("method") == "turn/completed":
            e["params"]["turn"]["status"] = "failed"
            e["params"]["turn"]["error"] = {"message": "boom"}
    res = _classify_events(evs, budget=10_000_000)
    assert res.outcome == "errored"


def test_jsonrpc_error_response_is_errored() -> None:
    res = _classify_events(
        [{"jsonrpc": "2.0", "id": 3, "error": {"code": -1, "message": "bad"}}],
        budget=10,
    )
    assert res.outcome == "errored"


def test_decline_text_with_tool_calls_recorded_not_terminal() -> None:
    evs = _sc_events("round_trip.jsonl")
    for e in evs:
        item = e.get("params", {}).get("item", {})
        if item.get("type") == "agentMessage":
            item["text"] = "I can't help with that part."
    res = _classify_events(evs, budget=10_000_000)
    assert res.outcome == "completed"
    assert res.refusal_text == "I can't help with that part."
