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

"""flosswing.agent.pricing — shared cost estimation."""

from __future__ import annotations

from flosswing.agent import pricing


def test_estimate_cost_basic_input_output() -> None:
    # 1M input @ $15 + 1M output @ $75 = $90 for a known model.
    cost = pricing.estimate_cost_usd(
        model="claude-opus-4-8", input_tokens=1_000_000, output_tokens=1_000_000
    )
    assert cost == 90.0


def test_estimate_cost_unknown_model_falls_back_to_opus_rate() -> None:
    known = pricing.estimate_cost_usd(
        model="claude-opus-4-8", input_tokens=1_000_000, output_tokens=0
    )
    unknown = pricing.estimate_cost_usd(
        model="totally-made-up", input_tokens=1_000_000, output_tokens=0
    )
    assert unknown == known == 15.0


def test_estimate_cost_accounts_for_cache_tokens() -> None:
    # The old per-stage estimate ignored cache tokens; the shared one prices
    # them relative to the input rate (reads 0.1x, writes 1.25x).
    base = pricing.estimate_cost_usd(
        model="claude-opus-4-8", input_tokens=0, output_tokens=0
    )
    assert base == 0.0
    with_cache = pricing.estimate_cost_usd(
        model="claude-opus-4-8",
        input_tokens=0,
        output_tokens=0,
        cache_read_tokens=1_000_000,
        cache_write_tokens=1_000_000,
    )
    # 1M reads @ 15*0.1 + 1M writes @ 15*1.25 = 1.5 + 18.75
    assert round(with_cache, 6) == round(1.5 + 18.75, 6)


def test_resolve_prefers_authoritative_when_present() -> None:
    cost = pricing.resolve_cost_usd(
        model="claude-opus-4-8",
        input_tokens=1_000_000,
        output_tokens=1_000_000,
        authoritative=3.21,
    )
    assert cost == 3.21  # authoritative wins, estimate ignored


def test_resolve_estimates_when_authoritative_none() -> None:
    cost = pricing.resolve_cost_usd(
        model="claude-opus-4-8",
        input_tokens=1_000_000,
        output_tokens=0,
        authoritative=None,
    )
    assert cost == 15.0  # falls back to the estimate


def test_resolve_authoritative_zero_falls_back_to_estimate() -> None:
    # A reported 0.0 for a token-consuming session (e.g. subscription auth that
    # doesn't surface per-token billing) must NOT be taken as final — that would
    # silently record $0.00 for a real session. It falls back to the estimate,
    # honoring "a token-consuming session is never silently zero".
    cost = pricing.resolve_cost_usd(
        model="claude-opus-4-8",
        input_tokens=1_000_000,
        output_tokens=0,
        authoritative=0.0,
    )
    assert cost == 15.0  # estimated, not the reported zero


def test_resolve_zero_tokens_zero_authoritative_is_zero() -> None:
    # With no tokens, both the reported 0.0 and the estimate are 0.0 — no spurious cost.
    cost = pricing.resolve_cost_usd(
        model="claude-opus-4-8",
        input_tokens=0,
        output_tokens=0,
        authoritative=0.0,
    )
    assert cost == 0.0
