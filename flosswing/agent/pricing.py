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

"""Model cost estimation — the single source of pricing truth.

This estimate is a *fallback*: the Anthropic SDK reports an authoritative
``ResultMessage.total_cost_usd`` that the stage code prefers whenever it is
present (see ``SessionResult.cost_usd``). ``estimate_cost_usd`` is used only
for the interim live figure while a session is still in flight, and for any
provider that does not report cost.

Previously this logic was copy-pasted, identically, into all six stage files.
It now lives here once. Unlike the old copies, it accounts for cache tokens.
"""

from __future__ import annotations

# Per-million-token USD rates (input, output). Placeholder rates; the
# authoritative per-session figure comes from the SDK. Unknown models fall
# back to the Opus rate so an estimate is never silently zero.
MODEL_RATES: dict[str, tuple[float, float]] = {
    "claude-opus-4-7": (15.0, 75.0),
    "claude-opus-4-8": (15.0, 75.0),
    "claude-sonnet-4-6": (3.0, 15.0),
    "claude-haiku-4-5": (0.80, 4.00),
}
_DEFAULT_RATE: tuple[float, float] = (15.0, 75.0)

# Cache tokens are billed relative to the input rate: reads are cheap, writes
# carry a premium. Multipliers follow Anthropic's published prompt-caching
# pricing. The old per-stage estimates ignored cache tokens entirely, which
# undercounted any run that used prompt caching.
_CACHE_READ_MULTIPLIER = 0.1
_CACHE_WRITE_MULTIPLIER = 1.25


def estimate_cost_usd(
    *,
    model: str,
    input_tokens: int,
    output_tokens: int,
    cache_read_tokens: int = 0,
    cache_write_tokens: int = 0,
) -> float:
    """Estimate session cost in USD from token counts.

    Cache read/write tokens are priced as multiples of the model's input rate.
    """
    in_rate, out_rate = MODEL_RATES.get(model, _DEFAULT_RATE)
    return (
        (input_tokens / 1_000_000) * in_rate
        + (output_tokens / 1_000_000) * out_rate
        + (cache_read_tokens / 1_000_000) * in_rate * _CACHE_READ_MULTIPLIER
        + (cache_write_tokens / 1_000_000) * in_rate * _CACHE_WRITE_MULTIPLIER
    )


def resolve_cost_usd(
    *,
    model: str,
    input_tokens: int,
    output_tokens: int,
    cache_read_tokens: int = 0,
    cache_write_tokens: int = 0,
    authoritative: float | None,
) -> float:
    """The session's cost: the provider's authoritative figure if present, else
    an estimate from the token counts. This is the one place stages decide."""
    if authoritative is not None:
        return authoritative
    return estimate_cost_usd(
        model=model,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cache_read_tokens=cache_read_tokens,
        cache_write_tokens=cache_write_tokens,
    )
