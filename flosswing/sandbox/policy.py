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

"""Per-attack-class network policy lookup.

Per docs/specs/2026-06-02-v0.4-sandbox-design.md § Component
responsibilities sandbox/policy.py. The policy is read from
AttackClassMeta on the existing registry — no separate registry, no
config file. `lookup()` is the only public entry point.

In v0.4 only `ssrf` sets network_permitted=True; the loopback fixture
itself is deferred, so in practice no class effectively permits
network in v0.4. The plumbing is here so the SSRF attack-class prompt
can flip its own bit when it lands.
"""

from __future__ import annotations

from dataclasses import dataclass

from flosswing import attack_classes
from flosswing.errors import InvalidAttackClassError


@dataclass(frozen=True)
class NetworkPolicy:
    """Resolved network policy for one attack class."""

    attack_class: str
    network_default: bool
    network_permitted: bool


def lookup(attack_class: str) -> NetworkPolicy:
    """Return the network policy for `attack_class`, or raise."""
    meta = attack_classes.REGISTRY.get(attack_class)
    if meta is None:
        raise InvalidAttackClassError(
            f"unknown attack_class {attack_class!r}; "
            f"see ARCHITECTURE.md § Recon for the v1 list"
        )
    return NetworkPolicy(
        attack_class=attack_class,
        network_default=meta.network_default,
        network_permitted=meta.network_permitted,
    )


__all__ = ["NetworkPolicy", "lookup"]
