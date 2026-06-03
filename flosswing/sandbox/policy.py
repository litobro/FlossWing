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
