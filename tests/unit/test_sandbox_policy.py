"""sandbox/policy.lookup: per-attack-class network policy.

Per docs/specs/2026-06-02-v0.4-sandbox-design.md § Testing strategy
unit tests / test_sandbox_policy.py. Every v1 class defaults to
network_default=False; only ssrf returns network_permitted=True.
Unknown classes raise InvalidAttackClassError (same as
attack_classes.validate).
"""

from __future__ import annotations

import pytest

from flosswing import attack_classes
from flosswing.errors import InvalidAttackClassError
from flosswing.sandbox.policy import NetworkPolicy, lookup


def test_lookup_returns_network_policy_for_known_class() -> None:
    pol = lookup("command_injection")
    assert isinstance(pol, NetworkPolicy)
    assert pol.attack_class == "command_injection"
    assert pol.network_default is False
    assert pol.network_permitted is False


def test_lookup_ssrf_permits_network() -> None:
    """Per spec § Component responsibilities sandbox/policy.py: only ssrf permits."""
    pol = lookup("ssrf")
    assert pol.network_default is False
    assert pol.network_permitted is True


@pytest.mark.parametrize(
    "class_name",
    [
        "command_injection",
        "sqli",
        "xss",
        "path_traversal",
        "buffer_overflow",
        "use_after_free",
        "unsafe_audit",
    ],
)
def test_lookup_non_ssrf_classes_do_not_permit_network(class_name: str) -> None:
    pol = lookup(class_name)
    assert pol.network_permitted is False


def test_lookup_unknown_class_raises() -> None:
    with pytest.raises(InvalidAttackClassError):
        lookup("not_a_real_class")


def test_every_registered_class_resolvable() -> None:
    """Smoke: lookup() works for every name in the registry."""
    for name in attack_classes.names():
        pol = lookup(name)
        assert pol.attack_class == name
