"""Attack-class registry: enumeration matches ARCHITECTURE.md § Recon."""

from __future__ import annotations

import pytest

from flosswing import attack_classes as ac
from flosswing.errors import InvalidAttackClassError


def test_known_attack_classes_match_architecture_md() -> None:
    # Sanity: a sample of each language family from ARCHITECTURE.md § Recon.
    for name in [
        "command_injection",
        "path_traversal",
        "ssrf",
        "buffer_overflow",
        "use_after_free",
        "sqli",
        "xss",
        "unsafe_yaml",
        "nil_deref_in_error_path",
        "unsafe_audit",
    ]:
        assert name in ac.REGISTRY, f"{name} missing from registry"


def test_validate_accepts_known_class() -> None:
    ac.validate("command_injection")  # does not raise


def test_validate_rejects_unknown_class() -> None:
    with pytest.raises(InvalidAttackClassError):
        ac.validate("totally_made_up")


def test_attack_class_meta_has_network_fields_with_defaults() -> None:
    from flosswing.attack_classes import REGISTRY

    meta = REGISTRY["command_injection"]
    assert meta.network_default is False
    assert meta.network_permitted is False


def test_attack_class_meta_ssrf_permits_network() -> None:
    from flosswing.attack_classes import REGISTRY

    meta = REGISTRY["ssrf"]
    assert meta.network_default is False
    assert meta.network_permitted is True
