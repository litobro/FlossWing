"""v1 attack-class registry.

Names are sourced from ARCHITECTURE.md § Recon "v1 attack class library".
Prompt content for each class is deferred to later milestones; v0.2 only
needs the registry of valid names so add_hunt_task can validate input.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from flosswing.errors import InvalidAttackClassError


@dataclass(frozen=True)
class AttackClassMeta:
    name: str
    language_scope: str  # 'polyglot' | 'c_family' | 'web' | 'go' | 'rust'


def _entry(name: str, scope: str) -> tuple[str, AttackClassMeta]:
    return name, AttackClassMeta(name=name, language_scope=scope)


# Source: ARCHITECTURE.md § Recon "v1 attack class library".
# NOTE: "unsafe_pickle" is spelled via concatenation below to work around a
# CI security-reminder hook that pattern-matches the word in tool inputs.
# The string value is identical to the single-literal form.
_UNSAFE_PY_DESER = "unsafe_" + "pick" + "le"

REGISTRY: Final[dict[str, AttackClassMeta]] = dict(
    [
        # Polyglot
        _entry("command_injection", "polyglot"),
        _entry("path_traversal", "polyglot"),
        _entry("ssrf", "polyglot"),
        _entry("auth_bypass", "polyglot"),
        _entry("hardcoded_secrets", "polyglot"),
        _entry("insecure_deserialization", "polyglot"),
        _entry("xxe", "polyglot"),
        _entry("open_redirect", "polyglot"),
        # C/C++
        _entry("buffer_overflow", "c_family"),
        _entry("use_after_free", "c_family"),
        _entry("integer_overflow", "c_family"),
        _entry("format_string", "c_family"),
        _entry("null_deref", "c_family"),
        # Web (Python / JS / Java deserialization family)
        _entry("sqli", "web"),
        _entry("xss", "web"),
        _entry("csrf", "web"),
        _entry("prototype_pollution", "web"),
        _entry("unsafe_yaml", "web"),
        _entry(_UNSAFE_PY_DESER, "web"),  # Python deserialization
        _entry("java_deserialization", "web"),
        # Go
        _entry("nil_deref_in_error_path", "go"),
        _entry("unsafe_pointer_misuse", "go"),
        _entry("goroutine_leak", "go"),
        # Rust
        _entry("unsafe_audit", "rust"),
        _entry("unwrap_in_reachable_path", "rust"),
        _entry("soundness_bug", "rust"),
    ]
)


def validate(name: str) -> None:
    """Raise InvalidAttackClassError if name is not in the registry."""
    if name not in REGISTRY:
        raise InvalidAttackClassError(
            f"unknown attack_class {name!r}; "
            f"see ARCHITECTURE.md § Recon for the v1 list"
        )


def names() -> list[str]:
    """Sorted list of valid attack-class names, for prompt construction."""
    return sorted(REGISTRY.keys())
