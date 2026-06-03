"""Sandbox-related error classes per docs/specs/2026-06-02-v0.4-sandbox-design.md.

These exercise the contract-mapping: which Python class raises which
on-the-wire error code. The mapping itself is the load-bearing contract
since multiple in-process exceptions can collapse onto the same code.
"""

from __future__ import annotations

import pytest

from flosswing.errors import (
    FlosswingError,
    LanguageNotSupportedError,
    NetworkNotPermittedError,
    PathEscapesScratchError,
    ResourceLimitExceededError,
    SandboxBackendUnavailableError,
    SandboxImageBuildError,
    SandboxUnavailableError,
)


def test_path_escapes_scratch_maps_to_input_validation_failed() -> None:
    """Per design decision #6: relative_path '..' maps to the v0.2 umbrella code."""
    err = PathEscapesScratchError("src/../escape.py")
    assert isinstance(err, FlosswingError)
    assert err.code == "input_validation_failed"
    assert err.retryable is False
    assert "src/../escape.py" in str(err)


def test_sandbox_image_build_error_carries_log_tail() -> None:
    """Build-log tail is part of the message — operator-diagnosable failures."""
    log_tail = "Step 4/5: RUN pip install ...\nERROR: package not found"
    err = SandboxImageBuildError(language="python", log_tail=log_tail)
    assert isinstance(err, FlosswingError)
    assert err.code == "sandbox_unavailable"
    assert err.retryable is False
    assert "python" in str(err)
    assert "package not found" in str(err)


def test_sandbox_backend_unavailable_specific_class_maps_to_umbrella_code() -> None:
    """Daemon-down-mid-run is a specific in-process raise; same wire code."""
    err = SandboxBackendUnavailableError("docker daemon ping failed")
    assert isinstance(err, FlosswingError)
    assert err.code == "sandbox_unavailable"
    assert err.retryable is False


def test_sandbox_backend_unavailable_is_distinct_class_from_umbrella() -> None:
    """The two classes share a code but differ as Python types (raise-site clarity)."""
    assert SandboxBackendUnavailableError is not SandboxUnavailableError


def test_network_not_permitted_distinct_code() -> None:
    err = NetworkNotPermittedError(
        "command_injection does not permit network access"
    )
    assert err.code == "network_not_permitted"
    assert err.retryable is False


def test_language_not_supported_distinct_code() -> None:
    err = LanguageNotSupportedError("scheme")
    assert err.code == "language_not_supported"
    assert err.retryable is False
    assert "scheme" in str(err)


def test_resource_limit_exceeded_distinct_code() -> None:
    err = ResourceLimitExceededError(
        "timeout_seconds=400 exceeds hard cap 300"
    )
    assert err.code == "resource_limit_exceeded"
    assert err.retryable is False


def test_all_new_errors_inherit_flosswing_error() -> None:
    """Cheap insurance: every sandbox error converts to a tool error via the base class."""
    for cls in (
        PathEscapesScratchError,
        SandboxImageBuildError,
        SandboxBackendUnavailableError,
        NetworkNotPermittedError,
        LanguageNotSupportedError,
        ResourceLimitExceededError,
    ):
        with pytest.raises(FlosswingError):
            if cls is PathEscapesScratchError:
                raise cls("p")
            elif cls is SandboxImageBuildError:
                raise cls(language="python", log_tail="t")
            else:
                raise cls("m")
