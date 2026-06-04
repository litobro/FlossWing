"""Validate-side error classes per docs/tool-contracts.md § findings
(Validate-side) and docs/specs/2026-06-02-v0.6-validate-design.md §
Error and refusal handling.

Exercises the contract-mapping: which Python class raises which on-the-
wire error code.

Per plan preamble decision #3 (operator override on 2026-06-03), the
defensive byte-level `EvidenceFilesTooLargeError` is NOT implemented.
Only the spec's 100-entry list cap (`EvidenceFilesTooManyError`) ships.
"""

from __future__ import annotations

import pytest

from flosswing.errors import (
    EvidenceFilesTooManyError,
    FindingAlreadyValidatedError,
    FindingNotFoundError,
    FlosswingError,
    RationaleTooShortError,
)


def test_finding_not_found_wire_code() -> None:
    err = FindingNotFoundError("finding_id=01XYZ not present in run 01ABC")
    assert isinstance(err, FlosswingError)
    assert err.code == "finding_not_found"
    assert err.retryable is False
    assert "01XYZ" in str(err)


def test_finding_already_validated_wire_code() -> None:
    err = FindingAlreadyValidatedError(
        "finding_id=01XYZ already has a validations row"
    )
    assert isinstance(err, FlosswingError)
    assert err.code == "finding_already_validated"
    assert err.retryable is False


def test_rationale_too_short_wire_code() -> None:
    err = RationaleTooShortError("rationale must be >=50 chars; got 12")
    assert isinstance(err, FlosswingError)
    assert err.code == "rationale_too_short"
    # The agent can retry with a longer rationale; mark retryable.
    assert err.retryable is True


def test_evidence_files_too_many_wire_code() -> None:
    err = EvidenceFilesTooManyError(
        "evidence_files has 142 entries (cap=100)"
    )
    assert isinstance(err, FlosswingError)
    assert err.code == "evidence_files_too_many"
    assert err.retryable is False


def test_all_new_errors_inherit_flosswing_error() -> None:
    for cls in (
        FindingNotFoundError,
        FindingAlreadyValidatedError,
        RationaleTooShortError,
        EvidenceFilesTooManyError,
    ):
        with pytest.raises(FlosswingError):
            raise cls("m")
