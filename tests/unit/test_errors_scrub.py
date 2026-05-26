"""Credential-scrubber tests. The scrubber must keep all auth material
out of strings that flow to logs, the state DB, or report output."""

from __future__ import annotations

import pytest

from flosswing.errors import (
    FlosswingError,
    PathEscapesRepoError,
    scrub,
)


@pytest.mark.parametrize(
    ("raw", "must_not_contain"),
    [
        ("Authorization: Bearer eyJabc.def.ghi", "eyJabc.def.ghi"),
        ("x-api-key: sk-ant-api03-secret", "sk-ant-api03-secret"),
        ("ANTHROPIC_API_KEY=sk-ant-api03-XYZ in env", "sk-ant-api03-XYZ"),
        (
            "ANTHROPIC_FOUNDRY_API_KEY=foundry-key-zzz oops",
            "foundry-key-zzz",
        ),
        (
            "token = eyJhbGciOiJIUzI1NiJ9"
            ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
            ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c done",
            "eyJhbGciOiJIUzI1NiJ9"
            ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
            ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        ),
    ],
)
def test_scrub_redacts_known_credential_forms(raw: str, must_not_contain: str) -> None:
    out = scrub(raw)
    assert must_not_contain not in out
    assert "[REDACTED]" in out


def test_scrub_passes_through_innocent_strings() -> None:
    assert scrub("hello world") == "hello world"
    assert scrub("") == ""


def test_path_escapes_repo_is_a_flosswing_error() -> None:
    err = PathEscapesRepoError("../etc/passwd")
    assert isinstance(err, FlosswingError)
    assert err.code == "path_escapes_repo"
    assert err.retryable is False
    assert "../etc/passwd" in err.message
