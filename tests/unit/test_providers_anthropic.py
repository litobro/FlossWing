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

"""providers.anthropic_sdk: auth validation + SDK error parsing."""

from __future__ import annotations

from collections.abc import Mapping

import pytest

from flosswing.agent.providers import anthropic_sdk as a
from flosswing.errors import AuthCredentialMissingError


def _provider() -> a.AnthropicSDKProvider:
    return a.AnthropicSDKProvider()


def test_name_and_auth_env_keys() -> None:
    p = _provider()
    assert p.name == "anthropic"
    assert "ANTHROPIC_API_KEY" in p.auth_env_keys
    assert "CLAUDE_CODE_USE_FOUNDRY" in p.auth_env_keys
    assert "AZURE_CLIENT_SECRET" in p.auth_env_keys
    assert "ANTHROPIC_DEFAULT_OPUS_MODEL" in p.auth_env_keys


def test_validate_auth_accepts_direct_key() -> None:
    _provider().validate_auth({"ANTHROPIC_API_KEY": "sk-ant-test"})  # no raise


def test_validate_auth_accepts_foundry_key() -> None:
    env: Mapping[str, str] = {
        "CLAUDE_CODE_USE_FOUNDRY": "1",
        "ANTHROPIC_FOUNDRY_RESOURCE": "res",
        "ANTHROPIC_FOUNDRY_API_KEY": "key",
    }
    _provider().validate_auth(env)  # no raise


def test_validate_auth_rejects_empty_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(a, "_has_az_session", lambda: False)
    with pytest.raises(AuthCredentialMissingError):
        _provider().validate_auth({})


def test_api_error_from_result_clean_run_returns_none() -> None:
    assert a._api_error_from_result(
        is_error=False, subtype="success", errors=None
    ) is None


def test_api_error_from_result_spurious_success_returns_none() -> None:
    assert a._api_error_from_result(
        is_error=True, subtype="success", errors=None
    ) is None


def test_api_error_from_result_real_error_propagates() -> None:
    msg = a._api_error_from_result(
        is_error=True, subtype="error_max_turns", errors=["boom"]
    )
    assert msg == "boom"


def test_api_error_from_result_spurious_success_ignores_errors_list() -> None:
    """Even when ``errors`` is populated (e.g. ["http_429"]), the success
    subtype takes precedence — the session itself succeeded."""
    assert a._api_error_from_result(
        is_error=True, subtype="success", errors=["http_429"]
    ) is None


def test_api_error_from_result_max_turns_sentinel() -> None:
    """``error_max_turns`` with no errors list returns the structured sentinel
    string ``result_is_error:<subtype>`` — this is the critical untested
    branch of the ``or f"result_is_error:{subtype}"`` fallback."""
    assert a._api_error_from_result(
        is_error=True, subtype="error_max_turns", errors=None
    ) == "result_is_error:error_max_turns"


def test_api_error_from_result_prefers_errors_list_over_sentinel() -> None:
    """When the SDK populates ``errors``, that's strictly more informative
    than the generic ``result_is_error:<subtype>`` sentinel — use it."""
    assert a._api_error_from_result(
        is_error=True,
        subtype="error_during_execution",
        errors=["upstream timed out after 60s"],
    ) == "upstream timed out after 60s"


def test_api_error_from_result_joins_multiple_errors() -> None:
    """Multiple entries in ``errors`` are semicolon-joined, preserving order."""
    assert a._api_error_from_result(
        is_error=True,
        subtype="error_during_execution",
        errors=["err one", "err two"],
    ) == "err one; err two"


def test_is_spurious_sdk_exit_error_anchors_full_string() -> None:
    assert a._is_spurious_sdk_exit_error(
        RuntimeError("Claude Code returned an error result: success")
    )
    assert not a._is_spurious_sdk_exit_error(
        RuntimeError("returned an error result: success")
    )
