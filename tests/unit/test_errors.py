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

from __future__ import annotations

from flosswing.errors import (
    FlosswingError,
    ProviderNotImplementedError,
    UnknownProviderError,
)


def test_provider_error_types_are_flosswing_errors() -> None:
    assert issubclass(UnknownProviderError, FlosswingError)
    assert issubclass(ProviderNotImplementedError, FlosswingError)
    assert UnknownProviderError("x").code == "unknown_provider"
    assert ProviderNotImplementedError("x").code == "provider_not_implemented"
    assert UnknownProviderError("x").retryable is False
    assert ProviderNotImplementedError("x").retryable is False


def test_ollama_backend_unavailable_is_flosswing_error() -> None:
    from flosswing.errors import FlosswingError, OllamaBackendUnavailableError

    err = OllamaBackendUnavailableError("ollama not reachable at default host")
    assert isinstance(err, FlosswingError)
    assert err.code == "ollama_backend_unavailable"
    assert err.retryable is False
    assert err.message == "ollama not reachable at default host"
