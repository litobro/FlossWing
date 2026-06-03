"""FlossWing exception hierarchy and credential scrubber.

All tools convert FlosswingError subclasses to structured ToolError
payloads per docs/tool-contracts.md § Errors. The scrub() function
runs over any string that may reach stderr, the state DB, or report
output.
"""

from __future__ import annotations

import re
from typing import ClassVar, Final


class FlosswingError(Exception):
    """Base class for all FlossWing-raised errors.

    Carries the structured fields the tool layer needs to construct a
    ToolError payload: a short error code, a human-readable message,
    and whether the agent could reasonably retry.
    """

    code: ClassVar[str] = "flosswing_error"
    retryable: ClassVar[bool] = False

    def __init__(self, message: str = "") -> None:
        super().__init__(message)
        self.message = message


class ToolValidationError(FlosswingError):
    code = "input_validation_failed"
    retryable = False


class PathEscapesRepoError(FlosswingError):
    code = "path_escapes_repo"
    retryable = False

    def __init__(self, path: str) -> None:
        super().__init__(f"path escapes repo root: {path}")


class FileNotFoundInRepoError(FlosswingError):
    code = "file_not_found"
    retryable = False


class PathNotFoundError(FlosswingError):
    code = "not_found"
    retryable = False


class PathIsDirectoryError(FlosswingError):
    code = "is_directory"
    retryable = False


class BinaryFileError(FlosswingError):
    code = "binary_file"
    retryable = False


class PathNotDirectoryError(FlosswingError):
    code = "not_a_directory"
    retryable = False


class InvalidRegexError(FlosswingError):
    code = "invalid_regex"
    retryable = True  # agent can rewrite the pattern


class PatternTooBroadError(FlosswingError):
    code = "pattern_too_broad"
    retryable = True


class SandboxUnavailableError(FlosswingError):
    """Raised by compile_and_run when no sandbox backend is available.

    Defined now even though compile_and_run lands in a later milestone,
    so the registry of error codes is complete.
    """

    code = "sandbox_unavailable"
    retryable = False


class BudgetExceededError(FlosswingError):
    code = "budget_exceeded"
    retryable = False


class AgentRefusedError(FlosswingError):
    code = "agent_refused"
    retryable = False


class AuthCredentialMissingError(FlosswingError):
    code = "auth_credential_missing"
    retryable = False


class InvalidAttackClassError(FlosswingError):
    code = "invalid_attack_class"
    retryable = False


class ReconAlreadyRecordedError(FlosswingError):
    code = "recon_already_recorded"
    retryable = False


class PathNotInRepoError(FlosswingError):
    code = "path_not_in_repo"
    retryable = False


class LineRangeInvalidError(FlosswingError):
    code = "line_range_invalid"
    retryable = False


class DescriptionRequiredForConfirmedError(FlosswingError):
    code = "description_required_for_confirmed"
    retryable = False


class DescriptionTooLargeError(FlosswingError):
    code = "description_too_large"
    retryable = False


class SuggestedFixTooLargeError(FlosswingError):
    code = "suggested_fix_too_large"
    retryable = False


# -----------------------------------------------------------------------------
# v0.4 sandbox errors (per docs/specs/2026-06-02-v0.4-sandbox-design.md
# § Error and refusal handling)
# -----------------------------------------------------------------------------


class PathEscapesScratchError(FlosswingError):
    """A SourceFile.relative_path resolves outside /scratch/src/.

    Per design decision #6, this maps to the existing v0.2
    `input_validation_failed` umbrella code at the tool layer to
    avoid touching the frozen tool contract.
    """

    code = "input_validation_failed"
    retryable = False

    def __init__(self, relative_path: str) -> None:
        super().__init__(
            f"SourceFile.relative_path escapes /scratch/src: {relative_path!r}"
        )


class SandboxImageBuildError(FlosswingError):
    """Building a per-language sandbox image failed.

    Carries a tail of the build log so the operator can diagnose
    without re-running. The contract-level code is `sandbox_unavailable`
    (per spec § Error and refusal handling) because the agent cannot
    make progress without the image.
    """

    code = "sandbox_unavailable"
    retryable = False

    def __init__(self, *, language: str, log_tail: str) -> None:
        super().__init__(
            f"failed to build sandbox image for language={language!r}; "
            f"build log tail:\n{log_tail}"
        )
        self.language = language
        self.log_tail = log_tail


class SandboxBackendUnavailableError(FlosswingError):
    """The selected backend was available at startup but failed mid-run.

    Distinct Python class from `SandboxUnavailableError` (raised by the
    selector when neither backend is installed) so the raise site is
    diagnosable. Both map to the same `sandbox_unavailable` wire code.
    """

    code = "sandbox_unavailable"
    retryable = False


class NetworkNotPermittedError(FlosswingError):
    code = "network_not_permitted"
    retryable = False


class LanguageNotSupportedError(FlosswingError):
    code = "language_not_supported"
    retryable = False


class ResourceLimitExceededError(FlosswingError):
    code = "resource_limit_exceeded"
    retryable = False


# -----------------------------------------------------------------------------
# Credential scrubber
# -----------------------------------------------------------------------------

_REPLACEMENT: Final[str] = "[REDACTED]"

_PATTERNS: Final[list[re.Pattern[str]]] = [
    # Authorization: Bearer <token>
    re.compile(r"(?i)(authorization\s*:\s*bearer\s+)\S+"),
    # x-api-key: <token>
    re.compile(r"(?i)(x-api-key\s*:\s*)\S+"),
    # ANTHROPIC_API_KEY=<value>
    re.compile(r"(ANTHROPIC_API_KEY\s*=\s*)\S+"),
    # ANTHROPIC_FOUNDRY_API_KEY=<value>
    re.compile(r"(ANTHROPIC_FOUNDRY_API_KEY\s*=\s*)\S+"),
    # Azure Entra ID env vars (per flosswing.config: AZURE_CLIENT_ID,
    # AZURE_TENANT_ID, AZURE_CLIENT_SECRET). All three flow through auth_env;
    # CLIENT_SECRET is the high-impact one but TENANT_ID / CLIENT_ID are
    # still identifying material we don't want in logs or the state DB.
    re.compile(r"(AZURE_CLIENT_SECRET\s*=\s*)\S+"),
    re.compile(r"(AZURE_CLIENT_ID\s*=\s*)\S+"),
    re.compile(r"(AZURE_TENANT_ID\s*=\s*)\S+"),
    # JWT-like tokens (three base64 segments separated by dots).
    # Conservative: requires the first segment to start with "ey" (typical JWT header)
    # AND each segment >= 10 chars to avoid false positives on strings like
    # "eyconfig.production.env" in attacker-controlled repo contents.
    re.compile(r"\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
]


def scrub(s: str) -> str:
    """Remove credential material from a string. Idempotent."""
    if not s:
        return s
    out = s
    for pattern in _PATTERNS:
        if pattern.groups == 1:
            out = pattern.sub(rf"\1{_REPLACEMENT}", out)
        else:
            out = pattern.sub(_REPLACEMENT, out)
    return out
