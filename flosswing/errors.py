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
# v0.5 symbol-index errors (per docs/specs/2026-06-02-v0.5-symbol-index-design.md
# § Error and refusal handling and docs/tool-contracts.md § Scope: symbols)
# -----------------------------------------------------------------------------


class IndexBuildError(FlosswingError):
    """Raised by orchestrator.run_scan when IndexBuild produces 0 symbols.

    Per spec § Error and refusal handling: "If IndexBuild ends with zero
    symbols recorded ... the orchestrator finalizes the run as `errored`
    with a clear message and exits 1. Hunters do not start."
    """

    code = "index_build_empty"
    retryable = False


class LanguageGrammarNotLoadedError(FlosswingError):
    """A per-file build raised because the tree-sitter grammar wouldn't load.

    Caught inside index.build.build_index per-file loop; the file is
    skipped and the build continues. Never surfaces to the agent — no
    wire code mapping.
    """

    code = "language_grammar_not_loaded"
    retryable = False

    def __init__(self, language: str) -> None:
        super().__init__(
            f"tree-sitter grammar for language={language!r} could not be loaded"
        )
        self.language = language


class SymbolNotFoundError(FlosswingError):
    """Per docs/tool-contracts.md § find_callers errors."""

    code = "symbol_not_found"
    retryable = False


class AmbiguousSymbolError(FlosswingError):
    """Per docs/tool-contracts.md § find_callers errors.

    The message includes the list of candidate locations so the agent
    can retry with file_hint per the contract's wording.
    """

    code = "ambiguous_symbol"
    retryable = False

    def __init__(self, *, symbol: str, candidates: list[str]) -> None:
        candidate_text = "; ".join(candidates) if candidates else "(none)"
        super().__init__(
            f"symbol={symbol!r} is ambiguous — candidates: {candidate_text}"
        )
        self.symbol = symbol
        self.candidates = candidates


class NotIndexedError(FlosswingError):
    """Per docs/tool-contracts.md § find_definition errors.

    Should be unreachable in normal v0.5 operation — IndexBuild
    guarantees ≥1 symbol or fails the run before Hunt starts. Logged
    loudly if it ever fires.
    """

    code = "not_indexed"
    retryable = False


# -----------------------------------------------------------------------------
# v0.6 Validate errors (per docs/tool-contracts.md § findings (Validate-side)
# and docs/specs/2026-06-02-v0.6-validate-design.md § Error and refusal handling)
#
# Per plan preamble decision #3 (operator override on 2026-06-03), the
# defensive byte-level `EvidenceFilesTooLargeError` / `evidence_files_too_large`
# is NOT implemented. Only the spec's 100-entry list cap
# (`EvidenceFilesTooManyError`) ships.
# -----------------------------------------------------------------------------


class FindingNotFoundError(FlosswingError):
    """Per docs/tool-contracts.md § findings (Validate-side) errors.

    Raised by validate_finding when the supplied finding_id does not
    resolve under the current run. Typically a prompt-injection /
    hallucination signal; the agent should refuse or stop.
    """

    code = "finding_not_found"
    retryable = False


class FindingAlreadyValidatedError(FlosswingError):
    """Per docs/tool-contracts.md § findings (Validate-side) errors.

    Raised by validate_finding when a validations row already exists
    for the target finding. The UNIQUE constraint on
    uq_validations_finding_id provides DB-side enforcement; the explicit
    pre-check produces a friendlier error and a smaller round-trip.

    The agent should treat this as a stop signal, not a retry signal.
    """

    code = "finding_already_validated"
    retryable = False


class RationaleTooShortError(FlosswingError):
    """Per docs/tool-contracts.md § findings (Validate-side) errors.

    Raised by validate_finding when len(rationale) < 50. The cap exists
    to force actual explanation, not 'looks fine.' Retryable: the agent
    can rewrite a longer rationale and try again.
    """

    code = "rationale_too_short"
    retryable = True


class EvidenceFilesTooManyError(FlosswingError):
    """Application-layer list-length cap on validate_finding's
    evidence_files argument. Per spec § Component responsibilities
    tools/findings.py — validate_finding, cap=100. Matches the existing
    fs-side caps in spirit.
    """

    code = "evidence_files_too_many"
    retryable = False


# -----------------------------------------------------------------------------
# v0.8 Dedupe errors (per docs/tool-contracts.md § findings (Dedupe-side)
# and docs/specs/2026-06-02-v0.8-dedupe-design.md § Error and refusal handling)
#
# `MergeFindingsError` / `LinkVariantError` are tool-grouping parents so the
# stage layer can catch all merge or link failures with one except clause.
# `FindingNotInClusterError` is shared (multiple-inheritance) because both
# tools raise it with the same semantics: a cross-cluster operation.
# -----------------------------------------------------------------------------


class MergeFindingsError(FlosswingError):
    """Parent for all merge_findings validation failures.

    Subclasses carry the specific wire code; this base is for ``except``-side
    grouping in the Dedupe stage.
    """


class LinkVariantError(FlosswingError):
    """Parent for all link_variant validation failures.

    Subclasses carry the specific wire code; this base is for ``except``-side
    grouping in the Dedupe stage.
    """


class RootCauseSummaryTooShortError(MergeFindingsError):
    """Per docs/tool-contracts.md § findings (Dedupe-side) errors.

    Raised by merge_findings when ``len(root_cause_summary) < 50``. Matches
    the validate_finding rationale cap in spirit — forces actual explanation.
    Retryable: agent can rewrite a longer summary.
    """

    code = "root_cause_summary_too_short"
    retryable = True


class PrimaryInDuplicatesError(MergeFindingsError):
    """Per docs/tool-contracts.md § findings (Dedupe-side) errors.

    Raised by merge_findings when ``primary_finding_id`` appears in
    ``duplicate_finding_ids``. Indicates a malformed call from the agent.
    """

    code = "primary_in_duplicates"
    retryable = False


class FindingNotInClusterError(MergeFindingsError, LinkVariantError):
    """Per docs/tool-contracts.md § findings (Dedupe-side) errors.

    Raised by either dedupe tool when one or more inputs do not share the
    expected ``dedupe_cluster_id`` (or any of them has a NULL cluster id).
    Blocks cross-cluster merges and cross-cluster variant links.

    Multiple inheritance from both tool-group parents so ``except
    MergeFindingsError`` and ``except LinkVariantError`` both catch it.
    """

    code = "finding_not_in_cluster"
    retryable = False


class SameFindingError(LinkVariantError):
    """Per docs/tool-contracts.md § findings (Dedupe-side) errors.

    Raised by link_variant when ``finding_id_a == finding_id_b``. Matches
    the DB-side ``ck_finding_links_distinct`` CHECK constraint with a
    friendlier message and earlier rejection.
    """

    code = "same_finding"
    retryable = False


class LinkAlreadyExistsError(LinkVariantError):
    """Per docs/tool-contracts.md § findings (Dedupe-side) errors.

    Raised by link_variant when a finding_links row already exists for
    the (a, b, relationship) pair in either direction. The DB-side
    ``uq_finding_links_ordered`` UNIQUE constraint only covers one
    direction; the tool layer checks both via UNION-style query.
    """

    code = "link_already_exists"
    retryable = False


# -----------------------------------------------------------------------------
# v0.9 Trace errors (per docs/tool-contracts.md § findings (Trace-side)
# and docs/specs/2026-06-02-v0.9-trace-design.md § Error and refusal handling)
#
# `RecordTraceError` is a tool-grouping parent so the stage layer can catch all
# record_trace failures with one except clause. `FindingNotFoundError` is
# reused from v0.6.
# -----------------------------------------------------------------------------


class RecordTraceError(FlosswingError):
    """Parent for all record_trace validation failures.

    Subclasses carry the specific wire code; this base is for ``except``-side
    grouping in the Trace stage.
    """


class FindingNotTraceableError(RecordTraceError):
    """Per docs/tool-contracts.md § record_trace.

    Raised by record_trace when the supplied finding_id does not satisfy
    ``status='confirmed' AND (dedupe_role IS NULL OR dedupe_role='primary')``.
    Defence-in-depth: the Trace stage's selection query already filters to
    eligible findings, so this fires only on a malformed call from the agent
    or a race with another stage.
    """

    code = "finding_not_traceable"
    retryable = False


class TraceAlreadyExistsError(RecordTraceError):
    """Per docs/tool-contracts.md § record_trace.

    Raised by record_trace when a traces row already exists for the target
    finding. The DB-side ``uq_traces_finding_id`` UNIQUE constraint provides
    server-side enforcement; the explicit pre-check produces a friendlier
    error and a smaller round-trip.
    """

    code = "trace_already_exists"
    retryable = False


class InconsistentTraceError(RecordTraceError):
    """Per docs/tool-contracts.md § record_trace.

    Raised by record_trace when ``reachable=='reachable'`` but
    ``entry_point_symbol IS NULL``. Matches the DB-side
    ``ck_traces_reachable_has_entry_point`` CHECK constraint with a friendlier
    message and earlier rejection. Retryable: the agent can re-emit with the
    correct shape.
    """

    code = "inconsistent_trace"
    retryable = True


class EmptyCallChainError(RecordTraceError):
    """Per docs/tool-contracts.md § record_trace.

    Raised by record_trace when ``len(call_chain) < 1``. The spec requires
    at least the bug site itself as a step. Retryable: the agent can re-emit
    with a non-empty call_chain.
    """

    code = "empty_call_chain"
    retryable = True


class RationaleEmptyError(RecordTraceError):
    """Per docs/tool-contracts.md § record_trace.

    Raised by record_trace when ``rationale.strip() == ""``. Forces actual
    explanation, not empty/whitespace-only justification. Retryable: the
    agent can re-emit with a non-empty rationale.
    """

    code = "rationale_empty"
    retryable = True


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
