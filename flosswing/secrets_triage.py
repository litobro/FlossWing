"""Deterministic post-verdict triage for hardcoded_secrets findings.

Pure, side-effect-free. The Validate stage uses this to downgrade a
`confirmed` hardcoded_secrets finding whose value is obviously a
dev/test default, placeholder, or vendor default — never a shipped
production secret.

Policy: strong-signal-required. Downgrade only when a high-confidence
dev signal is present AND there is no strong "real secret" counter-signal
(a high-entropy literal living in a production source path). This biases
toward *keeping* findings, so a real secret is never silently demoted.
"""

from __future__ import annotations

import math
import re
from pathlib import PurePosixPath
from typing import Final, Literal

from pydantic import BaseModel

Classification = Literal["real", "dev_default", "placeholder", "test_fixture"]

# Known placeholder / vendor-default substrings (matched lowercased).
_SENTINEL_VALUES: Final[frozenset[str]] = frozenset({
    "changeme", "change_me", "changeit", "changethis", "change-this",
    "password", "passw0rd", "admin", "secret", "minioadmin", "devpass",
    "example", "sample", "dummy", "placeholder", "your_", "notsecret",
    "insecure", "letmein",
})
_SENTINEL_WORD_RE: Final[re.Pattern[str]] = re.compile(
    r"change|example|sample|dummy|placeholder|dev[_-]?pass|test[_-]?pass",
    re.IGNORECASE,
)
_TEMPLATE_RE: Final[re.Pattern[str]] = re.compile(
    r"<[^>\n]+>|\$\{[^}\n]+\}|\{\{[^}\n]+\}\}"
)
_DEV_PATH_RE: Final[re.Pattern[str]] = re.compile(
    r"(^|/)(tests?|fixtures?|examples?|sample)s?(/|$)"
    r"|docker-compose[^/]*\.ya?ml$"
    r"|\.template$"
    r"|(^|/)ci(/|$)",
    re.IGNORECASE,
)
_LOCALHOST_RE: Final[re.Pattern[str]] = re.compile(
    r"localhost|127\.0\.0\.1|0\.0\.0\.0"
    r"|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+",
    re.IGNORECASE,
)
_LITERAL_RE: Final[re.Pattern[str]] = re.compile(r"""["'`]([^"'`\n]{6,})["'`]""")
_PROD_SRC_SUFFIXES: Final[frozenset[str]] = frozenset({
    ".py", ".go", ".rs", ".c", ".cpp", ".cc", ".h", ".hpp",
    ".java", ".js", ".jsx", ".ts", ".tsx",
})

# Threshold for the "real secret in prod source" false-negative guard.
# Calibrated above crafted-but-plausible dev values (e.g. a hand-typed
# "Ch@ngeTh!sPa33w0rd" or a "http://user:pass@localhost:9200" URL both land
# ~3.9-3.95) and below genuinely random tokens (a 39-char random secret
# lands ~5.0+), so a strong dev signal (sentinel word, localhost host, dev
# path) is not vetoed by incidental entropy from a crafted-looking value.
_HIGH_ENTROPY: Final[float] = 4.3


class SecretTriage(BaseModel):
    downgradeable: bool
    classification: Classification
    reason: str


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _max_literal_entropy(text: str) -> float:
    best = 0.0
    for m in _LITERAL_RE.finditer(text):
        best = max(best, _shannon_entropy(m.group(1)))
    return best


def _is_prod_source(file_path: str) -> bool:
    if _DEV_PATH_RE.search(file_path):
        return False
    return PurePosixPath(file_path).suffix.lower() in _PROD_SRC_SUFFIXES


def classify_secret(file_path: str, evidence_text: str) -> SecretTriage:
    """Classify a hardcoded_secrets finding's value context.

    `evidence_text` should be the finding's source span plus any poc_code;
    `file_path` is the repo-relative path. Pure — the caller does the read.
    """
    text = evidence_text or ""
    lower = text.lower()

    is_dev_path = bool(_DEV_PATH_RE.search(file_path))
    has_sentinel = any(v in lower for v in _SENTINEL_VALUES)
    has_word = bool(_SENTINEL_WORD_RE.search(text))
    has_template = bool(_TEMPLATE_RE.search(text))
    is_localhost = bool(_LOCALHOST_RE.search(text))
    max_entropy = _max_literal_entropy(text)

    dev_signal = (
        has_sentinel or has_word or has_template or is_dev_path or is_localhost
    )
    # False-negative guard: never demote a very-high-entropy literal living
    # in a production source path, even if a dev signal also matched.
    counter_signal = max_entropy >= _HIGH_ENTROPY and _is_prod_source(file_path)
    downgradeable = dev_signal and not counter_signal

    if is_dev_path:
        classification: Classification = "test_fixture"
        reason = "dev/test artifact path"
    elif has_template:
        classification = "placeholder"
        reason = "templated placeholder value"
    elif has_sentinel or has_word:
        classification = "placeholder"
        reason = "sentinel/placeholder value"
    elif is_localhost:
        classification = "dev_default"
        reason = "localhost default value"
    else:
        classification = "real"
        reason = "no dev signal"

    return SecretTriage(
        downgradeable=downgradeable, classification=classification, reason=reason
    )


__all__ = ["SecretTriage", "classify_secret"]
