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

"""Deterministic post-verdict triage for hardcoded_secrets findings.

Pure, side-effect-free. The Validate stage uses this to downgrade a
`confirmed` hardcoded_secrets finding whose value is obviously a
dev/test default, placeholder, or vendor default — never a shipped
production secret.

Policy: strong-signal-required. Downgrade only when a high-confidence
dev signal is present AND there is no strong "real secret" counter-signal
(a high-entropy literal living in a production source path). This biases
toward *keeping* findings, so a real secret is never silently demoted.

`localhost`/RFC-1918 references are a WEAK signal, not a strong one: a
real high-entropy secret can share its evidence span with an unrelated
localhost/RFC-1918 reference (e.g. a co-located `DB_HOST = "localhost"`
line), so `has_localhost` alone must not bypass the entropy counter-
signal — see `_HIGH_ENTROPY`.
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
_ASSIGN_RHS_RE: Final[re.Pattern[str]] = re.compile(
    r"""[:=]\s*(?P<v>[^\s#'"`][^\n#]*?)\s*$""", re.MULTILINE
)
_PROD_SRC_SUFFIXES: Final[frozenset[str]] = frozenset({
    ".py", ".go", ".rs", ".c", ".cpp", ".cc", ".h", ".hpp",
    ".java", ".js", ".jsx", ".ts", ".tsx",
    ".yaml", ".yml", ".json", ".ini", ".toml", ".cfg", ".conf",
})

# Threshold for the "real secret in prod source" false-negative guard. Signals
# are value-scoped (see `_candidate_values`), so this guards two cases: (a) a
# real secret's value literally contains a weak-signal substring (e.g.
# "admin" inside a random token), and (b) a real secret that merely shares
# its evidence span with a `localhost`/RFC-1918 reference (`has_localhost` is
# a WEAK signal — see below — precisely so this veto can fire for it).
#
# Empirically measured (see tests/unit/test_secrets_triage.py):
#   - "http://user:pass@localhost:9200" (benign dev connection string)
#     -> Shannon entropy ~3.94 bits/char
#   - "adminX9f3K1Lz8Qw2Rt7Yb4Xc6Vn0Ms5Pd3Hj1" (real random token that
#     happens to contain the substring "admin") -> ~4.98 bits/char
# 4.2 sits in the gap: above the benign localhost literal (so it stays
# downgradeable) and below a real secret's entropy (so it stays protected).
_HIGH_ENTROPY: Final[float] = 4.2


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


def _candidate_values(text: str) -> list[str]:
    """Pull likely secret *values* out of an evidence blob: quoted string
    literals plus the right-hand side of `key: value` / `key = value`
    lines. Deliberately excludes bare identifiers/variable names so a
    variable called CLIENT_SECRET does not itself count as a signal.
    """
    vals: list[str] = []
    for m in _LITERAL_RE.finditer(text):
        vals.append(m.group(1))
    for m in _ASSIGN_RHS_RE.finditer(text):
        v = m.group("v").strip().strip("\"'`")
        if v:
            vals.append(v)
    return vals


def _is_prod_source(file_path: str) -> bool:
    if _DEV_PATH_RE.search(file_path):
        return False
    name = PurePosixPath(file_path).name.lower()
    if name == ".env" or name.startswith(".env.") or name.endswith(".env"):
        return True
    return PurePosixPath(file_path).suffix.lower() in _PROD_SRC_SUFFIXES


def classify_secret(file_path: str, evidence_text: str) -> SecretTriage:
    """Classify a hardcoded_secrets finding's value context.

    `evidence_text` should be the finding's source span plus any poc_code;
    `file_path` is the repo-relative path. Pure — the caller does the read.
    """
    text = evidence_text or ""
    values = _candidate_values(text)

    is_dev_path = bool(_DEV_PATH_RE.search(file_path))
    has_template = any(_TEMPLATE_RE.search(v) for v in values)
    has_localhost = any(_LOCALHOST_RE.search(v) for v in values)
    has_sentinel = any(
        sentinel in v.lower() for v in values for sentinel in _SENTINEL_VALUES
    )
    has_word = any(_SENTINEL_WORD_RE.search(v) for v in values)

    # Strong signals are reliable and are never vetoed by entropy.
    strong_signal = is_dev_path or has_template
    # Weak signals are substring/context guesses that can coincidentally
    # co-occur with a real secret (e.g. a localhost reference living in the
    # same evidence span as a high-entropy production credential), so they
    # remain subject to the entropy veto below.
    weak_signal = has_sentinel or has_word or has_localhost

    # max() over an empty sequence would raise; no candidate values means no
    # entropy evidence exists, so the counter-signal cannot fire.
    max_value_entropy = max((_shannon_entropy(v) for v in values), default=0.0)
    # False-negative guard: never demote a very-high-entropy value living in
    # a production source path on the strength of a weak signal alone.
    counter_signal = max_value_entropy >= _HIGH_ENTROPY and _is_prod_source(file_path)

    downgradeable = strong_signal or (weak_signal and not counter_signal)

    if downgradeable:
        if is_dev_path:
            classification: Classification = "test_fixture"
            reason = "dev/test artifact path"
        elif has_template:
            classification = "placeholder"
            reason = "templated placeholder value"
        elif has_localhost:
            classification = "dev_default"
            reason = "localhost default value"
        else:  # weak signal, un-vetoed
            classification = "placeholder"
            reason = "sentinel/placeholder value"
    else:
        classification = "real"
        reason = (
            "high-entropy value in production source"
            if (weak_signal and counter_signal)
            else "no dev signal"
        )

    return SecretTriage(
        downgradeable=downgradeable, classification=classification, reason=reason
    )


__all__ = ["SecretTriage", "classify_secret"]
