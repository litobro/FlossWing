"""secrets_triage.py: deterministic dev/placeholder secret classifier."""

from __future__ import annotations

import pytest

from flosswing.secrets_triage import classify_secret

# High-entropy 40-char value that must NEVER be downgraded in prod source.
_REAL = '"a9F3k1Lz8Qw2Rt7Yb4Xc6Vn0Ms5Pd3Hj1Gf9Kd2"'


@pytest.mark.parametrize(
    ("file_path", "evidence", "expect_downgrade"),
    [
        # Real triage examples -> downgradeable
        ("docker/docker-compose.yml", "ELASTIC_PASSWORD: devpass", True),
        ("docker/config.yml.template", "elastic:devpass@localhost", True),
        # Leetspeak placeholder in prod source is NOT recognizable from the
        # value alone; safe direction is to keep it (shown at full severity).
        ("config.py", 'password = "Ch@ngeTh!sPa33w0rd"', False),
        ("assemblyline/common/config.py", 'key = "changeme"', True),
        ("test/docker-compose.yml", f"secret = {_REAL}", True),  # test path wins
        ("docker-compose.dev.yaml", "MINIO_SECRET_KEY: minioadmin", True),
        ("app.py", 'host = "http://user:pass@localhost:9200"', True),
        # Real secret in production source -> NOT downgradeable (guard)
        ("flosswing/prod.py", f"API_KEY = {_REAL}", False),
        ("assemblyline/service.py", f'token = {_REAL}', False),
        # Variable *name* contains "secret" but the value itself does not
        # carry a dev signal -> must not be downgraded (Critical regression).
        ("flosswing/config.py", 'CLIENT_SECRET = "3f9a7c2e8b1d4f6a"', False),
    ],
)
def test_classify_secret_downgrade_decision(
    file_path: str, evidence: str, expect_downgrade: bool
) -> None:
    result = classify_secret(file_path, evidence)
    assert result.downgradeable is expect_downgrade


def test_classify_secret_never_emits_real_value() -> None:
    result = classify_secret("flosswing/prod.py", f"API_KEY = {_REAL}")
    assert "a9F3k1Lz" not in result.reason


def test_classify_secret_empty_evidence_uses_path_only() -> None:
    assert classify_secret("tests/fixtures/x.py", "").downgradeable is True
    assert classify_secret("flosswing/x.py", "").downgradeable is False


def test_classify_secret_entropy_guard_vetoes_weak_sentinel_match() -> None:
    # value contains the substring "admin" but is a real random token
    result = classify_secret(
        "flosswing/app.py",
        'token = "adminX9f3K1Lz8Qw2Rt7Yb4Xc6Vn0Ms5Pd3Hj1"',
    )
    assert result.downgradeable is False
    assert result.classification == "real"


def test_real_secret_colocated_with_localhost_is_not_downgraded() -> None:
    # A real high-entropy secret sharing its evidence span with a
    # localhost reference must NOT be downgraded on the strength of the
    # localhost match alone (localhost is a weak, entropy-vetoed signal).
    evidence = (
        'DB_HOST = "localhost"\n'
        'API_KEY = "a9F3k1Lz8Qw2Rt7Yb4Xc6Vn0Ms5Pd3Hj1Gf9Kd2"'
    )
    result = classify_secret("flosswing/config.py", evidence)
    assert result.downgradeable is False
    assert result.classification == "real"
