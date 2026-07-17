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
        ("config.py", 'password = "Ch@ngeTh!sPa33w0rd"', True),
        ("assemblyline/common/config.py", 'key = "changeme"', True),
        ("test/docker-compose.yml", f"secret = {_REAL}", True),  # test path wins
        ("docker-compose.dev.yaml", "MINIO_SECRET_KEY: minioadmin", True),
        ("app.py", 'host = "http://user:pass@localhost:9200"', True),
        # Real secret in production source -> NOT downgradeable (guard)
        ("flosswing/prod.py", f"API_KEY = {_REAL}", False),
        ("assemblyline/service.py", f'token = {_REAL}', False),
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
