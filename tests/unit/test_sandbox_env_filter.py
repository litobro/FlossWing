"""DockerSandbox env-filter — allowlist enforced, secrets dropped.

Per docs/specs/2026-06-02-v0.4-sandbox-design.md § Env filtering and
§ Testing strategy test_sandbox_env_filter.py. The credential-rule
in CLAUDE.md § Hard rules forbids forwarding ANTHROPIC_* / AZURE_* /
AWS_* / GITHUB_* regardless of opt-in.
"""

from __future__ import annotations

from flosswing.sandbox.docker import _filter_env


def test_filter_keeps_allowlisted_vars() -> None:
    out = _filter_env(
        {
            "LANG": "C.UTF-8",
            "PYTHONUNBUFFERED": "1",
            "RUSTFLAGS": "-Cdebuginfo=0",
            "GOFLAGS": "-mod=vendor",
            "NODE_OPTIONS": "--max-old-space-size=128",
        }
    )
    assert out == {
        "LANG": "C.UTF-8",
        "PYTHONUNBUFFERED": "1",
        "RUSTFLAGS": "-Cdebuginfo=0",
        "GOFLAGS": "-mod=vendor",
        "NODE_OPTIONS": "--max-old-space-size=128",
    }


def test_filter_drops_anthropic_keys() -> None:
    out = _filter_env(
        {
            "LANG": "C.UTF-8",
            "ANTHROPIC_API_KEY": "sk-secret",
            "ANTHROPIC_FOUNDRY_API_KEY": "foundry-secret",
        }
    )
    assert "ANTHROPIC_API_KEY" not in out
    assert "ANTHROPIC_FOUNDRY_API_KEY" not in out
    assert out == {"LANG": "C.UTF-8"}


def test_filter_drops_azure_keys() -> None:
    out = _filter_env(
        {
            "AZURE_CLIENT_ID": "cli",
            "AZURE_TENANT_ID": "ten",
            "AZURE_CLIENT_SECRET": "sec",
            "PYTHONUNBUFFERED": "1",
        }
    )
    assert "AZURE_CLIENT_ID" not in out
    assert "AZURE_TENANT_ID" not in out
    assert "AZURE_CLIENT_SECRET" not in out
    assert out == {"PYTHONUNBUFFERED": "1"}


def test_filter_drops_aws_keys() -> None:
    out = _filter_env(
        {
            "AWS_ACCESS_KEY_ID": "AKIA...",
            "AWS_SECRET_ACCESS_KEY": "secret",
            "AWS_SESSION_TOKEN": "tok",
            "LANG": "C.UTF-8",
        }
    )
    for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
        assert k not in out
    assert out == {"LANG": "C.UTF-8"}


def test_filter_drops_github_token() -> None:
    out = _filter_env({"GITHUB_TOKEN": "ghp_xxx", "LANG": "C.UTF-8"})
    assert "GITHUB_TOKEN" not in out
    assert out == {"LANG": "C.UTF-8"}


def test_filter_drops_unknown_var_silently() -> None:
    """Anything not in the allowlist is silently dropped — deliberately tight."""
    out = _filter_env({"MY_CUSTOM_VAR": "v", "LANG": "C.UTF-8"})
    assert "MY_CUSTOM_VAR" not in out
    assert out == {"LANG": "C.UTF-8"}


def test_filter_empty_input_empty_output() -> None:
    assert _filter_env({}) == {}
