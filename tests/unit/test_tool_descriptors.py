from __future__ import annotations

from pathlib import Path

from flosswing.agent import tool_descriptors as td


def test_recon_descriptors_names_and_order() -> None:
    ds = td.build_recon_descriptors(repo_root=Path("/repo"), run_id="r", budget_total=20)
    assert [d.name for d in ds] == [
        "read_file",
        "list_dir",
        "grep",
        "record_recon_artifact",
        "add_hunt_task",
    ]


def test_descriptor_call_validation_error_is_tool_error() -> None:
    ds = {
        d.name: d
        for d in td.build_recon_descriptors(repo_root=Path("/repo"), run_id="r", budget_total=20)
    }
    # read_file requires `path`; omitting it must yield an is_error payload, not raise.
    out = ds["read_file"].call({})
    assert out["is_error"] is True
    assert "content" in out


def test_to_sdk_tool_preserves_name() -> None:
    d = td.build_recon_descriptors(repo_root=Path("/repo"), run_id="r", budget_total=20)[0]
    sdk_tool = td.to_sdk_tool(d)
    assert getattr(sdk_tool, "name", "") == "read_file"
