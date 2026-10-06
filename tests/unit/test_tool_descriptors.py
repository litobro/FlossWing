from __future__ import annotations

from pathlib import Path

import pytest

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


def _names(ds: list[td.ToolDescriptor]) -> list[str]:
    return [d.name for d in ds]


def test_hunt_descriptors_names() -> None:
    ds = td.build_hunt_descriptors(repo_root=Path("/repo"), run_id="r", hunt_task_id="t")
    assert _names(ds) == [
        "read_file", "list_dir", "grep", "record_finding", "find_definition", "find_callers",
    ]
    assert not any(d.is_async for d in ds)


def test_validate_descriptors_names() -> None:
    ds = td.build_validate_descriptors(repo_root=Path("/repo"), run_id="r", agent_session_id="a")
    assert _names(ds) == [
        "read_file", "list_dir", "grep", "find_definition", "find_callers",
        "compile_and_run", "query_findings", "validate_finding",
    ]
    assert [d.name for d in ds if d.is_async] == ["compile_and_run"]


def test_dedupe_descriptors_names() -> None:
    ds = td.build_dedupe_descriptors(repo_root=Path("/repo"), run_id="r")
    assert _names(ds) == ["read_file", "query_findings", "merge_findings", "link_variant"]


def test_trace_descriptors_names() -> None:
    ds = td.build_trace_descriptors(repo_root=Path("/repo"), run_id="r", agent_session_id="a")
    assert _names(ds) == [
        "read_file", "list_dir", "grep", "find_definition", "find_callers",
        "query_entry_points", "query_findings", "record_trace",
    ]


def test_gapfill_descriptors_names() -> None:
    ds = td.build_gapfill_descriptors(
        repo_root=Path("/repo"), run_id="r", gapfill_new_task_cap=3,
        budget_total=10, total_token_budget=1000,
    )
    assert _names(ds) == [
        "read_file", "list_dir", "grep", "query_findings", "query_run_state", "add_hunt_task",
    ]


@pytest.mark.asyncio
async def test_async_descriptor_validation_error_is_tool_error() -> None:
    ds = td.build_validate_descriptors(repo_root=Path("/repo"), run_id="r", agent_session_id="a")
    d = next(x for x in ds if x.name == "compile_and_run")
    out = await d.call({})
    assert out["is_error"] is True
