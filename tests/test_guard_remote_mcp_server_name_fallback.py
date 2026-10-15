"""Coverage for remote MCP matching when runtime endpoint identity is unavailable."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.models import GuardArtifact

from .local_cli_native_fixture import native_local_cli_grant_resident  # noqa: F401
from .mcp_recorded_expectations import instapods_matches, recorded


def _name_only_artifact(server_name: str) -> GuardArtifact:
    return GuardArtifact(
        artifact_id=f"codex:runtime:project:{server_name}:delete_pod",
        name=f"{server_name}:delete_pod",
        harness="codex",
        artifact_type="tool_call",
        source_scope="project",
        config_path=".mcp.json",
        command="delete_pod",
        transport="sse",
        metadata={"server_name": server_name, "mcp_tool_identity": {"tool_name": "delete_pod"}},
    )


@pytest.mark.parametrize("server_name", ["instapods", "instapods-mcp"])
def test_remote_instapods_matches_server_name_without_runtime_endpoint_identity(server_name: str) -> None:
    assert instapods_matches(_name_only_artifact(server_name))


def test_remote_instapods_does_not_match_unlisted_server_name_without_runtime_endpoint_identity() -> None:
    assert not instapods_matches(_name_only_artifact("production-pods"))


def test_recorded_cases_cover_the_name_fallback() -> None:
    names = [case["name"] for case in recorded()["matching_cases"]]
    assert "server name matches without runtime endpoint identity" in names
