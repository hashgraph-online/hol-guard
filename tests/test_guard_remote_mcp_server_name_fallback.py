"""Coverage for remote MCP matching when runtime endpoint identity is unavailable."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.models import GuardArtifact
from codex_plugin_scanner.guard.runtime import mcp_server_grants


def test_remote_instapods_matches_server_name_without_runtime_endpoint_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload: dict[str, object] = {
        "id": "mcp.instapods",
        "launch": {
            "kind": "remote-http",
            "url": "https://app.instapods.com/api/mcp",
            "serverNames": ["instapods", "instapods-mcp"],
        },
    }
    monkeypatch.setattr(mcp_server_grants, "load_mcp_contribution_payloads", lambda: (payload,))
    artifact = GuardArtifact(
        artifact_id="codex:runtime:project:instapods:delete_pod",
        name="instapods:delete_pod",
        harness="codex",
        artifact_type="tool_call",
        source_scope="project",
        config_path=".mcp.json",
        command="delete_pod",
        transport="sse",
        metadata={"server_name": "instapods"},
    )

    matched = mcp_server_grants.matching_mcp_contribution(artifact)

    assert matched is payload
