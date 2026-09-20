"""Regression coverage for hosted MCP endpoint validation and Copilot identity."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli.commands_support_runtime_resolution import (
    _copilot_runtime_server_identity,
    _CopilotMcpRuntimeServer,
)
from codex_plugin_scanner.guard.mcp_tool_calls import build_tool_call_artifact
from codex_plugin_scanner.guard.runtime.mcp_server_contribution import (
    mcp_tool_state,
    normalized_remote_mcp_url,
    validate_mcp_contribution,
)
from codex_plugin_scanner.guard.runtime.mcp_server_grants import matching_mcp_contribution


def _remote_payload(url: str) -> dict[str, object]:
    return {
        "schemaVersion": "guard.mcp-server-contribution.v1",
        "id": "mcp.example-remote",
        "version": "1.0.0",
        "name": "Example Remote MCP",
        "description": "Remote example",
        "trustClass": "external",
        "activation": "opt-in",
        "publisher": {"id": "example.test", "displayName": "Example"},
        "icon": {"kind": "none"},
        "launch": {
            "kind": "remote-http",
            "url": url,
            "serverNames": ["example"],
        },
        "riskClasses": ["remote"],
        "tools": [{"name": "write_data", "state": "review"}],
        "saferAlternatives": ["Keep the tool on normal review."],
    }


@pytest.mark.parametrize(
    "url",
    (
        "https://example.test/mcp\x00tail",
        "https://example.test/mcp?token=ok\x00tail",
        "https://example.test/mcp\\tail",
        "https://example.test/mcp?filter={bad}",
        "https://example.test/mcp%00tail",
    ),
)
def test_remote_http_url_contract_rejects_invalid_uri_characters(url: str) -> None:
    with pytest.raises(ValueError, match=r"schema|public HTTPS endpoint"):
        validate_mcp_contribution(_remote_payload(url))
    assert normalized_remote_mcp_url(url) is None


def test_copilot_hosted_url_wins_over_executable_command_for_matching(tmp_path: Path) -> None:
    server = _CopilotMcpRuntimeServer(
        server_name="instapods",
        source_scope="project",
        config_path=str(tmp_path / ".mcp.json"),
        server_config={
            "command": "npx",
            "args": ["@example/local-helper"],
            "url": "https://app.instapods.com/api/mcp",
        },
    )
    identity, fingerprint, transport = _copilot_runtime_server_identity(server, launch_cwd=tmp_path)
    assert transport == "http"
    assert identity.command == "https://app.instapods.com/api/mcp"

    artifact = build_tool_call_artifact(
        harness="copilot",
        server_name="instapods",
        tool_name="delete_pod",
        source_scope="project",
        config_path=server.config_path,
        transport=transport,
        server_fingerprint=fingerprint,
        server_identity=identity,
    )
    payload = matching_mcp_contribution(artifact)
    assert payload is not None
    assert payload["id"] == "mcp.instapods"
    assert mcp_tool_state(payload, "delete_pod") == "review"
