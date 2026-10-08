"""IPv4-mapped IPv6 remote MCP endpoint identity coverage."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.mcp_tool_calls import build_tool_call_artifact
from codex_plugin_scanner.guard.runtime.mcp_protection import build_mcp_server_identity
from codex_plugin_scanner.guard.runtime.mcp_server_contribution import (
    load_mcp_contribution_payloads,
    normalized_remote_mcp_url,
    remote_mcp_endpoint_identity,
)
from codex_plugin_scanner.guard.runtime.mcp_server_grants import _matches_remote_http_contribution

_NATIVE_URL = "https://93.184.216.34/mcp"
_MAPPED_URL = "https://[::ffff:93.184.216.34]/mcp"


def _remote_payload(url: str, *, mcp_id: str, server_name: str) -> dict[str, object]:
    return {
        "schemaVersion": "guard.mcp-server-contribution.v1",
        "id": mcp_id,
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
            "serverNames": [server_name],
        },
        "riskClasses": ["remote"],
        "tools": [{"name": "write_data", "state": "review"}],
        "saferAlternatives": ["Keep the tool on normal review."],
    }


def test_ipv4_mapped_ipv6_uses_native_ipv4_endpoint_identity() -> None:
    assert normalized_remote_mcp_url(_MAPPED_URL) == _NATIVE_URL
    assert remote_mcp_endpoint_identity(_MAPPED_URL) == _NATIVE_URL
    assert remote_mcp_endpoint_identity(_NATIVE_URL) == _NATIVE_URL


def test_ipv4_mapped_runtime_matches_native_ipv4_contribution() -> None:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command=_MAPPED_URL,
        args=(),
        transport="http",
    )
    artifact = build_tool_call_artifact(
        harness="codex",
        server_name="example",
        tool_name="write_data",
        source_scope="project",
        config_path=".mcp.json",
        transport="http",
        server_identity=identity,
    )
    launch = {
        "kind": "remote-http",
        "url": _NATIVE_URL,
        "serverNames": ["example"],
    }

    assert _matches_remote_http_contribution(artifact, launch)


def test_ipv4_mapped_and_native_ipv4_contributions_are_duplicate_endpoints(tmp_path: Path) -> None:
    native = _remote_payload(_NATIVE_URL, mcp_id="mcp.native-ipv4", server_name="native-ipv4")
    mapped = _remote_payload(_MAPPED_URL, mcp_id="mcp.mapped-ipv4", server_name="mapped-ipv4")
    (tmp_path / "mcp.native-ipv4.json").write_text(json.dumps(native), encoding="utf-8")
    (tmp_path / "mcp.mapped-ipv4.json").write_text(json.dumps(mapped), encoding="utf-8")

    with pytest.raises(ValueError, match="duplicate MCP remote endpoint"):
        load_mcp_contribution_payloads(tmp_path)
