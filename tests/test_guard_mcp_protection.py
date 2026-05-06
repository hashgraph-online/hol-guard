"""Behavior tests for Guard MCP identity protection primitives."""

from __future__ import annotations

from codex_plugin_scanner.guard.adapters.mcp_servers import managed_stdio_servers
from codex_plugin_scanner.guard.mcp_tool_calls import build_tool_call_artifact
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection
from codex_plugin_scanner.guard.runtime.mcp_protection import build_mcp_server_identity


def test_mcp_server_identity_hashes_args_and_sorts_env_keys() -> None:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="npx",
        args=("--yes", "@modelcontextprotocol/server-filesystem@1.2.3", "."),
        transport="stdio",
        env={"TOKEN": "redacted", "PATH": "redacted"},
    )

    assert identity.config_path == ".mcp.json"
    assert identity.command == "npx"
    assert identity.transport == "stdio"
    assert identity.env_keys == ("PATH", "TOKEN")
    assert identity.package_name == "@modelcontextprotocol/server-filesystem"
    assert identity.package_version == "1.2.3"
    assert len(identity.args_hash) == 64


def test_managed_stdio_servers_emit_server_identity() -> None:
    detection = HarnessDetection(
        harness="codex",
        installed=True,
        command_available=True,
        config_paths=(".mcp.json",),
        artifacts=(
            GuardArtifact(
                artifact_id="codex:mcp:filesystem",
                name="filesystem",
                harness="codex",
                artifact_type="mcp_server",
                source_scope="project",
                config_path=".mcp.json",
                command="npx",
                args=("--yes", "@modelcontextprotocol/server-filesystem"),
                transport="stdio",
                metadata={"env": {"TOKEN": "redacted"}},
            ),
        ),
    )

    servers = managed_stdio_servers(detection)

    assert len(servers) == 1
    identity = servers[0].identity
    assert identity is not None
    assert identity.command == "npx"
    assert identity.env_keys == ("TOKEN",)
    assert identity.package_name == "@modelcontextprotocol/server-filesystem"


def test_tool_call_artifact_emits_tool_identity_metadata() -> None:
    server_identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="python",
        args=("server.py",),
        transport="stdio",
        env={},
    )

    artifact = build_tool_call_artifact(
        harness="codex",
        server_name="filesystem",
        tool_name="read_file",
        source_scope="project",
        config_path=".mcp.json",
        transport="stdio",
        server_identity=server_identity,
        tool_schema={"properties": {"path": {"type": "string"}}},
        tool_description="Read files from an approved project folder.",
    )

    assert artifact.metadata["mcp_server_identity"]["args_hash"] == server_identity.args_hash
    tool_identity = artifact.metadata["mcp_tool_identity"]
    assert tool_identity["server_hash"] == server_identity.identity_hash
    assert tool_identity["tool_name"] == "read_file"
    assert len(tool_identity["schema_hash"]) == 64
    assert len(tool_identity["description_hash"]) == 64
