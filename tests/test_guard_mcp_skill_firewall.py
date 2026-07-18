"""Tests for portal-aligned MCP/skill firewall metadata."""

from __future__ import annotations

from codex_plugin_scanner.guard.adapters.opencode_artifacts import append_artifact
from codex_plugin_scanner.guard.mcp_tool_calls import build_tool_call_artifact
from codex_plugin_scanner.guard.models import GuardArtifact
from codex_plugin_scanner.guard.runtime.mcp_protection import build_mcp_server_identity
from codex_plugin_scanner.guard.runtime.mcp_skill_firewall import (
    enrich_artifact_with_mcp_skill_firewall,
    portal_skill_identity,
    skill_identity_metadata,
)
from codex_plugin_scanner.guard.runtime.skill_protection import build_skill_identity


def test_mcp_server_artifact_emits_mcp_skill_firewall_bundle() -> None:
    artifact = enrich_artifact_with_mcp_skill_firewall(
        GuardArtifact(
            artifact_id="cursor:project:filesystem",
            name="filesystem",
            harness="cursor",
            artifact_type="mcp_server",
            source_scope="project",
            config_path=".cursor/mcp.json",
            command="npx",
            args=("--yes", "@modelcontextprotocol/server-filesystem"),
            transport="stdio",
            metadata={"env": {"TOKEN": "redacted"}},
        )
    )

    firewall = artifact.metadata["mcpSkillFirewall"]
    assert isinstance(firewall, dict)
    server = firewall["mcpServer"]
    assert isinstance(server, dict)
    assert server["command"] == "npx"
    assert server["packageName"] == "@modelcontextprotocol/server-filesystem"
    assert server["commandHash"]
    assert server["transportHash"]
    legacy_server = artifact.metadata["mcp_server_identity"]
    assert isinstance(legacy_server, dict)
    assert legacy_server["identity_hash"] == server["identityHash"]


def test_tool_call_artifact_emits_mcp_skill_firewall_and_legacy_identities() -> None:
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

    firewall = artifact.metadata["mcpSkillFirewall"]
    assert isinstance(firewall, dict)
    tools = firewall["mcpTools"]
    assert len(tools) == 1
    assert tools[0]["toolName"] == "read_file"
    assert tools[0]["hashScope"] == "full"
    server = firewall["mcpServer"]
    assert isinstance(server, dict)
    assert server["envValuesHash"] == server_identity.env_values_hash
    legacy_server = artifact.metadata["mcp_server_identity"]
    legacy_tool = artifact.metadata["mcp_tool_identity"]
    assert isinstance(legacy_server, dict)
    assert isinstance(legacy_tool, dict)
    assert legacy_server["env_values_hash"] == server_identity.env_values_hash
    assert legacy_tool["tool_name"] == "read_file"


def test_legacy_tool_call_missing_environment_hash_gets_stable_non_secret_fallback() -> None:
    legacy_artifact = GuardArtifact(
        artifact_id="codex:mcp:filesystem:read_file",
        name="filesystem:read_file",
        harness="codex",
        artifact_type="tool_call",
        source_scope="project",
        config_path=".mcp.json",
        command="read_file",
        transport="stdio",
        metadata={
            "mcp_server_identity": {
                "args_hash": "args-hash",
                "command": "python",
                "env_keys": ["TOKEN"],
                "identity_hash": "server-hash",
                "transport": "stdio",
            },
            "mcp_tool_identity": {
                "description_hash": "description-hash",
                "identity_hash": "tool-hash",
                "schema_hash": "schema-hash",
                "server_hash": "server-hash",
                "tool_name": "read_file",
            },
        },
    )

    first = enrich_artifact_with_mcp_skill_firewall(legacy_artifact)
    second = enrich_artifact_with_mcp_skill_firewall(legacy_artifact)
    first_firewall = first.metadata["mcpSkillFirewall"]
    second_firewall = second.metadata["mcpSkillFirewall"]
    assert isinstance(first_firewall, dict)
    assert isinstance(second_firewall, dict)
    first_server = first_firewall["mcpServer"]
    second_server = second_firewall["mcpServer"]
    assert isinstance(first_server, dict)
    assert isinstance(second_server, dict)
    fallback_hash = first_server["envValuesHash"]
    assert isinstance(fallback_hash, str)
    assert len(fallback_hash) == 64
    assert fallback_hash == second_server["envValuesHash"]
    legacy_server = first.metadata["mcp_server_identity"]
    assert isinstance(legacy_server, dict)
    assert legacy_server["env_values_hash"] == fallback_hash


def test_skill_artifact_emits_skill_firewall_metadata(tmp_path) -> None:
    content = "---\nname: docs-helper\n---\n# Docs helper\n"
    skill_path = tmp_path / "SKILL.md"
    skill_path.write_text(content, encoding="utf-8")
    identity = build_skill_identity(content, skill_path=str(skill_path))
    artifact = enrich_artifact_with_mcp_skill_firewall(
        GuardArtifact(
            artifact_id="opencode:global:skill:claude:docs/SKILL.md",
            name="docs/SKILL.md",
            harness="opencode",
            artifact_type="skill",
            source_scope="global",
            config_path=str(skill_path),
            metadata={},
        )
    )

    firewall = artifact.metadata["mcpSkillFirewall"]
    assert isinstance(firewall, dict)
    skill = firewall["skill"]
    assert isinstance(skill, dict)
    assert skill["skillHash"] == identity.skill_hash
    metadata = skill_identity_metadata(identity)
    assert metadata["identity_hash"] == identity.identity_hash
    stable_id = portal_skill_identity(identity)["stableId"]
    assert isinstance(stable_id, str)
    assert stable_id.startswith("skill:")


def test_append_artifact_enriches_mcp_server_metadata() -> None:
    artifacts: list[GuardArtifact] = []
    seen: set[str] = set()
    append_artifact(
        artifacts,
        seen,
        GuardArtifact(
            artifact_id="opencode:project:filesystem",
            name="filesystem",
            harness="opencode",
            artifact_type="mcp_server",
            source_scope="project",
            config_path="opencode.json",
            command="uvx",
            args=("mcp-server-filesystem",),
            transport="stdio",
            metadata={},
        ),
    )

    assert len(artifacts) == 1
    assert "mcpSkillFirewall" in artifacts[0].metadata
