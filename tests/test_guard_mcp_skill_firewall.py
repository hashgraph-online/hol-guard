"""Tests for portal-aligned MCP/skill firewall metadata."""

from __future__ import annotations

from hashlib import sha256

import pytest

from codex_plugin_scanner.guard.mcp_tool_calls import build_tool_call_artifact
from codex_plugin_scanner.guard.models import GuardArtifact
from codex_plugin_scanner.guard.native_mcp_tool_evidence import NativeMcpToolEvidenceError
from codex_plugin_scanner.guard.runtime import mcp_skill_firewall
from codex_plugin_scanner.guard.runtime.mcp_protection import build_mcp_server_identity
from codex_plugin_scanner.guard.runtime.mcp_skill_firewall import enrich_artifact_with_mcp_skill_firewall

pytestmark = pytest.mark.usefixtures("native_context_digest")


@pytest.mark.parametrize("artifact_type", ("mcp_server", "tool_call"))
def test_firewall_enrichment_fails_closed_without_native_authority(
    monkeypatch: pytest.MonkeyPatch,
    artifact_type: str,
) -> None:
    def unavailable(_artifact):
        raise NativeMcpToolEvidenceError("native_mcp_tool_evidence_unavailable")

    monkeypatch.setattr(mcp_skill_firewall, "native_firewall_metadata_patch", unavailable)
    artifact = GuardArtifact(
        artifact_id="codex:project:filesystem",
        name="filesystem",
        harness="codex",
        artifact_type=artifact_type,
        source_scope="project",
        config_path=".mcp.json",
        command="npx",
        transport="stdio",
        metadata={},
    )
    with pytest.raises(NativeMcpToolEvidenceError, match=r"^native_mcp_tool_evidence_unavailable$"):
        enrich_artifact_with_mcp_skill_firewall(artifact)


def test_command_less_mcp_server_never_needs_the_resident(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(_artifact):
        raise AssertionError("command-less servers have no firewall and need no resident round trip")

    monkeypatch.setattr(mcp_skill_firewall, "native_firewall_metadata_patch", forbidden)
    for command in (None, "", "   "):
        artifact = GuardArtifact(
            artifact_id="cursor:project:remote",
            name="remote",
            harness="cursor",
            artifact_type="mcp_server",
            source_scope="project",
            config_path=".cursor/mcp.json",
            command=command,
            url="https://example.com/mcp",
            transport="http",
            metadata={},
        )
        assert enrich_artifact_with_mcp_skill_firewall(artifact) is artifact


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


def _skill_artifact(skill_path) -> GuardArtifact:
    return GuardArtifact(
        artifact_id="opencode:global:skill:claude:docs/SKILL.md",
        name="docs/SKILL.md",
        harness="opencode",
        artifact_type="skill",
        source_scope="global",
        config_path=str(skill_path),
        metadata={},
    )


def test_skill_artifact_emits_skill_firewall_metadata(tmp_path) -> None:
    content = "---\nname: docs-helper\n---\n# Docs helper\n"
    skill_path = tmp_path / "SKILL.md"
    skill_path.write_text(content, encoding="utf-8")
    artifact = enrich_artifact_with_mcp_skill_firewall(_skill_artifact(skill_path))

    firewall = artifact.metadata["mcpSkillFirewall"]
    assert isinstance(firewall, dict)
    assert firewall["mcpTools"] == []
    skill = firewall["skill"]
    assert isinstance(skill, dict)
    # The resident hashes the document text Python shipped, nothing else.
    assert skill["skillHash"] == sha256(content.encode()).hexdigest()
    assert skill["publisherStableId"] is None
    identity_hash = skill["identityHash"]
    assert isinstance(identity_hash, str)
    assert skill["stableId"] == f"skill:{identity_hash[:24]}"
    legacy = artifact.metadata["mcp_skill_identity"]
    assert isinstance(legacy, dict)
    assert legacy["identity_hash"] == identity_hash
    assert legacy["skill_hash"] == skill["skillHash"]
    assert legacy["descriptor_hash"] == skill["descriptorHash"]


def test_unreadable_skill_document_never_needs_the_resident(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    def forbidden(**_kwargs):
        raise AssertionError("an unreadable document has no text to project")

    monkeypatch.setattr(mcp_skill_firewall, "native_skill_firewall_metadata_patch", forbidden)
    artifact = _skill_artifact(tmp_path / "missing" / "SKILL.md")
    assert enrich_artifact_with_mcp_skill_firewall(artifact) is artifact


def test_skill_enrichment_fails_closed_without_native_authority(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    def unavailable(**_kwargs):
        raise NativeMcpToolEvidenceError("native_mcp_tool_evidence_unavailable")

    monkeypatch.setattr(mcp_skill_firewall, "native_skill_firewall_metadata_patch", unavailable)
    skill_path = tmp_path / "SKILL.md"
    skill_path.write_text("# Docs helper\n", encoding="utf-8")
    with pytest.raises(NativeMcpToolEvidenceError, match=r"^native_mcp_tool_evidence_unavailable$"):
        enrich_artifact_with_mcp_skill_firewall(_skill_artifact(skill_path))


def test_firewall_enriches_mcp_server_metadata() -> None:
    enriched = enrich_artifact_with_mcp_skill_firewall(
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

    assert "mcpSkillFirewall" in enriched.metadata
