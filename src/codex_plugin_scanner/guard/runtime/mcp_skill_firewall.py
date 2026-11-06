"""Portal-aligned MCP/skill firewall metadata for Guard artifacts and receipts.

Rust owns every fingerprint. Python reads a skill document because the
resident does no IO, then ships the text; nothing here derives an identity,
digest or stable id.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from ..models import GuardArtifact
from ..native_mcp_tool_evidence import (
    native_firewall_metadata_patch,
    native_skill_firewall_metadata_patch,
)


def _read_text_file(path: str) -> str | None:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _can_carry_firewall(artifact: GuardArtifact) -> bool:
    if artifact.artifact_type == "mcp_server":
        return isinstance(artifact.command, str) and bool(artifact.command.strip())
    if artifact.command is not None:
        return True
    return isinstance(artifact.metadata.get("mcp_server_identity"), dict) and isinstance(
        artifact.metadata.get("mcp_tool_identity"), dict
    )


def enrich_artifact_with_mcp_skill_firewall(artifact: GuardArtifact) -> GuardArtifact:
    """Attach firewall metadata; skill, MCP server and tool-call evidence is native-owned."""
    if artifact.artifact_type == "skill":
        content = _read_text_file(artifact.config_path)
        if content is None:
            # An unreadable document has no identity to project, and the
            # resident needs the text, so this never costs a round trip.
            return artifact
        patch = native_skill_firewall_metadata_patch(
            name=artifact.name,
            config_path=artifact.config_path,
            publisher=artifact.publisher,
            skill_content=content,
        )
        if patch is None:
            return artifact
        return replace(artifact, metadata={**artifact.metadata, **patch})
    if artifact.artifact_type not in {"mcp_server", "tool_call"}:
        return artifact
    if not _can_carry_firewall(artifact):
        # Transport precondition, not evidence derivation: these never have a
        # firewall, so they must not need a resident round trip.
        return artifact
    patch = native_firewall_metadata_patch(artifact)
    if patch is None:
        return artifact
    return replace(artifact, metadata={**artifact.metadata, **patch})


__all__ = ["enrich_artifact_with_mcp_skill_firewall"]
