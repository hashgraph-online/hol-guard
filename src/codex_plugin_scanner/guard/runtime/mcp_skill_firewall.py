"""Portal-aligned MCP/skill firewall metadata for Guard artifacts and receipts."""

from __future__ import annotations

import importlib
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..models import GuardArtifact
from ..native_context import (
    context_sha256_digest,
    is_unbound_context_digest,
    native_context_failure_reason,
)
from ..native_mcp_runtime_evidence import argument_entries, native_runtime_action_record, runtime_action_key
from ..native_mcp_tool_evidence import native_firewall_metadata_patch

if TYPE_CHECKING:
    from .actions import GuardActionEnvelope


def _skill_protection_module():
    return importlib.import_module(".skill_protection", __package__)


def _descriptor_digest(material: object) -> str:
    digest = context_sha256_digest(material, unbound_label="mcp-descriptor")
    if is_unbound_context_digest(digest):
        reason = native_context_failure_reason()  # name the real transport failure
        raise ValueError("native_mcp_descriptor_digest_unavailable" + (f":{reason}" if reason else ""))
    return digest


def _publisher_stable_id(source: str | None) -> str | None:
    normalized = (source or "").strip().lower()
    if not normalized:
        return None
    return f"publisher:{_descriptor_digest(normalized)}"


def skill_identity_metadata(
    identity: Any,
    *,
    publisher: str | None = None,
) -> dict[str, object]:
    descriptor_hash = _descriptor_digest(
        {
            "reference_hashes": list(identity.reference_hashes),
            "script_hashes": list(identity.script_hashes),
            "template_hashes": list(identity.template_hashes),
        }
    )
    stable_id = f"skill:{identity.identity_hash[:24]}"
    publisher_stable_id = _publisher_stable_id(publisher)
    return {
        "skill_hash": identity.skill_hash,
        "descriptor_hash": descriptor_hash,
        "identity_hash": identity.identity_hash,
        "stable_id": stable_id,
        "publisher_stable_id": publisher_stable_id,
    }


def portal_skill_identity(
    identity: Any,
    *,
    publisher: str | None = None,
) -> dict[str, object]:
    metadata = skill_identity_metadata(identity, publisher=publisher)
    return {
        "dependencyHashes": [],
        "descriptorHash": metadata["descriptor_hash"],
        "identityHash": metadata["identity_hash"],
        "publisherStableId": metadata.get("publisher_stable_id"),
        "skillHash": metadata["skill_hash"],
        "stableId": metadata["stable_id"],
    }


def build_mcp_skill_firewall_fingerprints(
    *,
    mcp_server: dict[str, object] | None = None,
    mcp_tools: list[dict[str, object]] | None = None,
    skill: dict[str, object] | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {"mcpTools": mcp_tools or []}
    if mcp_server is not None:
        payload["mcpServer"] = mcp_server
    if skill is not None:
        payload["skill"] = skill
    return payload


def build_runtime_action_record(
    *,
    artifact: GuardArtifact,
    arguments: object | None = None,
    action_envelope: GuardActionEnvelope | None = None,
    risk_categories: tuple[str, ...] = (),
) -> dict[str, object] | None:
    """Return the native-owned ``runtimeAction`` evidence record for a tool call."""
    description = artifact.metadata.get("tool_description")
    return native_runtime_action_record(
        tool_description=description if isinstance(description, str) else None,
        arguments=argument_entries(arguments, mapping_type=dict, relevant=runtime_action_key),
        risk_categories=risk_categories,
        envelope=None
        if action_envelope is None
        else {
            "target_paths": list(action_envelope.target_paths),
            "network_hosts": list(action_envelope.network_hosts),
            "package_manager": action_envelope.package_manager,
            "command": action_envelope.command,
        },
    )


def _legacy_skill_identity(skill: dict[str, object]) -> dict[str, object]:
    return {
        "dependency_hashes": skill.get("dependencyHashes") or [],
        "descriptor_hash": skill.get("descriptorHash"),
        "identity_hash": skill.get("identityHash"),
        "publisher_stable_id": skill.get("publisherStableId"),
        "skill_hash": skill.get("skillHash"),
        "stable_id": skill.get("stableId"),
    }


def _firewall_for_skill(artifact: GuardArtifact) -> dict[str, object] | None:
    content = _read_text_file(artifact.config_path)
    if content is None:
        return None
    identity = _skill_protection_module().build_skill_identity(content, skill_path=artifact.config_path)
    skill = portal_skill_identity(identity, publisher=artifact.publisher)
    return build_mcp_skill_firewall_fingerprints(skill=skill)


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
    """Attach firewall metadata; MCP server and tool-call evidence is native-owned."""
    if artifact.artifact_type == "skill":
        firewall = _firewall_for_skill(artifact)
        if firewall is None:
            return artifact
        skill = firewall.get("skill")
        metadata = dict(artifact.metadata)
        metadata["mcpSkillFirewall"] = firewall
        if isinstance(skill, dict):
            metadata["mcp_skill_identity"] = _legacy_skill_identity(skill)
        return replace(artifact, metadata=metadata)
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


__all__ = [
    "build_mcp_skill_firewall_fingerprints",
    "build_runtime_action_record",
    "enrich_artifact_with_mcp_skill_firewall",
    "portal_skill_identity",
    "skill_identity_metadata",
]
