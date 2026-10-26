"""The CPython inventory item-metadata grammar the Rust runtime replaced.

The runtime answers `inventory_item_classification` from
`rust/crates/guard-command/src/inventory_item_metadata.rs` and
`rust/crates/guard-runtime/src/inventory_item_classification_op.rs`. Nothing
under `src/` computes an item kind, a content hash, a capability set or a risk
level any more, so these functions exist only to generate the parity fixture
that pins the port to the behaviour it was written against.

They are a record, not a second implementation: never import them from
`codex_plugin_scanner`, and change one only to match what the shipped Python
did on the day it was retired.
"""

from __future__ import annotations

import re

from codex_plugin_scanner.guard.inventory_contract_models import (
    InventoryCapability,
    InventoryItemKind,
    InventorySeverity,
)
from codex_plugin_scanner.guard.skill_directory_identity import (
    validated_complete_skill_directory_hash,
)


def item_kind(artifact_type: str) -> InventoryItemKind:
    """Map a native artifact category to the inventory item-kind contract."""
    mapping: dict[str, InventoryItemKind] = {
        "skill": "skill",
        "skill_file": "skill",
        "mcp_server": "mcp_server",
        "mcp_tool": "mcp_tool",
        "channel": "channel",
        "gateway_config": "agent",
        "config": "agent",
        "agent": "agent",
        "hook": "hook",
        "instruction": "overlay",
        "overlay": "overlay",
        "command": "prompt_pack",
        "extension": "plugin",
        "plugin": "plugin",
        "plugin-file": "plugin",
        "repository": "repository",
        "container_image": "container_image",
        "policy": "policy",
        "secret_reference": "secret_reference",
        "network_endpoint": "network_endpoint",
        "guard_launcher_shim": "harness",
        "package": "package",
        "daemon_plugin": "daemon_plugin",
        "model_provider": "model_provider",
        "prompt_pack": "prompt_pack",
    }
    return mapping.get(artifact_type, "plugin")


def resolve_item_content_hash(metadata: dict[str, object], semantic_text: str) -> str:
    """Choose a verified content hash from supported artifact evidence."""
    for key in ("content_hash", "directory_hash"):
        candidate = metadata.get(key)
        if isinstance(candidate, str) and candidate:
            return canonical_inventory_content_hash(candidate)
    version_info = metadata.get("versionInfo")
    if isinstance(version_info, dict):
        version_hash = version_info.get("contentHash")
        if isinstance(version_hash, str) and version_hash:
            return canonical_inventory_content_hash(version_hash)
    return semantic_text


def discard_unverified_skill_directory_hash(metadata: dict[str, object]) -> dict[str, object]:
    """Remove a directory hash when its content cannot be verified safely."""
    if "skillDirectoryIdentity" not in metadata or validated_complete_skill_directory_hash(metadata) is not None:
        return metadata
    sanitized = dict(metadata)
    sanitized.pop("directory_hash", None)
    return sanitized


def canonical_inventory_content_hash(value: str) -> str:
    """Normalize a supported content fingerprint into its canonical wire form."""
    normalized = value.lower()
    if re.fullmatch(r"[0-9a-f]{64}", normalized):
        return f"sha256:{normalized}"
    return value


def capabilities_for_artifact(
    artifact_type: str,
    metadata: dict[str, object],
) -> tuple[InventoryCapability, ...]:
    """Classify native artifact capabilities from supported metadata and findings."""
    capabilities: set[InventoryCapability] = set()
    if artifact_type in {"instruction", "overlay", "command"}:
        capabilities.add("reads_files")
    if artifact_type == "mcp_server":
        capabilities.add("network_egress")
        if metadata.get("transport") == "stdio":
            capabilities.add("runs_shell")
    if artifact_type == "channel":
        capabilities.update({"reads_messages", "posts_messages", "network_ingress"})
    if bool(metadata.get("envConfigurationPresent")) or bool(metadata.get("has_auth_headers")):
        capabilities.add("reads_secrets")
    return tuple(sorted(capabilities)) if capabilities else ("unknown",)


def bind_skill_document_evidence(
    metadata: dict[str, object],
    *,
    primary_content_hash: str | None,
) -> dict[str, object]:
    """Bind skill document identity and content evidence to its inventory item."""
    bound = dict(metadata)
    # This value is derived from Guard's own full, safe read of SKILL.md.  It
    # remains the authority for primary-body upload when the inventory item's
    # public content hash is upgraded to the full directory identity.
    if isinstance(primary_content_hash, str):
        bound["primaryContentHash"] = primary_content_hash
    else:
        bound.pop("primaryContentHash", None)

    evidence = metadata.get("contentEvidence")
    if (
        isinstance(evidence, dict)
        and isinstance(primary_content_hash, str)
        and evidence.get("contentHash") == primary_content_hash
    ):
        return bound

    if isinstance(evidence, dict) and "contentHash" not in evidence:
        bound.pop("documentedCapabilities", None)
        return bound

    bound.pop("contentEvidence", None)
    bound.pop("documentedCapabilities", None)
    return bound


def risk_level(metadata: dict[str, object]) -> InventorySeverity:
    """Normalize a scanner severity to a supported inventory risk level."""
    if metadata.get("has_auth_headers") or metadata.get("envConfigurationPresent"):
        return "high"
    if metadata.get("endpointHostClass") == "remote_public":
        return "medium"
    return "info"
