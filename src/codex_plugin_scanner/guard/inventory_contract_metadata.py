"""Inventory evidence enrichment and safe source-of-truth inspection."""

from __future__ import annotations

import hashlib
import importlib
import re
from pathlib import Path

from ..path_support import resolves_within_root
from .inventory_contract_constants import _path_has_symlink_component
from .inventory_contract_models import InventoryCapability, InventoryItemKind, InventorySeverity
from .skill_directory_identity import validated_complete_skill_directory_hash


def _aibom_detection_module():
    """Load source-of-truth detection lazily to avoid inventory initialization cycles."""
    return importlib.import_module(".aibom_detection", __package__)


def _aibom_symlink_module():
    """Load symlink evidence helpers only when inventory enrichment requires them."""
    return importlib.import_module(".aibom_symlink", __package__)


def _aibom_trust_metadata_module():
    """Load trust metadata enrichment without eagerly initializing its dependencies."""
    return importlib.import_module(".aibom_trust_metadata", __package__)


def _inventory_item_description_module():
    """Load native item description helpers through their existing module interface."""
    return importlib.import_module(".inventory_item_description", __package__)


def _item_kind(artifact_type: str) -> InventoryItemKind:
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


def _resolve_item_content_hash(metadata: dict[str, object], semantic_text: str) -> str:
    """Choose a verified content hash from supported artifact evidence."""
    for key in ("content_hash", "directory_hash"):
        candidate = metadata.get(key)
        if isinstance(candidate, str) and candidate:
            return _canonical_inventory_content_hash(candidate)
    version_info = metadata.get("versionInfo")
    if isinstance(version_info, dict):
        version_hash = version_info.get("contentHash")
        if isinstance(version_hash, str) and version_hash:
            return _canonical_inventory_content_hash(version_hash)
    return semantic_text


def _discard_unverified_skill_directory_hash(metadata: dict[str, object]) -> dict[str, object]:
    """Remove a directory hash when its content cannot be verified safely."""
    if "skillDirectoryIdentity" not in metadata or validated_complete_skill_directory_hash(metadata) is not None:
        return metadata
    sanitized = dict(metadata)
    sanitized.pop("directory_hash", None)
    return sanitized


def _primary_artifact_content_hash(
    artifact: object,
    *,
    artifact_type: str,
    home_dir: Path,
    workspace_dir: Path | None,
) -> str | None:
    """Read the primary artifact fingerprint without substituting unrelated evidence."""
    path_value = getattr(artifact, "config_path", None)
    if not isinstance(path_value, str) or not path_value.strip():
        return None
    path = Path(path_value).expanduser()
    if artifact_type == "skill":
        if path.name != "SKILL.md":
            return None
        skills_root = next((parent for parent in path.parents if parent.name.lower() == "skills"), None)
        if skills_root is None:
            return None
        try:
            relative = path.relative_to(skills_root)
        except ValueError:
            return None
        if len(relative.parts) < 2:
            return None
        outer_root = next(
            (
                root
                for root in (home_dir, workspace_dir)
                if root is not None and resolves_within_root(root, skills_root, require_exists=True)
            ),
            None,
        )
        if outer_root is None:
            return None
        allowed_roots = (skills_root,)
    elif artifact_type == "instruction":
        if workspace_dir is None or path.suffix.lower() not in {".md", ".mdc"}:
            return None
        allowed_roots = (workspace_dir,)
    else:
        return None
    allowed_root = next(
        (root for root in allowed_roots if root is not None and resolves_within_root(root, path, require_exists=True)),
        None,
    )
    if allowed_root is None or _path_has_symlink_component(path, allowed_root=allowed_root):
        return None
    try:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(64 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return None
    return f"sha256:{digest.hexdigest()}"


def _canonical_inventory_content_hash(value: str) -> str:
    """Normalize a supported content fingerprint into its canonical wire form."""
    normalized = value.lower()
    if re.fullmatch(r"[0-9a-f]{64}", normalized):
        return f"sha256:{normalized}"
    return value


def _safe_roots_for_inspection(
    *,
    home_dir: Path,
    workspace_dir: Path | None,
) -> tuple[Path, ...]:
    """Derive bounded filesystem roots permitted for source-of-truth inspection."""
    roots: list[Path] = [home_dir]
    if workspace_dir is not None:
        roots.insert(0, workspace_dir)
    return tuple(roots)


def _apply_source_of_truth_metadata(
    artifact: object,
    *,
    harness: str,
    item_kind: InventoryItemKind,
    metadata: dict[str, object],
    home_dir: Path,
    workspace_dir: Path | None,
    follow_unsafe_symlinks: bool = False,
) -> dict[str, object]:
    """Reconcile metadata with the native source while retaining bounded inspection."""
    config_path = getattr(artifact, "config_path", None)
    if not isinstance(config_path, str) or not config_path:
        return metadata
    path = Path(config_path)
    if not path.is_symlink():
        return metadata
    inspection = _aibom_symlink_module().inspect_aibom_source_path(
        path,
        safe_roots=_safe_roots_for_inspection(home_dir=home_dir, workspace_dir=workspace_dir),
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        follow_unsafe_symlinks=follow_unsafe_symlinks,
    )
    source_link_id = f"{harness}:{item_kind}:{inspection.source_fingerprint[:24]}"
    enriched = dict(metadata)
    enriched["sourceOfTruth"] = _aibom_symlink_module().source_of_truth_metadata_from_inspection(
        inspection,
        source_link_id=source_link_id,
    )
    return enriched


def _apply_aibom_metadata_enrichment(
    artifact: object,
    *,
    captured_at: str,
    item_kind: InventoryItemKind,
    metadata: dict[str, object],
    home_dir: Path,
    workspace_dir: Path | None,
    cisco_runs: tuple[object, ...] = (),
) -> dict[str, object]:
    """Add inventory detection, symlink, and trust evidence through established helpers."""
    enriched = dict(metadata)
    artifact_type = str(getattr(artifact, "artifact_type", "unknown"))
    if artifact_type == "skill":
        from .skill_document_evidence import enrich_skill_document_metadata

        enriched = enrich_skill_document_metadata(
            getattr(artifact, "config_path", None),
            enriched,
            home_dir=home_dir,
            workspace_dir=workspace_dir,
        )
    if item_kind == "overlay" and "instructionRole" not in enriched:
        config_path = getattr(artifact, "config_path", None)
        if isinstance(config_path, str):
            role = _aibom_detection_module().instruction_role_for_path(Path(config_path))
            if role is not None:
                enriched["instructionRole"] = role
    return _aibom_trust_metadata_module().apply_local_trust_metadata(
        artifact,
        captured_at=captured_at,
        item_kind=item_kind,
        metadata=enriched,
        workspace_dir=workspace_dir,
        cisco_runs=cisco_runs,
    )


def _capabilities_for_artifact(
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


def _bind_skill_document_evidence(
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


def _risk_level(metadata: dict[str, object]) -> InventorySeverity:
    """Normalize a scanner severity to a supported inventory risk level."""
    if metadata.get("has_auth_headers") or metadata.get("envConfigurationPresent"):
        return "high"
    if metadata.get("endpointHostClass") == "remote_public":
        return "medium"
    return "info"
