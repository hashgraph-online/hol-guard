"""Native artifact and MCP-tool inventory item assembly."""

from __future__ import annotations

import copy
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

from ..version import __version__
from .inventory_contract_fingerprints import fingerprint_mapping
from .inventory_contract_mcp import (
    _apply_tool_trust_attestation_metadata,
    _attestation_path_hash,
    _attestation_repository_id,
)
from .inventory_contract_metadata import (
    _aibom_trust_metadata_module,
    _apply_aibom_metadata_enrichment,
    _inventory_item_description_module,
)
from .inventory_contract_models import (
    GuardAgentInventoryItem,
    InventoryCapability,
    InventoryItemKind,
    InventorySeverity,
)
from .inventory_contract_redaction import _redact_command_value, _safe_artifact_metadata, redact_url
from .native_inventory_item_classification import InventoryItemClassificationUnavailableError

# The metadata lists a server advertises its tool definitions under.
_MCP_TOOL_DEFINITION_KEYS = ("tools", "tool_schemas", "toolSchemas")


def _artifact_classification_entry(
    harness: str,
    artifact: object,
    *,
    generated_at: str,
    home_dir: Path,
    workspace_dir: Path | None,
    source_evidence: Mapping[str, object],
    cisco_runs: tuple[object, ...] = (),
) -> dict[str, object]:
    """Assemble what the resident needs to classify one native artifact.

    ``source_evidence`` is the resident's first answer about this artifact:
    the kind its type maps onto, the instruction role an overlay's configured
    path names, the source of truth behind a symlinked config path, and the
    hash of its primary document. The two filesystem readings are not derived
    here, and neither is the kind or the role.

    The result doubles as the classification request entry, so the caller can
    hand the whole artifact set over in one call.
    """
    artifact_id = str(getattr(artifact, "artifact_id", "artifact"))
    artifact_type = str(getattr(artifact, "artifact_type", "unknown"))
    name = str(getattr(artifact, "name", artifact_id))
    item_kind_value = source_evidence.get("item_kind")
    if not isinstance(item_kind_value, str) or not item_kind_value:
        raise InventoryItemClassificationUnavailableError
    safe_metadata = _safe_artifact_metadata(artifact, home_dir=home_dir, workspace_dir=workspace_dir)
    instruction_role = source_evidence.get("instruction_role")
    safe_metadata = _apply_aibom_metadata_enrichment(
        artifact,
        captured_at=generated_at,
        item_kind=cast("InventoryItemKind", item_kind_value),
        metadata=safe_metadata,
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        instruction_role=instruction_role if isinstance(instruction_role, str) else None,
        cisco_runs=cisco_runs,
    )
    source_of_truth = source_evidence.get("source_of_truth")
    if isinstance(source_of_truth, dict):
        safe_metadata = {**safe_metadata, "sourceOfTruth": source_of_truth}
    primary_hash_value = source_evidence.get("primary_content_hash")
    entry: dict[str, object] = {
        "harness": harness,
        "artifact_id": artifact_id,
        "artifact_type": artifact_type,
        "name": name,
        "metadata": safe_metadata,
    }
    if isinstance(primary_hash_value, str) and primary_hash_value:
        entry["primary_content_hash"] = primary_hash_value
    return entry


def _item_from_artifact(
    harness: str,
    artifact: object,
    *,
    home_dir: Path,
    workspace_dir: Path | None,
    entry: Mapping[str, object],
    classification: Mapping[str, object],
    trust_attestation_context: Mapping[str, object] | None = None,
) -> GuardAgentInventoryItem:
    """Convert a classified native artifact into an inventory item.

    ``entry`` is what ``_artifact_classification_entry`` assembled and
    ``classification`` is the resident's answer for it. The item's kind,
    capabilities, risk level and content hash are read from that answer, and
    the metadata it publishes is this item's own mapping with the edits the
    answer asked for, so the key order the scan built survives.
    """
    artifact_id = str(entry.get("artifact_id", "artifact"))
    name = str(entry.get("name", artifact_id))
    item_kind = cast("InventoryItemKind", classification["item_kind"])
    content_hash = str(classification["content_hash"])
    safe_metadata = _classified_metadata(entry, classification)
    from .runtime.trust_attestation import (
        GuardTrustAttestationSigningConfig,
        apply_trust_attestation_metadata,
    )

    workspace_id = None
    device_id = None
    analyzer_id = None
    analyzer_spec_version = None
    analyzer_version = None
    policy_version = None
    installation_id = None
    upload_id = None
    challenge_id = None
    nonce = None
    sequence = None
    expires_at = None
    signing_config = None
    if isinstance(trust_attestation_context, Mapping):
        raw_workspace_id = trust_attestation_context.get("workspaceId")
        workspace_id = raw_workspace_id if isinstance(raw_workspace_id, str) and raw_workspace_id else None
        raw_device_id = trust_attestation_context.get("deviceId")
        device_id = raw_device_id if isinstance(raw_device_id, str) and raw_device_id else None
        raw_analyzer_id = trust_attestation_context.get("analyzerId")
        analyzer_id = raw_analyzer_id if isinstance(raw_analyzer_id, str) and raw_analyzer_id else None
        raw_analyzer_spec_version = trust_attestation_context.get("analyzerSpecVersion")
        analyzer_spec_version = (
            raw_analyzer_spec_version
            if isinstance(raw_analyzer_spec_version, str) and raw_analyzer_spec_version
            else None
        )
        raw_analyzer_version = trust_attestation_context.get("analyzerVersion")
        analyzer_version = (
            raw_analyzer_version if isinstance(raw_analyzer_version, str) and raw_analyzer_version else None
        )
        raw_installation_id = trust_attestation_context.get("installationId")
        installation_id = raw_installation_id if isinstance(raw_installation_id, str) and raw_installation_id else None
        raw_upload_id = trust_attestation_context.get("uploadId")
        upload_id = raw_upload_id if isinstance(raw_upload_id, str) and raw_upload_id else None
        raw_challenge_id = trust_attestation_context.get("challengeId")
        challenge_id = raw_challenge_id if isinstance(raw_challenge_id, str) and raw_challenge_id else None
        raw_nonce = trust_attestation_context.get("nonce")
        nonce = raw_nonce if isinstance(raw_nonce, str) and raw_nonce else None
        raw_sequence = trust_attestation_context.get("sequence")
        if isinstance(raw_sequence, int):
            sequence = raw_sequence
        raw_policy_version = trust_attestation_context.get("policyVersion")
        policy_version = raw_policy_version if isinstance(raw_policy_version, str) and raw_policy_version else None
        raw_expires_at = trust_attestation_context.get("expiresAt")
        expires_at = raw_expires_at if isinstance(raw_expires_at, str) and raw_expires_at else None
        raw_signing_config = trust_attestation_context.get("signingConfig")
        if isinstance(raw_signing_config, GuardTrustAttestationSigningConfig):
            signing_config = raw_signing_config

    safe_metadata = apply_trust_attestation_metadata(
        safe_metadata,
        agent_id=f"{harness}:local",
        analyzer_id=analyzer_id,
        analyzer_spec_version=analyzer_spec_version,
        analyzer_version=analyzer_version,
        item_id=artifact_id,
        item_kind=item_kind,
        content_hash=content_hash,
        challenge_id=challenge_id,
        expires_at=expires_at,
        installation_id=installation_id,
        nonce=nonce,
        policy_version=policy_version,
        sequence=sequence,
        upload_id=upload_id,
        workspace_id=workspace_id,
        device_id=device_id,
        adapter_id=harness,
        adapter_version=__version__,
        config_path_hash=_attestation_path_hash(getattr(artifact, "config_path", None), fallback=artifact_id),
        repository_id=_attestation_repository_id(home_dir=home_dir, workspace_dir=workspace_dir),
        signing_config=signing_config,
    )
    publisher = getattr(artifact, "publisher", None)
    publisher_text = publisher if isinstance(publisher, str) else None
    description = _inventory_item_description_module().resolve_inventory_item_description(
        harness=harness,
        item_kind=item_kind,
        display_name=name,
        metadata=safe_metadata,
        publisher=publisher_text,
        home_dir=home_dir,
        workspace_dir=workspace_dir,
    )
    return GuardAgentInventoryItem(
        item_id=artifact_id,
        item_kind=item_kind,
        display_name=name,
        description=description,
        source_fingerprint=fingerprint_mapping({"harness": harness, "artifact_id": artifact_id}),
        content_hash=content_hash,
        capability_categories=tuple(cast("Sequence[InventoryCapability]", classification["capability_categories"])),
        risk_level=cast("InventorySeverity", classification["risk_level"]),
        scanner_sources=("hol-detector",),
        metadata=safe_metadata,
    )


def _classified_metadata(
    entry: Mapping[str, object],
    classification: Mapping[str, object],
) -> dict[str, object]:
    """Apply the resident's metadata edits to this item's own mapping.

    The resident answers with the keys to drop and the keys to write rather
    than a rewritten mapping, so an item that was not changed keeps the exact
    mapping the scan built, in the order it built it.
    """
    metadata = dict(cast("Mapping[str, object]", entry.get("metadata", {})))
    for key in cast("Sequence[str]", classification.get("metadata_removals", ())):
        metadata.pop(key, None)
    metadata.update(cast("Mapping[str, object]", classification.get("metadata_updates", {})))
    return metadata


def _mcp_tool_items_from_artifact(
    harness: str,
    artifact: object,
    server_item: GuardAgentInventoryItem,
    *,
    generated_at: str,
    home_dir: Path,
    workspace_dir: Path | None,
    cisco_runs: tuple[object, ...] = (),
    trust_attestation_context: Mapping[str, object] | None = None,
) -> tuple[GuardAgentInventoryItem, ...]:
    """Expand advertised MCP tool definitions into individually attributable inventory items.

    The resident reads the definitions: which tools the server declares, what
    each one can do, its risk level and the hashes that identify it. This keeps
    the trust metadata, attestation and description steps it already delegates.
    """
    artifact_type = str(getattr(artifact, "artifact_type", "unknown"))
    if artifact_type != "mcp_server":
        return ()
    raw_metadata = getattr(artifact, "metadata", {})
    if not isinstance(raw_metadata, dict):
        return ()
    definitions = {key: raw_metadata[key] for key in _MCP_TOOL_DEFINITION_KEYS if raw_metadata.get(key)}
    if not definitions:
        return ()
    expansion = _mcp_tool_expansion(harness, server_item, definitions)
    inherited_layers = expansion["inherited_layers"]
    server_command = getattr(artifact, "command", None)
    server_url = getattr(artifact, "url", None)
    server_fields: dict[str, object] = {
        "serverCommand": _redact_command_value(server_command, home_dir, workspace_dir)
        if isinstance(server_command, str) and server_command
        else None,
        "serverUrl": redact_url(server_url) if isinstance(server_url, str) and server_url else None,
        "serverTransport": getattr(artifact, "transport", None),
    }

    items: list[GuardAgentInventoryItem] = []
    for tool in expansion["tools"]:
        name = tool["name"]
        display_name = tool["display_name"]
        description = tool["description"]
        tool_item_id = tool["item_id"]
        semantic_hash = tool["semantic_hash"]
        metadata: dict[str, object] = {
            "serverItemId": server_item.item_id,
            "toolName": name,
            "title": display_name,
            **server_fields,
            **tool["fingerprints"],
        }
        tool_artifact = SimpleNamespace(
            artifact_id=f"{getattr(artifact, 'artifact_id', server_item.item_id)}:tool:{name}",
            artifact_type="mcp_tool",
            config_path=getattr(artifact, "config_path", ""),
            name=name,
            command=getattr(artifact, "command", None),
            url=getattr(artifact, "url", None),
            transport=getattr(artifact, "transport", None),
        )
        metadata = _aibom_trust_metadata_module().apply_local_trust_metadata(
            tool_artifact,
            captured_at=generated_at,
            item_kind="mcp_tool",
            metadata=metadata,
            workspace_dir=workspace_dir,
            cisco_runs=cisco_runs,
        )
        tool_layers = metadata.get("trustLayers")
        tool_layer_dicts = (
            [layer for layer in tool_layers if isinstance(layer, dict)] if isinstance(tool_layers, list) else []
        )
        if tool_layer_dicts:
            metadata["trustLayers"] = tool_layer_dicts
        metadata = _apply_tool_trust_attestation_metadata(
            metadata,
            harness=harness,
            item_id=tool_item_id,
            content_hash=semantic_hash,
            config_path_hash=_attestation_path_hash(
                getattr(artifact, "config_path", None),
                fallback=server_item.item_id,
            ),
            repository_id=_attestation_repository_id(home_dir=home_dir, workspace_dir=workspace_dir),
            trust_attestation_context=trust_attestation_context,
        )
        signed_tool_layers = metadata.get("trustLayers")
        tool_layer_dicts = (
            [layer for layer in signed_tool_layers if isinstance(layer, dict)]
            if isinstance(signed_tool_layers, list)
            else []
        )
        has_tool_cisco_layer = any(layer.get("layerType") == "cisco_mcp_scanner" for layer in tool_layer_dicts)
        if inherited_layers and not has_tool_cisco_layer:
            metadata["trustLayers"] = [*tool_layer_dicts, *copy.deepcopy(inherited_layers)]
        tool_description = _inventory_item_description_module().resolve_inventory_item_description(
            harness=harness,
            item_kind="mcp_tool",
            display_name=display_name,
            metadata=metadata,
            explicit_description=description or None,
            home_dir=home_dir,
            workspace_dir=workspace_dir,
        )
        capabilities = cast("tuple[InventoryCapability, ...]", tuple(tool["capabilities"]))
        items.append(
            GuardAgentInventoryItem(
                item_id=tool_item_id,
                item_kind="mcp_tool",
                display_name=display_name,
                description=tool_description,
                source_fingerprint=tool["source_fingerprint"],
                content_hash=semantic_hash,
                capability_categories=capabilities,
                risk_level=cast("InventorySeverity", tool["risk_level"]),
                scanner_sources=("hol-detector",),
                metadata=metadata,
            )
        )
    return tuple(items)


def _mcp_tool_expansion(
    harness: str,
    server_item: GuardAgentInventoryItem,
    definitions: Mapping[str, object],
) -> dict[str, Any]:
    """Ask the resident for the server's tool readings and the layers its tools inherit.

    Both travel as JSON text so the resident reads the keys in the order the
    server declared them. An unavailable resident fails the snapshot closed,
    as an unclassified artifact does, rather than listing tools unread.
    """
    from .native_runner_authority import native_runner_authority

    try:
        answer = native_runner_authority(
            "mcp_tool_inventory",
            {
                "harness": harness,
                "server_item_id": server_item.item_id,
                "definitions": json.dumps(definitions, default=str),
                "trust_layers": json.dumps(server_item.metadata.get("trustLayers"), default=str),
            },
        )
        return cast("dict[str, Any]", json.loads(answer["answer"]))
    except (KeyError, TypeError, ValueError) as error:
        raise InventoryItemClassificationUnavailableError from error
