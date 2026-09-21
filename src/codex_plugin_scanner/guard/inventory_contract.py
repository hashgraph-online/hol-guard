"""Public inventory API and snapshot assembly; legacy exports remain compatible."""

from __future__ import annotations

import hashlib as hashlib
import importlib as importlib
import ipaddress as ipaddress
import json as json
import re as re
from collections.abc import Mapping as Mapping
from dataclasses import asdict as asdict
from dataclasses import dataclass as dataclass
from dataclasses import field as field
from datetime import datetime as datetime
from datetime import timezone as timezone
from pathlib import Path as Path
from types import SimpleNamespace as SimpleNamespace
from typing import Literal as Literal
from urllib.parse import parse_qsl as parse_qsl
from urllib.parse import urlencode as urlencode
from urllib.parse import urlsplit as urlsplit
from urllib.parse import urlunsplit as urlunsplit

from ..path_support import resolves_within_root as resolves_within_root
from ..version import __version__ as __version__
from .inventory_agent_types import _AGENT_INVENTORY_TYPES as _AGENT_INVENTORY_TYPES
from .inventory_agent_types import AgentInventoryType as AgentInventoryType
from .inventory_agent_types import agent_type as _agent_type
from .inventory_contract_constants import _AIBOM_METADATA_KEYS as _AIBOM_METADATA_KEYS
from .inventory_contract_constants import _FREE_FORM_RECORD_KEYS as _FREE_FORM_RECORD_KEYS
from .inventory_contract_constants import _IGNORED_TREE_DIR_NAMES as _IGNORED_TREE_DIR_NAMES
from .inventory_contract_constants import _INVENTORY_DATETIME_KEYS as _INVENTORY_DATETIME_KEYS
from .inventory_contract_constants import _MAX_FINGERPRINT_FILE_BYTES as _MAX_FINGERPRINT_FILE_BYTES
from .inventory_contract_constants import _MCP_DELETE_RE as _MCP_DELETE_RE
from .inventory_contract_constants import _MCP_MODEL_RE as _MCP_MODEL_RE
from .inventory_contract_constants import _MCP_NETWORK_RE as _MCP_NETWORK_RE
from .inventory_contract_constants import _MCP_PERMISSION_RE as _MCP_PERMISSION_RE
from .inventory_contract_constants import _MCP_READ_RE as _MCP_READ_RE
from .inventory_contract_constants import _MCP_SECRET_RE as _MCP_SECRET_RE
from .inventory_contract_constants import _MCP_SHELL_RE as _MCP_SHELL_RE
from .inventory_contract_constants import _MCP_WRITE_RE as _MCP_WRITE_RE
from .inventory_contract_constants import _OPTIONAL_ONLY_CONTRACT_KEYS as _OPTIONAL_ONLY_CONTRACT_KEYS
from .inventory_contract_constants import _SAFE_SERIALIZED_MARKERS as _SAFE_SERIALIZED_MARKERS
from .inventory_contract_constants import _SENSITIVE_KEY_RE as _SENSITIVE_KEY_RE
from .inventory_contract_constants import _SENSITIVE_VALUE_RE as _SENSITIVE_VALUE_RE
from .inventory_contract_constants import _SERIALIZER_REDACTED_VALUE as _SERIALIZER_REDACTED_VALUE
from .inventory_contract_constants import _SERIALIZER_SECRET_ASSIGNMENT_RE as _SERIALIZER_SECRET_ASSIGNMENT_RE
from .inventory_contract_constants import _SERIALIZER_UNSAFE_PATH_PATTERN as _SERIALIZER_UNSAFE_PATH_PATTERN
from .inventory_contract_constants import _SERIALIZER_UNSAFE_PATH_RE as _SERIALIZER_UNSAFE_PATH_RE
from .inventory_contract_constants import _UNSAFE_PATH_MARKERS as _UNSAFE_PATH_MARKERS
from .inventory_contract_constants import _WHITESPACE_RE as _WHITESPACE_RE
from .inventory_contract_constants import _path_has_symlink_component as _path_has_symlink_component
from .inventory_contract_fingerprints import _fingerprint_file_bytes as _fingerprint_file_bytes
from .inventory_contract_fingerprints import _inventory_snapshot_content_hash as _inventory_snapshot_content_hash
from .inventory_contract_fingerprints import _stable_snapshot_sort_key as _stable_snapshot_sort_key
from .inventory_contract_fingerprints import _stable_snapshot_value as _stable_snapshot_value
from .inventory_contract_fingerprints import fingerprint_mapping as fingerprint_mapping
from .inventory_contract_fingerprints import fingerprint_path_tree as fingerprint_path_tree
from .inventory_contract_fingerprints import fingerprint_text as fingerprint_text
from .inventory_contract_fingerprints import inventory_item_id as inventory_item_id
from .inventory_contract_items import _item_from_artifact as _item_from_artifact
from .inventory_contract_items import _mcp_tool_items_from_artifact as _mcp_tool_items_from_artifact
from .inventory_contract_mcp import _apply_tool_trust_attestation_metadata as _apply_tool_trust_attestation_metadata
from .inventory_contract_mcp import _attestation_path_hash as _attestation_path_hash
from .inventory_contract_mcp import _attestation_repository_id as _attestation_repository_id
from .inventory_contract_mcp import _capabilities_for_mcp_tool as _capabilities_for_mcp_tool
from .inventory_contract_mcp import _first_present_value as _first_present_value
from .inventory_contract_mcp import _mcp_schema_signal_text as _mcp_schema_signal_text
from .inventory_contract_mcp import _mcp_tool_definitions as _mcp_tool_definitions
from .inventory_contract_mcp import _optional_context_string as _optional_context_string
from .inventory_contract_mcp import _risk_level_for_capabilities as _risk_level_for_capabilities
from .inventory_contract_mcp import _string_value as _string_value
from .inventory_contract_metadata import _aibom_detection_module as _aibom_detection_module
from .inventory_contract_metadata import _aibom_symlink_module as _aibom_symlink_module
from .inventory_contract_metadata import _aibom_trust_metadata_module as _aibom_trust_metadata_module
from .inventory_contract_metadata import _apply_aibom_metadata_enrichment as _apply_aibom_metadata_enrichment
from .inventory_contract_metadata import _apply_source_of_truth_metadata as _apply_source_of_truth_metadata
from .inventory_contract_metadata import _bind_skill_document_evidence as _bind_skill_document_evidence
from .inventory_contract_metadata import _canonical_inventory_content_hash as _canonical_inventory_content_hash
from .inventory_contract_metadata import _capabilities_for_artifact as _capabilities_for_artifact
from .inventory_contract_metadata import (
    _discard_unverified_skill_directory_hash as _discard_unverified_skill_directory_hash,
)
from .inventory_contract_metadata import _inventory_item_description_module as _inventory_item_description_module
from .inventory_contract_metadata import _item_kind as _item_kind
from .inventory_contract_metadata import _primary_artifact_content_hash as _primary_artifact_content_hash
from .inventory_contract_metadata import _resolve_item_content_hash as _resolve_item_content_hash
from .inventory_contract_metadata import _risk_level as _risk_level
from .inventory_contract_metadata import _safe_roots_for_inspection as _safe_roots_for_inspection
from .inventory_contract_models import DockerProofStatus as DockerProofStatus
from .inventory_contract_models import GuardAgentIntegrationRun as GuardAgentIntegrationRun
from .inventory_contract_models import GuardAgentInventoryDockerProof as GuardAgentInventoryDockerProof
from .inventory_contract_models import GuardAgentInventoryDrift as GuardAgentInventoryDrift
from .inventory_contract_models import GuardAgentInventoryFinding as GuardAgentInventoryFinding
from .inventory_contract_models import GuardAgentInventoryItem as GuardAgentInventoryItem
from .inventory_contract_models import GuardAgentInventorySnapshot as GuardAgentInventorySnapshot
from .inventory_contract_models import GuardHarnessSetupStep as GuardHarnessSetupStep
from .inventory_contract_models import GuardInventoryRiskComponent as GuardInventoryRiskComponent
from .inventory_contract_models import GuardInventorySource as GuardInventorySource
from .inventory_contract_models import InventoryCapability as InventoryCapability
from .inventory_contract_models import InventoryConfidence as InventoryConfidence
from .inventory_contract_models import InventoryDriftState as InventoryDriftState
from .inventory_contract_models import InventoryFindingSource as InventoryFindingSource
from .inventory_contract_models import InventoryItemKind as InventoryItemKind
from .inventory_contract_models import InventorySeverity as InventorySeverity
from .inventory_contract_redaction import (
    _assert_serialized_inventory_payload_safe as _assert_serialized_inventory_payload_safe,
)
from .inventory_contract_redaction import _redact_command_value as _redact_command_value
from .inventory_contract_redaction import _redact_known_path as _redact_known_path
from .inventory_contract_redaction import _safe_artifact_metadata as _safe_artifact_metadata
from .inventory_contract_redaction import _safe_finding_text as _safe_finding_text
from .inventory_contract_redaction import _safe_json as _safe_json
from .inventory_contract_redaction import _safe_source_detail as _safe_source_detail
from .inventory_contract_redaction import _sanitize_paths as _sanitize_paths
from .inventory_contract_redaction import _sanitize_serializer_string as _sanitize_serializer_string
from .inventory_contract_redaction import classify_endpoint_host as classify_endpoint_host
from .inventory_contract_redaction import redact_headers as redact_headers
from .inventory_contract_redaction import redact_local_path as redact_local_path
from .inventory_contract_redaction import redact_url as redact_url
from .inventory_contract_scans import _artifact_id_for_cisco_finding as _artifact_id_for_cisco_finding
from .inventory_contract_scans import _cisco_inventory_findings as _cisco_inventory_findings
from .inventory_contract_scans import _cisco_inventory_sources as _cisco_inventory_sources
from .inventory_contract_scans import _cisco_source as _cisco_source
from .inventory_contract_scans import _inventory_severity as _inventory_severity
from .inventory_contract_scans import _score_delta_for_severity as _score_delta_for_severity
from .inventory_contract_scans import _source_status_for_cisco_status as _source_status_for_cisco_status
from .inventory_contract_scans import _symlink_findings_from_items as _symlink_findings_from_items
from .path_security import path_has_symlink_component as path_has_symlink_component
from .skill_directory_identity import validated_complete_skill_directory_hash as validated_complete_skill_directory_hash


def _snake_to_camel_case_key(key: str) -> str:
    """Translate a Python field name to the inventory wire key."""
    if "_" not in key:
        return key
    head, *tail = key.split("_")
    return head + "".join(part[:1].upper() + part[1:] if part else "" for part in tail)


def _normalize_redaction_report(report: object) -> dict[str, object]:
    """Validate and normalize redaction counts into the public report shape."""
    if not isinstance(report, dict):
        return {"rawSecretsIncluded": False, "redactedFields": []}
    raw_secrets = report.get("rawSecretsIncluded")
    if raw_secrets is None:
        raw_secrets = report.get("raw_secret_values")
    if raw_secrets is None:
        raw_secrets = report.get("raw_secrets_included", False)
    redacted_fields = report.get("redactedFields")
    if redacted_fields is None:
        redacted_fields = report.get("redacted_fields", [])
    return {
        "rawSecretsIncluded": raw_secrets is True,
        "redactedFields": list(redacted_fields) if isinstance(redacted_fields, (list, tuple)) else [],
    }


def _normalize_inventory_datetime(value: object) -> object:
    """Serialize a valid inventory timestamp consistently in UTC."""
    if not isinstance(value, str) or not value.strip():
        return value
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        parsed = parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
        return parsed.isoformat().replace("+00:00", "Z")
    except (ValueError, OverflowError, TypeError):
        return value


def _inventory_contract_json(value: object) -> object:
    """Serialize contract data through the established field-name and safety rules."""
    if isinstance(value, list):
        return [_inventory_contract_json(item) for item in value]
    if isinstance(value, dict):
        normalized: dict[str, object] = {}
        for key, item in value.items():
            camel_key = _snake_to_camel_case_key(str(key))
            if item is None and camel_key in _OPTIONAL_ONLY_CONTRACT_KEYS:
                continue
            if camel_key in _FREE_FORM_RECORD_KEYS:
                normalized[camel_key] = item
                continue
            if camel_key == "redactionReport":
                normalized[camel_key] = _normalize_redaction_report(item)
                continue
            if camel_key in _INVENTORY_DATETIME_KEYS:
                normalized[camel_key] = _normalize_inventory_datetime(item)
                continue
            normalized[camel_key] = _inventory_contract_json(item)
        return normalized
    return value


def serialize_inventory_snapshot(snapshot: GuardAgentInventorySnapshot) -> dict[str, object]:
    """Emit the inventory wire contract after applying final redaction checks."""
    payload = _safe_json(asdict(snapshot))
    if not isinstance(payload, dict):
        raise TypeError("Inventory snapshot serialization produced invalid payload.")
    contract = _inventory_contract_json(payload)
    if not isinstance(contract, dict):
        raise TypeError("Inventory snapshot serialization produced invalid payload.")
    _assert_serialized_inventory_payload_safe(contract)
    return contract


def extract_aibom_metadata_extensions(metadata: dict[str, object]) -> dict[str, object]:
    """Return redacted AIBOM metadata extensions for CLI and inventory JSON output."""

    extensions = {key: _safe_json(metadata[key]) for key in _AIBOM_METADATA_KEYS if key in metadata}
    source_of_truth = extensions.get("sourceOfTruth")
    if "sourceLinks" not in extensions and isinstance(source_of_truth, dict):
        extensions["sourceLinks"] = [_safe_json(source_of_truth)]
    return extensions


def cloud_inventory_artifacts_from_detection(
    detection: object,
    *,
    home_dir: Path,
    workspace_dir: Path | None = None,
) -> tuple[object, ...]:
    """Return artifacts eligible for the cloud inventory contract.

    Supplementary skill files remain part of local detection and policy
    evaluation, but the cloud inventory represents the primary SKILL.md once.
    """
    harness = str(getattr(detection, "harness", "unknown"))
    artifacts: list[object] = list(getattr(detection, "artifacts", ()))
    if workspace_dir is not None:
        existing_ids = {str(getattr(artifact, "artifact_id", "")) for artifact in artifacts}
        for artifact in _aibom_detection_module().discover_shared_workspace_aibom_artifacts(
            harness,
            home_dir=home_dir,
            workspace_dir=workspace_dir,
        ):
            if artifact.artifact_id not in existing_ids:
                artifacts.append(artifact)
                existing_ids.add(artifact.artifact_id)
    artifacts = [artifact for artifact in artifacts if str(getattr(artifact, "artifact_type", "")) != "skill_file"]
    return tuple(artifacts)


def inventory_snapshot_from_detection(
    detection: object,
    *,
    generated_at: str,
    home_dir: Path,
    workspace_dir: Path | None = None,
    runtime_version: str | None = None,
    cisco_runs: tuple[object, ...] = (),
    include_symlinks: bool = True,
    follow_unsafe_symlinks: bool = False,
    trust_attestation_context: Mapping[str, object] | None = None,
    artifacts: tuple[object, ...] | None = None,
) -> GuardAgentInventorySnapshot:
    """Assemble native artifacts, scanner findings, and trust evidence into one snapshot."""
    harness = str(getattr(detection, "harness", "unknown"))
    artifact_tuple = (
        artifacts
        if artifacts is not None
        else cloud_inventory_artifacts_from_detection(
            detection,
            home_dir=home_dir,
            workspace_dir=workspace_dir,
        )
    )
    items: list[GuardAgentInventoryItem] = []
    for artifact in artifact_tuple:
        item = _item_from_artifact(
            harness,
            artifact,
            generated_at=generated_at,
            home_dir=home_dir,
            workspace_dir=workspace_dir,
            cisco_runs=cisco_runs,
            include_symlinks=include_symlinks,
            follow_unsafe_symlinks=follow_unsafe_symlinks,
            trust_attestation_context=trust_attestation_context,
        )
        items.append(item)
        items.extend(
            _mcp_tool_items_from_artifact(
                harness,
                artifact,
                item,
                generated_at=generated_at,
                home_dir=home_dir,
                workspace_dir=workspace_dir,
                cisco_runs=cisco_runs,
                trust_attestation_context=trust_attestation_context,
            )
        )
    config_paths = tuple(dict.fromkeys(str(path) for path in getattr(detection, "config_paths", ())))
    config_sources = tuple(
        GuardInventorySource(
            source_id=f"{harness}:config:{fingerprint_text(redact_local_path(path, home_dir=home_dir))[:12]}",
            source_type="config",
            status="available",
            captured_at=generated_at,
            detail=redact_local_path(path, home_dir=home_dir),
        )
        for path in config_paths
    )
    item_tuple = tuple(items)
    cisco_findings = _cisco_inventory_findings(
        cisco_runs,
        items=item_tuple,
        home_dir=home_dir,
        workspace_dir=workspace_dir,
    )
    symlink_findings = _symlink_findings_from_items(harness, item_tuple) if include_symlinks else ()
    sources = (*config_sources, *_cisco_inventory_sources(cisco_runs))
    snapshot_hash = _inventory_snapshot_content_hash(
        agent_type=harness,
        items=item_tuple,
        findings=(*cisco_findings, *symlink_findings),
        sources=sources,
        runtime_version=runtime_version,
    )
    return GuardAgentInventorySnapshot(
        snapshot_id=f"{harness}:snapshot:{snapshot_hash[:24]}",
        agent_id=f"{harness}:local",
        agent_type=_agent_type(harness),
        generated_at=generated_at,
        runtime_version=runtime_version,
        items=item_tuple,
        findings=(*cisco_findings, *symlink_findings),
        sources=sources,
        redaction_report={
            "rawSecretsIncluded": False,
            "redactedFields": ("headers", "env", "url", "paths", "ciscoFindingText"),
        },
    )
