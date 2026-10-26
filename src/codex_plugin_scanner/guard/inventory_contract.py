"""Public inventory API and snapshot assembly; legacy exports remain compatible."""

from __future__ import annotations

import copy as copy
import hashlib as hashlib
import importlib as importlib
import ipaddress as ipaddress
import json as json
import re as re
from collections.abc import Mapping as Mapping
from collections.abc import Sequence as Sequence
from dataclasses import asdict as asdict
from dataclasses import dataclass as dataclass
from dataclasses import field as field
from dataclasses import fields as fields
from dataclasses import is_dataclass as is_dataclass
from dataclasses import replace as replace
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
from . import native_inventory_url_redaction as _native_url
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
from .inventory_contract_items import _artifact_classification_entry as _artifact_classification_entry
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
from .inventory_contract_metadata import _aibom_trust_metadata_module as _aibom_trust_metadata_module
from .inventory_contract_metadata import _apply_aibom_metadata_enrichment as _apply_aibom_metadata_enrichment
from .inventory_contract_metadata import _inventory_item_description_module as _inventory_item_description_module
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
from .inventory_contract_redaction import _prefetch_export_redactions
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
from .native_inventory_item_classification import native_inventory_item_classification
from .native_inventory_scan_findings import (
    InventoryScanFindingsUnavailableError,
    native_inventory_scan_findings,
)
from .native_inventory_source_evidence import native_inventory_source_evidence
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


def _scan_records(
    cisco_runs: Sequence[object],
    *,
    harness: str,
    items: Sequence[GuardAgentInventoryItem],
    home_dir: Path,
    workspace_dir: Path | None,
    include_symlinks: bool,
) -> tuple[tuple[GuardAgentInventoryFinding, ...], tuple[GuardInventorySource, ...]]:
    """Build the scan's finding and source records from the resident's answers.

    The resident decided every field; this only names them. A record whose
    fields the dataclass will not take means the two sides disagree about the
    contract, which is the same unavailability as no answer at all: a snapshot
    assembled from a half-understood answer would publish findings nobody
    classified.
    """

    findings, sources = native_inventory_scan_findings(
        cisco_runs,
        harness=harness,
        items=items,
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        include_symlinks=include_symlinks,
    )
    try:
        return (
            tuple(GuardAgentInventoryFinding(**finding) for finding in findings),  # pyright: ignore[reportArgumentType]
            tuple(GuardInventorySource(**source) for source in sources),  # pyright: ignore[reportArgumentType]
        )
    except TypeError:
        raise InventoryScanFindingsUnavailableError from None


_ITEM_ID_MAX_LENGTH = 160


def _artifact_with(artifact: object, **changes: str) -> object | None:
    """Copy ``artifact`` with ``changes`` applied, or return None if it cannot take them."""
    if is_dataclass(artifact) and not isinstance(artifact, type):
        if not changes.keys() <= {item.name for item in fields(artifact)}:
            return None
        return replace(artifact, **changes)
    try:
        updated = copy.copy(artifact)
        for name, value in changes.items():
            setattr(updated, name, value)
    except (AttributeError, TypeError):
        return None
    return updated


def _artifact_without_config_path(artifact: object) -> object:
    if not hasattr(artifact, "config_path"):
        return artifact
    stripped = _artifact_with(artifact, config_path="")
    return artifact if stripped is None else stripped


def _artifacts_with_unique_ids(artifacts: tuple[object, ...], *, home_dir: Path) -> tuple[object, ...]:
    """Give every artifact its own ID before items are built from them.

    A harness can read the same entry from more than one config file (Z Code's
    ``config.json`` and ``setting.json``), which yields two artifacts with one
    ID. Guard Cloud rejects a snapshot whose item IDs repeat, so the whole
    harness would otherwise fail to sync. A copy that differs only in its
    config path is the same entry and is dropped. A different entry that happens
    to share the ID (two hooks at the same index in different files) is kept
    under an ID suffixed with its config path's fingerprint. Every original ID
    is reserved first, so a generated ID never takes one a later artifact owns.
    """
    kept: list[object] = []
    entries_by_id: dict[str, list[object]] = {}
    used_ids = {str(getattr(artifact, "artifact_id", "")) for artifact in artifacts}
    for artifact in artifacts:
        artifact_id = str(getattr(artifact, "artifact_id", ""))
        entry = _artifact_without_config_path(artifact)
        entries = entries_by_id.setdefault(artifact_id, [])
        if not entries:
            entries.append(entry)
            kept.append(artifact)
            continue
        if entry in entries:
            continue
        entries.append(entry)
        config_path = str(getattr(artifact, "config_path", ""))
        suffix = fingerprint_text(redact_local_path(config_path, home_dir=home_dir))[:8]
        candidate = f"{artifact_id[: _ITEM_ID_MAX_LENGTH - len(suffix) - 1]}#{suffix}"
        counter = 2
        while candidate in used_ids:
            tail = f"{suffix}-{counter}"
            candidate = f"{artifact_id[: _ITEM_ID_MAX_LENGTH - len(tail) - 1]}#{tail}"
            counter += 1
        renamed = _artifact_with(artifact, artifact_id=candidate)
        if renamed is None:
            continue
        used_ids.add(candidate)
        kept.append(renamed)
    return tuple(kept)


@_native_url.redaction_pass()
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
    artifact_tuple = _artifacts_with_unique_ids(artifact_tuple, home_dir=home_dir)
    _prefetch_export_redactions(artifact_tuple, cisco_runs, home_dir=home_dir, workspace_dir=workspace_dir)
    source_evidence = native_inventory_source_evidence(
        [
            {
                "harness": harness,
                "artifact_type": str(getattr(artifact, "artifact_type", "unknown")),
                "config_path": getattr(artifact, "config_path", None),
            }
            for artifact in artifact_tuple
        ],
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        include_symlinks=include_symlinks,
        follow_unsafe_symlinks=follow_unsafe_symlinks,
    )
    classification_entries = [
        _artifact_classification_entry(
            harness,
            artifact,
            generated_at=generated_at,
            home_dir=home_dir,
            workspace_dir=workspace_dir,
            source_evidence=evidence,
            cisco_runs=cisco_runs,
        )
        for artifact, evidence in zip(artifact_tuple, source_evidence, strict=True)
    ]
    classifications = native_inventory_item_classification(classification_entries)
    items: list[GuardAgentInventoryItem] = []
    for artifact, entry, classification in zip(artifact_tuple, classification_entries, classifications, strict=True):
        item = _item_from_artifact(
            harness,
            artifact,
            home_dir=home_dir,
            workspace_dir=workspace_dir,
            entry=entry,
            classification=classification,
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
    scan_findings, scanner_sources = _scan_records(
        cisco_runs,
        harness=harness,
        items=item_tuple,
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        include_symlinks=include_symlinks,
    )
    sources = (*config_sources, *scanner_sources)
    snapshot_hash = _inventory_snapshot_content_hash(
        agent_type=harness,
        items=item_tuple,
        findings=scan_findings,
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
        findings=scan_findings,
        sources=sources,
        redaction_report={
            "rawSecretsIncluded": False,
            "redactedFields": ("headers", "env", "url", "paths", "ciscoFindingText"),
        },
    )
