"""MCP capability classification and tool attestation metadata."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from pathlib import Path

from ..version import __version__
from .inventory_contract_constants import (
    _MCP_DELETE_RE,
    _MCP_MODEL_RE,
    _MCP_NETWORK_RE,
    _MCP_PERMISSION_RE,
    _MCP_READ_RE,
    _MCP_SECRET_RE,
    _MCP_SHELL_RE,
    _MCP_WRITE_RE,
)
from .inventory_contract_models import InventoryCapability, InventorySeverity


def _apply_tool_trust_attestation_metadata(
    metadata: dict[str, object],
    *,
    harness: str,
    item_id: str,
    content_hash: str,
    config_path_hash: str,
    repository_id: str,
    trust_attestation_context: Mapping[str, object] | None,
) -> dict[str, object]:
    """Attach tool-level trust metadata only when compatible attestation evidence exists."""
    from .runtime.trust_attestation import (
        GuardTrustAttestationSigningConfig,
        apply_trust_attestation_metadata,
    )

    if not isinstance(trust_attestation_context, Mapping):
        return apply_trust_attestation_metadata(
            metadata,
            agent_id=f"{harness}:local",
            item_id=item_id,
            item_kind="mcp_tool",
            content_hash=content_hash,
            adapter_id=harness,
            adapter_version=__version__,
            config_path_hash=config_path_hash,
            repository_id=repository_id,
        )

    raw_signing_config = trust_attestation_context.get("signingConfig")
    signing_config = raw_signing_config if isinstance(raw_signing_config, GuardTrustAttestationSigningConfig) else None
    raw_sequence = trust_attestation_context.get("sequence")
    sequence = raw_sequence if isinstance(raw_sequence, int) else None

    return apply_trust_attestation_metadata(
        metadata,
        agent_id=f"{harness}:local",
        analyzer_id=_optional_context_string(trust_attestation_context, "analyzerId"),
        analyzer_spec_version=_optional_context_string(trust_attestation_context, "analyzerSpecVersion"),
        analyzer_version=_optional_context_string(trust_attestation_context, "analyzerVersion"),
        item_id=item_id,
        item_kind="mcp_tool",
        content_hash=content_hash,
        challenge_id=_optional_context_string(trust_attestation_context, "challengeId"),
        expires_at=_optional_context_string(trust_attestation_context, "expiresAt"),
        installation_id=_optional_context_string(trust_attestation_context, "installationId"),
        nonce=_optional_context_string(trust_attestation_context, "nonce"),
        policy_version=_optional_context_string(trust_attestation_context, "policyVersion"),
        sequence=sequence,
        upload_id=_optional_context_string(trust_attestation_context, "uploadId"),
        workspace_id=_optional_context_string(trust_attestation_context, "workspaceId"),
        device_id=_optional_context_string(trust_attestation_context, "deviceId"),
        adapter_id=harness,
        adapter_version=__version__,
        config_path_hash=config_path_hash,
        repository_id=repository_id,
        signing_config=signing_config,
    )


def _attestation_path_hash(value: object, *, fallback: str) -> str:
    """Hash an attestation path without exporting the private absolute path."""
    raw = value if isinstance(value, str) and value else f"artifact:{fallback}"
    try:
        normalized = str(Path(raw).expanduser().resolve(strict=False))
    except (OSError, RuntimeError, ValueError):
        normalized = raw
    return f"sha256:{hashlib.sha256(normalized.encode('utf-8')).hexdigest()}"


def _attestation_repository_id(*, home_dir: Path, workspace_dir: Path | None) -> str:
    """Resolve repository identity from the available artifact metadata."""
    root = workspace_dir if workspace_dir is not None else home_dir
    try:
        normalized = str(root.expanduser().resolve(strict=False))
    except (OSError, RuntimeError, ValueError):
        normalized = str(root)
    return f"sha256:{hashlib.sha256(normalized.encode('utf-8')).hexdigest()}"


def _optional_context_string(context: Mapping[str, object], key: str) -> str | None:
    """Read a nonempty optional string from an untrusted metadata context."""
    value = context.get(key)
    return value if isinstance(value, str) and value else None


def _string_value(value: object) -> str | None:
    """Normalize an optional metadata value to a safe string."""
    return value if isinstance(value, str) else None


def _first_present_value(mapping: dict[str, object], *keys: str) -> object | None:
    """Select the first available metadata value in precedence order."""
    for key in keys:
        if key in mapping:
            return mapping[key]
    return None


def _mcp_tool_definitions(metadata: dict[str, object]) -> tuple[dict[str, object], ...]:
    """Read supported MCP definition shapes without treating arbitrary metadata as tools."""
    tools: list[dict[str, object]] = []
    seen_names: set[str] = set()
    for key in ("tools", "tool_schemas", "toolSchemas"):
        raw_tools = metadata.get(key)
        if not isinstance(raw_tools, list):
            continue
        for raw_tool in raw_tools:
            if not isinstance(raw_tool, dict):
                continue
            name = raw_tool.get("name")
            if not isinstance(name, str) or not name.strip() or name in seen_names:
                continue
            tools.append(raw_tool)
            seen_names.add(name)
    return tuple(tools)


def _mcp_schema_signal_text(value: object) -> str:
    """Extract textual signals from a tool schema for capability classification."""
    if isinstance(value, dict):
        parts: list[str] = []
        for key, item in value.items():
            if key in {"$schema", "$id"}:
                continue
            parts.append(key)
            parts.append(_mcp_schema_signal_text(item))
        return " ".join(part for part in parts if part)
    if isinstance(value, list):
        return " ".join(_mcp_schema_signal_text(item) for item in value)
    if isinstance(value, str):
        return value
    return ""


def _capabilities_for_mcp_tool(
    name: str,
    description: str,
    input_schema: object,
    annotations: dict[str, object],
) -> tuple[InventoryCapability, ...]:
    """Classify tool capabilities from its advertised name, description, and schema."""
    text = f"{name} {description} {_mcp_schema_signal_text(input_schema)}".lower()
    capabilities: set[InventoryCapability] = set()
    if annotations.get("readOnlyHint") is True or _MCP_READ_RE.search(text):
        capabilities.add("reads_files")
    if annotations.get("destructiveHint") is True or _MCP_DELETE_RE.search(text):
        capabilities.update({"writes_files", "deletes_files"})
    if annotations.get("writeHint") is True or _MCP_WRITE_RE.search(text):
        capabilities.add("writes_files")
    if _MCP_SHELL_RE.search(text):
        capabilities.add("runs_shell")
    if _MCP_SECRET_RE.search(text):
        capabilities.add("reads_secrets")
    if _MCP_NETWORK_RE.search(text):
        capabilities.add("network_egress")
    if _MCP_MODEL_RE.search(text):
        capabilities.add("uses_model_sampling")
    if _MCP_PERMISSION_RE.search(text):
        capabilities.add("changes_permissions")
    return tuple(sorted(capabilities)) if capabilities else ("unknown",)


def _risk_level_for_capabilities(capabilities: tuple[InventoryCapability, ...]) -> InventorySeverity:
    """Derive the inventory risk category from the classified capabilities."""
    if any(capability in capabilities for capability in ("deletes_files", "reads_secrets", "runs_shell")):
        return "high"
    if any(
        capability in capabilities
        for capability in ("writes_files", "network_egress", "uses_model_sampling", "changes_permissions")
    ):
        return "medium"
    return "info"
