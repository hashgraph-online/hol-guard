"""Typed client for the native MCP tool-evidence owner; no Python evaluator.

Rust owns the portal firewall evidence for ``mcp_server``, ``tool_call``
and ``skill`` artifacts. Python ships the DTO -- for a skill, the document
text it read, since the resident does no IO -- binds the answer by
``request_id`` and canonical ``request_sha256``, and renders it. Any
transport, scope, or binding failure raises ``NativeMcpToolEvidenceError``
(never another exception type); nothing here ever recomputes a fingerprint
locally, and a failure is never an empty result.

``risk_input`` builds the risk DTO the MCP proxy sends with its
``call_projection`` check, which renders the risk signals and summary.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from .models import GuardArtifact
from .native_context import (
    _native_runtime_status_memo,
    _resolve_digest_home,
)
from .native_resident_decision import BoundCall, bound_resident_call
from .runtime.json_safe_copy import json_safe_copy

_FEATURE = "mcp-tool-evidence-v1"
_REQUEST_SCHEMA = "guard-mcp-tool-evidence-request.v1"
_RESULT_SCHEMA = "guard-mcp-tool-evidence-result.v1"
_MAX_REQUEST_BYTES = 2 * 1024 * 1024
_TIMEOUT_SECONDS = 5.0
_INVALID_RESULT = "native_mcp_tool_evidence_result_invalid"
_FIREWALL_ARTIFACT_TYPES = frozenset({"mcp_server", "tool_call"})
_EMPTY_FIREWALL_INPUT: dict[str, object] = {
    "command": None,
    "transport": None,
    "has_url": False,
    "args": [],
    "server_name": None,
    "env": [],
    "mcp_server_identity": None,
    "mcp_tool_identity": None,
    "tool_schema": None,
    "tool_description": None,
    "tool_names": None,
    "tool_names_camel": None,
    "skill_content": None,
}


class NativeMcpToolEvidenceError(ValueError):
    """The native owner could not supply bound, typed MCP tool evidence."""


_CALL = BoundCall(
    operation="mcp_tool_evidence",
    feature=_FEATURE,
    prefix="native_mcp_tool_evidence",
    result_schema=_RESULT_SCHEMA,
    max_request_bytes=_MAX_REQUEST_BYTES,
    timeout_seconds=_TIMEOUT_SECONDS,
    error=NativeMcpToolEvidenceError,
    sha_prefix="",
    bound_canonical=True,
    clock_after_prerequisite=True,
)


def _arguments_dto(arguments: object) -> dict[str, object]:
    if isinstance(arguments, Mapping):
        return {"format": "mapping", "entries": json_safe_copy([(str(key), value) for key, value in arguments.items()])}
    if isinstance(arguments, str):
        return {"format": "json", "text": arguments}
    return {"format": "other", "value": json_safe_copy(arguments)}


def risk_input(
    artifact: GuardArtifact,
    arguments: object,
    *,
    risk_categories: tuple[str, ...] | None = None,
    summary_code: str | None = None,
) -> dict[str, object]:
    """Transport-only risk DTO for the proxy's ``call_projection`` check."""
    return {
        "artifact": json_safe_copy(
            {"name": artifact.name, "command": artifact.command, "metadata": dict(artifact.metadata)}
        ),
        "arguments": _arguments_dto(arguments),
        "risk_categories": None if risk_categories is None else list(risk_categories),
        "summary_code": summary_code,
    }


def _string_pairs(value: object) -> list[list[str]]:
    if not isinstance(value, dict):
        return []
    return [[key, item] for key, item in value.items() if isinstance(key, str) and isinstance(item, str)]


def _record(value: object) -> dict[str, object] | None:
    return json_safe_copy(value) if isinstance(value, dict) else None


def firewall_input(artifact: GuardArtifact) -> dict[str, object]:
    """Transport-only DTO for the ``firewall`` subop (only the fields Rust reads)."""
    metadata = artifact.metadata
    server_name = metadata.get("server_name")
    if "server_name" in metadata and not isinstance(server_name, str):
        raise NativeMcpToolEvidenceError("native_mcp_tool_evidence_server_name_unsupported")
    return {
        "artifact_type": artifact.artifact_type,
        "name": artifact.name,
        "command": artifact.command,
        "config_path": artifact.config_path,
        "transport": artifact.transport,
        "has_url": bool(artifact.url),
        "args": list(artifact.args),
        "publisher": artifact.publisher,
        "server_name": server_name if isinstance(server_name, str) else None,
        "env": _string_pairs(metadata.get("env")),
        "mcp_server_identity": _record(metadata.get("mcp_server_identity")),
        "mcp_tool_identity": _record(metadata.get("mcp_tool_identity")),
        "tool_schema": json_safe_copy(metadata.get("tool_schema")),
        "tool_description": json_safe_copy(metadata.get("tool_description")),
        "tool_names": json_safe_copy(metadata.get("tool_names")),
        "tool_names_camel": json_safe_copy(metadata.get("toolNames")),
        "skill_content": None,
    }


def skill_firewall_input(
    *,
    name: str,
    config_path: str,
    publisher: str | None,
    skill_content: str | None,
) -> dict[str, object]:
    """Transport-only DTO for a ``skill`` document's firewall projection.

    The resident derives the identity from ``skill_content``; Python reads the
    document because the op does no IO. ``None`` content means the document
    could not be read and projects to no firewall.
    """
    return {
        **_EMPTY_FIREWALL_INPUT,
        "artifact_type": "skill",
        "name": name,
        "config_path": config_path,
        "publisher": publisher,
        "skill_content": skill_content,
    }


def native_mcp_tool_evidence_request(
    subop: str,
    payload: dict[str, object],
    guard_home: Path | None = None,
    *,
    validate: Callable[[dict[str, Any]], Any] | None = None,
) -> Any:
    """One bound resident round trip; returns the verified ``payload`` object.

    ``validate`` checks the operation-specific payload before the resident is
    recorded healthy, so a reply that parses but is malformed counts as a
    resident failure instead of resetting the failure circuit.
    """
    guard_home = _resolve_digest_home(guard_home)
    request: dict[str, Any] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": uuid.uuid4().hex,
        "subop": subop,
        "guard_home": str(guard_home),
        "firewall": payload if subop == "firewall" else None,
    }
    reply = bound_resident_call(_CALL, request, guard_home=guard_home, status=_native_runtime_status_memo())
    return reply.payload(validate=validate)


def _validated_firewall_payload(payload: dict[str, Any]) -> dict[str, object] | None:
    patch = payload.get("metadata_patch")
    if "metadata_patch" not in payload or not (patch is None or isinstance(patch, dict)):
        raise NativeMcpToolEvidenceError(_INVALID_RESULT)
    return patch


def native_firewall_metadata_patch(artifact: GuardArtifact) -> dict[str, object] | None:
    """Return the native metadata patch for a firewall artifact, or ``None`` for no firewall."""
    if artifact.artifact_type not in _FIREWALL_ARTIFACT_TYPES:
        raise NativeMcpToolEvidenceError("native_mcp_tool_evidence_unsupported_artifact_type")
    return native_mcp_tool_evidence_request("firewall", firewall_input(artifact), validate=_validated_firewall_payload)


def native_skill_firewall_metadata_patch(
    *,
    name: str,
    config_path: str,
    publisher: str | None = None,
    skill_content: str | None,
    guard_home: Path | None = None,
) -> dict[str, object] | None:
    """Native metadata patch for a skill document, or ``None`` for no firewall."""
    return native_mcp_tool_evidence_request(
        "firewall",
        skill_firewall_input(name=name, config_path=config_path, publisher=publisher, skill_content=skill_content),
        guard_home,
        validate=_validated_firewall_payload,
    )
