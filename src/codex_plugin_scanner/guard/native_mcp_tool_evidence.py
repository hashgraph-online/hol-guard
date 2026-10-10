"""Typed client for the native MCP tool-evidence owner; no Python evaluator.

Rust owns two projections of an MCP tool call: the risk signals and summary
text (including browser scope, argument, schema, and target-redaction checks),
and the portal firewall evidence for ``mcp_server`` and ``tool_call``
artifacts. Python ships artifact/argument DTOs, binds the answer to the
request by ``request_id`` and canonical ``request_sha256``, and renders it.
Any transport, scope, or binding failure raises ``NativeMcpToolEvidenceError``
(never another exception type); nothing here ever recomputes a signal,
summary, or fingerprint locally, and a failure is never an empty result.
"""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from .models import GuardArtifact
from .native_context import (
    _MCP_RISK_CATEGORIES,
    _canonical_request_sha256,
    _native_error,
    _native_runtime_status_memo,
    _resolve_digest_home,
    ensure_resident_prerequisite,
)
from .native_resident_client import native_resident_client_request
from .native_runtime import _isolated_environment
from .native_runtime_resilience import (
    native_record_overload,
    native_record_resident_failure,
    native_record_resident_success,
)

_FEATURE = "mcp-tool-evidence-v1"
_RESIDENT_PROTOCOL_FEATURE = "resident-protocol-v2"
_REQUEST_SCHEMA = "guard-mcp-tool-evidence-request.v1"
_RESULT_SCHEMA = "guard-mcp-tool-evidence-result.v1"
_MAX_REQUEST_BYTES = 2 * 1024 * 1024
_TIMEOUT_SECONDS = 5.0
_INVALID_RESULT = "native_mcp_tool_evidence_result_invalid"
_FIREWALL_ARTIFACT_TYPES = frozenset({"mcp_server", "tool_call"})


class NativeMcpToolEvidenceError(ValueError):
    """The native owner could not supply bound, typed MCP tool evidence."""


def _json_value(value: object) -> Any:
    """JSON-safe copy of a value; ``default=str`` mirrors every other DTO."""
    return json.loads(json.dumps(value, default=str))


def _arguments_dto(arguments: object) -> dict[str, object]:
    if isinstance(arguments, Mapping):
        return {"format": "mapping", "entries": _json_value([(str(key), value) for key, value in arguments.items()])}
    if isinstance(arguments, str):
        return {"format": "json", "text": arguments}
    return {"format": "other", "value": _json_value(arguments)}


def risk_input(
    artifact: GuardArtifact,
    arguments: object,
    *,
    risk_categories: tuple[str, ...] | None = None,
    summary_code: str | None = None,
) -> dict[str, object]:
    """Transport-only DTO for the ``risk`` subop."""
    return {
        "artifact": _json_value(
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
    return _json_value(value) if isinstance(value, dict) else None


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
        "tool_schema": _json_value(metadata.get("tool_schema")),
        "tool_description": _json_value(metadata.get("tool_description")),
        "tool_names": _json_value(metadata.get("tool_names")),
        "tool_names_camel": _json_value(metadata.get("toolNames")),
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
        "risk": payload if subop == "risk" else None,
        "firewall": payload if subop == "firewall" else None,
    }
    status = _native_runtime_status_memo()
    if (
        status.mode == "off"
        or not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or _FEATURE not in status.capabilities.features
        or _RESIDENT_PROTOCOL_FEATURE not in status.capabilities.features
    ):
        raise NativeMcpToolEvidenceError("native_mcp_tool_evidence_unavailable")
    try:
        prerequisite = ensure_resident_prerequisite(guard_home)
    except Exception as error:
        raise NativeMcpToolEvidenceError("native_mcp_tool_evidence_prerequisite_unavailable") from error
    if not prerequisite:
        raise NativeMcpToolEvidenceError("native_mcp_tool_evidence_prerequisite_unavailable")
    try:
        request_sha256 = _canonical_request_sha256(request)
        # Rust bounds the ASCII-escaped canonical form, which can exceed the
        # UTF-8 envelope for non-ASCII text; reject on whichever is larger.
        canonical_size = len(
            json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
        )
        envelope = json.dumps(
            {"operation": "mcp_tool_evidence", "deadline_budget_ms": 5_000, "request": request},
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise NativeMcpToolEvidenceError("native_mcp_tool_evidence_component_unencodable") from error
    if max(len(envelope), canonical_size) > _MAX_REQUEST_BYTES:
        raise NativeMcpToolEvidenceError("native_mcp_tool_evidence_request_too_large")
    try:
        output = native_resident_client_request(
            executable=status.identity.path,
            guard_home=guard_home,
            environment=_isolated_environment(),
            payload=envelope,
            deadline_monotonic=time.monotonic() + _TIMEOUT_SECONDS,
        )
    except Exception:
        # RuntimeError (thread start), OSError, timeouts: all one typed failure.
        output = None
    if output is None:
        native_record_resident_failure(
            status.identity.sha256, guard_home, reason="native_mcp_tool_evidence_resident_unavailable"
        )
        raise NativeMcpToolEvidenceError("native_mcp_tool_evidence_resident_unavailable")
    try:
        result = json.loads(output)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        native_record_resident_failure(status.identity.sha256, guard_home, reason=_INVALID_RESULT)
        raise NativeMcpToolEvidenceError(_INVALID_RESULT) from error
    error_code = _native_error(result)
    if error_code is not None:
        if error_code == "native_overloaded":
            native_record_overload(status.identity.sha256, guard_home)
        else:
            native_record_resident_failure(status.identity.sha256, guard_home, reason=error_code)
        raise NativeMcpToolEvidenceError(error_code)
    if (
        not isinstance(result, dict)
        or result.get("schema") != _RESULT_SCHEMA
        or result.get("request_id") != request["request_id"]
        or result.get("request_sha256") != request_sha256
        or result.get("status") != "ok"
        or result.get("code") != "ok"
        or not isinstance(result.get("payload"), dict)
    ):
        native_record_resident_failure(status.identity.sha256, guard_home, reason=_INVALID_RESULT)
        code = result.get("code") if isinstance(result, dict) else None
        raise NativeMcpToolEvidenceError(
            code if isinstance(code, str) and code.startswith("native_mcp_tool_evidence_") else _INVALID_RESULT
        )
    verified: Any = result["payload"]
    if validate is not None:
        try:
            verified = validate(verified)
        except NativeMcpToolEvidenceError:
            native_record_resident_failure(status.identity.sha256, guard_home, reason=_INVALID_RESULT)
            raise
    native_record_resident_success(status.identity.sha256, guard_home)
    return verified


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise NativeMcpToolEvidenceError(_INVALID_RESULT)
    return value


def _validated_risk_payload(payload: dict[str, Any]) -> tuple[tuple[str, ...], tuple[str, ...], str]:
    categories = _string_list(payload.get("risk_categories"))
    signals = _string_list(payload.get("signals"))
    summary = payload.get("summary")
    if (
        not isinstance(summary, str)
        or len(signals) != len(categories)
        or any(category not in _MCP_RISK_CATEGORIES for category in categories)
    ):
        raise NativeMcpToolEvidenceError(_INVALID_RESULT)
    return tuple(categories), tuple(signals), summary


def _validated_firewall_payload(payload: dict[str, Any]) -> dict[str, object] | None:
    patch = payload.get("metadata_patch")
    if "metadata_patch" not in payload or not (patch is None or isinstance(patch, dict)):
        raise NativeMcpToolEvidenceError(_INVALID_RESULT)
    return patch


def native_tool_risk_evidence(
    artifact: GuardArtifact,
    arguments: object,
    *,
    risk_categories: tuple[str, ...] | None = None,
    summary_code: str | None = None,
) -> tuple[tuple[str, ...], tuple[str, ...], str]:
    """Return native ``(risk_categories, signals, summary)`` for one tool call."""
    return native_mcp_tool_evidence_request(
        "risk",
        risk_input(artifact, arguments, risk_categories=risk_categories, summary_code=summary_code),
        validate=_validated_risk_payload,
    )


def native_firewall_metadata_patch(artifact: GuardArtifact) -> dict[str, object] | None:
    """Return the native metadata patch for a firewall artifact, or ``None`` for no firewall."""
    if artifact.artifact_type not in _FIREWALL_ARTIFACT_TYPES:
        raise NativeMcpToolEvidenceError("native_mcp_tool_evidence_unsupported_artifact_type")
    return native_mcp_tool_evidence_request("firewall", firewall_input(artifact), validate=_validated_firewall_payload)
