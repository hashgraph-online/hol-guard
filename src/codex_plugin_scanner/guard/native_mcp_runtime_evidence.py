"""Typed client for the native MCP runtime-evidence owner; no Python evaluator.

Rust owns the ``runtimeAction`` receipt record and the displayed command text
of an MCP tool call. Python ships artifact/argument DTOs, binds the answer to
the request by ``request_id`` and canonical ``request_sha256``, and renders it.
Any transport, scope, or binding failure raises: evidence is an authority, so
an unavailable resident must never degrade to empty or locally derived evidence.
"""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import Mapping, Sequence
from typing import Any

from .native_context import (
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

_FEATURE = "mcp-runtime-evidence-v1"
_RESIDENT_PROTOCOL_FEATURE = "resident-protocol-v2"
_REQUEST_SCHEMA = "guard-mcp-runtime-evidence-request.v1"
_RESULT_SCHEMA = "guard-mcp-runtime-evidence-result.v1"
_MAX_REQUEST_BYTES = 256 * 1024
_TIMEOUT_SECONDS = 5.0
_INVALID_RESULT = "native_mcp_runtime_evidence_result_invalid"


class NativeMcpRuntimeEvidenceError(ValueError):
    """The native owner could not supply bound, typed MCP runtime evidence."""


def argument_entries(arguments: object, *, mapping_type: type | tuple[type, ...]) -> list[list[Any]] | None:
    """Transport-only projection: ordered ``[str(key), value-if-str-else-None]``."""
    if not isinstance(arguments, mapping_type) or not isinstance(arguments, Mapping):
        return None
    return [[str(key), value if isinstance(value, str) else None] for key, value in arguments.items()]


def _request(subop: str, **fields: Any) -> dict[str, Any]:
    guard_home = _resolve_digest_home(None)
    request: dict[str, Any] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": uuid.uuid4().hex,
        "subop": subop,
        "guard_home": str(guard_home),
        "artifact_name": "",
        "tool_description": None,
        "arguments": None,
        "risk_categories": [],
        "envelope": None,
        **fields,
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
        raise NativeMcpRuntimeEvidenceError("native_mcp_runtime_evidence_unavailable")
    if not ensure_resident_prerequisite(guard_home):
        raise NativeMcpRuntimeEvidenceError("native_mcp_runtime_evidence_prerequisite_unavailable")
    try:
        request_sha256 = _canonical_request_sha256(request)
        envelope = json.dumps(
            {"operation": "mcp_runtime_evidence", "deadline_budget_ms": 5_000, "request": request},
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise NativeMcpRuntimeEvidenceError("native_mcp_runtime_evidence_component_unencodable") from error
    if len(envelope) > _MAX_REQUEST_BYTES:
        raise NativeMcpRuntimeEvidenceError("native_mcp_runtime_evidence_request_too_large")
    output = native_resident_client_request(
        executable=status.identity.path,
        guard_home=guard_home,
        environment=_isolated_environment(),
        payload=envelope,
        deadline_monotonic=time.monotonic() + _TIMEOUT_SECONDS,
    )
    if output is None:
        native_record_resident_failure(
            status.identity.sha256, guard_home, reason="native_mcp_runtime_evidence_resident_unavailable"
        )
        raise NativeMcpRuntimeEvidenceError("native_mcp_runtime_evidence_resident_unavailable")
    try:
        payload = json.loads(output)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        native_record_resident_failure(status.identity.sha256, guard_home, reason=_INVALID_RESULT)
        raise NativeMcpRuntimeEvidenceError(_INVALID_RESULT) from error
    error_code = _native_error(payload)
    if error_code is not None:
        if error_code == "native_overloaded":
            native_record_overload(status.identity.sha256, guard_home)
        else:
            native_record_resident_failure(status.identity.sha256, guard_home, reason=error_code)
        raise NativeMcpRuntimeEvidenceError(error_code)
    if (
        not isinstance(payload, dict)
        or payload.get("schema") != _RESULT_SCHEMA
        or payload.get("request_id") != request["request_id"]
        or payload.get("request_sha256") != request_sha256
        or payload.get("status") != "ok"
        or payload.get("code") != "ok"
        or not isinstance(payload.get("payload"), dict)
    ):
        native_record_resident_failure(status.identity.sha256, guard_home, reason=_INVALID_RESULT)
        code = payload.get("code") if isinstance(payload, dict) else None
        raise NativeMcpRuntimeEvidenceError(
            code if isinstance(code, str) and code.startswith("native_mcp_runtime_evidence_") else _INVALID_RESULT
        )
    native_record_resident_success(status.identity.sha256, guard_home)
    return payload["payload"]


def native_runtime_action_record(
    *,
    tool_description: str | None,
    arguments: list[list[Any]] | None,
    risk_categories: Sequence[str],
    envelope: dict[str, object] | None,
) -> dict[str, object] | None:
    result = _request(
        "runtime_action",
        tool_description=tool_description,
        arguments=arguments,
        risk_categories=list(risk_categories),
        envelope=envelope,
    )
    record = result.get("runtime_action")
    if "runtime_action" not in result or not (record is None or isinstance(record, dict)):
        raise NativeMcpRuntimeEvidenceError(_INVALID_RESULT)
    return record


def native_command_text(artifact_name: str, arguments: list[list[Any]] | None) -> str | None:
    result = _request("command_text", artifact_name=artifact_name, arguments=arguments)
    text = result.get("command_text")
    if "command_text" not in result or not (text is None or isinstance(text, str)):
        raise NativeMcpRuntimeEvidenceError(_INVALID_RESULT)
    return text
