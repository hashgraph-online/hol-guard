"""Typed client for the native MCP runtime-evidence owner; no Python evaluator.

Rust owns the ``runtimeAction`` receipt record and the displayed command text
of an MCP tool call. Python ships artifact/argument DTOs, binds the answer to
the request by ``request_id`` and canonical ``request_sha256``, and renders it.
Any transport, scope, or binding failure raises ``NativeMcpRuntimeEvidenceError``
(never another exception type). Callers that record already-final verdicts
(``mcp_tool_call_evidence``) catch it and degrade to omitted evidence; nothing
here ever recomputes the evidence locally.
"""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
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


# Mirror of the argument keys the Rust evidence code reads (guard-contracts
# ``MCP_RUNTIME_EVIDENCE_*``); tests assert the two stay identical. Only these
# values are shipped so unrelated large arguments never reach the size limit.
_COMMAND_ARGUMENT_KEYS = (
    "command",
    "cmd",
    "shell_command",
    "shellCommand",
    "script",
    "expression",
    "code",
    "query",
)
_PATH_ARGUMENT_KEYS = (
    "path",
    "file_path",
    "filePath",
    "filepath",
    "directory",
    "dir",
    "cwd",
    "working_dir",
    "workingDir",
    "url",
    "uri",
)
_PATH_TOKENS = ("path", "file", "target", "source")
_COMMAND_TEXT_KEYS = frozenset((*_COMMAND_ARGUMENT_KEYS, *_PATH_ARGUMENT_KEYS))


def command_text_key(key: str) -> bool:
    """Whether ``command_text`` (and ``receipt_evidence``) can read this key."""
    return key in _COMMAND_TEXT_KEYS


def runtime_action_key(key: str) -> bool:
    """Whether the standalone ``runtime_action`` subop records this key as a path."""
    lowered = key.lower()
    return any(token in lowered for token in _PATH_TOKENS)


def argument_entries(
    arguments: object,
    *,
    mapping_type: type | tuple[type, ...],
    relevant: Callable[[str], bool] = command_text_key,
) -> list[list[Any]] | None:
    """Transport-only projection: ordered ``[key, value]`` for keys Rust reads.

    Values of keys the evidence code never reads are not shipped. ``None``
    still means "not a mapping".
    """
    if not isinstance(arguments, mapping_type) or not isinstance(arguments, Mapping):
        return None
    return [
        [name, value if isinstance(value, str) else None]
        for name, value in ((str(key), value) for key, value in arguments.items())
        if relevant(name)
    ]


def _request(subop: str, guard_home: Path | None, **fields: Any) -> dict[str, Any]:
    guard_home = _resolve_digest_home(guard_home)
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
    try:
        prerequisite = ensure_resident_prerequisite(guard_home)
    except Exception as error:
        raise NativeMcpRuntimeEvidenceError("native_mcp_runtime_evidence_prerequisite_unavailable") from error
    if not prerequisite:
        raise NativeMcpRuntimeEvidenceError("native_mcp_runtime_evidence_prerequisite_unavailable")
    try:
        request_sha256 = _canonical_request_sha256(request)
        # Rust bounds the ASCII-escaped canonical form, which can exceed the
        # UTF-8 envelope for non-ASCII text; reject on whichever is larger.
        canonical_size = len(
            json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
        )
        envelope = json.dumps(
            {"operation": "mcp_runtime_evidence", "deadline_budget_ms": 5_000, "request": request},
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise NativeMcpRuntimeEvidenceError("native_mcp_runtime_evidence_component_unencodable") from error
    if max(len(envelope), canonical_size) > _MAX_REQUEST_BYTES:
        raise NativeMcpRuntimeEvidenceError("native_mcp_runtime_evidence_request_too_large")
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
    guard_home: Path | None = None,
) -> dict[str, object] | None:
    result = _request(
        "runtime_action",
        guard_home,
        tool_description=tool_description,
        arguments=arguments,
        risk_categories=list(risk_categories),
        envelope=envelope,
    )
    record = result.get("runtime_action")
    if "runtime_action" not in result or not (record is None or isinstance(record, dict)):
        raise NativeMcpRuntimeEvidenceError(_INVALID_RESULT)
    return record


def native_command_text(
    artifact_name: str, arguments: list[list[Any]] | None, *, guard_home: Path | None = None
) -> str | None:
    result = _request("command_text", guard_home, artifact_name=artifact_name, arguments=arguments)
    text = result.get("command_text")
    if "command_text" not in result or not (text is None or isinstance(text, str)):
        raise NativeMcpRuntimeEvidenceError(_INVALID_RESULT)
    return text


def native_receipt_evidence(
    *,
    artifact_name: str,
    tool_description: str | None,
    arguments: list[list[Any]] | None,
    risk_categories: Sequence[str],
    guard_home: Path | None,
) -> tuple[str | None, dict[str, object] | None]:
    """One resident round trip: ``(command_text, runtime_action)`` for a receipt."""
    result = _request(
        "receipt_evidence",
        guard_home,
        artifact_name=artifact_name,
        tool_description=tool_description,
        arguments=arguments,
        risk_categories=list(risk_categories),
    )
    text = result.get("command_text")
    record = result.get("runtime_action")
    if (
        "command_text" not in result
        or "runtime_action" not in result
        or not (text is None or isinstance(text, str))
        or not (record is None or isinstance(record, dict))
    ):
        raise NativeMcpRuntimeEvidenceError(_INVALID_RESULT)
    return text, record
