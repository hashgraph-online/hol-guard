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

import uuid
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from .native_context import (
    _native_runtime_status_memo,
    _resolve_digest_home,
)
from .native_resident_decision import BoundCall, bound_resident_call

_FEATURE = "mcp-runtime-evidence-v1"
_REQUEST_SCHEMA = "guard-mcp-runtime-evidence-request.v1"
_RESULT_SCHEMA = "guard-mcp-runtime-evidence-result.v1"
_MAX_REQUEST_BYTES = 256 * 1024
_TIMEOUT_SECONDS = 5.0
_INVALID_RESULT = "native_mcp_runtime_evidence_result_invalid"


class NativeMcpRuntimeEvidenceError(ValueError):
    """The native owner could not supply bound, typed MCP runtime evidence."""


_CALL = BoundCall(
    operation="mcp_runtime_evidence",
    feature=_FEATURE,
    prefix="native_mcp_runtime_evidence",
    result_schema=_RESULT_SCHEMA,
    max_request_bytes=_MAX_REQUEST_BYTES,
    timeout_seconds=_TIMEOUT_SECONDS,
    error=NativeMcpRuntimeEvidenceError,
    sha_prefix="",
    bound_canonical=True,
    clock_after_prerequisite=True,
)


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
    reply = bound_resident_call(_CALL, request, guard_home=guard_home, status=_native_runtime_status_memo())
    return reply.payload()


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
