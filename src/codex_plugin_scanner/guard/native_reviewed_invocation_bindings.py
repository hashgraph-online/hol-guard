"""Resident bridge for the ``reviewed_invocation_bindings_validate`` op.

Rust owns the command grammar. Python used to build its own matchers while an
extension was reviewed, so a reviewed literal vector could be bound to one
operation at review time and matched by another once the extension was
installed. This module ships the discovery an extension declares and reports
the first reviewed row the runtime's grammar refuses.

No matcher is built here, so an unavailable resident fails closed rather than
binding from a second grammar.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from uuid import uuid4

from .native_context import _canonical_request_sha256, _resolve_digest_home, ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_store_policy import _payload

REVIEWED_INVOCATION_BINDINGS_FEATURE = "reviewed-invocation-bindings-v1"
_OPERATION = "reviewed_invocation_bindings_validate"
_REQUEST_SCHEMA = "guard-reviewed-invocation-bindings-request.v1"
_RESULT_SCHEMA = "guard-reviewed-invocation-bindings-result.v1"
_TIMEOUT_SECONDS = 10.0
_MAX_REQUEST_BYTES = 6 * 1024 * 1024 - 64 * 1024
_MAX_OPERATIONS = 4096
_MAX_ROWS = 4096
UNAVAILABLE = "native_reviewed_invocation_unavailable"
TOO_LARGE = "native_reviewed_invocation_too_large"
_REFUSAL_PREFIX = "native_reviewed_invocation_"

#: ``(operation_id, path, flags, options_with_values)`` for one discovered operation.
ReviewedOperation = tuple[str, Sequence[str], Sequence[str], Sequence[str]]
#: ``(operation_id, argv)`` for one reviewed literal vector.
ReviewedRow = tuple[str, Sequence[str]]


class ReviewedInvocationBindingsUnavailableError(ValueError):
    """The rows were not bound; no matcher was built in Python."""

    def __init__(self, code: str = UNAVAILABLE) -> None:
        super().__init__(code)
        self.code = code

    @property
    def refused(self) -> bool:
        """Whether the request was refused, rather than the runtime being absent."""

        return self.code != UNAVAILABLE


def _decoded(payload: object) -> tuple[int, str] | None:
    """``(index, code)`` for the first refused row, or ``None``."""

    if not isinstance(payload, dict) or set(payload) != {"refused"}:
        raise ReviewedInvocationBindingsUnavailableError
    refused = payload["refused"]
    if refused is None:
        return None
    if (
        not isinstance(refused, dict)
        or set(refused) != {"index", "code"}
        or not isinstance(refused["index"], int)
        or isinstance(refused["index"], bool)
        or refused["index"] < 0
        or not isinstance(refused["code"], str)
        or not refused["code"]
    ):
        raise ReviewedInvocationBindingsUnavailableError
    return refused["index"], refused["code"]


def _raise_refusal(response: dict[str, object] | None, request: dict[str, object]) -> None:
    """Re-raise the resident's own refusal code when the reply carries one."""

    if response is None:
        return
    try:
        digest = "sha256:" + _canonical_request_sha256(request)
    except (TypeError, ValueError):
        return
    if response.get("request_id") != request["request_id"] or response.get("request_sha256") != digest:
        return
    code = response.get("code")
    if response.get("status") == "error" and isinstance(code, str) and code.startswith(_REFUSAL_PREFIX):
        raise ReviewedInvocationBindingsUnavailableError(code)


def native_reviewed_invocation_bindings(
    executable: str,
    operations: Sequence[ReviewedOperation],
    rows: Sequence[ReviewedRow],
    blocked_operation_ids: Sequence[str],
    *,
    guard_home: Path | None = None,
) -> tuple[int, str] | None:
    """Bind every reviewed row in the resident; raise when it cannot answer."""

    if len(operations) > _MAX_OPERATIONS or len(rows) > _MAX_ROWS:
        raise ReviewedInvocationBindingsUnavailableError(TOO_LARGE)
    wire: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"reviewed-invocation-bindings-{uuid4().hex}",
        "executable": executable,
        "operations": [
            {
                "operation_id": operation_id,
                "path": list(path),
                "flags": sorted(flags),
                "options_with_values": sorted(options_with_values),
            }
            for operation_id, path, flags, options_with_values in operations
        ],
        "rows": [{"operation_id": operation_id, "argv": list(argv)} for operation_id, argv in rows],
        "blocked_operation_ids": sorted(blocked_operation_ids),
    }
    try:
        encoded = len(json.dumps(wire).encode("utf-8"))
    except (TypeError, ValueError):
        raise ReviewedInvocationBindingsUnavailableError from None
    if encoded > _MAX_REQUEST_BYTES:
        raise ReviewedInvocationBindingsUnavailableError(TOO_LARGE)
    home = Path(_resolve_digest_home(guard_home))
    if not ensure_resident_prerequisite(home):
        raise ReviewedInvocationBindingsUnavailableError
    try:
        response = _resident_request(
            operation=_OPERATION,
            request=wire,
            guard_home=home,
            timeout_seconds=_TIMEOUT_SECONDS,
            required_feature=REVIEWED_INVOCATION_BINDINGS_FEATURE,
            response_schema=_RESULT_SCHEMA,
            max_request_bytes=_MAX_REQUEST_BYTES,
            record_success=False,
        )
    except (TypeError, ValueError, OSError, RuntimeError):
        raise ReviewedInvocationBindingsUnavailableError from None
    payload = _payload(response, wire, home)
    if payload is None:
        _raise_refusal(response, wire)
    return _decoded(payload)


__all__ = [
    "REVIEWED_INVOCATION_BINDINGS_FEATURE",
    "TOO_LARGE",
    "UNAVAILABLE",
    "ReviewedInvocationBindingsUnavailableError",
    "ReviewedOperation",
    "ReviewedRow",
    "native_reviewed_invocation_bindings",
]
