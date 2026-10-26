"""Fused MCP stdio exchange: quiet edge, write and correlated response in one resident round trip."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Literal, cast

from .native_execution import (
    _MCP_STDIO_SESSION_FEATURE,
    _MCP_STDIO_SESSION_IO_SCHEMA,
    _MCP_STDIO_SESSION_RESULT_SCHEMA,
    _resident_request,
)
from .native_runtime import native_runtime_status
from .native_runtime_resilience import native_record_resident_failure, native_record_resident_success

ExchangeOutcome = Literal["boundary", "response", "event", "timeout", "eof"]
_OUTCOMES = frozenset({"boundary", "response", "event", "timeout", "eof"})
# Resident-side bounds the transport deadline must cover beyond the quiet and response windows:
# an unfinished child frame may extend the quiet edge, and the write itself may block on child stdin.
_QUIET_EXTENSION_SECONDS = 1.0
_WRITE_WINDOW_SECONDS = 5.0
_TRANSPORT_MARGIN_SECONDS = 2.0


def mcp_stdio_session_exchange_native(
    session_id: str,
    message: Mapping[str, object],
    *,
    guard_home: Path,
    quiet_seconds: float,
    response_timeout_seconds: float,
) -> dict[str, object] | None:
    """Wait for a quiet edge, write ``message`` and return the first thing the child says back.

    The resident reports ``status: "sent"`` with an ``outcome``:

    * ``boundary``: a frame arrived during the quiet edge, nothing was written;
    * ``response``: the response correlated to ``message["id"]``;
    * ``event``: another frame arrived first (child request or notification);
    * ``timeout`` or ``eof``: the message was written but no response came.

    ``None`` means the resident gave no usable answer, so the caller cannot
    know whether the message was written and must fail the call.
    """

    request: dict[str, object] = {
        "schema": _MCP_STDIO_SESSION_IO_SCHEMA,
        "session_id": session_id,
        "message": dict(message),
        "exchange": {
            "quiet_ms": int(quiet_seconds * 1000),
            "response_timeout_ms": int(response_timeout_seconds * 1000),
        },
    }
    status = native_runtime_status()
    reply = _resident_request(
        operation="mcp_stdio_session_send",
        request=request,
        guard_home=guard_home,
        timeout_seconds=(
            quiet_seconds
            + _QUIET_EXTENSION_SECONDS
            + _WRITE_WINDOW_SECONDS
            + response_timeout_seconds
            + _TRANSPORT_MARGIN_SECONDS
        ),
        required_feature=_MCP_STDIO_SESSION_FEATURE,
        response_schema=_MCP_STDIO_SESSION_RESULT_SCHEMA,
        record_success=False,
        status=status,
    )
    if reply is None:
        return None
    # ``_resident_request`` already recorded its own failures; a reply that is well formed but
    # unusable here is recorded below so it cannot reset the failure streak.
    identity = status.identity
    payload = reply.get("payload")
    if reply.get("status") == "error":
        if identity is not None:
            native_record_resident_success(identity.sha256, guard_home)
        return None
    if reply.get("status") != "sent" or not isinstance(payload, dict) or payload.get("outcome") not in _OUTCOMES:
        if identity is not None:
            native_record_resident_failure(identity.sha256, guard_home, reason="native_mcp_stdio_exchange_unusable")
        return None
    if identity is not None:
        native_record_resident_success(identity.sha256, guard_home)
    return cast("dict[str, object]", payload)
