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

ExchangeOutcome = Literal["boundary", "response", "event", "timeout", "eof"]
_OUTCOMES = frozenset({"boundary", "response", "event", "timeout", "eof"})


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
    reply = _resident_request(
        operation="mcp_stdio_session_send",
        request=request,
        guard_home=guard_home,
        timeout_seconds=quiet_seconds + response_timeout_seconds + 2.0,
        required_feature=_MCP_STDIO_SESSION_FEATURE,
        response_schema=_MCP_STDIO_SESSION_RESULT_SCHEMA,
    )
    if reply is None or reply.get("status") != "sent":
        return None
    payload = reply.get("payload")
    if not isinstance(payload, dict) or payload.get("outcome") not in _OUTCOMES:
        return None
    return cast("dict[str, object]", payload)
