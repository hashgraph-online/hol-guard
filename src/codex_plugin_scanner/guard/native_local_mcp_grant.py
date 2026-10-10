"""Local MCP grant decision from the native runtime.

The resident reads ``guard.db`` and decides whether a live MCP ``tools/call``
is covered by a this-device grant. Python sends the server identity material
recorded in artifact metadata, the tool name, and the live authority digests,
and presents the answer. A missing, malformed, or unbound reply is a
``NativeLocalMcpGrantFailure`` carrying a reason code, which callers must treat
as "no authoritative answer", never as an allow.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from uuid import uuid4

from .native_context import _canonical_request_sha256, ensure_resident_prerequisite
from .native_execution import _resident_request

LOCAL_MCP_GRANT_FEATURE = "local-mcp-grant-v1"
_REQUEST_SCHEMA = "guard-local-mcp-grant-request.v1"
_RESULT_SCHEMA = "guard-local-mcp-grant-result.v1"
_STATES: dict[str, NativeMcpGrantState] = {
    "allowed": "allowed",
    "blocked": "blocked",
    "review": "review",
    "none": "none",
}
_PAYLOAD_KEYS = frozenset({"state", "cli_id", "identity_hash"})
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_RESIDENT_CODE = re.compile(r"^native_local_mcp_grant_[a-z_]{1,64}$")
_UNAVAILABLE = "native_local_mcp_grant_unavailable"

NativeMcpGrantState = Literal["allowed", "blocked", "review", "none"]


@dataclass(frozen=True, slots=True)
class NativeLocalMcpGrant:
    state: NativeMcpGrantState
    cli_id: str | None
    identity_hash: str | None


@dataclass(frozen=True, slots=True)
class NativeLocalMcpGrantFailure:
    """No authoritative answer; ``code`` says why, for diagnostics only."""

    code: str


def native_local_mcp_grant(
    *,
    store_path: Path,
    guard_home: Path,
    current_action: str,
    harness: str,
    tool_name: str,
    server: Mapping[str, object],
    connection_identity_hash: str | None,
    tool_authority_hash: str | None,
    launcher_path: str | None,
    launcher_home: str | None,
) -> NativeLocalMcpGrant | NativeLocalMcpGrantFailure:
    """Return the resident's MCP grant decision, or why there is none."""

    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"local-mcp-grant-{uuid4().hex}",
        "store_path": str(store_path),
        "guard_home": str(guard_home),
        "current_action": current_action,
        "harness": harness,
        "tool_name": tool_name,
        "server": dict(server),
        "connection_identity_hash": connection_identity_hash,
        "tool_authority_hash": tool_authority_hash,
        "launcher_path": launcher_path,
        "launcher_home": launcher_home,
    }
    try:
        digest = "sha256:" + _canonical_request_sha256(request)
    except (TypeError, ValueError):
        return NativeLocalMcpGrantFailure("native_local_mcp_grant_request_invalid")
    if not ensure_resident_prerequisite(guard_home):
        return NativeLocalMcpGrantFailure("native_local_mcp_grant_prerequisite_unavailable")
    response = _resident_request(
        operation="local_mcp_grant_decide",
        request=request,
        guard_home=guard_home,
        timeout_seconds=10.0,
        required_feature=LOCAL_MCP_GRANT_FEATURE,
        response_schema=_RESULT_SCHEMA,
    )
    if (
        response is None
        or response.get("schema") != _RESULT_SCHEMA
        or response.get("request_id") != request["request_id"]
        or response.get("request_sha256") != digest
    ):
        return NativeLocalMcpGrantFailure(_UNAVAILABLE)
    status, code = response.get("status"), response.get("code")
    if status == "error":
        # A bound refusal names its reason. Keep only codes in the resident's
        # own namespace so arbitrary text never reaches diagnostics.
        reason = code if isinstance(code, str) and _RESIDENT_CODE.fullmatch(code) else _UNAVAILABLE
        return NativeLocalMcpGrantFailure(reason)
    if status != "ok" or code != "ok":
        return NativeLocalMcpGrantFailure(_UNAVAILABLE)
    decoded = _decode_payload(response.get("payload"))
    return decoded if decoded is not None else NativeLocalMcpGrantFailure("native_local_mcp_grant_payload_invalid")


def _decode_payload(payload: object) -> NativeLocalMcpGrant | None:
    if not isinstance(payload, dict) or set(payload) != _PAYLOAD_KEYS:
        return None
    state = payload["state"]
    cli_id = payload["cli_id"]
    identity_hash = payload["identity_hash"]
    if not isinstance(state, str) or state not in _STATES:
        return None
    if cli_id is not None and not isinstance(cli_id, str):
        return None
    if identity_hash is not None and (not isinstance(identity_hash, str) or _SHA256.fullmatch(identity_hash) is None):
        return None
    if state != "none" and (cli_id is None or identity_hash is None):
        return None
    return NativeLocalMcpGrant(_STATES[state], cli_id, identity_hash)


__all__ = [
    "LOCAL_MCP_GRANT_FEATURE",
    "NativeLocalMcpGrant",
    "NativeLocalMcpGrantFailure",
    "native_local_mcp_grant",
]
