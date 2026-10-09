"""Local MCP grant decision from the native runtime.

The resident reads ``guard.db`` and decides whether a live MCP ``tools/call``
is covered by a this-device grant. Python sends the server identity material
recorded in artifact metadata, the tool name, and the live authority digests,
and presents the answer. A missing, malformed, or unbound reply is ``None``, which callers
must treat as "no authoritative answer", never as an allow.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from uuid import uuid4

from .native_execution import _resident_request

LOCAL_MCP_GRANT_FEATURE = "local-mcp-grant-v1"
_REQUEST_SCHEMA = "guard-local-mcp-grant-request.v1"
_RESULT_SCHEMA = "guard-local-mcp-grant-result.v1"
_PAYLOAD_KEYS = frozenset({"state", "cli_id", "identity_hash"})
_SHA256 = re.compile(r"^[0-9a-f]{64}$")

NativeMcpGrantState = Literal["allowed", "blocked", "review", "none"]


@dataclass(frozen=True, slots=True)
class NativeLocalMcpGrant:
    state: NativeMcpGrantState
    cli_id: str | None
    identity_hash: str | None


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
) -> NativeLocalMcpGrant | None:
    """Return the resident's MCP grant decision, or ``None`` without an answer."""

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
        digest = (
            "sha256:"
            + hashlib.sha256(
                json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
            ).hexdigest()
        )
    except (TypeError, ValueError):
        return None
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
        or response.get("status") != "ok"
        or response.get("code") != "ok"
    ):
        return None
    return _decode_payload(response.get("payload"))


def _decode_payload(payload: object) -> NativeLocalMcpGrant | None:
    if not isinstance(payload, dict) or set(payload) != _PAYLOAD_KEYS:
        return None
    state = payload["state"]
    cli_id = payload["cli_id"]
    identity_hash = payload["identity_hash"]
    if state not in {"allowed", "blocked", "review", "none"}:
        return None
    if cli_id is not None and not isinstance(cli_id, str):
        return None
    if identity_hash is not None and (not isinstance(identity_hash, str) or _SHA256.fullmatch(identity_hash) is None):
        return None
    if state != "none" and (cli_id is None or identity_hash is None):
        return None
    return NativeLocalMcpGrant(state, cli_id, identity_hash)


__all__ = ["LOCAL_MCP_GRANT_FEATURE", "NativeLocalMcpGrant", "native_local_mcp_grant"]
