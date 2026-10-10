"""Contributed MCP decision from the native runtime.

The resident owns the bundled MCP contributions, per-tool states, the
package-launcher allow binding, and direct-command and remote-endpoint
matching. Python sends the identity material recorded in artifact metadata,
the tool name, and the extension-control layers it verified, and presents the
answer. A missing, malformed, or unbound reply is a ``NativeContributedMcpFailure``
carrying a reason code, which callers must treat as "no authoritative answer",
never as an allow.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from uuid import uuid4

from .native_context import _canonical_request_sha256, ensure_resident_prerequisite
from .native_execution import _resident_request

CONTRIBUTED_MCP_DECISION_FEATURE = "contributed-mcp-decision-v1"
_REQUEST_SCHEMA = "guard-contributed-mcp-decision-request.v1"
_RESULT_SCHEMA = "guard-contributed-mcp-decision-result.v1"
_PAYLOAD_KEYS = frozenset({"state", "action", "source", "reason"})
_ACTIONS = frozenset({"allow", "review", "block"})
_RESIDENT_CODE = re.compile(r"^native_contributed_mcp_[a-z_]{1,64}$")
_UNAVAILABLE = "native_contributed_mcp_unavailable"

NativeContributedState = Literal["decided", "none"]


@dataclass(frozen=True, slots=True)
class NativeContributedMcpDecision:
    state: NativeContributedState
    action: str | None
    source: str | None
    reason: str | None


@dataclass(frozen=True, slots=True)
class NativeContributedMcpFailure:
    """No authoritative answer; ``code`` says why, for diagnostics only."""

    code: str


def native_contributed_mcp_decision(
    *,
    store_path: Path,
    guard_home: Path,
    current_action: str,
    server_identity: Mapping[str, object] | None,
    artifact_transport: object,
    server_name: object,
    tool_name: object,
    layers: Sequence[Mapping[str, object]],
) -> NativeContributedMcpDecision | NativeContributedMcpFailure:
    """Return the resident's contributed decision, or why there is none."""

    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"contributed-mcp-{uuid4().hex}",
        "store_path": str(store_path),
        "guard_home": str(guard_home),
        "current_action": current_action,
        "server_identity": None if server_identity is None else dict(server_identity),
        "artifact_transport": artifact_transport,
        "server_name": server_name,
        "tool_name": tool_name,
        "layers": [dict(layer) for layer in layers],
    }
    try:
        digest = "sha256:" + _canonical_request_sha256(request)
    except (TypeError, ValueError):
        return NativeContributedMcpFailure("native_contributed_mcp_request_invalid")
    if not ensure_resident_prerequisite(guard_home):
        return NativeContributedMcpFailure("native_contributed_mcp_prerequisite_unavailable")
    response = _resident_request(
        operation="contributed_mcp_decide",
        request=request,
        guard_home=guard_home,
        timeout_seconds=10.0,
        required_feature=CONTRIBUTED_MCP_DECISION_FEATURE,
        response_schema=_RESULT_SCHEMA,
    )
    if (
        response is None
        or response.get("schema") != _RESULT_SCHEMA
        or response.get("request_id") != request["request_id"]
        or response.get("request_sha256") != digest
    ):
        return NativeContributedMcpFailure(_UNAVAILABLE)
    status, code = response.get("status"), response.get("code")
    if status == "error":
        # A bound refusal names its reason. Keep only codes in the resident's
        # own namespace so arbitrary text never reaches diagnostics.
        reason = code if isinstance(code, str) and _RESIDENT_CODE.fullmatch(code) else _UNAVAILABLE
        return NativeContributedMcpFailure(reason)
    if status != "ok" or code != "ok":
        return NativeContributedMcpFailure(_UNAVAILABLE)
    decoded = _decode_payload(response.get("payload"))
    return decoded if decoded is not None else NativeContributedMcpFailure("native_contributed_mcp_payload_invalid")


def _decode_payload(payload: object) -> NativeContributedMcpDecision | None:
    if not isinstance(payload, dict) or set(payload) != _PAYLOAD_KEYS:
        return None
    state, action, source, reason = (payload[key] for key in ("state", "action", "source", "reason"))
    if state == "none":
        if action is None and source is None and reason is None:
            return NativeContributedMcpDecision("none", None, None, None)
        return None
    if state != "decided" or not isinstance(action, str) or action not in _ACTIONS:
        return None
    if not isinstance(source, str) or not isinstance(reason, str):
        return None
    return NativeContributedMcpDecision("decided", action, source, reason)


__all__ = [
    "CONTRIBUTED_MCP_DECISION_FEATURE",
    "NativeContributedMcpDecision",
    "NativeContributedMcpFailure",
    "native_contributed_mcp_decision",
]
