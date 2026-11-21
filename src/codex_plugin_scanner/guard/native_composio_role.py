"""Resident bridge for the ``composio_role`` op.

The Rust Composio contract owns which wrapper a tool name routes to and how
much review a call to it draws. This module only frames one request, binds the
response by ``request_id`` plus ``request_sha256``, and decodes the role.

Any transport failure (resident unavailable, capability absent, timeout,
overload, malformed or mismatched result) yields ``None``. Callers must read
``None`` as "no role", which refuses every discovery-only path, and must draw
the provider review a tool the contract cannot place would draw. Python never
works the role out for itself.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass

from .native_resident_decision import BoundCall, ResidentCallError, bound_resident_call

_REQUEST_SCHEMA = "guard-composio-role-request.v1"
_CALL = BoundCall(
    operation="composio_role",
    feature="composio-role-v1",
    prefix="native_composio_role",
    result_schema="guard-composio-role-result.v1",
    max_request_bytes=16 * 1024,
    timeout_seconds=2.0,
    check_circuit=True,
    transport_failure="unavailable",
)
_ROLES = frozenset({"discovery", "batch", "workbench", "connections", "unknown"})
_REQUEST_IDS = itertools.count()


@dataclass(frozen=True, slots=True)
class NativeComposioRole:
    """The routing the resident read from a tool name.

    ``role`` is ``None`` for a tool the Composio contract does not route.
    """

    role: str | None
    requires_action_review: bool


def composio_role_native(
    tool_name: str,
    *,
    timeout_seconds: float = 2.0,
    deadline_monotonic: float | None = None,
) -> NativeComposioRole | None:
    """Route one MCP tool name in the resident, or return ``None``."""
    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"composio-{next(_REQUEST_IDS)}",
        "tool_name": str(tool_name),
    }
    try:
        reply = bound_resident_call(
            _CALL, request, timeout_seconds=timeout_seconds, deadline_monotonic=deadline_monotonic
        )
    except ResidentCallError:
        return None
    envelope = reply.envelope
    role = envelope.get("role")
    review = envelope.get("requires_action_review")
    if (
        envelope.get("status") != "ok"
        or envelope.get("code") != "ok"
        or not isinstance(review, bool)
        or not (role is None or (isinstance(role, str) and role in _ROLES))
    ):
        reply.fail()
        return None
    reply.healthy()
    return NativeComposioRole(role=role, requires_action_review=review)
