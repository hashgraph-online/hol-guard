"""Transport for the native MCP proxy decision owner.

The resident decides the authoritative outcomes of the MCP proxy: the
``tools/list`` catalog state machine, how one ``tools/call`` is routed, the
execution-boundary revalidation after a saved approval was claimed, and how a
package policy composes with the tool policy that carries it. Python frames the
stream, gathers facts from its collaborators (stores, claims, prompts) and
renders the answer. It never recomputes or overrides a verdict.

Facts only a collaborator can supply are requested lazily: the resident replies
``{"need": <name>}``, the caller supplies exactly that fact, and the identical
request is repeated. A supplier receives the resident's ``need`` reply. Anything but a bound, well-formed answer raises
``NativeMcpProxyDecisionError`` so callers fail closed.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any
from uuid import uuid4

from .native_context import _canonical_request_sha256, ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_runtime import native_runtime_status
from .native_runtime_resilience import native_record_resident_failure, native_record_resident_success

MCP_PROXY_DECISION_FEATURE = "mcp-proxy-decision-v1"
_REQUEST_SCHEMA = "guard-mcp-proxy-decision-request.v1"
_RESULT_SCHEMA = "guard-mcp-proxy-decision-result.v1"
_OPERATION = "mcp_proxy_decide"
_MAX_REQUEST_BYTES = 5 * 1024 * 1024
_MAX_NEED_ROUNDS = 4
_TIMEOUT_SECONDS = 10.0

Supplier = Callable[[Mapping[str, Any]], Mapping[str, object]]


class NativeMcpProxyDecisionError(ValueError):
    """No authoritative native answer; callers must fail closed."""


def _fail(code: str) -> NativeMcpProxyDecisionError:
    return NativeMcpProxyDecisionError(code)


def _round_trip(query: Mapping[str, object], guard_home: Path) -> tuple[dict[str, Any], str, str]:
    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"mcp-proxy-decision-{uuid4().hex}",
        "query": dict(query),
    }
    try:
        digest = "sha256:" + _canonical_request_sha256(request)
    except (TypeError, ValueError) as error:
        raise _fail("native_mcp_proxy_decision_request_invalid") from error
    if not ensure_resident_prerequisite(guard_home):
        raise _fail("native_mcp_proxy_decision_prerequisite_unavailable")
    response = _resident_request(
        operation=_OPERATION,
        request=request,
        guard_home=guard_home,
        timeout_seconds=_TIMEOUT_SECONDS,
        required_feature=MCP_PROXY_DECISION_FEATURE,
        response_schema=_RESULT_SCHEMA,
        max_request_bytes=_MAX_REQUEST_BYTES,
        record_success=False,
    )
    if response is None:
        # ``_resident_request`` already recorded the transport, malformed, status or
        # schema failure; recording it again would double-count one outage.
        raise _fail("native_mcp_proxy_decision_unavailable")
    if (
        response.get("schema") != _RESULT_SCHEMA
        or response.get("request_id") != request["request_id"]
        or response.get("request_sha256") != digest
    ):
        _record_failure(guard_home, "native_mcp_proxy_decision_binding_mismatch")
        raise _fail("native_mcp_proxy_decision_unavailable")
    if response.get("status") != "ok" or response.get("code") != "ok":
        # A bound refusal is the resident's answer for this exact request, not
        # an outage: it must not count toward the shared availability circuit.
        _record_success(guard_home)
        raise _fail("native_mcp_proxy_decision_refused")
    payload = response.get("payload")
    if not isinstance(payload, dict):
        _record_failure(guard_home, "native_mcp_proxy_decision_payload_invalid")
        raise _fail("native_mcp_proxy_decision_payload_invalid")
    return payload, digest, str(request["request_id"])


def native_mcp_proxy_decide(
    query: Mapping[str, object],
    *,
    guard_home: Path,
    supply: Mapping[str, Supplier] | None = None,
) -> dict[str, Any]:
    """Return the resident's payload for ``query``, resolving ``need`` replies."""

    current = dict(query)
    for _ in range(_MAX_NEED_ROUNDS):
        payload, _digest, _request_id = _round_trip(current, guard_home)
        need = payload.get("need")
        if need is None:
            _record_success(guard_home)
            return payload
        supplier = (supply or {}).get(need) if isinstance(need, str) else None
        if supplier is None:
            # A caller-side gap, not a resident failure: it never trips the circuit.
            raise _fail("native_mcp_proxy_decision_need_unsupplied")
        current = {**current, **supplier(payload)}
    raise _fail("native_mcp_proxy_decision_need_loop")


def _record_success(guard_home: Path) -> None:
    status = native_runtime_status()
    if status.identity is not None:
        native_record_resident_success(status.identity.sha256, guard_home)


def _record_failure(guard_home: Path, reason: str) -> None:
    status = native_runtime_status()
    if status.identity is not None:
        native_record_resident_failure(status.identity.sha256, guard_home, reason=reason)


def tool_facts(decision: Any) -> dict[str, object]:
    """The decision-relevant facts of one ``ToolCallDecision``."""

    return {
        "action": decision.action,
        "source": decision.source,
        "current_action": decision.current_action,
        "saved_action": decision.saved_action,
        "approval_reuse_status": decision.approval_reuse_status,
        "approval_reuse_reason_code": decision.approval_reuse_reason_code,
        "has_pending": decision.pending_approval_reuse_decision is not None,
    }


def package_facts(resolution: Any) -> dict[str, object]:
    """The decision-relevant facts of one package policy resolution."""

    return {
        "saved_policy_blocks": bool(resolution.saved_policy_blocks),
        "current_action": resolution.current_action,
        "policy_action": resolution.evaluation.policy_action,
        "has_pending": resolution.pending_approval_reuse_decision is not None,
    }


def cursor_fact(cursor: object) -> dict[str, object]:
    if cursor is None:
        return {"kind": "none"}
    if isinstance(cursor, str):
        return {"kind": "string", "value": cursor}
    return {"kind": "other"}
