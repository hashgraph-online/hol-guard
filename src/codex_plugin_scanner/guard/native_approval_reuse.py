"""Resident bridge for the ``approval_reuse_decide`` op (RTM-032).

Mirrors ``native_approval_gate.approval_gate_native``: ``runtime.approval_reuse``
calls :func:`approval_reuse_decide_native`; when the resident answers it
returns the decoded ``ApprovalReuseDecision.to_evidence()`` payload, and when
the resident cannot service the call it returns ``None`` — the established
transport-failure contract, never a decision. The resident is the sole
authority for this composition: a ``None`` result preserves the caller's
current evaluation unchanged (no saved approval is claimed); it never routes
to a Python evaluator.

The op is pure (no IO, no SQLite): it composes a recomputed action with saved
approval evidence. ``guard_home`` resolves through the same bound-home binding
that ``native_context`` uses so callers do not need to thread it.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from .native_resident_client import native_resident_client_request
from .native_runtime import _isolated_environment, _native_error, native_runtime_status
from .native_runtime_resilience import (
    native_record_overload,
    native_record_resident_failure,
    native_record_resident_success,
    native_runtime_health_snapshot,
)
from .runtime.approval_reuse import ApprovalReuseMalformedResultError

_MAX_REQUEST_BYTES = 256 * 1024
_RESIDENT_PROTOCOL_FEATURE = "resident-protocol-v2"
_APPROVAL_REUSE_FEATURE = "approval-reuse-v1"
_REQUEST_SCHEMA = "guard-approval-reuse-request.v1"
_RESULT_SCHEMA = "guard-approval-reuse-result.v1"

_request_counter = 0


def approval_reuse_decide_native(
    current_action: object,
    saved_action: object | None,
    *,
    saved_decision_present: bool | None,
    validation_reason: str | None,
    fresh_local_approval: bool,
    durable_exact_approval: bool,
    guard_home: Path,
    timeout_seconds: float = 2.0,
    deadline_monotonic: float | None = None,
) -> dict[str, object] | None:
    """Compose a reuse decision in the resident.

    Returns the decoded ``payload`` (an ``ApprovalReuseDecision.to_evidence()``
    dict) on success. Returns ``None`` when the resident cannot service the call
    (unavailable, capability absent, timeout or overload): the caller
    preserves the current evaluation. Malformed results raise instead of
    being treated as unavailable authority. Business-rule outcomes always
    return ``ok``; there is no domain-error envelope to reconstruct.
    Shared caller deadlines may shorten, never extend, the per-call timeout.
    """
    global _request_counter
    effective_deadline = time.monotonic() + timeout_seconds
    if deadline_monotonic is not None:
        effective_deadline = min(effective_deadline, deadline_monotonic)
    if effective_deadline <= time.monotonic():
        return None
    status = native_runtime_status(deadline_monotonic=effective_deadline)
    if (
        status.mode == "off"
        or not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or _RESIDENT_PROTOCOL_FEATURE not in status.capabilities.features
        or _APPROVAL_REUSE_FEATURE not in status.capabilities.features
    ):
        return None
    if native_runtime_health_snapshot(status.identity.sha256, guard_home).circuit_open:
        return None

    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"ar-{_request_counter}",
        "current_action": current_action,
        "saved_action": saved_action,
        "fresh_local_approval": bool(fresh_local_approval),
        "durable_exact_approval": bool(durable_exact_approval),
    }
    _request_counter += 1
    if saved_decision_present is not None:
        request["saved_decision_present"] = bool(saved_decision_present)
    if validation_reason is not None:
        request["validation_reason"] = str(validation_reason)

    remaining_seconds = effective_deadline - time.monotonic()
    if remaining_seconds <= 0:
        return None
    deadline_budget_ms = max(1, min(9_000, int(remaining_seconds * 1_000)))
    try:
        request_sha256 = (
            "sha256:"
            + hashlib.sha256(
                json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode(
                    "utf-8"
                )
            ).hexdigest()
        )
        resident = json.dumps(
            {
                "operation": "approval_reuse_decide",
                "deadline_budget_ms": deadline_budget_ms,
                "request": request,
            },
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ApprovalReuseMalformedResultError("approval_reuse request is not JSON data") from exc
    if len(resident) > _MAX_REQUEST_BYTES:
        return None
    if time.monotonic() >= effective_deadline:
        return None

    output = native_resident_client_request(
        executable=status.identity.path,
        guard_home=guard_home,
        environment=_isolated_environment(),
        payload=resident,
        deadline_monotonic=effective_deadline,
    )
    if output is None:
        native_record_resident_failure(
            status.identity.sha256,
            guard_home,
            reason="native_approval_reuse_unavailable",
        )
        return None
    try:
        envelope = json.loads(output)
    except (UnicodeDecodeError, json.JSONDecodeError):
        native_record_resident_failure(
            status.identity.sha256,
            guard_home,
            reason="native_approval_reuse_decode_failed",
        )
        raise ApprovalReuseMalformedResultError("approval_reuse result is not valid JSON") from None
    if _native_error(envelope) == "native_overloaded":
        native_record_overload(status.identity.sha256, guard_home)
        return None
    if (
        not isinstance(envelope, dict)
        or envelope.get("schema") != _RESULT_SCHEMA
        or envelope.get("request_id") != request["request_id"]
        or envelope.get("request_sha256") != request_sha256
    ):
        native_record_resident_failure(
            status.identity.sha256,
            guard_home,
            reason="native_approval_reuse_schema_mismatch",
        )
        raise ApprovalReuseMalformedResultError("approval_reuse result does not match the request")

    if envelope.get("status") != "ok" or envelope.get("code") != "ok":
        native_record_resident_failure(status.identity.sha256, guard_home, reason="native_approval_reuse_bad_status")
        raise ApprovalReuseMalformedResultError("resident rejected the approval_reuse request")
    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        native_record_resident_failure(
            status.identity.sha256, guard_home, reason="native_approval_reuse_no_decision_payload"
        )
        raise ApprovalReuseMalformedResultError("approval_reuse result has no decision object")
    native_record_resident_success(status.identity.sha256, guard_home)
    return payload
