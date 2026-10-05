"""Resident bridge for the ``approval_gate`` op (RTM-009(e)).

Mirrors ``native_pretool.review_pre_tool_native``: each ``approval_gate.py``
free fn calls :func:`approval_gate_native` first; when the resident answers it
returns the decoded payload, when the resident is unavailable/mismatched it
returns ``None`` and the caller falls back to the in-process Python body.

The bridge raises ``ApprovalGateError`` (reconstructed from the op's
``code``/``status``/``message``) for business-rule rejections — those are
deterministic and must propagate. It returns ``None`` only for transport
failures (resident missing, timeout, malformed envelope, capability absent),
which are non-deterministic and safe to fall back on.
"""

from __future__ import annotations

import json
import time
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING

from .native_resident_client import native_resident_client_request
from .native_runtime import _isolated_environment, _native_error, native_runtime_status
from .native_runtime_resilience import (
    native_record_overload,
    native_record_resident_failure,
    native_record_resident_success,
)

if TYPE_CHECKING:  # pragma: no cover - import cycle guard
    from .approval_gate import ApprovalGateGrant, ApprovalGateInput

_MAX_REQUEST_BYTES = 64 * 1024
_RESIDENT_PROTOCOL_FEATURE = "resident-protocol-v2"
_APPROVAL_GATE_FEATURE = "approval-gate-v1"
_REQUEST_SCHEMA = "guard-approval-gate-request.v1"
_RESULT_SCHEMA = "guard-approval-gate-result.v1"

_request_counter = 0


def _gate_error_cls():
    # Local import to avoid the approval_gate -> native_approval_gate cycle.
    from .approval_gate import ApprovalGateError

    return ApprovalGateError


def _input_to_wire(gate_input: ApprovalGateInput | None) -> dict[str, object] | None:
    if gate_input is None:
        return None
    wire: dict[str, object] = {}
    if gate_input.password is not None:
        wire["password"] = gate_input.password
    if gate_input.new_password is not None:
        wire["new_password"] = gate_input.new_password
    if gate_input.confirm_password is not None:
        wire["confirm_password"] = gate_input.confirm_password
    if gate_input.totp_code is not None:
        wire["totp_code"] = gate_input.totp_code
    if gate_input.use_cooldown is not None:
        wire["use_cooldown"] = bool(gate_input.use_cooldown)
    wire["revoke_cooldown"] = bool(gate_input.revoke_cooldown)
    wire["require_fresh_totp"] = bool(gate_input.require_fresh_totp)
    return wire


def _grant_to_wire(grant: ApprovalGateGrant | None) -> dict[str, object] | None:
    if grant is None:
        return None
    return {
        "grant_id": grant.grant_id,
        "purpose": grant.purpose,
        "issued_at": grant.issued_at,
        "expires_at": grant.expires_at,
        "action": grant.action,
        "scope": grant.scope,
        "subject": grant.subject,
        "session_nonce": grant.session_nonce,
        "factor_set": list(grant.factor_set),
        "strict": bool(grant.strict),
        "used_cooldown": bool(grant.used_cooldown),
        "cooldown_expires_at": grant.cooldown_expires_at,
        "password_verified": bool(grant.password_verified),
        "totp_verified": bool(grant.totp_verified),
    }


def approval_gate_native(
    method: str,
    guard_home: Path,
    *,
    params: Mapping[str, object] | None = None,
    approval_gate_input: ApprovalGateInput | None = None,
    approval_gate_grant: ApprovalGateGrant | None = None,
    strict: bool = False,
    purpose: str | None = None,
    now: str | None = None,
    duration_seconds: int | None = None,
    device_label: str | None = None,
    timeout_seconds: float = 2.0,
) -> dict[str, object] | None:
    """Run one approval-gate method in the resident.

    Returns the decoded ``payload`` on success, raises ``ApprovalGateError`` on
    a business-rule rejection, and returns ``None`` when the resident cannot
    service the call (caller falls back to the Python implementation).
    """
    global _request_counter
    status = native_runtime_status()
    if (
        status.mode == "off"
        or not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or _RESIDENT_PROTOCOL_FEATURE not in status.capabilities.features
        or _APPROVAL_GATE_FEATURE not in status.capabilities.features
    ):
        return None

    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"ag-{_request_counter}",
        "guard_home": str(guard_home),
        "method": method,
    }
    _request_counter += 1
    if params:
        request["params"] = dict(params)
    input_wire = _input_to_wire(approval_gate_input)
    if input_wire is not None:
        request["approval_gate_input"] = input_wire
    grant_wire = _grant_to_wire(approval_gate_grant)
    if grant_wire is not None:
        request["approval_gate_grant"] = grant_wire
    if strict:
        request["strict"] = True
    if purpose is not None:
        request["purpose"] = purpose
    if now is not None:
        request["now"] = now
    if duration_seconds is not None:
        request["duration_seconds"] = duration_seconds
    if device_label is not None:
        request["device_label"] = device_label

    deadline_monotonic = time.monotonic() + timeout_seconds
    deadline_budget_ms = max(1, min(9_000, int(timeout_seconds * 1_000)))
    resident = json.dumps(
        {
            "operation": "approval_gate",
            "deadline_budget_ms": deadline_budget_ms,
            "request": request,
        },
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    if len(resident) > _MAX_REQUEST_BYTES:
        return None

    output = native_resident_client_request(
        executable=status.identity.path,
        guard_home=guard_home,
        environment=_isolated_environment(),
        payload=resident,
        deadline_monotonic=deadline_monotonic,
    )
    if output is None:
        native_record_resident_failure(status.identity.sha256, guard_home, reason="native_approval_gate_unavailable")
        return None
    try:
        envelope = json.loads(output)
    except (UnicodeDecodeError, json.JSONDecodeError):
        native_record_resident_failure(status.identity.sha256, guard_home, reason="native_approval_gate_decode_failed")
        return None
    if _native_error(envelope) == "native_overloaded":
        native_record_overload(status.identity.sha256, guard_home)
        return None
    if not isinstance(envelope, dict) or envelope.get("schema") != _RESULT_SCHEMA:
        native_record_resident_failure(
            status.identity.sha256, guard_home, reason="native_approval_gate_schema_mismatch"
        )
        return None

    native_record_resident_success(status.identity.sha256, guard_home)
    envelope_status = envelope.get("status")
    if envelope_status == "error":
        error_cls = _gate_error_cls()
        raise error_cls(
            str(envelope.get("code") or "approval_gate_required"),
            str(envelope.get("message") or "Approval gate check failed."),
            status=int(envelope.get("error_status") or 403),
        )
    # Fail-closed on any status other than "ok": a typo'd or future status
    # (e.g. "denied") must not be treated as a successful gate pass — a
    # `-> None` caller would otherwise proceed unauthenticated.
    if envelope_status != "ok":
        native_record_resident_failure(status.identity.sha256, guard_home, reason="native_approval_gate_bad_status")
        return None
    payload = envelope.get("payload")
    return payload if isinstance(payload, dict) else None
