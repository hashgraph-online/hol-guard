"""Yanez Pulse as the approval-gate factor: transport and presentation only.

The resident owns every Pulse decision: it builds the terms, keeps the
receipt, verifies the Yanez and approver signatures and consumes the receipt.
This module starts a request, checks it every 10 seconds, one bounded call
at a time (so no resident lock is held while the user decides in the YID app),
and hands the request id back to the same grant call.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

from . import approval_gate as _gate
from .approval_gate_state import ApprovalGatePublicConfig
from .approval_gate_types import ApprovalGateError, ApprovalGateGrant, ApprovalGateInput

_PULSE_TIMEOUT_SECONDS = 9.0
_PULSE_POLL_INTERVAL_SECONDS = 10.0
# A check that could not reach Pulse is tried again on the next interval.
_PULSE_RETRYABLE_ERRORS = {"approval_gate_pulse_unavailable", "native_approval_gate_unavailable"}
# The 15-minute decision window plus the 60 s consent grace the resident adds.
_PULSE_DECISION_DEADLINE_SECONDS = 960.0
_PULSE_TERMINAL_ERRORS = {
    "rejected": ("approval_gate_pulse_rejected", "The action was rejected in the YID app."),
    "expired": ("approval_gate_pulse_expired", "The Pulse request expired before it was approved."),
}


def request_pulse_approval(
    guard_home: Path,
    *,
    purpose: str,
    strict: bool,
    action: str | None = None,
    scope: str | None = None,
    subject: str | None = None,
    session_nonce: str | None = None,
    verdict: str | None = None,
    batch_request_ids: tuple[str, ...] = (),
    now: str | None = None,
) -> dict[str, object]:
    """Ask the resident to send one Pulse request for this exact action.

    Returns ``{"status": "pending", "request_id", "match_code", "decide_by"}``,
    or ``{"status": "cooldown_covered"}`` when an open Pulse cooldown already
    covers it. A ``verdict`` other than a review never creates a request.
    """
    params: dict[str, object] = {"action": action, "scope": scope, "subject": subject, "session_nonce": session_nonce}
    if verdict is not None:
        params["verdict"] = verdict
    if batch_request_ids:
        params["batch_request_ids"] = list(batch_request_ids)
    return _gate._native(
        "pulse_request",
        guard_home,
        params=params,
        strict=strict,
        purpose=purpose,
        now=now,
        timeout_seconds=_PULSE_TIMEOUT_SECONDS,
    )


def poll_pulse_approval(
    guard_home: Path,
    request_id: str,
    *,
    now: str | None = None,
) -> str:
    """One check of the request. Returns pending, approved, rejected or expired."""
    payload = _gate._native(
        "pulse_poll",
        guard_home,
        params={"request_id": request_id},
        now=now,
        timeout_seconds=_PULSE_TIMEOUT_SECONDS,
    )
    status = payload.get("status")
    if status not in {"pending", "approved", "rejected", "expired"}:
        raise _gate._unavailable()
    return str(status)


def await_pulse_approval(
    guard_home: Path,
    request: dict[str, object],
    *,
    on_status: Callable[[str, dict[str, object]], None] | None = None,
    deadline_seconds: float = _PULSE_DECISION_DEADLINE_SECONDS,
) -> str:
    """Check every 10 seconds until the YID app answers or the window closes.

    Rejection and expiry raise. A check that cannot reach Pulse is tried again
    until the deadline; if Pulse is still unreachable then, that error is raised.
    """
    request_id = str(request.get("request_id") or "")
    if not request_id:
        raise _gate._unavailable()
    if on_status is not None:
        on_status("pending", request)
    deadline = time.monotonic() + deadline_seconds
    unreachable: ApprovalGateError | None = None
    while (remaining := deadline - time.monotonic()) > 0:
        time.sleep(min(_PULSE_POLL_INTERVAL_SECONDS, remaining))
        try:
            status = poll_pulse_approval(guard_home, request_id)
        except ApprovalGateError as error:
            if error.code not in _PULSE_RETRYABLE_ERRORS:
                raise
            unreachable = error
            continue
        unreachable = None
        if status == "approved":
            if on_status is not None:
                on_status("approved", request)
            return request_id
        if status in _PULSE_TERMINAL_ERRORS:
            code, message = _PULSE_TERMINAL_ERRORS[status]
            raise ApprovalGateError(code, message)
    if unreachable is not None:
        raise unreachable
    code, message = _PULSE_TERMINAL_ERRORS["expired"]
    raise ApprovalGateError(code, message)


def _with_pulse(
    method: str,
    guard_home: Path,
    *,
    pulse_purpose: str,
    pulse_strict: bool,
    params: dict[str, object],
    approval_gate_input: ApprovalGateInput | None,
    pulse_scope: str | None = None,
    **kwargs: object,
) -> dict[str, object] | None:
    """Run a grant method; when the gate asks for Pulse, get an approval for the same action and retry.

    The retry is the same resident call with the same params, so the resident
    checks the receipt against exactly the action it is granting.
    """
    if approval_gate_input is not None and approval_gate_input.pulse_request_id is not None:
        kwargs = {**kwargs, "timeout_seconds": _PULSE_TIMEOUT_SECONDS}
    try:
        return _gate._native_or_unconfigured(
            method, guard_home, params=params, approval_gate_input=approval_gate_input, **kwargs
        )
    except ApprovalGateError as error:
        if (
            error.code != "approval_gate_pulse_required"
            or approval_gate_input is None
            or approval_gate_input.pulse_mode == "off"
            or approval_gate_input.pulse_request_id is not None
        ):
            raise
    request = request_pulse_approval(
        guard_home,
        purpose=pulse_purpose,
        strict=pulse_strict,
        action=_optional_str(params.get("action")),
        scope=pulse_scope or _optional_str(params.get("scope")),
        subject=_optional_str(params.get("subject")),
        session_nonce=_optional_str(params.get("session_nonce")),
        batch_request_ids=approval_gate_input.pulse_batch_request_ids,
    )
    request_id: str | None = None
    if request.get("status") != "cooldown_covered":
        if approval_gate_input.pulse_mode == "defer":
            raise ApprovalGateError(
                "approval_gate_pulse_pending",
                "Approve this action in the YID app, then submit it again.",
                status=202,
                details={
                    "pulse_request_id": request.get("request_id"),
                    "pulse_match_code": request.get("match_code"),
                    "pulse_decide_by": request.get("decide_by"),
                },
            )
        request_id = await_pulse_approval(guard_home, request, on_status=approval_gate_input.pulse_on_status)
    retry_input = replace(approval_gate_input, pulse_request_id=request_id, pulse_mode="off", pulse_on_status=None)
    if request_id is not None:
        kwargs = {**kwargs, "timeout_seconds": _PULSE_TIMEOUT_SECONDS}
    return _gate._native_or_unconfigured(method, guard_home, params=params, approval_gate_input=retry_input, **kwargs)


def _optional_str(value: object) -> str | None:
    return value if isinstance(value, str) else None


def begin_pulse_enrollment(
    guard_home: Path,
    *,
    approval_gate_input: ApprovalGateInput,
    authorize_only: bool = False,
    min_tier: object = None,
    now: str | None = None,
) -> dict[str, object]:
    """Check the current factor, resolve the agent key's YID and send the enrollment request.

    With ``authorize_only`` the resident only checks the current factor and lets
    this session start setup without it for 15 minutes. ``min_tier`` is the
    lowest assurance tier Guard will accept, ``"medium"`` or ``"high"``; the
    resident validates it, saves it at confirmation and defaults to medium.
    """
    params: dict[str, object] = {"authorize_only": authorize_only}
    if min_tier is not None:
        params["min_tier"] = min_tier
    return _gate._native(
        "begin_pulse_enrollment",
        guard_home,
        params=params,
        approval_gate_input=approval_gate_input,
        now=now,
        timeout_seconds=_PULSE_TIMEOUT_SECONDS,
    )


def confirm_pulse_enrollment(
    guard_home: Path,
    *,
    request_id: str,
    cooldown_seconds: int = 0,
    now: str | None = None,
) -> dict[str, object]:
    """Verify the enrollment receipt and switch the gate to Pulse.

    The result carries a one-time ``recovery_code``; Guard keeps only its hash.
    """
    payload = _gate._native(
        "confirm_pulse_enrollment",
        guard_home,
        params={"request_id": request_id, "cooldown_seconds": cooldown_seconds},
        now=now,
        timeout_seconds=_PULSE_TIMEOUT_SECONDS,
    )
    _gate._config(payload)
    return payload


def disable_pulse(
    guard_home: Path,
    *,
    approval_gate_grant: ApprovalGateGrant | None,
    now: str | None = None,
) -> ApprovalGatePublicConfig:
    """Return to the password factor. Needs a fresh Pulse grant for ``settings_write``."""
    return _gate._config(_gate._native("disable_pulse", guard_home, approval_gate_grant=approval_gate_grant, now=now))


def recover_pulse(
    guard_home: Path,
    *,
    approval_gate_input: ApprovalGateInput,
    now: str | None = None,
) -> ApprovalGatePublicConfig:
    """Lost the YID app: the approval password plus the one-time recovery code turn Pulse off."""
    return _gate._config(_gate._native("recover_pulse", guard_home, approval_gate_input=approval_gate_input, now=now))
