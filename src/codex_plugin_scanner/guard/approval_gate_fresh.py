"""Approval-decision proofs that never lean on an earlier unlock.

An inline install prompt reads a typed "y" from a terminal that anything can
type into, so its approval must carry the gate's own factor every time. The
native ``verify`` method with ``strict`` set checks that factor directly: an
open password cooldown never stands in for the password, and the check never
opens one.
"""

from __future__ import annotations

from pathlib import Path

from .approval_gate import ApprovalGateError, _issued
from .approval_gate_pulse import _with_pulse
from .approval_gate_types import ApprovalGateGrant, ApprovalGateInput

__all__ = ["require_fresh_approval_decision"]


def require_fresh_approval_decision(
    guard_home: Path,
    *,
    action: str,
    scope: str,
    approval_gate_input: ApprovalGateInput | None,
    subject: str,
    now: str | None = None,
) -> ApprovalGateGrant:
    """Issue a strict approval-decision proof checked against the factor itself.

    Callers that also want a fresh authenticator code set ``require_fresh_totp``
    on the input. Where the gate asks for a Pulse approval, this requests one
    for the same action and retries with its receipt, so a phone approval
    reaches the same strict check.
    """

    payload = _with_pulse(
        "verify",
        guard_home,
        pulse_purpose="approval_decision",
        pulse_strict=True,
        pulse_scope=scope,
        params={"action": action, "scope": scope, "subject": subject},
        approval_gate_input=approval_gate_input,
        strict=True,
        purpose="approval_decision",
        now=now,
    )
    if payload is None:
        raise ApprovalGateError(
            "approval_gate_configuration_required",
            "Configure the approval gate before approving this request.",
            status=423,
        )
    return _issued(payload)
