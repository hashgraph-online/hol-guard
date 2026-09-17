"""Step-up authorization for disconnecting a managed app."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from .approval_gate import (
    ApprovalGateError,
    ApprovalGateGrant,
    ApprovalGateInput,
    require_high_risk,
)
from .approval_gate import (
    input_from_mapping as approval_gate_input_from_mapping,
)
from .approval_gate import (
    public_config as approval_gate_public_config,
)

_FRESH_AUTHENTICATOR_ACTIONS = frozenset(
    {
        "uninstall",
        "disconnect",
        "apps.disconnect",
    }
)


def disconnect_requires_fresh_authenticator(action: str) -> bool:
    """True when removing app protection must collect a new authenticator code."""

    return action in _FRESH_AUTHENTICATOR_ACTIONS


def require_harness_disconnect_gate(
    guard_home: Path,
    payload: Mapping[str, object] | None,
    *,
    harness: str,
) -> ApprovalGateGrant | None:
    """Require the approval gate before Guard removes a managed app."""

    gate = approval_gate_public_config(guard_home)
    if not gate.enabled:
        return None
    gate_input = approval_gate_input_from_mapping(payload) or ApprovalGateInput()
    if gate.totp_enabled and not (gate_input.totp_code or "").strip():
        raise ApprovalGateError("approval_gate_totp_required", "TOTP code is required.")
    return require_high_risk(
        guard_home,
        purpose="protection_lifecycle",
        approval_gate_input=gate_input,
        action="apps.disconnect",
        scope="local-protection",
        subject=harness,
    )


__all__ = [
    "disconnect_requires_fresh_authenticator",
    "require_harness_disconnect_gate",
]
