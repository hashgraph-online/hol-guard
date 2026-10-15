"""Advisory approval-gate posture for status and doctor output.

Without an approval password or authenticator, anything that can reach the
local approval center can approve a blocked action. This summary only nudges
the user; it never blocks, prompts, or changes the gate.
"""

from __future__ import annotations

from pathlib import Path

from .approval_gate import ApprovalGateError, public_config
from .approval_gate_state import APPROVAL_GATE_STATE_FILE

APPROVAL_GATE_NUDGE = "Set an approval password or MFA so only you can approve blocked actions."
APPROVAL_GATE_SETUP_HINT = (
    "Run `hol-guard dashboard`, then open Settings > Approval gate and turn on `Ask for proof on allow decisions`."
)


def approval_gate_posture(guard_home: Path) -> dict[str, object]:
    """Summarize whether approvals need user proof, without raising."""

    if (Path(guard_home) / APPROVAL_GATE_STATE_FILE).exists():
        try:
            config = public_config(guard_home)
        except (ApprovalGateError, OSError, RuntimeError, ValueError):
            return {"status": "unknown"}
        if config.enabled:
            return {"status": "protected", "totp_enabled": config.totp_enabled}
    # A home that never wrote gate state has no gate; skip the resident round trip.
    return {"status": "not_set", "nudge": APPROVAL_GATE_NUDGE, "setup": APPROVAL_GATE_SETUP_HINT}


__all__ = ["APPROVAL_GATE_NUDGE", "APPROVAL_GATE_SETUP_HINT", "approval_gate_posture"]
