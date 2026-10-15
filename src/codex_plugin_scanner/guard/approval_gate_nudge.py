"""Advisory approval-gate posture for status and doctor output.

Without an approval password or authenticator, anything that can reach the
local approval center can approve a blocked action. This summary only nudges
the user; it never blocks, prompts, or changes the gate.
"""

from __future__ import annotations

import json
from pathlib import Path

from .approval_gate import ApprovalGateError, public_config
from .approval_gate_state import APPROVAL_GATE_STATE_FILE

APPROVAL_GATE_NUDGE = "Set an approval password or MFA so only you can approve blocked actions."
APPROVAL_GATE_SETUP_HINT = (
    "Run `hol-guard dashboard`, then open Settings > Approval gate and turn on `Ask for proof on allow decisions`."
)


def _not_set() -> dict[str, object]:
    return {"status": "not_set", "nudge": APPROVAL_GATE_NUDGE, "setup": APPROVAL_GATE_SETUP_HINT}


def _posture_from_state_file(state_path: Path) -> dict[str, object]:
    """Read the gate's own on/off fields from its state file, as the resident does.

    The gate is on when ``enabled`` or ``fail_closed`` is true. An unreadable or
    malformed file makes the resident fail closed; this view reports it as
    unknown rather than guessing.
    """

    if not state_path.is_file():
        return _not_set()
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError):
        return {"status": "unknown"}
    if not isinstance(state, dict):
        return {"status": "unknown"}
    if state.get("enabled") is True or state.get("fail_closed") is True:
        return {"status": "protected", "totp_enabled": state.get("totp_enabled") is True}
    return _not_set()


def approval_gate_posture(guard_home: Path, *, passive: bool = False) -> dict[str, object]:
    """Summarize whether approvals need user proof, without raising.

    ``passive`` reads the gate state file directly instead of asking the
    native resident, so diagnostics such as ``doctor`` never start or wait on
    the resident and never record a resident failure. The resident stays the
    only authority that enforces the gate.
    """

    state_path = Path(guard_home) / APPROVAL_GATE_STATE_FILE
    if passive:
        return _posture_from_state_file(state_path)
    if state_path.exists():
        try:
            config = public_config(guard_home)
        except (ApprovalGateError, OSError, RuntimeError, ValueError):
            return {"status": "unknown"}
        if config.enabled:
            return {"status": "protected", "totp_enabled": config.totp_enabled}
    # A home that never wrote gate state has no gate; skip the resident round trip.
    return _not_set()


__all__ = ["APPROVAL_GATE_NUDGE", "APPROVAL_GATE_SETUP_HINT", "approval_gate_posture"]
