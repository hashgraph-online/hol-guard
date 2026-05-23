"""TTY prompt helpers for local approval gate checks."""

from __future__ import annotations

import getpass
import sys
from pathlib import Path

from ..approval_gate import ApprovalGateError, ApprovalGateInput, public_config


def prompt_for_approval_gate(
    guard_home: Path,
    *,
    use_cooldown: bool = True,
) -> ApprovalGateInput | None:
    gate = public_config(guard_home)
    if not gate.enabled:
        return None
    if not sys.stdin.isatty():
        raise ApprovalGateError(
            "approval_gate_interactive_required",
            "Approval password is required from an interactive terminal.",
        )
    password = getpass.getpass("Approval password: ")
    return ApprovalGateInput(
        password=password,
        use_cooldown=use_cooldown and gate.cooldown_seconds > 0,
    )


def approval_gate_cli_payload(error: ApprovalGateError) -> dict[str, object]:
    payload = error.to_payload()
    payload["exit_code"] = 4
    return payload
