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
    summary: str | None = None,
) -> ApprovalGateInput | None:
    gate = public_config(guard_home)
    if not gate.enabled:
        return None
    if not sys.stdin.isatty():
        proof_name = "Authenticator code" if gate.totp_enabled else "Approval password"
        raise ApprovalGateError(
            "approval_gate_interactive_required",
            f"{proof_name} is required from an interactive terminal.",
        )
    if summary:
        print(summary, file=sys.stderr)
    password = None if gate.totp_enabled else getpass.getpass("Approval password: ")
    totp_code = getpass.getpass("Authenticator code: ") if gate.totp_enabled else None
    return ApprovalGateInput(
        password=password,
        totp_code=totp_code,
        use_cooldown=use_cooldown and gate.cooldown_seconds > 0 and not gate.totp_enabled,
    )


def approval_gate_cli_payload(error: ApprovalGateError) -> dict[str, object]:
    payload = error.to_payload()
    payload["exit_code"] = 4
    return payload
