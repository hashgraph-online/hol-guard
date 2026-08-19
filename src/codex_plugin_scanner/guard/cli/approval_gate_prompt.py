"""TTY prompt helpers for local approval gate checks."""

from __future__ import annotations

import getpass
import os
import sys
from pathlib import Path

from ..approval_gate import ApprovalGateError, ApprovalGateInput, public_config, recent_totp_satisfied

_DESKTOP_CHILD_ENV = "HOL_GUARD_DESKTOP"
_PASSWORD_ENV = "HOL_GUARD_APPROVAL_PASSWORD"
_TOTP_ENV = "HOL_GUARD_APPROVAL_TOTP_CODE"


def _take_env(name: str) -> str | None:
    value = os.environ.pop(name, None)
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


def _desktop_child_proof(*, totp_enabled: bool, use_cooldown: bool, cooldown_seconds: int) -> ApprovalGateInput | None:
    if os.environ.get(_DESKTOP_CHILD_ENV) != "1":
        return None
    password = _take_env(_PASSWORD_ENV)
    totp_code = _take_env(_TOTP_ENV)
    if password is not None and totp_code is not None:
        raise ApprovalGateError(
            "approval_gate_factor_conflict",
            "Enter the approval password or the authenticator code, never both.",
        )
    if totp_enabled:
        if totp_code is None:
            return None
        return ApprovalGateInput(password=None, totp_code=totp_code, use_cooldown=False)
    if password is None:
        return None
    return ApprovalGateInput(
        password=password,
        totp_code=None,
        use_cooldown=use_cooldown and cooldown_seconds > 0,
    )


def prompt_for_approval_gate(
    guard_home: Path,
    *,
    use_cooldown: bool = True,
    summary: str | None = None,
) -> ApprovalGateInput | None:
    gate = public_config(guard_home)
    if not gate.enabled:
        return None
    desktop_proof = _desktop_child_proof(
        totp_enabled=gate.totp_enabled,
        use_cooldown=use_cooldown,
        cooldown_seconds=gate.cooldown_seconds,
    )
    if desktop_proof is not None:
        return desktop_proof
    if gate.totp_enabled and recent_totp_satisfied(guard_home):
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
