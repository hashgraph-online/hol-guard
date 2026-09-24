"""TTY prompt helpers for local approval gate checks."""

from __future__ import annotations

import getpass
import json
import os
import sys
from pathlib import Path

from ..approval_gate import ApprovalGateError, ApprovalGateInput, public_config, recent_totp_satisfied

_DESKTOP_CHILD_ENV = "HOL_GUARD_DESKTOP"
_PASSWORD_ENV = "HOL_GUARD_APPROVAL_PASSWORD"
_TOTP_ENV = "HOL_GUARD_APPROVAL_TOTP_CODE"
_MAX_DESKTOP_PROOF_BYTES = 4 * 1024


def _pop_env(name: str) -> str | None:
    value = os.environ.pop(name, None)
    return value if isinstance(value, str) else None


def consume_desktop_lifecycle_env(
    *,
    totp_enabled: bool,
    use_cooldown: bool,
    cooldown_seconds: int,
) -> ApprovalGateInput | None:
    """Take Desktop child proof for protection lifecycle commands only.

    The approval factor variables are always removed from the process environment
    so later subprocesses cannot inherit unused credentials.
    """

    password = _pop_env(_PASSWORD_ENV)
    totp_raw = _pop_env(_TOTP_ENV)
    totp_code = totp_raw.strip() if totp_raw is not None and totp_raw.strip() else None
    if os.environ.get(_DESKTOP_CHILD_ENV) != "1":
        return None
    if password is not None and totp_code is not None:
        raise ApprovalGateError(
            "approval_gate_factor_conflict",
            "Enter the approval password or the authenticator code, never both.",
        )
    if totp_enabled:
        if totp_code is None:
            return None
        return ApprovalGateInput(password=None, totp_code=totp_code, use_cooldown=False)
    if not password:
        return None
    return ApprovalGateInput(
        password=password,
        totp_code=None,
        use_cooldown=use_cooldown and cooldown_seconds > 0,
    )


def consume_desktop_lifecycle_stdin(*, totp_enabled: bool) -> ApprovalGateInput | None:
    """Read one bounded recovery proof without placing secrets in argv or env."""

    raw = sys.stdin.buffer.read(_MAX_DESKTOP_PROOF_BYTES + 1)
    if len(raw) > _MAX_DESKTOP_PROOF_BYTES:
        raise ApprovalGateError("approval_gate_proof_too_large", "Approval proof exceeded the allowed size.")
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ApprovalGateError("approval_gate_proof_invalid", "Approval proof was not valid JSON.") from error
    if not isinstance(payload, dict) or set(payload) != {"password", "totpCode"}:
        raise ApprovalGateError("approval_gate_proof_invalid", "Approval proof fields were invalid.")
    password = payload["password"]
    totp_code = payload["totpCode"]
    if password is not None and not isinstance(password, str):
        raise ApprovalGateError("approval_gate_proof_invalid", "Approval password was invalid.")
    if totp_code is not None and not isinstance(totp_code, str):
        raise ApprovalGateError("approval_gate_proof_invalid", "Authenticator code was invalid.")
    password = password if isinstance(password, str) and password else None
    totp_code = totp_code.strip() if isinstance(totp_code, str) and totp_code.strip() else None
    if password is not None and totp_code is not None:
        raise ApprovalGateError(
            "approval_gate_factor_conflict",
            "Enter the approval password or the authenticator code, never both.",
        )
    if totp_enabled:
        if totp_code is None:
            raise ApprovalGateError("approval_gate_totp_required", "Authenticator code is required.")
        return ApprovalGateInput(password=None, totp_code=totp_code, use_cooldown=False)
    if password is None:
        raise ApprovalGateError("approval_gate_password_required", "Approval password is required.")
    return ApprovalGateInput(password=password, totp_code=None, use_cooldown=False)


def prompt_for_approval_gate(
    guard_home: Path,
    *,
    use_cooldown: bool = True,
    summary: str | None = None,
    require_fresh_totp: bool = False,
) -> ApprovalGateInput | None:
    gate = public_config(guard_home)
    if not gate.enabled:
        return None
    if gate.totp_enabled and recent_totp_satisfied(guard_home) and not require_fresh_totp:
        return None
    if not sys.stdin.isatty():
        proof_name = "Authenticator code" if gate.totp_enabled else "Approval password"
        raise ApprovalGateError(
            "approval_gate_interactive_required",
            f"{proof_name} is required from an interactive terminal.",
        )
    if summary:
        print(summary, file=sys.stderr)
    proof_name = "authenticator code" if gate.totp_enabled else "approval password"
    print(
        f"HOL Guard is waiting for your {proof_name}. Enter it at the next prompt to continue.",
        file=sys.stderr,
        flush=True,
    )
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
