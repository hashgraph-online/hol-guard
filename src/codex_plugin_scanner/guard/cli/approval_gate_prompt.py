"""TTY prompt helpers for local approval gate checks."""

from __future__ import annotations

import getpass
import json
import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import TextIO

from ..approval_gate import (
    ApprovalGateError,
    ApprovalGateInput,
    await_pulse_approval,
    public_config,
    recent_totp_satisfied,
)

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
    strict: bool = False,
) -> ApprovalGateInput | None:
    """Collect the approval proof from the terminal.

    ``strict`` marks decisions that always need a fresh proof (global scope or
    strict-all mode). Otherwise an open cooldown window is honoured and no prompt
    is shown, but only for callers that allow the cooldown (``use_cooldown``).
    """

    gate = public_config(guard_home)
    if not gate.enabled:
        return None
    if gate.pulse_enabled:
        # The approval happens in the YID app, not at this prompt. The grant
        # call sends the Pulse request for its exact action and waits here.
        if summary:
            print(summary, file=sys.stderr)
        return ApprovalGateInput(
            pulse_mode="wait",
            pulse_on_status=print_pulse_status,
            use_cooldown=use_cooldown and not strict and gate.pulse_cooldown_seconds > 0,
        )
    if (
        use_cooldown
        and not strict
        and not gate.strict_all_decisions
        and not gate.totp_enabled
        and gate.cooldown_seconds > 0
        and gate.cooldown_active
        and not require_fresh_totp
    ):
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
        require_fresh_totp=require_fresh_totp,
    )


def print_pulse_status(status: str, request: dict[str, object]) -> None:
    """Tell the user where to approve, and the code both screens show."""
    if status == "pending":
        code = request.get("match_code") or "------"
        print(
            f"HOL Guard sent this approval to your YID app. Check that the app shows match code {code}, "
            "then approve with your face scan. Waiting...",
            file=sys.stderr,
            flush=True,
        )
    elif status == "approved":
        print("Approved in the YID app. Verifying the Pulse receipt...", file=sys.stderr, flush=True)


def approval_gate_cli_payload(error: ApprovalGateError) -> dict[str, object]:
    payload = error.to_payload()
    payload["exit_code"] = 4
    return payload


def print_approval_gate_error(error: ApprovalGateError, *, as_json: bool, output_stream: TextIO | None = None) -> int:
    """Report a refused approval gate the way every lifecycle command does; return exit code 4."""

    if as_json:
        print(json.dumps(approval_gate_cli_payload(error), sort_keys=True), file=output_stream or sys.stdout)
    else:
        print(f"Error: {error}", file=sys.stderr)
    return 4


def submit_with_pulse(
    guard_home: Path,
    send: Callable[[dict[str, object]], dict[str, object]],
    payload: dict[str, object],
    gate_input: ApprovalGateInput | None,
) -> dict[str, object]:
    """Send a gated request to the daemon, approving it in the YID app when Pulse is on.

    The daemon cannot wait for the phone, so in Pulse mode the first send asks
    it for a Pulse request for this exact action (as the dashboard does), this
    terminal waits for the approval, and the same payload is sent again with
    the request id. ``payload`` itself is not changed.
    """
    if getattr(gate_input, "pulse_mode", "off") != "wait":
        return send(payload)
    response = send({**payload, "approval_gate_pulse": True})
    if response.get("error") != "approval_gate_pulse_pending":
        return response
    request = {
        "request_id": response.get("pulse_request_id"),
        "match_code": response.get("pulse_match_code"),
        "decide_by": response.get("pulse_decide_by"),
    }
    request_id = await_pulse_approval(guard_home, request, on_status=getattr(gate_input, "pulse_on_status", None))
    return send({**payload, "approval_pulse_request_id": request_id})
