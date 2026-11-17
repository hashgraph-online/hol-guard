"""`hol-guard settings approval-pulse`: set up, turn off and recover Yanez Pulse.

`show-command on|off` chooses whether the YID app shows the command of a
paused action. It is off by default; turning it on first explains what is sent
and asks the user to confirm at the terminal. The resident builds the text the
phone shows and checks the approval; this module only names the setting.

Every secret (approval password, authenticator code, agent key, recovery code)
is read with ``getpass`` from an interactive terminal. None is accepted as a
command-line argument or environment variable, so none lands in shell history,
process listings or an agent's transcript.
"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from ..approval_gate import (
    ApprovalGateError,
    ApprovalGateInput,
    await_pulse_approval,
    begin_pulse_enrollment,
    confirm_pulse_enrollment,
    disable_pulse,
    public_config,
    recover_pulse,
    require_high_risk,
    update_settings,
)
from .approval_gate_prompt import print_pulse_status, prompt_for_approval_gate
from .approval_pulse_parser import PULSE_SITE_URL

_SETUP_STEPS = (
    "Set up Yanez Pulse as your approval factor:",
    f"  1. Scan the QR code on {PULSE_SITE_URL} with your phone camera.",
    "     It installs the YanezYID app if needed, then registers your Yanez identity.",
    "  2. In the YID app, go to Settings > Agent Keys and create a key named HOL Guard.",
    "  3. Paste that key at the prompt below. It is hidden and stored only in Guard's secret store.",
)
# Shown before the user opts in to sending commands to the YID app.
SHOW_COMMAND_NOTICE = (
    "Turning this on sends the command an agent wants to run to Yanez Pulse, so the",
    "YID app can show it before you approve. Guard hides the secrets and user folders it",
    "recognises (tokens, passwords, keys, your home folder shown as ~), but this filtering",
    "is best-effort and cannot catch every secret. With it off, the YID app shows only the",
    "program names, as it does by default.",
)


def _require_terminal(what: str) -> None:
    if not sys.stdin.isatty():
        raise ApprovalGateError(
            "approval_gate_interactive_required",
            f"{what} must be entered at an interactive terminal.",
        )


def _hidden(prompt: str, *, strip: bool = True) -> str:
    entered = getpass.getpass(prompt)
    if not entered.strip():
        raise ApprovalGateError("approval_gate_required", "No value was entered.")
    # The approval password is sent as typed, like the approval prompt does:
    # spaces at either end can be part of it.
    return entered.strip() if strip else entered


def _password() -> str:
    return _hidden("Approval password: ", strip=False)


def _enroll(args: argparse.Namespace, guard_home: Path) -> dict[str, object]:
    _require_terminal("Pulse setup")
    gate = public_config(guard_home)
    for line in _SETUP_STEPS:
        print(line, file=sys.stderr)
    password = _password()
    totp_code = _hidden("Authenticator code: ") if gate.totp_enabled else None
    agent_key = _hidden("YID agent key (input hidden): ")
    begun = begin_pulse_enrollment(
        guard_home,
        approval_gate_input=ApprovalGateInput(password=password, totp_code=totp_code, pulse_agent_key=agent_key),
        min_tier=args.min_tier,
    )
    print(f"Pulse found Yanez identity {begun.get('yid_hint')}.", file=sys.stderr)
    request_id = await_pulse_approval(guard_home, begun, on_status=print_pulse_status)
    confirmed = confirm_pulse_enrollment(
        guard_home,
        request_id=request_id,
        cooldown_seconds=int(args.cooldown),
    )
    recovery_code = confirmed.pop("recovery_code", None)
    floor = confirmed.get("pulse_min_tier", args.min_tier)
    print(
        f"\nPulse is now your approval factor, at {floor} assurance or above.\n"
        "Save this one-time recovery code somewhere offline.\n"
        "With your approval password it turns Pulse off if you lose the YID app. Guard cannot show it again.\n"
        f"\n    {recovery_code}\n",
        file=sys.stderr,
    )
    return {"approval_gate": confirmed}


def _disable(guard_home: Path) -> dict[str, object]:
    gate_input = prompt_for_approval_gate(guard_home, use_cooldown=False, strict=True)
    grant = require_high_risk(
        guard_home,
        purpose="settings_write",
        approval_gate_input=gate_input,
        settings_change={"kind": "pulse_disable"},
    )
    return {"approval_gate": disable_pulse(guard_home, approval_gate_grant=grant).to_dict()}


def _show_command(args: argparse.Namespace, guard_home: Path) -> dict[str, object]:
    gate = public_config(guard_home)
    if not gate.pulse_enabled:
        raise ApprovalGateError(
            "approval_gate_pulse_not_enabled",
            "Yanez Pulse is not the approval factor for this Guard.",
            status=409,
        )
    show = args.state == "on"
    if show:
        _confirm_show_command()
    change = {"pulse_show_command": show}
    gate_input = prompt_for_approval_gate(guard_home, use_cooldown=False, strict=True)
    # One approval covers exactly this change, like a dashboard settings save.
    grant = require_high_risk(
        guard_home,
        purpose="settings_write",
        approval_gate_input=gate_input,
        settings_change={"kind": "save", "settings": {"approval_gate": change}},
    )
    return {"approval_gate": update_settings(guard_home, change, approval_gate_grant=grant).to_dict()}


def _confirm_show_command() -> None:
    """Informed opt-in: explain what is sent, then require a typed yes."""
    _require_terminal("Turning on command sharing")
    for line in SHOW_COMMAND_NOTICE:
        print(line, file=sys.stderr)
    if input("Type yes to send commands to the YID app: ").strip().lower() != "yes":
        raise ApprovalGateError("approval_gate_cancelled", "Command sharing stays off.")


def _recover(guard_home: Path) -> dict[str, object]:
    _require_terminal("Pulse recovery")
    password = _password()
    code = _hidden("Pulse recovery code: ")
    gate = recover_pulse(
        guard_home,
        approval_gate_input=ApprovalGateInput(password=password, pulse_recovery_code=code),
    )
    return {"approval_gate": gate.to_dict()}


def run_approval_pulse_settings_command(*, args: argparse.Namespace, guard_home: Path) -> dict[str, object]:
    command = str(getattr(args, "settings_approval_pulse_command", "")).strip().lower()
    if command == "status":
        return {"approval_gate": public_config(guard_home).to_dict()}
    if command == "enroll":
        return _enroll(args, guard_home)
    if command == "disable":
        return _disable(guard_home)
    if command == "recover":
        return _recover(guard_home)
    if command == "show-command":
        return _show_command(args, guard_home)
    raise ValueError("Unsupported approval-pulse command.")
