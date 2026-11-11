"""`hol-guard settings approval-pulse`: set up, turn off and recover Yanez Pulse.

`show-command on|off` chooses whether the YID app shows the command of a
paused action (on by default). Secrets are hidden and the home folder shows as
``~``; the resident builds that text, this module only names the setting.

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

# Where a new user gets the YID app, the same link as the dashboard.
# `referrer_id` tells Yanez the visit came from HOL Guard; it carries nothing
# about the user or the machine.
PULSE_SITE_URL = "https://pulse.yanez.ai/?referrer_id=holguard"
# How Pulse works, for anyone who wants to read more.
PULSE_DOCS_URL = "https://docs.yanez.ai/pulse/"
_SETUP_STEPS = (
    "Set up Yanez Pulse as your approval factor:",
    f"  1. Scan the QR code on {PULSE_SITE_URL} with your phone camera.",
    "     It installs the YanezYID app if needed, then registers your Yanez identity.",
    "  2. In the YID app, go to Settings > Agent Keys and create a key named HOL Guard.",
    "  3. Paste that key at the prompt below. It is hidden and stored only in Guard's secret store.",
)
_HELP_LINKS = f"Get the YID app:  {PULSE_SITE_URL}\nHow Pulse works:  {PULSE_DOCS_URL}"


def add_approval_pulse_parser(settings_subparsers, add_common_args, parser_class) -> None:
    # Every Pulse command's --help ends with where to get the app and read more.
    links = {"epilog": _HELP_LINKS, "formatter_class": argparse.RawDescriptionHelpFormatter}
    parser = settings_subparsers.add_parser(
        "approval-pulse",
        help="Use Yanez Pulse (YID app face scan approval) as the approval factor",
        **links,
    )
    add_common_args(parser, suppress_defaults=True)
    parser.add_argument("--json", action="store_true")
    commands = parser.add_subparsers(dest="settings_approval_pulse_command", required=True, parser_class=parser_class)
    status = commands.add_parser("status", help="Show whether Pulse is the approval factor", **links)
    enroll = commands.add_parser("enroll", help="Set up Pulse; needs your current approval factor", **links)
    enroll.add_argument(
        "--cooldown",
        type=int,
        choices=(0, 900, 3600),
        default=0,
        help="Seconds one approval covers later actions of the same kind and scope (default 0: always ask)",
    )
    enroll.add_argument(
        "--min-tier",
        choices=("medium", "high"),
        default="medium",
        help="Lowest face-scan assurance Guard accepts (default medium; high needs a device that signs at high)",
    )
    disable = commands.add_parser("disable", help="Return to the approval password; needs a Pulse approval", **links)
    recover = commands.add_parser(
        "recover",
        help="Lost the YID app: turn Pulse off with the approval password and the recovery code",
        **links,
    )
    show_command = commands.add_parser(
        "show-command",
        help="Show the agent's command in the YID app (on by default); needs a Pulse approval to change",
        description=(
            "Choose whether the YID app shows the command an agent wants to run. "
            "Secrets are hidden and your home folder shows as ~. "
            "When off, the YID app shows only the program names."
        ),
        **links,
    )
    show_command.add_argument("state", choices=("on", "off"), help="on: show the command; off: program names only")
    for sub in (status, enroll, disable, recover, show_command):
        add_common_args(sub, suppress_defaults=True)
        # Suppressed, so `approval-pulse --json status` keeps the parent's --json.
        sub.add_argument("--json", action="store_true", default=argparse.SUPPRESS)


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
    change = {"pulse_show_command": args.state == "on"}
    gate_input = prompt_for_approval_gate(guard_home, use_cooldown=False, strict=True)
    # One approval covers exactly this change, like a dashboard settings save.
    grant = require_high_risk(
        guard_home,
        purpose="settings_write",
        approval_gate_input=gate_input,
        settings_change={"kind": "save", "settings": {"approval_gate": change}},
    )
    return {"approval_gate": update_settings(guard_home, change, approval_gate_grant=grant).to_dict()}


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
