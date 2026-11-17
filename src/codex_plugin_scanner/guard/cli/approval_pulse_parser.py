"""Argument parser for `hol-guard settings approval-pulse`.

Kept apart from ``approval_pulse_commands`` so building the CLI parser (and
``hol-guard --help``) does not import the approval gate or the native runtime.
"""

from __future__ import annotations

import argparse

# Where a new user gets the YID app, the same link as the dashboard.
# `referrer_id` tells Yanez the visit came from HOL Guard; it carries nothing
# about the user or the machine.
PULSE_SITE_URL = "https://pulse.yanez.ai/?referrer_id=holguard"
# How Pulse works, for anyone who wants to read more.
PULSE_DOCS_URL = "https://docs.yanez.ai/pulse/"
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
        help="Show the agent's command in the YID app (off by default); needs a Pulse approval to change",
        description=(
            "Choose whether the YID app shows the command an agent wants to run. It is off by default, "
            "and the YID app shows only the program names. When on, Guard hides the secrets and user "
            "folders it recognises, but this is best-effort. Turning it on asks you to confirm at the terminal."
        ),
        **links,
    )
    show_command.add_argument("state", choices=("on", "off"), help="on: show the command; off: program names only")
    for sub in (status, enroll, disable, recover, show_command):
        add_common_args(sub, suppress_defaults=True)
        # Suppressed, so `approval-pulse --json status` keeps the parent's --json.
        sub.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
