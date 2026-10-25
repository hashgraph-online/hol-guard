"""``hol-guard telemetry plugins``: opt-in counts of installed HOL plugin listings."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from ..config import resolve_guard_home
from .report import PRIVACY_URL, PluginTelemetryError, dry_run, send_now
from .state import read_state, turn_off, turn_on

_WHAT_IS_SENT = (
    "Once a week Guard sends HOL the public plugin listings installed on this machine:\n"
    "the listing, the agent runtime and the plugin version, with a counting key that\n"
    "changes every week. Plugins that are not public HOL listings never leave the machine.\n"
    "No user, machine, path or workspace identifier is sent, and HOL shows a count only\n"
    "once at least 10 installs report it.\n"
    f"Details: {PRIVACY_URL}"
)


def build_parser(*, program_name: str = "hol-guard telemetry") -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=program_name, description="Opt-in Guard telemetry.")
    parser.add_argument("--guard-home", help=argparse.SUPPRESS)
    areas = parser.add_subparsers(dest="area", required=True)
    plugins = areas.add_parser(
        "plugins",
        help="Weekly counts of installed HOL plugin listings (off until you turn it on).",
        description=_WHAT_IS_SENT,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    actions = plugins.add_subparsers(dest="action", required=True)
    actions.add_parser("on", help="Start sending weekly counts.")
    actions.add_parser("off", help="Stop sending counts and delete the device key.")
    actions.add_parser("status", help="Show whether counts are on and when the last report went out.")
    send = actions.add_parser("send", help="Send this week's report now.")
    send.add_argument("--dry-run", action="store_true", help="Print the report without sending it.")
    for action in actions.choices.values():
        action.add_argument("--json", action="store_true", help="Print JSON.")
    return parser


def _print(payload: dict[str, object], *, as_json: bool, text: str) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True) if as_json else text)


def main(argv: Sequence[str], *, program_name: str = "hol-guard telemetry") -> int:
    args = build_parser(program_name=program_name).parse_args(list(argv))
    guard_home = resolve_guard_home(args.guard_home)
    as_json = bool(args.json)
    if args.action == "on":
        turn_on(guard_home)
        _print({"enabled": True}, as_json=as_json, text=f"Plugin install counts are on.\n\n{_WHAT_IS_SENT}")
        return 0
    if args.action == "off":
        turn_off(guard_home)
        _print({"enabled": False}, as_json=as_json, text="Plugin install counts are off. The device key was deleted.")
        return 0
    if args.action == "status":
        state = read_state(guard_home)
        last = state.last_week or "never"
        _print(
            {"enabled": state.enabled, "lastWeek": state.last_week},
            as_json=as_json,
            text=f"Plugin install counts: {'on' if state.enabled else 'off'}. Last report: {last}.",
        )
        return 0
    return _send(guard_home, dry=bool(args.dry_run), as_json=as_json)


def _send(guard_home: Path, *, dry: bool, as_json: bool) -> int:
    try:
        if dry:
            built = dry_run(guard_home)
            print(json.dumps(built["report"], indent=2, sort_keys=True))
            if not as_json:
                print(f"\n{built.get('installed', 0)} plugins installed; the report above lists the HOL listings.")
            return 0
        result = send_now(guard_home)
    except PluginTelemetryError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2
    _print(
        result,
        as_json=as_json,
        text=f"Sent {result['listed']} listed plugins for {result['week']} ({result['accepted']} accepted).",
    )
    return 0
