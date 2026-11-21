"""``hol-guard plugin updates``: newer checked releases of installed plugins.

Guard downloads two public indexes from HOL, the plugin listings and the
releases their authors recorded with the HOL Plugin Release workflow, and the
native runtime compares the installed versions with them on the device. The
check runs only when the user asks for it and sends nothing about the
installed plugins.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from ..config import resolve_guard_home
from .host import PluginTelemetryError, host_request, user_home


def check_updates(guard_home: Path) -> dict[str, Any]:
    """``{"updates": [...], "dismissed": n}`` for the plugins installed on this machine."""

    return host_request("updates", guard_home, home=user_home())


def dismiss_update(guard_home: Path, slug: str, version: str) -> dict[str, Any]:
    """Stop prompting for ``slug`` until a release newer than ``version`` is checked."""

    return host_request("updates-dismiss", guard_home, slug=slug, version=version)


def build_parser(*, program_name: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=program_name,
        description=(
            "Compare installed plugins with the releases their authors checked on HOL. "
            "Guard downloads the public indexes and compares versions on this machine; "
            "nothing about your plugins is sent."
        ),
    )
    parser.add_argument("--guard-home", help=argparse.SUPPRESS)
    parser.add_argument("--json", action="store_true", help="Print JSON.")
    actions = parser.add_subparsers(dest="action")
    dismiss = actions.add_parser("dismiss", help="Stop prompting for a listing until a newer release is checked.")
    dismiss.add_argument("slug", help="Listing slug, as the update prompt shows it.")
    dismiss.add_argument("--version", required=True, help="The latest version the prompt showed.")
    # SUPPRESS keeps a subcommand from resetting a --json given before it.
    dismiss.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="Print JSON.")
    actions.add_parser("reset", help="Show dismissed prompts again.").add_argument(
        "--json", action="store_true", default=argparse.SUPPRESS, help="Print JSON."
    )
    return parser


def _describe(update: dict[str, Any]) -> str:
    line = (
        f"{update['slug']} ({update['runtime']}): {update['installedVersion']} -> {update['latestVersion']}\n"
        f"  {update['releasesUrl']}"
    )
    if update.get("reason") == "security_fix":
        return f"{line}\n  Urgent: a newer release fixes a high or critical finding."
    if update.get("reason") == "installed_high_severity":
        return f"{line}\n  Urgent: the installed release had a high or critical finding."
    return line


def main(argv: Sequence[str], *, program_name: str = "hol-guard plugin updates") -> int:
    args = build_parser(program_name=program_name).parse_args(list(argv))
    guard_home = resolve_guard_home(args.guard_home)
    try:
        if args.action == "dismiss":
            payload = dismiss_update(guard_home, args.slug, args.version)
            print(json.dumps(payload, sort_keys=True) if args.json else f"Dismissed {args.slug} {args.version}.")
            return 0
        if args.action == "reset":
            payload = host_request("updates-reset", guard_home)
            print(json.dumps(payload) if args.json else "Dismissed update prompts will show again.")
            return 0
        result = check_updates(guard_home)
    except PluginTelemetryError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    updates = result.get("updates") or []
    if not updates:
        print("No newer checked releases for the plugins installed here.")
    else:
        print("\n".join(_describe(update) for update in updates))
    hidden = result.get("dismissed") or 0
    if hidden:
        print(f"\n{hidden} dismissed. Run: {program_name} reset")
    return 0
