"""``hol-guard hooks`` parser construction kept free of hook-removal runtime imports."""

from __future__ import annotations

import argparse

from .commands_parser_helpers import _add_guard_common_args


def configure_guard_hooks_parser(
    guard_subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    hooks_parser = guard_subparsers.add_parser("hooks", help="Manage Guard hooks in harness configs")
    hooks_subparsers = hooks_parser.add_subparsers(dest="hooks_command", required=True)
    remove_parser = hooks_subparsers.add_parser(
        "remove",
        help="Remove every Guard hook from every known harness config (requires step-up)",
    )
    remove_parser.add_argument(
        "--all",
        action="store_true",
        help="Accepted for clarity; removal always covers every known harness",
    )
    remove_parser.add_argument(
        "--stop-daemon",
        action="store_true",
        help="Also stop the local Guard daemon after the hooks are removed",
    )
    remove_parser.add_argument("--dry-run", action="store_true", help="List what would be removed and change nothing")
    _add_guard_common_args(remove_parser)
    remove_parser.add_argument("--json", action="store_true")
