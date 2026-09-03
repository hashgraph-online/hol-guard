"""Hidden, versioned CLI contract for the native HOL Guard Desktop shell."""

from __future__ import annotations

import argparse

from ...argparse_utils import FriendlyArgumentParser
from .commands_parser_helpers import _add_guard_common_args


def _configure_guard_desktop_parser(
    guard_subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    desktop_parser = guard_subparsers.add_parser("desktop", help=argparse.SUPPRESS)
    _add_guard_common_args(desktop_parser)
    desktop_subparsers = desktop_parser.add_subparsers(
        dest="desktop_command",
        required=True,
        parser_class=FriendlyArgumentParser,
        metavar="{bootstrap,presentation-set,dashboard-update}",
    )
    bootstrap_parser = desktop_subparsers.add_parser("bootstrap", help=argparse.SUPPRESS)
    _add_guard_common_args(bootstrap_parser, suppress_defaults=True)
    bootstrap_parser.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
    presentation_parser = desktop_subparsers.add_parser("presentation-set", help=argparse.SUPPRESS)
    _add_guard_common_args(presentation_parser, suppress_defaults=True)
    presentation_parser.add_argument("--mode", choices=("everyday", "technical"), required=True)
    presentation_parser.add_argument("--expected-revision", type=int, default=None)
    presentation_parser.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
    dashboard_update_parser = desktop_subparsers.add_parser("dashboard-update", help=argparse.SUPPRESS)
    _add_guard_common_args(dashboard_update_parser, suppress_defaults=True)
    dashboard_update_parser.add_argument("--daemon-pid", type=int, required=True)
    dashboard_update_parser.add_argument("--daemon-port", type=int, required=True)
    dashboard_update_parser.add_argument("--update-token", required=True)
    dashboard_update_parser.add_argument("--force-pypi-reinstall", action="store_true")
    dashboard_update_parser.add_argument("--alpha", action="store_true")


__all__ = ["_configure_guard_desktop_parser"]
