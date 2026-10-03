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
        metavar="{bootstrap,qualify,dashboard-update}",
    )
    bootstrap_parser = desktop_subparsers.add_parser("bootstrap", help=argparse.SUPPRESS)
    _add_guard_common_args(bootstrap_parser, suppress_defaults=True)
    bootstrap_parser.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
    qualify_parser = desktop_subparsers.add_parser("qualify", help=argparse.SUPPRESS)
    _add_guard_common_args(qualify_parser, suppress_defaults=True)
    qualify_parser.add_argument("--json", action="store_true", required=True)
    qualify_parser.add_argument("--operation-id", required=True)
    qualify_parser.add_argument("--artifact-generation", required=True)
    qualify_parser.add_argument("--deadline-epoch", type=float, required=True)
    owned_parser = desktop_subparsers.add_parser("qualify-owned", help=argparse.SUPPRESS)
    _add_guard_common_args(owned_parser, suppress_defaults=True)
    owned_parser.add_argument("--json", action="store_true", required=True)
    owned_parser.add_argument("--operation-id", required=True)
    owned_parser.add_argument("--artifact-generation", required=True)
    owned_parser.add_argument("--deadline-epoch", type=float, required=True)
    owned_parser.add_argument("--daemon-executable", required=True)
    owned_parser.add_argument("--daemon-executable-sha256", required=True)
    owned_parser.add_argument("--daemon-package-version", required=True)
    for command in ("transition-status", "transition-recover", "transition-activate", "transition-finalize"):
        transition_parser = desktop_subparsers.add_parser(command, help=argparse.SUPPRESS)
        _add_guard_common_args(transition_parser, suppress_defaults=True)
        transition_parser.add_argument("--json", action="store_true", required=True)
        transition_parser.add_argument("--operation-id", required=True)
        transition_parser.add_argument("--deadline-epoch", type=float, required=True)
        if command == "transition-finalize":
            transition_parser.add_argument("--artifact-generation", required=True)
        if command == "transition-activate":
            transition_parser.add_argument("--request", required=True)
            transition_parser.add_argument("--request-sha256", required=True)
    dashboard_update_parser = desktop_subparsers.add_parser("dashboard-update", help=argparse.SUPPRESS)
    _add_guard_common_args(dashboard_update_parser, suppress_defaults=True)
    dashboard_update_parser.add_argument("--daemon-pid", type=int, required=True)
    dashboard_update_parser.add_argument("--daemon-port", type=int, required=True)
    dashboard_update_parser.add_argument("--update-token", required=True)
    dashboard_update_parser.add_argument("--force-pypi-reinstall", action="store_true")
    dashboard_update_parser.add_argument("--alpha", action="store_true")


__all__ = ["_configure_guard_desktop_parser"]
