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
        metavar="{bootstrap}",
    )
    bootstrap_parser = desktop_subparsers.add_parser("bootstrap", help=argparse.SUPPRESS)
    _add_guard_common_args(bootstrap_parser, suppress_defaults=True)
    bootstrap_parser.add_argument("--json", action="store_true", default=argparse.SUPPRESS)


__all__ = ["_configure_guard_desktop_parser"]
